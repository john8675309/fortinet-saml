//! GTK-thread-only AppIndicator integration. Resolve the installed GTK 3
//! runtime dynamically so missing tray support can fall back to the window.
use crate::Action;
use fortigate_manager::model::{ProfileView, Request, State};
use gtk::{glib::translate::ToGlibPtr, prelude::*};
use std::{
    ffi::{c_char, c_int, c_void, CString},
    ptr::NonNull,
    sync::mpsc,
};

#[derive(Clone, Copy)]
struct Api {
    new: unsafe extern "C" fn(*const c_char, *const c_char, c_int) -> *mut c_void,
    menu: unsafe extern "C" fn(*mut c_void, *mut gtk::ffi::GtkMenu),
    status: unsafe extern "C" fn(*mut c_void, c_int),
    icon: unsafe extern "C" fn(*mut c_void, *const c_char, *const c_char),
    title: unsafe extern "C" fn(*mut c_void, *const c_char),
}
impl Api {
    fn load() -> Option<Self> {
        for library in [c"libayatana-appindicator3.so.1", c"libappindicator3.so.1"] {
            // The C signatures match the installed AppIndicator GTK 3 typelib.
            // Successful libraries stay mapped for the lifetime of GTK objects.
            unsafe {
                let handle = libc::dlopen(library.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL);
                if handle.is_null() {
                    continue;
                }
                let names = [
                    c"app_indicator_new",
                    c"app_indicator_set_menu",
                    c"app_indicator_set_status",
                    c"app_indicator_set_icon_full",
                    c"app_indicator_set_title",
                ];
                let symbols = names.map(|name| libc::dlsym(handle, name.as_ptr()));
                if symbols.iter().any(|s| s.is_null()) {
                    libc::dlclose(handle);
                    continue;
                }
                return Some(Self {
                    new: std::mem::transmute::<
                        *mut c_void,
                        unsafe extern "C" fn(*const c_char, *const c_char, c_int) -> *mut c_void,
                    >(symbols[0]),
                    menu: std::mem::transmute::<
                        *mut c_void,
                        unsafe extern "C" fn(*mut c_void, *mut gtk::ffi::GtkMenu),
                    >(symbols[1]),
                    status: std::mem::transmute::<
                        *mut c_void,
                        unsafe extern "C" fn(*mut c_void, c_int),
                    >(symbols[2]),
                    icon: std::mem::transmute::<
                        *mut c_void,
                        unsafe extern "C" fn(*mut c_void, *const c_char, *const c_char),
                    >(symbols[3]),
                    title: std::mem::transmute::<
                        *mut c_void,
                        unsafe extern "C" fn(*mut c_void, *const c_char),
                    >(symbols[4]),
                });
            }
        }
        None
    }
}

pub struct Tray {
    api: Api,
    indicator: NonNull<c_void>,
    _menu: gtk::Menu,
    status: gtk::MenuItem,
    profiles: gtk::Menu,
    tx: mpsc::Sender<(Action, Request)>,
    snapshot: Vec<(String, String, State)>,
    available: Option<bool>,
    icon_name: CString,
}

impl Tray {
    pub fn new(
        window: &gtk::ApplicationWindow,
        app: &gtk::Application,
        tx: mpsc::Sender<(Action, Request)>,
    ) -> Option<Self> {
        let api = Api::load()?;
        let icon = [
            "/usr/share/icons/hicolor/scalable/apps/fortigate-manager.svg",
            "/usr/local/share/icons/hicolor/scalable/apps/fortigate-manager.svg",
            concat!(env!("CARGO_MANIFEST_DIR"), "/assets/fortigate-manager.svg"),
        ].into_iter().find(|path|std::path::Path::new(path).is_file())?;
        let icon_name = CString::new(icon).ok()?;
        let indicator = NonNull::new(unsafe {
            (api.new)(c"fortigate-manager".as_ptr(), icon_name.as_ptr(), 0)
        })?;
        let menu = gtk::Menu::new();
        let status = gtk::MenuItem::with_label("FortiGate Manager — checking service…");
        status.set_sensitive(false);
        menu.append(&status);
        let open = gtk::MenuItem::with_label("Open FortiGate Manager");
        let target = window.clone();
        open.connect_activate(move |_| {
            target.show();
            target.present();
        });
        menu.append(&open);
        menu.append(&gtk::SeparatorMenuItem::new());
        let profiles = gtk::Menu::new();
        let vpns = gtk::MenuItem::with_label("VPN connections");
        vpns.set_submenu(Some(&profiles));
        menu.append(&vpns);
        menu.append(&gtk::SeparatorMenuItem::new());
        let quit = gtk::MenuItem::with_label("Quit");
        quit.set_tooltip_text(Some(
            "Exit the client; the VPN service keeps established connections running.",
        ));
        let application = app.clone();
        quit.connect_activate(move |_| application.quit());
        menu.append(&quit);
        menu.show_all();
        unsafe {
            (api.menu)(indicator.as_ptr(), menu.to_glib_none().0);
            (api.title)(indicator.as_ptr(), c"FortiGate Manager".as_ptr());
            (api.status)(indicator.as_ptr(), 1);
        }
        let mut tray = Self {
            api,
            indicator,
            _menu: menu,
            status,
            profiles,
            tx,
            snapshot: vec![],
            available: None,
            icon_name,
        };
        tray.update(&[], false);
        Some(tray)
    }
    pub fn update(&mut self, profiles: &[ProfileView], available: bool) {
        let snapshot = profiles
            .iter()
            .map(|p| {
                (
                    p.profile.id.clone(),
                    p.profile.name.clone(),
                    p.state.clone(),
                )
            })
            .collect::<Vec<_>>();
        if self.available == Some(available) && self.snapshot == snapshot {
            return;
        }
        self.available = Some(available);
        self.snapshot = snapshot;
        let connected = profiles
            .iter()
            .filter(|p| p.state == State::Connected)
            .count();
        let description = if !available {
            "FortiGate Manager — service unavailable".into()
        } else if connected > 0 {
            format!("FortiGate Manager — {connected} VPN connected")
        } else if profiles.iter().any(|p| {
            matches!(
                p.state,
                State::Authenticating | State::AwaitingBrowser | State::Connecting
            )
        }) {
            "FortiGate Manager — connecting…".into()
        } else {
            "FortiGate Manager — disconnected".into()
        };
        self.status.set_label(&description);
        let description =
            CString::new(description).expect("static tray description contains no NUL");
        unsafe {
            (self.api.icon)(
                self.indicator.as_ptr(),
                self.icon_name.as_ptr(),
                description.as_ptr(),
            );
        }
        for child in self.profiles.children() {
            self.profiles.remove(&child);
        }
        if profiles.is_empty() {
            let empty = gtk::MenuItem::with_label("No saved VPNs — open the app to add one");
            empty.set_sensitive(false);
            self.profiles.append(&empty);
        }
        for profile in profiles {
            let item = gtk::MenuItem::with_label(&profile.profile.name);
            let submenu = gtk::Menu::new();
            let state = gtk::MenuItem::with_label(super::status_name(&profile.state));
            state.set_sensitive(false);
            submenu.append(&state);
            let stopping = matches!(
                profile.state,
                State::Connected
                    | State::Authenticating
                    | State::AwaitingBrowser
                    | State::Connecting
            );
            let action = gtk::MenuItem::with_label(if profile.state == State::Connected {
                "Disconnect"
            } else if stopping {
                "Cancel connection"
            } else {
                "Connect"
            });
            action.set_sensitive(available && profile.state != State::Disconnecting);
            let id = profile.profile.id.clone();
            let tx = self.tx.clone();
            action.connect_activate(move |_| {
                let request = if stopping {
                    Request::Disconnect { id: id.clone() }
                } else {
                    Request::Connect { id: id.clone() }
                };
                let _ = tx.send((
                    if stopping {
                        Action::Disconnect
                    } else {
                        Action::Connect
                    },
                    request,
                ));
            });
            submenu.append(&action);
            item.set_submenu(Some(&submenu));
            self.profiles.append(&item);
        }
        self.profiles.show_all();
    }
}
impl Drop for Tray {
    fn drop(&mut self) {
        unsafe {
            (self.api.status)(self.indicator.as_ptr(), 0);
            gtk::glib::gobject_ffi::g_object_unref(self.indicator.as_ptr().cast());
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn runtime_indicator_abi_can_be_resolved_without_a_display() {
        assert!(super::Api::load().is_some());
    }
}
