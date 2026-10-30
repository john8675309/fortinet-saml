use fortigate_manager::{
    model::{group_token, proposals, Profile, ProfileView, Request, Response, State},
    service, SOCKET,
};
use gtk::{glib, prelude::*};
use std::{
    cell::{Cell, RefCell},
    collections::HashSet,
    path::PathBuf,
    rc::Rc,
    sync::mpsc,
    thread,
    time::Duration,
};
#[path = "../tray.rs"]
mod tray;

#[derive(Clone, Copy)]
enum Action {
    Refresh,
    Save,
    Delete,
    Connect,
    Disconnect,
}
const GROUPS: [u16; 11] = [1, 2, 5, 14, 15, 16, 17, 18, 19, 20, 21];
#[derive(Clone)]
struct ProposalEditor {
    widget: gtk::Box,
    rows: Rc<RefCell<Vec<(gtk::Box, gtk::ComboBoxText, gtk::ComboBoxText)>>>,
    ike: bool,
}
impl ProposalEditor {
    fn new(ike: bool) -> Self {
        Self {
            widget: gtk::Box::new(gtk::Orientation::Vertical, 8),
            rows: Rc::new(RefCell::new(vec![])),
            ike,
        }
    }
    fn add(&self, encryption: &str, integrity: &str) {
        let row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        let enc = gtk::ComboBoxText::new();
        for (value, title) in [
            ("des", "DES"),
            ("3des", "3DES"),
            ("aes128", "AES128"),
            ("aes128gcm16", "AES128 GCM"),
            ("aes192", "AES192"),
            ("aes256", "AES256"),
            ("aes256gcm16", "AES256 GCM"),
        ] {
            enc.append(Some(value), title);
        }
        let auth = gtk::ComboBoxText::new();
        for (value, title) in [
            ("md5", "MD5"),
            ("sha1", "SHA1"),
            ("sha256", "SHA256"),
            ("sha384", "SHA384"),
            ("sha512", "SHA512"),
        ] {
            auth.append(Some(value), title);
        }
        enc.set_active_id(Some(encryption));
        auth.set_active_id(Some(integrity));
        enc.set_hexpand(true);
        auth.set_hexpand(true);
        if !self.ike {
            let target = auth.clone();
            enc.connect_changed(move |e| {
                target.set_sensitive(!e.active_id().map(|s| s.contains("gcm")).unwrap_or(false));
            });
            auth.set_sensitive(!encryption.contains("gcm"));
        }
        let remove = gtk::Button::with_label("−");
        row.pack_start(&enc, true, true, 0);
        row.pack_start(&auth, true, true, 0);
        row.pack_end(&remove, false, false, 0);
        self.widget.pack_start(&row, false, false, 0);
        self.rows.borrow_mut().push((row.clone(), enc, auth));
        let rows = Rc::downgrade(&self.rows);
        let container = self.widget.clone();
        remove.connect_clicked(move |_| {
            if let Some(rows) = rows.upgrade() {
                rows.borrow_mut().retain(|(r, _, _)| r != &row);
                container.remove(&row);
            }
        });
        self.widget.show_all();
    }
    fn fill(&self, raw: &str) {
        for child in self.widget.children() {
            self.widget.remove(&child);
        }
        self.rows.borrow_mut().clear();
        let mut unique = vec![];
        for proposal in raw.split(',') {
            let tokens = proposal.split('-').collect::<Vec<_>>();
            let encryption = tokens.first().copied().unwrap_or("aes128");
            let integrity = tokens
                .iter()
                .find_map(|t| {
                    let t = t.strip_prefix("prf").unwrap_or(t);
                    if ["md5", "sha1", "sha256", "sha384", "sha512"].contains(&t) {
                        Some(t)
                    } else {
                        None
                    }
                })
                .unwrap_or("sha256");
            if !unique.contains(&(encryption, integrity)) {
                unique.push((encryption, integrity));
                self.add(encryption, integrity);
            }
        }
    }
    fn values(&self) -> Vec<(String, String)> {
        self.rows
            .borrow()
            .iter()
            .map(|(_, e, a)| {
                (
                    e.active_id().map(|s| s.to_string()).unwrap_or_default(),
                    a.active_id().map(|s| s.to_string()).unwrap_or_default(),
                )
            })
            .collect()
    }
}
struct Editor {
    name: gtk::Entry,
    description: gtk::Entry,
    gateway: gtk::Entry,
    psk: gtk::Entry,
    saml: gtk::SpinButton,
    callback: gtk::SpinButton,
    ike_port: gtk::SpinButton,
    local: gtk::Entry,
    remote: gtk::Entry,
    phase1: ProposalEditor,
    phase2: ProposalEditor,
    dh: Vec<(u16, gtk::CheckButton)>,
    pfs: gtk::CheckButton,
    pfs_group: gtk::ComboBoxText,
    ike_life: gtk::SpinButton,
    esp_life: gtk::SpinButton,
    dpd: gtk::SpinButton,
    dpd_on: gtk::CheckButton,
    encap: gtk::CheckButton,
    lan: gtk::CheckButton,
    replay: gtk::CheckButton,
    kb_enabled: gtk::CheckButton,
    kb: gtk::SpinButton,
    ca: gtk::TextView,
}
impl Editor {
    fn read(&self, id: Option<String>) -> anyhow::Result<Profile> {
        let buffer = self.ca.buffer().unwrap();
        let groups = self
            .dh
            .iter()
            .filter(|(_, b)| b.is_active())
            .map(|(g, _)| *g)
            .collect::<Vec<_>>();
        let pfs = if self.pfs.is_active() {
            vec![self
                .pfs_group
                .active_id()
                .and_then(|s| s.parse().ok())
                .unwrap_or(20)]
        } else {
            vec![]
        };
        Ok(Profile {
            id: id.unwrap_or_default(),
            name: self.name.text().trim().into(),
            description: self.description.text().into(),
            gateway: self.gateway.text().trim().into(),
            saml_port: self.saml.value_as_int() as u16,
            callback_port: self.callback.value_as_int() as u16,
            ike_port: self.ike_port.value_as_int() as u16,
            local_id: self.local.text().trim().into(),
            remote_id: self.remote.text().trim().into(),
            ike_proposals: proposals(&self.phase1.values(), &groups, true)?,
            esp_proposals: proposals(&self.phase2.values(), &pfs, false)?,
            ike_lifetime: self.ike_life.value_as_int() as u32,
            esp_lifetime: self.esp_life.value_as_int() as u32,
            esp_lifetime_kb: if self.kb_enabled.is_active() {
                self.kb.value() as u64
            } else {
                0
            },
            replay_detection: self.replay.is_active(),
            enable_local_lan: self.lan.is_active(),
            dpd_seconds: if self.dpd_on.is_active() {
                self.dpd.value_as_int() as u32
            } else {
                0
            },
            force_encapsulation: self.encap.is_active(),
            ca_certificate_pem: buffer
                .text(&buffer.start_iter(), &buffer.end_iter(), false)
                .unwrap_or_default()
                .to_string(),
        })
    }
    fn fill(&self, p: &Profile, has_key: bool) {
        self.name.set_text(&p.name);
        self.description.set_text(&p.description);
        self.gateway.set_text(&p.gateway);
        self.psk.set_text("");
        self.psk.set_placeholder_text(Some(if has_key {
            "Saved — leave blank to keep"
        } else {
            "Enter your VPN pre-shared key"
        }));
        self.saml.set_value(p.saml_port as f64);
        self.callback.set_value(p.callback_port as f64);
        self.ike_port.set_value(p.ike_port as f64);
        self.local.set_text(&p.local_id);
        self.remote.set_text(&p.remote_id);
        self.phase1.fill(&p.ike_proposals);
        self.phase2.fill(&p.esp_proposals);
        let tokens = p.ike_proposals.split([',', '-']).collect::<Vec<_>>();
        for (g, b) in &self.dh {
            b.set_active(tokens.contains(&group_token(*g).unwrap()));
        }
        let pfs = GROUPS.iter().find(|g| {
            p.esp_proposals
                .split([',', '-'])
                .any(|t| Some(t) == group_token(**g))
        });
        self.pfs.set_active(pfs.is_some());
        self.pfs_group
            .set_active_id(Some(&pfs.copied().unwrap_or(20).to_string()));
        self.ike_life.set_value(p.ike_lifetime as f64);
        self.esp_life.set_value(p.esp_lifetime as f64);
        self.dpd.set_value(p.dpd_seconds as f64);
        self.dpd_on.set_active(p.dpd_seconds > 0);
        self.encap.set_active(p.force_encapsulation);
        self.lan.set_active(p.enable_local_lan);
        self.replay.set_active(p.replay_detection);
        self.kb_enabled.set_active(p.esp_lifetime_kb > 0);
        self.kb.set_value(if p.esp_lifetime_kb > 0 {
            p.esp_lifetime_kb as f64
        } else {
            5120.0
        });
        self.ca.buffer().unwrap().set_text(&p.ca_certificate_pem);
    }
}
struct Ui {
    profiles: RefCell<Vec<ProfileView>>,
    current: RefCell<Option<String>>,
    new_profile: Cell<bool>,
    updating: Cell<bool>,
    opened: RefCell<HashSet<String>>,
    list: gtk::ListBox,
    sidebar_snapshot: RefCell<Vec<(String, String, String, State)>>,
    editor: Editor,
    title: gtk::Label,
    state: gtk::Label,
    message: gtk::Label,
    routes: gtk::TextView,
    details: gtk::Label,
    connect: gtk::Button,
    browser: gtk::Button,
    delete: gtk::Button,
    save: gtk::Button,
    notebook: gtk::Notebook,
    service: gtk::Label,
    tx: mpsc::Sender<(Action, Request)>,
    poll_pending: Cell<bool>,
    tray: RefCell<Option<tray::Tray>>,
}
fn label(text: &str, class: &str) -> gtk::Label {
    let l = gtk::Label::new(Some(text));
    l.set_xalign(0.0);
    l.style_context().add_class(class);
    l
}
fn entry(placeholder: &str) -> gtk::Entry {
    let e = gtk::Entry::new();
    e.set_hexpand(true);
    e.set_placeholder_text(Some(placeholder));
    e
}
fn spin(min: f64, max: f64) -> gtk::SpinButton {
    gtk::SpinButton::with_range(min, max, 1.0)
}
fn row(grid: &gtk::Grid, index: i32, title: &str, widget: &impl IsA<gtk::Widget>) {
    let l = label(title, "field-label");
    grid.attach(&l, 0, index, 1, 1);
    grid.attach(widget, 1, index, 1, 1);
}
fn spacing(b: &impl IsA<gtk::Widget>, n: i32) {
    b.set_margin_start(n);
    b.set_margin_end(n);
    b.set_margin_top(n);
    b.set_margin_bottom(n);
}
fn status_name(s: &State) -> &'static str {
    match s {
        State::Disconnected => "Disconnected",
        State::Authenticating => "Preparing sign-in…",
        State::AwaitingBrowser => "Complete sign-in in your browser",
        State::Connecting => "Connecting…",
        State::Connected => "Connected",
        State::Disconnecting => "Disconnecting…",
        State::Failed => "Connection failed",
    }
}
fn busy(s: &State) -> bool {
    matches!(
        s,
        State::Authenticating | State::AwaitingBrowser | State::Connecting | State::Disconnecting
    )
}
impl Ui {
    fn selected(&self) -> Option<ProfileView> {
        let id = self.current.borrow();
        self.profiles
            .borrow()
            .iter()
            .find(|p| Some(&p.profile.id) == id.as_ref())
            .cloned()
    }
    fn send(&self, action: Action, request: Request) {
        if self.tx.send((action, request)).is_err() {
            self.message
                .set_text("The connection worker stopped. Restart the application.");
        }
    }
    fn refresh(&self) {
        if !self.poll_pending.replace(true) {
            self.send(Action::Refresh, Request::List);
        }
    }
    fn select(&self, id: String) {
        *self.current.borrow_mut() = Some(id);
        self.new_profile.set(false);
        if let Some(view) = self.selected() {
            self.editor.fill(&view.profile, view.has_psk);
            self.title.set_text(&view.profile.name);
        }
        self.render_details();
    }
    fn render_details(&self) {
        let buffer = self.routes.buffer().unwrap();
        if let Some(view) = self.selected() {
            self.state.set_text(status_name(&view.state));
            self.state.style_context().remove_class("connected");
            if view.state == State::Connected {
                self.state.style_context().add_class("connected");
            }
            self.connect
                .set_sensitive(view.state != State::Disconnecting);
            self.connect.set_label(if view.state == State::Connected {
                "Disconnect"
            } else if busy(&view.state) {
                "Cancel connection"
            } else {
                "Connect"
            });
            self.save
                .set_sensitive(!busy(&view.state) && view.state != State::Connected);
            self.delete
                .set_sensitive(!busy(&view.state) && view.state != State::Connected);
            self.browser.set_visible(view.browser_url.is_some());
            let ips = if view.virtual_ips.is_empty() {
                "—".into()
            } else {
                view.virtual_ips.join(", ")
            };
            self.details.set_text(&format!(
                "VPN address: {ips}\nReceived: {} bytes    Sent: {} bytes\n{} VPN networks",
                view.bytes_in,
                view.bytes_out,
                view.routes.len()
            ));
            let route_text = if view.routes.is_empty() {
                "Networks will appear after the gateway advertises them.".into()
            } else {
                view.routes.join("\n")
            };
            if buffer
                .text(&buffer.start_iter(), &buffer.end_iter(), false)
                .as_deref()
                != Some(route_text.as_str())
            {
                buffer.set_text(&route_text);
            }
            if let Some(error) = view.error {
                self.message.set_text(&error);
            }
        } else {
            self.state.set_text("Save this profile to connect");
            self.connect.set_sensitive(false);
            self.save.set_sensitive(true);
            self.delete.set_sensitive(false);
            self.browser.hide();
            self.details
                .set_text("Routes are discovered from your VPN gateway.");
            buffer.set_text("No active connection.");
        }
    }
    fn apply(&self, action: Action, result: Result<Response, String>) {
        if matches!(action, Action::Refresh) {
            self.poll_pending.set(false);
        }
        let response = match result {
            Ok(r) => r,
            Err(e) => {
                if let Some(tray) = self.tray.borrow_mut().as_mut() {
                    tray.update(&self.profiles.borrow(), false);
                }
                self.service.set_text("Service unavailable");
                self.message.set_text(&e);
                return;
            }
        };
        self.service.set_text("Local service connected");
        if !response.ok {
            self.message
                .set_text(response.error.as_deref().unwrap_or("Operation failed"));
            return;
        }
        if !matches!(action, Action::Refresh) {
            self.message.set_text(match action {
                Action::Save => "VPN profile saved.",
                Action::Delete => "VPN profile deleted.",
                Action::Connect => "Starting browser authentication…",
                Action::Disconnect => "VPN disconnected.",
                _ => "",
            });
        }
        let previous_state = self.selected().map(|p| p.state);
        *self.profiles.borrow_mut() = response.profiles;
        if let Some(tray) = self.tray.borrow_mut().as_mut() {
            tray.update(&self.profiles.borrow(), true);
        }
        if let Some(id) = response.saved_id {
            *self.current.borrow_mut() = Some(id);
            self.new_profile.set(false);
            self.editor.psk.set_text("");
        }
        if matches!(action, Action::Delete) {
            *self.current.borrow_mut() = None;
            self.new_profile.set(false);
        }
        let selected_exists = self.selected().is_some();
        if !selected_exists && !self.new_profile.get() {
            *self.current.borrow_mut() =
                self.profiles.borrow().first().map(|v| v.profile.id.clone());
            if self.current.borrow().is_none() {
                self.new_profile.set(true);
                self.editor.fill(&Profile::default(), false);
            }
        }
        let sidebar_snapshot = self
            .profiles
            .borrow()
            .iter()
            .map(|v| {
                (
                    v.profile.id.clone(),
                    v.profile.name.clone(),
                    v.profile.gateway.clone(),
                    v.state.clone(),
                )
            })
            .collect::<Vec<_>>();
        if *self.sidebar_snapshot.borrow() != sidebar_snapshot {
            self.updating.set(true);
            for widget in self.list.children() {
                self.list.remove(&widget);
            }
            let selected = self.current.borrow().clone();
            for view in self.profiles.borrow().iter() {
                let row = gtk::ListBoxRow::new();
                let content = gtk::Box::new(gtk::Orientation::Vertical, 5);
                spacing(&content, 12);
                content.pack_start(&label(&view.profile.name, "profile-name"), false, false, 0);
                let gateway = label(&view.profile.gateway, "muted");
                gateway.set_ellipsize(gtk::pango::EllipsizeMode::End);
                content.pack_start(&gateway, false, false, 0);
                content.pack_start(&label(status_name(&view.state), "small"), false, false, 0);
                row.add(&content);
                self.list.add(&row);
                if selected.as_deref() == Some(&view.profile.id) {
                    self.list.select_row(Some(&row));
                }
            }
            self.list.show_all();
            self.updating.set(false);
            *self.sidebar_snapshot.borrow_mut() = sidebar_snapshot;
        }
        if matches!(action, Action::Save | Action::Delete) || !selected_exists {
            if let Some(view) = self.selected() {
                self.editor.fill(&view.profile, view.has_psk);
                self.title.set_text(&view.profile.name);
                if !selected_exists && view.state == State::Connected {
                    self.notebook.set_current_page(Some(1));
                }
            }
        }
        for view in self.profiles.borrow().iter() {
            if let Some(url) = &view.browser_url {
                if self.opened.borrow_mut().insert(url.clone()) {
                    let url = url.clone();
                    thread::spawn(move || {
                        let _ = webbrowser::open(&url);
                    });
                }
            }
        }
        self.render_details();
        if matches!(action, Action::Refresh) {
            if let Some(view) = self.selected() {
                if previous_state.as_ref() != Some(&view.state) && view.error.is_none() {
                    if view.state == State::Connected {
                        self.message.set_text(
                            "Connected. Company traffic follows the gateway’s advertised networks.",
                        );
                    } else if view.state == State::Disconnected {
                        self.message.set_text("VPN disconnected.");
                    }
                }
            }
        }
    }
}
fn build(app: &gtk::Application, socket: PathBuf, start_hidden: bool) {
    if let Some(settings) = gtk::Settings::default() {
        settings.set_property("gtk-application-prefer-dark-theme", true);
        settings.set_property("gtk-theme-name", "Adwaita");
    }
    let window = gtk::ApplicationWindow::new(app);
    window.set_title("FortiGate Manager");
    window.set_default_size(1120, 780);
    window.set_size_request(920, 640);
    let header = gtk::HeaderBar::new();
    header.set_show_close_button(true);
    header.set_title(Some("FortiGate Manager"));
    header.set_subtitle(Some("Your VPN workspace"));
    window.set_titlebar(Some(&header));
    let root = gtk::Box::new(gtk::Orientation::Horizontal, 0);
    window.add(&root);
    let sidebar = gtk::Box::new(gtk::Orientation::Vertical, 16);
    sidebar.set_width_request(255);
    spacing(&sidebar, 18);
    sidebar.style_context().add_class("sidebar");
    root.pack_start(&sidebar, false, false, 0);
    sidebar.pack_start(&label("CONNECTIONS", "eyebrow"), false, false, 0);
    let new = gtk::Button::with_label("＋  New VPN");
    sidebar.pack_start(&new, false, false, 0);
    let list = gtk::ListBox::new();
    list.set_selection_mode(gtk::SelectionMode::Single);
    list.style_context().add_class("profiles");
    let scroll = gtk::ScrolledWindow::new(None::<&gtk::Adjustment>, None::<&gtk::Adjustment>);
    scroll.add(&list);
    sidebar.pack_start(&scroll, true, true, 0);
    let service_label = label("Connecting to local service…", "small");
    service_label.set_line_wrap(true);
    sidebar.pack_end(&service_label, false, false, 0);
    let main = gtk::Box::new(gtk::Orientation::Vertical, 16);
    spacing(&main, 26);
    root.pack_start(&main, true, true, 0);
    main.pack_start(
        &label("FORTIGATE · IKEv2 · SAML", "eyebrow"),
        false,
        false,
        0,
    );
    let title = label("New VPN", "page-title");
    main.pack_start(&title, false, false, 0);
    let top = gtk::Box::new(gtk::Orientation::Horizontal, 12);
    let state = label("Save this profile to connect", "state");
    top.pack_start(&state, true, true, 0);
    let connect = gtk::Button::with_label("Connect");
    connect.style_context().add_class("suggested-action");
    top.pack_end(&connect, false, false, 0);
    main.pack_start(&top, false, false, 0);
    let message = label(
        "Create a profile, then sign in using your browser.",
        "message",
    );
    message.set_line_wrap(true);
    message.set_selectable(true);
    main.pack_start(&message, false, false, 0);
    let notebook = gtk::Notebook::new();
    main.pack_start(&notebook, true, true, 0);
    let form = gtk::Box::new(gtk::Orientation::Vertical, 18);
    spacing(&form, 20);
    let grid = gtk::Grid::new();
    grid.set_row_spacing(14);
    grid.set_column_spacing(18);
    let pfs_group = gtk::ComboBoxText::new();
    for group in GROUPS {
        pfs_group.append(Some(&group.to_string()), &format!("Group {group}"));
    }
    let editor = Editor {
        name: entry("Work VPN"),
        description: entry("Optional description"),
        gateway: entry("vpn.example.com"),
        psk: entry("Pre-shared key"),
        saml: spin(1.0, 65535.0),
        callback: spin(1024.0, 65535.0),
        ike_port: spin(1.0, 65535.0),
        local: entry("Optional — use gateway defaults"),
        remote: entry("Optional — use gateway defaults"),
        phase1: ProposalEditor::new(true),
        phase2: ProposalEditor::new(false),
        dh: GROUPS
            .iter()
            .map(|g| (*g, gtk::CheckButton::with_label(&g.to_string())))
            .collect(),
        pfs: gtk::CheckButton::with_label("Perfect forward secrecy (PFS)"),
        pfs_group,
        ike_life: spin(300.0, 31_536_000.0),
        esp_life: spin(300.0, 31_536_000.0),
        dpd: spin(1.0, 3600.0),
        dpd_on: gtk::CheckButton::with_label("Dead peer detection"),
        encap: gtk::CheckButton::with_label("Force UDP encapsulation"),
        lan: gtk::CheckButton::with_label("Enable local LAN access"),
        replay: gtk::CheckButton::with_label("Enable replay detection"),
        kb_enabled: gtk::CheckButton::with_label("Also limit by transferred kilobytes"),
        kb: spin(1.0, 1_099_511_627_776.0),
        ca: gtk::TextView::new(),
    };
    editor.psk.set_visibility(false);
    editor.psk.set_input_purpose(gtk::InputPurpose::Password);
    row(&grid, 0, "Profile name", &editor.name);
    row(&grid, 1, "Description", &editor.description);
    row(&grid, 2, "VPN gateway", &editor.gateway);
    row(&grid, 3, "SAML HTTPS port", &editor.saml);
    row(&grid, 4, "Pre-shared key", &editor.psk);
    form.pack_start(&grid, false, false, 0);
    let note = label(
        "Sign-in and MFA happen in your browser. Network routes come from the gateway.",
        "muted",
    );
    note.set_line_wrap(true);
    form.pack_start(&note, false, false, 0);
    let advanced = gtk::Expander::new(Some("Advanced connection settings"));
    let advanced_box = gtk::Box::new(gtk::Orientation::Vertical, 12);
    advanced_box.set_margin_top(14);
    let ag = gtk::Grid::new();
    ag.set_row_spacing(12);
    ag.set_column_spacing(18);
    row(
        &ag,
        0,
        "VPN settings",
        &label("IKEv2 · Mode Config · UDP", "muted"),
    );
    row(&ag, 1, "IKE UDP port", &editor.ike_port);
    row(&ag, 2, "Browser callback port", &editor.callback);
    row(&ag, 3, "Phase 1 proposals", &editor.phase1.widget);
    let add1 = gtk::Button::with_label("Add phase 1 proposal");
    row(&ag, 4, "", &add1);
    let pe = editor.phase1.clone();
    add1.connect_clicked(move |_| pe.add("aes256", "sha256"));
    let dh = gtk::Grid::new();
    dh.set_row_spacing(6);
    dh.set_column_spacing(10);
    for (i, (_, button)) in editor.dh.iter().enumerate() {
        dh.attach(button, (i % 6) as i32, (i / 6) as i32, 1, 1);
    }
    row(&ag, 5, "DH groups", &dh);
    row(&ag, 6, "Phase 1 key life (sec)", &editor.ike_life);
    row(&ag, 7, "Local IKE identity", &editor.local);
    row(&ag, 8, "Remote IKE identity", &editor.remote);
    row(&ag, 9, "Peer detection", &editor.dpd_on);
    row(&ag, 10, "DPD interval (seconds)", &editor.dpd);
    row(
        &ag,
        11,
        "NAT traversal",
        &label("Automatic (UDP 4500 when needed)", "muted"),
    );
    row(&ag, 12, "", &editor.encap);
    row(&ag, 13, "Local network", &editor.lan);
    row(&ag, 14, "Phase 2 proposals", &editor.phase2.widget);
    let add2 = gtk::Button::with_label("Add phase 2 proposal");
    row(&ag, 15, "", &add2);
    let pe = editor.phase2.clone();
    add2.connect_clicked(move |_| pe.add("aes256", "sha256"));
    row(&ag, 16, "Phase 2 key life (sec)", &editor.esp_life);
    row(&ag, 17, "Byte lifetime", &editor.kb_enabled);
    row(&ag, 18, "Kilobytes", &editor.kb);
    row(&ag, 19, "Replay protection", &editor.replay);
    row(&ag, 20, "Key exchange", &editor.pfs);
    row(&ag, 21, "PFS DH group", &editor.pfs_group);
    let spin = editor.dpd.clone();
    editor
        .dpd_on
        .connect_toggled(move |b| spin.set_sensitive(b.is_active()));
    let spin = editor.kb.clone();
    editor
        .kb_enabled
        .connect_toggled(move |b| spin.set_sensitive(b.is_active()));
    let combo = editor.pfs_group.clone();
    editor
        .pfs
        .connect_toggled(move |b| combo.set_sensitive(b.is_active()));
    advanced_box.pack_start(&ag, false, false, 0);
    advanced_box.pack_start(
        &label(
            "Additional SAML CA certificate (PEM, optional)",
            "field-label",
        ),
        false,
        false,
        0,
    );
    editor.ca.set_monospace(true);
    editor.ca.set_wrap_mode(gtk::WrapMode::WordChar);
    editor.ca.set_height_request(100);
    advanced_box.pack_start(&editor.ca, false, false, 0);
    advanced.add(&advanced_box);
    form.pack_start(&advanced, false, false, 0);
    let fs = gtk::ScrolledWindow::new(None::<&gtk::Adjustment>, None::<&gtk::Adjustment>);
    fs.add(&form);
    notebook.append_page(&fs, Some(&gtk::Label::new(Some("Profile"))));
    let connection = gtk::Box::new(gtk::Orientation::Vertical, 16);
    spacing(&connection, 20);
    let details = label("Routes are discovered from your VPN gateway.", "details");
    details.set_selectable(true);
    connection.pack_start(&details, false, false, 0);
    let browser = gtk::Button::with_label("Open browser again");
    connection.pack_start(&browser, false, false, 0);
    connection.pack_start(&label("ADVERTISED NETWORKS", "eyebrow"), false, false, 0);
    let routes = gtk::TextView::new();
    routes.set_editable(false);
    routes.set_cursor_visible(false);
    routes.set_monospace(true);
    spacing(&routes, 12);
    let rs = gtk::ScrolledWindow::new(None::<&gtk::Adjustment>, None::<&gtk::Adjustment>);
    rs.add(&routes);
    connection.pack_start(&rs, true, true, 0);
    notebook.append_page(&connection, Some(&gtk::Label::new(Some("Connection"))));
    let footer = gtk::Box::new(gtk::Orientation::Horizontal, 10);
    let delete = gtk::Button::with_label("Delete profile");
    delete.style_context().add_class("destructive-action");
    let save = gtk::Button::with_label("Save profile");
    footer.pack_start(&delete, false, false, 0);
    footer.pack_end(&save, false, false, 0);
    main.pack_end(&footer, false, false, 0);
    let (tx, rx) = mpsc::channel::<(Action, Request)>();
    let (reply_tx, replies) = mpsc::channel();
    thread::spawn(move || {
        while let Ok((action, request)) = rx.recv() {
            let result = service::call(&socket, &request).map_err(|e| e.to_string());
            if reply_tx.send((action, result)).is_err() {
                break;
            }
        }
    });
    editor.fill(&Profile::default(), false);
    let ui = Rc::new(Ui {
        profiles: RefCell::new(vec![]),
        current: RefCell::new(None),
        new_profile: Cell::new(false),
        updating: Cell::new(false),
        opened: RefCell::new(HashSet::new()),
        list,
        sidebar_snapshot: RefCell::new(vec![]),
        editor,
        title,
        state,
        message,
        routes,
        details,
        connect,
        browser,
        delete,
        save,
        notebook,
        service: service_label,
        tx,
        poll_pending: Cell::new(false),
        tray: RefCell::new(None),
    });
    let weak = Rc::downgrade(&ui);
    ui.list.connect_row_selected(move |_, row| {
        if let (Some(ui), Some(row)) = (weak.upgrade(), row) {
            if !ui.updating.get() {
                let id = ui
                    .profiles
                    .borrow()
                    .get(row.index() as usize)
                    .map(|p| p.profile.id.clone());
                if let Some(id) = id {
                    ui.select(id);
                }
            }
        }
    });
    let weak = Rc::downgrade(&ui);
    new.connect_clicked(move |_| {
        if let Some(ui) = weak.upgrade() {
            ui.new_profile.set(true);
            *ui.current.borrow_mut() = None;
            ui.updating.set(true);
            ui.list.unselect_all();
            ui.updating.set(false);
            ui.editor.fill(&Profile::default(), false);
            ui.title.set_text("New VPN");
            ui.message
                .set_text("Enter your gateway and SAML settings. Your browser handles sign-in.");
            ui.notebook.set_current_page(Some(0));
            ui.render_details();
        }
    });
    let weak = Rc::downgrade(&ui);
    ui.save.connect_clicked(move |_| {
        if let Some(ui) = weak.upgrade() {
            let profile = match ui.editor.read(ui.current.borrow().clone()).and_then(|p| {
                p.validate()?;
                Ok(p)
            }) {
                Ok(p) => p,
                Err(e) => {
                    ui.message.set_text(&e.to_string());
                    return;
                }
            };
            let psk = ui.editor.psk.text().to_string();
            ui.send(
                Action::Save,
                Request::Save {
                    profile,
                    psk: if psk.is_empty() { None } else { Some(psk) },
                },
            );
        }
    });
    let weak = Rc::downgrade(&ui);
    ui.connect.connect_clicked(move |_| {
        if let Some(ui) = weak.upgrade() {
            if let Some(view) = ui.selected() {
                ui.notebook.set_current_page(Some(1));
                ui.message.set_text("Working…");
                if view.state == State::Connected || busy(&view.state) {
                    ui.send(
                        Action::Disconnect,
                        Request::Disconnect {
                            id: view.profile.id,
                        },
                    );
                } else {
                    ui.send(
                        Action::Connect,
                        Request::Connect {
                            id: view.profile.id,
                        },
                    );
                }
            }
        }
    });
    let weak = Rc::downgrade(&ui);
    ui.browser.connect_clicked(move |_| {
        if let Some(ui) = weak.upgrade() {
            if let Some(url) = ui.selected().and_then(|p| p.browser_url) {
                thread::spawn(move || {
                    let _ = webbrowser::open(&url);
                });
            }
        }
    });
    let weak = Rc::downgrade(&ui);
    let parent = window.clone();
    ui.delete.connect_clicked(move |_| {
        if let Some(ui) = weak.upgrade() {
            if let Some(view) = ui.selected() {
                let dialog = gtk::MessageDialog::new(
                    Some(&parent),
                    gtk::DialogFlags::MODAL,
                    gtk::MessageType::Question,
                    gtk::ButtonsType::None,
                    &format!("Delete “{}”?", view.profile.name),
                );
                dialog.add_button("Cancel", gtk::ResponseType::Cancel);
                dialog.add_button("Delete profile", gtk::ResponseType::Accept);
                let tx = ui.tx.clone();
                dialog.connect_response(move |d, response| {
                    if response == gtk::ResponseType::Accept {
                        let _ = tx.send((
                            Action::Delete,
                            Request::Delete {
                                id: view.profile.id.clone(),
                            },
                        ));
                    }
                    d.close();
                });
                dialog.show_all();
            }
        }
    });
    let provider = gtk::CssProvider::new();
    if provider
        .load_from_data(include_bytes!("../../assets/style.css"))
        .is_err()
    {
        eprintln!("Could not load the application theme; using the dark system theme.");
    }
    if let Some(screen) = gtk::prelude::GtkWindowExt::screen(&window) {
        gtk::StyleContext::add_provider_for_screen(
            &screen,
            &provider,
            gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
        );
    }
    *ui.tray.borrow_mut() = tray::Tray::new(&window, app, ui.tx.clone());
    let has_tray = ui.tray.borrow().is_some();
    if has_tray {
        window.connect_delete_event(|window, _| {
            window.hide();
            glib::Propagation::Stop
        });
    }
    if start_hidden && has_tray {
        root.show_all();
        header.show_all();
    } else {
        window.show_all();
    }
    ui.render_details();
    ui.refresh();
    let timer_ui = ui.clone();
    glib::timeout_add_local(Duration::from_millis(100), move || {
        while let Ok((action, result)) = replies.try_recv() {
            timer_ui.apply(action, result);
        }
        glib::ControlFlow::Continue
    });
    let poll_ui = ui.clone();
    glib::timeout_add_local(Duration::from_secs(2), move || {
        poll_ui.refresh();
        glib::ControlFlow::Continue
    });
}
fn main() {
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("Run the GUI as your normal desktop user, without sudo.");
        std::process::exit(1);
    }
    let args = std::env::args().collect::<Vec<_>>();
    let socket = args
        .iter()
        .position(|s| s == "--socket")
        .and_then(|i| args.get(i + 1))
        .cloned()
        .unwrap_or_else(|| SOCKET.into());
    let app_id = if socket == SOCKET {
        "com.local.FortiGateManager"
    } else {
        "com.local.FortiGateManager.Development"
    };
    let app = gtk::Application::new(Some(app_id), Default::default());
    let quit = gtk::gio::SimpleAction::new("quit", None);
    let weak = app.downgrade();
    quit.connect_activate(move |_, _| {
        if let Some(app) = weak.upgrade() {
            app.quit();
        }
    });
    app.add_action(&quit);
    let start_hidden = !args.iter().any(|arg| arg == "--show");
    app.connect_activate(move |app| {
        if let Some(window) = app.windows().first() {
            window.show();
            window.present();
        } else {
            build(app, PathBuf::from(&socket), start_hidden);
        }
    });
    app.run_with_args::<&str>(&[]);
}
