use crate::{
    backend::{Backend, Tunnel},
    model::{ProfileView, Request, Response, State},
    saml,
    store::Store,
};
use anyhow::{bail, ensure, Context, Result};
use std::{
    collections::HashMap,
    io::{BufRead, BufReader, Read, Write},
    os::{fd::AsRawFd, unix::net::UnixStream},
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};
use zeroize::Zeroizing;

#[derive(Default)]
struct Progress {
    state: State,
    error: Option<String>,
    browser_url: Option<String>,
}
struct Job {
    cancelled: AtomicBool,
    progress: Mutex<Progress>,
}
impl Job {
    fn new(state: State) -> Self {
        Self {
            cancelled: AtomicBool::new(false),
            progress: Mutex::new(Progress {
                state,
                ..Default::default()
            }),
        }
    }
    fn update(&self, state: State, error: Option<String>, url: Option<String>) {
        *self.progress.lock().unwrap() = Progress {
            state,
            error,
            browser_url: url,
        };
    }
}
pub struct Service {
    store: Mutex<Store>,
    backend: Backend,
    jobs: Mutex<HashMap<(u32, String), Arc<Job>>>,
    auth_busy: AtomicBool,
    network: Mutex<()>,
}
fn busy(state: &State) -> bool {
    matches!(
        state,
        State::Authenticating | State::AwaitingBrowser | State::Connecting | State::Disconnecting
    )
}
impl Service {
    pub fn new(store: Store, backend: Backend) -> Arc<Self> {
        Arc::new(Self {
            store: Mutex::new(store),
            backend,
            jobs: Mutex::new(HashMap::new()),
            auth_busy: AtomicBool::new(false),
            network: Mutex::new(()),
        })
    }
    fn job(&self, uid: u32, id: &str) -> Option<Arc<Job>> {
        self.jobs.lock().unwrap().get(&(uid, id.into())).cloned()
    }
    fn snapshot(&self, uid: u32) -> Result<Vec<ProfileView>> {
        let stored = self.store.lock().unwrap().list(uid)?;
        let mut views = Vec::new();
        for saved in stored {
            let mut view = ProfileView {
                profile: saved.profile.clone(),
                has_psk: !saved.psk.0.is_empty(),
                ..Default::default()
            };
            if let Some(job) = self.job(uid, &view.profile.id) {
                let p = job.progress.lock().unwrap();
                view.state = p.state.clone();
                view.error = p.error.clone();
                view.browser_url = p.browser_url.clone();
            }
            if !busy(&view.state) {
                match self.backend.status(&view.profile, uid) {
                    Ok(Tunnel {
                        state,
                        routes,
                        virtual_ips,
                        bytes_in,
                        bytes_out,
                    }) => {
                        if view.state != State::Failed || state == State::Connected {
                            view.state = state;
                        }
                        view.routes = routes;
                        view.virtual_ips = virtual_ips;
                        view.bytes_in = bytes_in;
                        view.bytes_out = bytes_out;
                    }
                    Err(_) => {
                        view.error=Some("Cannot read strongSwan status; check the local service and VICI socket".into());
                    }
                }
            }
            views.push(view);
        }
        Ok(views)
    }
    fn ensure_editable(&self, uid: u32, id: &str) -> Result<()> {
        if let Some(job) = self.job(uid, id) {
            ensure!(
                !busy(&job.progress.lock().unwrap().state),
                "Wait for the current operation before editing this VPN"
            );
        }
        let p = self.store.lock().unwrap().load(uid, id)?;
        ensure!(
            self.backend.status(&p.profile, uid)?.state == State::Disconnected,
            "Disconnect this VPN before editing or deleting it"
        );
        Ok(())
    }
    fn connect(self: &Arc<Self>, uid: u32, id: String) -> Result<()> {
        let _network = self.network.lock().unwrap();
        let stored = self.store.lock().unwrap().load(uid, &id)?;
        if let Some(job) = self.job(uid, &id) {
            let p = job.progress.lock().unwrap();
            ensure!(!busy(&p.state), "This VPN is already connected or busy");
        }
        self.backend.ready()?;
        ensure!(
            self.backend.status(&stored.profile, uid)?.state == State::Disconnected,
            "This VPN already has an active IKE session"
        );
        ensure!(
            self.auth_busy
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok(),
            "Another browser authentication is in progress; finish or cancel it first"
        );
        let job = Arc::new(Job::new(State::Authenticating));
        self.jobs.lock().unwrap().insert((uid, id), job.clone());
        let service = self.clone();
        thread::spawn(move || {
            struct AuthGuard<'a>(&'a AtomicBool);
            impl Drop for AuthGuard<'_> {
                fn drop(&mut self) {
                    self.0.store(false, Ordering::Release);
                }
            }
            let result = (|| -> Result<()> {
                let guard = AuthGuard(&service.auth_busy);
                let session = saml::authenticate(&stored.profile, &job.cancelled, |url| {
                    job.update(State::AwaitingBrowser, None, Some(url))
                })?;
                drop(guard);
                let _network = service.network.lock().unwrap();
                ensure!(
                    !job.cancelled.load(Ordering::Acquire),
                    "Connection cancelled"
                );
                job.update(State::Connecting, None, None);
                service.backend.connect(uid, &stored, &session)?;
                if job.cancelled.load(Ordering::Acquire) {
                    service.backend.disconnect(&stored.profile, uid)?;
                    bail!("Connection cancelled");
                }
                job.update(State::Connected, None, None);
                Ok(())
            })();
            if let Err(error) = result {
                if job.cancelled.load(Ordering::Acquire) {
                    job.update(State::Disconnected, None, None);
                } else {
                    job.update(State::Failed, Some(error.to_string()), None);
                }
            }
        });
        Ok(())
    }
    fn disconnect(&self, uid: u32, id: &str) -> Result<()> {
        let stored = self.store.lock().unwrap().load(uid, id)?;
        let job = if let Some(job) = self.job(uid, id) {
            job
        } else {
            let job = Arc::new(Job::new(State::Disconnected));
            self.jobs
                .lock()
                .unwrap()
                .insert((uid, id.into()), job.clone());
            job
        };
        job.cancelled.store(true, Ordering::Release);
        job.update(State::Disconnecting, None, None);
        let _network = self.network.lock().unwrap();
        match self.backend.disconnect(&stored.profile, uid) {
            Ok(()) => {
                job.update(State::Disconnected, None, None);
                Ok(())
            }
            Err(error) => {
                job.update(State::Failed, Some(error.to_string()), None);
                Err(error)
            }
        }
    }
    pub fn handle(self: &Arc<Self>, uid: u32, request: Request) -> Response {
        let mut saved_id = None;
        let result = (|| -> Result<()> {
            match request {
                Request::List => {}
                Request::Save { profile, psk } => {
                    let _network = self.network.lock().unwrap();
                    if !profile.id.is_empty() {
                        self.ensure_editable(uid, &profile.id)?;
                        let old = self.store.lock().unwrap().load(uid, &profile.id)?;
                        self.backend.disconnect(&old.profile, uid)?;
                    }
                    let id = self.store.lock().unwrap().save(uid, profile, psk)?;
                    self.jobs.lock().unwrap().remove(&(uid, id.clone()));
                    saved_id = Some(id);
                }
                Request::Delete { id } => {
                    let _network = self.network.lock().unwrap();
                    self.ensure_editable(uid, &id)?;
                    let old = self.store.lock().unwrap().load(uid, &id)?;
                    self.backend.disconnect(&old.profile, uid)?;
                    self.store.lock().unwrap().delete(uid, &id)?;
                    self.jobs.lock().unwrap().remove(&(uid, id));
                }
                Request::Connect { id } => self.connect(uid, id)?,
                Request::Disconnect { id } => self.disconnect(uid, &id)?,
            }
            Ok(())
        })();
        match result.and_then(|_| self.snapshot(uid)) {
            Ok(profiles) => Response {
                ok: true,
                profiles,
                saved_id,
                error: None,
            },
            Err(error) => Response {
                ok: false,
                error: Some(error.to_string()),
                ..Default::default()
            },
        }
    }
    pub fn shutdown(&self) {
        let jobs = self
            .jobs
            .lock()
            .unwrap()
            .iter()
            .map(|((uid, id), job)| {
                job.cancelled.store(true, Ordering::Release);
                (*uid, id.clone())
            })
            .collect::<Vec<_>>();
        let mut all = jobs;
        if let Ok(stored) = self.store.lock().unwrap().all_ids() {
            all.extend(stored);
        }
        all.sort();
        all.dedup();
        for (uid, id) in all {
            let _ = self.disconnect(uid, &id);
        }
    }
}

pub fn peer_uid(stream: &UnixStream) -> Result<u32> {
    let mut credentials = std::mem::MaybeUninit::<libc::ucred>::uninit();
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SO_PEERCRED is kernel-supplied identity, never a UID supplied by the UI.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            credentials.as_mut_ptr().cast(),
            &mut len,
        )
    };
    ensure!(
        result == 0 && len as usize == std::mem::size_of::<libc::ucred>(),
        "Cannot authenticate local client"
    );
    Ok(unsafe { credentials.assume_init() }.uid)
}
const LIMIT: u64 = 1_048_576;
pub fn serve_client(mut stream: UnixStream, service: Arc<Service>) -> Result<()> {
    let uid = peer_uid(&stream)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let mut line = Zeroizing::new(String::new());
    BufReader::new(stream.try_clone()?)
        .take(LIMIT + 1)
        .read_line(&mut line)?;
    ensure!(
        line.len() as u64 <= LIMIT && line.ends_with('\n'),
        "Request too large or incomplete"
    );
    let request =
        serde_json::from_str::<Request>(&line).map_err(|_| anyhow::anyhow!("Invalid request"))?;
    let reply = service.handle(uid, request);
    let mut bytes = serde_json::to_vec(&reply)?;
    bytes.push(b'\n');
    stream.write_all(&bytes)?;
    Ok(())
}
pub fn call(socket: &Path, request: &Request) -> Result<Response> {
    let mut stream=UnixStream::connect(socket).context("Cannot reach the local VPN service. Install/start fortigate-manager.socket; sign out and back in after group membership changes.")?;
    stream.set_read_timeout(Some(Duration::from_secs(75)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let mut data = Zeroizing::new(serde_json::to_vec(request)?);
    data.push(b'\n');
    stream.write_all(&data)?;
    let mut line = String::new();
    BufReader::new(stream)
        .take(LIMIT + 1)
        .read_line(&mut line)?;
    ensure!(
        line.len() as u64 <= LIMIT && line.ends_with('\n'),
        "Invalid service response"
    );
    Ok(serde_json::from_str(&line)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn peer_credentials_use_kernel_identity() {
        let (a, _) = UnixStream::pair().unwrap();
        assert_eq!(peer_uid(&a).unwrap(), unsafe { libc::getuid() });
    }
    #[test]
    fn profile_cannot_be_read_by_another_user() {
        let dir = std::env::temp_dir().join(format!("fgr-service-{:032x}", rand::random::<u128>()));
        let service = Service::new(
            Store::new(&dir).unwrap(),
            crate::backend::Backend {
                socket: dir.join("unavailable-vici.sock"),
            },
        );
        let p = crate::model::Profile {
            gateway: "vpn.example.com".into(),
            ..Default::default()
        };
        let r = service.handle(
            1000,
            Request::Save {
                profile: p,
                psk: Some("synthetic-key".into()),
            },
        );
        assert!(r.ok);
        assert!(!serde_json::to_string(&r).unwrap().contains("synthetic-key"));
        assert!(service.handle(1001, Request::List).profiles.is_empty());
        assert!(
            !service
                .handle(
                    1001,
                    Request::Connect {
                        id: r.saved_id.unwrap()
                    }
                )
                .ok
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
}
