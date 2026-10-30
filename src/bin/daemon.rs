use anyhow::{bail, ensure, Result};
use fortigate_manager::{
    backend::default_backend,
    service::{serve_client, Service},
    store::Store,
};
use std::{
    env,
    os::{fd::FromRawFd, unix::net::UnixListener},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};

fn main() -> Result<()> {
    let mut args = env::args().skip(1);
    let mut state = PathBuf::from("/var/lib/fortigate-manager");
    let mut backend = default_backend();
    let mut check = false;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--check" => check = true,
            "--state-dir" => {
                state = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("Missing state directory"))?
                    .into()
            }
            "--vici" => {
                backend.socket = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("Missing VICI path"))?
                    .into()
            }
            "--help" => {
                println!("fortigate-managerd [--state-dir PATH] [--vici PATH]\nStart through fortigate-manager.socket.");
                return Ok(());
            }
            _ => bail!("Unknown service option"),
        }
    }
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "Start the service through fortigate-manager.socket"
    );
    if check {
        backend.ready()?;
        println!("strongSwan and advertised-route support are ready");
        return Ok(());
    }
    let activated = env::var("LISTEN_FDS").ok().as_deref() == Some("1")
        && env::var("LISTEN_PID")
            .ok()
            .and_then(|s| s.parse::<u32>().ok())
            == Some(std::process::id());
    ensure!(
        activated,
        "Start the service through fortigate-manager.socket"
    );
    unsafe {
        libc::umask(0o077);
    }
    let service = Service::new(Store::new(state)?, backend);
    let listener = unsafe { UnixListener::from_raw_fd(3) };
    listener.set_nonblocking(true)?;
    let stopped = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGTERM, stopped.clone())?;
    signal_hook::flag::register(signal_hook::consts::SIGINT, stopped.clone())?;
    let clients = Arc::new(AtomicUsize::new(0));
    eprintln!("FortiGate Manager local service ready");
    while !stopped.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, _)) => {
                if clients.fetch_add(1, Ordering::AcqRel) >= 32 {
                    clients.fetch_sub(1, Ordering::AcqRel);
                    continue;
                }
                let service = service.clone();
                let clients = clients.clone();
                thread::spawn(move || {
                    let _ = serve_client(stream, service);
                    clients.fetch_sub(1, Ordering::AcqRel);
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(50))
            }
            Err(e) => return Err(e.into()),
        }
    }
    service.shutdown();
    Ok(())
}
