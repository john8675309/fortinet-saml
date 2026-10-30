//! Tests the real service API with VICI unavailable; never simulates a VPN.
use fortigate_manager::{
    backend::Backend,
    model::{Profile, Request, State},
    service::{call, serve_client, Service},
    store::Store,
};
use std::{fs, os::unix::net::UnixListener, thread};
#[test]
fn real_socket_stores_profiles_and_reports_unavailable_vici_honestly() {
    let root = std::env::temp_dir().join(format!("fgr-api-test-{:032x}", rand::random::<u128>()));
    fs::create_dir(&root).unwrap();
    let socket = root.join("control.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let service = Service::new(
        Store::new(root.join("state")).unwrap(),
        Backend {
            socket: root.join("missing-vici.sock"),
        },
    );
    let server = thread::spawn(move || {
        for _ in 0..3 {
            let (stream, _) = listener.accept().unwrap();
            serve_client(stream, service.clone()).unwrap();
        }
    });
    let profile = Profile {
        name: "API test".into(),
        gateway: "vpn.example.com".into(),
        ..Default::default()
    };
    let saved = call(
        &socket,
        &Request::Save {
            profile,
            psk: Some("synthetic-api-secret".into()),
        },
    )
    .unwrap();
    assert!(saved.ok);
    assert!(!serde_json::to_string(&saved)
        .unwrap()
        .contains("synthetic-api-secret"));
    assert_eq!(saved.profiles[0].state, State::Disconnected);
    assert!(saved.profiles[0].error.is_some());
    let id = saved.saved_id.unwrap();
    let connect = call(&socket, &Request::Connect { id }).unwrap();
    assert!(!connect.ok);
    let listed = call(&socket, &Request::List).unwrap();
    assert!(listed.ok);
    assert!(listed.profiles[0].routes.is_empty());
    server.join().unwrap();
    fs::remove_dir_all(root).unwrap();
}
