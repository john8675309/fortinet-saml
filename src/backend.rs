use crate::{
    model::{Profile, State},
    saml::Session,
    store::Stored,
    vici::{self, kv, list, section, Message, Value},
};
use anyhow::{ensure, Result};
use std::{
    net::ToSocketAddrs,
    path::{Path, PathBuf},
    time::Duration,
};
use zeroize::Zeroize;

#[derive(Clone)]
pub struct Backend {
    pub socket: PathBuf,
}
#[derive(Default)]
pub struct Tunnel {
    pub state: State,
    pub routes: Vec<String>,
    pub virtual_ips: Vec<String>,
    pub bytes_in: u64,
    pub bytes_out: u64,
}
impl Backend {
    fn command(&self, operation: &str, message: Message) -> Result<()> {
        let mut reply = vici::request(
            &self.socket,
            operation,
            message,
            None,
            Duration::from_secs(65),
        )?;
        let success = command_succeeded(operation, &reply.response);
        // Never propagate arbitrary daemon errors that might echo credentials.
        for (_, value) in &mut reply.response {
            if let Value::Bytes(b) = value {
                b.zeroize();
            }
        }
        ensure!(success,"strongSwan rejected {operation}; check the gateway authentication and proposal settings");
        Ok(())
    }
    pub fn ready(&self) -> Result<()> {
        let reply = vici::request(&self.socket, "stats", vec![], None, Duration::from_secs(3))?;
        ensure!(vici::strings(&reply.response,"plugins").iter().any(|p|p=="fortigate-manager-subnets"),
            "Install and load the fortigate-manager-subnets plugin before connecting; full-tunnel fallback is disabled");
        Ok(())
    }
    pub fn connect(&self, uid: u32, stored: &Stored, session: &Session) -> Result<()> {
        self.ready()?;
        let profile = &stored.profile;
        let name = profile.connection_name(uid);
        let endpoints = (profile.gateway.as_str(), 500)
            .to_socket_addrs()?
            .map(|s| s.ip().to_string())
            .collect::<Vec<_>>();
        ensure!(
            !endpoints.is_empty(),
            "Gateway did not resolve to an IP address"
        );
        let all = vici::request(
            &self.socket,
            "list-sas",
            vec![],
            Some("list-sa"),
            Duration::from_secs(3),
        )?;
        for event in all.events {
            for (other, sa) in event {
                if let Value::Section(sa) = sa {
                    ensure!(
                        !(other != name
                            && vici::text(&sa, "state") == "ESTABLISHED"
                            && endpoints.contains(&vici::text(&sa, "remote-host"))),
                        "Another tunnel to this gateway is already connected; disconnect it first"
                    );
                }
            }
        }
        let mut owners = endpoints;
        owners.push(profile.gateway.clone());
        if !profile.remote_id.is_empty() {
            owners.push(profile.remote_id.clone());
        }
        let mut message = connection(profile, uid, &session.uid);
        let result = (|| -> Result<()> {
            // Load just this connection; never run --load-conns/--load-creds,
            // which can unload other profiles or credentials.
            let request_result = self.command("load-conn", message.clone());
            zero_message(&mut message);
            request_result?;
            let mut key = vec![
                kv("id", format!("{name}-ike")),
                kv("type", "IKE"),
                kv("data", &stored.psk.0),
                list("owners", &owners),
            ];
            let key_result = self.command("load-shared", key.clone());
            zero_message(&mut key);
            key_result?;
            let mut eap = vec![
                kv("id", format!("{name}-eap")),
                kv("type", "EAP"),
                kv("data", &session.token.0),
                list("owners", &[session.uid.clone()]),
            ];
            let eap_result = self.command("load-shared", eap.clone());
            zero_message(&mut eap);
            eap_result?;
            self.command(
                "initiate",
                vec![
                    kv("ike", &name),
                    kv("child", &name),
                    kv("timeout", "60000"),
                    kv("loglevel", "-1"),
                ],
            )?;
            let state = self.status(profile, uid)?;
            ensure!(
                state.state == State::Connected && !state.routes.is_empty(),
                "No installed child tunnel with advertised routes"
            );
            Ok(())
        })();
        if result.is_err() {
            let _ = self.disconnect(profile, uid);
        }
        result
    }
    pub fn disconnect(&self, profile: &Profile, uid: u32) -> Result<()> {
        let name = profile.connection_name(uid);
        // Only remove credentials/config after termination has succeeded.
        self.command(
            "terminate",
            vec![
                kv("ike", &name),
                kv("timeout", "10000"),
                kv("force", "yes"),
                kv("loglevel", "-1"),
            ],
        )?;
        let shared = vici::request(
            &self.socket,
            "get-shared",
            vec![],
            None,
            Duration::from_secs(3),
        )?;
        let shared = vici::strings(&shared.response, "keys");
        let mut failed = false;
        for suffix in ["eap", "ike"] {
            let id = format!("{name}-{suffix}");
            if shared.contains(&id) && self.command("unload-shared", vec![kv("id", id)]).is_err() {
                failed = true;
            }
        }
        let conns = vici::request(
            &self.socket,
            "get-conns",
            vec![],
            None,
            Duration::from_secs(3),
        )?;
        if vici::strings(&conns.response, "conns").contains(&name)
            && self
                .command("unload-conn", vec![kv("name", &name)])
                .is_err()
        {
            failed = true;
        }
        ensure!(!failed,"Tunnel stopped, but some temporary credentials or connection settings could not be removed");
        Ok(())
    }
    pub fn status(&self, profile: &Profile, uid: u32) -> Result<Tunnel> {
        let name = profile.connection_name(uid);
        let reply = vici::request(
            &self.socket,
            "list-sas",
            vec![kv("ike", &name)],
            Some("list-sa"),
            Duration::from_secs(3),
        )?;
        let mut status = Tunnel::default();
        for event in reply.events {
            let Some(sa) = vici::child(&event, &name) else {
                continue;
            };
            status.state = State::Connecting;
            status.virtual_ips = vici::strings(sa, "local-vips");
            let Some(children) = vici::child(sa, "child-sas") else {
                continue;
            };
            for (_, child) in children {
                let Value::Section(child) = child else {
                    continue;
                };
                if vici::text(child, "state") != "INSTALLED" {
                    continue;
                }
                let routes = vici::strings(child, "remote-ts");
                // Defend against accidentally using a legacy or unscoped plugin.
                ensure!(
                    !routes.iter().any(|r| r == "0.0.0.0/0" || r == "::/0"),
                    "Unexpected full-tunnel selector; disconnect this profile"
                );
                status.state = State::Connected;
                status.routes.extend(routes);
                status.bytes_in += vici::text(child, "bytes-in").parse::<u64>().unwrap_or(0);
                status.bytes_out += vici::text(child, "bytes-out").parse::<u64>().unwrap_or(0);
            }
        }
        status.routes.sort();
        status.routes.dedup();
        Ok(status)
    }
}
fn command_succeeded(operation: &str, response: &Message) -> bool {
    vici::text(response, "success") == "yes"
        || (operation == "terminate"
            && vici::text(response, "matches") == "0"
            && vici::text(response, "terminated") == "0")
}
fn zero_message(m: &mut Message) {
    for (_, v) in m {
        match v {
            Value::Bytes(b) => b.zeroize(),
            Value::List(l) => {
                for b in l {
                    b.zeroize();
                }
            }
            Value::Section(s) => zero_message(s),
        }
    }
}

pub fn connection(profile: &Profile, uid: u32, saml_uid: &str) -> Message {
    let name = profile.connection_name(uid);
    let mut local = vec![kv("auth", "eap"), kv("eap_id", saml_uid)];
    if !profile.local_id.is_empty() {
        local.push(kv("id", &profile.local_id));
    }
    let mut child = vec![
        list("local_ts", &["dynamic".into()]),
        list("remote_ts", &["0.0.0.0/0".into()]),
        list(
            "esp_proposals",
            &profile
                .esp_proposals
                .split(',')
                .map(str::to_string)
                .collect::<Vec<_>>(),
        ),
        kv("rekey_time", (profile.esp_lifetime * 11 / 12).to_string()),
        kv("life_time", profile.esp_lifetime.to_string()),
        kv(
            "replay_window",
            if profile.replay_detection { "32" } else { "0" },
        ),
        kv("dpd_action", "clear"),
        kv("start_action", "none"),
    ];
    if profile.esp_lifetime_kb > 0 {
        let bytes = profile.esp_lifetime_kb * 1024;
        child.push(kv("life_bytes", bytes.to_string()));
        child.push(kv("rekey_bytes", (bytes * 11 / 12).to_string()));
    }
    let mut remote = vec![kv("auth", "psk")];
    if !profile.remote_id.is_empty() {
        remote.push(kv("id", &profile.remote_id));
    }
    vec![section(
        &name,
        vec![
            kv("version", "2"),
            kv("remote_port", profile.ike_port.to_string()),
            list("remote_addrs", &[profile.gateway.clone()]),
            list(
                "proposals",
                &profile
                    .ike_proposals
                    .split(',')
                    .map(str::to_string)
                    .collect::<Vec<_>>(),
            ),
            kv("rekey_time", profile.ike_lifetime.to_string()),
            kv("reauth_time", "0"),
            kv("dpd_delay", profile.dpd_seconds.to_string()),
            list("vips", &["0.0.0.0".into()]),
            kv("fragmentation", "yes"),
            kv("mobike", "no"),
            kv(
                "encap",
                if profile.force_encapsulation {
                    "yes"
                } else {
                    "no"
                },
            ),
            section("local", local),
            section("remote", remote),
            section("children", vec![section(&name, child)]),
        ],
    )]
}

pub fn default_backend() -> Backend {
    Backend {
        socket: Path::new("/run/charon.vici").into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn profile_creates_isolated_connection_with_dynamic_routes() {
        let p = Profile {
            id: "0123456789abcdef0123456789abcdef".into(),
            gateway: "vpn.example.com".into(),
            ..Default::default()
        };
        let m = connection(&p, 1000, "SESSION");
        let name = p.connection_name(1000);
        let c = vici::child(&m, &name).unwrap();
        assert_eq!(vici::strings(c, "remote_addrs"), ["vpn.example.com"]);
        let child = vici::child(vici::child(c, "children").unwrap(), &name).unwrap();
        assert_eq!(vici::strings(child, "remote_ts"), ["0.0.0.0/0"]);
        assert!(vici::child(c, "local")
            .unwrap()
            .iter()
            .any(|(k, _)| k == "eap_id"));
        assert!(!m.iter().any(|(k, _)| k == "fortigate"));
    }
    #[test]
    fn replay_and_byte_lifetimes_reach_strongswan() {
        let p = Profile {
            id: "0123456789abcdef0123456789abcdef".into(),
            gateway: "vpn.example.com".into(),
            esp_lifetime_kb: 5120,
            replay_detection: false,
            ..Default::default()
        };
        let name = p.connection_name(1000);
        let m = connection(&p, 1000, "SESSION");
        let c = vici::child(&m, &name).unwrap();
        let child = vici::child(vici::child(c, "children").unwrap(), &name).unwrap();
        assert_eq!(vici::text(child, "life_bytes"), "5242880");
        assert_eq!(vici::text(child, "replay_window"), "0");
        assert!(name.ends_with("-lan"));
    }
    #[test]
    fn already_disconnected_is_success_but_real_termination_failure_is_not() {
        let no_session = vec![
            kv("success", "no"),
            kv("matches", "0"),
            kv("terminated", "0"),
        ];
        assert!(command_succeeded("terminate", &no_session));
        assert!(!command_succeeded("load-conn", &no_session));
        assert!(!command_succeeded(
            "terminate",
            &vec![
                kv("success", "no"),
                kv("matches", "1"),
                kv("terminated", "0")
            ]
        ));
    }
}
