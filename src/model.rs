use anyhow::{bail, ensure, Result};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
#[serde(default)]
pub struct Profile {
    pub id: String,
    pub name: String,
    pub description: String,
    pub gateway: String,
    pub saml_port: u16,
    pub callback_port: u16,
    pub ike_port: u16,
    pub local_id: String,
    pub remote_id: String,
    pub ike_proposals: String,
    pub esp_proposals: String,
    pub ike_lifetime: u32,
    pub esp_lifetime: u32,
    pub esp_lifetime_kb: u64,
    pub replay_detection: bool,
    pub enable_local_lan: bool,
    pub dpd_seconds: u32,
    pub force_encapsulation: bool,
    pub ca_certificate_pem: String,
}

impl Default for Profile {
    fn default() -> Self {
        Self {
            id: String::new(), name: "New VPN".into(), description: String::new(), gateway: String::new(),
            saml_port: 8443, callback_port: 8020, ike_port: 500, local_id: String::new(), remote_id: String::new(),
            ike_proposals: "aes128-sha256-modp2048,aes128-sha256-ecp384,aes256-sha256-modp2048,aes256-sha256-ecp384".into(),
            esp_proposals: "aes128-sha1-ecp384,aes256-sha256-ecp384".into(), ike_lifetime: 43200,
            esp_lifetime: 43200, esp_lifetime_kb: 0, replay_detection: true, enable_local_lan: true,
            dpd_seconds: 20, force_encapsulation: false,
            ca_certificate_pem: String::new(),
        }
    }
}

pub fn valid_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

impl Profile {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.id.is_empty() || valid_id(&self.id),
            "Invalid profile ID"
        );
        ensure!(
            !self.name.trim().is_empty() && self.name.len() <= 100,
            "Name must contain 1–100 characters"
        );
        ensure!(self.description.len() <= 1024, "Description is too long");
        let ip = self.gateway.parse::<std::net::IpAddr>().is_ok();
        let domain = !self.gateway.is_empty()
            && self.gateway.len() <= 253
            && self.gateway.split('.').all(|part| {
                !part.is_empty()
                    && part.len() <= 63
                    && !part.starts_with('-')
                    && !part.ends_with('-')
                    && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            });
        ensure!(
            ip || domain,
            "Enter a gateway hostname or IP, without a URL or port"
        );
        ensure!(
            self.saml_port != 0 && self.ike_port != 0 && self.callback_port >= 1024,
            "Invalid SAML, IKE or callback port"
        );
        ensure!(
            self.local_id.len() <= 255 && !self.local_id.chars().any(char::is_control),
            "Invalid local identity"
        );
        ensure!(
            self.remote_id.len() <= 255 && !self.remote_id.chars().any(char::is_control),
            "Invalid remote identity"
        );
        for proposals in [&self.ike_proposals, &self.esp_proposals] {
            ensure!(
                !proposals.is_empty() && proposals.len() <= 1024,
                "Proposal list is empty or too long"
            );
            for proposal in proposals.split(',') {
                ensure!(!proposal.is_empty(), "Empty algorithm proposal");
                for token in proposal.split('-') {
                    match token {
                        "aes128" | "aes192" | "aes256" | "aes128gcm16" | "aes256gcm16" | "des"
                        | "3des" | "md5" | "sha1" | "sha256" | "sha384" | "sha512" | "prfmd5"
                        | "prfsha1" | "prfsha256" | "prfsha384" | "prfsha512" | "modp768"
                        | "modp1024" | "modp1536" | "modp2048" | "modp3072" | "modp4096"
                        | "modp6144" | "modp8192" | "ecp256" | "ecp384" | "ecp521"
                        | "curve25519" | "none" | "noesn" | "esn" => {}
                        _ => bail!("Unsupported algorithm token: {token}"),
                    }
                }
            }
        }
        ensure!(
            (300..=31_536_000).contains(&self.ike_lifetime)
                && (300..=31_536_000).contains(&self.esp_lifetime),
            "Lifetimes must be 300–31536000 seconds"
        );
        ensure!(
            self.dpd_seconds <= 3600,
            "DPD interval must be 0–3600 seconds"
        );
        ensure!(
            self.esp_lifetime_kb <= 1_099_511_627_776,
            "Byte lifetime is too large"
        );
        ensure!(
            self.ca_certificate_pem.len() <= 65536,
            "CA certificate too large"
        );
        if !self.ca_certificate_pem.is_empty() {
            reqwest::Certificate::from_pem(self.ca_certificate_pem.as_bytes())
                .map_err(|_| anyhow::anyhow!("Invalid CA certificate PEM"))?;
        }
        Ok(())
    }
    pub fn connection_name(&self, uid: u32) -> String {
        format!(
            "fgr-{uid}-{}-{}",
            self.id,
            if self.enable_local_lan { "lan" } else { "all" }
        )
    }
}

pub fn group_token(group: u16) -> Option<&'static str> {
    match group {
        1 => Some("modp768"),
        2 => Some("modp1024"),
        5 => Some("modp1536"),
        14 => Some("modp2048"),
        15 => Some("modp3072"),
        16 => Some("modp4096"),
        17 => Some("modp6144"),
        18 => Some("modp8192"),
        19 => Some("ecp256"),
        20 => Some("ecp384"),
        21 => Some("ecp521"),
        _ => None,
    }
}
pub fn proposals(rows: &[(String, String)], groups: &[u16], ike: bool) -> Result<String> {
    ensure!(!rows.is_empty(), "Add at least one encryption proposal");
    ensure!(
        !ike || !groups.is_empty(),
        "Select at least one phase 1 DH group"
    );
    let mut result = Vec::new();
    for (encryption, integrity) in rows {
        let base = if encryption.contains("gcm") {
            if ike {
                format!("{encryption}-prf{integrity}")
            } else {
                encryption.clone()
            }
        } else {
            format!("{encryption}-{integrity}")
        };
        if groups.is_empty() {
            result.push(base);
        } else {
            for group in groups {
                result.push(format!(
                    "{base}-{}",
                    group_token(*group).ok_or_else(|| anyhow::anyhow!("Unsupported DH group"))?
                ));
            }
        }
    }
    result.dedup();
    Ok(result.join(","))
}

#[derive(Clone, Serialize, Deserialize, Debug, Default, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum State {
    #[default]
    Disconnected,
    Authenticating,
    AwaitingBrowser,
    Connecting,
    Connected,
    Disconnecting,
    Failed,
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct ProfileView {
    pub profile: Profile,
    pub has_psk: bool,
    pub state: State,
    pub routes: Vec<String>,
    pub virtual_ips: Vec<String>,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub error: Option<String>,
    pub browser_url: Option<String>,
}

// Deliberately no Debug implementation: Save contains a credential.
#[derive(Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    List,
    Save {
        profile: Profile,
        psk: Option<String>,
    },
    Delete {
        id: String,
    },
    Connect {
        id: String,
    },
    Disconnect {
        id: String,
    },
}

#[derive(Serialize, Deserialize, Default)]
pub struct Response {
    pub ok: bool,
    pub error: Option<String>,
    pub profiles: Vec<ProfileView>,
    pub saved_id: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validation_rejects_paths_and_configuration_injection() {
        let mut p = Profile {
            gateway: "vpn.example.com".into(),
            ..Default::default()
        };
        assert!(p.validate().is_ok());
        p.id = "../../etc/shadow".into();
        assert!(p.validate().is_err());
        p.id.clear();
        p.gateway = "vpn.example.com/secret".into();
        assert!(p.validate().is_err());
        p.gateway = "vpn.example.com".into();
        p.ike_proposals = "aes128\nremote_ts=0/0".into();
        assert!(p.validate().is_err());
    }
    #[test]
    fn screenshot_proposals_expand_to_all_selected_groups() {
        let rows = vec![
            ("aes128".into(), "sha256".into()),
            ("aes256".into(), "sha256".into()),
        ];
        assert_eq!(proposals(&rows,&[14,20],true).unwrap(),"aes128-sha256-modp2048,aes128-sha256-ecp384,aes256-sha256-modp2048,aes256-sha256-ecp384");
        assert_eq!(
            proposals(&[("aes128gcm16".into(), "sha256".into())], &[20], true).unwrap(),
            "aes128gcm16-prfsha256-ecp384"
        );
        assert_eq!(
            proposals(&[("aes128gcm16".into(), "sha256".into())], &[], false).unwrap(),
            "aes128gcm16"
        );
        assert!(proposals(&rows, &[], true).is_err());
    }
}
