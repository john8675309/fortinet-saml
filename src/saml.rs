use crate::{model::Profile, store::Secret};
use anyhow::{bail, ensure, Context, Result};
use regex::Regex;
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::{Duration, Instant},
};
use url::Url;

pub struct Session {
    pub uid: String,
    pub token: Secret,
}
pub fn extract_redirect(html: &str) -> Result<String> {
    let re = Regex::new(r#"(?i)(?:window\.)?location(?:\.href)?\s*=\s*["']([^"']+)["']"#)?;
    let target = re
        .captures(html)
        .and_then(|c| c.get(1))
        .context("Gateway did not return a browser SAML redirect")?
        .as_str();
    let url = Url::parse(target).context("Gateway returned an invalid SAML redirect")?;
    ensure!(
        url.scheme() == "https" && url.username().is_empty() && url.password().is_none(),
        "SAML redirect must use HTTPS without URL credentials"
    );
    Ok(url.into())
}
pub fn callback_token(request: &str, port: u16) -> Result<Secret> {
    let (headers, _) = request
        .split_once("\r\n\r\n")
        .context("Incomplete browser callback")?;
    let mut lines = headers.split("\r\n");
    let mut first = lines.next().unwrap_or_default().split_whitespace();
    ensure!(first.next() == Some("GET"), "Invalid callback method");
    let target = first.next().context("Missing callback target")?;
    ensure!(
        target.starts_with("/?") && target.len() <= 4096,
        "Invalid callback path"
    );
    let host = format!("127.0.0.1:{port}");
    let hosts = lines
        .filter_map(|l| l.split_once(':'))
        .filter(|(k, _)| k.eq_ignore_ascii_case("host"))
        .map(|(_, v)| v.trim().to_owned())
        .collect::<Vec<_>>();
    let accepted = [
        host.clone(),
        format!("localhost:{port}"),
        format!("[::1]:{port}"),
    ];
    ensure!(
        hosts.len() == 1 && accepted.iter().any(|h| h.eq_ignore_ascii_case(&hosts[0])),
        "Invalid callback host"
    );
    let url = Url::parse(&format!("http://{host}{target}"))?;
    let tokens = url
        .query_pairs()
        .filter(|(k, _)| k == "tokenid")
        .map(|(_, v)| v.into_owned())
        .collect::<Vec<_>>();
    ensure!(
        tokens.len() == 1
            && tokens[0].len() == 32
            && tokens[0].bytes().all(|b| b.is_ascii_hexdigit()),
        "Invalid authentication token"
    );
    Ok(Secret(tokens.into_iter().next().unwrap()))
}
fn receive_callback(mut stream: TcpStream, port: u16) -> Result<Secret> {
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    let mut data = Vec::new();
    let mut buf = [0; 1024];
    while data.len() < 8192 {
        let n = stream.read(&mut buf)?;
        if n == 0 {
            break;
        }
        data.extend_from_slice(&buf[..n]);
        if data.windows(4).any(|b| b == b"\r\n\r\n") {
            break;
        }
    }
    let token = std::str::from_utf8(&data)
        .ok()
        .and_then(|s| callback_token(s, port).ok());
    let (status, body) = if token.is_some() {
        ("200 OK","<!doctype html><meta charset=utf-8><title>VPN authentication complete</title><script>history.replaceState(null,'','/success');window.close()</script><h2>Authentication complete</h2><p>You can return to FortiGate Manager.</p>")
    } else {
        ("400 Bad Request", "Invalid callback")
    };
    let reply=format!("HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",body.len());
    stream.write_all(reply.as_bytes())?;
    token.context("Invalid callback")
}

pub fn authenticate(
    profile: &Profile,
    cancel: &AtomicBool,
    show_browser: impl Fn(String),
) -> Result<Session> {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, profile.callback_port))
        .context("Cannot open the SAML callback port; another VPN client may be using it")?;
    listener.set_nonblocking(true)?;
    let mut listeners = vec![listener];
    match TcpListener::bind((std::net::Ipv6Addr::LOCALHOST,profile.callback_port)){
        Ok(listener)=>{listener.set_nonblocking(true)?;listeners.push(listener);},
        Err(error) if matches!(error.raw_os_error(),Some(libc::EAFNOSUPPORT|libc::EADDRNOTAVAIL))=>{},
        Err(_)=>bail!("Cannot reserve IPv6 loopback for the SAML callback; another client may be using the port"),
    }
    let uid = format!("{:032X}", rand::random::<u128>());
    let mut url = Url::parse("https://vpn.invalid/saml_login?")?;
    url.set_host(Some(&profile.gateway))
        .map_err(|_| anyhow::anyhow!("Invalid gateway"))?;
    url.set_port(Some(profile.saml_port))
        .map_err(|_| anyhow::anyhow!("Invalid SAML port"))?;
    let mut client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::limited(5));
    if !profile.ca_certificate_pem.is_empty() {
        client = client.add_root_certificate(reqwest::Certificate::from_pem(
            profile.ca_certificate_pem.as_bytes(),
        )?);
    }
    let response=client.build()?.post(url)
        .header("User-Agent","FortiSSLVPN (Linux; SV1 [SV{v=02.01; f=05;}])")
        .json(&serde_json::json!({"type":"rawData","bytes":format!("UID={uid}&REDIRECT_PORT={}",profile.callback_port)}))
        .send().map_err(|_|anyhow::anyhow!("Cannot reach the gateway SAML endpoint; check hostname, port and TLS trust"))?;
    ensure!(
        response.status().is_success(),
        "Gateway rejected SAML initialization (HTTP {})",
        response.status().as_u16()
    );
    let mut html = String::new();
    response.take(1_048_577).read_to_string(&mut html)?;
    ensure!(html.len() <= 1_048_576, "SAML response too large");
    let redirect = extract_redirect(&html)?;
    if cancel.load(Ordering::Acquire) {
        bail!("Connection cancelled");
    }
    show_browser(redirect);
    let until = Instant::now() + Duration::from_secs(180);
    while Instant::now() < until {
        if cancel.load(Ordering::Acquire) {
            bail!("Connection cancelled");
        }
        for listener in &listeners {
            match listener.accept() {
                Ok((stream, _)) => {
                    if let Ok(token) = receive_callback(stream, profile.callback_port) {
                        return Ok(Session { uid, token });
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e.into()),
            }
        }
        thread::sleep(Duration::from_millis(75));
    }
    bail!("Browser authentication timed out after 180 seconds")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn redirect_requires_https_and_no_embedded_credentials() {
        assert!(extract_redirect(
            "window.location.href = 'https://vpn.example.com/saml?nonce=test';"
        )
        .is_ok());
        assert!(extract_redirect("location='javascript:alert(1)'").is_err());
        assert!(extract_redirect("location='https://secret:password@example.com/'").is_err());
    }
    #[test]
    fn callbacks_validate_host_token_and_duplicates() {
        let valid="GET /?tokenid=0123456789abcdef0123456789abcdef HTTP/1.1\r\nHost: 127.0.0.1:8020\r\n\r\n";
        assert!(callback_token(valid, 8020).is_ok());
        assert!(callback_token(&valid.replace("127.0.0.1:8020", "localhost:8020"), 8020).is_ok());
        assert!(callback_token(&valid.replace("127.0.0.1:8020", "[::1]:8020"), 8020).is_ok());
        assert!(callback_token(&valid.replace("127.0.0.1:8020", "localhost:8021"), 8020).is_err());
        assert!(
            callback_token(&valid.replace("127.0.0.1:8020", "attacker.example"), 8020).is_err()
        );
        assert!(callback_token(
            &valid.replace(" HTTP/1.1", "&tokenid=another HTTP/1.1"),
            8020
        )
        .is_err());
        assert!(callback_token(
            &valid.replace("0123456789abcdef0123456789abcdef", "bad\"token"),
            8020
        )
        .is_err());
    }
}
