//! Minimal bounded VICI implementation, matched to strongSwan 6.0.1's protocol.
use anyhow::{bail, ensure, Context, Result};
use std::{
    io::{Read, Write},
    os::unix::net::UnixStream,
    path::Path,
    time::Duration,
};

const MAX_PACKET: usize = 512 * 1024;
#[derive(Clone, PartialEq)]
pub enum Value {
    Bytes(Vec<u8>),
    List(Vec<Vec<u8>>),
    Section(Message),
}
pub type Message = Vec<(String, Value)>;
pub fn kv(key: &str, value: impl AsRef<[u8]>) -> (String, Value) {
    (key.into(), Value::Bytes(value.as_ref().to_vec()))
}
pub fn list(key: &str, values: &[String]) -> (String, Value) {
    (
        key.into(),
        Value::List(values.iter().map(|v| v.as_bytes().to_vec()).collect()),
    )
}
pub fn section(key: &str, values: Message) -> (String, Value) {
    (key.into(), Value::Section(values))
}
pub fn bytes<'a>(m: &'a Message, key: &str) -> Option<&'a [u8]> {
    m.iter().find_map(|(k, v)| {
        if k == key {
            if let Value::Bytes(b) = v {
                Some(b.as_slice())
            } else {
                None
            }
        } else {
            None
        }
    })
}
pub fn text(m: &Message, key: &str) -> String {
    bytes(m, key)
        .and_then(|b| std::str::from_utf8(b).ok())
        .unwrap_or_default()
        .into()
}
pub fn strings(m: &Message, key: &str) -> Vec<String> {
    m.iter()
        .find_map(|(k, v)| {
            if k == key {
                if let Value::List(items) = v {
                    Some(
                        items
                            .iter()
                            .filter_map(|b| String::from_utf8(b.clone()).ok())
                            .collect(),
                    )
                } else {
                    None
                }
            } else {
                None
            }
        })
        .unwrap_or_default()
}
pub fn child<'a>(m: &'a Message, key: &str) -> Option<&'a Message> {
    m.iter().find_map(|(k, v)| {
        if k == key {
            if let Value::Section(s) = v {
                Some(s)
            } else {
                None
            }
        } else {
            None
        }
    })
}
fn name(out: &mut Vec<u8>, value: &str) -> Result<()> {
    ensure!(value.len() <= 255 && value.is_ascii(), "Invalid VICI name");
    out.push(value.len() as u8);
    out.extend_from_slice(value.as_bytes());
    Ok(())
}
fn blob(out: &mut Vec<u8>, value: &[u8]) -> Result<()> {
    ensure!(value.len() <= 65535, "VICI value too large");
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value);
    Ok(())
}
fn encode_into(out: &mut Vec<u8>, message: &Message, depth: usize) -> Result<()> {
    ensure!(depth <= 32, "VICI nesting limit exceeded");
    for (key, value) in message {
        match value {
            Value::Bytes(b) => {
                out.push(3);
                name(out, key)?;
                blob(out, b)?;
            }
            Value::List(items) => {
                out.push(4);
                name(out, key)?;
                for item in items {
                    out.push(5);
                    blob(out, item)?;
                }
                out.push(6);
            }
            Value::Section(s) => {
                out.push(1);
                name(out, key)?;
                encode_into(out, s, depth + 1)?;
                out.push(2);
            }
        }
        ensure!(out.len() <= MAX_PACKET, "VICI packet too large");
    }
    Ok(())
}
pub fn encode(message: &Message) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    encode_into(&mut out, message, 0)?;
    Ok(out)
}
struct Decoder<'a> {
    data: &'a [u8],
    offset: usize,
    elements: usize,
}
impl<'a> Decoder<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        ensure!(
            n <= self.data.len().saturating_sub(self.offset),
            "Truncated VICI message"
        );
        let out = &self.data[self.offset..self.offset + n];
        self.offset += n;
        Ok(out)
    }
    fn byte(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn name(&mut self) -> Result<String> {
        let len = self.byte()? as usize;
        let b = self.take(len)?;
        ensure!(b.is_ascii(), "Invalid VICI name");
        Ok(String::from_utf8(b.to_vec())?)
    }
    fn blob(&mut self) -> Result<Vec<u8>> {
        let len = self.take(2)?;
        let len = u16::from_be_bytes([len[0], len[1]]) as usize;
        Ok(self.take(len)?.to_vec())
    }
    fn message(&mut self, depth: usize) -> Result<Message> {
        ensure!(depth <= 32, "VICI nesting limit exceeded");
        let mut out = Vec::new();
        while self.offset < self.data.len() {
            self.elements += 1;
            ensure!(self.elements <= 16384, "Too many VICI elements");
            let tag = self.byte()?;
            if tag == 2 {
                ensure!(depth > 0, "Unexpected VICI section end");
                return Ok(out);
            }
            let key = self.name()?;
            ensure!(!out.iter().any(|(k, _)| k == &key), "Duplicate VICI key");
            let val = match tag {
                1 => Value::Section(self.message(depth + 1)?),
                3 => Value::Bytes(self.blob()?),
                4 => {
                    let mut items = Vec::new();
                    loop {
                        match self.byte()? {
                            5 => {
                                items.push(self.blob()?);
                                ensure!(items.len() <= 8192, "VICI list limit exceeded");
                            }
                            6 => break,
                            _ => bail!("Invalid VICI list"),
                        }
                    }
                    Value::List(items)
                }
                _ => bail!("Unknown VICI element"),
            };
            out.push((key, val));
        }
        ensure!(depth == 0, "Unterminated VICI section");
        Ok(out)
    }
}
pub fn decode(data: &[u8]) -> Result<Message> {
    ensure!(data.len() <= MAX_PACKET, "VICI message too large");
    Decoder {
        data,
        offset: 0,
        elements: 0,
    }
    .message(0)
}
fn send(stream: &mut UnixStream, packet: &[u8]) -> Result<()> {
    ensure!(packet.len() <= MAX_PACKET, "VICI packet too large");
    stream.write_all(&(packet.len() as u32).to_be_bytes())?;
    stream.write_all(packet)?;
    Ok(())
}
fn receive(stream: &mut UnixStream) -> Result<Vec<u8>> {
    let mut len = [0; 4];
    stream.read_exact(&mut len)?;
    let len = u32::from_be_bytes(len) as usize;
    ensure!(len > 0 && len <= MAX_PACKET, "Invalid VICI frame size");
    let mut data = vec![0; len];
    stream.read_exact(&mut data)?;
    Ok(data)
}
pub struct Reply {
    pub response: Message,
    pub events: Vec<Message>,
}
pub fn request(
    path: &Path,
    command: &str,
    message: Message,
    event: Option<&str>,
    timeout: Duration,
) -> Result<Reply> {
    let mut stream = UnixStream::connect(path)
        .context("Cannot reach strongSwan VICI; check strongswan.service")?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    if let Some(event) = event {
        let mut packet = vec![3];
        name(&mut packet, event)?;
        send(&mut stream, &packet)?;
        let reply = receive(&mut stream)?;
        ensure!(reply == [5], "VICI event registration failed");
    }
    let mut packet = vec![0];
    name(&mut packet, command)?;
    packet.extend(encode(&message)?);
    send(&mut stream, &packet)?;
    let mut events = Vec::new();
    loop {
        let packet = receive(&mut stream)?;
        match packet[0] {
            1 => {
                return Ok(Reply {
                    response: decode(&packet[1..])?,
                    events,
                })
            }
            2 => bail!("strongSwan does not support the requested VICI command"),
            7 => {
                ensure!(packet.len() >= 2, "Invalid VICI event");
                let len = packet[1] as usize;
                ensure!(packet.len() >= 2 + len, "Truncated VICI event");
                ensure!(events.len() < 4096, "Too many VICI events");
                events.push(decode(&packet[2 + len..])?);
            }
            _ => bail!("Unexpected VICI reply"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn round_trip_binary_secrets_and_nested_lists() {
        let msg = vec![section(
            "conn",
            vec![
                kv("secret", [0, 255, 1]),
                list("ts", &["198.51.100.0/24".into()]),
            ],
        )];
        assert!(decode(&encode(&msg).unwrap()).unwrap() == msg);
    }
    #[test]
    fn malformed_frames_are_rejected() {
        for data in [
            &[2][..],
            &[1, 1, b'x'][..],
            &[3, 1, b'x', 255, 255][..],
            &[4, 1, b'x', 2][..],
        ] {
            assert!(decode(data).is_err());
        }
        let mut data = vec![];
        for _ in 0..34 {
            data.extend([1, 1, b'x']);
        }
        assert!(decode(&data).is_err());
    }
    #[test]
    fn matches_documented_wire_format() {
        let expected = b"\x03\x07success\x00\x03yes";
        assert_eq!(encode(&vec![kv("success", "yes")]).unwrap(), expected);
        assert_eq!(text(&decode(expected).unwrap(), "success"), "yes");
    }
    #[test]
    fn command_stream_handles_registered_events_before_response() {
        use std::{os::unix::net::UnixListener, thread};
        let path =
            std::env::temp_dir().join(format!("fgr-vici-{:016x}.sock", rand::random::<u64>()));
        let listener = UnixListener::bind(&path).unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            assert_eq!(receive(&mut stream).unwrap(), b"\x03\x07list-sa");
            send(&mut stream, &[5]).unwrap();
            assert_eq!(receive(&mut stream).unwrap(), b"\x00\x08list-sas");
            let event = vec![section("example", vec![kv("state", "ESTABLISHED")])];
            let mut packet = b"\x07\x07list-sa".to_vec();
            packet.extend(encode(&event).unwrap());
            send(&mut stream, &packet).unwrap();
            send(&mut stream, &[1]).unwrap();
        });
        let reply = request(
            &path,
            "list-sas",
            vec![],
            Some("list-sa"),
            Duration::from_secs(3),
        )
        .unwrap();
        assert_eq!(reply.events.len(), 1);
        assert_eq!(
            text(child(&reply.events[0], "example").unwrap(), "state"),
            "ESTABLISHED"
        );
        server.join().unwrap();
        std::fs::remove_file(path).unwrap();
    }
}
