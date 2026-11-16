//! Pairing codes (docs/SERVER.md, section 3): twelve digits, one use, ten minutes, five tries.
//! While a code is valid the engine answers LAN discovery and posts an encrypted
//! announcement to the rendezvous, so the app can find it from the digits alone.

use crate::crypto;
use crate::App;
use qrcode::render::unicode;
use qrcode::QrCode;
use rand_core::{OsRng, RngCore};
use serde_json::json;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

pub const LIFETIME: Duration = Duration::from_secs(600);
pub const MAX_TRIES: u32 = 5;

pub struct Pairing {
  pub code: String,
  pub topic: String,
  pub announcement: String,
  pub expires: Instant,
  pub tries: u32,
}

/// Twelve uniformly random digits.
fn digits() -> String {
  const LIMIT: u64 = u64::MAX - (u64::MAX % 1_000_000_000_000);
  loop {
    let n = OsRng.next_u64();
    if n < LIMIT {
      return format!("{:012}", n % 1_000_000_000_000);
    }
  }
}

pub fn grouped(code: &str) -> String {
  code.as_bytes().chunks(4).map(|c| std::str::from_utf8(c).unwrap_or("")).collect::<Vec<_>>().join(" ")
}

/// What the QR code carries: the code, the server key's fingerprint and where to reach it.
pub fn qr_payload(app: &App, code: &str) -> String {
  let address = app.addresses.first().cloned().unwrap_or_default();
  format!("mildly://pair?c={code}&k={}&a={address}", app.key.fingerprint())
}

pub fn qr_text(payload: &str) -> String {
  match QrCode::new(payload.as_bytes()) {
    Ok(code) => code.render::<unicode::Dense1x2>().quiet_zone(true).build(),
    Err(_) => String::new(),
  }
}

/// Makes a fresh code, replacing any earlier one, and starts announcing it.
pub async fn start(app: Arc<App>) -> String {
  let code = digits();
  let key = {
    let code = code.clone();
    tokio::task::spawn_blocking(move || crypto::code_key(&code)).await.expect("pbkdf2 task")
  };
  let body = json!({
    "v": 1,
    "a": app.addresses,
    "k": crypto::b64(app.key.public_raw()),
    "n": app.name,
  });
  let pairing = Pairing {
    code: code.clone(),
    topic: crypto::topic(&key),
    announcement: crypto::seal_announcement(&key, body.to_string().as_bytes()),
    expires: Instant::now() + LIFETIME,
    tries: 0,
  };
  let topic = pairing.topic.clone();
  *app.pairing.lock().expect("pairing lock") = Some(pairing);
  tokio::spawn(announce(app.clone(), topic));
  code
}

/// Posts the announcement to the rendezvous now and every two minutes while the code lives.
async fn announce(app: Arc<App>, topic: String) {
  if app.config.rendezvous.is_empty() {
    return;
  }
  let client = reqwest::Client::builder().timeout(Duration::from_secs(10)).build().expect("http client");
  loop {
    let message = {
      let guard = app.pairing.lock().expect("pairing lock");
      match guard.as_ref() {
        Some(p) if p.topic == topic && p.expires > Instant::now() => p.announcement.clone(),
        _ => return,
      }
    };
    let url = format!("{}/{}", app.config.rendezvous.trim_end_matches('/'), topic);
    if let Err(e) = client.post(&url).body(message).send().await {
      tracing::warn!("rendezvous unreachable: {e}");
    }
    tokio::time::sleep(Duration::from_secs(120)).await;
  }
}

/// Answers `MLDY1 <topic>` broadcasts on the local network with the announcement.
pub async fn lan_responder(app: Arc<App>) {
  let socket = match UdpSocket::bind(("0.0.0.0", app.config.discovery_port)).await {
    Ok(s) => s,
    Err(e) => return tracing::warn!("LAN discovery is off: {e}"),
  };
  let mut buf = [0u8; 256];
  loop {
    let Ok((n, from)) = socket.recv_from(&mut buf).await else { continue };
    let Some(asked) = std::str::from_utf8(&buf[..n]).ok().and_then(|s| s.trim().strip_prefix("MLDY1 ")).map(str::to_owned) else {
      continue;
    };
    let reply = {
      let guard = app.pairing.lock().expect("pairing lock");
      guard.as_ref().filter(|p| p.topic == asked && p.expires > Instant::now()).map(|p| p.announcement.clone())
    };
    if let Some(reply) = reply {
      let _ = socket.send_to(reply.as_bytes(), from).await;
    }
  }
}

pub enum Check {
  Ok,
  Wrong,
  Expired,
}

/// Checks a code and uses it up. Wrong tries count; the fifth ends the code.
pub fn check(app: &App, offered: &str) -> Check {
  let mut guard = app.pairing.lock().expect("pairing lock");
  let Some(p) = guard.as_mut() else { return Check::Expired };
  if p.expires <= Instant::now() {
    *guard = None;
    return Check::Expired;
  }
  let same = p.code.len() == offered.len() && p.code.bytes().zip(offered.bytes()).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0;
  if same {
    *guard = None;
    return Check::Ok;
  }
  p.tries += 1;
  if p.tries >= MAX_TRIES {
    *guard = None;
    return Check::Expired;
  }
  Check::Wrong
}
