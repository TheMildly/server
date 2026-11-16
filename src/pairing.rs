//! Pairing codes (docs/SERVER.md, section 3): twelve digits, one use, ten minutes, five tries.
//!
//! Two kinds share the same path for the joining device:
//! - the installer's code (and `mildly-server pair`), made here;
//! - an invite, made on a paired device, so that the engine never learns the code. The device
//!   sends what the engine needs to announce it and to check the joining device: the topic,
//!   the announcement key and the proof. None of them reveals the code.
//!
//! While a code is valid the engine answers LAN discovery and posts an encrypted announcement
//! to the rendezvous, so the app can find it from the digits alone. The joining device proves
//! it knows the code with `HMAC(codeKey, "proof")`; the code itself never travels.

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
  pub proof: [u8; 32],
  pub topic: String,
  pub announcement: String,
  pub expires: Instant,
  pub tries: u32,
  /// The invite this code belongs to; `None` for the installer's code.
  pub invite: Option<String>,
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

fn announcement(app: &App, announce_key: &[u8; 32]) -> String {
  let body = json!({
    "v": 1,
    "a": app.addresses,
    "k": crypto::b64(app.key.public_raw()),
    "n": app.name,
  });
  crypto::seal_announcement(announce_key, body.to_string().as_bytes())
}

fn add(app: &Arc<App>, pairing: Pairing) {
  let topic = pairing.topic.clone();
  let mut all = app.pairing.lock().expect("pairing lock");
  all.retain(|p| p.expires > Instant::now());
  // A new installer code replaces the earlier one; invites live side by side.
  if pairing.invite.is_none() {
    all.retain(|p| p.invite.is_some());
  }
  all.push(pairing);
  drop(all);
  tokio::spawn(announce(app.clone(), topic));
}

/// Makes a fresh installer code, replacing any earlier one, and starts announcing it.
pub async fn start(app: Arc<App>) -> String {
  let code = digits();
  let key = {
    let code = code.clone();
    tokio::task::spawn_blocking(move || crypto::code_key(&code)).await.expect("pbkdf2 task")
  };
  add(
    &app,
    Pairing {
      proof: crypto::code_tag(&key, b"proof"),
      topic: crypto::topic(&key),
      announcement: announcement(&app, &crypto::announce_key(&key)),
      expires: Instant::now() + LIFETIME,
      tries: 0,
      invite: None,
    },
  );
  code
}

/// Starts announcing an invite made on a device. Returns when it expires.
pub fn start_invite(app: &Arc<App>, invite: &str, topic: String, announce_key: [u8; 32], proof: [u8; 32]) -> Instant {
  let expires = Instant::now() + LIFETIME;
  add(app, Pairing { proof, topic, announcement: announcement(app, &announce_key), expires, tries: 0, invite: Some(invite.to_string()) });
  expires
}

pub fn cancel_invite(app: &App, invite: &str) {
  app.pairing.lock().expect("pairing lock").retain(|p| p.invite.as_deref() != Some(invite));
}

/// Posts the announcement to the rendezvous now and every two minutes while the code lives.
async fn announce(app: Arc<App>, topic: String) {
  if app.config.rendezvous.is_empty() {
    return;
  }
  let client = reqwest::Client::builder().timeout(Duration::from_secs(10)).build().expect("http client");
  loop {
    let message = {
      let all = app.pairing.lock().expect("pairing lock");
      match all.iter().find(|p| p.topic == topic && p.expires > Instant::now()) {
        Some(p) => p.announcement.clone(),
        None => return,
      }
    };
    let url = format!("{}/{}", app.config.rendezvous.trim_end_matches('/'), topic);
    match client.post(&url).body(message).send().await {
      Ok(res) if !res.status().is_success() => {
        // ntfy.sh limits free messages per address and day; LAN discovery and the QR code still work.
        tracing::warn!("the rendezvous refused the announcement ({}); the code still works on the local network and by QR code", res.status());
      }
      Ok(_) => {}
      Err(e) => tracing::warn!("rendezvous unreachable: {e}"),
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
      let all = app.pairing.lock().expect("pairing lock");
      all.iter().find(|p| p.topic == asked && p.expires > Instant::now()).map(|p| p.announcement.clone())
    };
    if let Some(reply) = reply {
      let _ = socket.send_to(reply.as_bytes(), from).await;
    }
  }
}

pub enum Check {
  /// The code was right; `Some` names the invite it belonged to.
  Ok(Option<String>),
  Wrong,
  Expired,
}

/// Checks a proof and uses its code up. A wrong try counts against every open code; the
/// fifth ends them.
pub fn check(app: &App, offered: &[u8]) -> Check {
  let mut all = app.pairing.lock().expect("pairing lock");
  all.retain(|p| p.expires > Instant::now());
  if all.is_empty() {
    return Check::Expired;
  }
  let same = |p: &Pairing| offered.len() == 32 && p.proof.iter().zip(offered).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0;
  if let Some(i) = all.iter().position(same) {
    let p = all.remove(i);
    return Check::Ok(p.invite);
  }
  for p in all.iter_mut() {
    p.tries += 1;
  }
  all.retain(|p| p.tries < MAX_TRIES);
  if all.is_empty() { Check::Expired } else { Check::Wrong }
}
