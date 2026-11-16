//! The user's space (docs/SERVER.md, section 6): personal files, chat copies and the memory
//! list, all encrypted on the devices with the space key before they arrive. The engine
//! stores opaque bytes and an opaque description, and knows only sizes and times.
//!
//! Invites relay the space key from a paired device to a joining one, sealed to a key only
//! the joining device holds; the engine passes it on without being able to open it.

use crate::crypto;
use crate::state::now_ms;
use crate::App;
use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Largest piece of a file or chat sent in one call.
pub const MAX_PART: usize = 8 * 1024 * 1024;

fn clean_id(id: &str) -> Result<&str> {
  if id.is_empty() || id.len() > 80 || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
    bail!("not-found");
  }
  Ok(id)
}

fn dir(app: &App, name: &str) -> Result<PathBuf> {
  let d = app.config.data_dir.join(name);
  std::fs::create_dir_all(&d)?;
  Ok(d)
}

fn modified_ms(path: &std::path::Path) -> u64 {
  std::fs::metadata(path).and_then(|m| m.modified()).ok().and_then(|t| t.duration_since(UNIX_EPOCH).ok()).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// Writes a file whole or not at all.
fn write_atomic(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
  let tmp = path.with_extension("tmp");
  let mut f = std::fs::File::create(&tmp)?;
  f.write_all(bytes)?;
  f.sync_all()?;
  std::fs::rename(&tmp, path)?;
  Ok(())
}

/* ---------- personal storage ---------- */

#[derive(Serialize, Deserialize, Clone)]
pub struct Meta {
  origin: String,
  /// Size of the stored (encrypted) bytes.
  size: u64,
  at: u64,
  /// The item's name, kind and the like, encrypted on the device.
  desc: String,
}

fn wire(id: &str, m: &Meta) -> Value {
  json!({ "id": id, "origin": m.origin, "size": m.size, "at": m.at, "desc": m.desc })
}

pub fn items(app: &App) -> Vec<Value> {
  let Ok(d) = dir(app, "blobs") else { return vec![] };
  let mut out: Vec<(u64, Value)> = std::fs::read_dir(d)
    .into_iter()
    .flatten()
    .flatten()
    .filter_map(|e| {
      let path = e.path();
      if path.extension()? != "json" {
        return None;
      }
      let id = path.file_stem()?.to_string_lossy().into_owned();
      let m: Meta = serde_json::from_slice(&std::fs::read(&path).ok()?).ok()?;
      Some((m.at, wire(&id, &m)))
    })
    .collect();
  out.sort_by_key(|(at, _)| std::cmp::Reverse(*at));
  out.into_iter().map(|(_, v)| v).collect()
}

/// Bytes of personal files, which count against the quota. Generated media does not.
fn personal_bytes(app: &App) -> u64 {
  items(app).iter().filter(|v| v["origin"] == "personal").map(|v| v["size"].as_u64().unwrap_or(0)).sum()
}

/// Starts an upload of `size` encrypted bytes. Returns the item's id.
pub fn begin(app: &App, origin: &str, size: u64, desc: &str) -> Result<String> {
  if !matches!(origin, "personal" | "generated") || desc.len() > 64 * 1024 {
    bail!("bad-request");
  }
  if origin == "personal" {
    let quota = app.store.read(|s| s.quota_gb) as u64 * 1_000_000_000;
    if personal_bytes(app) + size > quota {
      bail!("quota");
    }
  }
  let id = format!("s{}", hex::encode(crypto::random(8)));
  let d = dir(app, "blobs")?;
  std::fs::write(d.join(format!("{id}.part")), [])?;
  app.uploads.lock().expect("uploads lock").insert(id.clone(), (Meta { origin: origin.into(), size, at: now_ms(), desc: desc.into() }, Instant::now()));
  Ok(id)
}

/// Adds the next piece; `offset` must be where the upload stands.
pub fn put(app: &App, id: &str, offset: u64, data: &[u8]) -> Result<()> {
  let id = clean_id(id)?;
  let expected = app.uploads.lock().expect("uploads lock").get(id).map(|(m, _)| m.size).ok_or_else(|| anyhow!("not-found"))?;
  let path = dir(app, "blobs")?.join(format!("{id}.part"));
  let have = std::fs::metadata(&path).map(|m| m.len()).map_err(|_| anyhow!("not-found"))?;
  if offset != have || have + data.len() as u64 > expected {
    bail!("bad-request");
  }
  let mut f = std::fs::OpenOptions::new().append(true).open(&path)?;
  f.write_all(data)?;
  Ok(())
}

pub fn end(app: &App, id: &str) -> Result<Value> {
  let id = clean_id(id)?;
  let (meta, _) = app.uploads.lock().expect("uploads lock").remove(id).ok_or_else(|| anyhow!("not-found"))?;
  let d = dir(app, "blobs")?;
  let part = d.join(format!("{id}.part"));
  if std::fs::metadata(&part).map(|m| m.len()).unwrap_or(0) != meta.size {
    let _ = std::fs::remove_file(&part);
    bail!("bad-request");
  }
  std::fs::rename(&part, d.join(format!("{id}.bin")))?;
  write_atomic(&d.join(format!("{id}.json")), &serde_json::to_vec(&meta)?)?;
  Ok(wire(id, &meta))
}

pub fn get(app: &App, id: &str, offset: u64, length: usize) -> Result<Vec<u8>> {
  use std::io::{Read, Seek, SeekFrom};
  let id = clean_id(id)?;
  let mut f = std::fs::File::open(dir(app, "blobs")?.join(format!("{id}.bin"))).map_err(|_| anyhow!("not-found"))?;
  f.seek(SeekFrom::Start(offset))?;
  let mut out = Vec::new();
  f.take(length.min(MAX_PART) as u64).read_to_end(&mut out)?;
  Ok(out)
}

pub fn remove(app: &App, id: &str) -> Result<()> {
  let id = clean_id(id)?;
  let d = dir(app, "blobs")?;
  app.uploads.lock().expect("uploads lock").remove(id);
  for ext in ["bin", "json", "part"] {
    let _ = std::fs::remove_file(d.join(format!("{id}.{ext}")));
  }
  Ok(())
}

/// Forgets uploads that stopped halfway more than a day ago.
pub fn sweep(app: &App) {
  let stale: Vec<String> = {
    let mut up = app.uploads.lock().expect("uploads lock");
    let old: Vec<String> = up.iter().filter(|(_, (_, at))| at.elapsed() > Duration::from_secs(86_400)).map(|(id, _)| id.clone()).collect();
    for id in &old {
      up.remove(id);
    }
    old
  };
  if let Ok(d) = dir(app, "blobs") {
    for id in stale {
      let _ = std::fs::remove_file(d.join(format!("{id}.part")));
    }
  }
}

/* ---------- chats and memory ---------- */

pub fn put_chat(app: &App, id: &str, data: &[u8]) -> Result<()> {
  let id = clean_id(id)?;
  write_atomic(&dir(app, "chats")?.join(format!("{id}.bin")), data)
}

/// Chats stored or changed at `since` or later, as `{id, at, data}`.
pub fn chats_since(app: &App, since: u64) -> Result<Vec<Value>> {
  let mut out = Vec::new();
  for e in std::fs::read_dir(dir(app, "chats")?)?.flatten() {
    let path = e.path();
    if path.extension().is_none_or(|x| x != "bin") {
      continue;
    }
    let at = modified_ms(&path);
    if at < since {
      continue;
    }
    let id = path.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    out.push(json!({ "id": id, "at": at, "data": crypto::b64(&std::fs::read(&path)?) }));
  }
  Ok(out)
}

pub fn drop_chat(app: &App, id: &str) -> Result<()> {
  let id = clean_id(id)?;
  let _ = std::fs::remove_file(dir(app, "chats")?.join(format!("{id}.bin")));
  Ok(())
}

pub fn put_memory(app: &App, data: &[u8]) -> Result<()> {
  write_atomic(&app.config.data_dir.join("memory.bin"), data)
}

pub fn memory(app: &App) -> Option<Value> {
  let path = app.config.data_dir.join("memory.bin");
  let data = std::fs::read(&path).ok()?;
  Some(json!({ "at": modified_ms(&path), "data": crypto::b64(&data) }))
}

/* ---------- invites ---------- */

pub struct Invite {
  /// The device that made it, and the only one that may see or answer it.
  pub from: String,
  pub expires: Instant,
  /// The joined device, its key for receiving the space key, and that key's code-bound tag.
  pub joined: Option<(String, String, String)>,
  /// The space key sealed for the joined device: `{e, n, c}`.
  pub sealed: Option<Value>,
}

/// How long a joined device may wait for its space key.
const DELIVERY: Duration = Duration::from_secs(15 * 60);

pub fn epoch_ms(at: Instant) -> u64 {
  let left = at.saturating_duration_since(Instant::now());
  SystemTime::now().checked_add(left).and_then(|t| t.duration_since(UNIX_EPOCH).ok()).map(|d| d.as_millis() as u64).unwrap_or(0)
}

pub fn tidy_invites(app: &App) {
  app.invites.lock().expect("invites lock").retain(|_, i| i.expires + DELIVERY > Instant::now());
}
