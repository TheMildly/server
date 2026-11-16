//! What the engine remembers between restarts: its key, the paired devices and the choices
//! from setup. One JSON file, written atomically and readable by root only.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn now_ms() -> u64 {
  SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
  pub id: String,
  pub name: String,
  pub kind: String,
  /// The device's public signing key, raw P-256, base64url.
  pub key: String,
  pub owner: bool,
  pub added_at: u64,
  pub last_seen: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Saved {
  /// The server key's secret scalar, base64url.
  pub server_key: String,
  pub created_at: u64,
  pub setup_done: bool,
  pub quota_gb: u32,
  /// `DomainInfo` as the app sent it, or null for the bare address.
  pub domain: Option<serde_json::Value>,
  pub devices: Vec<Device>,
  /// deSEC token for free names, set by `mildly-server free-names`. Never leaves the server.
  pub desec_token: String,
  /// The `name.dedyn.io` this server's deSEC account holds, if any.
  pub free_domain: String,
}

pub struct Store {
  path: PathBuf,
  saved: Mutex<Saved>,
}

impl Store {
  pub fn open(dir: &Path) -> Result<Self> {
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let path = dir.join("state.json");
    let saved = match std::fs::read_to_string(&path) {
      Ok(text) => serde_json::from_str(&text).context("reading state.json")?,
      Err(e) if e.kind() == std::io::ErrorKind::NotFound => Saved::default(),
      Err(e) => return Err(e).context("reading state.json"),
    };
    Ok(Self { path, saved: Mutex::new(saved) })
  }

  pub fn read<T>(&self, f: impl FnOnce(&Saved) -> T) -> T {
    f(&self.saved.lock().expect("state lock"))
  }

  /// Changes the state and writes it before returning.
  pub fn write<T>(&self, f: impl FnOnce(&mut Saved) -> T) -> Result<T> {
    let mut saved = self.saved.lock().expect("state lock");
    let out = f(&mut saved);
    let text = serde_json::to_vec_pretty(&*saved)?;
    let tmp = self.path.with_extension("json.tmp");
    std::fs::write(&tmp, text).context("writing state")?;
    #[cfg(unix)]
    {
      use std::os::unix::fs::PermissionsExt;
      std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    }
    std::fs::rename(&tmp, &self.path).context("writing state")?;
    Ok(out)
  }
}
