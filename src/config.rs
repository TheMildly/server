//! `/etc/mildly/config.toml`. Every field has a default, so an empty file is a valid setup.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Runtime {
  Docker,
  Podman,
}

impl Runtime {
  pub fn label(self) -> &'static str {
    match self {
      Runtime::Docker => "Docker",
      Runtime::Podman => "Podman",
    }
  }

  fn default_socket(self) -> &'static str {
    match self {
      Runtime::Docker => "/var/run/docker.sock",
      Runtime::Podman => "/run/podman/podman.sock",
    }
  }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Config {
  /// Where the sealed API listens.
  pub listen: String,
  /// UDP port that answers LAN discovery while a pairing code is valid.
  pub discovery_port: u16,
  pub runtime: Runtime,
  /// The runtime's Docker-compatible socket; the runtime's usual path when empty.
  pub socket: String,
  pub data_dir: PathBuf,
  /// ntfy server used as the pairing rendezvous; empty switches it off.
  pub rendezvous: String,
  /// Addresses to announce (host or host:port), in order of preference. Found by itself when empty.
  pub public_addresses: Vec<String>,
  /// Image per container kind (and `front` for the HTTPS front), to replace the defaults.
  pub images: HashMap<String, String>,
  /// `internal` makes the front use its own certificate authority instead of Let's Encrypt,
  /// for servers that cannot be reached from the internet.
  pub front_tls: String,
  /// The deSEC API that hands out free names.
  pub free_names_api: String,
}

impl Default for Config {
  fn default() -> Self {
    Self {
      listen: "0.0.0.0:7680".into(),
      discovery_port: 7681,
      runtime: Runtime::Docker,
      socket: String::new(),
      data_dir: PathBuf::from("/var/lib/mildly"),
      rendezvous: "https://ntfy.sh".into(),
      public_addresses: Vec::new(),
      images: HashMap::new(),
      front_tls: String::new(),
      free_names_api: "https://desec.io/api/v1".into(),
    }
  }
}

impl Config {
  pub fn load(path: &Path) -> Result<Self> {
    match std::fs::read_to_string(path) {
      Ok(text) => toml::from_str(&text).with_context(|| format!("reading {}", path.display())),
      Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
      Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
  }

  pub fn socket(&self) -> &str {
    if self.socket.is_empty() { self.runtime.default_socket() } else { &self.socket }
  }

  pub fn port(&self) -> u16 {
    self.listen.rsplit(':').next().and_then(|p| p.parse().ok()).unwrap_or(7680)
  }

  /// The local admin socket the `pair` command talks to.
  pub fn admin_socket(&self) -> PathBuf {
    self.data_dir.join("admin.sock")
  }

  pub fn image(&self, kind: &str) -> String {
    if let Some(i) = self.images.get(kind) {
      return i.clone();
    }
    match kind {
      "database" => "postgres:17-alpine",
      "logic" | "worker" => "node:22-alpine",
      "front" => "caddy:2-alpine",
      _ => "nginx:alpine",
    }
    .to_string()
  }
}
