//! Mildly Server: the personal server the Mildly app pairs with. See docs/SERVER.md.
//!
//!   mildly-server [run] [--config PATH]   start the engine (what the systemd unit runs)
//!   mildly-server pair  [--config PATH]   print a fresh pairing code and QR code
//!   mildly-server free-names --email ADDRESS | --token TOKEN
//!                                         let the server register free names (name.dedyn.io)
//!   mildly-server version

mod config;
mod crypto;
mod domains;
mod metrics;
mod pairing;
mod rpc;
mod runtime;
mod state;
mod terminal;

use anyhow::{Context, Result};
use axum::routing::{get, post};
use axum::Router;
use config::Config;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tower_http::cors::CorsLayer;

/// Everything the request handlers share.
pub struct App {
  pub config: Config,
  pub key: crypto::ServerKey,
  pub store: state::Store,
  /// The machine's name, shown in the app.
  pub name: String,
  pub os: String,
  pub disk_gb: u32,
  /// Where the app can reach the API, best first ("203.0.113.5:7680").
  pub addresses: Vec<String>,
  pub pairing: Mutex<Option<pairing::Pairing>>,
  pub nonces: Mutex<HashMap<String, u64>>,
  pub metrics: Arc<metrics::Metrics>,
  pub containers: Option<Arc<runtime::Containers>>,
  pub terminals: terminal::Terminals,
  /// What the HTTPS front was last configured for (address and sites).
  pub front: Mutex<String>,
  /// One change to the front at a time.
  pub front_busy: tokio::sync::Mutex<()>,
}

fn main() {
  // Errors end the command with one plain sentence, not a debug dump.
  if let Err(e) = start() {
    eprintln!("\n  mildly-server: {e:#}\n");
    std::process::exit(1);
  }
}

fn start() -> Result<()> {
  let args: Vec<String> = std::env::args().skip(1).collect();
  let config_path = args
    .iter()
    .position(|a| a == "--config")
    .and_then(|i| args.get(i + 1))
    .map(PathBuf::from)
    .unwrap_or_else(|| PathBuf::from("/etc/mildly/config.toml"));
  let flag = |name: &str| args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned();
  let values: Vec<String> = ["--config", "--email", "--token"].iter().filter_map(|f| flag(f)).collect();
  let command = args.iter().find(|a| !a.starts_with("--") && !values.contains(a)).cloned();
  let config = Config::load(&config_path)?;

  tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into())).init();
  let rt = tokio::runtime::Runtime::new()?;
  match command.as_deref().unwrap_or("run") {
    "run" => rt.block_on(run(config)),
    "pair" => rt.block_on(ask_for_code(&config)),
    "free-names" => rt.block_on(free_names(&config, flag("--email"), flag("--token"))),
    "version" => {
      println!("mildly-server {}", env!("CARGO_PKG_VERSION"));
      Ok(())
    }
    other => anyhow::bail!("unknown command `{other}`; use run, pair, free-names or version"),
  }
}

async fn run(config: Config) -> Result<()> {
  let store = state::Store::open(&config.data_dir)?;
  let saved_key = store.read(|s| s.server_key.clone());
  let key = if saved_key.is_empty() {
    let k = crypto::ServerKey::generate();
    store.write(|s| {
      s.server_key = crypto::b64(&k.secret_bytes());
      s.created_at = state::now_ms();
      s.quota_gb = 20;
    })?;
    k
  } else {
    crypto::ServerKey::from_bytes(&crypto::unb64(&saved_key)?)?
  };

  let containers = match runtime::Containers::connect(&config) {
    Ok(c) if c.version().await.is_some() => Some(Arc::new(c)),
    _ => {
      tracing::warn!("{} is not answering at {}; containers are off until it does", config.runtime.label(), config.socket());
      None
    }
  };
  let app = Arc::new(App {
    addresses: addresses(&config).await,
    name: hostname::get().ok().and_then(|h| h.into_string().ok()).unwrap_or_else(|| "server".into()),
    os: metrics::os_name(),
    disk_gb: metrics::disk_total_gb(&config.data_dir),
    key,
    store,
    pairing: Mutex::new(None),
    nonces: Mutex::new(HashMap::new()),
    metrics: Arc::new(metrics::Metrics::default()),
    containers,
    terminals: terminal::Terminals::default(),
    front: Mutex::new(String::new()),
    front_busy: tokio::sync::Mutex::new(()),
    config,
  });

  tokio::spawn(metrics::sample_forever(app.metrics.clone()));
  tokio::spawn(pairing::lan_responder(app.clone()));
  tokio::spawn(admin(app.clone()));
  tokio::spawn(domains::keep(app.clone()));

  // A fresh server prints its first code by itself, so the installer's output ends with it.
  if app.store.read(|s| s.devices.is_empty()) {
    let code = pairing::start(app.clone()).await;
    print_code(&code, &pairing::qr_payload(&app, &code));
  }

  let router = Router::new()
    .route("/v1/hello", get(rpc::hello))
    .route("/v1/rpc", post(rpc::rpc))
    .layer(CorsLayer::permissive())
    .with_state(app.clone());
  let listener = tokio::net::TcpListener::bind(&app.config.listen).await.with_context(|| format!("listening on {}", app.config.listen))?;
  tracing::info!("Mildly Server {} on {} ({})", env!("CARGO_PKG_VERSION"), app.config.listen, app.addresses.join(", "));
  axum::serve(listener, router).await?;
  Ok(())
}

/// Where the app can reach this machine: the configured addresses, or the public and local IPs.
async fn addresses(config: &Config) -> Vec<String> {
  let port = config.port();
  let with_port = |a: &str| if a.contains(':') { a.to_string() } else { format!("{a}:{port}") };
  if !config.public_addresses.is_empty() {
    return config.public_addresses.iter().map(|a| with_port(a)).collect();
  }
  let mut out = Vec::new();
  // Asks a public echo once; a server behind NAT simply keeps its local address.
  let public = reqwest::Client::builder().timeout(std::time::Duration::from_secs(4)).build().ok();
  if let Some(client) = public {
    if let Ok(res) = client.get("https://api.ipify.org").send().await {
      if let Ok(ip) = res.text().await {
        if ip.trim().parse::<std::net::IpAddr>().is_ok() {
          out.push(with_port(ip.trim()));
        }
      }
    }
  }
  // The address of the interface that would carry traffic out; nothing is sent.
  if let Ok(sock) = std::net::UdpSocket::bind("0.0.0.0:0") {
    if sock.connect("192.0.2.1:9").is_ok() {
      if let Ok(local) = sock.local_addr() {
        let a = with_port(&local.ip().to_string());
        if !out.contains(&a) {
          out.push(a);
        }
      }
    }
  }
  out
}

fn print_code(code: &str, payload: &str) {
  println!();
  println!("  Pair this server with Mildly");
  println!();
  println!("  Code: {}    (works once, for ten minutes)", pairing::grouped(code));
  println!();
  for line in pairing::qr_text(payload).lines() {
    println!("  {line}");
  }
  println!();
  println!("  In the app: Settings → Personal server → type the code or scan the QR code.");
  println!("  Need a new code later? Run: mildly-server pair");
  println!();
}

/// The local admin socket: `mildly-server pair` asks the running engine for a code through it.
async fn admin(app: Arc<App>) {
  let path = app.config.admin_socket();
  let _ = std::fs::remove_file(&path);
  let listener = match UnixListener::bind(&path) {
    Ok(l) => l,
    Err(e) => return tracing::warn!("admin socket: {e}"),
  };
  #[cfg(unix)]
  {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
  }
  loop {
    let Ok((stream, _)) = listener.accept().await else { continue };
    let app = app.clone();
    tokio::spawn(async move {
      let (read, mut write) = stream.into_split();
      let mut line = String::new();
      if BufReader::new(read).read_line(&mut line).await.is_err() {
        return;
      }
      let reply = match line.trim().split_once(' ').unwrap_or((line.trim(), "")) {
        ("pair", _) => {
          let code = pairing::start(app.clone()).await;
          serde_json::json!({ "code": code, "payload": pairing::qr_payload(&app, &code) })
        }
        ("free-names", token) if !token.is_empty() => match app.store.write(|s| s.desec_token = token.to_string()) {
          Ok(()) => serde_json::json!({ "ok": true }),
          Err(e) => serde_json::json!({ "error": e.to_string() }),
        },
        _ => serde_json::json!({ "error": "unknown request" }),
      };
      let _ = write.write_all(reply.to_string().as_bytes()).await;
    });
  }
}

async fn admin_call(config: &Config, line: &str) -> Result<serde_json::Value> {
  let mut stream = UnixStream::connect(config.admin_socket()).await.context("the engine is not running (systemctl status mildly)")?;
  stream.write_all(format!("{line}\n").as_bytes()).await?;
  let mut reply = String::new();
  stream.read_to_string(&mut reply).await?;
  Ok(serde_json::from_str(&reply)?)
}

/// Gives the engine a deSEC account: a new one for `--email` (deSEC sends one confirmation
/// email), or an existing account's token.
async fn free_names(config: &Config, email: Option<String>, token: Option<String>) -> Result<()> {
  // Checks the engine answers before anything is signed up.
  UnixStream::connect(config.admin_socket()).await.context("the engine is not running (systemctl status mildly)")?;
  let token = match (token, email) {
    (Some(t), _) => {
      domains::verify_token(&config.free_names_api, &t).await?;
      t
    }
    (None, Some(email)) => domains::register(&config.free_names_api, &email).await?,
    (None, None) => anyhow::bail!("use --email ADDRESS to sign the server up with deSEC, or --token TOKEN for an account you have"),
  };
  let v = admin_call(config, &format!("free-names {token}")).await?;
  if let Some(e) = v["error"].as_str() {
    anyhow::bail!("{e}");
  }
  println!("\n  Free names are on. In the app, pick a name under .dedyn.io for this server.\n");
  Ok(())
}

async fn ask_for_code(config: &Config) -> Result<()> {
  let v = admin_call(config, "pair").await?;
  print_code(v["code"].as_str().unwrap_or(""), v["payload"].as_str().unwrap_or(""));
  Ok(())
}
