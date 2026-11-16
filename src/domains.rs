//! Addresses and HTTPS (docs/SERVER.md, section 7).
//!
//! - Free names come from deSEC (`name.dedyn.io`): one per deSEC account, so the server holds
//!   its own account. `mildly-server free-names` signs it up (deSEC sends one confirmation
//!   email) or takes an existing token; after that the app's free-name search and choice work.
//! - Own domains: the user points `name` and `*.name` at the server; the engine checks.
//! - HTTPS: a Caddy container ("the front") answers on 80/443 for the chosen name and
//!   `<site>.<name>` for each web, mini-app and logic container, with certificates from
//!   Let's Encrypt. If another app already holds 80/443, the front stays off and says so.

use crate::runtime::NETWORK;
use crate::App;
use anyhow::{anyhow, bail, Context, Result};
use bollard::models::{ContainerCreateBody, ExecConfig, HostConfig, PortBinding, RestartPolicy, RestartPolicyNameEnum};
use bollard::query_parameters::{
  CreateContainerOptionsBuilder, CreateImageOptionsBuilder, InspectContainerOptions, RemoveContainerOptionsBuilder, StartContainerOptions,
};
use futures_util::StreamExt;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

pub const FREE_ZONE: &str = "dedyn.io";
const FRONT: &str = "mildly-front";

fn http() -> reqwest::Client {
  reqwest::Client::builder().timeout(Duration::from_secs(20)).user_agent("mildly-server").build().expect("http client")
}

/* ---------- DNS, over HTTPS so local resolvers and caches do not get in the way ---------- */

/// Records of one type, and whether the name exists at all.
pub async fn lookup(name: &str, kind: &str) -> Result<(bool, Vec<String>)> {
  let url = format!("https://cloudflare-dns.com/dns-query?name={name}&type={kind}");
  let v: Value = http().get(url).header("Accept", "application/dns-json").send().await?.json().await?;
  let status = v["Status"].as_u64().unwrap_or(2);
  let answers = v["Answer"].as_array().map(|a| a.iter().filter_map(|r| r["data"].as_str().map(str::to_owned)).collect()).unwrap_or_default();
  Ok((status != 3, answers))
}

/// The server's public IPv4 address, for A records.
pub fn public_ipv4(app: &App) -> Option<String> {
  app.addresses.iter().filter_map(|a| a.rsplit_once(':').map(|(h, _)| h.to_string())).find(|h| match h.parse::<IpAddr>() {
    Ok(IpAddr::V4(ip)) => !ip.is_private() && !ip.is_loopback() && !ip.is_link_local(),
    _ => false,
  })
}

/* ---------- free names ---------- */

fn slug(wanted: &str) -> String {
  let s: String = wanted.trim().to_lowercase().chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '-' }).collect();
  let s = s.split('-').filter(|p| !p.is_empty()).collect::<Vec<_>>().join("-");
  s.chars().take(40).collect()
}

/// Names under dedyn.io near what the user typed, and whether each is still open.
pub async fn search(app: &App, wanted: &str) -> Result<Vec<Value>> {
  if app.store.read(|s| s.desec_token.is_empty()) {
    bail!("no-free-names");
  }
  let base = slug(wanted);
  if base.is_empty() {
    return Ok(vec![]);
  }
  let suffix = hex::encode(crate::crypto::random(2));
  let candidates = [base.clone(), format!("{base}-home"), format!("{base}-{suffix}")];
  let mut out = Vec::new();
  for c in candidates {
    let name = format!("{c}.{FREE_ZONE}");
    // A taken name is a delegated zone, so it has name servers.
    let (exists, ns) = lookup(&name, "NS").await.unwrap_or((true, vec!["?".into()]));
    out.push(json!({ "name": name, "free": !exists || ns.is_empty() }));
  }
  Ok(out)
}

fn desec(token: &str, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
  req.header("Authorization", format!("Token {token}"))
}

/// Takes `name.dedyn.io` for this server's deSEC account and points it, and every name under
/// it, at the server.
async fn claim_free(app: &App, name: &str) -> Result<()> {
  let api = &app.config.free_names_api;
  let token = app.store.read(|s| s.desec_token.clone());
  if token.is_empty() {
    bail!("no-free-names");
  }
  let ip = public_ipv4(app).ok_or_else(|| anyhow!("no-public-address"))?;
  let client = http();
  let current = app.store.read(|s| s.free_domain.clone());
  if current != name {
    // deSEC allows one dedyn.io name per account: let the old one go first.
    if !current.is_empty() {
      let _ = desec(&token, client.delete(format!("{api}/domains/{current}/"))).send().await;
    }
    let res = desec(&token, client.post(format!("{api}/domains/"))).json(&json!({ "name": name })).send().await.context("dns")?;
    match res.status().as_u16() {
      201 => {}
      400 | 409 => bail!("name-taken"),
      401 | 403 => bail!("no-free-names"),
      _ => bail!("dns"),
    }
    app.store.write(|s| s.free_domain = name.to_string())?;
  }
  let records = json!([
    { "subname": "", "type": "A", "ttl": 3600, "records": [ip] },
    { "subname": "*", "type": "A", "ttl": 3600, "records": [ip] },
  ]);
  let res = desec(&token, client.put(format!("{api}/domains/{name}/rrsets/"))).json(&records).send().await.context("dns")?;
  if !res.status().is_success() {
    bail!("dns");
  }
  Ok(())
}

/* ---------- own domains ---------- */

/// Whether `name` (and a test name under it) point at this server. Returns the addresses found.
pub async fn check_own(app: &App, name: &str) -> Result<Value> {
  let name = name.trim().trim_end_matches('.').to_lowercase();
  if !name.contains('.') || name.ends_with(FREE_ZONE) {
    bail!("bad-name");
  }
  let want = public_ipv4(app);
  let (_, root) = lookup(&name, "A").await.context("dns")?;
  let (_, wild) = lookup(&format!("mildly-check.{name}"), "A").await.context("dns")?;
  // The name itself must point here; `*.name` gives each site its own name and is advised.
  let ok = want.as_ref().is_some_and(|w| root.contains(w));
  let wildcard = want.as_ref().is_some_and(|w| wild.contains(w));
  Ok(json!({ "ok": ok, "found": root, "wildcard": wildcard, "want": want }))
}

/* ---------- setting the address ---------- */

/// Changes the address: a free name, the user's own domain, or none (the bare IP).
pub async fn set(app: &App, domain: Option<&Value>) -> Result<()> {
  let before = app.store.read(|s| s.domain.clone());
  let chosen = domain.filter(|d| !d.is_null());
  match chosen {
    Some(d) => {
      let name = d["name"].as_str().unwrap_or("").trim().to_lowercase();
      match d["kind"].as_str() {
        Some("free") if name.ends_with(&format!(".{FREE_ZONE}")) => claim_free(app, &name).await?,
        Some("own") => {
          let check = check_own(app, &name).await?;
          if !check["ok"].as_bool().unwrap_or(false) {
            bail!("not-pointing");
          }
        }
        _ => bail!("bad-name"),
      }
      let info = json!({ "name": name, "kind": d["kind"], "https": "issuing", "renewsInDays": 90 });
      app.store.write(|s| s.domain = Some(info))?;
    }
    None => app.store.write(|s| s.domain = None)?,
  }
  // The address only counts once the front serves it; otherwise the old one stays.
  if let Err(e) = apply(app).await {
    app.store.write(|s| s.domain = before)?;
    let _ = apply(app).await;
    return Err(e);
  }
  *app.front.lock().expect("front lock") = signature(app).await;
  Ok(())
}

async fn signature(app: &App) -> String {
  let domain = app.store.read(|s| s.domain.as_ref().and_then(|d| d["name"].as_str().map(str::to_owned)));
  let sites = match app.containers.as_ref() {
    Some(c) => c.sites().await.unwrap_or_default(),
    None => Vec::new(),
  };
  format!("{domain:?} {sites:?}")
}

/// Keeps the front in step with the containers: sites made, changed or removed by the app,
/// the model or by hand show up under the address within a few seconds.
pub async fn keep(app: std::sync::Arc<App>) {
  loop {
    tokio::time::sleep(Duration::from_secs(5)).await;
    if app.store.read(|s| s.domain.is_none()) {
      continue;
    }
    let now = signature(&app).await;
    if *app.front.lock().expect("front lock") == now {
      continue;
    }
    let result = apply(&app).await;
    // A failure is tried again when something changes, or after a minute.
    *app.front.lock().expect("front lock") = now;
    if let Err(e) = result {
      tracing::warn!("front: {e:#}");
      tokio::time::sleep(Duration::from_secs(55)).await;
      *app.front.lock().expect("front lock") = String::new();
    }
  }
}

/// The domain as the app shows it, with the HTTPS state read from the front's certificates.
pub fn current(app: &App) -> Option<Value> {
  let mut d = app.store.read(|s| s.domain.clone())?;
  let name = d["name"].as_str().unwrap_or("").to_string();
  let certs = app.config.data_dir.join("front/data/caddy/certificates");
  let issued = walk(&certs).into_iter().any(|p| p.file_name().is_some_and(|f| f.to_string_lossy() == format!("{name}.crt")));
  d["https"] = json!(if issued { "active" } else { "issuing" });
  Some(d)
}

fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
  let mut out = Vec::new();
  if let Ok(entries) = std::fs::read_dir(dir) {
    for e in entries.flatten() {
      let p = e.path();
      if p.is_dir() {
        out.extend(walk(&p));
      } else {
        out.push(p);
      }
    }
  }
  out
}

/* ---------- the HTTPS front ---------- */

fn port_free(port: u16) -> bool {
  std::net::TcpListener::bind(("0.0.0.0", port)).is_ok()
}

/// Writes the front's configuration for the current address and sites, and starts or reloads it.
/// With no address the front is removed.
pub async fn apply(app: &App) -> Result<()> {
  let Some(containers) = app.containers.as_ref() else { return Ok(()) };
  let _one = app.front_busy.lock().await;
  let docker = containers.docker();
  let domain = app.store.read(|s| s.domain.as_ref().and_then(|d| d["name"].as_str().map(str::to_owned)));
  let exists = docker.inspect_container(FRONT, None::<InspectContainerOptions>).await.ok();
  let Some(domain) = domain else {
    if exists.is_some() {
      docker.remove_container(FRONT, Some(RemoveContainerOptionsBuilder::new().force(true).build())).await?;
    }
    return Ok(());
  };

  let dir = app.config.data_dir.join("front");
  std::fs::create_dir_all(dir.join("data"))?;
  std::fs::create_dir_all(dir.join("config"))?;
  let sites = containers.sites().await?;
  let mut caddy = String::new();
  if app.config.front_tls == "internal" {
    caddy.push_str("{\n\tlocal_certs\n}\n\n");
  }
  // The bare name opens the first site, or says the server is there.
  match sites.first() {
    Some((_, host, port)) => caddy.push_str(&format!("{domain} {{\n\treverse_proxy {host}:{port}\n}}\n\n")),
    None => caddy.push_str(&format!("{domain} {{\n\trespond \"Mildly Server\" 200\n}}\n\n")),
  }
  for (name, host, port) in &sites {
    caddy.push_str(&format!("{name}.{domain} {{\n\treverse_proxy {host}:{port}\n}}\n\n"));
  }
  std::fs::write(dir.join("Caddyfile"), caddy)?;

  let running = exists.as_ref().and_then(|i| i.state.as_ref()).and_then(|s| s.running).unwrap_or(false);
  if running {
    let config = ExecConfig {
      attach_stdout: Some(true),
      attach_stderr: Some(true),
      cmd: Some(vec!["caddy".into(), "reload".into(), "--config".into(), "/etc/caddy/Caddyfile".into(), "--adapter".into(), "caddyfile".into()]),
      ..Default::default()
    };
    let exec = docker.create_exec(FRONT, config).await?;
    if let bollard::exec::StartExecResults::Attached { mut output, .. } = docker.start_exec(&exec.id, None).await? {
      while output.next().await.is_some() {}
    }
    return Ok(());
  }
  if exists.is_some() {
    docker.remove_container(FRONT, Some(RemoveContainerOptionsBuilder::new().force(true).build())).await?;
  }
  // Another app already serving the web keeps its ports; the front does not take them.
  if !port_free(80) || !port_free(443) {
    bail!("ports-busy");
  }
  let image = app.config.image("front");
  let mut pull = docker.create_image(Some(CreateImageOptionsBuilder::new().from_image(&image).build()), None, None);
  while let Some(step) = pull.next().await {
    step.with_context(|| format!("pulling {image}"))?;
  }
  let bind = |p: &str| Some(vec![PortBinding { host_ip: Some("0.0.0.0".into()), host_port: Some(p.into()) }]);
  let ports: HashMap<String, Option<Vec<PortBinding>>> = HashMap::from([("80/tcp".into(), bind("80")), ("443/tcp".into(), bind("443")), ("443/udp".into(), bind("443"))]);
  let body = ContainerCreateBody {
    image: Some(image),
    labels: Some(HashMap::from([("ai.mildly.role".to_string(), "front".to_string())])),
    exposed_ports: Some(vec!["80/tcp".into(), "443/tcp".into(), "443/udp".into()]),
    host_config: Some(HostConfig {
      binds: Some(vec![
        format!("{}:/etc/caddy/Caddyfile:ro", dir.join("Caddyfile").display()),
        format!("{}:/data", dir.join("data").display()),
        format!("{}:/config", dir.join("config").display()),
      ]),
      port_bindings: Some(ports),
      network_mode: Some(NETWORK.into()),
      restart_policy: Some(RestartPolicy { name: Some(RestartPolicyNameEnum::UNLESS_STOPPED), ..Default::default() }),
      ..Default::default()
    }),
    ..Default::default()
  };
  docker.create_container(Some(CreateContainerOptionsBuilder::new().name(FRONT).build()), body).await?;
  docker.start_container(FRONT, None::<StartContainerOptions>).await?;
  Ok(())
}

/* ---------- signing the server up with deSEC (CLI) ---------- */

/// Signs a new deSEC account up for this server and waits for the email to be confirmed.
/// Returns a long-lived token.
pub async fn register(api: &str, email: &str) -> Result<String> {
  let client = http();
  let password = hex::encode(crate::crypto::random(24));
  let res = client.post(format!("{api}/auth/")).json(&json!({ "email": email, "password": password, "outreach_preference": false })).send().await?;
  if !res.status().is_success() {
    bail!("deSEC did not accept the sign-up: {}", res.text().await.unwrap_or_default());
  }
  println!("\n  deSEC sent a confirmation email to {email}.");
  println!("  Open the link in it (deSEC may ask you to solve a short captcha there).");
  println!("  This waits until the account is confirmed…\n");
  for _ in 0..240 {
    tokio::time::sleep(Duration::from_secs(5)).await;
    let login = client.post(format!("{api}/auth/login/")).json(&json!({ "email": email, "password": password })).send().await?;
    if login.status().is_success() {
      let v: Value = login.json().await?;
      let session = v["token"].as_str().ok_or_else(|| anyhow!("deSEC sent no token"))?.to_string();
      let made: Value = client
        .post(format!("{api}/auth/tokens/"))
        .header("Authorization", format!("Token {session}"))
        .json(&json!({ "name": "mildly-server" }))
        .send()
        .await?
        .json()
        .await?;
      return made["token"].as_str().map(str::to_owned).ok_or_else(|| anyhow!("deSEC sent no token"));
    }
  }
  bail!("the account was not confirmed within twenty minutes; run this again")
}

/// Checks a token the user made on desec.io themselves.
pub async fn verify_token(api: &str, token: &str) -> Result<()> {
  let res = desec(token, http().get(format!("{api}/domains/"))).send().await?;
  if !res.status().is_success() {
    bail!("deSEC did not accept this token");
  }
  Ok(())
}
