//! `POST /v1/rpc`: one sealed call, one sealed answer (docs/SERVER.md, sections 2 and 4).

use crate::crypto::{self, b64, unb64};
use crate::domains;
use crate::space;
use crate::pairing::{self, Check};
use crate::runtime::Spec;
use crate::state::{now_ms, Device};
use crate::App;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;

/// How far a request's clock may be from the server's, and how long its nonce is remembered.
const WINDOW_MS: u64 = 120_000;

#[derive(Deserialize)]
pub struct Envelope {
  /// The app's ephemeral public key.
  e: String,
  n: String,
  c: String,
}

#[derive(Deserialize)]
struct Call {
  /// Method.
  m: String,
  /// Params as the exact JSON text that was signed.
  p: String,
  /// Device id; absent for `pair`.
  d: Option<String>,
  t: u64,
  r: String,
  s: String,
}

/// An error the app turns into a sentence. Codes are listed in docs/SERVER.md, section 4.
pub struct Fail(pub &'static str);

impl From<anyhow::Error> for Fail {
  fn from(e: anyhow::Error) -> Self {
    let text = e.to_string();
    for code in CODES {
      if text == code {
        return Fail(code);
      }
    }
    tracing::warn!("runtime: {e:#}");
    Fail("runtime")
  }
}

/// Codes the engine's modules raise as plain errors and the app knows.
const CODES: [&str; 17] = [
  "exists",
  "quota",
  "bad-request",
  "not-found",
  "bad-kind",
  "bad-name",
  "bad-path",
  "unavailable",
  "external",
  "too-large",
  "no-free-names",
  "name-taken",
  "no-public-address",
  "not-pointing",
  "ports-busy",
  "dns",
  "not-owner",
];

type Out = Result<Value, Fail>;

pub async fn hello(State(app): State<Arc<App>>) -> Json<Value> {
  Json(json!({ "name": "mildly", "version": env!("CARGO_PKG_VERSION"), "key": b64(app.key.public_raw()) }))
}

pub async fn rpc(State(app): State<Arc<App>>, headers: HeaderMap, Json(env): Json<Envelope>) -> Response {
  let opened = (|| {
    let key = app.key.request_key(&unb64(&env.e).ok()?).ok()?;
    let plain = crypto::open(&key, &unb64(&env.n).ok()?, &unb64(&env.c).ok()?, crypto::REQ_AAD).ok()?;
    Some((key, serde_json::from_slice::<Call>(&plain).ok()?))
  })();
  let Some((key, call)) = opened else { return StatusCode::BAD_REQUEST.into_response() };
  let host = headers.get("host").and_then(|h| h.to_str().ok()).map(|h| h.rsplit_once(':').map(|(a, _)| a).unwrap_or(h)).unwrap_or("").to_string();

  let answer = match handle(&app, &call, &host).await {
    Ok(v) => json!({ "ok": true, "v": v }),
    Err(Fail(code)) => json!({ "ok": false, "error": { "code": code } }),
  };
  let (iv, ct) = crypto::seal(&key, answer.to_string().as_bytes(), crypto::RES_AAD);
  Json(json!({ "n": b64(&iv), "c": b64(&ct) })).into_response()
}

fn signed(call: &Call) -> Vec<u8> {
  format!("{}\n{}\n{}\n{}", call.m, call.t, call.r, crypto::sha256_b64(call.p.as_bytes())).into_bytes()
}

/// Rejects stale and repeated requests.
fn fresh(app: &App, call: &Call) -> bool {
  let now = now_ms();
  if call.t + WINDOW_MS < now || call.t > now + WINDOW_MS || call.r.len() < 16 {
    return false;
  }
  let mut seen = app.nonces.lock().expect("nonce lock");
  seen.retain(|_, at| *at + 2 * WINDOW_MS > now);
  seen.insert(call.r.clone(), now).is_none()
}

async fn handle(app: &Arc<App>, call: &Call, host: &str) -> Out {
  if !fresh(app, call) {
    return Err(Fail("stale"));
  }
  let params: Value = serde_json::from_str(&call.p).map_err(|_| Fail("bad-request"))?;
  if call.m == "pair" {
    return pair(app, call, &params);
  }
  let device = app
    .store
    .read(|s| s.devices.iter().find(|d| Some(&d.id) == call.d.as_ref()).cloned())
    .ok_or(Fail("unknown-device"))?;
  if !crypto::verify(&unb64(&device.key).map_err(|_| Fail("unknown-device"))?, &signed(call), &unb64(&call.s).unwrap_or_default()) {
    return Err(Fail("unknown-device"));
  }
  seen(app, &device);
  let owner = |out: Out| if device.owner { out } else { Err(Fail("not-owner")) };
  let text = |key: &str| params.get(key).and_then(Value::as_str).unwrap_or("").to_string();
  let number = |key: &str| params.get(key).and_then(Value::as_u64);

  match call.m.as_str() {
    "load" => snapshot(app, &device, host, true).await,
    "setup" if device.owner => setup(app, &device, &params, host).await,
    // A device that joined later walks the same wizard; the owner's choices stay.
    "setup" if app.store.read(|s| s.setup_done) => snapshot(app, &device, host, false).await,
    "setup" => Err(Fail("not-owner")),
    "unpair" => {
      app.store.write(|s| s.devices.retain(|d| d.id != device.id)).map_err(Fail::from)?;
      Ok(Value::Null)
    }
    "metrics" => Ok(json!(app.metrics.recent())),

    /* ---------- containers: the app's buttons and the model's tools ---------- */
    "containers.list" => Ok(json!(runtime(app)?.list(host, domain(app).as_deref()).await?)),
    "containers.create" => {
      let c = runtime(app)?;
      // Names are host names on the shared network and under the address: one container each.
      let wanted = crate::runtime::clean_name(&text("name")).ok_or(Fail("bad-name"))?;
      if c.list(host, None).await?.iter().any(|x| x["name"] == wanted.as_str() && x["external"] == false) {
        return Err(Fail("exists"));
      }
      Ok(c.create(&text("kind"), &wanted, spec(&params))?)
    }
    "containers.configure" => {
      let id = text("id");
      runtime(app)?.configure(&id, spec(&params)).await?;
      one(app, host, &id).await
    }
    "containers.action" => {
      let id = text("id");
      runtime(app)?.action(&id, &text("action")).await?;
      one(app, host, &id).await
    }
    "containers.remove" => {
      runtime(app)?.remove(&text("id")).await?;
      Ok(Value::Null)
    }
    "containers.logs" => Ok(json!(runtime(app)?.logs(&text("id")).await?)),
    "containers.inspect" => Ok(runtime(app)?.inspect(&text("id")).await?),
    "containers.read" => Ok(json!(runtime(app)?.read(&text("id"), &text("path")).await?)),
    "containers.write" => Ok(json!({ "path": runtime(app)?.write(&text("id"), &text("path"), &text("content")).await? })),
    "containers.exec" => {
      let wait = Duration::from_secs(number("timeoutSec").unwrap_or(60).clamp(1, 300));
      Ok(runtime(app)?.exec(&text("id"), &text("command"), wait).await?)
    }

    /* ---------- terminals ---------- */
    "terminal.open" => {
      let (cols, rows) = (number("cols").unwrap_or(80) as u16, number("rows").unwrap_or(24) as u16);
      let target = text("target");
      let id = if target == "host" {
        // The server's own shell is root on the machine: the owner's alone.
        if !device.owner {
          return Err(Fail("not-owner"));
        }
        app.terminals.open_host(cols, rows, &device.id)?
      } else {
        let c = runtime(app)?;
        let found = c.locate(&target).await?;
        // Apps that were on the machine before Mildly belong to whoever set the machine up.
        if found.external && !device.owner {
          return Err(Fail("not-owner"));
        }
        let workdir = (!found.external).then(|| crate::runtime::layout(&found.kind).0);
        app.terminals.open_container(c.docker(), &found.docker_id, workdir, cols, rows, &device.id).await?
      };
      Ok(json!({ "id": id }))
    }
    "terminal.read" => {
      let wait = Duration::from_millis(number("waitMs").unwrap_or(20_000).min(25_000));
      let (data, next, closed) = app.terminals.read(&text("id"), &device.id, number("from").unwrap_or(0), wait).await?;
      Ok(json!({ "data": data, "next": next, "closed": closed }))
    }
    "terminal.write" => {
      let data = unb64(&text("data")).map_err(|_| Fail("bad-request"))?;
      app.terminals.write(&text("id"), &device.id, &data)?;
      Ok(Value::Null)
    }
    "terminal.resize" => {
      app.terminals.resize(&text("id"), &device.id, number("cols").unwrap_or(80) as u16, number("rows").unwrap_or(24) as u16).await?;
      Ok(Value::Null)
    }
    "terminal.close" => {
      app.terminals.close(&text("id"), &device.id);
      Ok(Value::Null)
    }

    /* ---------- address ---------- */
    "domain.search" => Ok(json!(domains::search(app, &text("wanted")).await?)),
    "domain.check" => Ok(domains::check_own(app, &text("name")).await?),
    "domain.set" => owner(async {
      domains::set(app, params.get("domain")).await?;
      Ok(server_info(app, &device))
    }.await),
    "quota.set" => owner(async {
      let gb = number("gb").unwrap_or(20).clamp(1, 100_000) as u32;
      app.store.write(|s| s.quota_gb = gb)?;
      Ok(Value::Null)
    }.await),

    /* ---------- devices ---------- */
    "invite.create" => owner(async {
      let raw = |k: &str| -> Result<[u8; 32], Fail> { unb64(&text(k)).ok().and_then(|b| b.try_into().ok()).ok_or(Fail("bad-request")) };
      let (announce, proof) = (raw("announceKey")?, raw("proof")?);
      let topic = text("topic");
      if !topic.starts_with("mildly-") || topic.len() > 40 {
        return Err(Fail("bad-request"));
      }
      space::tidy_invites(app);
      let id = format!("i{}", hex::encode(crypto::random(6)));
      let expires = pairing::start_invite(app, &id, topic, announce, proof);
      app.invites.lock().expect("invites lock").insert(id.clone(), space::Invite { from: device.id.clone(), expires, joined: None, sealed: None });
      Ok(json!({ "id": id, "expiresAt": space::epoch_ms(expires) }))
    }.await),
    "invite.status" => {
      let id = text("id");
      let all = app.invites.lock().expect("invites lock");
      let Some(i) = all.get(&id).filter(|i| i.from == device.id) else { return Ok(json!({ "state": "expired" })) };
      match &i.joined {
        Some((joined, boxed, tag)) => {
          let d = app.store.read(|s| s.devices.iter().find(|d| &d.id == joined).cloned());
          Ok(json!({ "state": "joined", "device": d.map(|d| device_info(&d, &device.id)), "box": boxed, "boxTag": tag }))
        }
        None if i.expires <= std::time::Instant::now() => Ok(json!({ "state": "expired" })),
        None => Ok(json!({ "state": "waiting" })),
      }
    }
    "invite.deliver" => {
      let mut all = app.invites.lock().expect("invites lock");
      let i = all.get_mut(&text("id")).filter(|i| i.from == device.id && i.joined.is_some()).ok_or(Fail("not-found"))?;
      i.sealed = params.get("sealed").cloned();
      Ok(Value::Null)
    }
    "invite.cancel" => {
      let id = text("id");
      let mut all = app.invites.lock().expect("invites lock");
      if all.get(&id).is_some_and(|i| i.from == device.id) {
        all.remove(&id);
        pairing::cancel_invite(app, &id);
      }
      Ok(Value::Null)
    }
    "space.receive" => {
      let mut all = app.invites.lock().expect("invites lock");
      let found = all.iter().find(|(_, i)| i.joined.as_ref().is_some_and(|j| j.0 == device.id) && i.sealed.is_some()).map(|(id, _)| id.clone());
      Ok(found.and_then(|id| all.remove(&id)).and_then(|i| i.sealed).unwrap_or(Value::Null))
    }
    "devices.remove" => owner(async {
      let id = text("id");
      if id == device.id {
        return Err(Fail("bad-request"));
      }
      app.store.write(|s| s.devices.retain(|d| d.id != id))?;
      Ok(Value::Null)
    }.await),

    /* ---------- the space: files, chats, memory ---------- */
    "storage.list" => Ok(json!(space::items(app))),
    "storage.begin" => Ok(json!({ "id": space::begin(app, &text("origin"), number("size").unwrap_or(0), &text("desc"))? })),
    "storage.put" => {
      let data = unb64(&text("data")).map_err(|_| Fail("bad-request"))?;
      space::put(app, &text("id"), number("offset").unwrap_or(0), &data)?;
      Ok(Value::Null)
    }
    "storage.end" => Ok(space::end(app, &text("id"))?),
    "storage.get" => Ok(json!(b64(&space::get(app, &text("id"), number("offset").unwrap_or(0), number("length").unwrap_or(0) as usize)?))),
    "storage.remove" => {
      space::remove(app, &text("id"))?;
      Ok(Value::Null)
    }
    "context.put" => {
      let data = unb64(&text("data")).map_err(|_| Fail("bad-request"))?;
      space::put_chat(app, &text("id"), &data)?;
      Ok(Value::Null)
    }
    "context.list" => Ok(json!(space::chats_since(app, number("since").unwrap_or(0))?)),
    "context.drop" => {
      space::drop_chat(app, &text("id"))?;
      Ok(Value::Null)
    }
    "memory.put" => {
      let data = unb64(&text("data")).map_err(|_| Fail("bad-request"))?;
      space::put_memory(app, &data)?;
      Ok(Value::Null)
    }
    "memory.get" => Ok(space::memory(app).unwrap_or(Value::Null)),

    /* ---------- upkeep ---------- */
    "server.restart" => owner(async {
      tracing::info!("restarting, as asked from {}", device.name);
      // The answer goes out first; the service manager starts the engine again.
      tokio::spawn(async {
        tokio::time::sleep(Duration::from_millis(400)).await;
        std::process::exit(75);
      });
      Ok(Value::Null)
    }.await),
    "update.check" => Ok(json!({ "current": env!("CARGO_PKG_VERSION"), "latest": latest_release().await.unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string()) })),
    _ => Err(Fail("unavailable")),
  }
}

/// The newest published engine version, from the project's releases.
async fn latest_release() -> Option<String> {
  let client = reqwest::Client::builder().timeout(Duration::from_secs(8)).user_agent("mildly-server").build().ok()?;
  let v: Value = client.get(RELEASES).send().await.ok()?.error_for_status().ok()?.json().await.ok()?;
  v["tag_name"].as_str().map(|t| t.trim_start_matches('v').to_string())
}

const RELEASES: &str = "https://api.github.com/repos/TheMildly/server/releases/latest";

/// What the model or the app asked for beyond kind and name.
fn spec(params: &Value) -> Spec {
  let strings = |v: &Value| v.as_array().map(|a| a.iter().filter_map(|s| s.as_str().map(str::to_owned)).collect::<Vec<_>>());
  Spec {
    image: params.get("image").and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty()).map(str::to_owned),
    command: params.get("command").and_then(|c| strings(c).or_else(|| c.as_str().map(|s| vec!["sh".into(), "-c".into(), s.into()]))).filter(|c| !c.is_empty()),
    port: params.get("port").and_then(Value::as_u64).and_then(|p| u16::try_from(p).ok()).filter(|p| *p > 0),
    networks: params.get("networks").and_then(strings).unwrap_or_default(),
  }
}

fn domain(app: &App) -> Option<String> {
  app.store.read(|s| s.domain.as_ref().and_then(|d| d["name"].as_str().map(str::to_owned)))
}

/// One container as the app shows it, after a change.
async fn one(app: &App, host: &str, id: &str) -> Out {
  let all = runtime(app)?.list(host, domain(app).as_deref()).await?;
  all.into_iter().find(|c| c["id"] == id).ok_or(Fail("not-found"))
}

fn runtime(app: &App) -> Result<&Arc<crate::runtime::Containers>, Fail> {
  app.containers.as_ref().ok_or(Fail("runtime"))
}

/// Remembers when a device was last heard from, at most once a minute.
fn seen(app: &App, device: &Device) {
  if now_ms().saturating_sub(device.last_seen) > 60_000 {
    let id = device.id.clone();
    let _ = app.store.write(|s| {
      if let Some(d) = s.devices.iter_mut().find(|d| d.id == id) {
        d.last_seen = now_ms();
      }
    });
  }
}

fn pair(app: &Arc<App>, call: &Call, params: &Value) -> Out {
  let get = |k: &str| params.get(k).and_then(Value::as_str).unwrap_or("").to_string();
  let device_key = unb64(&get("key")).map_err(|_| Fail("bad-request"))?;
  // Proves the new device holds the key it registers.
  if !crypto::verify(&device_key, &signed(call), &unb64(&call.s).unwrap_or_default()) {
    return Err(Fail("bad-request"));
  }
  let invite = match pairing::check(app, &unb64(&get("proof")).unwrap_or_default()) {
    Check::Ok(invite) => invite,
    Check::Wrong => return Err(Fail("bad-code")),
    Check::Expired => return Err(Fail("expired")),
  };
  let kind = match get("kind").as_str() {
    k @ ("phone" | "laptop" | "tablet" | "desktop") => k.to_string(),
    _ => "laptop".to_string(),
  };
  let device = Device {
    id: format!("d{}", hex::encode(crypto::random(6))),
    name: get("name").chars().take(60).collect(),
    kind,
    key: b64(&device_key),
    owner: false,
    added_at: now_ms(),
    last_seen: now_ms(),
  };
  let device = app
    .store
    .write(|s| {
      let mut d = device;
      d.owner = s.devices.is_empty();
      s.devices.push(d.clone());
      d
    })
    .map_err(Fail::from)?;
  // Joined through an invite: the inviting device seals the space key for this one.
  if let Some(id) = &invite {
    if let Some(i) = app.invites.lock().expect("invites lock").get_mut(id) {
      i.joined = Some((device.id.clone(), get("box"), get("boxTag")));
    }
  }
  tracing::info!("paired {} ({})", device.name, if device.owner { "owner" } else { "member" });
  Ok(json!({ "server": server_info(app, &device), "device": device_info(&device, &device.id), "invited": invite.is_some() }))
}

async fn setup(app: &Arc<App>, device: &Device, params: &Value, host: &str) -> Out {
  let quota = params.get("quotaGb").and_then(Value::as_u64).unwrap_or(20).clamp(1, 100_000) as u32;
  app
    .store
    .write(|s| {
      s.quota_gb = quota;
      s.setup_done = true;
    })
    .map_err(Fail::from)?;
  domains::set(app, params.get("domain")).await?;
  snapshot(app, device, host, false).await
}

pub fn server_info(app: &App, device: &Device) -> Value {
  let quota = app.store.read(|s| s.quota_gb);
  let domain = domains::current(app);
  json!({
    "name": app.name,
    "address": app.addresses.first().cloned().unwrap_or_default(),
    "version": env!("CARGO_PKG_VERSION"),
    "os": app.os,
    "pairedAt": device.added_at,
    "domain": domain,
    "personalQuotaGb": quota,
    "diskTotalGb": app.disk_gb,
    "passkeyId": crypto::fingerprint(&unb64(&device.key).unwrap_or_default()),
  })
}

fn device_info(d: &Device, me: &str) -> Value {
  json!({ "id": d.id, "name": d.name, "kind": d.kind, "thisDevice": d.id == me, "owner": d.owner, "addedAt": d.added_at, "lastSeenAt": d.last_seen })
}

async fn snapshot(app: &Arc<App>, device: &Device, host: &str, with_devices: bool) -> Out {
  let containers = match app.containers.as_ref() {
    Some(c) => c.list(host, domain(app).as_deref()).await.map_err(Fail::from)?,
    None => Vec::new(),
  };
  let version = match app.containers.as_ref() {
    Some(c) => c.version().await.unwrap_or_default(),
    None => String::new(),
  };
  let mut out = json!({
    "server": server_info(app, device),
    "containers": containers,
    "storage": space::items(app),
    "addons": [
      { "id": "runtime", "kind": "engine", "enabled": app.containers.is_some(), "params": [
        { "key": "runtime", "value": app.config.runtime.label() },
        { "key": "version", "value": version },
      ] },
      { "id": "https", "kind": "engine", "enabled": domain(app).is_some(), "params": [
        { "key": "domain", "value": domain(app).unwrap_or_default() },
      ] },
      { "id": "mail", "kind": "addon", "enabled": false, "params": [] },
    ],
    "mailboxes": [],
    "dns": [],
    "catchAll": false,
  });
  if with_devices {
    out["devices"] = json!(app.store.read(|s| s.devices.iter().map(|d| device_info(d, &device.id)).collect::<Vec<_>>()));
  }
  Ok(out)
}
