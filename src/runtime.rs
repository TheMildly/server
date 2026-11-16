//! The user's containers, through the Docker-compatible API that Docker and Podman both serve
//! (docs/SERVER.md, section 5).
//!
//! Containers the engine made carry `ai.mildly.*` labels and their own id (`ai.mildly.id`),
//! so the app's records survive a container being recreated. Containers that were already on
//! the machine are listed too, as *external* (id `x` + the runtime's short id): they can be
//! looked at, started, stopped and restarted by the user, and joined over their networks, but
//! the engine never writes into them, recreates them or removes them.

use crate::config::Config;
use crate::crypto;
use crate::state::now_ms;
use anyhow::{anyhow, bail, Context, Result};
use bollard::exec::{StartExecOptions, StartExecResults};
use bollard::models::{
  EndpointSettings, NetworkingConfig,
  ContainerCreateBody, ContainerInspectResponse, ContainerSummary, ExecConfig, HostConfig, NetworkConnectRequest, NetworkCreateRequest, PortBinding, RestartPolicy,
  RestartPolicyNameEnum,
};
use bollard::query_parameters::{
  CreateContainerOptionsBuilder, CreateImageOptionsBuilder, DownloadFromContainerOptionsBuilder, InspectContainerOptions, ListContainersOptionsBuilder,
  ListNetworksOptions, LogsOptionsBuilder, RemoveContainerOptionsBuilder, RestartContainerOptions, StartContainerOptions, StatsOptionsBuilder,
  StopContainerOptions,
};
use bollard::{Docker, API_DEFAULT_VERSION};
use futures_util::{future::join_all, StreamExt, TryStreamExt};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub const KINDS: [&str; 5] = ["web", "miniapp", "logic", "worker", "database"];
pub const NETWORK: &str = "mildly";
const MAX_WRITE: usize = 4 * 1024 * 1024;
const MAX_READ: usize = 256 * 1024;
const MAX_OUTPUT: usize = 64 * 1024;

/// What the model or the app asks for beyond the kind and name.
#[derive(Default, Clone)]
pub struct Spec {
  pub image: Option<String>,
  pub command: Option<Vec<String>>,
  pub port: Option<u16>,
  /// Networks of other containers to join, to talk to apps already on the server.
  pub networks: Vec<String>,
}

struct Pending {
  info: Value,
}

pub struct Containers {
  docker: Docker,
  config: Config,
  pending: Mutex<HashMap<String, Pending>>,
}

/// A container as the engine sees it.
pub struct Found {
  pub docker_id: String,
  pub external: bool,
  pub kind: String,
  pub name: String,
}

fn label(labels: &Option<HashMap<String, String>>, key: &str) -> String {
  labels.as_ref().and_then(|l| l.get(key)).cloned().unwrap_or_default()
}

/// Where a kind keeps its files, and the port it serves on by default.
pub fn layout(kind: &str) -> (&'static str, Option<u16>) {
  match kind {
    "web" | "miniapp" => ("/usr/share/nginx/html", Some(80)),
    "logic" => ("/app", Some(3000)),
    "worker" => ("/app", None),
    _ => ("/var/lib/postgresql/data", None),
  }
}

/// A guess at what an external container is, from its image.
fn infer_kind(image: &str) -> &'static str {
  let i = image.to_lowercase();
  let has = |words: &[&str]| words.iter().any(|w| i.contains(w));
  if has(&["postgres", "mysql", "mariadb", "mongo", "redis", "valkey", "clickhouse", "elastic", "couch", "influx"]) {
    "database"
  } else if has(&["nginx", "httpd", "caddy", "apache", "traefik", "lighttpd", "wordpress", "ghost"]) {
    "web"
  } else if has(&["node", "python", "php", "ruby", "golang", "openjdk", "java", "deno", "bun", "dotnet", "rust"]) {
    "logic"
  } else {
    "worker"
  }
}

/// Names become part of container and host names: lowercase letters, digits and dashes.
pub fn clean_name(name: &str) -> Option<String> {
  let slug: String = name.trim().to_lowercase().chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '-' }).collect();
  let slug = slug.split('-').filter(|p| !p.is_empty()).collect::<Vec<_>>().join("-");
  (!slug.is_empty() && slug.len() <= 40).then_some(slug)
}

/// A path inside a container's files: relative, plain names only.
fn clean_relative(path: &str) -> Option<PathBuf> {
  let p = Path::new(path.trim_start_matches("./"));
  (!path.is_empty() && p.components().all(|c| matches!(c, Component::Normal(_)))).then(|| p.to_path_buf())
}

impl Containers {
  pub fn connect(config: &Config) -> Result<Self> {
    let docker = Docker::connect_with_socket(config.socket(), 300, API_DEFAULT_VERSION).context("connecting to the container runtime")?;
    Ok(Self { docker, config: config.clone(), pending: Mutex::new(HashMap::new()) })
  }

  pub fn docker(&self) -> &Docker {
    &self.docker
  }

  pub async fn version(&self) -> Option<String> {
    self.docker.version().await.ok().and_then(|v| v.version)
  }

  fn volume(&self, id: &str) -> PathBuf {
    self.config.data_dir.join("volumes").join(id)
  }

  /// Finds a container by the id the app knows.
  pub async fn locate(&self, id: &str) -> Result<Found> {
    if let Some(short) = id.strip_prefix('x') {
      let all = self.docker.list_containers(Some(ListContainersOptionsBuilder::new().all(true).build())).await?;
      let c = all.into_iter().find(|c| c.id.as_deref().is_some_and(|d| d.starts_with(short)) && label(&c.labels, "ai.mildly.id").is_empty()).ok_or_else(|| anyhow!("not-found"))?;
      let image = c.image.clone().unwrap_or_default();
      return Ok(Found { docker_id: c.id.clone().unwrap_or_default(), external: true, kind: infer_kind(&image).into(), name: display_name(&c) });
    }
    let filters = HashMap::from([("label", vec![format!("ai.mildly.id={id}")])]);
    let found = self.docker.list_containers(Some(ListContainersOptionsBuilder::new().all(true).filters(&filters).build())).await?;
    let c = found.into_iter().next().ok_or_else(|| anyhow!("not-found"))?;
    Ok(Found { docker_id: c.id.clone().unwrap_or_default(), external: false, kind: label(&c.labels, "ai.mildly.kind"), name: label(&c.labels, "ai.mildly.name") })
  }

  async fn mine(&self, id: &str) -> Result<Found> {
    let f = self.locate(id).await?;
    if f.external {
      bail!("external");
    }
    Ok(f)
  }

  /// Every container as the app's `ContainerInfo`: the engine's own, then the ones it found.
  pub async fn list(&self, host: &str, domain: Option<&str>) -> Result<Vec<Value>> {
    let all = self.docker.list_containers(Some(ListContainersOptionsBuilder::new().all(true).size(true).build())).await?;
    let made: Vec<_> = all
      .into_iter()
      // The HTTPS front is part of the engine, not one of the user's apps.
      .filter(|c| label(&c.labels, "ai.mildly.role").is_empty())
      .map(|c| async move {
        let docker_id = c.id.clone().unwrap_or_default();
        let mine = !label(&c.labels, "ai.mildly.id").is_empty();
        let image = c.image.clone().unwrap_or_default();
        let id = if mine { label(&c.labels, "ai.mildly.id") } else { format!("x{}", &docker_id[..12.min(docker_id.len())]) };
        let kind = if mine { label(&c.labels, "ai.mildly.kind") } else { infer_kind(&image).to_string() };
        let name = if mine { label(&c.labels, "ai.mildly.name") } else { display_name(&c) };
        let project = if mine {
          label(&c.labels, "ai.mildly.project")
        } else {
          Some(label(&c.labels, "com.docker.compose.project")).filter(|p| !p.is_empty()).unwrap_or_else(|| name.clone())
        };
        let state = c.state.as_ref().map(|s| s.to_string()).unwrap_or_default();
        let running = state == "running";
        let inspect = self.docker.inspect_container(&docker_id, None::<InspectContainerOptions>).await.ok();
        // A busy machine can make stats slow; the page should not wait for them.
        let (cpu, mem, limit) = if running {
          tokio::time::timeout(Duration::from_secs(3), self.usage(&docker_id)).await.unwrap_or((0.0, 0.0, 0.0))
        } else {
          (0.0, 0.0, 0.0)
        };
        let port = c.ports.clone().unwrap_or_default().into_iter().find_map(|p| p.public_port);
        let started = inspect.as_ref().and_then(|i| i.state.as_ref()).and_then(|s| s.started_at.clone()).unwrap_or_default();
        let restarts = inspect.as_ref().and_then(|i| i.restart_count).unwrap_or(0);
        let env = inspect.as_ref().and_then(|i| i.config.as_ref()).and_then(|c| c.env.as_ref()).map(|e| e.len()).unwrap_or(0);
        let served = mine && matches!(kind.as_str(), "web" | "miniapp" | "logic") && !label(&c.labels, "ai.mildly.port").is_empty();
        let url = match (domain, served) {
          (Some(d), true) => Some(format!("https://{name}.{d}")),
          _ => port.map(|p| format!("http://{host}:{p}")),
        };
        let status = match state.as_str() {
          "running" => "running",
          "restarting" => "building",
          "dead" => "error",
          _ => "stopped",
        };
        json!({
          "id": id, "name": name, "project": project, "kind": kind, "status": status, "description": "",
          "image": image, "url": url, "port": port, "cpuPct": cpu, "memMb": mem, "memLimitMb": limit,
          "diskMb": c.size_rw.unwrap_or(0) as f64 / 1_048_576.0,
          "startedAt": if running { started } else { String::new() },
          "createdAt": c.created.unwrap_or(0) * 1000, "restarts": restarts, "envCount": env, "snapshot": null,
          "external": !mine,
        })
      })
      .collect();
    let mut out = join_all(made).await;
    let listed: Vec<String> = out.iter().filter_map(|v| v["id"].as_str().map(str::to_owned)).collect();
    let mut pending = self.pending.lock().expect("pending lock");
    pending.retain(|id, _| !listed.contains(id));
    out.extend(pending.values().map(|p| p.info.clone()));
    // The engine's own first, newest first; then what it found.
    out.sort_by_key(|v| (v["external"].as_bool().unwrap_or(false), std::cmp::Reverse(v["createdAt"].as_u64().unwrap_or(0))));
    Ok(out)
  }

  /// The engine's own containers that serve HTTP: (name, name on the network, port).
  pub async fn sites(&self) -> Result<Vec<(String, String, u16)>> {
    let filters = HashMap::from([("label", vec!["ai.mildly.id".to_string()])]);
    let all = self.docker.list_containers(Some(ListContainersOptionsBuilder::new().all(true).filters(&filters).build())).await?;
    Ok(all
      .into_iter()
      .filter_map(|c| {
        let port: u16 = label(&c.labels, "ai.mildly.port").parse().ok()?;
        let kind = label(&c.labels, "ai.mildly.kind");
        matches!(kind.as_str(), "web" | "miniapp" | "logic").then(|| (label(&c.labels, "ai.mildly.name"), display_name(&c), port))
      })
      .collect())
  }

  async fn usage(&self, docker_id: &str) -> (f64, f64, f64) {
    let mut stream = self.docker.stats(docker_id, Some(StatsOptionsBuilder::new().stream(false).build()));
    let Some(Ok(s)) = stream.next().await else { return (0.0, 0.0, 0.0) };
    let cpu = (|| {
      let now = s.cpu_stats.as_ref()?;
      let before = s.precpu_stats.as_ref()?;
      let used = now.cpu_usage.as_ref()?.total_usage? as f64 - before.cpu_usage.as_ref()?.total_usage.unwrap_or(0) as f64;
      let system = now.system_cpu_usage? as f64 - before.system_cpu_usage.unwrap_or(0) as f64;
      let cpus = now.online_cpus.unwrap_or(1) as f64;
      (system > 0.0).then(|| used / system * cpus * 100.0)
    })()
    .unwrap_or(0.0);
    let mem = s.memory_stats.as_ref();
    (cpu, mem.and_then(|m| m.usage).unwrap_or(0) as f64 / 1_048_576.0, mem.and_then(|m| m.limit).unwrap_or(0) as f64 / 1_048_576.0)
  }

  /// Makes a container in the background and returns at once with it as `building`.
  pub fn create(self: &Arc<Self>, kind: &str, name: &str, spec: Spec) -> Result<Value> {
    if !KINDS.contains(&kind) {
      bail!("bad-kind");
    }
    let name = clean_name(name).ok_or_else(|| anyhow!("bad-name"))?;
    let id = format!("c{}", hex::encode(crypto::random(6)));
    let image = spec.image.clone().unwrap_or_else(|| self.config.image(kind));
    let info = json!({
      "id": id, "name": name, "project": name, "kind": kind, "status": "building", "description": "",
      "image": image, "cpuPct": 0, "memMb": 0, "memLimitMb": 0, "diskMb": 0,
      "startedAt": "", "createdAt": now_ms(), "restarts": 0, "envCount": 0, "snapshot": null, "external": false,
    });
    self.pending.lock().expect("pending lock").insert(id.clone(), Pending { info: info.clone() });
    let me = self.clone();
    let (kind, made_id) = (kind.to_string(), id.clone());
    tokio::spawn(async move {
      if let Err(e) = me.make(&made_id, &kind, &name, spec, None).await {
        tracing::warn!("making {name}: {e:#}");
        if let Some(p) = me.pending.lock().expect("pending lock").get_mut(&made_id) {
          p.info["status"] = json!("error");
          p.info["error"] = json!(format!("{e:#}"));
        }
      }
    });
    Ok(info)
  }

  async fn pull(&self, image: &str) -> Result<()> {
    let mut pull = self.docker.create_image(Some(CreateImageOptionsBuilder::new().from_image(image).build()), None, None);
    while let Some(step) = pull.next().await {
      step.with_context(|| format!("pulling {image}"))?;
    }
    Ok(())
  }

  /// Creates and starts the container. `keep_port` reuses a host port when it is recreated.
  async fn make(&self, id: &str, kind: &str, name: &str, spec: Spec, keep_port: Option<String>) -> Result<()> {
    let image = spec.image.clone().unwrap_or_else(|| self.config.image(kind));
    self.pull(&image).await?;
    self.ensure_network().await?;

    let (path, default_port) = layout(kind);
    let port = spec.port.or(default_port);
    let dir = self.volume(id);
    std::fs::create_dir_all(&dir)?;
    let empty = std::fs::read_dir(&dir).map(|mut d| d.next().is_none()).unwrap_or(true);
    let custom = spec.image.is_some();
    let mut env = Vec::new();
    let mut cmd = spec.command.clone();
    match kind {
      "web" | "miniapp" if empty && !custom => {
        std::fs::write(dir.join("index.html"), format!("<!doctype html><meta charset=\"utf-8\"><title>{name}</title><p>{name} is ready.</p>\n"))?
      }
      "logic" if cmd.is_none() && !custom => {
        if empty {
          std::fs::write(dir.join("server.js"), "require('http').createServer((q, s) => s.end(JSON.stringify({ ok: true }))).listen(3000);\n")?;
        }
        cmd = Some(vec!["node".into(), "/app/server.js".into()]);
      }
      "worker" if cmd.is_none() && !custom => cmd = Some(vec!["node".into(), "-e".into(), "setInterval(() => {}, 1 << 30)".into()]),
      "database" if !custom => env.push(format!("POSTGRES_PASSWORD={}", hex::encode(crypto::random(16)))),
      _ => {}
    }

    let mut labels = HashMap::from([
      ("ai.mildly.id".to_string(), id.to_string()),
      ("ai.mildly.kind".to_string(), kind.to_string()),
      ("ai.mildly.name".to_string(), name.to_string()),
      ("ai.mildly.project".to_string(), name.to_string()),
    ]);
    if let Some(p) = port {
      labels.insert("ai.mildly.port".into(), p.to_string());
    }
    let exposed = port.map(|p| format!("{p}/tcp"));
    // A fixed host port, so a site keeps its address across restarts.
    let host_port = match (&exposed, keep_port) {
      (Some(_), Some(kept)) => Some(kept),
      (Some(_), None) => Some(std::net::TcpListener::bind("0.0.0.0:0")?.local_addr()?.port().to_string()),
      _ => None,
    };
    let bindings = exposed.as_ref().map(|e| HashMap::from([(e.clone(), Some(vec![PortBinding { host_ip: Some("0.0.0.0".into()), host_port: host_port.clone() }]))]));
    let body = ContainerCreateBody {
      image: Some(image),
      labels: Some(labels),
      env: (!env.is_empty()).then_some(env),
      cmd,
      working_dir: matches!(kind, "logic" | "worker").then(|| "/app".to_string()),
      exposed_ports: exposed.map(|e| vec![e]),
      host_config: Some(HostConfig {
        binds: Some(vec![format!("{}:{path}", dir.display())]),
        port_bindings: bindings,
        network_mode: Some(NETWORK.into()),
        restart_policy: Some(RestartPolicy { name: Some(RestartPolicyNameEnum::UNLESS_STOPPED), ..Default::default() }),
        ..Default::default()
      }),
      // Other containers reach this one by its plain name, such as `db`.
      networking_config: Some(NetworkingConfig {
        endpoints_config: Some(HashMap::from([(NETWORK.to_string(), EndpointSettings { aliases: Some(vec![name.to_string()]), ..Default::default() })])),
      }),
      ..Default::default()
    };
    let made = self.docker.create_container(Some(CreateContainerOptionsBuilder::new().name(&format!("mildly-{name}-{id}")).build()), body).await?;
    // Joining another app's network changes only the new container.
    for net in &spec.networks {
      self.docker.connect_network(net, NetworkConnectRequest { container: made.id.clone(), ..Default::default() }).await.with_context(|| format!("joining network {net}"))?;
    }
    self.docker.start_container(&made.id, None::<StartContainerOptions>).await?;
    Ok(())
  }

  async fn ensure_network(&self) -> Result<()> {
    let nets = self.docker.list_networks(None::<ListNetworksOptions>).await?;
    if nets.iter().any(|n| n.name.as_deref() == Some(NETWORK)) {
      return Ok(());
    }
    let labels = HashMap::from([("ai.mildly.network".to_string(), "1".to_string())]);
    self.docker.create_network(NetworkCreateRequest { name: NETWORK.into(), labels: Some(labels), ..Default::default() }).await?;
    Ok(())
  }

  /// Recreates one of the engine's containers with a new image, command or port. Its files stay.
  pub async fn configure(&self, id: &str, spec: Spec) -> Result<()> {
    let f = self.mine(id).await?;
    let old = self.docker.inspect_container(&f.docker_id, None::<InspectContainerOptions>).await?;
    let labels = old.config.as_ref().and_then(|c| c.labels.clone());
    let old_port: Option<u16> = label(&labels, "ai.mildly.port").parse().ok();
    let kept = host_port(&old);
    let networks: Vec<String> = old
      .network_settings
      .as_ref()
      .and_then(|n| n.networks.as_ref())
      .map(|n| n.keys().filter(|k| k.as_str() != NETWORK).cloned().collect())
      .unwrap_or_default();
    let spec = Spec {
      image: spec.image.or_else(|| old.config.as_ref().and_then(|c| c.image.clone())),
      command: spec.command.or_else(|| old.config.as_ref().and_then(|c| c.cmd.clone())),
      port: spec.port.or(old_port),
      networks: if spec.networks.is_empty() { networks } else { spec.networks },
    };
    self.docker.remove_container(&f.docker_id, Some(RemoveContainerOptionsBuilder::new().force(true).build())).await?;
    let keep = if spec.port == old_port { kept } else { None };
    self.make(id, &f.kind, &f.name, spec, keep).await
  }

  pub async fn action(&self, id: &str, action: &str) -> Result<()> {
    let f = self.locate(id).await?;
    match action {
      "start" => self.docker.start_container(&f.docker_id, None::<StartContainerOptions>).await?,
      "stop" => self.docker.stop_container(&f.docker_id, None::<StopContainerOptions>).await?,
      "restart" => self.docker.restart_container(&f.docker_id, None::<RestartContainerOptions>).await?,
      _ => bail!("unavailable"),
    }
    Ok(())
  }

  pub async fn remove(&self, id: &str) -> Result<()> {
    self.pending.lock().expect("pending lock").remove(id);
    match self.locate(id).await {
      Ok(f) if f.external => bail!("external"),
      Ok(f) => {
        self.docker.remove_container(&f.docker_id, Some(RemoveContainerOptionsBuilder::new().force(true).v(true).build())).await?;
      }
      Err(_) => {}
    }
    let dir = self.volume(id);
    if dir.starts_with(self.config.data_dir.join("volumes")) && !id.starts_with('x') {
      let _ = std::fs::remove_dir_all(dir);
    }
    Ok(())
  }

  pub async fn logs(&self, id: &str) -> Result<Vec<String>> {
    let f = self.locate(id).await?;
    let opts = LogsOptionsBuilder::new().stdout(true).stderr(true).timestamps(true).tail("120").build();
    let chunks: Vec<_> = self.docker.logs(&f.docker_id, Some(opts)).try_collect().await?;
    let mut lines = Vec::new();
    for chunk in chunks {
      for line in chunk.to_string().lines() {
        let (stamp, rest) = line.split_once(' ').unwrap_or(("", line));
        lines.push(format!("{} {rest}", stamp.get(11..19).unwrap_or("--:--:--")));
      }
    }
    Ok(lines)
  }

  /// Writes a file into one of the engine's containers, relative to its app folder.
  pub async fn write(&self, id: &str, path: &str, content: &str) -> Result<String> {
    let f = self.mine(id).await?;
    if content.len() > MAX_WRITE {
      bail!("too-large");
    }
    let rel = clean_relative(path).ok_or_else(|| anyhow!("bad-path"))?;
    let target = self.volume(id).join(&rel);
    std::fs::create_dir_all(target.parent().ok_or_else(|| anyhow!("bad-path"))?)?;
    std::fs::write(&target, content)?;
    Ok(format!("{}/{}", layout(&f.kind).0, rel.display()))
  }

  /// Reads a file: from the app folder of the engine's containers, or any absolute path in any
  /// container through the runtime's archive call, which runs nothing inside it.
  pub async fn read(&self, id: &str, path: &str) -> Result<String> {
    let f = self.locate(id).await?;
    if !f.external {
      if let Some(rel) = clean_relative(path) {
        let bytes = std::fs::read(self.volume(id).join(rel)).map_err(|_| anyhow!("not-found"))?;
        return Ok(String::from_utf8_lossy(&bytes[..bytes.len().min(MAX_READ)]).into_owned());
      }
    }
    let opts = DownloadFromContainerOptionsBuilder::new().path(path).build();
    let tarball: Vec<u8> = self.docker.download_from_container(&f.docker_id, Some(opts)).map_ok(|b| b.to_vec()).try_concat().await.map_err(|_| anyhow!("not-found"))?;
    let mut archive = tar::Archive::new(tarball.as_slice());
    for entry in archive.entries()? {
      let mut entry = entry?;
      if entry.header().entry_type().is_file() {
        let mut out = Vec::new();
        std::io::Read::read_to_end(&mut std::io::Read::take(&mut entry, MAX_READ as u64), &mut out)?;
        return Ok(String::from_utf8_lossy(&out).into_owned());
      }
    }
    bail!("not-found")
  }

  /// Runs a shell command in one of the engine's containers and returns its exit code and output.
  pub async fn exec(&self, id: &str, command: &str, timeout: Duration) -> Result<Value> {
    let f = self.mine(id).await?;
    let config = ExecConfig {
      attach_stdout: Some(true),
      attach_stderr: Some(true),
      cmd: Some(vec!["sh".into(), "-c".into(), command.into()]),
      working_dir: Some(layout(&f.kind).0.into()),
      ..Default::default()
    };
    let exec = self.docker.create_exec(&f.docker_id, config).await?;
    let mut output = Vec::new();
    let run = async {
      if let StartExecResults::Attached { output: mut stream, .. } = self.docker.start_exec(&exec.id, None::<StartExecOptions>).await? {
        while let Some(chunk) = stream.next().await {
          output.extend_from_slice(&chunk?.into_bytes());
          if output.len() > 4 * MAX_OUTPUT {
            output.drain(..output.len() - MAX_OUTPUT);
          }
        }
      }
      anyhow::Ok(())
    };
    let finished = tokio::time::timeout(timeout, run).await.is_ok();
    let code = self.docker.inspect_exec(&exec.id).await.ok().and_then(|i| i.exit_code);
    let tail = &output[output.len().saturating_sub(MAX_OUTPUT)..];
    Ok(json!({ "exitCode": code, "finished": finished, "output": String::from_utf8_lossy(tail) }))
  }

  /// What the model needs to know about a container, without secrets: env values are left out.
  pub async fn inspect(&self, id: &str) -> Result<Value> {
    let f = self.locate(id).await?;
    let i = self.docker.inspect_container(&f.docker_id, None::<InspectContainerOptions>).await?;
    let config = i.config.as_ref();
    let ports: Vec<Value> = i
      .network_settings
      .as_ref()
      .and_then(|n| n.ports.as_ref())
      .map(|p| p.iter().map(|(k, v)| json!({ "container": k, "host": v.as_ref().and_then(|b| b.first()).and_then(|b| b.host_port.clone()) })).collect())
      .unwrap_or_default();
    let networks: Vec<String> = i.network_settings.as_ref().and_then(|n| n.networks.as_ref()).map(|n| n.keys().cloned().collect()).unwrap_or_default();
    let mounts: Vec<String> = i.mounts.as_ref().map(|m| m.iter().filter_map(|m| m.destination.clone()).collect()).unwrap_or_default();
    let env_names: Vec<String> = config.and_then(|c| c.env.as_ref()).map(|e| e.iter().map(|v| v.split('=').next().unwrap_or("").to_string()).collect()).unwrap_or_default();
    Ok(json!({
      "id": id,
      "name": f.name,
      "external": f.external,
      "kind": f.kind,
      "image": config.and_then(|c| c.image.clone()),
      "command": config.and_then(|c| c.cmd.clone()),
      "workingDir": config.and_then(|c| c.working_dir.clone()),
      "appFolder": (!f.external).then(|| layout(&f.kind).0),
      "status": i.state.as_ref().and_then(|s| s.status.map(|v| v.to_string())),
      "hostname": i.name.as_ref().map(|n| n.trim_start_matches('/').to_string()),
      "ports": ports,
      "networks": networks,
      "mounts": mounts,
      "envNames": env_names,
    }))
  }
}

fn display_name(c: &ContainerSummary) -> String {
  c.names.as_ref().and_then(|n| n.first()).map(|n| n.trim_start_matches('/').to_string()).unwrap_or_default()
}

fn host_port(i: &ContainerInspectResponse) -> Option<String> {
  i.host_config.as_ref()?.port_bindings.as_ref()?.values().flatten().flatten().find_map(|b| b.host_port.clone()).filter(|p| !p.is_empty())
}
