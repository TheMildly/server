//! Terminal sessions for the app: a shell in a container, or on the server itself for the
//! owner. Output is kept in a buffer the app reads with long polls through the sealed RPC;
//! keystrokes come back the same way. Sessions close after fifteen idle minutes.

use crate::crypto;
use anyhow::{anyhow, Result};
use bollard::exec::{StartExecOptions, StartExecResults};
use bollard::models::ExecConfig;
use bollard::query_parameters::ResizeExecOptionsBuilder;
use bollard::Docker;
use futures_util::StreamExt;
use portable_pty::{native_pty_system, CommandBuilder, MasterPty, PtySize};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, Notify};

/// Output older than this many bytes is dropped; a terminal that far behind starts fresh.
const KEEP: usize = 512 * 1024;
const IDLE: Duration = Duration::from_secs(15 * 60);

enum Resizer {
  Exec { docker: Docker, exec_id: String },
  Pty(Mutex<Box<dyn MasterPty + Send>>),
}

struct Session {
  /// Output bytes; `base` is the offset of the first byte still kept.
  out: Mutex<(u64, Vec<u8>)>,
  more: Notify,
  input: mpsc::UnboundedSender<Vec<u8>>,
  closed: AtomicBool,
  last: Mutex<Instant>,
  resize: Resizer,
  /// Owner-only sessions (the server's own shell) remember who opened them.
  device: String,
}

impl Session {
  fn push(&self, bytes: &[u8]) {
    let mut out = self.out.lock().expect("terminal lock");
    out.1.extend_from_slice(bytes);
    if out.1.len() > KEEP {
      let drop = out.1.len() - KEEP;
      out.1.drain(..drop);
      out.0 += drop as u64;
    }
    drop(out);
    self.more.notify_waiters();
  }

  fn end(&self) {
    self.closed.store(true, Ordering::SeqCst);
    self.more.notify_waiters();
  }
}

#[derive(Default)]
pub struct Terminals {
  sessions: Mutex<HashMap<String, Arc<Session>>>,
}

fn size(cols: u16, rows: u16) -> (u16, u16) {
  (cols.clamp(20, 400), rows.clamp(5, 200))
}

impl Terminals {
  fn add(&self, s: Session) -> (String, Arc<Session>) {
    let id = format!("t{}", hex::encode(crypto::random(8)));
    let s = Arc::new(s);
    let mut all = self.sessions.lock().expect("terminal lock");
    all.retain(|_, s| !s.closed.load(Ordering::SeqCst) && s.last.lock().map(|l| l.elapsed() < IDLE).unwrap_or(false));
    all.insert(id.clone(), s.clone());
    (id, s)
  }

  fn get(&self, id: &str, device: &str) -> Result<Arc<Session>> {
    let s = self.sessions.lock().expect("terminal lock").get(id).cloned().ok_or_else(|| anyhow!("not-found"))?;
    if s.device != device {
      return Err(anyhow!("not-found"));
    }
    *s.last.lock().expect("terminal lock") = Instant::now();
    Ok(s)
  }

  /// A shell inside a container: bash when it has one, else sh.
  pub async fn open_container(&self, docker: &Docker, docker_id: &str, workdir: Option<&str>, cols: u16, rows: u16, device: &str) -> Result<String> {
    let (cols, rows) = size(cols, rows);
    let config = ExecConfig {
      attach_stdin: Some(true),
      attach_stdout: Some(true),
      attach_stderr: Some(true),
      tty: Some(true),
      env: Some(vec!["TERM=xterm-256color".into()]),
      cmd: Some(vec!["sh".into(), "-c".into(), "command -v bash >/dev/null 2>&1 && exec bash -l || exec sh -l".into()]),
      working_dir: workdir.map(str::to_string),
      console_size: Some(vec![rows as usize, cols as usize]),
      ..Default::default()
    };
    let exec = docker.create_exec(docker_id, config).await?;
    let started = docker.start_exec(&exec.id, Some(StartExecOptions { detach: false, tty: true, output_capacity: None })).await?;
    let StartExecResults::Attached { mut output, mut input } = started else { return Err(anyhow!("runtime")) };
    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let (id, s) = self.add(Session {
      out: Mutex::new((0, Vec::new())),
      more: Notify::new(),
      input: tx,
      closed: AtomicBool::new(false),
      last: Mutex::new(Instant::now()),
      resize: Resizer::Exec { docker: docker.clone(), exec_id: exec.id.clone() },
      device: device.to_string(),
    });
    let reader = s.clone();
    tokio::spawn(async move {
      while let Some(Ok(chunk)) = output.next().await {
        reader.push(&chunk.into_bytes());
      }
      reader.end();
    });
    let writer = s.clone();
    tokio::spawn(async move {
      while let Some(bytes) = rx.recv().await {
        if writer.closed.load(Ordering::SeqCst) || input.write_all(&bytes).await.is_err() {
          break;
        }
        let _ = input.flush().await;
      }
    });
    Ok(id)
  }

  /// A login shell on the server itself. Only for the owner; checked by the caller.
  pub fn open_host(&self, cols: u16, rows: u16, device: &str) -> Result<String> {
    let (cols, rows) = size(cols, rows);
    let pair = native_pty_system().openpty(PtySize { rows, cols, pixel_width: 0, pixel_height: 0 })?;
    let shell = ["/bin/bash", "/bin/sh"].into_iter().find(|p| std::path::Path::new(p).exists()).unwrap_or("/bin/sh");
    let mut cmd = CommandBuilder::new(shell);
    cmd.arg("-l");
    cmd.env("TERM", "xterm-256color");
    cmd.cwd(std::env::var("HOME").unwrap_or_else(|_| "/root".into()));
    let mut child = pair.slave.spawn_command(cmd)?;
    drop(pair.slave);
    let mut reader = pair.master.try_clone_reader()?;
    let mut writer = pair.master.take_writer()?;
    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let (id, s) = self.add(Session {
      out: Mutex::new((0, Vec::new())),
      more: Notify::new(),
      input: tx,
      closed: AtomicBool::new(false),
      last: Mutex::new(Instant::now()),
      resize: Resizer::Pty(Mutex::new(pair.master)),
      device: device.to_string(),
    });
    let out = s.clone();
    std::thread::spawn(move || {
      let mut buf = [0u8; 8192];
      while let Ok(n) = reader.read(&mut buf) {
        if n == 0 {
          break;
        }
        out.push(&buf[..n]);
      }
      out.end();
      let _ = child.kill();
    });
    let input = s.clone();
    tokio::task::spawn_blocking(move || {
      while let Some(bytes) = rx.blocking_recv() {
        if input.closed.load(Ordering::SeqCst) || writer.write_all(&bytes).is_err() {
          break;
        }
        let _ = writer.flush();
      }
    });
    Ok(id)
  }

  /// Output from `from` on, waiting up to `wait` for something new. Returns (bytes, next offset, closed).
  pub async fn read(&self, id: &str, device: &str, from: u64, wait: Duration) -> Result<(String, u64, bool)> {
    let s = self.get(id, device)?;
    let deadline = Instant::now() + wait;
    loop {
      let notified = s.more.notified();
      {
        let out = s.out.lock().expect("terminal lock");
        let end = out.0 + out.1.len() as u64;
        let closed = s.closed.load(Ordering::SeqCst);
        if end > from || closed {
          let start = from.max(out.0);
          let slice = &out.1[(start - out.0) as usize..];
          return Ok((crypto::b64(slice), end, closed && end <= from.max(out.0) + slice.len() as u64));
        }
      }
      let left = deadline.saturating_duration_since(Instant::now());
      if left.is_zero() {
        return Ok((String::new(), from, false));
      }
      let _ = tokio::time::timeout(left, notified).await;
    }
  }

  pub fn write(&self, id: &str, device: &str, data: &[u8]) -> Result<()> {
    let s = self.get(id, device)?;
    s.input.send(data.to_vec()).map_err(|_| anyhow!("not-found"))
  }

  pub async fn resize(&self, id: &str, device: &str, cols: u16, rows: u16) -> Result<()> {
    let s = self.get(id, device)?;
    let (cols, rows) = size(cols, rows);
    match &s.resize {
      Resizer::Exec { docker, exec_id } => docker.resize_exec(exec_id, ResizeExecOptionsBuilder::new().h(rows as i32).w(cols as i32).build()).await?,
      Resizer::Pty(master) => master.lock().expect("terminal lock").resize(PtySize { rows, cols, pixel_width: 0, pixel_height: 0 })?,
    }
    Ok(())
  }

  pub fn close(&self, id: &str, device: &str) {
    if let Ok(s) = self.get(id, device) {
      // Ends the shell the polite way first; the reader closes the session when it exits.
      let _ = s.input.send(b"exit\n".to_vec());
      s.end();
      self.sessions.lock().expect("terminal lock").remove(id);
    }
  }
}
