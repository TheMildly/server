//! Live load for the realtime tiles: a reading every 1.5 seconds, the last 24 kept.

use serde::Serialize;
use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::Duration;
use sysinfo::{Disks, Networks, System};

pub const KEEP: usize = 24;
pub const EVERY: Duration = Duration::from_millis(1500);

#[derive(Debug, Clone, Copy, Serialize)]
pub struct Sample {
  pub cpu: f32,
  pub mem: f32,
  #[serde(rename = "netDown")]
  pub net_down: f32,
  #[serde(rename = "netUp")]
  pub net_up: f32,
}

#[derive(Default)]
pub struct Metrics {
  samples: Mutex<VecDeque<Sample>>,
}

impl Metrics {
  pub fn recent(&self) -> Vec<Sample> {
    self.samples.lock().expect("metrics lock").iter().copied().collect()
  }

  fn push(&self, s: Sample) {
    let mut q = self.samples.lock().expect("metrics lock");
    if q.len() == KEEP {
      q.pop_front();
    }
    q.push_back(s);
  }
}

pub async fn sample_forever(metrics: std::sync::Arc<Metrics>) {
  let (Ok(mut system), Ok(mut networks)) = (System::new(), Networks::new_with_refreshed_list()) else {
    return tracing::warn!("system readings are not available on this machine");
  };
  system.refresh_cpu_usage();
  loop {
    tokio::time::sleep(EVERY).await;
    system.refresh_cpu_usage();
    system.refresh_memory();
    networks.refresh(true);
    let (down, up) = networks.iter().fold((0u64, 0u64), |(d, u), (_, n)| (d + n.received(), u + n.transmitted()));
    let secs = EVERY.as_secs_f32();
    let total = system.total_memory().max(1) as f32;
    metrics.push(Sample {
      cpu: system.global_cpu_usage().clamp(0.0, 100.0),
      mem: (system.used_memory() as f32 / total * 100.0).clamp(0.0, 100.0),
      net_down: down as f32 * 8.0 / 1_000_000.0 / secs,
      net_up: up as f32 * 8.0 / 1_000_000.0 / secs,
    });
  }
}

/// Size of the disk that holds the engine's data, in GB.
pub fn disk_total_gb(data_dir: &std::path::Path) -> u32 {
  let Ok(disks) = Disks::new_with_refreshed_list() else { return 0 };
  let best = (&disks)
    .into_iter()
    .filter(|d| data_dir.starts_with(d.mount_point()))
    .max_by_key(|d| d.mount_point().as_os_str().len())
    .or_else(|| (&disks).into_iter().max_by_key(|d| d.total_space()));
  best.map(|d| (d.total_space() / 1_000_000_000) as u32).unwrap_or(0)
}

pub fn os_name() -> String {
  let name = System::name().unwrap_or_else(|_| "Linux".into());
  match System::os_version() {
    Ok(v) => format!("{name} {v}"),
    Err(_) => name,
  }
}
