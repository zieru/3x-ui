use serde::Serialize;
use std::ffi::CString;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MemInfo {
    pub current: u64,
    pub total: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct XrayInfo {
    pub state: String,
    pub error_msg: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetIO {
    pub up: u64,
    pub down: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusSnapshot {
    pub cpu: f64,
    pub cpu_cores: i32,
    pub mem: MemInfo,
    pub swap: MemInfo,
    pub disk: MemInfo,
    pub xray: XrayInfo,
    pub panel_version: String,
    pub panel_guid: String,
    pub uptime: u64,
    pub loads: Vec<f64>,
    #[serde(rename = "netIO")]
    pub net_io: NetIO,
    pub update_available: bool,
    pub latest_version: String,
    pub auto_update: bool,
    pub core_update_available: bool,
    pub latest_core_version: String,
}

pub fn read_meminfo() -> (u64, u64, u64, u64) {
    let Ok(data) = fs::read_to_string("/proc/meminfo") else {
        return (0, 0, 0, 0);
    };
    let (mut total, mut avail, mut swap_total, mut swap_free) = (0u64, 0u64, 0u64, 0u64);
    for line in data.lines() {
        let mut parts = line.split_whitespace();
        let Some(key) = parts.next() else { continue };
        let Some(val_str) = parts.next() else { continue };
        let Ok(val) = val_str.parse::<u64>() else { continue };
        match key {
            "MemTotal:" => total = val * 1024,
            "MemAvailable:" => avail = val * 1024,
            "SwapTotal:" => swap_total = val * 1024,
            "SwapFree:" => swap_free = val * 1024,
            _ => {}
        }
    }
    (total, avail, swap_total, swap_free)
}

pub fn read_loadavg() -> Vec<f64> {
    let Ok(data) = fs::read_to_string("/proc/loadavg") else {
        return Vec::new();
    };
    data.split_whitespace()
        .take(3)
        .filter_map(|s| s.parse::<f64>().ok())
        .collect()
}

fn read_proc_stat_cpu() -> Option<(u64, u64)> {
    let data = fs::read_to_string("/proc/stat").ok()?;
    for line in data.lines() {
        if !line.starts_with("cpu ") {
            continue;
        }
        let mut total = 0u64;
        let mut idle = 0u64;
        for (i, tok) in line.split_whitespace().skip(1).enumerate() {
            if let Ok(v) = tok.parse::<u64>() {
                total += v;
                if i == 3 || i == 4 {
                    idle += v;
                }
            }
        }
        return Some((idle, total));
    }
    None
}

pub async fn read_cpu_percent() -> f64 {
    let Some((idle1, total1)) = read_proc_stat_cpu() else {
        return 0.0;
    };
    tokio::time::sleep(Duration::from_millis(200)).await;
    let Some((idle2, total2)) = read_proc_stat_cpu() else {
        return 0.0;
    };
    if total2 <= total1 {
        return 0.0;
    }
    let d_idle = (idle2 - idle1) as f64;
    let d_total = (total2 - total1) as f64;
    if d_total == 0.0 {
        0.0
    } else {
        (1.0 - d_idle / d_total) * 100.0
    }
}

pub fn disk_usage(path: &Path) -> (u64, u64) {
    let target = if path.exists() {
        path
    } else {
        path.parent().unwrap_or_else(|| Path::new("/"))
    };
    let Ok(c_path) = CString::new(target.as_os_str().as_bytes()) else {
        return (0, 0);
    };
    unsafe {
        let mut st: libc::statvfs = std::mem::zeroed();
        if libc::statvfs(c_path.as_ptr(), &mut st) != 0 {
            return (0, 0);
        }
        let total = (st.f_blocks as u64).saturating_mul(st.f_frsize as u64);
        let free = (st.f_bfree as u64).saturating_mul(st.f_frsize as u64);
        let used = total.saturating_sub(free);
        (used, total)
    }
}

pub fn uptime_seconds(started_at: Instant) -> u64 {
    started_at.elapsed().as_secs()
}
