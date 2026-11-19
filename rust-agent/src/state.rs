use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use uuid::Uuid;

pub const VERSION: &str = "v3.11.0-agent6-rs";
pub const API_INBOUND_PORT: i32 = 10085;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ClientTraffic {
    pub id: i32,
    pub inbound_id: i32,
    pub enable: bool,
    pub email: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub uuid: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sub_id: String,
    pub up: i64,
    pub down: i64,
    pub expiry_time: i64,
    pub total: i64,
    pub reset: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Inbound {
    pub id: i32,
    pub up: i64,
    pub down: i64,
    pub total: i64,
    pub remark: String,
    pub sub_sort_index: i32,
    pub exclude_from_sub: bool,
    pub enable: bool,
    pub expiry_time: i64,
    pub traffic_reset: String,
    pub traffic_reset_day: i32,
    pub last_traffic_reset_time: i64,
    pub listen: String,
    pub port: i32,
    pub protocol: String,
    pub settings: String,
    pub stream_settings: String,
    pub tag: String,
    pub sniffing: String,
    pub share_addr_strategy: String,
    pub share_addr: String,
    pub disable_flow: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub origin_node_guid: String,
    #[serde(default)]
    pub client_stats: Vec<ClientTraffic>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PersistentState {
    pub panel_guid: String,
    pub next_id: i32,
    pub inbounds: Vec<Inbound>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub stat_base: HashMap<String, i64>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub stat_last: HashMap<String, i64>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub last_online: HashMap<String, i64>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub inbound_last_active: HashMap<String, i64>,
}

impl Default for PersistentState {
    fn default() -> Self {
        Self {
            panel_guid: Uuid::new_v4().to_string(),
            next_id: 1,
            inbounds: Vec::new(),
            stat_base: HashMap::new(),
            stat_last: HashMap::new(),
            last_online: HashMap::new(),
            inbound_last_active: HashMap::new(),
        }
    }
}

pub type ExtraPorts = HashMap<String, Vec<i32>>;

pub fn load_state(path: &Path) -> Result<PersistentState, String> {
    match fs::read(path) {
        Ok(bytes) => {
            let mut st: PersistentState =
                serde_json::from_slice(&bytes).map_err(|e| format!("parse state file: {e}"))?;
            if st.panel_guid.is_empty() {
                st.panel_guid = Uuid::new_v4().to_string();
            }
            if st.next_id < 1 {
                st.next_id = 1;
            }
            Ok(st)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let st = PersistentState::default();
            save_state(path, &st)?;
            Ok(st)
        }
        Err(e) => Err(format!("read state file: {e}")),
    }
}

pub fn save_state(path: &Path, st: &PersistentState) -> Result<(), String> {
    let data = serde_json::to_vec_pretty(st).map_err(|e| format!("marshal state: {e}"))?;
    let tmp = PathBuf::from(format!("{}.tmp", path.display()));
    fs::write(&tmp, &data).map_err(|e| format!("write tmp state: {e}"))?;
    let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600));
    fs::rename(&tmp, path).map_err(|e| format!("rename state: {e}"))?;
    Ok(())
}

pub fn load_or_create_token(path: &Path) -> Result<(String, bool), String> {
    if let Ok(raw) = fs::read_to_string(path) {
        let tok = raw.trim().to_string();
        if !tok.is_empty() {
            return Ok((tok, false));
        }
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("mkdir token dir: {e}"))?;
        let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
    }
    // 24 random bytes -> 48 hex chars (matches Go x-ui-agent)
    let mut raw = [0u8; 24];
    let u1 = Uuid::new_v4();
    let u2 = Uuid::new_v4();
    raw[..16].copy_from_slice(u1.as_bytes());
    raw[16..].copy_from_slice(&u2.as_bytes()[..8]);
    let tok = hex::encode(raw);
    fs::write(path, format!("{tok}\n")).map_err(|e| format!("write token: {e}"))?;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    Ok((tok, true))
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

pub fn load_extra_ports(state_dir: &Path) -> ExtraPorts {
    let path = state_dir.join("extra-ports.json");
    let Ok(data) = fs::read(path) else {
        return HashMap::new();
    };
    serde_json::from_slice(&data).unwrap_or_default()
}

pub fn extra_ports_for(ib: &Inbound, extra: &ExtraPorts, used: &mut HashSet<i32>) -> Vec<i32> {
    let candidates = extra
        .get(&ib.tag)
        .or_else(|| {
            if !ib.remark.is_empty() {
                extra.get(&ib.remark)
            } else {
                None
            }
        })
        .cloned()
        .unwrap_or_default();

    let mut out = Vec::new();
    for p in candidates {
        if !(1..=65535).contains(&p) || p == ib.port || p == API_INBOUND_PORT || used.contains(&p) {
            continue;
        }
        used.insert(p);
        out.push(p);
    }
    out
}

pub fn settings_clients(settings: &str) -> Vec<serde_json::Map<String, Value>> {
    let Ok(Value::Object(map)) = serde_json::from_str::<Value>(settings) else {
        return Vec::new();
    };
    let Some(Value::Array(arr)) = map.get("clients") else {
        return Vec::new();
    };
    arr.iter()
        .filter_map(|v| v.as_object().cloned())
        .collect()
}

pub fn set_settings_clients(settings: &str, clients: Vec<serde_json::Map<String, Value>>) -> String {
    let mut map = match serde_json::from_str::<Value>(settings) {
        Ok(Value::Object(m)) => m,
        _ => serde_json::Map::new(),
    };
    map.insert(
        "clients".to_string(),
        Value::Array(clients.into_iter().map(Value::Object).collect()),
    );
    serde_json::to_string(&Value::Object(map)).unwrap_or_else(|_| settings.to_string())
}

pub fn client_email(c: &serde_json::Map<String, Value>) -> String {
    c.get("email")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

pub fn client_id(c: &serde_json::Map<String, Value>) -> String {
    c.get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

pub fn client_enabled(c: &serde_json::Map<String, Value>) -> bool {
    c.get("enable").and_then(|v| v.as_bool()).unwrap_or(true)
}
