use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Method, Request, Response, StatusCode};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Instant, SystemTime};
use tokio::sync::Mutex;

use crate::engine::ProxyEngine;
use crate::shell::{handle_exec, upgrade_pty, ShellGuard};
use crate::state::{
    client_email, client_id, constant_time_eq, load_extra_ports, save_state, set_settings_clients,
    settings_clients, sha256_hex, ClientTraffic, Inbound, PersistentState, VERSION,
};
use crate::stats::{
    now_unix, online_snapshot, reported_traffic, zero_traffic, ClientIpEntry, ClientIpsRow,
    StatPair,
};
use crate::status::{
    disk_usage, read_cpu_percent, read_loadavg, read_meminfo, uptime_seconds, MemInfo, NetIO,
    StatusSnapshot, XrayInfo,
};
use crate::translator::render_shoes_yaml;

pub struct AgentContext {
    pub state_dir: PathBuf,
    pub state_path: PathBuf,
    pub token_path: PathBuf,
    pub token: Mutex<(String, Option<SystemTime>)>,
    pub base_path: String,
    pub started_at: Instant,
    pub state: Mutex<PersistentState>,
    pub engine: Mutex<ProxyEngine>,
    pub raw_stats: Mutex<HashMap<String, StatPair>>,
    pub live_ips: Mutex<HashMap<String, Vec<ClientIpEntry>>>,
    pub shell_guard: Arc<ShellGuard>,
}

impl AgentContext {
    pub async fn current_token(&self) -> String {
        let mtime = std::fs::metadata(&self.token_path)
            .and_then(|m| m.modified())
            .ok();
        let mut guard = self.token.lock().await;
        if let Some(mt) = mtime {
            if guard.1 != Some(mt) {
                if let Ok(raw) = std::fs::read_to_string(&self.token_path) {
                    let trimmed = raw.trim().to_string();
                    if !trimmed.is_empty() {
                        if guard.0 != trimmed {
                            log::info!("API bearer token reloaded from {}", self.token_path.display());
                        }
                        guard.0 = trimmed;
                        guard.1 = Some(mt);
                    }
                }
            }
        }
        guard.0.clone()
    }

    pub async fn apply(&self) -> Result<(), String> {
        let inbounds = {
            let st = self.state.lock().await;
            st.inbounds.clone()
        };
        let extra = load_extra_ports(&self.state_dir);
        let res = render_shoes_yaml(&inbounds, &extra);
        for w in &res.warnings {
            log::warn!("translator: {w}");
        }
        let mut eng = self.engine.lock().await;
        eng.apply_yaml(&res.yaml).await
    }

    fn client_stats_for(
        st: &PersistentState,
        raw: &HashMap<String, StatPair>,
        ib: &Inbound,
    ) -> Vec<ClientTraffic> {
        let clients = settings_clients(&ib.settings);
        let mut out = Vec::with_capacity(clients.len());
        for (i, c) in clients.iter().enumerate() {
            let email = client_email(c);
            let enable = c.get("enable").and_then(|v| v.as_bool()).unwrap_or(true);
            let expiry_time = c.get("expiryTime").and_then(|v| v.as_i64()).unwrap_or(0);
            let total_gb = c.get("totalGB").and_then(|v| v.as_i64()).unwrap_or(0);
            let total = total_gb.saturating_mul(1024 * 1024 * 1024);
            let (up, down) = reported_traffic(st, raw, &email);
            out.push(ClientTraffic {
                id: (i + 1) as i32,
                inbound_id: ib.id,
                enable,
                email,
                uuid: client_id(c),
                sub_id: String::new(),
                up,
                down,
                expiry_time,
                total,
                reset: 0,
            });
        }
        out
    }
}

#[derive(Serialize)]
struct Envelope<T: Serialize> {
    success: bool,
    msg: String,
    obj: T,
}

fn json_response<T: Serialize>(status: StatusCode, success: bool, msg: &str, obj: T) -> Response<Full<Bytes>> {
    let body = serde_json::to_vec(&Envelope {
        success,
        msg: msg.to_string(),
        obj,
    })
    .unwrap_or_else(|_| b"{}".to_vec());
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

fn ok_envelope<T: Serialize>(obj: T) -> Response<Full<Bytes>> {
    json_response(StatusCode::OK, true, "", obj)
}

fn fail_envelope(msg: &str) -> Response<Full<Bytes>> {
    json_response(StatusCode::OK, false, msg, Value::Null)
}

fn err_response(status: StatusCode, msg: &str) -> Response<Full<Bytes>> {
    json_response(status, false, msg, Value::Null)
}

fn parse_bool(s: &str) -> bool {
    matches!(s.trim().to_ascii_lowercase().as_str(), "true" | "1" | "t" | "yes")
}

fn decode_wire_inbound(body: &[u8], existing: Option<&Inbound>) -> Inbound {
    let mut ib = existing.cloned().unwrap_or_default();
    let params: HashMap<String, String> = url::form_urlencoded::parse(body)
        .into_owned()
        .collect();

    if let Some(v) = params.get("total") {
        ib.total = v.trim().parse().unwrap_or(0);
    }
    if let Some(v) = params.get("remark") {
        ib.remark = v.clone();
    }
    if let Some(v) = params.get("subSortIndex") {
        ib.sub_sort_index = v.trim().parse().unwrap_or(1);
    }
    if ib.sub_sort_index == 0 {
        ib.sub_sort_index = 1;
    }
    if let Some(v) = params.get("excludeFromSub") {
        ib.exclude_from_sub = parse_bool(v);
    }
    if let Some(v) = params.get("enable") {
        ib.enable = parse_bool(v);
    }
    if let Some(v) = params.get("expiryTime") {
        ib.expiry_time = v.trim().parse().unwrap_or(0);
    }
    if let Some(v) = params.get("listen") {
        ib.listen = v.clone();
    }
    if let Some(v) = params.get("port") {
        ib.port = v.trim().parse().unwrap_or(0);
    }
    if let Some(v) = params.get("protocol") {
        ib.protocol = v.clone();
    }
    if let Some(v) = params.get("settings") {
        ib.settings = v.clone();
    }
    if let Some(v) = params.get("streamSettings") {
        ib.stream_settings = v.clone();
    }
    if let Some(v) = params.get("tag") {
        ib.tag = v.clone();
    }
    if ib.tag.is_empty() && ib.port > 0 {
        ib.tag = format!("in-{}-{}", ib.port, ib.protocol);
    }
    if let Some(v) = params.get("sniffing") {
        ib.sniffing = v.clone();
    }
    if let Some(v) = params.get("shareAddrStrategy") {
        ib.share_addr_strategy = v.clone();
    }
    if let Some(v) = params.get("shareAddr") {
        ib.share_addr = v.clone();
    }
    if let Some(v) = params.get("disableFlow") {
        ib.disable_flow = parse_bool(v);
    }
    if let Some(v) = params.get("trafficReset") {
        ib.traffic_reset = v.clone();
    }
    if let Some(v) = params.get("trafficResetDay") {
        ib.traffic_reset_day = v.trim().parse().unwrap_or(0);
    }
    ib
}

pub async fn handle_request(
    ctx: Arc<AgentContext>,
    peer_ip: IpAddr,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let method = req.method().clone();
    let raw_path = req.uri().path().to_string();
    let raw_query = req.uri().query().unwrap_or("").to_string();

    // Strip base path
    let stripped_path = if ctx.base_path == "/" {
        raw_path
    } else {
        let prefix = ctx.base_path.trim_end_matches('/');
        if !raw_path.starts_with(prefix) {
            return Ok(err_response(StatusCode::NOT_FOUND, "not found"));
        }
        let rest = &raw_path[prefix.len()..];
        if rest.starts_with('/') {
            rest.to_string()
        } else {
            format!("/{rest}")
        }
    };

    if !stripped_path.starts_with("/panel/api/") {
        return Ok(err_response(StatusCode::NOT_FOUND, "not found"));
    }

    // Remote shell endpoints: Ed25519 + Timestamp + Nonce + optional IP allowlist
    // (completely separate from 3x-ui master Bearer token).
    if stripped_path == "/panel/api/shell/pty" && method == Method::GET {
        if let Err((code, msg)) = ctx
            .shell_guard
            .verify_request(peer_ip, "GET", &stripped_path, req.headers(), b"")
            .await
        {
            return Ok(err_response(code, msg));
        }
        return Ok(upgrade_pty(ctx.shell_guard.clone(), peer_ip, req));
    }
    if stripped_path == "/panel/api/shell/exec" && method == Method::POST {
        let headers = req.headers().clone();
        let body_bytes = req.into_body().collect().await?.to_bytes();
        if let Err((code, msg)) = ctx
            .shell_guard
            .verify_request(peer_ip, "POST", &stripped_path, &headers, &body_bytes)
            .await
        {
            return Ok(err_response(code, msg));
        }
        let res = handle_exec(peer_ip, &body_bytes).await;
        return Ok(ok_envelope(res));
    }

    // Auth: Bearer token for 3x-ui master node-sync endpoints
    let auth_header = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let provided = auth_header.strip_prefix("Bearer ").map(|s| s.trim()).unwrap_or("");
    let expected_token = ctx.current_token().await;
    if provided.is_empty() || !constant_time_eq(provided.as_bytes(), expected_token.as_bytes()) {
        return Ok(err_response(StatusCode::UNAUTHORIZED, "unauthorized"));
    }

    // Reject zstd
    if req
        .headers()
        .get("content-encoding")
        .and_then(|v| v.to_str().ok())
        == Some("zstd")
    {
        return Ok(err_response(
            StatusCode::BAD_REQUEST,
            "zstd not supported by this agent",
        ));
    }

    let expected_sha = req
        .headers()
        .get("x-config-sha256")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_ascii_lowercase());

    let body_bytes = req.into_body().collect().await?.to_bytes();
    if !body_bytes.is_empty() {
        if let Some(want) = expected_sha {
            let got = sha256_hex(&body_bytes);
            if !constant_time_eq(got.as_bytes(), want.as_bytes()) {
                return Ok(err_response(
                    StatusCode::BAD_REQUEST,
                    "X-Config-Sha256 mismatch",
                ));
            }
        }
    }

    let path = stripped_path.trim_start_matches("/panel/api/");
    let seg: Vec<&str> = path.trim_matches('/').split('/').collect();

    Ok(dispatch(&ctx, &method, path, &seg, &raw_query, &body_bytes).await)
}

async fn dispatch(
    ctx: &AgentContext,
    method: &Method,
    path: &str,
    seg: &[&str],
    query: &str,
    body: &[u8],
) -> Response<Full<Bytes>> {
    match (method, path) {
        (&Method::GET, "server/status") => {
            let cpu = read_cpu_percent().await;
            let (mem_total, mem_avail, swap_total, swap_free) = read_meminfo();
            let (disk_used, disk_total) = disk_usage(&ctx.state_path);
            let (xray_state, xray_err, xray_ver) = {
                let eng = ctx.engine.lock().await;
                (eng.state.clone(), eng.error_msg.clone(), eng.version.clone())
            };
            let (panel_guid, net_up, net_down) = {
                let st = ctx.state.lock().await;
                let raw = ctx.raw_stats.lock().await;
                let mut up = 0u64;
                let mut down = 0u64;
                for ib in &st.inbounds {
                    for cs in AgentContext::client_stats_for(&st, &raw, ib) {
                        up = up.saturating_add(cs.up.max(0) as u64);
                        down = down.saturating_add(cs.down.max(0) as u64);
                    }
                }
                (st.panel_guid.clone(), up, down)
            };
            let snap = StatusSnapshot {
                cpu,
                cpu_cores: 1,
                mem: MemInfo {
                    current: mem_total.saturating_sub(mem_avail),
                    total: mem_total,
                },
                swap: MemInfo {
                    current: swap_total.saturating_sub(swap_free),
                    total: swap_total,
                },
                disk: MemInfo {
                    current: disk_used,
                    total: disk_total,
                },
                xray: XrayInfo {
                    state: xray_state,
                    error_msg: xray_err,
                    version: xray_ver,
                },
                panel_version: VERSION.to_string(),
                panel_guid,
                uptime: uptime_seconds(ctx.started_at),
                loads: read_loadavg(),
                net_io: NetIO {
                    up: net_up,
                    down: net_down,
                },
                update_available: false,
                latest_version: String::new(),
                auto_update: false,
                core_update_available: false,
                latest_core_version: String::new(),
            };
            ok_envelope(snap)
        }
        (&Method::POST, "server/restartXrayService") => {
            let mut eng = ctx.engine.lock().await;
            match eng.start_from_disk().await {
                Ok(()) => ok_envelope(Value::Null),
                Err(e) => fail_envelope(&e),
            }
        }
        (&Method::POST, "server/updatePanel") => {
            fail_envelope("updatePanel not supported by this agent")
        }
        (&Method::POST, "server/checkUpdate") => ok_envelope(json!({
            "current": VERSION,
            "latest": VERSION,
            "available": false,
            "coreInstalled": "",
            "coreLatest": "",
            "coreAvailable": false,
            "noToken": true,
            "error": "",
            "checkedAt": now_unix()
        })),
        (&Method::GET, "server/descendants") => ok_envelope(json!([])),
        (&Method::GET, "server/clientIps") => {
            let ips = ctx.live_ips.lock().await;
            let mut rows: Vec<ClientIpsRow> = ips
                .iter()
                .map(|(email, entries)| ClientIpsRow {
                    client_email: email.clone(),
                    ips: entries.clone(),
                })
                .collect();
            rows.sort_by(|a, b| a.client_email.cmp(&b.client_email));
            ok_envelope(rows)
        }
        (&Method::POST, "server/clientIps") => ok_envelope(Value::Null),

        // --- Inbounds ---
        (&Method::GET, "inbounds/list") => {
            let st = ctx.state.lock().await;
            let raw = ctx.raw_stats.lock().await;
            let mut out = Vec::with_capacity(st.inbounds.len());
            for ib in &st.inbounds {
                let mut item = ib.clone();
                let stats = AgentContext::client_stats_for(&st, &raw, ib);
                item.up = stats.iter().map(|c| c.up).sum();
                item.down = stats.iter().map(|c| c.down).sum();
                item.client_stats = stats;
                out.push(item);
            }
            ok_envelope(out)
        }
        (&Method::POST, "inbounds/add") => {
            let mut ib = decode_wire_inbound(body, None);
            let (id, tag) = {
                let mut st = ctx.state.lock().await;
                ib.id = st.next_id;
                st.next_id += 1;
                if ib.tag.is_empty() {
                    ib.tag = format!("in-{}-{}", ib.port, ib.protocol);
                }
                let id = ib.id;
                let tag = ib.tag.clone();
                st.inbounds.push(ib);
                if let Err(e) = save_state(&ctx.state_path, &st) {
                    return fail_envelope(&e);
                }
                (id, tag)
            };
            if let Err(e) = ctx.apply().await {
                return fail_envelope(&e);
            }
            ok_envelope(json!({ "id": id, "tag": tag }))
        }
        (&Method::POST, _) if seg.len() == 3 && seg[0] == "inbounds" && seg[1] == "update" => {
            let Ok(id) = seg[2].parse::<i32>() else {
                return fail_envelope("invalid inbound id");
            };
            {
                let mut st = ctx.state.lock().await;
                let Some(idx) = st.inbounds.iter().position(|x| x.id == id) else {
                    return fail_envelope("inbound not found");
                };
                let updated = decode_wire_inbound(body, Some(&st.inbounds[idx]));
                st.inbounds[idx] = updated;
                if let Err(e) = save_state(&ctx.state_path, &st) {
                    return fail_envelope(&e);
                }
            }
            if let Err(e) = ctx.apply().await {
                return fail_envelope(&e);
            }
            ok_envelope(Value::Null)
        }
        (&Method::POST, _) if seg.len() == 3 && seg[0] == "inbounds" && seg[1] == "del" => {
            let Ok(id) = seg[2].parse::<i32>() else {
                return fail_envelope("invalid inbound id");
            };
            {
                let mut st = ctx.state.lock().await;
                let before = st.inbounds.len();
                st.inbounds.retain(|x| x.id != id);
                if st.inbounds.len() == before {
                    return fail_envelope("inbound not found");
                }
                if let Err(e) = save_state(&ctx.state_path, &st) {
                    return fail_envelope(&e);
                }
            }
            if let Err(e) = ctx.apply().await {
                return fail_envelope(&e);
            }
            ok_envelope(Value::Null)
        }
        (&Method::POST, _)
            if seg.len() == 3 && seg[0] == "inbounds" && seg[2] == "subSortIndex" =>
        {
            let Ok(id) = seg[1].parse::<i32>() else {
                return fail_envelope("invalid inbound id");
            };
            let params: HashMap<String, String> =
                url::form_urlencoded::parse(body).into_owned().collect();
            let idx_val = params
                .get("subSortIndex")
                .and_then(|v| v.trim().parse::<i32>().ok())
                .unwrap_or(1);
            let mut st = ctx.state.lock().await;
            let Some(ib) = st.inbounds.iter_mut().find(|x| x.id == id) else {
                return fail_envelope("inbound not found");
            };
            ib.sub_sort_index = idx_val;
            let _ = save_state(&ctx.state_path, &st);
            ok_envelope(Value::Null)
        }
        (&Method::POST, _)
            if seg.len() == 3 && seg[0] == "inbounds" && seg[2] == "resetTraffic" =>
        {
            let Ok(id) = seg[1].parse::<i32>() else {
                return fail_envelope("invalid inbound id");
            };
            let mut st = ctx.state.lock().await;
            let raw = ctx.raw_stats.lock().await;
            let Some(idx) = st.inbounds.iter().position(|x| x.id == id) else {
                return fail_envelope("inbound not found");
            };
            let emails: Vec<String> = settings_clients(&st.inbounds[idx].settings)
                .into_iter()
                .map(|c| client_email(&c))
                .collect();
            zero_traffic(&mut st, &raw, &emails);
            st.inbounds[idx].up = 0;
            st.inbounds[idx].down = 0;
            let _ = save_state(&ctx.state_path, &st);
            ok_envelope(Value::Null)
        }
        (&Method::POST, "inbounds/resetAllTraffics")
        | (&Method::POST, "clients/bulkResetTraffic") => {
            let mut st = ctx.state.lock().await;
            let raw = ctx.raw_stats.lock().await;
            let mut all_emails = Vec::new();
            for ib in &mut st.inbounds {
                for c in settings_clients(&ib.settings) {
                    all_emails.push(client_email(&c));
                }
                ib.up = 0;
                ib.down = 0;
            }
            zero_traffic(&mut st, &raw, &all_emails);
            let _ = save_state(&ctx.state_path, &st);
            ok_envelope(Value::Null)
        }
        (&Method::POST, "inbounds/pushClientTraffics") => ok_envelope(Value::Null),

        // --- Clients ---
        (&Method::POST, "clients/add") => {
            let Ok(val) = serde_json::from_slice::<Value>(body) else {
                return fail_envelope("invalid json");
            };
            let Some(client) = val.get("client").and_then(|v| v.as_object()).cloned() else {
                return fail_envelope("missing client object");
            };
            let inbound_ids: Vec<i32> = val
                .get("inboundIds")
                .and_then(|v| v.as_array())
                .map(|a| a.iter().filter_map(|x| x.as_i64().map(|n| n as i32)).collect())
                .unwrap_or_default();
            let email = client_email(&client);
            {
                let mut st = ctx.state.lock().await;
                for ib in &mut st.inbounds {
                    if !inbound_ids.is_empty() && !inbound_ids.contains(&ib.id) {
                        continue;
                    }
                    let mut clients = settings_clients(&ib.settings);
                    clients.retain(|c| client_email(c) != email);
                    clients.push(client.clone());
                    ib.settings = set_settings_clients(&ib.settings, clients);
                }
                if let Err(e) = save_state(&ctx.state_path, &st) {
                    return fail_envelope(&e);
                }
            }
            if let Err(e) = ctx.apply().await {
                return fail_envelope(&e);
            }
            ok_envelope(Value::Null)
        }
        (&Method::POST, _) if seg.len() == 3 && seg[0] == "clients" && seg[1] == "update" => {
            let target_email = url::form_urlencoded::parse(seg[2].as_bytes())
                .next()
                .map(|(k, _)| k.into_owned())
                .unwrap_or_else(|| seg[2].to_string());
            let Ok(Value::Object(client)) = serde_json::from_slice::<Value>(body) else {
                return fail_envelope("invalid client json");
            };
            let inbound_ids: Vec<i32> = url::form_urlencoded::parse(query.as_bytes())
                .filter_map(|(k, v)| {
                    if k == "inboundIds" {
                        v.parse::<i32>().ok()
                    } else {
                        None
                    }
                })
                .collect();
            {
                let mut st = ctx.state.lock().await;
                for ib in &mut st.inbounds {
                    if !inbound_ids.is_empty() && !inbound_ids.contains(&ib.id) {
                        continue;
                    }
                    let mut clients = settings_clients(&ib.settings);
                    if let Some(pos) = clients.iter().position(|c| client_email(c) == target_email)
                    {
                        clients[pos] = client.clone();
                        ib.settings = set_settings_clients(&ib.settings, clients);
                    }
                }
                if let Err(e) = save_state(&ctx.state_path, &st) {
                    return fail_envelope(&e);
                }
            }
            if let Err(e) = ctx.apply().await {
                return fail_envelope(&e);
            }
            ok_envelope(Value::Null)
        }
        (&Method::POST, _) if seg.len() == 3 && seg[0] == "clients" && seg[2] == "detach" => {
            let target_email = seg[1].to_string();
            let inbound_ids: Vec<i32> = serde_json::from_slice::<Value>(body)
                .ok()
                .and_then(|v| {
                    v.get("inboundIds").and_then(|a| {
                        a.as_array()
                            .map(|arr| arr.iter().filter_map(|x| x.as_i64().map(|n| n as i32)).collect())
                    })
                })
                .unwrap_or_default();
            {
                let mut st = ctx.state.lock().await;
                for ib in &mut st.inbounds {
                    if !inbound_ids.is_empty() && !inbound_ids.contains(&ib.id) {
                        continue;
                    }
                    let mut clients = settings_clients(&ib.settings);
                    clients.retain(|c| client_email(c) != target_email);
                    ib.settings = set_settings_clients(&ib.settings, clients);
                }
                let _ = save_state(&ctx.state_path, &st);
            }
            if let Err(e) = ctx.apply().await {
                return fail_envelope(&e);
            }
            ok_envelope(Value::Null)
        }
        (&Method::POST, _) if seg.len() == 3 && seg[0] == "clients" && seg[1] == "del" => {
            let target_email = seg[2].to_string();
            {
                let mut st = ctx.state.lock().await;
                for ib in &mut st.inbounds {
                    let mut clients = settings_clients(&ib.settings);
                    clients.retain(|c| client_email(c) != target_email);
                    ib.settings = set_settings_clients(&ib.settings, clients);
                }
                let _ = save_state(&ctx.state_path, &st);
            }
            if let Err(e) = ctx.apply().await {
                return fail_envelope(&e);
            }
            ok_envelope(Value::Null)
        }
        (&Method::POST, _)
            if seg.len() == 3 && seg[0] == "clients" && seg[1] == "resetTraffic" =>
        {
            let target_email = seg[2].to_string();
            let mut st = ctx.state.lock().await;
            let raw = ctx.raw_stats.lock().await;
            zero_traffic(&mut st, &raw, &[target_email]);
            let _ = save_state(&ctx.state_path, &st);
            ok_envelope(Value::Null)
        }

        // --- Online status ---
        (&Method::POST, "clients/onlines") => {
            let st = ctx.state.lock().await;
            let ips = ctx.live_ips.lock().await;
            let (emails, _, _) = online_snapshot(&st, &ips, now_unix());
            ok_envelope(emails)
        }
        (&Method::POST, "clients/onlinesByGuid") => {
            let st = ctx.state.lock().await;
            let ips = ctx.live_ips.lock().await;
            let (emails, _, _) = online_snapshot(&st, &ips, now_unix());
            let mut map = HashMap::new();
            if !emails.is_empty() {
                map.insert(st.panel_guid.clone(), emails);
            }
            ok_envelope(map)
        }
        (&Method::POST, "clients/lastOnline") => {
            let st = ctx.state.lock().await;
            let ips = ctx.live_ips.lock().await;
            let (_, last_online, _) = online_snapshot(&st, &ips, now_unix());
            ok_envelope(last_online)
        }
        (&Method::POST, "clients/activeInbounds") => {
            let st = ctx.state.lock().await;
            let ips = ctx.live_ips.lock().await;
            let (_, _, tags) = online_snapshot(&st, &ips, now_unix());
            let mut map = HashMap::new();
            if !tags.is_empty() {
                map.insert(st.panel_guid.clone(), tags);
            }
            ok_envelope(map)
        }
        (&Method::POST, "clients/clientIpsByGuid") => {
            let st = ctx.state.lock().await;
            let ips = ctx.live_ips.lock().await;
            let mut map = HashMap::new();
            if !ips.is_empty() {
                map.insert(st.panel_guid.clone(), ips.clone());
            }
            ok_envelope(map)
        }
        (&Method::GET, "hosts/list") => ok_envelope(json!([])),

        _ => err_response(StatusCode::NOT_FOUND, &format!("not found: {path}")),
    }
}
