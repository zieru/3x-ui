use serde_json::Value;
use serde_yaml::{Mapping, Value as YamlValue};
use std::collections::HashSet;

use crate::state::{
    client_enabled, client_id, extra_ports_for, settings_clients, ExtraPorts, Inbound,
    API_INBOUND_PORT,
};

#[derive(Debug, Clone)]
pub struct TranslateResult {
    pub yaml: String,
    pub warnings: Vec<String>,
}

fn yaml_str(s: &str) -> YamlValue {
    YamlValue::String(s.to_string())
}

fn yaml_bool(b: bool) -> YamlValue {
    YamlValue::Bool(b)
}

fn map_insert_str(m: &mut Mapping, k: &str, v: &str) {
    m.insert(yaml_str(k), yaml_str(v));
}

fn map_insert_bool(m: &mut Mapping, k: &str, v: bool) {
    m.insert(yaml_str(k), yaml_bool(v));
}

fn parse_json(s: &str) -> Value {
    if s.trim().is_empty() {
        return Value::Object(Default::default());
    }
    serde_json::from_str(s).unwrap_or_else(|_| Value::Object(Default::default()))
}

fn build_inner_protocol(
    ib: &Inbound,
    settings: &Value,
    clients: &[serde_json::Map<String, Value>],
    warnings: &mut Vec<String>,
) -> Option<Mapping> {
    let proto = ib.protocol.to_lowercase();
    let mut m = Mapping::new();

    match proto.as_str() {
        "vless" => {
            map_insert_str(&mut m, "type", "vless");
            // shoes expects user_id; if multiple enabled clients exist, emit first or user_ids
            // Note: shoes v0.3.8 vless server accepts user_id (string). If multiple clients,
            // we emit the primary user_id and warn if >1 until multi-user patch is applied.
            if let Some(first) = clients.first() {
                let id = client_id(first);
                if !id.is_empty() {
                    map_insert_str(&mut m, "user_id", &id);
                }
            } else {
                warnings.push(format!("inbound {} ({}): no enabled clients", ib.tag, proto));
                return None;
            }
            if clients.len() > 1 {
                warnings.push(format!(
                    "inbound {} (vless): {} enabled clients; shoes single-user listener uses first client (multi-user requires shoes server patch)",
                    ib.tag,
                    clients.len()
                ));
            }
            map_insert_bool(&mut m, "udp_enabled", true);
            Some(m)
        }
        "vmess" => {
            map_insert_str(&mut m, "type", "vmess");
            if let Some(first) = clients.first() {
                let id = client_id(first);
                if !id.is_empty() {
                    map_insert_str(&mut m, "user_id", &id);
                }
            } else {
                warnings.push(format!("inbound {} ({}): no enabled clients", ib.tag, proto));
                return None;
            }
            map_insert_str(&mut m, "cipher", "aes-128-gcm");
            map_insert_bool(&mut m, "udp_enabled", true);
            Some(m)
        }
        "trojan" => {
            map_insert_str(&mut m, "type", "trojan");
            if let Some(first) = clients.first() {
                let pw = first
                    .get("password")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if !pw.is_empty() {
                    map_insert_str(&mut m, "password", pw);
                }
            } else {
                warnings.push(format!("inbound {} ({}): no enabled clients", ib.tag, proto));
                return None;
            }
            Some(m)
        }
        "shadowsocks" => {
            map_insert_str(&mut m, "type", "shadowsocks");
            let method = settings
                .get("method")
                .and_then(|v| v.as_str())
                .unwrap_or("aes-256-gcm");
            let password = settings
                .get("password")
                .and_then(|v| v.as_str())
                .or_else(|| {
                    clients
                        .first()
                        .and_then(|c| c.get("password").and_then(|v| v.as_str()))
                })
                .unwrap_or("");
            if password.is_empty() {
                warnings.push(format!("inbound {} (shadowsocks): missing password", ib.tag));
                return None;
            }
            map_insert_str(&mut m, "cipher", method);
            map_insert_str(&mut m, "password", password);
            let network = settings
                .get("network")
                .and_then(|v| v.as_str())
                .unwrap_or("tcp,udp");
            map_insert_bool(&mut m, "udp_enabled", network.contains("udp"));
            Some(m)
        }
        other => {
            warnings.push(format!(
                "inbound {}: protocol '{}' is not supported by shoes translator yet",
                ib.tag, other
            ));
            None
        }
    }
}

fn wrap_stream_settings(
    ib: &Inbound,
    inner_proto: Mapping,
    stream: &Value,
    clients: &[serde_json::Map<String, Value>],
    warnings: &mut Vec<String>,
) -> Mapping {
    let network = stream
        .get("network")
        .and_then(|v| v.as_str())
        .unwrap_or("tcp");
    let security = stream
        .get("security")
        .and_then(|v| v.as_str())
        .unwrap_or("none");

    let mut current = inner_proto;

    // Wrap WebSocket / XHTTP if present
    if network == "ws" {
        let mut ws = Mapping::new();
        map_insert_str(&mut ws, "type", "websocket");
        if let Some(ws_settings) = stream.get("wsSettings") {
            let mut matching = Mapping::new();
            if let Some(path) = ws_settings.get("path").and_then(|v| v.as_str()) {
                if !path.is_empty() {
                    map_insert_str(&mut matching, "path", path);
                }
            }
            if !matching.is_empty() {
                ws.insert(yaml_str("matching"), YamlValue::Mapping(matching));
            }
        }
        ws.insert(yaml_str("protocol"), YamlValue::Mapping(current));
        current = ws;
    } else if network != "tcp" && network != "raw" {
        warnings.push(format!(
            "inbound {}: network '{}' mapped as plain transport",
            ib.tag, network
        ));
    }

    // Wrap TLS or Reality
    if security == "reality" {
        if let Some(reality) = stream.get("realitySettings") {
            let private_key = reality
                .get("privateKey")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let dest = reality
                .get("dest")
                .and_then(|v| v.as_str())
                .or_else(|| reality.get("target").and_then(|v| v.as_str()))
                .unwrap_or("www.google.com:443");
            let server_names: Vec<String> = reality
                .get("serverNames")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|x| x.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .filter(|v: &Vec<String>| !v.is_empty())
                .unwrap_or_else(|| vec!["www.google.com".to_string()]);
            let short_ids: Vec<YamlValue> = reality
                .get("shortIds")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|x| x.as_str().map(yaml_str))
                        .collect()
                })
                .filter(|v: &Vec<YamlValue>| !v.is_empty())
                .unwrap_or_else(|| vec![yaml_str("")]);

            let vision = !ib.disable_flow
                && clients.iter().any(|c| {
                    c.get("flow")
                        .and_then(|v| v.as_str())
                        .map(|f| f.contains("vision"))
                        .unwrap_or(false)
                });

            let mut targets = Mapping::new();
            for sni in server_names {
                let mut target_cfg = Mapping::new();
                map_insert_str(&mut target_cfg, "private_key", private_key);
                target_cfg.insert(yaml_str("short_ids"), YamlValue::Sequence(short_ids.clone()));
                map_insert_str(&mut target_cfg, "dest", dest);
                if vision && ib.protocol.eq_ignore_ascii_case("vless") {
                    map_insert_bool(&mut target_cfg, "vision", true);
                }
                target_cfg.insert(yaml_str("protocol"), YamlValue::Mapping(current.clone()));
                targets.insert(yaml_str(&sni), YamlValue::Mapping(target_cfg));
            }

            let mut tls = Mapping::new();
            map_insert_str(&mut tls, "type", "tls");
            tls.insert(yaml_str("reality_targets"), YamlValue::Mapping(targets));
            return tls;
        }
    } else if security == "tls" {
        if let Some(tls_settings) = stream.get("tlsSettings") {
            let mut tls = Mapping::new();
            map_insert_str(&mut tls, "type", "tls");
            if let Some(certs) = tls_settings.get("certificates").and_then(|v| v.as_array()) {
                if let Some(first_cert) = certs.first() {
                    let cert = first_cert
                        .get("certificateFile")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let key = first_cert
                        .get("keyFile")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let sni = tls_settings
                        .get("serverName")
                        .and_then(|v| v.as_str())
                        .unwrap_or("*");
                    if !cert.is_empty() && !key.is_empty() {
                        let mut sni_cfg = Mapping::new();
                        map_insert_str(&mut sni_cfg, "cert", cert);
                        map_insert_str(&mut sni_cfg, "key", key);
                        sni_cfg.insert(yaml_str("protocol"), YamlValue::Mapping(current));
                        let mut sni_targets = Mapping::new();
                        sni_targets.insert(yaml_str(sni), YamlValue::Mapping(sni_cfg));
                        tls.insert(yaml_str("sni_targets"), YamlValue::Mapping(sni_targets));
                        return tls;
                    }
                }
            }
            warnings.push(format!(
                "inbound {}: tlsSettings missing certificateFile/keyFile",
                ib.tag
            ));
        }
    }

    current
}

pub fn render_shoes_yaml(inbounds: &[Inbound], extra: &ExtraPorts) -> TranslateResult {
    let mut warnings = Vec::new();
    let mut docs: Vec<YamlValue> = Vec::new();

    let mut used_ports: HashSet<i32> = HashSet::new();
    used_ports.insert(API_INBOUND_PORT);
    for ib in inbounds {
        if ib.enable {
            used_ports.insert(ib.port);
        }
    }

    for ib in inbounds {
        if !ib.enable {
            continue;
        }
        let settings = parse_json(&ib.settings);
        let stream = parse_json(&ib.stream_settings);

        let all_clients = settings_clients(&ib.settings);
        let enabled_clients: Vec<_> = all_clients
            .into_iter()
            .filter(|c| client_enabled(c))
            .collect();

        // Shadowsocks may not use `clients[]` array in 3x-ui single-user mode
        if enabled_clients.is_empty() && !ib.protocol.eq_ignore_ascii_case("shadowsocks") {
            continue;
        }

        let Some(inner_proto) = build_inner_protocol(ib, &settings, &enabled_clients, &mut warnings)
        else {
            continue;
        };

        let protocol_map =
            wrap_stream_settings(ib, inner_proto, &stream, &enabled_clients, &mut warnings);

        let listen = if ib.listen.trim().is_empty() {
            "0.0.0.0"
        } else {
            ib.listen.trim()
        };

        let mut ports = vec![ib.port];
        for ep in extra_ports_for(ib, extra, &mut used_ports) {
            ports.push(ep);
        }

        for port in ports {
            let mut entry = Mapping::new();
            map_insert_str(&mut entry, "address", &format!("{listen}:{port}"));
            entry.insert(
                yaml_str("protocol"),
                YamlValue::Mapping(protocol_map.clone()),
            );
            docs.push(YamlValue::Mapping(entry));
        }
    }

    let yaml = if docs.is_empty() {
        "[]\n".to_string()
    } else {
        serde_yaml::to_string(&YamlValue::Sequence(docs)).unwrap_or_else(|_| "[]\n".to_string())
    };

    TranslateResult { yaml, warnings }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::ProxyEngine;
    use std::collections::HashMap;

    #[test]
    fn test_vless_reality_vision_valid_shoes_yaml() {
        let ib = Inbound {
            id: 1,
            enable: true,
            listen: "0.0.0.0".to_string(),
            port: 443,
            protocol: "vless".to_string(),
            tag: "in-443-vless".to_string(),
            settings: r#"{"clients":[{"id":"b85798ef-e9dc-46a4-9a87-8da4499d36d0","email":"alice@test","flow":"xtls-rprx-vision","enable":true}]}"#.to_string(),
            stream_settings: r#"{"network":"tcp","security":"reality","realitySettings":{"privateKey":"cO_FAKE_KEY_FOR_UNIT_TEST_0123456789abcdef0=","shortIds":["0123456789abcdef"],"serverNames":["www.google.com"],"dest":"www.google.com:443"}}"#.to_string(),
            ..Default::default()
        };
        let mut extra = HashMap::new();
        extra.insert("in-443-vless".to_string(), vec![5010]);

        let res = render_shoes_yaml(&[ib], &extra);
        assert!(res.yaml.contains("0.0.0.0:443"));
        assert!(res.yaml.contains("0.0.0.0:5010"));
        assert!(res.yaml.contains("vision: true"));
        // Validate directly with shoes::config::load_config_str!
        ProxyEngine::validate_yaml(&res.yaml).expect("shoes should accept generated VLESS+Reality YAML");
    }

    #[test]
    fn test_shadowsocks_2022_valid_shoes_yaml() {
        let ib = Inbound {
            id: 2,
            enable: true,
            listen: "0.0.0.0".to_string(),
            port: 8390,
            protocol: "shadowsocks".to_string(),
            tag: "in-8390-ss".to_string(),
            settings: r#"{"method":"2022-blake3-aes-256-gcm","password":"N5tp51JibWA9kIPEUoDHzyyjfgkDYToOERh+u9L47fk=","network":"tcp,udp"}"#.to_string(),
            ..Default::default()
        };
        let res = render_shoes_yaml(&[ib], &HashMap::new());
        ProxyEngine::validate_yaml(&res.yaml).expect("shoes should accept generated SS-2022 YAML");
    }

    #[test]
    fn test_disabled_inbound_and_disabled_client_omitted() {
        let ib = Inbound {
            id: 3,
            enable: true,
            port: 8443,
            protocol: "vless".to_string(),
            tag: "in-8443-vless".to_string(),
            settings: r#"{"clients":[{"id":"b85798ef-e9dc-46a4-9a87-8da4499d36d0","email":"disabled@test","enable":false}]}"#.to_string(),
            ..Default::default()
        };
        let res = render_shoes_yaml(&[ib], &HashMap::new());
        assert_eq!(res.yaml.trim(), "[]");
        ProxyEngine::validate_yaml(&res.yaml).unwrap();
    }
}

