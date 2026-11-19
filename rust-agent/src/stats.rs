use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::state::{client_email, settings_clients, PersistentState};

pub const ONLINE_GRACE_SECS: i64 = 20;

#[derive(Debug, Clone, Copy, Default)]
pub struct StatPair {
    pub up: i64,
    pub down: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientIpEntry {
    pub ip: String,
    pub timestamp: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientIpsRow {
    pub client_email: String,
    pub ips: Vec<ClientIpEntry>,
}

pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub fn stat_key(email: &str, dir: &str) -> String {
    format!("{email}|{dir}")
}

/// Folds raw proxy counters into persistent `statBase` / `statLast` offsets
/// and updates `lastOnline` / `inboundLastActive` when counters advance.
/// Returns `true` if `statBase` changed (requiring immediate disk save).
pub fn fold_raw_stats(
    st: &mut PersistentState,
    raw: &HashMap<String, StatPair>,
    now: i64,
) -> bool {
    let mut base_changed = false;

    // Map email -> inbound tags for activeInbounds tracking
    let mut email_tags: HashMap<String, Vec<String>> = HashMap::new();
    for ib in &st.inbounds {
        if !ib.enable || ib.tag.is_empty() {
            continue;
        }
        for c in settings_clients(&ib.settings) {
            let email = client_email(&c);
            if !email.is_empty() {
                email_tags.entry(email).or_default().push(ib.tag.clone());
            }
        }
    }

    for (email, pair) in raw {
        let up_key = stat_key(email, "uplink");
        let down_key = stat_key(email, "downlink");

        let last_up = *st.stat_last.get(&up_key).unwrap_or(&0);
        let last_down = *st.stat_last.get(&down_key).unwrap_or(&0);

        let mut moved = false;
        if pair.up < last_up {
            *st.stat_base.entry(up_key.clone()).or_insert(0) += last_up;
            base_changed = true;
            if pair.up > 0 {
                moved = true;
            }
        } else if pair.up > last_up {
            moved = true;
        }

        if pair.down < last_down {
            *st.stat_base.entry(down_key.clone()).or_insert(0) += last_down;
            base_changed = true;
            if pair.down > 0 {
                moved = true;
            }
        } else if pair.down > last_down {
            moved = true;
        }

        st.stat_last.insert(up_key, pair.up);
        st.stat_last.insert(down_key, pair.down);

        if moved {
            st.last_online.insert(email.clone(), now);
            if let Some(tags) = email_tags.get(email) {
                for tag in tags {
                    st.inbound_last_active.insert(tag.clone(), now);
                }
            }
        }
    }

    base_changed
}

pub fn reported_traffic(st: &PersistentState, raw: &HashMap<String, StatPair>, email: &str) -> (i64, i64) {
    if email.is_empty() {
        return (0, 0);
    }
    let up_key = stat_key(email, "uplink");
    let down_key = stat_key(email, "downlink");
    let raw_pair = raw.get(email).copied().unwrap_or_default();
    let up = st.stat_base.get(&up_key).copied().unwrap_or(0) + raw_pair.up;
    let down = st.stat_base.get(&down_key).copied().unwrap_or(0) + raw_pair.down;
    (up.max(0), down.max(0))
}

pub fn zero_traffic(st: &mut PersistentState, raw: &HashMap<String, StatPair>, emails: &[String]) {
    for email in emails {
        if email.is_empty() {
            continue;
        }
        let raw_pair = raw.get(email).copied().unwrap_or_default();
        let up_key = stat_key(email, "uplink");
        let down_key = stat_key(email, "downlink");
        st.stat_base.insert(up_key.clone(), -raw_pair.up);
        st.stat_base.insert(down_key.clone(), -raw_pair.down);
        st.stat_last.insert(up_key, raw_pair.up);
        st.stat_last.insert(down_key, raw_pair.down);
    }
}

pub fn online_snapshot(
    st: &PersistentState,
    live_ips: &HashMap<String, Vec<ClientIpEntry>>,
    now: i64,
) -> (Vec<String>, HashMap<String, i64>, Vec<String>) {
    let mut online_set: HashSet<String> = HashSet::new();
    let mut last_online = st.last_online.clone();

    for (email, &ts) in &st.last_online {
        if now - ts <= ONLINE_GRACE_SECS {
            online_set.insert(email.clone());
        }
    }

    for (email, ips) in live_ips {
        if !ips.is_empty() {
            online_set.insert(email.clone());
            let max_ts = ips.iter().map(|i| i.timestamp).max().unwrap_or(now);
            let entry = last_online.entry(email.clone()).or_insert(0);
            if max_ts > *entry {
                *entry = max_ts;
            }
        }
    }

    let mut emails: Vec<String> = online_set.into_iter().collect();
    emails.sort();

    let mut active_tags: Vec<String> = st
        .inbound_last_active
        .iter()
        .filter_map(|(tag, &ts)| {
            if now - ts <= ONLINE_GRACE_SECS {
                Some(tag.clone())
            } else {
                None
            }
        })
        .collect();
    active_tags.sort();

    (emails, last_online, active_tags)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::Inbound;

    #[test]
    fn test_stats_fold_restart_and_reset() {
        let mut st = PersistentState::default();
        st.inbounds.push(Inbound {
            id: 1,
            enable: true,
            tag: "in-443-vless".to_string(),
            settings: r#"{"clients":[{"email":"alice@test","id":"123"}]}"#.to_string(),
            ..Default::default()
        });

        let mut raw = HashMap::new();
        raw.insert("alice@test".to_string(), StatPair { up: 1000, down: 2000 });
        assert!(!fold_raw_stats(&mut st, &raw, 100));
        assert_eq!(reported_traffic(&st, &raw, "alice@test"), (1000, 2000));

        // Simulate proxy restart (raw drops below last)
        raw.insert("alice@test".to_string(), StatPair { up: 250, down: 500 });
        assert!(fold_raw_stats(&mut st, &raw, 110));
        assert_eq!(reported_traffic(&st, &raw, "alice@test"), (1250, 2500));

        // Simulate traffic reset
        zero_traffic(&mut st, &raw, &["alice@test".to_string()]);
        assert_eq!(reported_traffic(&st, &raw, "alice@test"), (0, 0));

        // Online snapshot within 20s grace window
        let (onlines, _, active_tags) = online_snapshot(&st, &HashMap::new(), 125);
        assert_eq!(onlines, vec!["alice@test".to_string()]);
        assert_eq!(active_tags, vec!["in-443-vless".to_string()]);
    }
}

