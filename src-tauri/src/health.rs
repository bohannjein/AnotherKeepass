//! Password health (like KeePassXC's reports): weak, reused, old, expired, and optionally
//! known from data breaches (Have I Been Pwned, k-anonymity). Passwords never leave Rust:
//! the UI only gets flags, and for HIBP only the first 5 hex chars of each SHA-1.

use std::collections::HashMap;

use chrono::{NaiveDateTime, Utc};
use keepass::db::{Database, Entry, GroupId};
use serde::Serialize;
use sha1::{Digest, Sha1};

use crate::vault::Vaults;

/// Older than this (days since the password last changed) counts as "old".
const OLD_DAYS: i64 = 365;
/// Below this estimated entropy a password counts as weak (same cut as the generator meter).
const WEAK_BITS: f64 = 50.0;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Health {
    vault: String,
    id: String,
    bits: u32,
    weak: bool,
    /// number of other entries (all open vaults) with the same password
    reused: usize,
    /// days since the password changed
    age_days: i64,
    old: bool,
    expired: bool,
}

/// ponytail: class-pool × length estimate with a few pattern penalties; swap for zxcvbn
/// if users report misjudged passwords.
pub fn entropy_bits(pw: &str) -> f64 {
    let chars: Vec<char> = pw.chars().collect();
    if chars.is_empty() {
        return 0.0;
    }
    let mut pool = 0;
    if chars.iter().any(|c| c.is_ascii_lowercase()) { pool += 26; }
    if chars.iter().any(|c| c.is_ascii_uppercase()) { pool += 26; }
    if chars.iter().any(|c| c.is_ascii_digit()) { pool += 10; }
    if chars.iter().any(|c| c.is_ascii_punctuation() || *c == ' ') { pool += 33; }
    if chars.iter().any(|c| !c.is_ascii()) { pool += 100; }
    // repeated or sequential characters add almost nothing ("aaaa", "1234", "abcd")
    let mut effective = 1.0;
    for w in chars.windows(2) {
        let d = w[1] as i64 - w[0] as i64;
        effective += if d == 0 || d.abs() == 1 { 0.25 } else { 1.0 };
    }
    let mut bits = effective * (pool as f64).log2();
    let lower = pw.to_lowercase();
    if COMMON.iter().any(|c| lower.contains(c)) {
        bits = bits.min(20.0);
    }
    bits
}

const COMMON: &[&str] = &[
    "password", "passwort", "123456", "qwerty", "qwertz", "letmein", "welcome", "willkommen", "admin", "iloveyou",
    "monkey", "dragon", "sunshine", "princess", "football", "fussball", "hallo", "geheim", "secret", "abc123",
];

/// When the current password was set: walk back through history while it stays the same.
fn password_since(e: &Entry) -> Option<NaiveDateTime> {
    let current = e.get("Password").unwrap_or_default();
    let mut since = e.times.last_modification;
    if let Some(h) = &e.history {
        // history is newest first
        for old in h.get_entries() {
            if old.get("Password").unwrap_or_default() != current {
                break;
            }
            since = old.times.last_modification.or(since);
        }
    }
    since.or(e.times.creation)
}

fn in_bin(db: &Database, mut g: Option<GroupId>) -> bool {
    let bin = db.recycle_bin().map(|b| b.id());
    while let Some(id) = g {
        if Some(id) == bin {
            return true;
        }
        g = db.group(id).and_then(|x| x.parent().map(|p| p.id()));
    }
    false
}

fn report(vaults: &HashMap<String, crate::vault::OpenVault>) -> Vec<Health> {
    let now = Utc::now().naive_utc();
    let mut rows = Vec::new();
    let mut by_password: HashMap<String, usize> = HashMap::new();
    for (vid, v) in vaults {
        for e in v.db().iter_all_entries() {
            let pw = e.get("Password").unwrap_or_default();
            if pw.is_empty() || in_bin(v.db(), Some(e.parent().id())) {
                continue;
            }
            *by_password.entry(pw.to_string()).or_default() += 1;
            let bits = entropy_bits(pw);
            let age_days = password_since(&e).map(|t| (now - t).num_days()).unwrap_or(0);
            rows.push((pw.to_string(), Health {
                vault: vid.clone(),
                id: e.id().to_string(),
                bits: bits as u32,
                weak: bits < WEAK_BITS,
                reused: 0,
                age_days,
                old: age_days > OLD_DAYS,
                expired: e.times.expires == Some(true) && e.times.expiry < now,
            }));
        }
    }
    rows.into_iter()
        .map(|(pw, mut h)| {
            h.reused = by_password[&pw] - 1;
            h
        })
        .collect()
}

#[tauri::command]
pub fn health_report(state: tauri::State<'_, Vaults>) -> Result<Vec<Health>, String> {
    let map = state.0.lock().map_err(|_| "lock")?;
    Ok(report(&map))
}

fn sha1_hex(pw: &str) -> String {
    Sha1::digest(pw.as_bytes()).iter().map(|b| format!("{b:02X}")).collect()
}

/// 5-char SHA-1 prefixes the UI asks api.pwnedpasswords.com for (k-anonymity).
#[tauri::command]
pub fn health_breach_prefixes(state: tauri::State<'_, Vaults>) -> Result<Vec<String>, String> {
    let map = state.0.lock().map_err(|_| "lock")?;
    let mut p: Vec<String> = map
        .values()
        .flat_map(|v| v.db().iter_all_entries().filter_map(|e| e.get("Password").filter(|p| !p.is_empty()).map(|p| sha1_hex(p)[..5].to_string())).collect::<Vec<_>>())
        .collect();
    p.sort();
    p.dedup();
    Ok(p)
}

/// The API answers (per prefix: "SUFFIX:COUNT" lines) → how often each entry's password was seen.
#[tauri::command]
pub fn health_breach_match(state: tauri::State<'_, Vaults>, ranges: HashMap<String, String>) -> Result<HashMap<String, u64>, String> {
    let map = state.0.lock().map_err(|_| "lock")?;
    let mut out = HashMap::new();
    for v in map.values() {
        for e in v.db().iter_all_entries() {
            let Some(pw) = e.get("Password").filter(|p| !p.is_empty()) else { continue };
            let hash = sha1_hex(pw);
            let count = breach_count(&hash, ranges.get(&hash[..5]).map(String::as_str).unwrap_or(""));
            if count > 0 {
                out.insert(e.id().to_string(), count);
            }
        }
    }
    Ok(out)
}

fn breach_count(hash: &str, range: &str) -> u64 {
    range
        .lines()
        .filter_map(|l| l.trim().split_once(':'))
        .find(|(suffix, _)| suffix.eq_ignore_ascii_case(&hash[5..]))
        .and_then(|(_, n)| n.trim().parse().ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy() {
        assert!(entropy_bits("password1") < WEAK_BITS);
        assert!(entropy_bits("aaaaaaaaaaaaaaaa") < WEAK_BITS);
        assert!(entropy_bits("12345678901234") < WEAK_BITS);
        assert!(entropy_bits("Tr7#kq9!Lm2$vX") > WEAK_BITS);
        assert!(entropy_bits("correct-horse-battery-staple") > WEAK_BITS);
    }

    #[test]
    fn breach_lookup() {
        let h = sha1_hex("password");
        assert_eq!(h, "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8");
        let range = "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:9545824\r\n";
        assert_eq!(breach_count(&h, range), 9545824);
        assert_eq!(breach_count(&sha1_hex("x"), range), 0);
    }
}

/// Strength of a password typed in the UI (master password): estimated bits.
#[tauri::command]
pub fn password_bits(password: String) -> u32 {
    entropy_bits(&password) as u32
}

/// How often a password was seen in breaches (HIBP range API, k-anonymity: only 5 hash chars leave).
#[tauri::command]
pub async fn password_breached(password: String) -> Result<u64, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let hash = sha1_hex(&password);
        let range = ureq::get(&format!("https://api.pwnedpasswords.com/range/{}", &hash[..5]))
            .set("Add-Padding", "true")
            .timeout(std::time::Duration::from_secs(10))
            .call()
            .map_err(|e| format!("hibp:{e}"))?
            .into_string()
            .map_err(|e| format!("hibp:{e}"))?;
        Ok(breach_count(&hash, &range))
    })
    .await
    .map_err(|e| e.to_string())?
}
