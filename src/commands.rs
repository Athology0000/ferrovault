//! Command handlers. These take already-obtained secrets so they are testable
//! without TTY prompts; `main.rs` does the prompting and rendering.

use crate::crypto::KdfParams;
use crate::hibp::{pwned_count, HttpFetcher};
use crate::model::Entry;
use crate::vault::VaultStore;
use crate::{Error, Result};
use std::path::PathBuf;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

pub fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

pub fn default_vault_path() -> PathBuf {
    let base = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    base.join(".ferrovault").join("vault.pvlt")
}

pub fn cmd_init(store: &VaultStore, master: &[u8]) -> Result<()> {
    store.create(master)
}

pub fn cmd_add(store: &VaultStore, master: &[u8], name: &str, entry: Entry) -> Result<()> {
    let name = name.to_string();
    store.update(master, move |v| {
        if v.entries.contains_key(&name) {
            return Err(Error::EntryExists(name.clone()));
        }
        v.entries.insert(name.clone(), entry);
        Ok(())
    })
}

pub fn cmd_get(store: &VaultStore, master: &[u8], name: &str) -> Result<Entry> {
    let (vault, _) = store.open(master)?;
    vault
        .entries
        .get(name)
        .cloned()
        .ok_or_else(|| Error::EntryNotFound(name.to_string()))
}

pub fn cmd_list(store: &VaultStore, master: &[u8]) -> Result<Vec<String>> {
    let (vault, _) = store.open(master)?;
    Ok(vault.entries.keys().cloned().collect())
}

pub fn cmd_delete(store: &VaultStore, master: &[u8], name: &str) -> Result<()> {
    let name = name.to_string();
    store.update(master, move |v| {
        if v.entries.remove(&name).is_none() {
            return Err(Error::EntryNotFound(name.clone()));
        }
        Ok(())
    })
}

/// Re-encrypt the entire vault under a fresh salt + current default KDF params.
pub fn cmd_change_password(store: &VaultStore, old: &[u8], new: &[u8]) -> Result<()> {
    let (vault, _params) = store.open(old)?; // verifies the old password
    let params = KdfParams::generate_default();
    store.rewrite(new, &params, &vault)
}

/// Current TOTP code for an entry that has a stored secret.
pub fn cmd_totp(store: &VaultStore, master: &[u8], name: &str) -> Result<(String, u64)> {
    let entry = cmd_get(store, master, name)?;
    let secret = entry.totp.ok_or(Error::Totp)?;
    let now = OffsetDateTime::now_utc().unix_timestamp().max(0) as u64;
    crate::totp::current_code(&secret, now)
}

/// Online breach check for a password (k-anonymity). Network failure surfaces
/// as `Error::Network`; the caller decides whether to treat it as fatal.
pub fn cmd_check(password: &str) -> Result<u64> {
    pwned_count(&HttpFetcher, password)
}

/// Local-only vault health metrics. Computed on-machine; never transmitted.
pub struct VaultStats {
    pub total: usize,
    pub with_totp: usize,
    pub with_url: usize,
    pub weak: usize,
    pub reused_passwords: usize,
    pub reused_entries: usize,
    pub avg_len: f64,
}

fn is_weak(pw: &str) -> bool {
    let len = pw.chars().count();
    if len < 12 {
        return true;
    }
    let classes = [
        pw.chars().any(|c| c.is_ascii_lowercase()),
        pw.chars().any(|c| c.is_ascii_uppercase()),
        pw.chars().any(|c| c.is_ascii_digit()),
        pw.chars().any(|c| !c.is_ascii_alphanumeric()),
    ]
    .iter()
    .filter(|&&b| b)
    .count();
    classes < 3
}

/// Compute local-only health stats for the vault.
pub fn cmd_stats(store: &VaultStore, master: &[u8]) -> Result<VaultStats> {
    let (vault, _) = store.open(master)?;
    let total = vault.entries.len();
    let mut with_totp = 0;
    let mut with_url = 0;
    let mut weak = 0;
    let mut len_sum = 0usize;
    let mut pw_counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for e in vault.entries.values() {
        if e.totp.is_some() {
            with_totp += 1;
        }
        if e.url.is_some() {
            with_url += 1;
        }
        if is_weak(&e.password) {
            weak += 1;
        }
        len_sum += e.password.chars().count();
        *pw_counts.entry(e.password.as_str()).or_insert(0) += 1;
    }
    let reused_passwords = pw_counts.values().filter(|&&c| c > 1).count();
    let reused_entries: usize = pw_counts.values().filter(|&&c| c > 1).sum();
    let avg_len = if total > 0 {
        len_sum as f64 / total as f64
    } else {
        0.0
    };
    Ok(VaultStats {
        total,
        with_totp,
        with_url,
        weak,
        reused_passwords,
        reused_entries,
        avg_len,
    })
}

pub fn exit_code(err: &Error) -> i32 {
    match err {
        Error::VaultNotFound(_) => 3,
        Error::VaultExists(_) => 4,
        Error::WrongPasswordOrCorrupt => 5,
        Error::BadFormat(_) => 6,
        Error::EntryNotFound(_) => 7,
        Error::EntryExists(_) => 8,
        Error::Locked => 9,
        Error::Io(_) => 10,
        Error::Clipboard(_) => 11,
        Error::Network(_) => 12,
        Error::Totp => 13,
        Error::TooShort(_) => 14,
        Error::Crypto => 15,
        Error::Serialize(_) => 16,
    }
}
