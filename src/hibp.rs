//! Have I Been Pwned range check using k-anonymity: only the first 5 hex
//! characters of the SHA-1 hash are sent; the suffix is matched locally.

use crate::{Error, Result};
use sha1::{Digest, Sha1};

pub trait RangeFetcher {
    fn fetch(&self, prefix: &str) -> Result<String>;
}

pub struct HttpFetcher;

impl RangeFetcher for HttpFetcher {
    fn fetch(&self, prefix: &str) -> Result<String> {
        let url = format!("https://api.pwnedpasswords.com/range/{prefix}");
        let resp = attohttpc::get(&url)
            .send()
            .map_err(|e| Error::Network(e.to_string()))?;
        if !resp.is_success() {
            return Err(Error::Network(format!("HTTP {}", resp.status())));
        }
        resp.text().map_err(|e| Error::Network(e.to_string()))
    }
}

fn sha1_hex_upper(password: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(password.as_bytes());
    let digest = hasher.finalize();
    let mut s = String::with_capacity(40);
    for b in digest {
        s.push_str(&format!("{b:02X}"));
    }
    s
}

/// Number of times the password appears in known breaches (0 = not found).
pub fn pwned_count(fetcher: &impl RangeFetcher, password: &str) -> Result<u64> {
    let hex = sha1_hex_upper(password);
    let (prefix, suffix) = hex.split_at(5);
    let body = fetcher.fetch(prefix)?;
    for line in body.lines() {
        let mut parts = line.trim().splitn(2, ':');
        let line_suffix = parts.next().unwrap_or("");
        let count = parts.next().unwrap_or("0");
        if line_suffix.eq_ignore_ascii_case(suffix) {
            return Ok(count.trim().parse().unwrap_or(0));
        }
    }
    Ok(0)
}
