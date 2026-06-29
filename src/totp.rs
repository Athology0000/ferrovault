//! TOTP (RFC 6238) over HMAC-SHA1, with base32-encoded secrets.

use crate::{Error, Result};
use hmac::{Hmac, Mac};
use sha1::Sha1;

type HmacSha1 = Hmac<Sha1>;

/// HOTP dynamic-truncation value (a 31-bit integer).
fn hotp_value(key: &[u8], counter: u64) -> u32 {
    let mut mac = HmacSha1::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = (digest[19] & 0x0f) as usize;
    ((u32::from(digest[offset] & 0x7f)) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3])
}

/// TOTP code for a raw key at a given unix time.
pub fn totp_code(key: &[u8], unix_seconds: u64, period: u64, digits: u32) -> String {
    let counter = unix_seconds / period;
    let value = hotp_value(key, counter) % 10u32.pow(digits);
    format!("{:0width$}", value, width = digits as usize)
}

/// Decode a base32 secret and produce the current 6-digit code (30s period)
/// plus the number of seconds it remains valid.
pub fn current_code(secret_b32: &str, unix_seconds: u64) -> Result<(String, u64)> {
    let cleaned: String = secret_b32.chars().filter(|c| !c.is_whitespace()).collect();
    let key = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, &cleaned.to_uppercase())
        .ok_or(Error::Totp)?;
    if key.is_empty() {
        return Err(Error::Totp);
    }
    let code = totp_code(&key, unix_seconds, 30, 6);
    let remaining = 30 - (unix_seconds % 30);
    Ok((code, remaining))
}
