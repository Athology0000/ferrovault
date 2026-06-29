//! The `PVLT` binary vault container. Little-endian. The header doubles as the
//! AES-GCM associated data (AAD), so tampering with any header byte breaks
//! authentication.
//!
//! Layout:
//!   magic "PVLT" (4) | version (1) | kdf_id (1) | m_cost u32 | t_cost u32 |
//!   p_cost u8 | salt_len u8 | salt (salt_len) | nonce (12) | ct_len u64 |
//!   ciphertext‖tag (ct_len)

use crate::crypto::KdfParams;
use crate::{Error, Result};

pub const MAGIC: &[u8; 4] = b"PVLT";
pub const VERSION: u8 = 1;
pub const KDF_ARGON2ID: u8 = 1;
const SALT_LEN: usize = 16;

#[derive(Debug)]
pub struct Decoded {
    pub params: KdfParams,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
    pub aad: Vec<u8>,
}

/// Serialize just the header (everything before the ciphertext).
pub fn encode_header(p: &KdfParams, nonce: &[u8; 12], ct_len: u64) -> Vec<u8> {
    let mut h = Vec::with_capacity(36 + SALT_LEN);
    h.extend_from_slice(MAGIC);
    h.push(VERSION);
    h.push(KDF_ARGON2ID);
    h.extend_from_slice(&p.m_cost.to_le_bytes());
    h.extend_from_slice(&p.t_cost.to_le_bytes());
    h.push(p.p_cost);
    h.push(p.salt.len() as u8);
    h.extend_from_slice(&p.salt);
    h.extend_from_slice(nonce);
    h.extend_from_slice(&ct_len.to_le_bytes());
    h
}

/// Serialize the full file: header followed by the ciphertext.
pub fn encode(p: &KdfParams, nonce: &[u8; 12], ciphertext: &[u8]) -> Vec<u8> {
    let mut out = encode_header(p, nonce, ciphertext.len() as u64);
    out.extend_from_slice(ciphertext);
    out
}

/// Parse a vault file. Bounds-checked: malformed input returns `BadFormat`,
/// never panics.
pub fn decode(b: &[u8]) -> Result<Decoded> {
    // Smallest valid file (16-byte salt): 4+1+1+4+4+1+1+16+12+8 = 52 header bytes.
    if b.len() < 16 || &b[0..4] != MAGIC {
        return Err(Error::BadFormat("bad magic or too short"));
    }
    if b[4] != VERSION {
        return Err(Error::BadFormat("unsupported version"));
    }
    if b[5] != KDF_ARGON2ID {
        return Err(Error::BadFormat("unknown kdf id"));
    }
    let m_cost = u32::from_le_bytes(b[6..10].try_into().unwrap());
    let t_cost = u32::from_le_bytes(b[10..14].try_into().unwrap());
    let p_cost = b[14];
    let salt_len = b[15] as usize;
    if salt_len != SALT_LEN {
        return Err(Error::BadFormat("bad salt length"));
    }
    let salt_end = 16 + salt_len; // 32
    let nonce_end = salt_end + 12; // 44
    let ctlen_end = nonce_end + 8; // 52
    if b.len() < ctlen_end {
        return Err(Error::BadFormat("truncated header"));
    }
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&b[16..salt_end]);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&b[salt_end..nonce_end]);
    let ct_len = u64::from_le_bytes(b[nonce_end..ctlen_end].try_into().unwrap()) as usize;
    let ct_start = ctlen_end;
    let ct_end = ct_start
        .checked_add(ct_len)
        .ok_or(Error::BadFormat("ciphertext length overflow"))?;
    if b.len() < ct_end {
        return Err(Error::BadFormat("truncated ciphertext"));
    }
    Ok(Decoded {
        params: KdfParams { m_cost, t_cost, p_cost, salt },
        nonce,
        ciphertext: b[ct_start..ct_end].to_vec(),
        aad: b[0..ct_start].to_vec(),
    })
}
