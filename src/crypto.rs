//! Key derivation (Argon2id) and authenticated encryption (AES-256-GCM).

use crate::{Error, Result};
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use zeroize::Zeroizing;

/// Argon2id parameters plus the salt; stored in the vault header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KdfParams {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u8,
    pub salt: [u8; 16],
}

impl KdfParams {
    pub const DEFAULT_M: u32 = 65536; // 64 MiB
    pub const DEFAULT_T: u32 = 3;
    pub const DEFAULT_P: u32 = 4;

    /// Fresh default-strength parameters with a new random salt.
    pub fn generate_default() -> Self {
        let mut salt = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        KdfParams {
            m_cost: Self::DEFAULT_M,
            t_cost: Self::DEFAULT_T,
            p_cost: Self::DEFAULT_P as u8,
            salt,
        }
    }

    /// True if any cost is below the current defaults (triggers auto-upgrade).
    pub fn is_weaker_than_default(&self) -> bool {
        self.m_cost < Self::DEFAULT_M
            || self.t_cost < Self::DEFAULT_T
            || (self.p_cost as u32) < Self::DEFAULT_P
    }
}

/// Derive a 32-byte key from the master password. Returned key zeroizes on drop.
pub fn derive_key(password: &[u8], p: &KdfParams) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(p.m_cost, p.t_cost, p.p_cost as u32, Some(32))
        .map_err(|_| Error::Crypto)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(password, &p.salt, key.as_mut_slice())
        .map_err(|_| Error::Crypto)?;
    Ok(key)
}

/// Encrypt `plaintext`, authenticating `aad`. Returns ciphertext‖tag.
pub fn seal(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .encrypt(Nonce::from_slice(nonce), Payload { msg: plaintext, aad })
        .map_err(|_| Error::Crypto)
}

/// Decrypt and verify. Any failure (wrong key or tamper) is `WrongPasswordOrCorrupt`.
pub fn open(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let pt = cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ciphertext, aad })
        .map_err(|_| Error::WrongPasswordOrCorrupt)?;
    Ok(Zeroizing::new(pt))
}

/// A fresh random 12-byte nonce from the OS CSPRNG.
pub fn random_nonce() -> [u8; 12] {
    let mut n = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut n);
    n
}
