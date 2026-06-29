//! Vault data model and CBOR (de)serialization.

use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zeroize::Zeroize;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Entry {
    pub username: String,
    pub password: String,
    pub url: Option<String>,
    pub notes: Option<String>,
    /// base32 TOTP secret, if any.
    pub totp: Option<String>,
    pub created: String,
    pub updated: String,
}

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct Vault {
    pub version: u32,
    /// BTreeMap → deterministic, sorted serialization.
    pub entries: BTreeMap<String, Entry>,
}

impl Drop for Vault {
    fn drop(&mut self) {
        for e in self.entries.values_mut() {
            e.password.zeroize();
        }
    }
}

pub fn to_cbor(v: &Vault) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(v, &mut buf).map_err(|_| Error::Crypto)?;
    Ok(buf)
}

pub fn from_cbor(b: &[u8]) -> Result<Vault> {
    ciborium::de::from_reader(b).map_err(|_| Error::BadFormat("invalid cbor payload"))
}
