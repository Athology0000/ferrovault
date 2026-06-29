# ferrovault Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `ferrovault`, an encrypted command-line password manager in Rust, from scratch (clean-room) — Argon2id + AES-256-GCM, a custom `PVLT` binary vault format, secret zeroization, cross-platform locking, plus clipboard auto-clear, KDF auto-upgrade, TOTP, and HIBP breach checking.

**Architecture:** A library crate (`src/lib.rs` + modules) holds all logic; a thin binary (`src/main.rs`) parses arguments and dispatches. The whole vault is encrypted as one unit: a custom binary header (which doubles as the AES-GCM AAD) followed by AES-256-GCM ciphertext whose plaintext is the CBOR-serialized entry map. Command handlers take already-obtained secrets as parameters so they are unit-testable without TTY prompts.

**Tech Stack:** Rust 2021, RustCrypto (`argon2`, `aes-gcm`, `hmac`, `sha1`), `ciborium` (CBOR), `clap` (derive), `rpassword`, `zeroize`, `fd-lock`, `arboard`, `attohttpc` (native-TLS, no `ring`/C), `base32`, `rand`, `thiserror`, `dirs`, `time`. Dev: `assert_cmd`, `predicates`, `tempfile`.

## Global Constraints

- **Edition:** Rust 2021. Pure-Rust dependencies only — **no C build dependencies** (must build cleanly on Windows/MSVC). HIBP uses `attohttpc` with OS-native TLS (not `ureq`/`ring`) to honor this.
- **Local build env (do not commit):** a git-ignored `.cargo/config.toml` injects the MSVC linker path + `vcvars` env so `cargo` works in this shell; it is machine-specific and intentionally untracked. Run `cargo` commands normally from the repo root.
- **Clean-room rule:** No source code, tests, rule tables, or fixtures copied from `CarterPerez-dev/Cybersecurity-Projects`. Re-derive from primary specs (Argon2, AES-GCM, RFC 6238, HIBP k-anonymity).
- **License:** MIT. Include `ATTRIBUTION.md` crediting the curriculum, stating nothing was copied.
- **KDF defaults:** Argon2id `m_cost = 65536` KiB, `t_cost = 3`, `p_cost = 4`, 16-byte salt.
- **Crypto invariants:** fresh random 12-byte nonce on **every** write; never accept the master password from a CLI flag or env var; decrypt failure and tamper both surface as the single `WrongPasswordOrCorrupt` error.
- **Secrets:** master password, derived key, and decrypted plaintext live in `Zeroizing` wrappers.
- **Vault paths in tests:** always use `tempfile::tempdir()` — never touch the user's real vault.
- **Commit cadence:** one commit per task (after its tests pass).

---

## Task 1: Project scaffold, dependencies, Error enum, CI

**Files:**
- Create: `Cargo.toml`, `src/lib.rs`, `src/main.rs`, `.github/workflows/ci.yml`, `rust-toolchain.toml`

**Interfaces:**
- Produces: the `ferrovault::Error` enum (used by every later task); a `ferrovault` library crate + a `ferrovault` binary.

- [ ] **Step 1: Create `Cargo.toml`**

```toml
[package]
name = "ferrovault"
version = "0.1.0"
edition = "2021"
description = "Encrypted command-line password manager"
license = "MIT"

[lib]
name = "ferrovault"
path = "src/lib.rs"

[[bin]]
name = "ferrovault"
path = "src/main.rs"

[dependencies]
argon2 = "0.5"
aes-gcm = "0.10"
ciborium = "0.2"
serde = { version = "1", features = ["derive"] }
clap = { version = "4", features = ["derive", "env"] }
rpassword = "7"
zeroize = "1"
fd-lock = "4"
arboard = "3"
attohttpc = { version = "0.28", default-features = false, features = ["tls-native"] }
hmac = "0.12"
sha1 = "0.10"
base32 = "0.5"
rand = "0.8"
thiserror = "1"
dirs = "5"
time = { version = "0.3", features = ["formatting", "std"] }

[dev-dependencies]
assert_cmd = "2"
predicates = "3"
tempfile = "3"
```

- [ ] **Step 2: Create `rust-toolchain.toml`**

```toml
[toolchain]
channel = "stable"
components = ["rustfmt", "clippy"]
```

- [ ] **Step 3: Create `src/lib.rs` with the Error enum**

```rust
//! ferrovault — encrypted command-line password manager (library core).

use std::path::PathBuf;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("no vault found at {0}")]
    VaultNotFound(PathBuf),
    #[error("a vault already exists at {0}")]
    VaultExists(PathBuf),
    #[error("wrong master password or corrupt vault")]
    WrongPasswordOrCorrupt,
    #[error("malformed vault file: {0}")]
    BadFormat(&'static str),
    #[error("no entry named '{0}'")]
    EntryNotFound(String),
    #[error("an entry named '{0}' already exists")]
    EntryExists(String),
    #[error("vault is locked by another process")]
    Locked,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("clipboard error: {0}")]
    Clipboard(String),
    #[error("network error: {0}")]
    Network(String),
    #[error("invalid TOTP secret")]
    Totp,
    #[error("password too short (minimum {0})")]
    TooShort(usize),
    #[error("cryptography error")]
    Crypto,
}

pub type Result<T> = std::result::Result<T, Error>;
```

- [ ] **Step 4: Create a placeholder `src/main.rs`**

```rust
fn main() {
    eprintln!("ferrovault: not yet wired up");
    std::process::exit(1);
}
```

- [ ] **Step 5: Create `.github/workflows/ci.yml`**

```yaml
name: CI
on: [push, pull_request]
jobs:
  build-test:
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest]
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: rustfmt, clippy
      - name: Format
        run: cargo fmt --all -- --check
      - name: Clippy
        run: cargo clippy --all-targets -- -D warnings
      - name: Test
        run: cargo test --all
```

- [ ] **Step 6: Verify it builds**

Run: `cargo build`
Expected: compiles with no errors (warnings about unused `Error` variants are fine for now).

- [ ] **Step 7: Commit**

```bash
git add Cargo.toml rust-toolchain.toml src/ .github/
git commit -m "chore: scaffold ferrovault crate, deps, error enum, CI"
```

---

## Task 2: Crypto core — Argon2id KDF + AES-256-GCM seal/open

**Files:**
- Create: `src/crypto.rs`, `tests/crypto.rs`
- Modify: `src/lib.rs` (add `pub mod crypto;`)

**Interfaces:**
- Produces:
  - `pub struct KdfParams { pub m_cost: u32, pub t_cost: u32, pub p_cost: u8, pub salt: [u8; 16] }`
  - `impl KdfParams` consts `DEFAULT_M: u32 = 65536`, `DEFAULT_T: u32 = 3`, `DEFAULT_P: u32 = 4`; `KdfParams::generate_default() -> KdfParams` (random salt); `KdfParams::is_weaker_than_default(&self) -> bool`
  - `pub fn derive_key(password: &[u8], p: &KdfParams) -> Result<Zeroizing<[u8; 32]>>`
  - `pub fn seal(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>>` (returns ciphertext‖tag)
  - `pub fn open(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>>`
  - `pub fn random_nonce() -> [u8; 12]`

- [ ] **Step 1: Add module to `src/lib.rs`**

Add near the top (after the imports): `pub mod crypto;`

- [ ] **Step 2: Write failing tests in `tests/crypto.rs`**

```rust
use ferrovault::crypto::{self, KdfParams};
use ferrovault::Error;

fn test_params() -> KdfParams {
    // small cost for fast tests
    KdfParams { m_cost: 8, t_cost: 1, p_cost: 1, salt: [7u8; 16] }
}

#[test]
fn round_trip() {
    let p = test_params();
    let key = crypto::derive_key(b"correct horse", &p).unwrap();
    let nonce = crypto::random_nonce();
    let aad = b"header-bytes";
    let ct = crypto::seal(&key, &nonce, aad, b"secret data").unwrap();
    let pt = crypto::open(&key, &nonce, aad, &ct).unwrap();
    assert_eq!(&pt[..], b"secret data");
}

#[test]
fn wrong_password_fails() {
    let p = test_params();
    let nonce = crypto::random_nonce();
    let aad = b"h";
    let key = crypto::derive_key(b"right", &p).unwrap();
    let ct = crypto::seal(&key, &nonce, aad, b"x").unwrap();
    let wrong = crypto::derive_key(b"wrong", &p).unwrap();
    let err = crypto::open(&wrong, &nonce, aad, &ct).unwrap_err();
    assert!(matches!(err, Error::WrongPasswordOrCorrupt));
}

#[test]
fn tamper_fails_identically() {
    let p = test_params();
    let key = crypto::derive_key(b"k", &p).unwrap();
    let nonce = crypto::random_nonce();
    let aad = b"h";
    let mut ct = crypto::seal(&key, &nonce, aad, b"hello world").unwrap();
    ct[0] ^= 0x01; // flip a bit
    let err = crypto::open(&key, &nonce, aad, &ct).unwrap_err();
    assert!(matches!(err, Error::WrongPasswordOrCorrupt));
}

#[test]
fn aad_mismatch_fails() {
    let p = test_params();
    let key = crypto::derive_key(b"k", &p).unwrap();
    let nonce = crypto::random_nonce();
    let ct = crypto::seal(&key, &nonce, b"aad-A", b"data").unwrap();
    let err = crypto::open(&key, &nonce, b"aad-B", &ct).unwrap_err();
    assert!(matches!(err, Error::WrongPasswordOrCorrupt));
}

#[test]
fn is_weaker_than_default() {
    let weak = KdfParams { m_cost: 1024, t_cost: 1, p_cost: 1, salt: [0; 16] };
    assert!(weak.is_weaker_than_default());
    let strong = KdfParams::generate_default();
    assert!(!strong.is_weaker_than_default());
}
```

- [ ] **Step 3: Run tests to confirm they fail**

Run: `cargo test --test crypto`
Expected: FAIL (module/functions not found).

- [ ] **Step 4: Implement `src/crypto.rs`**

```rust
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
```

- [ ] **Step 5: Run tests to confirm they pass**

Run: `cargo test --test crypto`
Expected: all 5 tests PASS.

- [ ] **Step 6: Commit**

```bash
git add src/lib.rs src/crypto.rs tests/crypto.rs
git commit -m "feat: argon2id KDF + aes-256-gcm seal/open with AAD"
```

---

## Task 3: Binary vault container (`PVLT` format)

**Files:**
- Create: `src/format.rs`, `tests/format.rs`
- Modify: `src/lib.rs` (add `pub mod format;`)

**Interfaces:**
- Consumes: `crypto::KdfParams`
- Produces:
  - `pub struct Decoded { pub params: KdfParams, pub nonce: [u8; 12], pub ciphertext: Vec<u8>, pub aad: Vec<u8> }`
  - `pub fn encode_header(p: &KdfParams, nonce: &[u8; 12], ct_len: u64) -> Vec<u8>`
  - `pub fn encode(p: &KdfParams, nonce: &[u8; 12], ciphertext: &[u8]) -> Vec<u8>`
  - `pub fn decode(bytes: &[u8]) -> Result<Decoded>`

- [ ] **Step 1: Add module to `src/lib.rs`**

Add: `pub mod format;`

- [ ] **Step 2: Write failing tests in `tests/format.rs`**

```rust
use ferrovault::crypto::KdfParams;
use ferrovault::format;
use ferrovault::Error;

fn params() -> KdfParams {
    KdfParams { m_cost: 65536, t_cost: 3, p_cost: 4, salt: [9u8; 16] }
}

#[test]
fn round_trip() {
    let p = params();
    let nonce = [1u8; 12];
    let ct = vec![0xAB; 40];
    let bytes = format::encode(&p, &nonce, &ct);
    let d = format::decode(&bytes).unwrap();
    assert_eq!(d.params, p);
    assert_eq!(d.nonce, nonce);
    assert_eq!(d.ciphertext, ct);
    // AAD is exactly the header (everything before the ciphertext)
    assert_eq!(d.aad, format::encode_header(&p, &nonce, ct.len() as u64));
    assert_eq!(&bytes[..d.aad.len()], &d.aad[..]);
}

#[test]
fn rejects_empty() {
    assert!(matches!(format::decode(&[]).unwrap_err(), Error::BadFormat(_)));
}

#[test]
fn rejects_bad_magic() {
    let mut b = format::encode(&params(), &[0u8; 12], &[1, 2, 3]);
    b[0] = b'X';
    assert!(matches!(format::decode(&b).unwrap_err(), Error::BadFormat(_)));
}

#[test]
fn rejects_truncated_without_panicking() {
    let full = format::encode(&params(), &[0u8; 12], &vec![5u8; 20]);
    for cut in 0..full.len() {
        // must return an error, never panic
        let _ = format::decode(&full[..cut]);
    }
}

#[test]
fn rejects_garbage() {
    let junk = [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
    assert!(format::decode(&junk).is_err());
}
```

- [ ] **Step 3: Run tests to confirm they fail**

Run: `cargo test --test format`
Expected: FAIL (module not found).

- [ ] **Step 4: Implement `src/format.rs`**

```rust
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
```

- [ ] **Step 5: Run tests to confirm they pass**

Run: `cargo test --test format`
Expected: all 5 tests PASS (note `rejects_truncated_without_panicking` exercises every cut length).

- [ ] **Step 6: Commit**

```bash
git add src/lib.rs src/format.rs tests/format.rs
git commit -m "feat: PVLT binary vault container with header-as-AAD"
```

---

## Task 4: Data model + CBOR serialization

**Files:**
- Create: `src/model.rs`, `tests/model.rs`
- Modify: `src/lib.rs` (add `pub mod model;`)

**Interfaces:**
- Produces:
  - `pub struct Entry { pub username: String, pub password: String, pub url: Option<String>, pub notes: Option<String>, pub totp: Option<String>, pub created: String, pub updated: String }`
  - `pub struct Vault { pub version: u32, pub entries: BTreeMap<String, Entry> }`
  - `pub fn to_cbor(v: &Vault) -> Result<Vec<u8>>`
  - `pub fn from_cbor(b: &[u8]) -> Result<Vault>`
  - `Vault` zeroizes entry passwords on drop.

- [ ] **Step 1: Add module to `src/lib.rs`**

Add: `pub mod model;`

- [ ] **Step 2: Write failing tests in `tests/model.rs`**

```rust
use ferrovault::model::{self, Entry, Vault};
use std::collections::BTreeMap;

fn sample() -> Vault {
    let mut entries = BTreeMap::new();
    entries.insert(
        "github".to_string(),
        Entry {
            username: "alice".into(),
            password: "hunter2".into(),
            url: Some("https://github.com".into()),
            notes: None,
            totp: None,
            created: "2026-06-28T00:00:00Z".into(),
            updated: "2026-06-28T00:00:00Z".into(),
        },
    );
    Vault { version: 1, entries }
}

#[test]
fn cbor_round_trip() {
    let v = sample();
    let bytes = model::to_cbor(&v).unwrap();
    let back = model::from_cbor(&bytes).unwrap();
    assert_eq!(back.version, 1);
    let e = back.entries.get("github").unwrap();
    assert_eq!(e.username, "alice");
    assert_eq!(e.password, "hunter2");
    assert_eq!(e.url.as_deref(), Some("https://github.com"));
    assert_eq!(e.notes, None);
}

#[test]
fn cbor_is_smaller_than_json_and_not_text() {
    let v = sample();
    let bytes = model::to_cbor(&v).unwrap();
    // CBOR is binary: the password should not appear as a contiguous ASCII run
    // surrounded by JSON quotes. Sanity check that we did not accidentally emit JSON.
    assert!(!bytes.starts_with(b"{"));
}

#[test]
fn from_cbor_rejects_garbage() {
    assert!(model::from_cbor(&[0xff, 0x00, 0x13, 0x37]).is_err());
}
```

- [ ] **Step 3: Run tests to confirm they fail**

Run: `cargo test --test model`
Expected: FAIL (module not found).

- [ ] **Step 4: Implement `src/model.rs`**

```rust
//! Vault data model and CBOR (de)serialization.

use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zeroize::Zeroize;

#[derive(Clone, Serialize, Deserialize)]
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

#[derive(Default, Serialize, Deserialize)]
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
```

- [ ] **Step 5: Run tests to confirm they pass**

Run: `cargo test --test model`
Expected: all 3 tests PASS.

- [ ] **Step 6: Commit**

```bash
git add src/lib.rs src/model.rs tests/model.rs
git commit -m "feat: vault data model with CBOR serialization + password zeroize"
```

---

## Task 5: Vault store — open/create/update, atomic write, locking

**Files:**
- Create: `src/vault.rs`, `tests/vault.rs`
- Modify: `src/lib.rs` (add `pub mod vault;`)

**Interfaces:**
- Consumes: `crypto`, `format`, `model::{Vault, Entry}`
- Produces:
  - `pub struct VaultStore { /* path */ }`
  - `VaultStore::new(path: PathBuf) -> VaultStore`
  - `VaultStore::path(&self) -> &Path`
  - `VaultStore::exists(&self) -> bool`
  - `VaultStore::create(&self, master: &[u8]) -> Result<()>`
  - `VaultStore::open(&self, master: &[u8]) -> Result<(Vault, KdfParams)>`
  - `VaultStore::update<F: FnOnce(&mut Vault) -> Result<()>>(&self, master: &[u8], f: F) -> Result<()>` (applies KDF auto-upgrade)
  - `VaultStore::rewrite(&self, master: &[u8], params: &KdfParams, vault: &Vault) -> Result<()>` (used by change-password — Task 8)

- [ ] **Step 1: Add module to `src/lib.rs`**

Add: `pub mod vault;`

- [ ] **Step 2: Write failing tests in `tests/vault.rs`**

```rust
use ferrovault::crypto::KdfParams;
use ferrovault::model::Entry;
use ferrovault::vault::VaultStore;
use ferrovault::Error;
use tempfile::tempdir;

fn entry() -> Entry {
    Entry {
        username: "alice".into(),
        password: "pw".into(),
        url: None,
        notes: None,
        totp: None,
        created: "t".into(),
        updated: "t".into(),
    }
}

#[test]
fn create_then_open() {
    let dir = tempdir().unwrap();
    let store = VaultStore::new(dir.path().join("vault.pvlt"));
    assert!(!store.exists());
    store.create(b"master").unwrap();
    assert!(store.exists());
    let (vault, _params) = store.open(b"master").unwrap();
    assert_eq!(vault.entries.len(), 0);
}

#[test]
fn create_twice_fails() {
    let dir = tempdir().unwrap();
    let store = VaultStore::new(dir.path().join("vault.pvlt"));
    store.create(b"master").unwrap();
    assert!(matches!(store.create(b"master").unwrap_err(), Error::VaultExists(_)));
}

#[test]
fn open_missing_fails() {
    let dir = tempdir().unwrap();
    let store = VaultStore::new(dir.path().join("nope.pvlt"));
    assert!(matches!(store.open(b"m").unwrap_err(), Error::VaultNotFound(_)));
}

#[test]
fn wrong_password_fails() {
    let dir = tempdir().unwrap();
    let store = VaultStore::new(dir.path().join("vault.pvlt"));
    store.create(b"right").unwrap();
    assert!(matches!(store.open(b"wrong").unwrap_err(), Error::WrongPasswordOrCorrupt));
}

#[test]
fn update_persists_entry() {
    let dir = tempdir().unwrap();
    let store = VaultStore::new(dir.path().join("vault.pvlt"));
    store.create(b"m").unwrap();
    store
        .update(b"m", |v| {
            v.entries.insert("github".into(), entry());
            Ok(())
        })
        .unwrap();
    let (vault, _) = store.open(b"m").unwrap();
    assert_eq!(vault.entries.get("github").unwrap().username, "alice");
}

#[test]
fn nonce_changes_each_write() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.pvlt");
    let store = VaultStore::new(path.clone());
    store.create(b"m").unwrap();
    let first = std::fs::read(&path).unwrap();
    store.update(b"m", |_v| Ok(())).unwrap();
    let second = std::fs::read(&path).unwrap();
    // Same plaintext, but a fresh nonce → different bytes.
    assert_ne!(first, second);
}

#[test]
fn rewrite_uses_given_params() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.pvlt");
    let store = VaultStore::new(path.clone());
    store.create(b"m").unwrap();
    let (vault, _) = store.open(b"m").unwrap();
    let weak = KdfParams { m_cost: 1024, t_cost: 1, p_cost: 1, salt: [3u8; 16] };
    store.rewrite(b"m", &weak, &vault).unwrap();
    let bytes = std::fs::read(&path).unwrap();
    let decoded = ferrovault::format::decode(&bytes).unwrap();
    assert_eq!(decoded.params, weak);
}
```

- [ ] **Step 3: Run tests to confirm they fail**

Run: `cargo test --test vault`
Expected: FAIL (module not found).

- [ ] **Step 4: Implement `src/vault.rs`**

```rust
//! On-disk vault store: locked, atomic, durable read-modify-write.

use crate::crypto::{self, KdfParams};
use crate::model::{self, Vault};
use crate::{format, Error, Result};
use rand::RngCore;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

pub struct VaultStore {
    path: PathBuf,
}

impl VaultStore {
    pub fn new(path: PathBuf) -> Self {
        VaultStore { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    fn lock_path(&self) -> PathBuf {
        let mut s = self.path.clone().into_os_string();
        s.push(".lock");
        PathBuf::from(s)
    }

    /// Run `f` while holding an exclusive advisory lock on the sidecar lock file.
    /// Cross-platform via `fd-lock` (works on Windows and POSIX).
    fn with_lock<T>(&self, f: impl FnOnce() -> Result<T>) -> Result<T> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(self.lock_path())?;
        let mut lock = fd_lock::RwLock::new(file);
        let _guard = lock.write().map_err(|_| Error::Locked)?;
        f()
    }

    pub fn create(&self, master: &[u8]) -> Result<()> {
        self.with_lock(|| {
            if self.path.exists() {
                return Err(Error::VaultExists(self.path.clone()));
            }
            let vault = Vault { version: 1, entries: Default::default() };
            let params = KdfParams::generate_default();
            self.write_locked(master, &params, &vault)
        })
    }

    pub fn open(&self, master: &[u8]) -> Result<(Vault, KdfParams)> {
        self.with_lock(|| self.read_locked(master))
    }

    /// Decrypt, apply `f`, then write back — re-deriving stronger KDF params if
    /// the stored ones are below current defaults.
    pub fn update<F: FnOnce(&mut Vault) -> Result<()>>(&self, master: &[u8], f: F) -> Result<()> {
        self.with_lock(|| {
            let (mut vault, params) = self.read_locked(master)?;
            f(&mut vault)?;
            let params = if params.is_weaker_than_default() {
                KdfParams::generate_default()
            } else {
                params
            };
            self.write_locked(master, &params, &vault)
        })
    }

    /// Re-encrypt the whole vault under explicit params (used by change-password).
    pub fn rewrite(&self, master: &[u8], params: &KdfParams, vault: &Vault) -> Result<()> {
        self.with_lock(|| self.write_locked(master, params, vault))
    }

    // --- internals (assume the lock is already held) ---

    fn read_locked(&self, master: &[u8]) -> Result<(Vault, KdfParams)> {
        let bytes = match std::fs::read(&self.path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(Error::VaultNotFound(self.path.clone()))
            }
            Err(e) => return Err(e.into()),
        };
        let d = format::decode(&bytes)?;
        let key = crypto::derive_key(master, &d.params)?;
        let pt = crypto::open(&key, &d.nonce, &d.aad, &d.ciphertext)?;
        let vault = model::from_cbor(&pt)?;
        Ok((vault, d.params))
    }

    fn write_locked(&self, master: &[u8], params: &KdfParams, vault: &Vault) -> Result<()> {
        let key = crypto::derive_key(master, params)?;
        let pt = Zeroizing::new(model::to_cbor(vault)?);
        let mut nonce = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let ct_len = (pt.len() + 16) as u64;
        let aad = format::encode_header(params, &nonce, ct_len);
        let ct = crypto::seal(&key, &nonce, &aad, &pt)?;
        let bytes = format::encode(params, &nonce, &ct);
        atomic_write(&self.path, &bytes)
    }
}

/// tmp file (0600 on Unix) → fsync → atomic rename → dir fsync (POSIX).
fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
    let file_name = path.file_name().ok_or(Error::BadFormat("no file name"))?;
    let tmp = parent.join(format!(".{}.tmp", file_name.to_string_lossy()));
    {
        let mut opts = OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    #[cfg(unix)]
    {
        if let Ok(dir) = File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}
```

- [ ] **Step 5: Run tests to confirm they pass**

Run: `cargo test --test vault`
Expected: all 7 tests PASS.

- [ ] **Step 6: Commit**

```bash
git add src/lib.rs src/vault.rs tests/vault.rs
git commit -m "feat: locked atomic vault store (create/open/update/rewrite)"
```

---

## Task 6: CLI wiring — init/add/get/list/delete

**Files:**
- Create: `src/cli.rs`, `src/commands.rs`
- Modify: `src/lib.rs` (add `pub mod cli; pub mod commands;`), `src/main.rs` (full rewrite), `tests/cli.rs` (create)

**Interfaces:**
- Consumes: `vault::VaultStore`, `model::Entry`
- Produces (in `commands.rs`, all unit-testable without prompts):
  - `pub fn cmd_init(store: &VaultStore, master: &[u8]) -> Result<()>`
  - `pub fn cmd_add(store: &VaultStore, master: &[u8], name: &str, entry: Entry) -> Result<()>`
  - `pub fn cmd_get(store: &VaultStore, master: &[u8], name: &str) -> Result<Entry>`
  - `pub fn cmd_list(store: &VaultStore, master: &[u8]) -> Result<Vec<String>>`
  - `pub fn cmd_delete(store: &VaultStore, master: &[u8], name: &str) -> Result<()>`
  - `pub fn now_rfc3339() -> String`
  - `pub fn default_vault_path() -> PathBuf`
  - `pub fn exit_code(err: &Error) -> i32`

- [ ] **Step 1: Add modules to `src/lib.rs`**

Add: `pub mod cli;` and `pub mod commands;`

- [ ] **Step 2: Write failing tests in `tests/cli.rs`**

```rust
use ferrovault::commands::{self, exit_code};
use ferrovault::model::Entry;
use ferrovault::vault::VaultStore;
use ferrovault::Error;
use tempfile::tempdir;

fn entry(pw: &str) -> Entry {
    Entry {
        username: "alice".into(),
        password: pw.into(),
        url: None,
        notes: None,
        totp: None,
        created: commands::now_rfc3339(),
        updated: commands::now_rfc3339(),
    }
}

#[test]
fn init_add_get_list_delete() {
    let dir = tempdir().unwrap();
    let store = VaultStore::new(dir.path().join("v.pvlt"));
    commands::cmd_init(&store, b"m").unwrap();

    commands::cmd_add(&store, b"m", "github", entry("s3cr3t")).unwrap();
    let got = commands::cmd_get(&store, b"m", "github").unwrap();
    assert_eq!(got.password, "s3cr3t");

    assert_eq!(commands::cmd_list(&store, b"m").unwrap(), vec!["github".to_string()]);

    commands::cmd_delete(&store, b"m", "github").unwrap();
    assert!(matches!(commands::cmd_get(&store, b"m", "github").unwrap_err(), Error::EntryNotFound(_)));
}

#[test]
fn add_duplicate_fails() {
    let dir = tempdir().unwrap();
    let store = VaultStore::new(dir.path().join("v.pvlt"));
    commands::cmd_init(&store, b"m").unwrap();
    commands::cmd_add(&store, b"m", "x", entry("a")).unwrap();
    assert!(matches!(commands::cmd_add(&store, b"m", "x", entry("b")).unwrap_err(), Error::EntryExists(_)));
}

#[test]
fn delete_missing_fails() {
    let dir = tempdir().unwrap();
    let store = VaultStore::new(dir.path().join("v.pvlt"));
    commands::cmd_init(&store, b"m").unwrap();
    assert!(matches!(commands::cmd_delete(&store, b"m", "nope").unwrap_err(), Error::EntryNotFound(_)));
}

#[test]
fn exit_codes_are_stable() {
    assert_eq!(exit_code(&Error::VaultNotFound("x".into())), 3);
    assert_eq!(exit_code(&Error::WrongPasswordOrCorrupt), 5);
    assert_eq!(exit_code(&Error::EntryNotFound("x".into())), 7);
}
```

- [ ] **Step 3: Run tests to confirm they fail**

Run: `cargo test --test cli`
Expected: FAIL (modules not found).

- [ ] **Step 4: Implement `src/commands.rs`**

```rust
//! Command handlers. These take already-obtained secrets so they are testable
//! without TTY prompts; `main.rs` does the prompting and rendering.

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
    }
}
```

- [ ] **Step 5: Implement `src/cli.rs`**

```rust
//! Command-line interface definition (clap derive).

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "ferrovault", about = "Encrypted command-line password manager")]
pub struct Cli {
    /// Path to the vault file (overrides $PV_VAULT and the default).
    #[arg(long, global = true, env = "PV_VAULT")]
    pub vault: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Create a new empty vault.
    Init,
    /// Add a new entry.
    Add {
        name: String,
        /// Generate a random password instead of prompting.
        #[arg(short, long)]
        generate: bool,
        /// Attach a base32 TOTP secret.
        #[arg(long)]
        totp: Option<String>,
    },
    /// Show one entry. `--copy` copies the password to the clipboard.
    Get {
        name: String,
        #[arg(long)]
        copy: bool,
        #[arg(long, default_value_t = 15)]
        timeout: u64,
    },
    /// List entry names.
    List,
    /// Delete an entry.
    Delete { name: String },
    /// Generate a strong password (no vault needed).
    Gen {
        #[arg(default_value_t = 20)]
        length: usize,
        #[arg(long)]
        no_symbols: bool,
    },
    /// Rotate the master password.
    ChangePassword,
    /// Print the current TOTP code for an entry.
    Totp { name: String },
    /// Check a password against Have I Been Pwned (k-anonymity).
    Check { name: Option<String> },
}
```

- [ ] **Step 6: Rewrite `src/main.rs`**

```rust
//! Thin binary: parse args, prompt for secrets, dispatch, render, map errors.

use clap::Parser;
use ferrovault::cli::{Cli, Command};
use ferrovault::commands::{self, default_vault_path, exit_code};
use ferrovault::model::Entry;
use ferrovault::vault::VaultStore;
use ferrovault::{Error, Result};
use zeroize::Zeroizing;

fn prompt_master() -> Result<Zeroizing<String>> {
    Ok(Zeroizing::new(
        rpassword::prompt_password("Master password: ").map_err(Error::Io)?,
    ))
}

fn prompt_new_master() -> Result<Zeroizing<String>> {
    let a = Zeroizing::new(rpassword::prompt_password("New master password: ").map_err(Error::Io)?);
    let b = Zeroizing::new(rpassword::prompt_password("Confirm master password: ").map_err(Error::Io)?);
    if a.as_str() != b.as_str() {
        eprintln!("Passwords do not match.");
        std::process::exit(2);
    }
    Ok(a)
}

fn read_line(prompt: &str) -> String {
    use std::io::Write;
    eprint!("{prompt}");
    let _ = std::io::stderr().flush();
    let mut s = String::new();
    let _ = std::io::stdin().read_line(&mut s);
    s.trim().to_string()
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let path = cli.vault.clone().unwrap_or_else(default_vault_path);
    let store = VaultStore::new(path);

    match cli.command {
        Command::Init => {
            let master = prompt_new_master()?;
            commands::cmd_init(&store, master.as_bytes())?;
            eprintln!("Vault created at {}", store.path().display());
        }
        Command::Add { name, generate, totp } => {
            let master = prompt_master()?;
            let username = read_line(&format!("Username for {name}: "));
            let password = if generate {
                ferrovault::generator::generate(&ferrovault::generator::GenOptions {
                    length: 20,
                    symbols: true,
                })?
            } else {
                Zeroizing::new(rpassword::prompt_password(format!("Password for {name} (hidden): "))
                    .map_err(Error::Io)?)
            };
            let url = read_line("URL (optional): ");
            let notes = read_line("Notes (optional): ");
            let now = commands::now_rfc3339();
            let entry = Entry {
                username,
                password: password.to_string(),
                url: if url.is_empty() { None } else { Some(url) },
                notes: if notes.is_empty() { None } else { Some(notes) },
                totp,
                created: now.clone(),
                updated: now,
            };
            commands::cmd_add(&store, master.as_bytes(), &name, entry)?;
            eprintln!("Added entry: {name}");
        }
        Command::Get { name, copy, timeout } => {
            let master = prompt_master()?;
            let entry = commands::cmd_get(&store, master.as_bytes(), &name)?;
            if copy {
                ferrovault::clipboard::copy_with_clear(&entry.password, timeout)?;
                eprintln!("Password copied; clipboard clears in {timeout}s.");
            } else {
                println!("username  {}", entry.username);
                println!("password  {}", entry.password);
                if let Some(u) = &entry.url { println!("url       {u}"); }
                if let Some(n) = &entry.notes { println!("notes     {n}"); }
            }
        }
        Command::List => {
            let master = prompt_master()?;
            for name in commands::cmd_list(&store, master.as_bytes())? {
                println!("{name}");
            }
        }
        Command::Delete { name } => {
            let master = prompt_master()?;
            commands::cmd_delete(&store, master.as_bytes(), &name)?;
            eprintln!("Deleted entry: {name}");
        }
        Command::Gen { length, no_symbols } => {
            let pw = ferrovault::generator::generate(&ferrovault::generator::GenOptions {
                length,
                symbols: !no_symbols,
            })?;
            println!("{}", pw.as_str());
        }
        Command::ChangePassword => {
            let old = prompt_master()?;
            let new = prompt_new_master()?;
            ferrovault::commands::cmd_change_password(&store, old.as_bytes(), new.as_bytes())?;
            eprintln!("Master password changed.");
        }
        Command::Totp { name } => {
            let master = prompt_master()?;
            let (code, remaining) = ferrovault::commands::cmd_totp(&store, master.as_bytes(), &name)?;
            println!("{code}");
            eprintln!("(valid for {remaining}s)");
        }
        Command::Check { name } => {
            let password = match name {
                Some(n) => {
                    let master = prompt_master()?;
                    commands::cmd_get(&store, master.as_bytes(), &n)?.password
                }
                None => rpassword::prompt_password("Password to check: ").map_err(Error::Io)?,
            };
            let count = ferrovault::commands::cmd_check(&password)?;
            if count > 0 {
                eprintln!("WARNING: found in {count} known breaches.");
            } else {
                eprintln!("Not found in any known breach.");
            }
        }
    }
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(exit_code(&e));
    }
}
```

> Note: `main.rs` references `generator`, `clipboard`, `cmd_change_password`, `cmd_totp`, and `cmd_check`, which are added in Tasks 7–11. Until those tasks land, comment out the `Add --generate`, `Get --copy`, `Gen`, `ChangePassword`, `Totp`, and `Check` arms (or stub them to `unimplemented!()`), then restore them as each task completes. The library tests for this task do not depend on `main.rs`.

- [ ] **Step 7: Run the handler tests**

Run: `cargo test --test cli`
Expected: all 4 tests PASS.

- [ ] **Step 8: Commit**

```bash
git add src/lib.rs src/cli.rs src/commands.rs src/main.rs tests/cli.rs
git commit -m "feat: CLI + handlers for init/add/get/list/delete"
```

---

## Task 7: Password generator + `gen` command

**Files:**
- Create: `src/generator.rs`, `tests/generator.rs`
- Modify: `src/lib.rs` (add `pub mod generator;`), `src/main.rs` (un-stub the `Gen` and `Add --generate` arms)

**Interfaces:**
- Produces:
  - `pub struct GenOptions { pub length: usize, pub symbols: bool }`
  - `pub fn generate(opts: &GenOptions) -> Result<Zeroizing<String>>`

- [ ] **Step 1: Add module to `src/lib.rs`**

Add: `pub mod generator;`

- [ ] **Step 2: Write failing tests in `tests/generator.rs`**

```rust
use ferrovault::generator::{generate, GenOptions};
use ferrovault::Error;

#[test]
fn honors_length() {
    let pw = generate(&GenOptions { length: 32, symbols: true }).unwrap();
    assert_eq!(pw.chars().count(), 32);
}

#[test]
fn too_short_errors() {
    assert!(matches!(generate(&GenOptions { length: 3, symbols: true }).unwrap_err(), Error::TooShort(_)));
}

#[test]
fn includes_each_required_class() {
    // Over several samples, every required class must appear in each password.
    for _ in 0..50 {
        let pw = generate(&GenOptions { length: 12, symbols: true }).unwrap();
        assert!(pw.chars().any(|c| c.is_ascii_lowercase()));
        assert!(pw.chars().any(|c| c.is_ascii_uppercase()));
        assert!(pw.chars().any(|c| c.is_ascii_digit()));
        assert!(pw.chars().any(|c| !c.is_ascii_alphanumeric()));
    }
}

#[test]
fn no_symbols_excludes_symbols() {
    for _ in 0..50 {
        let pw = generate(&GenOptions { length: 16, symbols: false }).unwrap();
        assert!(pw.chars().all(|c| c.is_ascii_alphanumeric()));
    }
}
```

- [ ] **Step 3: Run tests to confirm they fail**

Run: `cargo test --test generator`
Expected: FAIL (module not found).

- [ ] **Step 4: Implement `src/generator.rs`**

```rust
//! Cryptographically secure password generation (OS CSPRNG, unbiased).

use crate::{Error, Result};
use rand::seq::SliceRandom;
use rand::Rng;
use zeroize::Zeroizing;

const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{};:,.?";

pub struct GenOptions {
    pub length: usize,
    pub symbols: bool,
}

pub fn generate(opts: &GenOptions) -> Result<Zeroizing<String>> {
    let mut classes: Vec<&[u8]> = vec![LOWER, UPPER, DIGITS];
    if opts.symbols {
        classes.push(SYMBOLS);
    }
    if opts.length < classes.len() {
        return Err(Error::TooShort(classes.len()));
    }
    let pool: Vec<u8> = classes.concat();
    let mut rng = rand::rngs::OsRng;

    let mut out: Vec<u8> = Vec::with_capacity(opts.length);
    // Guarantee at least one character from each required class.
    for class in &classes {
        out.push(class[rng.gen_range(0..class.len())]);
    }
    // Fill the remainder from the full pool.
    while out.len() < opts.length {
        out.push(pool[rng.gen_range(0..pool.len())]);
    }
    // Shuffle so the guaranteed characters are not always at the front.
    out.shuffle(&mut rng);

    // All bytes are ASCII by construction.
    Ok(Zeroizing::new(String::from_utf8(out).expect("ascii only")))
}
```

- [ ] **Step 5: Run tests to confirm they pass**

Run: `cargo test --test generator`
Expected: all 4 tests PASS.

- [ ] **Step 6: Restore the `Gen` and `Add --generate` arms in `src/main.rs`**

Un-comment / un-stub them (the code is already written in Task 6 Step 6). Then:

Run: `cargo build`
Expected: compiles.

- [ ] **Step 7: Commit**

```bash
git add src/lib.rs src/generator.rs tests/generator.rs src/main.rs
git commit -m "feat: unbiased password generator + gen command"
```

---

## Task 8: Change master password + KDF auto-upgrade

**Files:**
- Modify: `src/commands.rs` (add `cmd_change_password`), `src/main.rs` (un-stub `ChangePassword`)
- Test: `tests/change_password.rs` (create)

**Interfaces:**
- Consumes: `vault::VaultStore`, `crypto::KdfParams`
- Produces: `pub fn cmd_change_password(store: &VaultStore, old: &[u8], new: &[u8]) -> Result<()>`

- [ ] **Step 1: Write failing tests in `tests/change_password.rs`**

```rust
use ferrovault::commands;
use ferrovault::crypto::KdfParams;
use ferrovault::model::Entry;
use ferrovault::vault::VaultStore;
use ferrovault::Error;
use tempfile::tempdir;

fn entry() -> Entry {
    Entry {
        username: "a".into(), password: "p".into(), url: None, notes: None,
        totp: None, created: "t".into(), updated: "t".into(),
    }
}

#[test]
fn rotates_master_password() {
    let dir = tempdir().unwrap();
    let store = VaultStore::new(dir.path().join("v.pvlt"));
    commands::cmd_init(&store, b"old").unwrap();
    commands::cmd_add(&store, b"old", "x", entry()).unwrap();

    commands::cmd_change_password(&store, b"old", b"new").unwrap();

    assert!(matches!(store.open(b"old").unwrap_err(), Error::WrongPasswordOrCorrupt));
    let (vault, _) = store.open(b"new").unwrap();
    assert!(vault.entries.contains_key("x"));
}

#[test]
fn wrong_old_password_fails() {
    let dir = tempdir().unwrap();
    let store = VaultStore::new(dir.path().join("v.pvlt"));
    commands::cmd_init(&store, b"old").unwrap();
    assert!(matches!(commands::cmd_change_password(&store, b"WRONG", b"new").unwrap_err(), Error::WrongPasswordOrCorrupt));
}

#[test]
fn update_upgrades_weak_kdf_params() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("v.pvlt");
    let store = VaultStore::new(path.clone());
    commands::cmd_init(&store, b"m").unwrap();

    // Force the vault onto deliberately weak params.
    let (vault, _) = store.open(b"m").unwrap();
    let weak = KdfParams { m_cost: 1024, t_cost: 1, p_cost: 1, salt: [1u8; 16] };
    store.rewrite(b"m", &weak, &vault).unwrap();

    // Any update should transparently upgrade to default strength.
    store.update(b"m", |v| { v.entries.insert("x".into(), entry()); Ok(()) }).unwrap();

    let decoded = ferrovault::format::decode(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(decoded.params.m_cost, KdfParams::DEFAULT_M);
    assert_eq!(decoded.params.t_cost, KdfParams::DEFAULT_T);
}
```

- [ ] **Step 2: Run tests to confirm they fail**

Run: `cargo test --test change_password`
Expected: FAIL (`cmd_change_password` not found).

- [ ] **Step 3: Add `cmd_change_password` to `src/commands.rs`**

```rust
use crate::crypto::KdfParams;

/// Re-encrypt the entire vault under a fresh salt + current default KDF params.
pub fn cmd_change_password(store: &VaultStore, old: &[u8], new: &[u8]) -> Result<()> {
    let (vault, _params) = store.open(old)?; // verifies the old password
    let params = KdfParams::generate_default();
    store.rewrite(new, &params, &vault)
}
```

- [ ] **Step 4: Run tests to confirm they pass**

Run: `cargo test --test change_password`
Expected: all 3 tests PASS.

- [ ] **Step 5: Restore the `ChangePassword` arm in `src/main.rs`, then build**

Run: `cargo build`
Expected: compiles.

- [ ] **Step 6: Commit**

```bash
git add src/commands.rs src/main.rs tests/change_password.rs
git commit -m "feat: change-password + transparent KDF param auto-upgrade"
```

---

## Task 9: TOTP (RFC 6238)

**Files:**
- Create: `src/totp.rs`, `tests/totp.rs`
- Modify: `src/lib.rs` (add `pub mod totp;`), `src/commands.rs` (add `cmd_totp`), `src/main.rs` (un-stub `Totp`)

**Interfaces:**
- Produces:
  - `pub fn totp_code(key: &[u8], unix_seconds: u64, period: u64, digits: u32) -> String`
  - `pub fn current_code(secret_b32: &str, unix_seconds: u64) -> Result<(String, u64)>`
  - In `commands.rs`: `pub fn cmd_totp(store: &VaultStore, master: &[u8], name: &str) -> Result<(String, u64)>`

- [ ] **Step 1: Add module to `src/lib.rs`**

Add: `pub mod totp;`

- [ ] **Step 2: Write failing tests in `tests/totp.rs`**

```rust
use ferrovault::totp::{current_code, totp_code};

// RFC 6238 Appendix B test seed (SHA-1): ASCII "12345678901234567890".
// The RFC tabulates 8-digit codes; our 6-digit codes are those mod 10^6.
const SEED: &[u8] = b"12345678901234567890";

#[test]
fn rfc6238_vectors_6_digits() {
    assert_eq!(totp_code(SEED, 59, 30, 6), "287082");
    assert_eq!(totp_code(SEED, 1111111109, 30, 6), "081804");
    assert_eq!(totp_code(SEED, 1111111111, 30, 6), "050471");
    assert_eq!(totp_code(SEED, 1234567890, 30, 6), "005924");
    assert_eq!(totp_code(SEED, 2000000000, 30, 6), "279037");
}

#[test]
fn current_code_decodes_base32_and_reports_remaining() {
    // base32(RFC4648, no pad) of the seed.
    let b32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    let (code, remaining) = current_code(b32, 59).unwrap();
    assert_eq!(code, "287082");
    assert_eq!(remaining, 1); // 30 - (59 % 30)
}

#[test]
fn invalid_base32_errors() {
    assert!(current_code("not valid base32 !!!", 0).is_err());
}
```

- [ ] **Step 3: Run tests to confirm they fail**

Run: `cargo test --test totp`
Expected: FAIL (module not found).

- [ ] **Step 4: Implement `src/totp.rs`**

```rust
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
```

- [ ] **Step 5: Run tests to confirm they pass**

Run: `cargo test --test totp`
Expected: all 3 tests PASS.

- [ ] **Step 6: Add `cmd_totp` to `src/commands.rs`**

> `OffsetDateTime` is already imported at the top of `commands.rs` (Task 6); do not re-import it.

```rust
/// Current TOTP code for an entry that has a stored secret.
pub fn cmd_totp(store: &VaultStore, master: &[u8], name: &str) -> Result<(String, u64)> {
    let entry = cmd_get(store, master, name)?;
    let secret = entry.totp.ok_or(Error::Totp)?;
    let now = OffsetDateTime::now_utc().unix_timestamp().max(0) as u64;
    crate::totp::current_code(&secret, now)
}
```

- [ ] **Step 7: Restore the `Totp` arm in `src/main.rs`, then build & test all**

Run: `cargo build && cargo test --test totp`
Expected: compiles; tests PASS.

- [ ] **Step 8: Commit**

```bash
git add src/lib.rs src/totp.rs tests/totp.rs src/commands.rs src/main.rs
git commit -m "feat: RFC 6238 TOTP + totp command"
```

---

## Task 10: Clipboard copy with auto-clear

**Files:**
- Create: `src/clipboard.rs`
- Modify: `src/lib.rs` (add `pub mod clipboard;`), `src/main.rs` (un-stub `Get --copy`)

**Interfaces:**
- Produces: `pub fn copy_with_clear(secret: &str, timeout_secs: u64) -> Result<()>`

- [ ] **Step 1: Add module to `src/lib.rs`**

Add: `pub mod clipboard;`

- [ ] **Step 2: Implement `src/clipboard.rs`**

> Clipboard access is environment-dependent (needs a desktop session) and cannot be reliably unit-tested in CI, so this module is verified manually (Step 4). Keep the logic minimal.

```rust
//! Copy a secret to the clipboard, then wipe it after a timeout.

use crate::{Error, Result};
use std::time::Duration;

pub fn copy_with_clear(secret: &str, timeout_secs: u64) -> Result<()> {
    let mut cb = arboard::Clipboard::new().map_err(|e| Error::Clipboard(e.to_string()))?;
    cb.set_text(secret.to_string())
        .map_err(|e| Error::Clipboard(e.to_string()))?;
    if timeout_secs > 0 {
        std::thread::sleep(Duration::from_secs(timeout_secs));
        // Best-effort wipe; ignore failure (clipboard may have changed).
        let _ = cb.set_text(String::new());
    }
    Ok(())
}
```

- [ ] **Step 3: Restore the `Get --copy` arm in `src/main.rs`, then build**

Run: `cargo build`
Expected: compiles.

- [ ] **Step 4: Manual verification**

```bash
cargo run -- --vault ./demo.pvlt init        # set a master password
cargo run -- --vault ./demo.pvlt add demo    # add an entry with a password
cargo run -- --vault ./demo.pvlt get demo --copy --timeout 3
# paste somewhere within 3s -> value present; paste after 3s -> cleared
rm demo.pvlt demo.pvlt.lock
```

Expected: clipboard holds the password, then is empty after the timeout.

- [ ] **Step 5: Commit**

```bash
git add src/lib.rs src/clipboard.rs src/main.rs
git commit -m "feat: clipboard copy with timed auto-clear"
```

---

## Task 11: HIBP breach check (k-anonymity)

**Files:**
- Create: `src/hibp.rs`, `tests/hibp.rs`
- Modify: `src/lib.rs` (add `pub mod hibp;`), `src/commands.rs` (add `cmd_check`), `src/main.rs` (un-stub `Check`)

**Interfaces:**
- Produces:
  - `pub trait RangeFetcher { fn fetch(&self, prefix: &str) -> Result<String>; }`
  - `pub struct HttpFetcher;` implementing `RangeFetcher`
  - `pub fn pwned_count(fetcher: &impl RangeFetcher, password: &str) -> Result<u64>`
  - In `commands.rs`: `pub fn cmd_check(password: &str) -> Result<u64>`

- [ ] **Step 1: Add module to `src/lib.rs`**

Add: `pub mod hibp;`

- [ ] **Step 2: Write failing tests in `tests/hibp.rs`**

```rust
use ferrovault::hibp::{pwned_count, RangeFetcher};
use ferrovault::Result;
use std::cell::RefCell;

// Records the prefix it was asked for and returns a canned range body.
struct FakeFetcher {
    body: String,
    seen_prefix: RefCell<String>,
}

impl RangeFetcher for FakeFetcher {
    fn fetch(&self, prefix: &str) -> Result<String> {
        *self.seen_prefix.borrow_mut() = prefix.to_string();
        Ok(self.body.clone())
    }
}

#[test]
fn finds_pwned_password_and_sends_only_prefix() {
    // SHA1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
    // prefix = 5BAA6 ; suffix = 1E4C9B93F3F0682250B6CF8331B7EE68FD8
    let fake = FakeFetcher {
        body: "1E4C9B93F3F0682250B6CF8331B7EE68FD8:99\r\n0018A45C4D1DEF81644B54AB7F969B88D65:1".into(),
        seen_prefix: RefCell::new(String::new()),
    };
    let count = pwned_count(&fake, "password").unwrap();
    assert_eq!(count, 99);
    assert_eq!(*fake.seen_prefix.borrow(), "5BAA6"); // only 5 hex chars leave
}

#[test]
fn clean_password_returns_zero() {
    let fake = FakeFetcher {
        body: "0018A45C4D1DEF81644B54AB7F969B88D65:1".into(),
        seen_prefix: RefCell::new(String::new()),
    };
    assert_eq!(pwned_count(&fake, "password").unwrap(), 0);
}
```

- [ ] **Step 3: Run tests to confirm they fail**

Run: `cargo test --test hibp`
Expected: FAIL (module not found).

- [ ] **Step 4: Implement `src/hibp.rs`**

```rust
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
```

- [ ] **Step 5: Run tests to confirm they pass**

Run: `cargo test --test hibp`
Expected: both tests PASS.

- [ ] **Step 6: Add `cmd_check` to `src/commands.rs`**

```rust
use crate::hibp::{pwned_count, HttpFetcher};

/// Online breach check for a password (k-anonymity). Network failure surfaces
/// as `Error::Network`; the caller decides whether to treat it as fatal.
pub fn cmd_check(password: &str) -> Result<u64> {
    pwned_count(&HttpFetcher, password)
}
```

- [ ] **Step 7: Restore the `Check` arm in `src/main.rs`, then build & test all**

Run: `cargo build && cargo test`
Expected: compiles; the full suite PASSES.

- [ ] **Step 8: Commit**

```bash
git add src/lib.rs src/hibp.rs tests/hibp.rs src/commands.rs src/main.rs
git commit -m "feat: HIBP k-anonymity breach check + check command"
```

---

## Task 12: Docs, license, attribution, threat model, polish

**Files:**
- Create: `README.md`, `LICENSE`, `ATTRIBUTION.md`, `docs/threat-model.md`

**Interfaces:** none (documentation + final quality gate).

- [ ] **Step 1: Create `LICENSE` (MIT)**

Use the standard MIT License text with the year `2026` and your name as the copyright holder.

- [ ] **Step 2: Create `ATTRIBUTION.md`**

```markdown
# Attribution

`ferrovault` is an independent, from-scratch implementation written for my own
learning and portfolio. The problem and feature scope were inspired by the
`foundations/password-manager` project in
[`CarterPerez-dev/Cybersecurity-Projects`](https://github.com/CarterPerez-dev/Cybersecurity-Projects)
(AGPL-3.0).

**No source code, tests, or data files were copied** from that repository. The
design, code, and tests here are my own, and this project is released under the
MIT License. Where the original drew on public standards, I implemented against
those primary specifications directly:

- Argon2id — RFC 9106
- AES-GCM — NIST SP 800-38D
- TOTP — RFC 6238
- HIBP range API / k-anonymity — Have I Been Pwned API docs
```

- [ ] **Step 3: Create `docs/threat-model.md`**

Summarize §14 of the design spec: what ferrovault defends against (vault theft, tampering via GCM+AAD, power-loss via atomic writes, concurrent writers, predictable randomness) and what it explicitly does NOT (compromised host while unlocked, memory captured via swap/hibernation/core dumps — zeroization is best-effort, weak master passwords, clipboard history managers, binary tampering).

- [ ] **Step 4: Create `README.md`**

Include: a one-line description with defensive framing, a CI badge, the command table (from the design spec §6), a "Security design" section (Argon2id + AES-256-GCM + AAD-bound `PVLT` format + zeroization + atomic/locked writes), a "Build & test" section (`cargo build`, `cargo test`, `cargo clippy`), a link to `docs/threat-model.md`, and the attribution section (link `ATTRIBUTION.md`). Point any demo at a throwaway `--vault ./demo.pvlt`, never the default path.

- [ ] **Step 5: Final quality gate**

Run: `cargo fmt --all && cargo clippy --all-targets -- -D warnings && cargo test`
Expected: formatted, no clippy warnings, all tests PASS.

- [ ] **Step 6: Commit**

```bash
git add README.md LICENSE ATTRIBUTION.md docs/
git commit -m "docs: README, MIT license, attribution, threat model"
```

---

## Self-Review notes (for the planner)

- **Spec coverage:** crypto core (Task 2), PVLT format + AAD (Task 3), model/CBOR (Task 4), vault/atomic/locking (Task 5), CLI + core commands (Task 6), generator (Task 7), change-password + KDF auto-upgrade (Task 8), TOTP (Task 9), clipboard auto-clear (Task 10), HIBP (Task 11), repo/license/attribution/threat-model (Tasks 1 & 12). All §1–§14 spec sections map to a task.
- **Indistinguishable failure** verified in Tasks 2 & 5 (wrong-key and tamper both → `WrongPasswordOrCorrupt`).
- **No-panic parsing** verified by `rejects_truncated_without_panicking` (Task 3).
- **Master password never a flag** — `cli.rs` exposes no password argument; `main.rs` only prompts.
- **Type consistency:** `KdfParams`, `Decoded`, `VaultStore`, `Entry`, `GenOptions`, `RangeFetcher`, and the `cmd_*` signatures are used identically across the tasks that produce and consume them.
