//! On-disk vault store: locked, atomic, durable read-modify-write.

use crate::crypto::{self, KdfParams};
use crate::model::{self, Vault};
use crate::{format, Error, Result};
use rand::RngCore;
use std::fs::OpenOptions;
#[cfg(unix)]
use std::fs::File;
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
