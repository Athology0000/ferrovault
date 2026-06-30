//! End-to-end-encrypted, bring-your-own-storage sync. The remote only ever sees
//! ciphertext; merging is per-entry, newest `updated` wins.

/// A remote storage back-end. The implementation only sees opaque ciphertext.
/// `pull` returns `Ok(None)` when the remote file does not exist yet (e.g. HTTP 404).
pub trait Remote {
    fn pull(&self) -> crate::Result<Option<Vec<u8>>>;
    fn push(&self, data: &[u8]) -> crate::Result<()>;
}

/// HTTP/HTTPS remote backed by a single URL (PUT to upload, GET to download).
pub struct HttpRemote {
    pub url: String,
    pub token: Option<String>,
}

impl Remote for HttpRemote {
    fn pull(&self) -> crate::Result<Option<Vec<u8>>> {
        let mut builder = attohttpc::get(&self.url);
        if let Some(ref token) = self.token {
            builder = builder.header("Authorization", format!("Bearer {token}"));
        }
        let resp = builder
            .send()
            .map_err(|e| crate::Error::Network(e.to_string()))?;
        if resp.status().as_u16() == 404 {
            return Ok(None);
        }
        if !resp.is_success() {
            return Err(crate::Error::Network(format!("HTTP {}", resp.status())));
        }
        let bytes = resp
            .bytes()
            .map_err(|e| crate::Error::Network(e.to_string()))?;
        Ok(Some(bytes))
    }

    fn push(&self, data: &[u8]) -> crate::Result<()> {
        let mut builder = attohttpc::put(&self.url);
        if let Some(ref token) = self.token {
            builder = builder.header("Authorization", format!("Bearer {token}"));
        }
        let resp = builder
            .bytes(data.to_vec())
            .send()
            .map_err(|e| crate::Error::Network(e.to_string()))?;
        if !resp.is_success() {
            return Err(crate::Error::Network(format!("HTTP {}", resp.status())));
        }
        Ok(())
    }
}

/// Summary of what a sync operation did.
#[derive(Debug)]
pub struct SyncReport {
    /// Entries present in the remote but not in the local vault before merge.
    pub added: usize,
    /// Entries present in both sides where the remote copy was newer.
    pub updated: usize,
    /// Total number of entries in the merged result.
    pub total: usize,
    /// Whether the merged vault was successfully pushed to the remote.
    pub pushed: bool,
}

/// Merge two vaults: per-entry, newest `updated` timestamp wins. Ties keep local.
///
/// Returns the merged `Vault` and a `SyncReport` describing what changed.
/// `report.pushed` is always `false` on return; the caller sets it after pushing.
pub fn merge(
    mut local: crate::model::Vault,
    mut remote: crate::model::Vault,
) -> (crate::model::Vault, SyncReport) {
    // `Vault` implements `Drop`, so we cannot destructure it by moving.
    // Use `std::mem::take` to extract the BTreeMaps without triggering the Drop guard.
    let local_version = local.version;
    let remote_version = remote.version;
    let mut entries = std::mem::take(&mut local.entries);
    let remote_entries = std::mem::take(&mut remote.entries);
    // Both vaults will now drop empty entry maps — no passwords to zeroize.

    let mut added = 0usize;
    let mut updated = 0usize;

    for (name, remote_entry) in remote_entries {
        // Clone the `updated` timestamp so we drop the borrow on `entries` before
        // potentially inserting into it.
        let local_updated = entries.get(&name).map(|e| e.updated.clone());
        match local_updated {
            None => {
                // Entry only exists on the remote side.
                entries.insert(name, remote_entry);
                added += 1;
            }
            Some(lu) => {
                // Entry exists on both sides — keep whichever has the newer timestamp.
                // RFC 3339 sorts lexicographically in chronological order.
                if remote_entry.updated > lu {
                    entries.insert(name, remote_entry);
                    updated += 1;
                }
                // else: local is newer-or-equal, keep it (already in `entries`)
            }
        }
    }

    let total = entries.len();
    let merged = crate::model::Vault {
        version: local_version.max(remote_version),
        entries,
    };
    let report = SyncReport {
        added,
        updated,
        total,
        pushed: false,
    };
    (merged, report)
}
