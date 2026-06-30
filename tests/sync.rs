use ferrovault::commands::cmd_sync;
use ferrovault::model::{Entry, Vault};
use ferrovault::sync::{merge, Remote};
use ferrovault::vault::VaultStore;
use ferrovault::Error;
use std::cell::RefCell;
use std::collections::BTreeMap;
use tempfile::tempdir;

// ─── Fake in-memory remote ────────────────────────────────────────────────────

struct FakeRemote {
    data: RefCell<Option<Vec<u8>>>,
}

impl FakeRemote {
    fn empty() -> Self {
        FakeRemote {
            data: RefCell::new(None),
        }
    }
}

impl Remote for FakeRemote {
    fn pull(&self) -> ferrovault::Result<Option<Vec<u8>>> {
        Ok(self.data.borrow().clone())
    }
    fn push(&self, data: &[u8]) -> ferrovault::Result<()> {
        *self.data.borrow_mut() = Some(data.to_vec());
        Ok(())
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn make_entry(updated: &str) -> Entry {
    Entry {
        username: "user".into(),
        password: "pw".into(),
        url: None,
        notes: None,
        totp: None,
        created: "2024-01-01T00:00:00Z".into(),
        updated: updated.into(),
    }
}

fn vault_with(entries: &[(&str, &str)]) -> Vault {
    let mut map = BTreeMap::new();
    for &(name, updated) in entries {
        map.insert(name.to_string(), make_entry(updated));
    }
    Vault {
        version: 1,
        entries: map,
    }
}

// ─── merge unit tests ─────────────────────────────────────────────────────────

#[test]
fn merge_union_keeps_all_entries() {
    let local = vault_with(&[("alpha", "2024-01-01T00:00:00Z")]);
    let remote = vault_with(&[("beta", "2024-01-01T00:00:00Z")]);
    let (merged, report) = merge(local, remote);
    assert!(merged.entries.contains_key("alpha"));
    assert!(merged.entries.contains_key("beta"));
    assert_eq!(merged.entries.len(), 2);
    assert_eq!(report.total, 2);
    assert_eq!(report.added, 1);
    assert_eq!(report.updated, 0);
    assert!(!report.pushed);
}

#[test]
fn merge_newer_remote_wins_on_conflict() {
    let local = vault_with(&[("site", "2024-01-01T00:00:00Z")]);
    let remote = vault_with(&[("site", "2024-06-01T00:00:00Z")]);
    let (merged, report) = merge(local, remote);
    // Remote's entry is newer → should win.
    assert_eq!(merged.entries["site"].updated, "2024-06-01T00:00:00Z");
    assert_eq!(report.updated, 1);
    assert_eq!(report.added, 0);
}

#[test]
fn merge_older_remote_keeps_local() {
    let local = vault_with(&[("site", "2024-06-01T00:00:00Z")]);
    let remote = vault_with(&[("site", "2024-01-01T00:00:00Z")]);
    let (merged, report) = merge(local, remote);
    // Local is newer → keep it.
    assert_eq!(merged.entries["site"].updated, "2024-06-01T00:00:00Z");
    assert_eq!(report.updated, 0);
    assert_eq!(report.added, 0);
}

#[test]
fn merge_tie_keeps_local() {
    let ts = "2024-01-01T00:00:00Z";
    let mut local = vault_with(&[("site", ts)]);
    local.entries.get_mut("site").unwrap().username = "local-user".into();
    let mut remote = vault_with(&[("site", ts)]);
    remote.entries.get_mut("site").unwrap().username = "remote-user".into();
    let (merged, _report) = merge(local, remote);
    // Tie → local wins.
    assert_eq!(merged.entries["site"].username, "local-user");
}

#[test]
fn merge_version_is_max() {
    let mut local = vault_with(&[]);
    local.version = 2;
    let mut remote = vault_with(&[]);
    remote.version = 5;
    let (merged, _) = merge(local, remote);
    assert_eq!(merged.version, 5);
}

#[test]
fn merge_counts_are_correct_for_mixed_case() {
    // local: A (old), B (new), C (only local)
    // remote: A (new → updated), B (old → keep local), D (only remote → added)
    let local = vault_with(&[
        ("A", "2024-01-01T00:00:00Z"),
        ("B", "2024-06-01T00:00:00Z"),
        ("C", "2024-01-01T00:00:00Z"),
    ]);
    let remote = vault_with(&[
        ("A", "2024-06-01T00:00:00Z"), // newer → updated
        ("B", "2024-01-01T00:00:00Z"), // older → keep local
        ("D", "2024-01-01T00:00:00Z"), // only remote → added
    ]);
    let (merged, report) = merge(local, remote);
    assert_eq!(merged.entries.len(), 4);
    assert_eq!(report.added, 1);
    assert_eq!(report.updated, 1);
    assert_eq!(report.total, 4);
}

// ─── keyfile tests ────────────────────────────────────────────────────────────

#[test]
fn keyfile_vault_rejected_without_keyfile() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.pvlt");
    let master = b"master-pass";
    let keyfile = b"my-secret-keyfile".to_vec();

    // Create vault WITH keyfile.
    let store_with = VaultStore::new(path.clone()).with_keyfile(Some(keyfile.clone()));
    store_with.create(master).unwrap();

    // Open WITHOUT keyfile → wrong key → WrongPasswordOrCorrupt.
    let store_without = VaultStore::new(path.clone());
    assert!(matches!(
        store_without.open(master),
        Err(Error::WrongPasswordOrCorrupt)
    ));
}

#[test]
fn keyfile_vault_opens_with_correct_keyfile() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.pvlt");
    let master = b"master-pass";
    let keyfile = b"my-secret-keyfile".to_vec();

    let store = VaultStore::new(path.clone()).with_keyfile(Some(keyfile.clone()));
    store.create(master).unwrap();

    // Open WITH the correct keyfile → succeeds.
    let store2 = VaultStore::new(path).with_keyfile(Some(keyfile));
    let (vault, _) = store2.open(master).unwrap();
    assert_eq!(vault.entries.len(), 0);
}

#[test]
fn keyfile_wrong_keyfile_rejected() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.pvlt");
    let master = b"master-pass";

    let store = VaultStore::new(path.clone()).with_keyfile(Some(b"correct-key".to_vec()));
    store.create(master).unwrap();

    let store_wrong = VaultStore::new(path).with_keyfile(Some(b"wrong-key".to_vec()));
    assert!(matches!(
        store_wrong.open(master),
        Err(Error::WrongPasswordOrCorrupt)
    ));
}

// ─── end-to-end sync with FakeRemote ─────────────────────────────────────────

#[test]
fn sync_end_to_end_merges_two_stores() {
    let remote = FakeRemote::empty();
    let master = b"test-master";
    let keyfile = b"shared-keyfile".to_vec();

    // Store 1: create vault, add entry A, sync → pushes to remote.
    let dir1 = tempdir().unwrap();
    let store1 =
        VaultStore::new(dir1.path().join("vault.pvlt")).with_keyfile(Some(keyfile.clone()));
    store1.create(master).unwrap();
    store1
        .update(master, |v| {
            v.entries
                .insert("A".into(), make_entry("2024-01-01T00:00:00Z"));
            Ok(())
        })
        .unwrap();
    let report1 = cmd_sync(&store1, master, &remote).unwrap();
    assert!(report1.pushed);
    assert_eq!(report1.total, 1);

    // Store 2: different path, same remote, same master+keyfile — add entry B, sync.
    let dir2 = tempdir().unwrap();
    let store2 =
        VaultStore::new(dir2.path().join("vault.pvlt")).with_keyfile(Some(keyfile.clone()));
    // Add B locally before syncing (store2 starts empty).
    // We create the vault first, then add B, then sync.
    store2.create(master).unwrap();
    store2
        .update(master, |v| {
            v.entries
                .insert("B".into(), make_entry("2024-02-01T00:00:00Z"));
            Ok(())
        })
        .unwrap();
    let report2 = cmd_sync(&store2, master, &remote).unwrap();
    assert!(report2.pushed);
    // After merge: both A and B should be present.
    assert_eq!(report2.total, 2);
    assert_eq!(report2.added, 1); // A was added from remote

    // Verify store2 now has both A and B.
    let (vault2, _) = store2.open(master).unwrap();
    assert!(vault2.entries.contains_key("A"));
    assert!(vault2.entries.contains_key("B"));

    // Sync store1 again to pull B back.
    let report3 = cmd_sync(&store1, master, &remote).unwrap();
    assert_eq!(report3.total, 2);
    let (vault1, _) = store1.open(master).unwrap();
    assert!(vault1.entries.contains_key("A"));
    assert!(vault1.entries.contains_key("B"));
}

#[test]
fn sync_fresh_local_pulls_remote_content() {
    let remote = FakeRemote::empty();
    let master = b"pw";

    // Populate the remote via store1.
    let dir1 = tempdir().unwrap();
    let store1 = VaultStore::new(dir1.path().join("vault.pvlt"));
    store1.create(master).unwrap();
    store1
        .update(master, |v| {
            v.entries
                .insert("entry1".into(), make_entry("2024-03-01T00:00:00Z"));
            Ok(())
        })
        .unwrap();
    cmd_sync(&store1, master, &remote).unwrap();

    // Store2 starts with no local vault — sync should create it and pull entry1.
    let dir2 = tempdir().unwrap();
    let store2 = VaultStore::new(dir2.path().join("vault.pvlt"));
    let report = cmd_sync(&store2, master, &remote).unwrap();
    assert_eq!(report.added, 1);
    assert_eq!(report.total, 1);
    let (vault2, _) = store2.open(master).unwrap();
    assert!(vault2.entries.contains_key("entry1"));
}
