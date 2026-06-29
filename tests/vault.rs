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
    assert!(matches!(store.open(b"m"), Err(Error::VaultNotFound(_))));
}

#[test]
fn wrong_password_fails() {
    let dir = tempdir().unwrap();
    let store = VaultStore::new(dir.path().join("vault.pvlt"));
    store.create(b"right").unwrap();
    assert!(matches!(store.open(b"wrong"), Err(Error::WrongPasswordOrCorrupt)));
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
