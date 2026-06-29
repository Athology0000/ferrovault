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

    assert!(matches!(store.open(b"old"), Err(Error::WrongPasswordOrCorrupt)));
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
