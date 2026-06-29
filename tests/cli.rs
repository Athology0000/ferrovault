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
    assert!(matches!(commands::cmd_get(&store, b"m", "github"), Err(Error::EntryNotFound(_))));
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
