use ferrovault::commands::{self, cmd_stats};
use ferrovault::model::Entry;
use ferrovault::vault::VaultStore;
use tempfile::tempdir;

fn entry(pw: &str, totp: Option<&str>, url: Option<&str>) -> Entry {
    Entry {
        username: "u".into(),
        password: pw.into(),
        url: url.map(|s| s.into()),
        notes: None,
        totp: totp.map(|s| s.into()),
        created: "t".into(),
        updated: "t".into(),
    }
}

#[test]
fn stats_counts_totp_weak_and_reused() {
    let dir = tempdir().unwrap();
    let store = VaultStore::new(dir.path().join("v.pvlt"));
    commands::cmd_init(&store, b"m").unwrap();
    commands::cmd_add(
        &store,
        b"m",
        "a",
        entry("Str0ng!Passw0rd#1", Some("GEZDGNBV"), Some("https://x")),
    )
    .unwrap();
    // Two entries sharing a weak password.
    commands::cmd_add(&store, b"m", "b", entry("abc", None, None)).unwrap();
    commands::cmd_add(&store, b"m", "c", entry("abc", None, None)).unwrap();

    let s = cmd_stats(&store, b"m").unwrap();
    assert_eq!(s.total, 3);
    assert_eq!(s.with_totp, 1);
    assert_eq!(s.with_url, 1);
    assert_eq!(s.weak, 2);
    assert_eq!(s.reused_passwords, 1);
    assert_eq!(s.reused_entries, 2);
}
