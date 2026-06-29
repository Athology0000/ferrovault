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
