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
    Vault {
        version: 1,
        entries,
    }
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
fn cbor_output_is_not_json() {
    let v = sample();
    let bytes = model::to_cbor(&v).unwrap();
    // Sanity-check that we emitted binary CBOR and not JSON. This does NOT imply
    // secrets are hidden in the serialised bytes — CBOR stores text strings as
    // literal UTF-8, so field values are present in the plaintext payload.
    // Secret confidentiality is provided by AES-256-GCM encryption at rest, not
    // by the choice of serialisation format.
    assert!(!bytes.starts_with(b"{"));
}

#[test]
fn from_cbor_rejects_garbage() {
    assert!(model::from_cbor(&[0xff, 0x00, 0x13, 0x37]).is_err());
}
