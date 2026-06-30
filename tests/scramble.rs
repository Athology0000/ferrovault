use ferrovault::scramble::apply;
use ferrovault::vault::VaultStore;
use tempfile::tempdir;

#[test]
fn is_its_own_inverse() {
    for data in [
        b"".to_vec(),
        b"PVLT\x01...".to_vec(),
        (0u8..=255).collect::<Vec<u8>>(),
        vec![0xABu8; 1000],
    ] {
        assert_eq!(apply(&apply(&data)), data, "scramble must round-trip");
    }
}

#[test]
fn actually_changes_the_bytes() {
    let data = b"ferrovault PVLT header and ciphertext bytes".to_vec();
    let scrambled = apply(&data);
    assert_eq!(scrambled.len(), data.len());
    assert_ne!(scrambled, data, "output should differ from input");
    assert!(!scrambled.windows(4).any(|w| w == b"PVLT"));
}

#[test]
fn scrambled_vault_round_trips_and_hides_magic() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("v.pvlt");
    let store = VaultStore::new(path.clone()).with_scramble(true);
    store.create(b"master").unwrap();

    // On disk: no plaintext "PVLT" magic.
    let raw = std::fs::read(&path).unwrap();
    assert!(
        !raw.windows(4).any(|w| w == b"PVLT"),
        "scrambled vault must not show the magic"
    );

    // It still opens.
    let (vault, _) = store.open(b"master").unwrap();
    assert_eq!(vault.entries.len(), 0);

    // A store WITHOUT the scramble flag still reads it (reads auto-detect).
    assert!(VaultStore::new(path).open(b"master").is_ok());
}

#[test]
fn plain_vault_is_readable_by_a_scramble_enabled_store() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("v.pvlt");
    VaultStore::new(path.clone()).create(b"m").unwrap(); // plain write

    let raw = std::fs::read(&path).unwrap();
    assert!(
        raw.windows(4).any(|w| w == b"PVLT"),
        "plain vault has magic"
    );

    // Auto-detect on read: a scramble-enabled store still opens the plain vault.
    assert!(VaultStore::new(path).with_scramble(true).open(b"m").is_ok());
}
