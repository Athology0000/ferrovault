use ferrovault::crypto::{self, KdfParams};
use ferrovault::Error;

fn test_params() -> KdfParams {
    // small cost for fast tests
    KdfParams { m_cost: 8, t_cost: 1, p_cost: 1, salt: [7u8; 16] }
}

#[test]
fn round_trip() {
    let p = test_params();
    let key = crypto::derive_key(b"correct horse", &p).unwrap();
    let nonce = crypto::random_nonce();
    let aad = b"header-bytes";
    let ct = crypto::seal(&key, &nonce, aad, b"secret data").unwrap();
    let pt = crypto::open(&key, &nonce, aad, &ct).unwrap();
    assert_eq!(&pt[..], b"secret data");
}

#[test]
fn wrong_password_fails() {
    let p = test_params();
    let nonce = crypto::random_nonce();
    let aad = b"h";
    let key = crypto::derive_key(b"right", &p).unwrap();
    let ct = crypto::seal(&key, &nonce, aad, b"x").unwrap();
    let wrong = crypto::derive_key(b"wrong", &p).unwrap();
    let err = crypto::open(&wrong, &nonce, aad, &ct).unwrap_err();
    assert!(matches!(err, Error::WrongPasswordOrCorrupt));
}

#[test]
fn tamper_fails_identically() {
    let p = test_params();
    let key = crypto::derive_key(b"k", &p).unwrap();
    let nonce = crypto::random_nonce();
    let aad = b"h";
    let mut ct = crypto::seal(&key, &nonce, aad, b"hello world").unwrap();
    ct[0] ^= 0x01; // flip a bit
    let err = crypto::open(&key, &nonce, aad, &ct).unwrap_err();
    assert!(matches!(err, Error::WrongPasswordOrCorrupt));
}

#[test]
fn aad_mismatch_fails() {
    let p = test_params();
    let key = crypto::derive_key(b"k", &p).unwrap();
    let nonce = crypto::random_nonce();
    let ct = crypto::seal(&key, &nonce, b"aad-A", b"data").unwrap();
    let err = crypto::open(&key, &nonce, b"aad-B", &ct).unwrap_err();
    assert!(matches!(err, Error::WrongPasswordOrCorrupt));
}

#[test]
fn is_weaker_than_default() {
    let weak = KdfParams { m_cost: 1024, t_cost: 1, p_cost: 1, salt: [0; 16] };
    assert!(weak.is_weaker_than_default());
    let strong = KdfParams::generate_default();
    assert!(!strong.is_weaker_than_default());
}
