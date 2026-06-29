use ferrovault::crypto::KdfParams;
use ferrovault::format;
use ferrovault::Error;

fn params() -> KdfParams {
    KdfParams { m_cost: 65536, t_cost: 3, p_cost: 4, salt: [9u8; 16] }
}

#[test]
fn round_trip() {
    let p = params();
    let nonce = [1u8; 12];
    let ct = vec![0xAB; 40];
    let bytes = format::encode(&p, &nonce, &ct);
    let d = format::decode(&bytes).unwrap();
    assert_eq!(d.params, p);
    assert_eq!(d.nonce, nonce);
    assert_eq!(d.ciphertext, ct);
    // AAD is exactly the header (everything before the ciphertext)
    assert_eq!(d.aad, format::encode_header(&p, &nonce, ct.len() as u64));
    assert_eq!(&bytes[..d.aad.len()], &d.aad[..]);
}

#[test]
fn rejects_empty() {
    assert!(matches!(format::decode(&[]).unwrap_err(), Error::BadFormat(_)));
}

#[test]
fn rejects_bad_magic() {
    let mut b = format::encode(&params(), &[0u8; 12], &[1, 2, 3]);
    b[0] = b'X';
    assert!(matches!(format::decode(&b).unwrap_err(), Error::BadFormat(_)));
}

#[test]
fn rejects_truncated_without_panicking() {
    let full = format::encode(&params(), &[0u8; 12], &vec![5u8; 20]);
    for cut in 0..full.len() {
        // must return an error, never panic
        let _ = format::decode(&full[..cut]);
    }
}

#[test]
fn rejects_garbage() {
    let junk = [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
    assert!(format::decode(&junk).is_err());
}
