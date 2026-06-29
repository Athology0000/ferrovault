use ferrovault::totp::{current_code, totp_code};

// RFC 6238 Appendix B test seed (SHA-1): ASCII "12345678901234567890".
// The RFC tabulates 8-digit codes; our 6-digit codes are those mod 10^6.
const SEED: &[u8] = b"12345678901234567890";

#[test]
fn rfc6238_vectors_6_digits() {
    assert_eq!(totp_code(SEED, 59, 30, 6), "287082");
    assert_eq!(totp_code(SEED, 1111111109, 30, 6), "081804");
    assert_eq!(totp_code(SEED, 1111111111, 30, 6), "050471");
    assert_eq!(totp_code(SEED, 1234567890, 30, 6), "005924");
    assert_eq!(totp_code(SEED, 2000000000, 30, 6), "279037");
}

#[test]
fn current_code_decodes_base32_and_reports_remaining() {
    // base32(RFC4648, no pad) of the seed.
    let b32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    let (code, remaining) = current_code(b32, 59).unwrap();
    assert_eq!(code, "287082");
    assert_eq!(remaining, 1); // 30 - (59 % 30)
}

#[test]
fn invalid_base32_errors() {
    assert!(current_code("not valid base32 !!!", 0).is_err());
}
