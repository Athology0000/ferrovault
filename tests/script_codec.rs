use ferrovault::script_codec::{decode, encode, fingerprint};
use ferrovault::Error;

#[test]
fn round_trips_arbitrary_text() {
    for s in [
        "",
        "p@ssw0rd!",
        "correct horse battery staple",
        "héllo, café — 日本語 Ω",
        "Tr0ub4dor&3xY!~`",
    ] {
        let enc = encode(s);
        assert_eq!(decode(&enc).unwrap(), s, "round-trip failed for {s:?}");
    }
}

#[test]
fn encoded_output_uses_exotic_scripts_not_ascii() {
    let enc = encode("a reasonably long password 12345");
    assert!(!enc.is_empty());
    // No plain ASCII letters/digits leak into the encoded form.
    assert!(enc.chars().all(|c| !c.is_ascii()));
    // It should visibly mix scripts: at least three distinct Unicode blocks.
    let block = |c: char| (c as u32) >> 8; // rough block bucket
    let distinct_blocks: std::collections::HashSet<u32> = enc.chars().map(block).collect();
    assert!(
        distinct_blocks.len() >= 3,
        "expected a mixture of scripts, got blocks {distinct_blocks:?}"
    );
}

#[test]
fn decode_rejects_non_alphabet_text() {
    // Plain Latin text is not in the alphabet.
    assert!(matches!(decode("hello"), Err(Error::BadFormat(_))));
}

#[test]
fn decode_ignores_whitespace() {
    let enc = encode("spaced out");
    let spaced: String = enc.chars().flat_map(|c| [c, ' ']).collect();
    assert_eq!(decode(&spaced).unwrap(), "spaced out");
}

#[test]
fn fingerprint_is_deterministic_fixed_length_and_distinguishes() {
    assert_eq!(fingerprint("secret"), fingerprint("secret"));
    assert_eq!(fingerprint("secret").chars().count(), 6);
    assert_ne!(fingerprint("secret"), fingerprint("Secret"));
    // It must not be the input.
    assert_ne!(fingerprint("secret"), "secret");
}
