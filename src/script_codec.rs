//! Exotic-script text codec — turn any text into a visible mixture of Chinese,
//! Japanese, Korean, Russian (Cyrillic), and Arabic glyphs, and back; plus a
//! one-way recognition fingerprint.
//!
//! # This is NOT encryption
//! `encode`/`decode` are a **reversible encoding** — like base64 with a Unicode
//! alphabet. They provide **no secrecy**: the alphabet is in this (open-source)
//! file, so anyone can decode. It's a novelty/obfuscation, not a security
//! boundary. `fingerprint` is a one-way hash → glyphs: it reveals nothing about
//! the input and cannot be reversed.
//!
//! Everything here is **fully local** — nothing is ever sent anywhere.

use crate::{Error, Result};
use std::collections::HashMap;
use std::sync::OnceLock;

/// 256 distinct glyphs — one per byte value — interleaved across five scripts so
/// any non-trivial input renders as a visible mixture of all of them.
fn alphabet() -> &'static [char; 256] {
    static A: OnceLock<[char; 256]> = OnceLock::new();
    A.get_or_init(build_alphabet)
}

fn build_alphabet() -> [char; 256] {
    // Each pool is assigned, renderable letters from one script. Pools come from
    // disjoint Unicode blocks, so every glyph is distinct.
    let cyrillic: Vec<char> = (0x0410u32..=0x044F).filter_map(char::from_u32).collect(); // Russian
    let katakana: Vec<char> = (0x30A1u32..=0x30F6).filter_map(char::from_u32).collect(); // Japanese
    let hangul: Vec<char> = (0xAC00u32..=0xAC51).filter_map(char::from_u32).collect(); // Korean
    let cjk: Vec<char> = (0x4E00u32..=0x4E51).filter_map(char::from_u32).collect(); // Chinese
    let arabic: Vec<char> = (0x0621u32..=0x063A)
        .chain(0x0641..=0x064A)
        .chain(0x0671..=0x06BF)
        .filter_map(char::from_u32)
        .collect(); // Arabic

    let pools = [cyrillic, katakana, hangul, cjk, arabic];
    let mut out: Vec<char> = Vec::with_capacity(256);
    let mut cursor = [0usize; 5];
    loop {
        let mut progressed = false;
        for (p, pool) in pools.iter().enumerate() {
            if cursor[p] < pool.len() {
                out.push(pool[cursor[p]]);
                cursor[p] += 1;
                progressed = true;
                if out.len() == 256 {
                    let mut arr = ['\0'; 256];
                    arr.copy_from_slice(&out);
                    return arr;
                }
            }
        }
        assert!(progressed, "alphabet pools must total >= 256 glyphs");
    }
}

fn reverse() -> &'static HashMap<char, u8> {
    static R: OnceLock<HashMap<char, u8>> = OnceLock::new();
    R.get_or_init(|| {
        alphabet()
            .iter()
            .enumerate()
            .map(|(i, &c)| (c, i as u8))
            .collect()
    })
}

/// Encode arbitrary text as a mixture of CJK/Cyrillic/Arabic glyphs (one glyph
/// per UTF-8 byte). Reversible with [`decode`]. Not encryption.
pub fn encode(text: &str) -> String {
    let a = alphabet();
    text.bytes().map(|b| a[b as usize]).collect()
}

/// Decode glyphs produced by [`encode`] back to the original text. Whitespace is
/// ignored; any glyph outside the alphabet is an error.
pub fn decode(encoded: &str) -> Result<String> {
    let r = reverse();
    let mut bytes = Vec::new();
    for ch in encoded.chars() {
        if ch.is_whitespace() {
            continue;
        }
        match r.get(&ch) {
            Some(&b) => bytes.push(b),
            None => return Err(Error::BadFormat("not ferrovault-encoded text")),
        }
    }
    String::from_utf8(bytes).map_err(|_| Error::BadFormat("decoded bytes are not valid UTF-8"))
}

/// A short (6-glyph), **one-way** fingerprint of `text` — deterministic and not
/// reversible (it's a hash mapped into the exotic alphabet). Lets you recognize
/// a secret at a glance without revealing it.
pub fn fingerprint(text: &str) -> String {
    use sha1::{Digest, Sha1};
    let a = alphabet();
    let digest = Sha1::digest(text.as_bytes());
    digest.iter().take(6).map(|&b| a[b as usize]).collect()
}
