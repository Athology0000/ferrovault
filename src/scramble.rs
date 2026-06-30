//! Reversible byte "scrambler" for the vault file.
//!
//! # Obfuscation, NOT encryption
//! This algorithm is public (it's right here in the open source), so it adds
//! **no secrecy** — the real protection is the AES-256-GCM layer underneath.
//! Its only job is to make a vault file not trivially recognizable: with it on,
//! the file has no plaintext `PVLT` magic or visible header structure and looks
//! like uniform random bytes. It is a thin outer wrapper applied to the already-
//! encrypted file, so it cannot affect confidentiality or tamper-evidence.
//!
//! Fully local; nothing leaves the machine. The transform is its own inverse
//! (XOR with a fixed keystream), so the same function scrambles and descrambles.

use sha1::{Digest, Sha1};

const DOMAIN: &[u8] = b"ferrovault-scramble-v1";

/// XOR `data` with a deterministic keystream. Applying it twice returns the
/// original input, so this is both the scramble and the descramble operation.
pub fn apply(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut block: u64 = 0;
    let mut i = 0;
    while i < data.len() {
        // 20 keystream bytes per block from SHA1(DOMAIN || block_index_le).
        let mut h = Sha1::new();
        h.update(DOMAIN);
        h.update(block.to_le_bytes());
        let ks = h.finalize();
        for &k in ks.iter() {
            if i >= data.len() {
                break;
            }
            out.push(data[i] ^ k);
            i += 1;
        }
        block += 1;
    }
    out
}
