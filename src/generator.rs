//! Cryptographically secure password generation (OS CSPRNG, unbiased).

use crate::{Error, Result};
use rand::seq::SliceRandom;
use rand::Rng;
use zeroize::Zeroizing;

const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{};:,.?";

pub struct GenOptions {
    pub length: usize,
    pub symbols: bool,
}

pub fn generate(opts: &GenOptions) -> Result<Zeroizing<String>> {
    let mut classes: Vec<&[u8]> = vec![LOWER, UPPER, DIGITS];
    if opts.symbols {
        classes.push(SYMBOLS);
    }
    if opts.length < classes.len() {
        return Err(Error::TooShort(classes.len()));
    }
    let pool: Vec<u8> = classes.concat();
    let mut rng = rand::rngs::OsRng;

    let mut out: Vec<u8> = Vec::with_capacity(opts.length);
    // Guarantee at least one character from each required class.
    for class in &classes {
        out.push(class[rng.gen_range(0..class.len())]);
    }
    // Fill the remainder from the full pool.
    while out.len() < opts.length {
        out.push(pool[rng.gen_range(0..pool.len())]);
    }
    // Shuffle so the guaranteed characters are not always at the front.
    out.shuffle(&mut rng);

    // All bytes are ASCII by construction.
    Ok(Zeroizing::new(String::from_utf8(out).expect("ascii only")))
}
