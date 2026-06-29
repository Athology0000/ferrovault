# ferrovault — Design Spec

- **Status:** Approved (design); ready for implementation planning
- **Date:** 2026-06-28
- **Author:** (you)
- **Type:** Encrypted command-line password manager (Rust)

---

## 1. Overview & purpose

`ferrovault` is an encrypted command-line password manager written in Rust. One
master password protects a single encrypted vault file holding many credentials.

It is a **clean-room reimplementation** written from scratch for learning and
portfolio purposes, inspired in scope by the `foundations/password-manager`
project in `CarterPerez-dev/Cybersecurity-Projects` (AGPL-3.0). **No source code,
tests, or data files are copied** from that repository; all code, design, and
tests here are original and the project is released under the **MIT License**.

### Goals
- Correct applied cryptography (Argon2id KDF, AES-256-GCM AEAD) with the
  parameters stored in the vault so they can be upgraded over time.
- Memory-safe handling of secrets, including **best-effort zeroization** of the
  master password, derived key, and decrypted contents.
- **Cross-platform** (Windows + POSIX) durable, concurrency-safe vault writes —
  fixing the POSIX-only file locking of the original.
- Thorough automated tests, including known-answer vectors, as the primary
  signal of authorship.
- Defensible in an interview: every design decision has a stated reason.

### Non-goals (explicitly out of scope for v1 — YAGNI)
- Cloud sync, browser extensions, GUI, mobile.
- Multi-user vaults or credential sharing.
- Per-entry encryption / embedded database store (noted as a possible *future*
  direction; v1 encrypts the whole vault as one unit).
- Accepting the master password from a CLI flag or environment variable (a
  deliberate security decision — see §6).

---

## 2. Security & cryptographic design

### Key derivation — Argon2id
- Master password → 32-byte key via **Argon2id**.
- Starting parameters: `m_cost = 65536 KiB (64 MiB)`, `t_cost = 3`, `p_cost = 4`.
- 16-byte salt from the OS CSPRNG (`OsRng`), regenerated on every
  `change-password`.
- **Parameters are stored in the vault header** so old vaults remain readable
  when defaults change, and `change-password` / auto-upgrade can raise them.

### Encryption — AES-256-GCM
- A **fresh random 12-byte nonce on every write** (nonce reuse under GCM is
  catastrophic — a must-explain interview point).
- The 16-byte GCM authentication tag provides tamper detection.

### AAD binding
- The **entire binary header** (everything before the ciphertext — magic,
  version, KDF id + params, salt, nonce, ciphertext length) is supplied as the
  GCM **Associated Data**. An attacker therefore cannot downgrade the Argon2
  parameters or alter any header field without breaking authentication. This is
  a deliberate improvement over the original and falls out of the file format
  for free (§3).

### Indistinguishable failure
- Decryption failure (wrong master password) and authentication failure
  (tampered/corrupt file) both surface as a **single `WrongPasswordOrCorrupt`
  error**. Exposing which one occurred would leak information to an attacker.

### Secret handling (zeroization)
- Master password: `Zeroizing<String>` (read via `rpassword`, never echoed).
- Derived key: `Zeroizing<[u8; 32]>`.
- Decrypted plaintext: `Zeroizing<Vec<u8>>`; entry passwords wrapped so they are
  wiped on drop.
- **Honest limitation (documented in the threat model):** zeroization is
  best-effort. The OS may copy memory via swap, hibernation, or core dumps, and
  cannot be fully controlled from user space. This is stated plainly rather than
  overclaimed.

---

## 3. Vault file format (custom binary container)

Little-endian. The file is a fixed header followed by the AEAD ciphertext.

```
offset  field         size   notes
------  ------------  -----  ------------------------------------------
0       magic         4      ASCII "PVLT"
4       version       1      format version (0x01)
5       kdf_id        1      0x01 = argon2id
6       m_cost        4      u32, KiB
10      t_cost        4      u32, iterations
14      p_cost        1      u8, lanes
15      salt_len      1      u8 (= 16)
16      salt          N      salt_len bytes
16+N    nonce         12     AES-GCM nonce
28+N    ct_len        8      u64, length of ciphertext‖tag
36+N    ciphertext    M      ct_len bytes (CBOR plaintext encrypted ‖ 16-byte tag)
```

- **AAD = bytes [0 .. 36+N)** (the whole header, up to but excluding the
  ciphertext).
- The **plaintext** that gets encrypted is the `Vault` model (§4) serialized with
  **CBOR** (`ciborium`) — compact binary, IETF RFC 8949, no base64.
- The decoder is **bounds-checked**: truncated or malformed input returns a
  `BadFormat` error and never panics (verified by tests).

---

## 4. Data model

```rust
struct Vault {
    version: u32,
    entries: BTreeMap<String, Entry>, // sorted, deterministic serialization
}

struct Entry {
    username: String,
    password: String,              // wrapped for zeroization in memory
    url: Option<String>,
    notes: Option<String>,
    totp: Option<String>,          // base32 TOTP secret, if any
    created: String,               // RFC 3339 timestamp
    updated: String,               // RFC 3339 timestamp
}

struct KdfParams {
    m_cost: u32,
    t_cost: u32,
    p_cost: u8,
    salt: [u8; 16],
}
```

`BTreeMap` gives deterministic, sorted serialization (clean `list` output and
reproducible bytes).

---

## 5. Module architecture (library core + thin binary)

A `lib` crate holds all logic; `main.rs` only parses arguments and dispatches.
This keeps everything integration-testable and is the idiomatic structure.

```
src/
  lib.rs        // Error enum (thiserror), public module re-exports
  format.rs     // binary container encode + bounds-checked decode; header-as-AAD
  crypto.rs     // derive_key (argon2id); seal/open (aes-256-gcm + AAD)
  model.rs      // Entry, Vault, KdfParams; serde (+ CBOR via ciborium)
  vault.rs      // lock -> read -> decode -> decrypt -> CBOR; CRUD; atomic write
  generator.rs  // OsRng password generation; class guarantees; no modulo bias
  totp.rs       // RFC 6238 (hand-rolled HMAC-SHA1 + base32 decode)
  hibp.rs       // SHA-1 prefix range query (attohttpc, native TLS); k-anonymity
  clipboard.rs  // arboard copy + timed auto-clear
  cli.rs        // clap (derive): Args + Commands
  commands.rs   // command handlers
  main.rs       // parse -> dispatch -> map errors to exit codes
tests/
  crypto.rs format.rs vault.rs totp.rs generator.rs hibp.rs
```

Each module has one purpose, a small public interface, and is testable in
isolation.

---

## 6. CLI & UX

| Command | Behavior |
|---|---|
| `init` | Create a new empty vault; prompt for master password twice. |
| `add <name>` | Add an entry; prompt for username/password/optional url, notes; `--generate/-g` to use a random password; `--totp <secret>` to attach a TOTP seed. |
| `get <name>` | Show one entry; `--copy` copies the password to the clipboard with auto-clear (`--timeout <secs>`, default 15). |
| `list` | Print entry names only (never passwords). |
| `delete <name>` | Remove an entry. |
| `gen [length]` | Generate and print a strong password; no vault needed; `--no-symbols`. |
| `change-password` | Rotate the master password; re-encrypt under a fresh salt + current default KDF params. |
| `totp <name>` | Print the current 6-digit TOTP code and seconds remaining. |
| `check [name]` | HIBP k-anonymity breach check for an entry's password (or a prompted one). |

- Global `--vault <path>` (or `PV_VAULT` env). Default path:
  `~/.ferrovault/vault.pvlt` (Windows: `%USERPROFILE%\.ferrovault\vault.pvlt`),
  resolved via the `dirs` crate.
- **The master password is never a CLI flag** — only hidden interactive prompts
  (`rpassword`), since flags leak into shell history and process listings.
- `stdout` carries data (so `gen` and `totp` pipe cleanly); `stderr` carries
  prompts, status, and errors.

---

## 7. Standout features (all four in v1)

1. **Clipboard auto-clear** (`get --copy [--timeout 15]`): copies the password
   via `arboard`, then overwrites the clipboard after N seconds. *Limitation
   (documented):* the process stays alive to perform the clear; if it is killed
   early the value remains. No clipboard *history* mitigation is possible from
   user space — stated in the threat model.
2. **KDF parameter auto-upgrade:** on save, if the vault's stored parameters are
   weaker than the current defaults, the vault is transparently re-derived under
   fresh parameters and a new salt. `change-password` always uses current
   defaults.
3. **TOTP (RFC 6238):** optional base32 secret per entry; `totp <name>` prints
   the live 6-digit code and time remaining. Implemented by hand (HMAC-SHA1 +
   base32) and validated against the **RFC 6238 test vectors**.
4. **HIBP breach check (k-anonymity):** SHA-1 the password, send only the first
   5 hex characters to `api.pwnedpasswords.com/range/{prefix}`, match the suffix
   locally. Surfaced by `check` and as a warning on `add` / `change-password`.
   Offline or API failure is a **soft warning, never fatal**.

---

## 8. Error handling

A single `thiserror` enum at the library boundary:

| Variant | Meaning | Exit code |
|---|---|---|
| `VaultNotFound` | No vault at the path | 3 |
| `VaultExists` | `init` over an existing vault | 4 |
| `WrongPasswordOrCorrupt` | Decrypt/auth failed (indistinguishable by design) | 5 |
| `BadFormat` | Malformed/truncated container | 6 |
| `EntryNotFound` | No such entry | 7 |
| `EntryExists` | `add` of a duplicate name | 8 |
| `Locked` | Could not acquire the vault lock | 9 |
| `Io` | Filesystem error | 10 |
| `Clipboard` | Clipboard backend error | 11 |
| `Network` | HIBP request failed (non-fatal where used) | 12 |
| `Totp` | Invalid TOTP secret | 13 |

`main.rs` maps each to an exit code and a clear `stderr` message.

---

## 9. Durability & concurrency

- **Atomic durable write:** write to a temp file in the same directory (opened
  `0o600` on Unix at the syscall), `write` → `fsync` the file → atomic `rename`
  over the real vault → `fsync` the parent directory (POSIX; a no-op where the
  platform does not support it). Always old-or-new, never half-written.
- **Advisory exclusive lock** (`fd-lock`) held for the whole read-modify-write so
  two concurrent `ferrovault` runs cannot race. Works on **Windows and POSIX**.

---

## 10. Dependencies (all pure-Rust — no C toolchain)

| Crate | Purpose |
|---|---|
| `argon2` | Argon2id key derivation |
| `aes-gcm` | AES-256-GCM AEAD |
| `ciborium` | CBOR (de)serialization of the vault plaintext |
| `serde` | Derive serialization for the model |
| `clap` (derive) | CLI parsing |
| `rpassword` | Hidden master-password prompts |
| `zeroize` | Best-effort secret wiping |
| `fd-lock` | Cross-platform advisory file locking |
| `arboard` | Cross-platform clipboard |
| `attohttpc` | Blocking HTTP for HIBP, `tls-native` feature (OS-native TLS: schannel on Windows) — avoids `ring`/C, keeping the build pure-Rust |
| `hmac`, `sha1` | TOTP HMAC-SHA1 (RFC 6238) and HIBP prefix hashing (both use SHA-1) |
| `base32` | TOTP secret decoding |
| `rand` / `getrandom` | `OsRng` for salts, nonces, password generation |
| `thiserror` | Error enum |
| `dirs` | Default vault path resolution |
| `time` or `chrono` | RFC 3339 timestamps |

(Exact set finalized during planning; the constraint is **no C build
dependencies** so it builds cleanly on Windows/MSVC.)

---

## 11. Testing strategy (TDD, red-green per module)

- **crypto:** encrypt/decrypt round-trip; wrong key fails; a single flipped
  ciphertext byte fails *identically* to a wrong key; swapping an AAD/header byte
  fails.
- **format:** encode/decode round-trip; truncated and garbage input return
  `BadFormat` and **never panic**.
- **vault:** CRUD; atomic write survives (old file intact on simulated failure);
  KDF params persisted and upgraded on save.
- **totp:** **RFC 6238 known-answer vectors**.
- **generator:** requested length honored; required character classes present;
  charset respects `--no-symbols`; basic distribution sanity (no obvious bias).
- **hibp:** mocked HTTP — correct prefix sent, suffix matched, offline handled.
- **CI:** GitHub Actions running `build` + `test` + `clippy` + `fmt` → green
  badge in the README.

---

## 12. Build order (8 phases, each a working, committable milestone)

0. Repo scaffold, `Cargo.toml`, CI, lib/bin skeleton, `Error` enum.
1. `crypto.rs` + `format.rs` — the security core (TDD).
2. `model.rs` + `vault.rs` + `init/add/get/list/delete` + `cli.rs` →
   **a working password manager**.
3. `generator.rs` + `gen`.
4. `change-password` + KDF auto-upgrade.
5. `totp.rs` + `totp`.
6. `clipboard.rs` + `get --copy`.
7. `hibp.rs` + `check`.
8. README + threat-model doc + `ATTRIBUTION.md` + polish.

---

## 13. Repository, license & attribution

- Fresh `git init` at `C:\Users\aeare\Desktop\ferrovault` — clean history,
  separate from the reference clone.
- **MIT License** (a genuine clean-room reimplementation is not a derivative
  work, so AGPL copyleft does not attach — but the inspiration is credited
  regardless, which is the honest and mature thing to do).
- `ATTRIBUTION.md`: credits the `CarterPerez-dev/Cybersecurity-Projects`
  curriculum as the inspiration, states that no code/tests/fixtures were copied,
  and notes that any standards used (Argon2, AES-GCM, RFC 6238, HIBP
  k-anonymity) were implemented against their primary specifications.
- **Hard rule:** no file, code block, rule table, or test fixture is copied from
  the original. Re-derive from primary sources.

---

## 14. Threat model summary (what it does and does NOT defend)

**Defends against:**
- Theft of the vault file at rest (Argon2id + AES-256-GCM).
- Tampering with the vault or its header (GCM tag + AAD binding).
- Power loss mid-write (atomic durable write).
- Concurrent writers (advisory lock).
- Predictable randomness (OS CSPRNG everywhere).

**Does NOT defend against (stated honestly):**
- A compromised host (malware, keylogger, memory scraper) while you type the
  master password or while the vault is unlocked in RAM.
- Memory captured via OS swap, hibernation, or core dumps (zeroization is
  best-effort).
- A weak master password (Argon2 raises the cost per guess but cannot rescue a
  trivial password).
- Clipboard history managers retaining a copied password despite auto-clear.
- An attacker who can modify the binary itself.
