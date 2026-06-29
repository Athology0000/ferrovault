# ferrovault — Code Walkthrough & Interview Prep

A guided tour of the three modules that matter most — `crypto.rs`, `format.rs`,
`vault.rs` — plus the end-to-end flows and the questions an interviewer will ask.
Read this until you can whiteboard the **write path**, the **read path**, and the
**AAD round-trip** without looking.

## How the layers fit

```
main.rs ──► cli.rs (clap)                 parse args, prompt for the master
   │                                       password (rpassword), route
   ▼
commands.rs   cmd_init/add/get/list/...   orchestration; takes secrets as params
   │                                       (so handlers are testable w/o a TTY)
   ▼
vault.rs      VaultStore                   lock → read/modify → write, atomically
   ├─► crypto.rs   derive_key, seal, open  Argon2id + AES-256-GCM
   ├─► format.rs   encode/decode (PVLT)    binary container; header == AAD
   └─► model.rs    Vault/Entry + CBOR      the plaintext that gets encrypted
```

One vault file holds everything, encrypted as a single unit. Nothing in
`crypto`/`format`/`model` knows about the CLI; `vault` is the only place that
touches the disk.

---

## crypto.rs — key derivation + authenticated encryption

### `derive_key(password, params) -> Zeroizing<[u8;32]>`
Runs **Argon2id** (`Algorithm::Argon2id`, `Version::V0x13`) with the params stored
in the vault (`m=64 MiB, t=3, p=4`, 16-byte salt) to stretch the master password
into a 32-byte AES key. The output buffer is `Zeroizing`, so it is wiped from RAM
on drop.

- **Why Argon2id and not PBKDF2/bcrypt/SHA?** Argon2id is *memory-hard* — it
  forces an attacker to spend ~64 MiB per guess, which neutralises GPU/ASIC
  parallelism the way iteration-only KDFs can't. It's the current OWASP
  recommendation. The `id` variant blends Argon2i (side-channel resistance) and
  Argon2d (GPU resistance).
- **Why store the params in the file?** So old vaults stay readable when the
  defaults get stronger, and so the vault can be transparently *upgraded* (see
  `vault::update`).

### `seal` / `open` — AES-256-GCM
`seal(key, nonce, aad, plaintext) -> ciphertext‖tag`;
`open(key, nonce, aad, ciphertext) -> Zeroizing<plaintext>`.

- **AES-256-GCM is an AEAD**: it gives confidentiality (the cipher) *and*
  integrity/authenticity (a 16-byte GCM tag) in one primitive. If even one bit of
  ciphertext, nonce, or AAD changes, `open` fails.
- **Nonce**: a fresh random 12-byte value on *every* write.
  **Nonce reuse under GCM is catastrophic** — encrypting two messages with the
  same key+nonce leaks the XOR of plaintexts and lets an attacker forge the
  authentication tag (the GHASH key is recoverable). This is *the* GCM footgun;
  ferrovault avoids it by drawing a new `OsRng` nonce per write and never reusing.
- **AAD (Associated Data)**: extra bytes that are *authenticated but not
  encrypted*. ferrovault passes the entire file header as AAD (see `format.rs`),
  so the KDF parameters, version, salt, and nonce are all covered by the tag —
  an attacker can't downgrade the Argon2 cost or flip a header byte without
  breaking decryption.

### One error for "wrong password" vs "tampered file"
`open` maps every AEAD failure to a single `Error::WrongPasswordOrCorrupt`.
- **Why hide which one it is?** Cryptographically you *can't* tell them apart
  (both just mean "the tag didn't verify"), and surfacing the difference would
  leak information to an attacker probing the vault. KDF/parameter errors map to a
  separate `Error::Crypto`, because those are programming/config faults, not
  authentication outcomes.

---

## format.rs — the `PVLT` binary container

Layout (little-endian):
```
magic "PVLT"(4) │ ver(1) │ kdf_id(1) │ m_cost(u32) │ t_cost(u32) │ p_cost(u8)
│ salt_len(1) │ salt(16) │ nonce(12) │ ct_len(u64) │ ciphertext‖tag
```

- **The header *is* the AAD.** `decode` returns `aad = bytes[0..ct_start]` — the
  literal header bytes as read from disk. `seal`/`open` authenticate exactly those
  bytes. That's what makes header tampering (e.g. an Argon2 downgrade attack)
  break decryption.
- **Why a custom binary format + CBOR inside, not JSON?** JSON would base64-bloat
  every binary field (salt/nonce/ciphertext) and is text-ambiguous. The container
  is a compact, fully-specified binary format you designed; the *plaintext* inside
  is CBOR (RFC 8949) — a compact, standard binary encoding — not JSON.
- **`decode` is bounds-checked and never panics.** Every read is gated by a prior
  length check; the `try_into().unwrap()` calls operate on slices already proven
  to be the right length; `ct_len` is range-checked with `try_into`/`checked_add`
  so a hostile `ct_len` returns `BadFormat`, not a panic or OOM. There's a test
  that feeds *every* truncation length and asserts no panic — parsing
  attacker-controlled files is itself an attack surface, so this matters.

---

## vault.rs — locked, atomic, durable read-modify-write

`VaultStore` is the only module that touches disk. Public API: `create`, `open`,
`update`, `rewrite`.

### Locking — `with_lock`
Every public method runs its body inside `with_lock`, which takes an **exclusive
advisory lock** (`fd-lock`) on a `<vault>.lock` sidecar for the duration. This
serialises concurrent `ferrovault` processes so two writers can't interleave a
read-modify-write and lose data. It's cross-platform (Windows + POSIX), which is
why it replaced the original's POSIX-only `fcntl`. The internal helpers
(`read_locked`/`write_locked`) assume the lock is already held and never re-lock —
so there's no self-deadlock.

### Atomic durable write — `atomic_write`
`temp file (0600 on Unix) → write → fsync → atomic rename over the vault → fsync
the parent dir (POSIX)`. The real vault is never partially written: a crash mid-
save leaves either the complete old file or the complete new one, never a
half-file. `rename` within the same directory is atomic on NTFS and POSIX.

### The write path — `write_locked`
```
key   = derive_key(master, params)
pt    = Zeroizing(to_cbor(vault))          // serialize the entry map
nonce = OsRng 12 bytes                      // fresh every write
aad   = encode_header(params, nonce, pt.len()+16)
ct    = seal(key, nonce, aad, pt)           // ct = pt‖tag
bytes = encode(params, nonce, ct)           // header ‖ ct
atomic_write(bytes)
```

### The read path — `read_locked`
```
bytes = read(file)                          // VaultNotFound if missing
d     = decode(bytes)                        // BadFormat on garbage, no panic
key   = derive_key(master, d.params)
pt    = open(key, d.nonce, d.aad, d.ciphertext)   // WrongPasswordOrCorrupt on fail
vault = from_cbor(pt)
```

### The AAD round-trip (the subtle invariant)
On write, the AAD is `encode_header(params, nonce, pt.len()+16)`. On read, the AAD
is the header bytes `decode` slices out of the file. **These are byte-identical for
a legitimately written file**, because AES-GCM ciphertext length is always
`plaintext_len + 16` (the tag), so the `ct_len` written into the header equals the
actual ciphertext length on disk. If they could ever diverge, a valid vault would
fail to open — they can't, by construction.

### KDF auto-upgrade — `update`
After applying the caller's change, `update` checks
`params.is_weaker_than_default()`; if the stored params are below current defaults,
it generates fresh default params + a new salt and re-derives the key before
writing. So vaults transparently strengthen over time. `change-password` always
rotates to fresh defaults.

### Secret hygiene
Master password, derived key, and decrypted plaintext are all `Zeroizing`.
`Vault::drop` additionally wipes each entry's `password`, `totp`, and `notes`.
This is **best-effort** (the honest caveat in the threat model): the OS can still
copy memory via swap/hibernation/core dumps, and `Clone`d copies escape the
destructor. You can't fully control that from user space — say so plainly.

---

## Interview Q&A (rapid fire)

**Q: Why is reusing a GCM nonce so bad?**
Same key+nonce → keystream reuse (XOR of plaintexts leaks) *and* the GHASH
authentication key becomes recoverable, enabling tag forgery. ferrovault uses a
fresh `OsRng` nonce per write.

**Q: Why Argon2id over a fast hash or PBKDF2?**
Memory-hardness. 64 MiB/guess defeats GPU/ASIC parallelism; PBKDF2/SHA are cheap
to parallelise. Params are stored so they can be raised over time.

**Q: What does binding the header as AAD buy you?**
Tamper-evidence for the *unencrypted* metadata — version, KDF params, salt, nonce.
Without it, an attacker could try a parameter-downgrade or header-swap; with it,
any header edit breaks the GCM tag.

**Q: Why is "wrong password" indistinguishable from "corrupt file"?**
They're the same cryptographic event (tag failure), and distinguishing them leaks
information. Both → `WrongPasswordOrCorrupt`.

**Q: How do you guarantee the vault is never half-written?**
Write to a temp file, fsync, atomic rename over the target, fsync the dir. Always
old-or-new.

**Q: What stops two concurrent runs from corrupting the vault?**
An exclusive `fd-lock` held across the whole read-modify-write.

**Q: How does the breach check avoid sending the password to a third party?**
HIBP k-anonymity: SHA-1 the password, send only the first 5 hex chars of the hash,
match the 35-char suffix locally against the returned range. The password and full
hash never leave the machine.

**Q: What are the limits of your zeroization?**
It's best-effort in-process wiping. OS swap/hibernation/core dumps may already
hold copies, and `Clone`d secrets aren't reached by `Drop`. Documented in the
threat model rather than overclaimed.

**Q: Why parse the vault file so defensively?**
It's attacker-controllable input; a panic on a malformed file is a DoS at best.
`decode` bounds-checks every field and returns `BadFormat`, proven by a test that
truncates at every offset.
