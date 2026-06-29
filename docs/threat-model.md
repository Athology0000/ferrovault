# Threat Model

`ferrovault` is a single-user, single-vault encrypted password manager. This
document states honestly what it does and does not protect against.

---

## What ferrovault defends against

**Vault theft at rest.**
The vault file is encrypted with AES-256-GCM using a key derived from the
master password via Argon2id (m=64 MiB, t=3, p=4). An attacker who steals
the vault file and does not know the master password gains nothing readable.

**Tampering with the vault or its header.**
The entire binary header (magic, version, KDF id, KDF parameters, salt, nonce,
ciphertext length) is bound as GCM Associated Data (AAD). Any modification to
any header field — including a downgrade of the Argon2 parameters — breaks
authentication and the vault cannot be opened. The 16-byte GCM tag covers both
header and ciphertext.

**Power loss mid-write.**
Writes use a write-to-temp → fsync → atomic rename sequence. The vault is
always either the old complete version or the new complete version; a power
failure during a write cannot produce a half-written vault.

**Concurrent writers.**
An advisory exclusive lock (`fd-lock`, cross-platform) is held for the entire
read-modify-write cycle. Two concurrent `ferrovault` processes cannot race to
corrupt the vault.

**Predictable randomness.**
Salts (16 bytes), nonces (12 bytes), and generated passwords all come from the
OS CSPRNG (`OsRng`). No seeded or weak PRNG is used anywhere.

---

## What ferrovault does NOT defend against

**A compromised host while you are using it.**
If malware, a keylogger, or a memory scraper is running while you type your
master password or while the decrypted vault is in memory, ferrovault offers
no protection. It is designed to protect data at rest, not on a live infected
machine.

**Memory captured via swap, hibernation, or core dumps.**
ferrovault zeroes secrets on drop (master password, derived key, decrypted
plaintext) using the `zeroize` crate. However, zeroization is best-effort:
the OS may have already paged memory to disk (swap/hibernation) or written a
core dump before the destructor runs, and there is no way to erase those
copies from user space. This limitation is stated plainly rather than
overclaimed.

**Weak master passwords.**
Argon2id with its configured parameters raises the computational cost per
guess but cannot rescue a trivially guessable password. Choose a strong,
unique master password.

**Clipboard history managers.**
`get --copy` overwrites the clipboard after the configured timeout (default 15
seconds). However, a running clipboard history manager may have already
captured the value before the overwrite, and ferrovault cannot prevent that
from user space.

**Binary tampering.**
If an attacker can modify the `ferrovault` binary itself, all bets are off.
Binary integrity is outside the scope of this tool.

---

## Out of scope (by design, not oversight)

- Cloud sync, browser extensions, GUI, multi-user sharing, per-entry
  encryption (single-vault design is explicit; see design spec §1).
- The master password is never accepted as a CLI flag or environment variable —
  flags appear in shell history and process listings; ferrovault uses hidden
  interactive prompts only.
