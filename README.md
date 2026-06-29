# ferrovault

An encrypted command-line password manager written in Rust: one master
password, one vault file, applied cryptography done correctly.

[![CI](https://github.com/Athology0000/ferrovault/actions/workflows/ci.yml/badge.svg)](https://github.com/Athology0000/ferrovault/actions/workflows/ci.yml)

> **Note:** The badge resolves once GitHub Actions runs on
> `github.com/Athology0000/ferrovault`.

---

## Commands

| Command | Behavior |
|---|---|
| `init` | Create a new empty vault; prompt for master password twice. |
| `add <name>` | Add an entry; prompt for username, password, optional URL and notes; `--generate`/`-g` to use a random password; `--totp <secret>` to attach a TOTP seed. |
| `get <name>` | Show one entry; `--copy` copies the password to the clipboard with auto-clear (`--timeout <secs>`, default 15). |
| `list` | Print entry names only (never passwords). |
| `delete <name>` | Remove an entry. |
| `gen [length]` | Generate and print a strong password; no vault needed; `--no-symbols` for alphanumeric only. |
| `change-password` | Rotate the master password; re-encrypt under a fresh salt and current default KDF parameters. |
| `totp <name>` | Print the current 6-digit TOTP code and seconds remaining in the window. |
| `check [name]` | HIBP k-anonymity breach check for an entry's password (or a prompted one). |

Global `--vault <path>` or `PV_VAULT` environment variable. Default:
`~/.ferrovault/vault.pvlt` (Windows: `%USERPROFILE%\.ferrovault\vault.pvlt`).

The master password is **never a CLI flag** — only hidden interactive prompts,
because flags appear in shell history and process listings.

---

## Quick demo

```sh
# Use a throwaway path so nothing touches your real vault
ferrovault --vault ./demo.pvlt init
ferrovault --vault ./demo.pvlt add github
ferrovault --vault ./demo.pvlt list
ferrovault --vault ./demo.pvlt get github --copy
ferrovault --vault ./demo.pvlt check github
rm ./demo.pvlt ./demo.pvlt.lock   # POSIX; on Windows: del demo.pvlt demo.pvlt.lock
```

---

## Security design

| Property | Mechanism |
|---|---|
| Key derivation | Argon2id, m=64 MiB, t=3, p=4; 16-byte salt from OS CSPRNG; parameters stored in vault header for forward compatibility |
| Encryption | AES-256-GCM; fresh random 12-byte nonce on every write (nonce reuse under GCM is catastrophic — a deliberate, tested invariant) |
| Header binding (AAD) | The entire binary header (magic, version, KDF id + params, salt, nonce, length) is supplied as GCM Associated Data; any header modification breaks authentication and prevents decryption |
| Vault format | Custom binary `PVLT` container; plaintext is CBOR (compact binary, no base64) |
| Secret handling | Master password, derived key, and decrypted contents are wrapped in `Zeroizing<_>` and wiped on drop (best-effort; see threat model) |
| Durable writes | Write to temp file → `fsync` → atomic `rename` → directory `fsync` (POSIX); never half-written |
| Concurrency | Advisory exclusive lock (`fd-lock`) held across the full read-modify-write; works on Windows and POSIX |
| HIBP check | SHA-1 the password; send only the 5-character hex prefix; match suffix locally — your password never leaves the machine |
| Clipboard clear | `get --copy` overwrites the clipboard after N seconds (default 15); a history manager may capture it before the overwrite — see threat model |

---

## Build & test

```sh
cargo build --release
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --all
```

Requires Rust stable (1.80+). Windows and macOS need no C build toolchain —
TLS is provided by OS-native SChannel (Windows) and Security.framework (macOS).
**Linux** links the system OpenSSL via `openssl-sys` and therefore requires a C
toolchain and OpenSSL development headers (e.g. `libssl-dev` on Debian/Ubuntu,
`openssl-devel` on Fedora).

---

## Security & scope

See [`docs/threat-model.md`](docs/threat-model.md) for a full description of
what ferrovault defends against and what it explicitly does not.

---

## Attribution

See [`ATTRIBUTION.md`](ATTRIBUTION.md).

This is an independent, from-scratch implementation. The feature scope was
inspired by `CarterPerez-dev/Cybersecurity-Projects` (AGPL-3.0); no code,
tests, or data files were copied. Released under the MIT License.
