# Attribution

`ferrovault` is an independent, from-scratch implementation written for my own
learning and portfolio. The problem and feature scope were inspired by the
`foundations/password-manager` project in
[`CarterPerez-dev/Cybersecurity-Projects`](https://github.com/CarterPerez-dev/Cybersecurity-Projects)
(AGPL-3.0).

**No source code, tests, or data files were copied** from that repository. The
design, code, and tests here are my own, and this project is released under the
MIT License. Where the original drew on public standards, I implemented against
those primary specifications directly:

- Argon2id — RFC 9106
- AES-GCM — NIST SP 800-38D
- TOTP — RFC 6238
- HIBP range API / k-anonymity — Have I Been Pwned API docs
