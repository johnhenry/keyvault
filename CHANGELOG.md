# Changelog

All notable changes to `@johnhenry/keyvault`. Format follows [Keep a Changelog](https://keepachangelog.com/); versions follow semver (0.x: minor bumps may break).

## [0.1.0] - Unreleased

First release. Consolidates the password-based crypto that p2pws (`backup.mjs`, `login.mjs`) and
`@johnhenry/browsermesh-core` (`VaultIdentityStorage`) each carried a copy of.

### Added
- `seal()` / `open()` / `openText()` / `openJson()`: PBKDF2-SHA256 (600,000 by default) to AES-256-GCM. The whole header, including the KDF parameters, is AES-GCM additional data. Byte-compatible with p2pws's `v: 1` backup files in both directions.
- `open()` also reads browsermesh `VaultIdentityStorage` envelopes (and whole stored records), exactly as that class reads them (no Unicode normalisation, no header binding).
- `needsUpgrade()`: true when a record's KDF is weaker than `defaultKdf()` (or a target you pass), or it is a header-less browsermesh vault envelope.
- `deriveKey()` with an explicit domain-separation `purpose`; `deriveLoginKeys()` / `deriveVaultKey()` reproduce p2pws's `salt || "\np2pws-login/" + purpose` derivation exactly (`P2PWS_LOGIN_KDF` = its 310,000 iterations).
- `VaultError` with stable codes `bad_passphrase`, `corrupt`, `unsupported`, `wrong_type`, `weak_secret`.
- Caps on hostile input: PBKDF2 iterations 1,000 to 10,000,000, Argon2id memory/passes/lanes, unknown KDF names, oversized records and payloads, empty / undefined / non-string secrets.
- `prfFromPasskey()`: a secret from a passkey via the WebAuthn PRF extension.
- Optional `@johnhenry/keyvault/argon2`: Argon2id through `hash-wasm` (optional peer dependency) or your own implementation.
- Zero runtime dependencies; ESM; browsers, Node >= 22, Deno. TypeScript declarations.
- Tests in Node, Deno and headless Chromium (Playwright), with fixtures written by the current p2pws and browsermesh-core code.
