# @johnhenry/keyvault

Turn a human secret (a password, a passphrase, a passkey) into keys, and seal small secrets such as private keys with them.

- **Zero runtime dependencies.** WebCrypto only. ESM. Browsers, Node >= 22 and Deno.
- **Self-describing.** The KDF name and parameters are written into every record and authenticated, so you can raise them later without orphaning old records (`needsUpgrade()`).
- **Safe on hostile input.** Iteration, memory and size caps, unknown KDFs rejected, empty / `undefined` / non-string secrets refused.
- **Compatible.** Reads (and writes) the sealed files p2pws's `backup.mjs` produces, and reads the records browsermesh's `VaultIdentityStorage` stores.

```sh
npm install @johnhenry/keyvault
```

## Quick start

```js
import { seal, open, needsUpgrade, VaultError } from '@johnhenry/keyvault';

// Seal a private key (bytes or a string). The header is readable, and tamper-proof.
const text = await seal(pkcs8Bytes, 'correct horse battery staple', {
  type: 'my-key-backup',
  header: { kid: 'abc', label: 'laptop', createdAt: Date.now() },
});
// `text` is JSON: store it anywhere.

try {
  const { header, payload } = await open(text, passphrase, { type: 'my-key-backup' });
  // payload is a Uint8Array; header.kid etc. are authenticated.
  if (needsUpgrade(text)) await save(await seal(payload, passphrase, { type: 'my-key-backup', header }));
} catch (e) {
  if (e instanceof VaultError && e.code === 'bad_passphrase') { /* ask again */ }
  else throw e;
}
```

## API

### Sealing

| Function | |
|---|---|
| `seal(payload, secret, { type, header?, kdf?, minLength? })` | `payload`: `Uint8Array` or string (at most 1 MiB). `type` is required. `header`: extra readable fields (strings, safe integers, booleans, `null`, arrays, plain objects; not `v`, `t`, `kdf`, `iv`, `ct`). `kdf` defaults to `defaultKdf()`. `minLength` is your password policy (default 1). Returns JSON text. |
| `open(text, secret, { type?, limits? })` | Resolves `{ header, type, kdf, payload: Uint8Array, legacy }`. Pass `type`: a record of another type is refused with `wrong_type` before any key derivation. `text` may also be an already-parsed object. |
| `openText(...)` / `openJson(...)` | The same, decoding `payload` as UTF-8 / JSON (`corrupt` if it is not). |
| `needsUpgrade(text, target = defaultKdf())` | `true` when the record's KDF is weaker than `target` (fewer PBKDF2 iterations; PBKDF2 vs Argon2id; less Argon2 memory or fewer passes), or it is a header-less browsermesh vault envelope. Does not decrypt. Throws `VaultError` for something that is not a valid record. |
| `defaultKdf()` | `{ name: 'PBKDF2-SHA256', iterations: 600000 }` today (OWASP's figure). A fresh object each call. |

`open()` returns `header` only after authenticating it, so its fields can be trusted, but it is still *your* data: check it the way you would any input (for example that a key id matches the key you decrypted).

### Deriving keys

```js
import { deriveKey, deriveLoginKeys, p2pwsLoginPurpose, P2PWS_LOGIN_KDF, defaultKdf } from '@johnhenry/keyvault';

// One password, two unrelated keys: authKey goes to a server (which should store only a verifier of it),
// vaultKey never leaves the device and is the `secret` for seal()/open().
const { authKey, vaultKey } = await deriveLoginKeys(password, salt, defaultKdf());

// The general primitive. `purpose` is required; keys for different purposes are unrelated.
const bytes = await deriveKey(secret, salt, defaultKdf(), 'my-app/session-key'); // Uint8Array(32)
```

`deriveKey(secret, salt, params, purpose, { bits = 256, normalize = false, limits })` runs the KDF over the salt bytes followed by the UTF-8 of `purpose`: `salt || purpose`. `salt` is bytes or a base64url string.

**p2pws compatibility.** p2pws derives its sign-in keys with salt `salt || "\np2pws-login/" + purpose`, PBKDF2-SHA256 at 310,000 iterations, no Unicode normalisation, and base64url output. `deriveLoginKeys(password, salt, P2PWS_LOGIN_KDF)` and `deriveVaultKey(...)` reproduce those keys exactly (checked against fixtures written by p2pws's own `login.mjs`), so existing logins keep working; `deriveKey(..., p2pwsLoginPurpose('auth'))` is the same thing spelled out. Move to `defaultKdf()` on the next successful sign-in.

### Normalisation

`seal`/`open` NFKC-normalise the secret, as p2pws's backups do (so a fullwidth `ｐａｓｓ` and `pass` are the same passphrase). `deriveKey` does **not** unless you pass `normalize: 'NFKC'`, because p2pws's login derivation does not. browsermesh vault records are read without normalisation, exactly as `VaultIdentityStorage` wrote them.

### Errors

Every expected failure is a `VaultError` with a stable `code`:

| code | meaning |
|---|---|
| `bad_passphrase` | Wrong secret, **or the record was modified**. AES-GCM cannot tell the two apart. |
| `corrupt` | Not JSON, truncated, wrong shape, bad base64url, ciphertext shorter than its tag, a KDF parameter of the wrong type. |
| `unsupported` | A valid shape that is refused: unknown record version, unknown KDF name, parameters outside the caps (iterations 1,000 to 10,000,000 for PBKDF2), Argon2id not enabled, payload over 1 MiB. |
| `wrong_type` | The record's `type` is not the `type` you asked for. |
| `weak_secret` | The secret is empty, `undefined`, `null`, not a string, or shorter than `minLength`. |

Mistakes in your own call (a missing `type`, a reserved or non-integer header field, an empty `purpose`) throw `TypeError` instead.

Caps can be tightened per call with `limits: { minIterations, maxIterations, maxArgon2Passes, maxMemoryKiB, maxParallelism }`.

### Argon2id (optional)

WebCrypto has no Argon2, so it lives behind a separate entry point and the core never loads it.

```js
import { enableArgon2id, argon2idKdf } from '@johnhenry/keyvault/argon2';
await enableArgon2id();                       // uses the optional peer dependency `hash-wasm`
const text = await seal(bytes, secret, { type: 'my-key-backup', kdf: argon2idKdf() }); // 19 MiB, 2 passes, 1 lane
```

`npm install hash-wasm` (a bare `import('hash-wasm')` needs a bundler or an import map in browsers), or pass your own implementation: `enableArgon2id({ hash: ({ password, salt, iterations, memoryKiB, parallelism, hashLength }) => Uint8Array })`. Until it is enabled, Argon2id records are refused with `unsupported` and a message naming this entry point. Whether Argon2id becomes `defaultKdf()` is a decision for the consuming apps; today it is opt-in.

### Passkeys

```js
import { prfFromPasskey, seal, open } from '@johnhenry/keyvault';
const secret = await prfFromPasskey({ credentialId, salt: appSalt, rpId: 'example.com' }); // base64url, 32 bytes
const text = await seal(bytes, secret, { type: 'my-key-backup' });
```

Uses the WebAuthn `prf` extension: the secret exists only when the authenticator is used, so nothing a server stores can be guessed offline. Needs a secure context and an authenticator that supports PRF (otherwise `unsupported`). Create the credential yourself with `extensions: { prf: {} }`. Because the secret is high entropy, you may pass `kdf: { name: 'PBKDF2-SHA256', iterations: 1000 }` to skip the stretching.

## File format

Plain JSON, version 1:

```json
{ "v": 1, "t": "my-key-backup",
  "kdf": { "name": "PBKDF2-SHA256", "iterations": 600000, "salt": "<base64url, 16 bytes>" },
  "kid": "...", "label": "laptop", "createdAt": 1760000000000,
  "iv": "<base64url, 12 bytes>", "ct": "<base64url AES-256-GCM ciphertext + tag>" }
```

The key is PBKDF2-HMAC-SHA256 of the NFKC-normalised secret, 256 bits. The AES-GCM additional data is the UTF-8 of the **canonical JSON** (keys sorted, safe integers only) of every field except `ct`. That is the construction p2pws's `backup.mjs` uses, so its files are valid records, and records written here with the same header fields (`kid`, `account`, `label`, `createdAt`) open with p2pws's `openBackup` / `openIdentityBundle`.

p2pws-specific rules (key ids, `acct_` ids, the 1 MiB bundle limit) are not enforced here; validate them in the application after `open()`.

Accepted from browsermesh: the `{ kdf?, iterations?, salt, iv, ciphertext }` envelope of `VaultIdentityStorage` (type `'browsermesh-vault'`, `legacy: true`), or the stored record that contains it as `encryptedPrivateKey`. `kdf` and `iterations` may be missing in old records (PBKDF2, 310,000). Those envelopes bind no header, so `needsUpgrade()` is always `true` for them.

## Security notes

- A sealed record is only as strong as its secret. The KDF slows guessing down; it does not stop it. Prefer passkeys or long passphrases, and Argon2id where WASM is acceptable.
- `bad_passphrase` also means "tampered". Do not tell users which.
- Nothing is zeroed in JavaScript memory beyond the raw derived key bytes; do not treat this as a hardware boundary.
- Payloads are capped at 1 MiB: this is for keys, not files.

## Tests

```sh
npm test                 # Node: unit cases, node:crypto cross-checks, Argon2id
npm run test:deno        # the same cases under Deno
npx playwright install chromium && npm run test:browser   # the same cases in headless Chromium, plus Argon2id and a real WebAuthn PRF round trip via a virtual authenticator
npm run typecheck
```

The cases include the RFC 6070 (PBKDF2-HMAC-SHA1, as a WebCrypto platform check) and RFC 7914 section 11 (PBKDF2-HMAC-SHA-256) vectors, round trips, tampering with every authenticated field, truncation, and hostile iteration counts, KDF names and secrets.

`test/fixtures/` holds files written by the *current* p2pws (`createBackup`, `sealIdentityBundle` for `p2pws-account-recovery` and `p2pws-identity-bundle`, `deriveLoginKeys`) and browsermesh-core `VaultIdentityStorage` code, at 1,000 and the real default 600,000 / 310,000 iterations. `test/fixtures/manifest.json` records which commit/version wrote them. To regenerate: `P2PWS_DIR=/path/to/p2pws npm run fixtures`.

## Releasing

Main is the release branch: a push to `main` whose `package.json` version is not on npm publishes it (trusted publishing, with provenance) and tags `v<version>`. Do not rename `.github/workflows/publish.yml`; the npm trusted-publisher entry is bound to that filename.

## License

MIT
