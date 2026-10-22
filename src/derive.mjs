import { fail, requireSecret } from './errors.mjs';
import { te, toBytes, concat, b64uEncode } from './bytes.mjs';
import { defaultKdf, validateKdf, kdfOf } from './kdf.mjs';

/** The domain-separation prefix p2pws uses for its sign-in keys: salt || "\np2pws-login/" + purpose. */
export const P2PWS_LOGIN_PREFIX = '\np2pws-login/';
/** The `purpose` string that reproduces p2pws's login derivation for `name` ('auth' or 'vault'). */
export const p2pwsLoginPurpose = (name) => P2PWS_LOGIN_PREFIX + name;
/** The PBKDF2 parameters p2pws's login.mjs used before keyvault. Pass these to derive the same keys as existing logins. */
export const P2PWS_LOGIN_KDF = Object.freeze({ name: 'PBKDF2-SHA256', iterations: 310_000 });

const NORMALIZE = new Set([false, 'NFKC']);

/** @returns {Promise<Uint8Array>} the raw derived bytes. Callers own (and should wipe) them. */
export async function deriveBytes(secret, saltBytes, params, bits, normalize = false) {
  if (!NORMALIZE.has(normalize)) throw new TypeError("normalize must be false or 'NFKC'");
  const kdf = kdfOf(params);
  return kdf.derive(te.encode(normalize ? secret.normalize(normalize) : secret), saltBytes, params, bits);
}

/**
 * Stretch a human secret into a 32-byte key, domain-separated by `purpose`.
 *
 * The bytes actually fed to the KDF as salt are `salt || utf8(purpose)`. Two different purposes therefore give unrelated keys
 * from the same secret and salt. `purpose` is required and is used verbatim, so p2pws's exact construction is
 * `deriveKey(pw, salt, params, p2pwsLoginPurpose('auth'))`.
 *
 * The secret is used exactly as given (no Unicode normalisation) unless `options.normalize` is `'NFKC'`; this matches
 * p2pws's login derivation, which does not normalise. Sealing (`seal`/`open`) always applies NFKC, as p2pws backups do.
 *
 * @param {string} secret
 * @param {Uint8Array|ArrayBuffer|string} salt bytes, or a base64url string
 * @param {{name: string, iterations: number}} [params] defaults to defaultKdf()
 * @param {string} purpose non-empty domain-separation string
 * @param {{bits?: number, normalize?: false|'NFKC', limits?: object}} [options]
 * @returns {Promise<Uint8Array>}
 */
export async function deriveKey(secret, salt, params, purpose, options = {}) {
  requireSecret(secret);
  if (typeof purpose !== 'string' || purpose.length === 0) throw new TypeError('purpose must be a non-empty string');
  const p = validateKdf(params ?? defaultKdf(), options.limits);
  const bits = options.bits ?? 256;
  if (!Number.isInteger(bits) || bits < 128 || bits > 512 || bits % 8) throw new TypeError('bits must be a multiple of 8 between 128 and 512');
  const saltBytes = concat(toBytes(salt, 'salt'), te.encode(purpose));
  return deriveBytes(secret, saltBytes, p, bits, options.normalize ?? false);
}

/**
 * From one password derive an `authKey` (send it to a server, which should keep only a verifier of it) and a `vaultKey`
 * (never sent; use it as the secret for `seal`). The two are unrelated. Both are base64url strings of 32 bytes.
 *
 * Existing p2pws logins were derived with 310,000 iterations: pass `P2PWS_LOGIN_KDF` to reproduce them, and re-seal with
 * `defaultKdf()` on the next successful sign-in.
 *
 * @example const { authKey, vaultKey } = await deriveLoginKeys('correct horse battery', salt, P2PWS_LOGIN_KDF);
 */
export async function deriveLoginKeys(password, salt, params = defaultKdf(), options = {}) {
  requireSecret(password, 1, 'password');
  const [authKey, vaultKey] = await Promise.all(['auth', 'vault'].map(async (n) => b64uEncode(await deriveKey(password, salt, params, p2pwsLoginPurpose(n), options))));
  return { authKey, vaultKey };
}

/** Only the vault half of `deriveLoginKeys` (p2pws's `deriveVaultKey`, for external logins). */
export async function deriveVaultKey(passphrase, salt, params = defaultKdf(), options = {}) {
  requireSecret(passphrase, 1, 'passphrase');
  return b64uEncode(await deriveKey(passphrase, salt, params, p2pwsLoginPurpose('vault'), options));
}
