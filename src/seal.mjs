import { fail, requireSecret, VaultError } from './errors.mjs';
import { te, b64uEncode, b64uDecode, canonicalize } from './bytes.mjs';
import { defaultKdf, validateKdf, isWeaker, PBKDF2 } from './kdf.mjs';
import { deriveBytes } from './derive.mjs';

export const FORMAT_VERSION = 1;
/** `type` reported by open() for records written by browsermesh's VaultIdentityStorage. */
export const BROWSERMESH_VAULT = 'browsermesh-vault';
const RESERVED = new Set(['v', 't', 'kdf', 'iv', 'ct']);
const SALT_BYTES = 16, IV_BYTES = 12, TAG_BYTES = 16;
const MAX_FILE_CHARS = 2 * 1024 * 1024;     // reading: a hostile blob cannot be parsed forever
const MAX_PAYLOAD_BYTES = 1024 * 1024;      // sealing: this is for keys, not files
const MAX_HEADER_CHARS = 64 * 1024;
const VAULT_DEFAULT_ITERATIONS = 310_000;   // VaultIdentityStorage's constant, used when its envelope has no `iterations`

const isObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

async function aesKey(secret, salt, params, usage, normalize) {
  const raw = await deriveBytes(secret, salt, params, 256, normalize);
  try { return await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, [usage]); } finally { raw.fill(0); }
}

function kdfToFile(params, salt) {
  const { name, ...rest } = params;
  return { name, ...rest, salt: b64uEncode(salt) };
}

/**
 * Seal a small secret under a human secret.
 *
 * The file is plain JSON: `{ v: 1, t: type, kdf: {name, ...params, salt}, ...header, iv, ct }`. Everything except `ct` is bound
 * as AES-GCM additional data, so editing the type, the KDF parameters or any header field makes `open` fail. This is
 * byte-compatible with the files p2pws's backup.mjs writes (the secret is NFKC-normalised, as there).
 *
 * @param {Uint8Array|string} payload  bytes, or a string (UTF-8). At most 1 MiB.
 * @param {string} secret  non-empty string (see `minLength`)
 * @param {object} options
 * @param {string} options.type  what this record is, e.g. 'p2pws-key-backup'. Checked by open().
 * @param {object} [options.header]  extra authenticated, readable fields (strings, safe integers, booleans, null, arrays, plain objects). Not v/t/kdf/iv/ct.
 * @param {{name: string, iterations: number}} [options.kdf]  defaults to defaultKdf()
 * @param {number} [options.minLength=1]  minimum secret length, your password policy
 * @param {object} [options.limits]  see DEFAULT_LIMITS
 * @returns {Promise<string>} JSON text
 */
export async function seal(payload, secret, options = {}) {
  const { type, header = {}, kdf, minLength = 1, limits } = options;
  requireSecret(secret, minLength);
  if (typeof type !== 'string' || type.length === 0) throw new TypeError('options.type must be a non-empty string');
  if (!isObject(header)) throw new TypeError('options.header must be an object');
  for (const k of Object.keys(header)) if (RESERVED.has(k)) throw new TypeError(`header field "${k}" is reserved`);
  const bytes = typeof payload === 'string' ? te.encode(payload) : payload;
  if (!(bytes instanceof Uint8Array)) throw new TypeError('payload must be a string or Uint8Array');
  if (bytes.length > MAX_PAYLOAD_BYTES) fail('unsupported', 'payload is larger than 1 MiB; keyvault seals keys, not files');

  const params = validateKdf(kdf ?? defaultKdf(), limits);
  const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const file = { v: FORMAT_VERSION, t: type, kdf: kdfToFile(params, salt), ...header, iv: b64uEncode(iv) };
  let aad;
  try { aad = te.encode(canonicalize(file)); } catch (e) { throw new TypeError(`header is not canonicalisable: ${e.message}`); }
  if (aad.length > MAX_HEADER_CHARS) throw new TypeError('header is too large');
  const key = await aesKey(secret, salt, params, 'encrypt', 'NFKC');
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, bytes));
  return JSON.stringify({ ...file, ct: b64uEncode(ct) }, null, 2);
}

/**
 * Parse and structurally validate a record without decrypting it. Throws VaultError. Used by open() and needsUpgrade().
 * @returns {{legacy: boolean, type: string, kdf: object, salt: Uint8Array, iv: Uint8Array, ct: Uint8Array, header: object, file: object}}
 */
export function parse(input, { limits, maxChars = MAX_FILE_CHARS } = {}) {
  let f = input;
  if (typeof input === 'string') {
    if (input.length > maxChars) fail('corrupt', 'record is too large');
    try { f = JSON.parse(input); } catch { fail('corrupt', 'not JSON (truncated or not a keyvault record)'); }
  }
  if (!isObject(f)) fail('corrupt', 'record must be a JSON object');
  // A whole VaultIdentityStorage record: the envelope is its encryptedPrivateKey.
  if (isObject(f.encryptedPrivateKey) && f.v === undefined && f.ct === undefined) f = f.encryptedPrivateKey;
  if (f.v === undefined && f.t === undefined && typeof f.ciphertext === 'string') return parseVaultEnvelope(f, limits);

  if (f.v !== FORMAT_VERSION) fail(typeof f.v === 'number' ? 'unsupported' : 'corrupt', typeof f.v === 'number' ? `unsupported record version ${f.v}` : 'not a keyvault record (no version)');
  if (typeof f.t !== 'string' || f.t.length === 0) fail('corrupt', 'record has no type');
  const kdf = validateKdf(f.kdf, limits);
  const salt = b64uDecode(f.kdf.salt, 'kdf.salt');
  if (salt.length < 8 || salt.length > 64) fail('corrupt', 'kdf.salt has a bad length');
  const iv = b64uDecode(f.iv, 'iv');
  if (iv.length !== IV_BYTES) fail('corrupt', 'iv has a bad length');
  const ct = b64uDecode(f.ct, 'ct');
  if (ct.length < TAG_BYTES) fail('corrupt', 'ciphertext is truncated');
  const { kdf: _k, iv: _i, ct: _c, ...header } = f;
  return { legacy: false, type: f.t, kdf, salt, iv, ct, header, file: f };
}

function parseVaultEnvelope(e, limits) {
  if (e.kdf !== undefined && e.kdf !== PBKDF2) fail('unsupported', 'unsupported key derivation function in vault record');
  const kdf = validateKdf({ name: PBKDF2, iterations: e.iterations ?? VAULT_DEFAULT_ITERATIONS }, limits);
  const salt = b64uDecode(e.salt, 'salt');
  if (salt.length < 8 || salt.length > 64) fail('corrupt', 'salt has a bad length');
  const iv = b64uDecode(e.iv, 'iv');
  if (iv.length !== IV_BYTES) fail('corrupt', 'iv has a bad length');
  const ct = b64uDecode(e.ciphertext, 'ciphertext');
  if (ct.length < TAG_BYTES) fail('corrupt', 'ciphertext is truncated');
  return { legacy: true, type: BROWSERMESH_VAULT, kdf, salt, iv, ct, header: { t: BROWSERMESH_VAULT }, file: e };
}

/**
 * Open a record written by `seal`, by p2pws's backup.mjs (types p2pws-key-backup, p2pws-identity-bundle,
 * p2pws-account-recovery), or by browsermesh's VaultIdentityStorage (type 'browsermesh-vault'; the envelope or the whole record).
 *
 * Header fields come back only after authentication, so they can be trusted (browsermesh vault envelopes have no header).
 * Apply your own checks to them (e.g. that a key id matches the decrypted key).
 *
 * @param {string|object} input  the JSON text (or parsed object)
 * @param {string} secret
 * @param {{type?: string, limits?: object}} [options]  `type`: refuse (wrong_type) anything else. Pass it.
 * @returns {Promise<{header: object, type: string, kdf: object, payload: Uint8Array, legacy: boolean}>}
 * @throws {VaultError} weak_secret | corrupt | unsupported | wrong_type | bad_passphrase
 */
export async function open(input, secret, options = {}) {
  requireSecret(secret);
  const { type, limits } = options;
  if (type !== undefined && typeof type !== 'string') throw new TypeError('options.type must be a string');
  const r = parse(input, { limits });
  if (type !== undefined && r.type !== type) fail('wrong_type', `this is a ${JSON.stringify(r.type.slice(0, 60))} record, not ${JSON.stringify(type)}`);
  const params = { name: 'AES-GCM', iv: r.iv };
  if (!r.legacy) {
    const { ct, ...rest } = r.file;
    try { params.additionalData = te.encode(canonicalize(rest)); } catch { fail('corrupt', 'record header is not canonical'); }
  }
  // Vault envelopes were written without header binding and without NFKC; keep reading them exactly as written.
  const key = await aesKey(secret, r.salt, r.kdf, 'decrypt', r.legacy ? false : 'NFKC');
  let payload;
  try { payload = new Uint8Array(await crypto.subtle.decrypt(params, key, r.ct)); } catch { fail('bad_passphrase', 'wrong secret, or the record was modified'); }
  return { header: r.header, type: r.type, kdf: { ...r.kdf }, payload, legacy: r.legacy };
}

/** `open`, decoding the payload as UTF-8 text. */
export async function openText(input, secret, options) {
  const r = await open(input, secret, options);
  try { return { ...r, payload: new TextDecoder('utf-8', { fatal: true }).decode(r.payload) }; } catch { fail('corrupt', 'payload is not UTF-8 text'); }
}

/** `open`, decoding the payload as JSON. */
export async function openJson(input, secret, options) {
  const r = await openText(input, secret, options);
  try { return { ...r, payload: JSON.parse(r.payload) }; } catch { fail('corrupt', 'payload is not JSON'); }
}

/**
 * True when the record should be re-sealed: its KDF is weaker than `target` (default `defaultKdf()`), or it is a
 * browsermesh vault envelope (no header binding). Does not decrypt, so call it before or after a successful open().
 * @param {string|object} input
 * @param {{name: string, iterations: number}} [target]
 */
export function needsUpgrade(input, target = defaultKdf(), options = {}) {
  const r = parse(input, options);
  if (r.legacy) return true;
  return isWeaker(r.kdf, validateKdf(target, options.limits));
}

export { VaultError };
