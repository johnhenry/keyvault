// KDF registry. PBKDF2-SHA256 is built in (WebCrypto). Argon2id is registered by '@johnhenry/keyvault/argon2'.
// Every KDF parameter set that is read from untrusted input passes through `validateKdf`, which enforces the caps.
import { fail } from './errors.mjs';

export const PBKDF2 = 'PBKDF2-SHA256';
export const ARGON2ID = 'Argon2id';

/** Hard defaults for what a file may ask of this machine. Callers can pass tighter (or looser) `limits`. */
export const DEFAULT_LIMITS = Object.freeze({
  minIterations: 1000,        // floor when reading; below this a "KDF" is no protection at all
  maxIterations: 10_000_000,  // PBKDF2 cap: a hostile file cannot hang the tab (p2pws's cap)
  maxArgon2Passes: 20,
  maxMemoryKiB: 262_144,      // 256 MiB: Argon2 cap, so a hostile file cannot exhaust memory
  maxParallelism: 16,
});

const int = (v) => typeof v === 'number' && Number.isSafeInteger(v);

/** Raw PBKDF2 over WebCrypto. `hash` is only ever 'SHA-256' in the public API; SHA-1 exists so RFC 6070 can be checked. */
export async function pbkdf2Bits(secret, salt, iterations, bits, hash = 'SHA-256') {
  const base = await crypto.subtle.importKey('raw', secret, 'PBKDF2', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash, salt, iterations }, base, bits));
}

const registry = new Map();

registry.set(PBKDF2, {
  name: PBKDF2,
  rank: 1,
  validate(p, lim) {
    if (!int(p.iterations)) fail('corrupt', 'kdf.iterations must be an integer');
    if (p.iterations < lim.minIterations || p.iterations > lim.maxIterations) {
      fail('unsupported', `kdf.iterations ${p.iterations} is outside the accepted range ${lim.minIterations}..${lim.maxIterations}`);
    }
    return { name: PBKDF2, iterations: p.iterations };
  },
  derive: (secret, salt, p, bits) => pbkdf2Bits(secret, salt, p.iterations, bits),
  weaker: (p, target) => p.iterations < target.iterations,
});

/** Used by '@johnhenry/keyvault/argon2'. `impl(secret, salt, params, bits) -> Promise<Uint8Array>`. */
export function registerKdf(def) { registry.set(def.name, def); }
export const hasKdf = (name) => registry.has(name);

/** The parameters new files are written with today. A fresh object each call. */
export function defaultKdf() { return { name: PBKDF2, iterations: 600_000 }; }

/**
 * Validate KDF parameters from anywhere (a file, a caller). Returns a clean copy without `salt`.
 * @throws {VaultError} corrupt (wrong shape), unsupported (unknown name / outside limits / not enabled)
 */
export function validateKdf(params, limits) {
  if (!params || typeof params !== 'object' || Array.isArray(params)) fail('corrupt', 'kdf must be an object');
  if (typeof params.name !== 'string') fail('corrupt', 'kdf.name must be a string');
  const def = registry.get(params.name);
  if (!def) {
    fail('unsupported', params.name === ARGON2ID
      ? "Argon2id is not enabled: import '@johnhenry/keyvault/argon2' and call enableArgon2id() first"
      : `unknown key derivation function ${JSON.stringify(String(params.name).slice(0, 40))}`);
  }
  return def.validate(params, { ...DEFAULT_LIMITS, ...limits });
}

export const kdfOf = (params) => registry.get(params.name);

/** Is `params` (validated) weaker than `target` (validated)? Different KDFs are ranked: Argon2id beats PBKDF2. */
export function isWeaker(params, target) {
  const a = kdfOf(params), b = kdfOf(target);
  if (a.rank !== b.rank) return a.rank < b.rank;
  return a.weaker(params, target);
}
