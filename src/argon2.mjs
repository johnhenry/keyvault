// Optional Argon2id. WebCrypto has no Argon2, so this entry point drives a WASM implementation. The core never imports it.
//
//   import { enableArgon2id, argon2idKdf } from '@johnhenry/keyvault/argon2';
//   await enableArgon2id();                       // loads the optional peer dependency `hash-wasm`
//   const text = await seal(bytes, secret, { type, kdf: argon2idKdf() });
//
// Once enabled, open() reads Argon2id files and needsUpgrade() ranks Argon2id above PBKDF2.
import { fail } from './errors.mjs';
import { ARGON2ID, registerKdf, DEFAULT_LIMITS } from './kdf.mjs';

const int = (v) => typeof v === 'number' && Number.isSafeInteger(v);

/** OWASP's minimum Argon2id profile (19 MiB, 2 passes, 1 lane). A fresh object each call. */
export function argon2idKdf(overrides = {}) {
  return { name: ARGON2ID, iterations: 2, memoryKiB: 19_456, parallelism: 1, ...overrides };
}

/**
 * Register Argon2id.
 * @param {object} [options]
 * @param {(a: {password: Uint8Array, salt: Uint8Array, iterations: number, memoryKiB: number, parallelism: number, hashLength: number}) => Promise<Uint8Array>|Uint8Array} [options.hash]
 *   your own implementation (e.g. one backed by a bundled WASM build). Default: `hash-wasm`'s argon2id, imported on demand.
 */
export async function enableArgon2id({ hash } = {}) {
  let impl = hash;
  if (!impl) {
    let mod;
    try { mod = await import('hash-wasm'); } catch { fail('unsupported', "Argon2id needs the optional dependency 'hash-wasm' (npm install hash-wasm), or pass enableArgon2id({ hash })"); }
    impl = ({ password, salt, iterations, memoryKiB, parallelism, hashLength }) =>
      mod.argon2id({ password, salt, iterations, memorySize: memoryKiB, parallelism, hashLength, outputType: 'binary' });
  }
  registerKdf({
    name: ARGON2ID,
    rank: 2,
    validate(p, lim) {
      for (const k of ['iterations', 'memoryKiB', 'parallelism']) if (!int(p[k])) fail('corrupt', `kdf.${k} must be an integer`);
      const L = { ...DEFAULT_LIMITS, ...lim };
      if (p.iterations < 1 || p.iterations > L.maxArgon2Passes) fail('unsupported', `kdf.iterations ${p.iterations} is outside 1..${L.maxArgon2Passes}`);
      if (p.parallelism < 1 || p.parallelism > L.maxParallelism) fail('unsupported', `kdf.parallelism ${p.parallelism} is outside 1..${L.maxParallelism}`);
      if (p.memoryKiB < 8 * p.parallelism || p.memoryKiB > L.maxMemoryKiB) fail('unsupported', `kdf.memoryKiB ${p.memoryKiB} is outside ${8 * p.parallelism}..${L.maxMemoryKiB}`);
      return { name: ARGON2ID, iterations: p.iterations, memoryKiB: p.memoryKiB, parallelism: p.parallelism };
    },
    async derive(secret, salt, p, bits) {
      const out = await impl({ password: secret, salt, iterations: p.iterations, memoryKiB: p.memoryKiB, parallelism: p.parallelism, hashLength: bits / 8 });
      if (!(out instanceof Uint8Array) || out.length !== bits / 8) fail('corrupt', 'Argon2id implementation returned the wrong output');
      return out;
    },
    weaker: (p, t) => p.memoryKiB < t.memoryKiB || p.iterations < t.iterations,
  });
}
