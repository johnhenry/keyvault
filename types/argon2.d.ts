import type { Argon2idParams } from './index.js';

/** OWASP's minimum Argon2id profile (19 MiB, 2 passes, 1 lane), with optional overrides. */
export function argon2idKdf(overrides?: Partial<Omit<Argon2idParams, 'name'>>): Argon2idParams;

export interface Argon2idImplementation {
  (args: { password: Uint8Array; salt: Uint8Array; iterations: number; memoryKiB: number; parallelism: number; hashLength: number }): Promise<Uint8Array> | Uint8Array;
}
/** Register Argon2id so `seal`, `open`, `deriveKey` and `needsUpgrade` understand it. Loads the optional `hash-wasm` unless `hash` is given. */
export function enableArgon2id(options?: { hash?: Argon2idImplementation }): Promise<void>;
