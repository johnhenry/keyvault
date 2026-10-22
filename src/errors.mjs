/**
 * Every failure a caller is expected to handle is a VaultError with one of these stable codes.
 * Programmer mistakes (wrong argument types for options, for example) throw TypeError instead.
 */
export const CODES = Object.freeze({
  /** Wrong secret, or the file was modified (AES-GCM cannot tell the two apart). */
  bad_passphrase: 'bad_passphrase',
  /** Not a keyvault/p2pws/browsermesh record, truncated, or structurally invalid. */
  corrupt: 'corrupt',
  /** Valid shape but something we refuse: unknown version or KDF, parameters outside the accepted limits, KDF not enabled. */
  unsupported: 'unsupported',
  /** The record's `t` is not the type the caller asked for. */
  wrong_type: 'wrong_type',
  /** The secret is empty, undefined, not a string, or shorter than the caller's minimum. */
  weak_secret: 'weak_secret',
});

export class VaultError extends Error {
  /** @param {keyof typeof CODES} code @param {string} [message] */
  constructor(code, message) {
    super(message ?? code);
    this.name = 'VaultError';
    this.code = code;
  }
}

export const fail = (code, message) => { throw new VaultError(code, message); };

/**
 * Refuse a secret that would not protect anything. PBKDF2 accepts an empty key and TextEncoder renders `undefined` as the
 * bytes "undefined", so either would produce a well-formed ciphertext that anyone can open.
 * @returns {string}
 */
export function requireSecret(secret, minLength = 1, what = 'secret') {
  if (typeof secret !== 'string') fail('weak_secret', `${what} must be a string, got ${secret === null ? 'null' : typeof secret}`);
  if (secret.length === 0) fail('weak_secret', `${what} must not be empty`);
  if (secret.length < minLength) fail('weak_secret', `${what} must be at least ${minLength} characters`);
  return secret;
}
