import { fail } from './errors.mjs';
import { toBytes, b64uEncode } from './bytes.mjs';

/**
 * Get a stable per-credential secret from a passkey via the WebAuthn `prf` extension. The secret exists only when the
 * authenticator is used, so nothing a server stores can be guessed offline. Use the result as the `secret` for `seal`/`open`.
 *
 * Needs a secure context and a browser/authenticator with PRF support (otherwise VaultError 'unsupported'). The user-presence
 * prompt and its cancellation surface as the browser's own DOMException (NotAllowedError); they are not wrapped.
 *
 * @param {object} options
 * @param {Uint8Array|ArrayBuffer|string} options.credentialId  the credential to use (bytes, or base64url)
 * @param {Uint8Array|ArrayBuffer|string} options.salt  application salt, 1..64 bytes; a different salt gives an unrelated secret
 * @param {string} [options.rpId]
 * @param {'required'|'preferred'|'discouraged'} [options.userVerification='preferred']
 * @param {number} [options.timeout]
 * @param {{get: Function}} [options.credentials=navigator.credentials]  injectable for tests
 * @returns {Promise<string>} the 32-byte PRF output as base64url (a string, so it satisfies the "secret is a string" rule)
 */
export async function prfFromPasskey({ credentialId, salt, rpId, userVerification = 'preferred', timeout, credentials = globalThis.navigator?.credentials } = {}) {
  if (!credentials || typeof credentials.get !== 'function') fail('unsupported', 'WebAuthn is not available in this environment');
  const id = toBytes(credentialId, 'credentialId');
  const saltBytes = toBytes(salt, 'salt');
  if (id.length === 0) throw new TypeError('credentialId must not be empty');
  if (saltBytes.length === 0 || saltBytes.length > 64) throw new TypeError('salt must be 1..64 bytes');
  const publicKey = {
    challenge: crypto.getRandomValues(new Uint8Array(32)), // the assertion is never verified server-side; PRF is the point
    allowCredentials: [{ type: 'public-key', id }],
    userVerification,
    extensions: { prf: { eval: { first: saltBytes } } },
  };
  if (rpId) publicKey.rpId = rpId;
  if (timeout) publicKey.timeout = timeout;
  const cred = await credentials.get({ publicKey });
  const first = cred?.getClientExtensionResults?.()?.prf?.results?.first;
  if (!first) fail('unsupported', 'this passkey or browser does not support the WebAuthn PRF extension');
  const out = ArrayBuffer.isView(first) ? new Uint8Array(first.buffer, first.byteOffset, first.byteLength) : new Uint8Array(first);
  if (out.length !== 32) fail('corrupt', 'unexpected PRF output length');
  return b64uEncode(out);
}
