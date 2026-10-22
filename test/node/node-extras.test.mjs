// Node-only cross-checks against node:crypto, an implementation independent of WebCrypto.
import { test } from 'node:test';
import { pbkdf2Sync } from 'node:crypto';
import { deriveKey, deriveLoginKeys, P2PWS_LOGIN_KDF } from '../../src/index.mjs';
import { equal, deepEqual } from '../lib/assert.mjs';

test('deriveKey matches node:crypto pbkdf2 over salt || purpose', async () => {
  const salt = Buffer.from('0123456789abcdef');
  for (const [secret, purpose, it] of [['hunter2hunter2', 'a', 1000], ['päss ✓', '\np2pws-login/vault', 5000]]) {
    const want = pbkdf2Sync(secret, Buffer.concat([salt, Buffer.from(purpose)]), it, 32, 'sha256');
    deepEqual(await deriveKey(secret, salt, { name: 'PBKDF2-SHA256', iterations: it }, purpose), new Uint8Array(want));
  }
});

test('deriveLoginKeys matches the p2pws construction computed with node:crypto', async () => {
  const salt = Buffer.alloc(32, 0x42), pw = 'a long login password';
  const { authKey, vaultKey } = await deriveLoginKeys(pw, salt.toString('base64url'), P2PWS_LOGIN_KDF);
  equal(authKey, pbkdf2Sync(pw, Buffer.concat([salt, Buffer.from('\np2pws-login/auth')]), 310000, 32, 'sha256').toString('base64url'));
  equal(vaultKey, pbkdf2Sync(pw, Buffer.concat([salt, Buffer.from('\np2pws-login/vault')]), 310000, 32, 'sha256').toString('base64url'));
});
