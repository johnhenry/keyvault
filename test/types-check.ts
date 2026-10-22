// Compiled by `npm run typecheck`; never run.
import { seal, open, openJson, needsUpgrade, defaultKdf, deriveKey, deriveLoginKeys, VaultError, P2PWS_LOGIN_KDF, prfFromPasskey } from '../types/index.js';
import { enableArgon2id, argon2idKdf } from '../types/argon2.js';

async function main() {
  const kdf = defaultKdf();
  const text: string = await seal('x', 'secret', { type: 't', header: { kid: 'k', n: 1, nested: { a: [true, null] } }, kdf });
  const r = await open(text, 'secret', { type: 't' });
  const bytes: Uint8Array = r.payload;
  const j = await openJson<{ a: number }>(text, 'secret');
  const n: number = j.payload.a;
  const up: boolean = needsUpgrade(text);
  const key: Uint8Array = await deriveKey('s', new Uint8Array(16), kdf, 'purpose', { bits: 512 });
  const { authKey, vaultKey } = await deriveLoginKeys('pw', 'c2FsdA', P2PWS_LOGIN_KDF);
  await enableArgon2id();
  await seal('x', 'secret', { type: 't', kdf: argon2idKdf({ memoryKiB: 65536 }) });
  const s: string = await prfFromPasskey({ credentialId: 'abc', salt: new Uint8Array(8) });
  try { await open('', 'x'); } catch (e) { if (e instanceof VaultError && e.code === 'corrupt') return [bytes, n, up, key, authKey, vaultKey, s]; }
}
main();
