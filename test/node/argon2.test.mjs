import { test } from 'node:test';
import * as nodeCrypto from 'node:crypto';
import { seal, open, needsUpgrade, defaultKdf, deriveKey, VaultError } from '../../src/index.mjs';
import { enableArgon2id, argon2idKdf } from '../../src/argon2.mjs';
import { b64uDecode } from '../../src/bytes.mjs';
import { ok, equal, deepEqual, rejectsCode } from '../lib/assert.mjs';

const LOW = argon2idKdf({ iterations: 1, memoryKiB: 64, parallelism: 1 });
const FAST = { name: 'PBKDF2-SHA256', iterations: 1000 };
const code = (p, c, m) => rejectsCode(p, c, VaultError, m);

await enableArgon2id();

test('Argon2id round trip through hash-wasm; the file is self-describing', async () => {
  const text = await seal('payload', 'correct horse', { type: 't', header: { kid: 'k' }, kdf: LOW });
  const f = JSON.parse(text);
  deepEqual({ ...f.kdf, salt: undefined }, { name: 'Argon2id', iterations: 1, memoryKiB: 64, parallelism: 1, salt: undefined });
  const r = await open(text, 'correct horse', { type: 't' });
  equal(new TextDecoder().decode(r.payload), 'payload');
  deepEqual(r.kdf, LOW);
  await code(open(text, 'wrong horse', { type: 't' }), 'bad_passphrase');
  const bad = JSON.parse(text); bad.kdf.memoryKiB = 128;
  await code(open(JSON.stringify(bad), 'correct horse', { type: 't' }), 'bad_passphrase', 'kdf parameters are authenticated');
});

test('Argon2id output equals node:crypto argon2 when the runtime has it', { skip: typeof nodeCrypto.argon2Sync !== 'function' && 'node:crypto.argon2Sync needs Node >= 24.7' }, async () => {
  const salt = new Uint8Array(16).fill(7);
  const got = await deriveKey('hunter2hunter2', salt, { name: 'Argon2id', iterations: 3, memoryKiB: 256, parallelism: 2 }, 'purpose');
  const full = Buffer.concat([Buffer.from(salt), Buffer.from('purpose')]);
  const want = nodeCrypto.argon2Sync('argon2id', { message: 'hunter2hunter2', nonce: full, parallelism: 2, tagLength: 32, memory: 256, passes: 3 });
  deepEqual(got, new Uint8Array(want));
});

test('Argon2id hostile parameters are refused before allocating', async () => {
  const base = JSON.parse(await seal('x', 'secret!!', { type: 't', kdf: LOW }));
  const t0 = Date.now();
  for (const patch of [{ memoryKiB: 4 * 1024 * 1024 }, { memoryKiB: 262_145 }, { memoryKiB: 0 }, { memoryKiB: 7 }, { iterations: 0 }, { iterations: 21 }, { iterations: 1e9 }, { parallelism: 0 }, { parallelism: 17 }]) {
    const f = { ...base, kdf: { ...base.kdf, ...patch } };
    await code(open(JSON.stringify(f), 'secret!!', { type: 't' }), 'unsupported', JSON.stringify(patch));
  }
  for (const patch of [{ memoryKiB: '64' }, { iterations: 1.5 }, { parallelism: null }, { memoryKiB: undefined }]) {
    await code(open(JSON.stringify({ ...base, kdf: { ...base.kdf, ...patch } }), 'secret!!', { type: 't' }), 'corrupt', JSON.stringify(patch));
  }
  ok(Date.now() - t0 < 1000);
  await code(seal('x', 'secret!!', { type: 't', kdf: argon2idKdf({ memoryKiB: 1 << 30 }) }), 'unsupported');
  await code(open(JSON.stringify(base), 'secret!!', { type: 't', limits: { maxMemoryKiB: 32 } }), 'unsupported', 'caller can tighten');
});

test('needsUpgrade ranks Argon2id above PBKDF2 and compares its cost', async () => {
  const pb = await seal('x', 'secret!!', { type: 't', kdf: FAST });
  const ar = await seal('x', 'secret!!', { type: 't', kdf: LOW });
  equal(needsUpgrade(pb, LOW), true, 'pbkdf2 file, argon2 target');
  equal(needsUpgrade(ar, defaultKdf()), false, 'argon2 file is not weaker than pbkdf2');
  equal(needsUpgrade(ar, LOW), false);
  equal(needsUpgrade(ar, argon2idKdf()), true, 'less memory/passes than the target');
  equal(needsUpgrade(ar, argon2idKdf({ iterations: 1, memoryKiB: 32 })), false);
});

test('a custom Argon2 implementation can be injected and its output size is checked', async () => {
  const { enableArgon2id: again } = await import('../../src/argon2.mjs');
  await again({ hash: () => new Uint8Array(5) });
  await code(seal('x', 'secret!!', { type: 't', kdf: LOW }), 'corrupt', 'wrong-size output');
  await again(); // restore hash-wasm
  equal(b64uDecode(JSON.parse(await seal('x', 'secret!!', { type: 't', kdf: LOW })).iv).length, 12);
});
