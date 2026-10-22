// Runtime-neutral test cases: run by test/node/core.test.mjs (Node, and Deno via `deno test`) and by the browser page.
// `env` supplies the one thing that differs per runtime: loading fixtures. Nothing here touches the filesystem.
import * as kv from '../src/index.mjs';
import { pbkdf2Bits } from '../src/kdf.mjs';
import { b64uEncode, b64uDecode } from '../src/bytes.mjs';
import { ok, equal, deepEqual, notEqual, rejectsCode, rejectsType, hex, unhex } from './lib/assert.mjs';

const { VaultError, seal, open, openText, openJson, needsUpgrade, defaultKdf, deriveKey, deriveLoginKeys, deriveVaultKey, P2PWS_LOGIN_KDF, p2pwsLoginPurpose, prfFromPasskey } = kv;
const te = new TextEncoder(), td = new TextDecoder();
const FAST = { name: 'PBKDF2-SHA256', iterations: 1000 };
const code = (p, c, msg) => rejectsCode(p, c, VaultError, msg);
const edit = (text, fn) => { const o = JSON.parse(text); fn(o); return JSON.stringify(o); };

export function makeCases(env) {
  const cases = [];
  const test = (name, run) => cases.push({ name, run });
  const load = async () => (env.manifest ??= JSON.parse(await env.fixture('manifest.json')));

  // ---- known-answer vectors --------------------------------------------------------------------------------------
  test('RFC 6070 PBKDF2-HMAC-SHA1 vectors (WebCrypto platform check)', async () => {
    const v = [
      ['password', 'salt', 1, 20, '0c60c80f961f0e71f3a9b524af6012062fe037a6'],
      ['password', 'salt', 2, 20, 'ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957'],
      ['password', 'salt', 4096, 20, '4b007901b765489abead49d926f721d065a429c1'],
      ['passwordPASSWORDpassword', 'saltSALTsaltSALTsaltSALTsaltSALTsalt', 4096, 25, '3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038'],
      ['pass\0word', 'sa\0lt', 4096, 16, '56fa6aa75548099dcc37d7f03425e0c3'],
    ];
    for (const [p, s, c, len, want] of v) equal(hex(await pbkdf2Bits(te.encode(p), te.encode(s), c, len * 8, 'SHA-1')), want, `c=${c}`);
  });

  test('RFC 7914 section 11 PBKDF2-HMAC-SHA-256 vectors (the KDF keyvault uses)', async () => {
    equal(hex(await pbkdf2Bits(te.encode('passwd'), te.encode('salt'), 1, 512)),
      '55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783');
    equal(hex(await pbkdf2Bits(te.encode('Password'), te.encode('NaCl'), 80000, 512)),
      '4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d');
  });

  // ---- domain separation -----------------------------------------------------------------------------------------
  test('deriveKey is PBKDF2 over salt || purpose, 32 bytes, and purposes are unrelated', async () => {
    const salt = unhex('000102030405060708090a0b0c0d0e0f');
    const a = await deriveKey('hunter2hunter2', salt, FAST, 'purpose-a');
    equal(a.length, 32);
    // independent construction: salt || utf8(purpose), straight through the KDF
    const want = await pbkdf2Bits(te.encode('hunter2hunter2'), new Uint8Array([...salt, ...te.encode('purpose-a')]), 1000, 256);
    deepEqual(a, want);
    deepEqual(await deriveKey('hunter2hunter2', salt, FAST, 'purpose-a'), a, 'deterministic');
    notEqual(await deriveKey('hunter2hunter2', salt, FAST, 'purpose-b'), a, 'purpose');
    notEqual(await deriveKey('hunter2hunter2', unhex('ff' + '01020304050607080910111213141516'), FAST, 'purpose-a'), a, 'salt');
    notEqual(await deriveKey('hunter2hunter3', salt, FAST, 'purpose-a'), a, 'secret');
    deepEqual(await deriveKey('hunter2hunter2', b64uEncode(salt), FAST, 'purpose-a'), a, 'base64url salt');
    equal((await deriveKey('hunter2hunter2', salt, FAST, 'p', { bits: 512 })).length, 64);
  });

  test('deriveKey validates its inputs', async () => {
    const salt = new Uint8Array(16);
    await rejectsType(deriveKey('secret!!', salt, FAST, ''), TypeError, 'empty purpose');
    await rejectsType(deriveKey('secret!!', salt, FAST, undefined), TypeError, 'no purpose');
    await rejectsType(deriveKey('secret!!', salt, FAST, 'p', { bits: 100 }), TypeError, 'bits');
    await rejectsType(deriveKey('secret!!', 12345, FAST, 'p'), TypeError, 'salt type');
    await code(deriveKey('secret!!', 'not base64url!', FAST, 'p'), 'corrupt', 'salt text');
    await code(deriveKey('secret!!', salt, { name: 'PBKDF2-SHA256', iterations: 50_000_000 }, 'p'), 'unsupported', 'cap');
    await code(deriveKey('secret!!', salt, { name: 'scrypt', iterations: 1 }, 'p'), 'unsupported', 'unknown kdf');
  });

  test('p2pws login derivation is reproduced exactly (fixtures from login.mjs)', async () => {
    const m = await load();
    ok(m.logins.length >= 2);
    for (const l of m.logins) {
      const { authKey, vaultKey } = await deriveLoginKeys(l.password, l.salt, P2PWS_LOGIN_KDF);
      equal(authKey, l.authKey, 'authKey');
      equal(vaultKey, l.vaultKey, 'vaultKey');
      equal(await deriveVaultKey(l.password, l.salt, P2PWS_LOGIN_KDF), l.deriveVaultKey, 'deriveVaultKey');
      notEqual(authKey, vaultKey);
      equal(b64uDecode(authKey).length, 32);
      // the same thing spelled out through the public primitive
      equal(b64uEncode(await deriveKey(l.password, l.salt, P2PWS_LOGIN_KDF, '\np2pws-login/auth')), l.authKey);
      equal(p2pwsLoginPurpose('auth'), '\np2pws-login/auth');
    }
  });

  test('deriveLoginKeys defaults to defaultKdf and differs from the legacy 310k keys', async () => {
    const m = await load();
    const l = m.logins[0];
    const now = await deriveLoginKeys(l.password, l.salt, FAST);
    notEqual(now.authKey, l.authKey);
    notEqual(now.vaultKey, l.vaultKey);
  });

  test('defaultKdf is self-describing, PBKDF2 at 600,000, and a fresh object', () => {
    deepEqual(defaultKdf(), { name: 'PBKDF2-SHA256', iterations: 600000 });
    ok(defaultKdf() !== defaultKdf());
    const k = defaultKdf(); k.iterations = 1; equal(defaultKdf().iterations, 600000);
  });

  // ---- compatibility fixtures -----------------------------------------------------------------------------------
  test('open() reads every committed fixture written by p2pws and VaultIdentityStorage', async () => {
    const m = await load();
    ok(m.backups.length >= 10, 'fixtures present');
    const seen = new Set();
    for (const f of m.backups) {
      const text = await env.fixture(f.file);
      const r = await open(text, f.passphrase, { type: f.type });
      equal(b64uEncode(r.payload), f.payload, f.file);
      equal(r.type, f.type, f.file);
      equal(r.kdf.name, 'PBKDF2-SHA256');
      equal(r.kdf.iterations, f.iterations, f.file);
      equal(r.legacy, f.format === 'browsermesh-vault', f.file);
      if (f.header) for (const [k, v] of Object.entries(f.header)) deepEqual(r.header[k], v, `${f.file} header.${k}`);
      seen.add(f.type);
    }
    for (const t of ['p2pws-key-backup', 'p2pws-account-recovery', 'p2pws-identity-bundle', 'browsermesh-vault']) ok(seen.has(t), `fixture for ${t}`);
  });

  test('p2pws passphrases are NFKC-normalised (fullwidth fixture opens with the ASCII form)', async () => {
    const m = await load();
    const f = m.backups.find((b) => b.file === 'p2pws-key-backup-nfkc-1k.json');
    equal(f.passphrase.normalize('NFKC') !== f.passphrase, true, 'fixture is non-trivial');
    const r = await open(await env.fixture(f.file), f.passphrase.normalize('NFKC'), { type: f.type });
    equal(b64uEncode(r.payload), f.payload);
  });

  test('browsermesh vault records are NOT normalised, exactly as VaultIdentityStorage reads them', async () => {
    const m = await load();
    const f = m.backups.find((b) => b.file === 'browsermesh-vault-unicode-310k.json');
    const text = await env.fixture(f.file);
    await code(open(text, f.passphrase.normalize('NFKC'), { type: f.type }), 'bad_passphrase');
    equal(b64uEncode((await open(text, f.passphrase, { type: f.type })).payload), f.payload);
  });

  test('a whole VaultIdentityStorage record (not just the envelope) opens', async () => {
    const m = await load();
    const f = m.backups.find((b) => b.file === 'browsermesh-vault-310k.json');
    const record = JSON.parse(await env.fixture('browsermesh-vault-record.json'));
    ok(record.encryptedPrivateKey && record.privateKeyJwk === null, 'is a stored record');
    const r = await open(record, f.passphrase, { type: 'browsermesh-vault' });
    equal(b64uEncode(r.payload), f.payload);
    const j = await openJson(JSON.stringify(record), f.passphrase);
    equal(j.payload.kty, 'OKP');
  });

  test('openText and openJson decode the payload', async () => {
    const m = await load();
    const f = m.backups.find((b) => b.file === 'p2pws-account-recovery-1k.json');
    const j = await openJson(await env.fixture(f.file), f.passphrase, { type: f.type });
    equal(j.payload.note, 'fixture ✓');
    const t = await openText(await env.fixture(f.file), f.passphrase, { type: f.type });
    equal(typeof t.payload, 'string');
    const bin = await seal(new Uint8Array([0xff, 0xfe, 0xfd]), 'secret!!', { type: 'x', kdf: FAST });
    await code(openText(bin, 'secret!!'), 'corrupt', 'not utf8');
    await code(openJson(await seal('not json', 'secret!!', { type: 'x', kdf: FAST }), 'secret!!'), 'corrupt', 'not json');
  });

  test('wrong passphrase and wrong type are told apart', async () => {
    const m = await load();
    const bundle = m.backups.find((b) => b.file === 'p2pws-identity-bundle-1k.json');
    const text = await env.fixture(bundle.file);
    await code(open(text, 'definitely not it', { type: bundle.type }), 'bad_passphrase');
    await code(open(text, bundle.passphrase, { type: 'p2pws-key-backup' }), 'wrong_type');
    const vault = m.backups.find((b) => b.format === 'browsermesh-vault');
    await code(open(await env.fixture(vault.file), vault.passphrase, { type: 'p2pws-key-backup' }), 'wrong_type');
    // type is checked before any key derivation, so a wrong type is cheap even on a 600k file
    const t0 = Date.now();
    await code(open(await env.fixture('p2pws-key-backup-600k.json'), 'x'.repeat(12), { type: 'other' }), 'wrong_type');
    ok(Date.now() - t0 < 200, 'wrong_type must not run the KDF');
  });

  // ---- needsUpgrade -------------------------------------------------------------------------------------------
  test('needsUpgrade: weaker iterations, legacy vault envelopes, custom targets', async () => {
    const m = await load();
    const text = (n) => env.fixture(n);
    equal(needsUpgrade(await text('p2pws-key-backup-1k.json')), true, '1k < 600k');
    equal(needsUpgrade(await text('p2pws-key-backup-600k.json')), false, '600k is current');
    equal(needsUpgrade(await text('p2pws-account-recovery-600k.json')), false);
    equal(needsUpgrade(await text('browsermesh-vault-310k.json')), true, 'vault envelopes lack header binding');
    equal(needsUpgrade(JSON.parse(await text('browsermesh-vault-record.json'))), true);
    equal(needsUpgrade(await text('p2pws-key-backup-600k.json'), { name: 'PBKDF2-SHA256', iterations: 1_000_000 }), true, 'target raised');
    equal(needsUpgrade(await text('p2pws-key-backup-1k.json'), FAST), false, 'target equal');
    const mine = await seal('x', 'secret!!', { type: 't', kdf: FAST });
    equal(needsUpgrade(mine), true);
    equal(needsUpgrade(mine, FAST), false);
    ok(m);
  });

  test('needsUpgrade refuses what open would refuse', async () => {
    const good = await seal('x', 'secret!!', { type: 't', kdf: FAST });
    for (const bad of ['', 'nope', '[]', 'null', '{}', JSON.stringify({ v: 9, t: 'a' })]) {
      let threw = false;
      try { needsUpgrade(bad); } catch (e) { threw = e instanceof VaultError; }
      ok(threw, `needsUpgrade(${bad})`);
    }
    equal(needsUpgrade(good, FAST), false);
    await code(Promise.resolve().then(() => needsUpgrade(edit(good, (o) => { o.kdf.iterations = 99_000_000; }))), 'unsupported');
  });

  // ---- round trips ----------------------------------------------------------------------------------------------
  test('seal/open round trip: bytes, string, empty, binary, unicode, header', async () => {
    const header = { kid: 'abc', account: null, label: 'laptop ✓', createdAt: 1760000000000, nested: { a: [1, 2, { b: true }] } };
    for (const payload of [new Uint8Array([0, 1, 2, 255]), new Uint8Array(0), 'hello ✓', crypto.getRandomValues(new Uint8Array(4096))]) {
      const text = await seal(payload, 'correct horse', { type: 'my-type', header, kdf: FAST });
      const f = JSON.parse(text);
      equal(f.v, 1); equal(f.t, 'my-type');
      deepEqual(f.kdf.name, 'PBKDF2-SHA256'); equal(f.kdf.iterations, 1000);
      equal(b64uDecode(f.kdf.salt).length, 16); equal(b64uDecode(f.iv).length, 12);
      const r = await open(text, 'correct horse', { type: 'my-type' });
      deepEqual(r.payload, typeof payload === 'string' ? te.encode(payload) : payload);
      deepEqual(r.header, { v: 1, t: 'my-type', ...header });
      deepEqual(r.kdf, FAST);
      equal(r.legacy, false);
    }
  });

  test('every seal uses a fresh salt and iv', async () => {
    const a = JSON.parse(await seal('x', 'secret!!', { type: 't', kdf: FAST })), b = JSON.parse(await seal('x', 'secret!!', { type: 't', kdf: FAST }));
    notEqual(a.kdf.salt, b.kdf.salt); notEqual(a.iv, b.iv); notEqual(a.ct, b.ct);
  });

  test('open accepts a parsed object as well as text, and seal defaults to defaultKdf()', async () => {
    const text = await seal('x', 'secret!!', { type: 't' });
    equal(JSON.parse(text).kdf.iterations, 600000);
    equal(td.decode((await open(JSON.parse(text), 'secret!!', { type: 't' })).payload), 'x');
    equal(needsUpgrade(text), false);
  });

  test('the secret is NFKC-normalised when sealing (as p2pws backups are)', async () => {
    const text = await seal('x', 'ｐａｓｓｗｏｒｄ１２３', { type: 't', kdf: FAST });
    equal(td.decode((await open(text, 'password123', { type: 't' })).payload), 'x');
  });

  test('seal enforces the caller’s minimum length and refuses oversized payloads / bad headers', async () => {
    await code(seal('x', 'short', { type: 't', kdf: FAST, minLength: 8 }), 'weak_secret');
    await code(seal(new Uint8Array(1024 * 1024 + 1), 'secret!!', { type: 't', kdf: FAST }), 'unsupported');
    for (const k of ['v', 't', 'kdf', 'iv', 'ct']) await rejectsType(seal('x', 'secret!!', { type: 't', kdf: FAST, header: { [k]: 1 } }), TypeError, k);
    await rejectsType(seal('x', 'secret!!', { type: 't', kdf: FAST, header: { n: 1.5 } }), TypeError, 'float');
    await rejectsType(seal('x', 'secret!!', { type: 't', kdf: FAST, header: { n: undefined } }), TypeError, 'undefined');
    await rejectsType(seal('x', 'secret!!', { kdf: FAST }), TypeError, 'no type');
    await rejectsType(seal(42, 'secret!!', { type: 't', kdf: FAST }), TypeError, 'payload type');
    await code(seal('x', 'secret!!', { type: 't', kdf: { name: 'PBKDF2-SHA256', iterations: 20_000_000 } }), 'unsupported', 'seal cap');
  });

  // ---- tampering ----------------------------------------------------------------------------------------------
  test('tampering with ANY authenticated field fails: header, type, kdf, iv, extra fields, ciphertext', async () => {
    const text = await seal('payload', 'correct horse', { type: 't', header: { kid: 'k1', label: 'a' }, kdf: FAST });
    equal(td.decode((await open(text, 'correct horse', { type: 't' })).payload), 'payload', 'control');
    const flip = (s) => s.slice(0, 5) + (s[5] === 'A' ? 'B' : 'A') + s.slice(6);
    const tampers = {
      'header field': (o) => { o.kid = 'k2'; },
      'header field removed': (o) => { delete o.label; },
      'extra field added': (o) => { o.admin = true; },
      'iterations': (o) => { o.kdf.iterations = 1001; },
      'salt': (o) => { o.kdf.salt = flip(o.kdf.salt); },
      'iv': (o) => { o.iv = flip(o.iv); },
      'ciphertext': (o) => { o.ct = flip(o.ct); },
      // flip a bit in the decoded last byte (the end of the GCM tag); editing a base64url character can be a no-op
      'tag (last byte)': (o) => { const b = b64uDecode(o.ct); b[b.length - 1] ^= 0x01; o.ct = b64uEncode(b); },
    };
    for (const [name, fn] of Object.entries(tampers)) await code(open(edit(text, fn), 'correct horse', { type: 't' }), 'bad_passphrase', name);
    // changing the type is caught by the type check; without one it is caught by authentication
    await code(open(edit(text, (o) => { o.t = 'u'; }), 'correct horse', { type: 't' }), 'wrong_type');
    await code(open(edit(text, (o) => { o.t = 'u'; }), 'correct horse'), 'bad_passphrase');
  });

  test('tampering with a committed p2pws fixture fails too (header is AAD there as well)', async () => {
    const m = await load();
    const f = m.backups.find((b) => b.file === 'p2pws-key-backup-1k.json');
    const text = await env.fixture(f.file);
    for (const fn of [(o) => { o.label = 'evil'; }, (o) => { o.account = null; }, (o) => { o.createdAt += 1; }, (o) => { o.kid = o.kid.slice(0, -1) + (o.kid.endsWith('A') ? 'B' : 'A'); }, (o) => { o.kdf.iterations = 1001; }]) {
      await code(open(edit(text, fn), f.passphrase, { type: f.type }), 'bad_passphrase');
    }
  });

  test('a swapped-in ciphertext from another record does not open', async () => {
    const a = JSON.parse(await seal('aaaa', 'secret!!', { type: 't', kdf: FAST }));
    const b = JSON.parse(await seal('bbbb', 'secret!!', { type: 't', kdf: FAST }));
    await code(open(JSON.stringify({ ...a, ct: b.ct }), 'secret!!', { type: 't' }), 'bad_passphrase');
  });

  test('tampering with a browsermesh vault envelope fails', async () => {
    const m = await load();
    const f = m.backups.find((b) => b.file === 'browsermesh-vault-310k.json');
    const text = await env.fixture(f.file);
    await code(open(edit(text, (o) => { o.iterations = 310001; }), f.passphrase), 'bad_passphrase');
    await code(open(edit(text, (o) => { o.ciphertext = o.ciphertext.slice(0, 8) + (o.ciphertext[8] === 'A' ? 'B' : 'A') + o.ciphertext.slice(9); }), f.passphrase), 'bad_passphrase');
  });

  // ---- truncation / malformed -------------------------------------------------------------------------------
  test('truncation: cut-off text, short ciphertext, short iv/salt', async () => {
    const text = await seal('payload', 'correct horse', { type: 't', kdf: FAST });
    for (const n of [0, 1, 10, Math.floor(text.length / 2), text.length - 1]) await code(open(text.slice(0, n), 'correct horse'), 'corrupt', `text cut at ${n}`);
    const o = JSON.parse(text);
    await code(open(edit(text, (x) => { x.ct = x.ct.slice(0, 10); }), 'correct horse'), 'corrupt', 'ct shorter than the tag');
    await code(open(edit(text, (x) => { x.ct = ''; }), 'correct horse'), 'corrupt', 'empty ct');
    await code(open(edit(text, (x) => { x.ct = x.ct.slice(0, -4); }), 'correct horse'), 'bad_passphrase', 'ct missing its last bytes (tag fails)');
    await code(open(edit(text, (x) => { x.iv = x.iv.slice(0, -4); }), 'correct horse'), 'corrupt', 'short iv');
    await code(open(edit(text, (x) => { x.kdf.salt = x.kdf.salt.slice(0, 4); }), 'correct horse'), 'corrupt', 'short salt');
    await code(open(edit(text, (x) => { x.kdf.salt = 'x'.repeat(200); }), 'correct horse'), 'corrupt', 'long salt');
    ok(o.ct.length > 16);
    // same for a vault envelope
    const m = await load();
    const vf = await env.fixture('browsermesh-vault-310k.json');
    await code(open(vf.slice(0, vf.length - 20), m.backups[0].passphrase), 'corrupt');
    await code(open(edit(vf, (x) => { x.ciphertext = x.ciphertext.slice(0, 10); }), 'vault passphrase'), 'corrupt');
  });

  test('not-a-record inputs are corrupt; unknown versions are unsupported', async () => {
    for (const bad of ['', ' ', 'garbage', '{', 'null', '1', '"x"', '[]', '{}', '{"v":1}', '{"v":1,"t":""}', '{"t":"x"}', '{"v":"1","t":"x"}']) await code(open(bad, 'secret!!'), 'corrupt', JSON.stringify(bad));
    for (const bad of [null, undefined, 5, [], 'x'.repeat(2 * 1024 * 1024 + 1)]) await code(open(bad, 'secret!!'), 'corrupt', `input ${typeof bad}`);
    const text = await seal('x', 'secret!!', { type: 't', kdf: FAST });
    await code(open(edit(text, (o) => { o.v = 2; }), 'secret!!'), 'unsupported', 'v2');
    await code(open(edit(text, (o) => { o.v = 0; }), 'secret!!'), 'unsupported', 'v0');
    await code(open(edit(text, (o) => { delete o.kdf; }), 'secret!!'), 'corrupt', 'no kdf');
    await code(open(edit(text, (o) => { o.kdf = 'PBKDF2-SHA256'; }), 'secret!!'), 'corrupt', 'kdf not object');
    await code(open(edit(text, (o) => { o.kdf = null; }), 'secret!!'), 'corrupt', 'kdf null');
    await code(open(edit(text, (o) => { o.iv = 5; }), 'secret!!'), 'corrupt', 'iv not string');
    await code(open(edit(text, (o) => { o.header = { n: 1.5 }; }), 'secret!!'), 'corrupt', 'non-canonical header');
  });

  // ---- hostile parameters ---------------------------------------------------------------------------------------
  test('hostile iteration counts are refused before any work is done', async () => {
    const text = await seal('x', 'secret!!', { type: 't', kdf: FAST });
    const t0 = Date.now();
    for (const it of [10_000_001, 2 ** 31, 2 ** 53 - 1, 1e12, 999, 1, 0, -1, -1000000]) {
      await code(open(edit(text, (o) => { o.kdf.iterations = it; }), 'secret!!', { type: 't' }), 'unsupported', `iterations ${it}`);
    }
    for (const it of ['600000', 1.5, NaN, Infinity, null, undefined, true, [], {}, 2 ** 53]) {
      await code(open(edit(text, (o) => { o.kdf.iterations = it; }), 'secret!!', { type: 't' }), 'corrupt', `iterations ${String(it)}`);
    }
    ok(Date.now() - t0 < 1000, 'refusals must not run the KDF');
    // the caller can tighten the cap
    await code(open(text, 'secret!!', { type: 't', limits: { maxIterations: 999 } }), 'unsupported', 'caller cap');
    // the cap itself is inclusive: 10,000,000 is allowed by validation (we do not run it here, just check needsUpgrade parses it)
    equal(needsUpgrade(edit(text, (o) => { o.kdf.iterations = 10_000_000; })), false);
  });

  test('hostile vault envelope iteration counts are capped too (browsermesh envelopes had no cap)', async () => {
    const vf = await env.fixture('browsermesh-vault-310k.json');
    for (const it of [10_000_001, 2 ** 40, 0, -5]) await code(open(edit(vf, (o) => { o.iterations = it; }), 'vault passphrase'), 'unsupported', `vault ${it}`);
    await code(open(edit(vf, (o) => { o.iterations = '310000'; }), 'vault passphrase'), 'corrupt');
    await code(open(edit(vf, (o) => { o.kdf = 'scrypt'; }), 'vault passphrase'), 'unsupported');
  });

  test('unknown or malformed KDF names are unsupported/corrupt, never derived with', async () => {
    const text = await seal('x', 'secret!!', { type: 't', kdf: FAST });
    for (const name of ['scrypt', 'PBKDF2', 'pbkdf2-sha256', 'PBKDF2-SHA1', 'PBKDF2-SHA512', 'bcrypt', '', '__proto__', 'constructor', 'toString', 'hasOwnProperty', 'x'.repeat(10_000)]) {
      await code(open(edit(text, (o) => { o.kdf.name = name; }), 'secret!!', { type: 't' }), 'unsupported', JSON.stringify(name.slice(0, 20)));
    }
    for (const name of [null, undefined, 5, {}, []]) await code(open(edit(text, (o) => { o.kdf.name = name; }), 'secret!!', { type: 't' }), 'corrupt', String(name));
    const e = await code(open(edit(text, (o) => { o.kdf.name = 'x'.repeat(10_000); }), 'secret!!'), 'unsupported');
    ok(e.message.length < 200, 'error messages do not echo hostile input in full');
  });

  test('Argon2id records are unsupported until the argon2 entry point is enabled', async () => {
    const text = await seal('x', 'secret!!', { type: 't', kdf: FAST });
    const fake = edit(text, (o) => { o.kdf = { name: 'Argon2id', iterations: 2, memoryKiB: 19456, parallelism: 1, salt: o.kdf.salt }; });
    const e = await code(open(fake, 'secret!!', { type: 't' }), 'unsupported');
    ok(/keyvault\/argon2/.test(e.message), 'tells the caller what to import');
    await code(seal('x', 'secret!!', { type: 't', kdf: { name: 'Argon2id', iterations: 2, memoryKiB: 19456, parallelism: 1 } }), 'unsupported');
  });

  // ---- bad secrets ------------------------------------------------------------------------------------------------
  test('empty, undefined, null and non-string secrets are refused everywhere', async () => {
    const text = await seal('x', 'secret!!', { type: 't', kdf: FAST });
    const salt = new Uint8Array(16);
    for (const bad of ['', undefined, null, 0, 1, true, {}, [], ['abc'], new Uint8Array([1, 2, 3]), Symbol.iterator, () => 'x']) {
      const label = bad === '' ? "''" : typeof bad === 'symbol' ? 'symbol' : String(typeof bad === 'function' ? 'fn' : JSON.stringify(bad));
      await code(seal('x', bad, { type: 't', kdf: FAST }), 'weak_secret', `seal ${label}`);
      await code(open(text, bad, { type: 't' }), 'weak_secret', `open ${label}`);
      await code(deriveKey(bad, salt, FAST, 'p'), 'weak_secret', `deriveKey ${label}`);
      await code(deriveLoginKeys(bad, salt, FAST), 'weak_secret', `deriveLoginKeys ${label}`);
      await code(deriveVaultKey(bad, salt, FAST), 'weak_secret', `deriveVaultKey ${label}`);
    }
    // a secret that is merely the text "undefined" is a real (if poor) secret; it must not equal "no secret"
    await code(open(text, 'undefined', { type: 't' }), 'bad_passphrase');
  });

  // ---- errors -------------------------------------------------------------------------------------------------
  test('VaultError has a stable name, code and the five documented codes', () => {
    const e = new VaultError('corrupt', 'm');
    ok(e instanceof Error); equal(e.name, 'VaultError'); equal(e.code, 'corrupt'); equal(e.message, 'm');
    deepEqual(Object.keys(kv.CODES).sort(), ['bad_passphrase', 'corrupt', 'unsupported', 'weak_secret', 'wrong_type']);
    ok(Object.isFrozen(kv.CODES));
  });

  // ---- passkey PRF ------------------------------------------------------------------------------------------
  test('prfFromPasskey asks for the PRF extension and returns the first result as base64url', async () => {
    let seen;
    const out = new Uint8Array(32).map((_, i) => i + 1);
    const credentials = { get: async (o) => { seen = o; return { getClientExtensionResults: () => ({ prf: { results: { first: out.buffer } } }) }; } };
    const s = await prfFromPasskey({ credentialId: new Uint8Array([9, 9, 9]), salt: 'c2FsdA', rpId: 'example.test', credentials });
    equal(s, b64uEncode(out));
    equal(seen.publicKey.rpId, 'example.test');
    deepEqual(seen.publicKey.allowCredentials[0].id, new Uint8Array([9, 9, 9]));
    deepEqual(seen.publicKey.extensions.prf.eval.first, te.encode('salt'));
    equal(seen.publicKey.challenge.length, 32);
    // the output works as a seal secret
    const text = await seal('p', s, { type: 't', kdf: FAST });
    equal(td.decode((await open(text, s, { type: 't' })).payload), 'p');
  });

  test('prfFromPasskey: no PRF support, no WebAuthn, bad arguments', async () => {
    const none = { get: async () => ({ getClientExtensionResults: () => ({}) }) };
    await code(prfFromPasskey({ credentialId: new Uint8Array(4), salt: new Uint8Array(4), credentials: none }), 'unsupported');
    await code(prfFromPasskey({ credentialId: new Uint8Array(4), salt: new Uint8Array(4), credentials: {} }), 'unsupported');
    const short = { get: async () => ({ getClientExtensionResults: () => ({ prf: { results: { first: new Uint8Array(8) } } }) }) };
    await code(prfFromPasskey({ credentialId: new Uint8Array(4), salt: new Uint8Array(4), credentials: short }), 'corrupt');
    await rejectsType(prfFromPasskey({ credentialId: new Uint8Array(0), salt: new Uint8Array(4), credentials: none }), TypeError);
    await rejectsType(prfFromPasskey({ credentialId: new Uint8Array(4), salt: new Uint8Array(0), credentials: none }), TypeError);
    await rejectsType(prfFromPasskey({ credentialId: new Uint8Array(4), salt: new Uint8Array(65), credentials: none }), TypeError);
  });

  return cases;
}
