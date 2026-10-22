// Regenerates test/fixtures/* using the CURRENT p2pws and browsermesh-core code.
//
//   P2PWS_DIR=~/Projects/p2pws node scripts/gen-fixtures.mjs
//
// P2PWS_DIR is a p2pws checkout with `npm install` done (it provides @johnhenry/p2pws-protocol and
// @johnhenry/browsermesh-core). Fixtures are committed; this script is only for regenerating them, and the tests
// never run it. Nothing in keyvault's own runtime imports any of this.
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import { join, resolve } from 'node:path';

const root = resolve(process.env.P2PWS_DIR ?? '');
if (!process.env.P2PWS_DIR) { console.error('set P2PWS_DIR to a p2pws checkout'); process.exit(1); }
const imp = (p) => import(pathToFileURL(join(root, p)).href);
const backup = await imp('packages/shell/src/new/backup.mjs');
const login = await imp('packages/shell/src/new/login.mjs');
const protocol = await imp('packages/protocol/src/index.mjs');
const bm = await imp('node_modules/@johnhenry/browsermesh-core/src/index.mjs');
const bmVersion = JSON.parse(readFileSync(join(root, 'node_modules/@johnhenry/browsermesh-core/package.json'), 'utf8')).version;
const p2pwsCommit = execFileSync('git', ['-C', root, 'rev-parse', '--short', 'HEAD']).toString().trim();

const out = new URL('../test/fixtures/', import.meta.url).pathname;
mkdirSync(out, { recursive: true });
const b64u = protocol.b64uEncode;
const manifest = {
  generatedBy: { p2pws: p2pwsCommit, 'browsermesh-core': bmVersion },
  note: 'Written by the code named above. `payload` is the expected plaintext as base64url bytes; `passphrase` opens it.',
  backups: [], logins: [],
};
const write = (name, text) => writeFileSync(join(out, name), typeof text === 'string' ? text : JSON.stringify(text, null, 2) + '\n');
const bytesOf = (s) => b64u(new TextEncoder().encode(s));

const key = await protocol.generateKey();
const pkcs8 = await protocol.exportKey(key);
const kid = key.kid;
const account = 'acct_' + b64u(new Uint8Array(16).fill(7)); // acct_ + 22 chars
const NOW = 1_760_000_000_000;

// 1. p2pws-key-backup (createBackup)
for (const [name, iterations, passphrase] of [
  ['p2pws-key-backup-600k', backup.DEFAULT_ITERATIONS, 'correct horse battery staple'],
  ['p2pws-key-backup-1k', 1000, 'correct horse battery staple'],
  ['p2pws-key-backup-nfkc-1k', 1000, 'ｐａｓｓｗｏｒｄ１２３ ✓'], // fullwidth: p2pws applies NFKC, so 'password123 ✓' opens it
]) {
  const file = await backup.createBackup({ pkcs8, kid, account, label: 'laptop' }, passphrase, { iterations, now: NOW });
  write(`${name}.json`, JSON.stringify(file, null, 2));
  manifest.backups.push({ file: `${name}.json`, format: 'p2pws', type: backup.BACKUP_TYPE, passphrase, payload: pkcs8, iterations, header: { kid, account, label: 'laptop', createdAt: NOW } });
}
{
  const file = await backup.createBackup({ pkcs8, kid }, 'no account here', { iterations: 1000, now: NOW });
  write('p2pws-key-backup-noaccount-1k.json', JSON.stringify(file, null, 2));
  manifest.backups.push({ file: 'p2pws-key-backup-noaccount-1k.json', format: 'p2pws', type: backup.BACKUP_TYPE, passphrase: 'no account here', payload: pkcs8, iterations: 1000, header: { kid, account: null, label: '', createdAt: NOW } });
}

// 2. sealIdentityBundle: both documented types
const bundlePayload = { v: 1, keys: [{ kid, pkcs8 }], note: 'fixture ✓' };
for (const [name, type, iterations] of [
  ['p2pws-account-recovery-1k', 'p2pws-account-recovery', 1000],
  ['p2pws-account-recovery-600k', 'p2pws-account-recovery', backup.DEFAULT_ITERATIONS],
  ['p2pws-identity-bundle-1k', 'p2pws-identity-bundle', 1000],
]) {
  const text = await backup.sealIdentityBundle({ kid, account, label: 'bundle' }, bundlePayload, 'a bundle passphrase', { type, iterations, now: NOW });
  write(`${name}.json`, text);
  manifest.backups.push({ file: `${name}.json`, format: 'p2pws', type, passphrase: 'a bundle passphrase', payload: bytesOf(JSON.stringify(bundlePayload)), iterations, header: { kid, account, label: 'bundle', createdAt: NOW } });
}

// 3. VaultIdentityStorage records (browsermesh-core)
const jwk = await crypto.subtle.exportKey('jwk', (await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify'])).privateKey);
for (const [name, passphrase, stripKdf] of [
  ['browsermesh-vault-310k', 'vault passphrase', false],
  ['browsermesh-vault-unicode-310k', 'ｐａｓｓ ünï ✓', false], // not normalised by VaultIdentityStorage
  ['browsermesh-vault-legacy-310k', 'vault passphrase', true], // envelope without kdf/iterations, as written before they were recorded
]) {
  const inner = new bm.InMemoryIdentityStorage();
  const vault = new bm.VaultIdentityStorage(inner, { getPassphrase: async () => passphrase });
  await vault.save('pod-1', { podId: 'pod-1', publicKey: 'AAAA', privateKeyJwk: jwk });
  const env = (await inner.load('pod-1')).encryptedPrivateKey; // a copy: the record fixture below is written before stripping
  if (stripKdf) { delete env.kdf; delete env.iterations; }
  write(`${name}.json`, JSON.stringify(env, null, 2));
  if (name === 'browsermesh-vault-310k') write('browsermesh-vault-record.json', await inner.load('pod-1')); // the whole stored record (privateKeyJwk is null, the envelope is encryptedPrivateKey)
  manifest.backups.push({ file: `${name}.json`, format: 'browsermesh-vault', type: 'browsermesh-vault', passphrase, payload: bytesOf(JSON.stringify(jwk)), iterations: 310000, legacy: stripKdf });
}

// 4. login.mjs derivations
for (const [password, salt] of [['a long login password', b64u(new Uint8Array(32).map((_, i) => i))], ['pässwörd with ünicode ✓ 123', b64u(new Uint8Array(32).fill(0xa5))]]) {
  const { authKey, vaultKey } = await login.deriveLoginKeys(password, salt);
  const external = await login.deriveVaultKey(password, salt);
  manifest.logins.push({ password, salt, iterations: 310000, authKey, vaultKey, deriveVaultKey: external });
}
write('manifest.json', manifest);
console.log('wrote fixtures for p2pws', p2pwsCommit, 'browsermesh-core', bmVersion);
