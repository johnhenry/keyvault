// Runs test/cases.mjs (plus Argon2id and a real WebAuthn PRF round trip) in headless Chromium via Playwright.
// Playwright's own bundled Chromium is used; a virtual authenticator with PRF is attached over CDP.
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

const root = fileURLToPath(new URL('../../', import.meta.url));
const types = { '.html': 'text/html', '.mjs': 'text/javascript', '.js': 'text/javascript', '.json': 'application/json', '.wasm': 'application/wasm' };
const server = createServer(async (req, res) => {
  try {
    const path = normalize(decodeURIComponent(new URL(req.url, 'http://x').pathname));
    if (path.includes('..')) throw new Error('no');
    const file = join(root, path === '/' ? 'test/browser/index.html' : path);
    const body = await readFile(file);
    res.writeHead(200, { 'content-type': types[extname(file)] ?? 'application/octet-stream', 'cache-control': 'no-store' }).end(body);
  } catch { res.writeHead(404).end('not found'); }
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const origin = `http://localhost:${server.address().port}`;

let failures = 0;
const check = (name, okay, detail = '') => { console.log(`${okay ? 'ok  ' : 'FAIL'} ${name}${detail ? '  ' + detail : ''}`); if (!okay) failures++; };
const browser = await chromium.launch({ headless: true });
try {
  const page = await browser.newPage();
  const errors = [];
  page.on('pageerror', (e) => errors.push(String(e)));
  page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()); });
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('WebAuthn.enable', { enableUI: false });
  await cdp.send('WebAuthn.addVirtualAuthenticator', { options: {
    protocol: 'ctap2', ctap2Version: 'ctap2_1', transport: 'internal',
    hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true,
  } });
  await page.goto(origin + '/');
  await page.waitForFunction(() => window.ready === true || window.__ENV === undefined, null, { timeout: 15000 });
  console.log(`browser: ${browser.version()}`);
  const env = await page.evaluate(() => window.__ENV);
  check('secure context with crypto.subtle', env.secure && env.subtle);

  const results = await page.evaluate(() => window.runCases());
  for (const r of results) check(r.name, r.ok, r.ok ? `${r.ms}ms` : '\n' + r.error);
  check('ran the shared cases', results.length >= 30, `${results.length} cases`);

  const a = await page.evaluate(() => window.argon2Case());
  check('Argon2id (hash-wasm) round trip in the browser', a.payload === 'hello' && a.wrong === 'bad_passphrase' && a.kdf.name === 'Argon2id', JSON.stringify(a.kdf));

  const p = await page.evaluate(() => window.passkeyCase());
  check('passkey PRF: virtual authenticator returns a stable per-salt secret', p.prfEnabled && p.same && p.different && p.length === 43 && p.opened === 'passkey sealed', JSON.stringify(p));

  check('no page errors', errors.length === 0, errors.join(' | '));
} finally {
  await browser.close();
  server.close();
}
console.log(failures ? `${failures} FAILED` : 'all browser checks passed');
process.exit(failures ? 1 : 0);
