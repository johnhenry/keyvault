// Tiny assertion helpers that run unchanged in Node, Deno and the browser.
export const hex = (b) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
export const unhex = (h) => new Uint8Array(h.match(/../g).map((x) => parseInt(x, 16)));
const norm = (v) => JSON.stringify(v, (_, x) => (x instanceof Uint8Array ? { bytes: hex(x) } : x));

export function ok(v, msg = 'expected truthy') { if (!v) throw new Error(msg); }
export function equal(a, b, msg) { if (a !== b) throw new Error(`${msg ?? 'not equal'}: ${String(a)} !== ${String(b)}`); }
export function deepEqual(a, b, msg) { if (norm(a) !== norm(b)) throw new Error(`${msg ?? 'not deep equal'}: ${norm(a)} !== ${norm(b)}`); }
export function notEqual(a, b, msg) { if (a === b || norm(a) === norm(b)) throw new Error(`${msg ?? 'expected different values'}: ${norm(a)}`); }

/** The promise (or function returning one) must reject with a VaultError carrying `code`. */
export async function rejectsCode(p, code, VaultError, msg = '') {
  try { await (typeof p === 'function' ? p() : p); } catch (e) {
    if (!(e instanceof VaultError)) throw new Error(`${msg} expected VaultError(${code}), got ${e?.name}: ${e?.message}`);
    if (e.code !== code) throw new Error(`${msg} expected code ${code}, got ${e.code}: ${e.message}`);
    return e;
  }
  throw new Error(`${msg} expected VaultError(${code}), but it resolved`);
}
export async function rejectsType(p, Type, msg = '') {
  try { await (typeof p === 'function' ? p() : p); } catch (e) { if (e instanceof Type) return e; throw new Error(`${msg} expected ${Type.name}, got ${e?.name}: ${e?.message}`); }
  throw new Error(`${msg} expected ${Type.name}, but it resolved`);
}
