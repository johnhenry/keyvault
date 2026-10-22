import { fail } from './errors.mjs';

export const te = new TextEncoder();

export function b64uEncode(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  return btoa(s).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
}

/** Strict base64url (no padding, no other alphabets). Throws VaultError('corrupt'). */
export function b64uDecode(str, what = 'value') {
  if (typeof str !== 'string' || !/^[A-Za-z0-9_-]*$/.test(str) || str.length % 4 === 1) fail('corrupt', `${what} is not base64url`);
  const s = atob(str.replaceAll('-', '+').replaceAll('_', '/'));
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

/** Uint8Array | ArrayBuffer | base64url string -> Uint8Array copy-free where possible. */
export function toBytes(v, what = 'value') {
  if (v instanceof Uint8Array) return v;
  if (v instanceof ArrayBuffer) return new Uint8Array(v);
  if (ArrayBuffer.isView(v)) return new Uint8Array(v.buffer, v.byteOffset, v.byteLength);
  if (typeof v === 'string') return b64uDecode(v, what);
  throw new TypeError(`${what} must be a Uint8Array, ArrayBuffer or base64url string`);
}

export const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
};

/**
 * Sorted-key JSON (JCS-like subset: objects, arrays, strings, booleans, null, safe integers). Identical to the
 * canonicalisation p2pws uses for its header, so p2pws files authenticate the same bytes. Throws TypeError on anything else.
 */
export function canonicalize(v) {
  if (v === null) return 'null';
  switch (typeof v) {
    case 'string': return JSON.stringify(v);
    case 'boolean': return v ? 'true' : 'false';
    case 'number':
      if (!Number.isSafeInteger(v)) throw new TypeError('only safe integers are allowed in a header');
      return String(v);
    case 'object': {
      if (Array.isArray(v)) return '[' + v.map(canonicalize).join(',') + ']';
      const proto = Object.getPrototypeOf(v);
      if (proto !== Object.prototype && proto !== null) throw new TypeError('plain objects only');
      return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canonicalize(v[k])).join(',') + '}';
    }
    default: throw new TypeError(`unsupported header value of type ${typeof v}`);
  }
}
