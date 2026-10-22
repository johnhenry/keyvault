export type VaultErrorCode = 'bad_passphrase' | 'corrupt' | 'unsupported' | 'wrong_type' | 'weak_secret';

export class VaultError extends Error {
  constructor(code: VaultErrorCode, message?: string);
  readonly name: 'VaultError';
  readonly code: VaultErrorCode;
}
export const CODES: Readonly<Record<VaultErrorCode, VaultErrorCode>>;

/** PBKDF2 parameters. */
export interface Pbkdf2Params { name: 'PBKDF2-SHA256'; iterations: number }
/** Argon2id parameters (needs `@johnhenry/keyvault/argon2`). `iterations` is the number of passes. */
export interface Argon2idParams { name: 'Argon2id'; iterations: number; memoryKiB: number; parallelism: number }
export type KdfParams = Pbkdf2Params | Argon2idParams;

export interface Limits {
  minIterations?: number;
  maxIterations?: number;
  maxArgon2Passes?: number;
  maxMemoryKiB?: number;
  maxParallelism?: number;
}
export const DEFAULT_LIMITS: Readonly<Required<Limits>>;

/** `{ name: 'PBKDF2-SHA256', iterations: 600000 }` today. A fresh object each call. */
export function defaultKdf(): Pbkdf2Params;

export type Bytes = Uint8Array | ArrayBuffer;

export interface DeriveOptions {
  /** Output size in bits, a multiple of 8 from 128 to 512. Default 256. */
  bits?: number;
  /** Unicode-normalise the secret first. Default `false`, which is what p2pws's login derivation does. */
  normalize?: false | 'NFKC';
  limits?: Limits;
}
export function deriveKey(secret: string, salt: Bytes | string, params: KdfParams | undefined, purpose: string, options?: DeriveOptions): Promise<Uint8Array>;
export function deriveLoginKeys(password: string, salt: Bytes | string, params?: KdfParams, options?: DeriveOptions): Promise<{ authKey: string; vaultKey: string }>;
export function deriveVaultKey(passphrase: string, salt: Bytes | string, params?: KdfParams, options?: DeriveOptions): Promise<string>;
export function p2pwsLoginPurpose(name: 'auth' | 'vault' | (string & {})): string;
export const P2PWS_LOGIN_PREFIX: '\np2pws-login/';
/** `{ name: 'PBKDF2-SHA256', iterations: 310000 }`: what existing p2pws logins were derived with. */
export const P2PWS_LOGIN_KDF: Readonly<Pbkdf2Params>;

export type HeaderValue = string | number | boolean | null | HeaderValue[] | { [key: string]: HeaderValue };
export interface SealOptions {
  /** What this record is, e.g. `'p2pws-key-backup'`. Checked by `open`. */
  type: string;
  /** Extra readable, authenticated fields. Not `v`, `t`, `kdf`, `iv` or `ct`. Numbers must be safe integers. */
  header?: { [key: string]: HeaderValue };
  kdf?: KdfParams;
  /** Your password policy: refuse secrets shorter than this. Default 1. */
  minLength?: number;
  limits?: Limits;
}
export function seal(payload: Uint8Array | string, secret: string, options: SealOptions): Promise<string>;

export interface OpenOptions { type?: string; limits?: Limits }
export interface Opened<P = Uint8Array> {
  /** Authenticated fields (`v`, `t` and everything given as `header`). For browsermesh vault records: `{ t: 'browsermesh-vault' }`. */
  header: { v?: number; t: string; [key: string]: HeaderValue | undefined };
  type: string;
  kdf: KdfParams;
  payload: P;
  /** True for browsermesh VaultIdentityStorage envelopes (no header binding): re-seal them. */
  legacy: boolean;
}
export function open(input: string | object, secret: string, options?: OpenOptions): Promise<Opened>;
export function openText(input: string | object, secret: string, options?: OpenOptions): Promise<Opened<string>>;
export function openJson<T = unknown>(input: string | object, secret: string, options?: OpenOptions): Promise<Opened<T>>;
export function needsUpgrade(input: string | object, target?: KdfParams, options?: { limits?: Limits }): boolean;

export const FORMAT_VERSION: 1;
export const BROWSERMESH_VAULT: 'browsermesh-vault';

export interface PrfOptions {
  credentialId: Bytes | string;
  salt: Bytes | string;
  rpId?: string;
  userVerification?: 'required' | 'preferred' | 'discouraged';
  timeout?: number;
  credentials?: { get(options: any): Promise<any> };
}
/** The 32-byte PRF output as base64url; use it as the `secret` for `seal`/`open`. */
export function prfFromPasskey(options: PrfOptions): Promise<string>;
