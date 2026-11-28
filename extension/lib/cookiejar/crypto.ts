/** Passphrase-encrypted exports and at-rest encryption for stored snapshots (WebCrypto, AES-GCM). */

export type CryptoErrorCode = 'wrong-passphrase' | 'bad-envelope' | 'unsupported' | 'unavailable';

export class CryptoError extends Error {
  constructor(readonly code: CryptoErrorCode, message: string) {
    super(message);
    this.name = 'CryptoError';
  }
}

export const ENVELOPE_FORMAT = 'argus-encrypted-cookies';
export const ENVELOPE_VERSION = 1;
export const DEFAULT_ITERATIONS = 600_000;
const MAX_ITERATIONS = 5_000_000;
const AAD = new TextEncoder().encode(`${ENVELOPE_FORMAT}/${ENVELOPE_VERSION}`);

/** The versioned envelope of a passphrase-encrypted export (JSON text). */
export interface Envelope {
  format: typeof ENVELOPE_FORMAT;
  v: number;
  alg: 'AES-GCM';
  kdf: 'PBKDF2-SHA256';
  /** PBKDF2 iterations, stored so the cost can be raised later without breaking old files. */
  iter: number;
  salt: string;
  iv: string;
  ct: string;
}

const subtle = (): SubtleCrypto => {
  const s = globalThis.crypto?.subtle;
  if (!s) throw new CryptoError('unavailable', 'This browser context has no encryption support.');
  return s;
};

export function b64(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s);
}
export function unb64(s: string): Uint8Array<ArrayBuffer> {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
const rand = (n: number): Uint8Array<ArrayBuffer> => globalThis.crypto.getRandomValues(new Uint8Array(n));

async function passKey(pass: string, salt: Uint8Array<ArrayBuffer>, iter: number): Promise<CryptoKey> {
  const base = await subtle().importKey('raw', new TextEncoder().encode(pass), 'PBKDF2', false, ['deriveKey']);
  return subtle().deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: iter }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

/** Encrypts `text` with a key derived from `passphrase`; returns the envelope as JSON text. */
export async function encryptWithPassphrase(text: string, passphrase: string, o: { iterations?: number } = {}): Promise<string> {
  if (!passphrase) throw new CryptoError('wrong-passphrase', 'Enter a passphrase.');
  const iter = o.iterations ?? DEFAULT_ITERATIONS;
  const salt = rand(16), iv = rand(12);
  const key = await passKey(passphrase, salt, iter);
  const ct = new Uint8Array(await subtle().encrypt({ name: 'AES-GCM', iv, additionalData: AAD }, key, new TextEncoder().encode(text)));
  const env: Envelope = { format: ENVELOPE_FORMAT, v: ENVELOPE_VERSION, alg: 'AES-GCM', kdf: 'PBKDF2-SHA256', iter, salt: b64(salt), iv: b64(iv), ct: b64(ct) };
  return JSON.stringify(env);
}

export function parseEnvelope(text: string): Envelope {
  let e: Partial<Envelope>;
  try { e = JSON.parse(text.trim()); } catch { throw new CryptoError('bad-envelope', 'This is not an encrypted Argus export.'); }
  if (!e || e.format !== ENVELOPE_FORMAT) throw new CryptoError('bad-envelope', 'This is not an encrypted Argus export.');
  if (e.v !== ENVELOPE_VERSION || e.alg !== 'AES-GCM' || e.kdf !== 'PBKDF2-SHA256') throw new CryptoError('unsupported', 'This export was made by a newer version of Argus.');
  if (typeof e.iter !== 'number' || !(e.iter >= 1 && e.iter <= MAX_ITERATIONS) || typeof e.salt !== 'string' || typeof e.iv !== 'string' || typeof e.ct !== 'string') {
    throw new CryptoError('bad-envelope', 'This encrypted export is damaged.');
  }
  return e as Envelope;
}

/** Whether text is an encrypted Argus export. */
export function isEncrypted(text: string): boolean {
  try { parseEnvelope(text); return true; } catch { return false; }
}

/** Decrypts an envelope; a wrong passphrase or altered file is a clean `wrong-passphrase` error. */
export async function decryptWithPassphrase(text: string, passphrase: string): Promise<string> {
  const e = parseEnvelope(text);
  let salt: Uint8Array<ArrayBuffer>, iv: Uint8Array<ArrayBuffer>, ct: Uint8Array<ArrayBuffer>;
  try { salt = unb64(e.salt); iv = unb64(e.iv); ct = unb64(e.ct); } catch { throw new CryptoError('bad-envelope', 'This encrypted export is damaged.'); }
  const key = await passKey(passphrase, salt, e.iter);
  try {
    return new TextDecoder().decode(await subtle().decrypt({ name: 'AES-GCM', iv, additionalData: AAD }, key, ct));
  } catch {
    throw new CryptoError('wrong-passphrase', 'The passphrase is wrong, or the file was changed.');
  }
}

// -- at rest ------------------------------------------------------------------------------

/** Where the non-extractable snapshot key lives. */
export interface KeyStore {
  get(): Promise<CryptoKey | undefined>;
  put(key: CryptoKey): Promise<void>;
}

const req = <T>(r: IDBRequest<T>): Promise<T> => new Promise((ok, no) => { r.onsuccess = () => ok(r.result); r.onerror = () => no(r.error); });

/** The key in IndexedDB (structured-cloned, so the raw bytes are never readable by script). */
export function idbKeyStore(o: { dbName?: string; factory?: IDBFactory } = {}): KeyStore {
  const name = o.dbName ?? 'argus-cookiejar';
  const open = (): Promise<IDBDatabase> => {
    const f = o.factory ?? globalThis.indexedDB;
    if (!f) return Promise.reject(new CryptoError('unavailable', 'This browser context has no IndexedDB.'));
    const r = f.open(name, 1);
    r.onupgradeneeded = () => { r.result.createObjectStore('keys'); };
    return req(r);
  };
  return {
    async get() {
      const db = await open();
      try { return (await req(db.transaction('keys').objectStore('keys').get('snapshots'))) as CryptoKey | undefined; } finally { db.close(); }
    },
    async put(key) {
      const db = await open();
      try {
        const tx = db.transaction('keys', 'readwrite');
        tx.objectStore('keys').put(key, 'snapshots');
        await new Promise<void>((ok, no) => { tx.oncomplete = () => ok(); tx.onerror = () => no(tx.error); tx.onabort = () => no(tx.error); });
      } finally { db.close(); }
    },
  };
}

/** What is stored for one sealed value. */
export interface Sealed {
  v: 1;
  iv: string;
  ct: string;
}

/** Encrypts snapshot data under a non-extractable AES-GCM key created on first use. */
export class AtRestCipher {
  private key?: Promise<CryptoKey>;
  constructor(private readonly store: KeyStore) {}

  private getKey(): Promise<CryptoKey> {
    this.key ??= (async () => {
      const have = await this.store.get();
      if (have) return have;
      const k = await subtle().generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
      await this.store.put(k);
      return k;
    })().catch((e) => { this.key = undefined; throw e; });
    return this.key;
  }

  async seal(value: unknown): Promise<Sealed> {
    const iv = rand(12);
    const ct = new Uint8Array(await subtle().encrypt({ name: 'AES-GCM', iv }, await this.getKey(), new TextEncoder().encode(JSON.stringify(value))));
    return { v: 1, iv: b64(iv), ct: b64(ct) };
  }

  async open<T>(s: Sealed): Promise<T> {
    if (!s || s.v !== 1) throw new CryptoError('unsupported', 'This snapshot was saved by a newer version of Argus.');
    try {
      return JSON.parse(new TextDecoder().decode(await subtle().decrypt({ name: 'AES-GCM', iv: unb64(s.iv) }, await this.getKey(), unb64(s.ct)))) as T;
    } catch (e) {
      if (e instanceof CryptoError) throw e;
      throw new CryptoError('bad-envelope', 'This snapshot cannot be decrypted; its key may have been cleared.');
    }
  }
}
