import { IDBFactory } from 'fake-indexeddb';
import { describe, expect, it } from 'vitest';
import { AtRestCipher, CryptoError, decryptWithPassphrase, encryptWithPassphrase, idbKeyStore, isEncrypted, parseEnvelope, type KeyStore } from '../lib/cookiejar/crypto';

const FAST = { iterations: 1000 };

describe('passphrase envelope', () => {
  it('round-trips and stores a versioned envelope with salt and iteration count', async () => {
    const text = JSON.stringify([{ name: 'é', value: '🍪'.repeat(50) }]);
    const env = await encryptWithPassphrase(text, 'correct horse', FAST);
    const e = parseEnvelope(env);
    expect(e).toMatchObject({ format: 'argus-encrypted-cookies', v: 1, alg: 'AES-GCM', kdf: 'PBKDF2-SHA256', iter: 1000 });
    expect(atob(e.salt)).toHaveLength(16);
    expect(env).not.toContain('🍪');
    expect(await decryptWithPassphrase(env, 'correct horse')).toBe(text);
    expect(isEncrypted(env)).toBe(true);
    expect(isEncrypted('[]')).toBe(false);
  });
  it('uses a fresh salt and iv each time', async () => {
    const a = parseEnvelope(await encryptWithPassphrase('x', 'p', FAST));
    const b = parseEnvelope(await encryptWithPassphrase('x', 'p', FAST));
    expect(a.salt).not.toBe(b.salt);
    expect(a.iv).not.toBe(b.iv);
  });
  it('a wrong passphrase or a changed file is a clean error', async () => {
    const env = await encryptWithPassphrase('secret', 'right', FAST);
    await expect(decryptWithPassphrase(env, 'wrong')).rejects.toMatchObject({ code: 'wrong-passphrase', message: 'The passphrase is wrong, or the file was changed.' });
    const e = parseEnvelope(env);
    const flipped = { ...e, ct: (e.ct[0] === 'A' ? 'B' : 'A') + e.ct.slice(1) };
    await expect(decryptWithPassphrase(JSON.stringify(flipped), 'right')).rejects.toMatchObject({ code: 'wrong-passphrase' });
    // the iteration count is authenticated through the derived key
    await expect(decryptWithPassphrase(JSON.stringify({ ...e, iter: 1001 }), 'right')).rejects.toMatchObject({ code: 'wrong-passphrase' });
    await expect(encryptWithPassphrase('x', '', FAST)).rejects.toBeInstanceOf(CryptoError);
  });
  it('rejects non-envelopes, newer versions and absurd iteration counts', async () => {
    await expect(decryptWithPassphrase('hello', 'p')).rejects.toMatchObject({ code: 'bad-envelope' });
    await expect(decryptWithPassphrase('{"format":"other"}', 'p')).rejects.toMatchObject({ code: 'bad-envelope' });
    const e = parseEnvelope(await encryptWithPassphrase('x', 'p', FAST));
    await expect(decryptWithPassphrase(JSON.stringify({ ...e, v: 2 }), 'p')).rejects.toMatchObject({ code: 'unsupported' });
    await expect(decryptWithPassphrase(JSON.stringify({ ...e, iter: 1e12 }), 'p')).rejects.toMatchObject({ code: 'bad-envelope' });
    await expect(decryptWithPassphrase(JSON.stringify({ ...e, salt: '!!!' }), 'p')).rejects.toMatchObject({ code: 'bad-envelope' });
  });
});

class MemKeys implements KeyStore {
  k?: CryptoKey; puts = 0;
  async get() { return this.k; }
  async put(k: CryptoKey) { this.k = k; this.puts++; }
}

describe('at-rest cipher', () => {
  it('seals and opens, creating one non-extractable key on first use', async () => {
    const ks = new MemKeys();
    const c = new AtRestCipher(ks);
    const [a, b] = await Promise.all([c.seal({ a: 1 }), c.seal({ b: 'é' })]);
    expect(ks.puts).toBe(1);
    expect(ks.k!.extractable).toBe(false);
    expect(await c.open(a)).toEqual({ a: 1 });
    expect(await c.open(b)).toEqual({ b: 'é' });
    expect(a.ct).not.toBe(b.ct);
    // a second cipher on the same store reads the same key
    expect(await new AtRestCipher(ks).open(a)).toEqual({ a: 1 });
  });
  it('fails cleanly when the key is gone or the data was altered', async () => {
    const ks = new MemKeys();
    const sealed = await new AtRestCipher(ks).seal({ a: 1 });
    await expect(new AtRestCipher(new MemKeys()).open(sealed)).rejects.toMatchObject({ code: 'bad-envelope' });
    await expect(new AtRestCipher(ks).open({ ...sealed, v: 2 as 1 })).rejects.toMatchObject({ code: 'unsupported' });
  });
  it('keeps the key in IndexedDB across instances', async () => {
    const factory = new IDBFactory();
    const sealed = await new AtRestCipher(idbKeyStore({ factory })).seal({ secret: true });
    const again = new AtRestCipher(idbKeyStore({ factory }));
    expect(await again.open(sealed)).toEqual({ secret: true });
    const key = await idbKeyStore({ factory }).get();
    expect(key?.extractable).toBe(false);
    // a different database has a different key
    await expect(new AtRestCipher(idbKeyStore({ factory: new IDBFactory() })).open(sealed)).rejects.toMatchObject({ code: 'bad-envelope' });
  });
  it('retries key creation after a storage failure', async () => {
    let fail = true;
    const ks: KeyStore = { get: async () => { if (fail) { fail = false; throw new Error('idb down'); } return undefined; }, put: async () => undefined };
    const c = new AtRestCipher(ks);
    await expect(c.seal(1)).rejects.toThrow('idb down');
    expect(await c.open(await c.seal(1))).toBe(1);
  });
});
