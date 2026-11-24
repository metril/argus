export interface Frame { type: number; job: number; payload: Uint8Array }

export function encodeFrame(type: number, job: number, payload: Uint8Array | string | object = new Uint8Array(0)): ArrayBuffer {
  const body = payload instanceof Uint8Array ? payload
    : new TextEncoder().encode(typeof payload === 'string' ? payload : JSON.stringify(payload));
  const out = new Uint8Array(5 + body.length);
  const dv = new DataView(out.buffer);
  dv.setUint8(0, type);
  dv.setUint32(1, job >>> 0, false);
  out.set(body, 5);
  return out.buffer;
}

export function decodeFrame(buf: ArrayBuffer | Uint8Array): Frame | null {
  const u = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  if (u.length < 5) return null;
  const dv = new DataView(u.buffer, u.byteOffset, u.byteLength);
  return { type: dv.getUint8(0), job: dv.getUint32(1, false), payload: u.subarray(5) };
}

export function payloadJson<T>(p: Uint8Array): T {
  return JSON.parse(new TextDecoder().decode(p)) as T;
}
