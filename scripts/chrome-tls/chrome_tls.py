#!/usr/bin/env python3
"""Capture a real Chrome's TLS ClientHello and turn it into a test fixture.

    chrome_tls.py capture --chrome /path/to/chrome --out caps.jsonl [-n 12]
    chrome_tls.py fixture --in caps.jsonl --label 156 --out crates/proxy-core/tests/fixtures/chrome-tls/chrome-156.json

`capture` runs a tiny local TCP listener that records the first TLS record of every connection (no
certificate, no third party) and launches the browser at it N times with a throwaway profile.
`fixture` checks the samples agree with each other and writes the comparable view of the
ClientHello that `crates/proxy-core/tests/chrome_tls_tests.rs` pins. See docs/UPSTREAM-TLS.md.
"""
import argparse, hashlib, json, os, socket, struct, subprocess, tempfile, threading, time


def is_grease(v):
    return (v & 0x0F0F) == 0x0A0A and (v >> 8) == (v & 0xFF)


def u16s(b):
    return [struct.unpack('>H', b[i:i + 2])[0] for i in range(0, len(b), 2)]


def hx(v):
    return '%04x' % v


def gh(v):
    return 'GREASE' if is_grease(v) else hx(v)


def protos(d):
    out, i = [], 0
    while i < len(d):
        out.append(d[i + 1:i + 1 + d[i]].decode('latin1'))
        i += 1 + d[i]
    return out


def parse(rec):
    assert rec[0] == 22 and rec[5] == 1, 'not a ClientHello'
    b = rec[9:]
    p = 2 + 32
    p += 1 + b[p]
    cl = struct.unpack('>H', b[p:p + 2])[0]
    p += 2
    ciphers = u16s(b[p:p + cl])
    p += cl
    p += 1 + b[p]
    el = struct.unpack('>H', b[p:p + 2])[0]
    p += 2
    end, exts = p + el, []
    while p < end:
        t, l = struct.unpack('>HH', b[p:p + 4])
        exts.append((t, b[p + 4:p + 4 + l]))
        p += 4 + l
    return ciphers, exts


def ja4(ciphers, exts):
    ex = {t: d for t, d in exts if not is_grease(t)}
    sv = [v for v in u16s(ex[43][1:]) if not is_grease(v)]
    tv = {0x0304: '13', 0x0303: '12'}.get(max(sv), '00')
    a = protos(ex[16][2:])[0]
    cs = sorted(hx(c) for c in ciphers if not is_grease(c))
    es = sorted(hx(t) for t, _ in exts if not is_grease(t) and t not in (0, 16))
    sa = [hx(x) for x in u16s(ex[13][2:]) if not is_grease(x)]
    h = lambda s: hashlib.sha256(s.encode()).hexdigest()[:12]
    ne = len([1 for t, _ in exts if not is_grease(t)])
    return 't%s%s%02d%02d%s_%s_%s' % (tv, 'd' if 0 in ex else 'i', len(cs), ne, a[0] + a[-1], h(','.join(cs)),
                                      h(','.join(es) + '_' + ','.join(sa)))


def canon(ciphers, exts):
    """The same keys as `Hello::canon` in chrome_tls_tests.rs."""
    ex = {t: d for t, d in exts if not is_grease(t)}
    order = ['GREASE' if is_grease(t) else hx(t) for t, _ in exts]
    sig = u16s(ex[13][2:])
    ks, d, i = [], ex[51][2:], 0
    while i < len(d):
        g, l = struct.unpack('>HH', d[i:i + 4])
        ks.append('%s:%d' % (gh(g), l))
        i += 4 + l
    hexs = lambda b: b.hex()
    return {
        'ja4': ja4(ciphers, exts),
        'cipher_suites': [gh(c) for c in ciphers],
        'groups': [gh(g) for g in u16s(ex[10][2:])],
        'key_shares': ks,
        'sigalgs': [hx(s) for s in sig if not is_grease(s)],
        'sigalg_grease_first': bool(sig) and is_grease(sig[0]),
        'sigalg_grease_count': len([s for s in sig if is_grease(s)]),
        'alpn': protos(ex[16][2:]),
        'alps_17613': protos(ex[17613][2:]) if 17613 in ex else None,
        'alps_17513': protos(ex[17513][2:]) if 17513 in ex else None,
        'cert_compression': [hx(v) for v in u16s(ex[27][1:])] if 27 in ex else None,
        'psk_modes': list(ex[45][1:]) if 45 in ex else None,
        'supported_versions': [gh(v) for v in u16s(ex[43][1:])],
        'ec_point_formats': list(ex[11][1:]) if 11 in ex else None,
        'status_request': hexs(ex[5]) if 5 in ex else None,
        'ext_set': sorted(hx(t) for t, _ in exts if not is_grease(t)),
        'ext_grease_first_last': order[0] == 'GREASE' and order[-1] == 'GREASE',
        'trust_anchors': hexs(ex[0xCA34]) if 0xCA34 in ex else None,
        'server_padding': hexs(ex[0x12E0]) if 0x12E0 in ex else None,
        'ech_header': hexs(ex[0xFE0D][:5]) if 0xFE0D in ex else None,
        'ech_enc_len': struct.unpack('>H', ex[0xFE0D][6:8])[0] if 0xFE0D in ex else None,
    }


def cmd_capture(a):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('127.0.0.1', 0))
    s.listen(64)
    port = s.getsockname()[1]
    recs = []

    def serve():
        while True:
            try:
                c, _ = s.accept()
            except OSError:
                return
            try:
                c.settimeout(5)
                b = b''
                while len(b) < 5:
                    b += c.recv(4096)
                n = int.from_bytes(b[3:5], 'big')
                while len(b) < 5 + n:
                    b += c.recv(4096)
                recs.append(b[:5 + n])
            except Exception:
                pass
            finally:
                c.close()

    threading.Thread(target=serve, daemon=True).start()
    flags = ['--headless=new', '--no-sandbox', '--disable-gpu', '--no-first-run',
             '--disable-field-trial-config', '--ignore-certificate-errors']
    for _ in range(a.n):
        with tempfile.TemporaryDirectory() as d:
            p = subprocess.Popen([a.chrome, *flags, '--user-data-dir=' + d, *a.flag, '--dump-dom',
                                  'https://localhost:%d/' % port], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                p.wait(15)
            except subprocess.TimeoutExpired:
                p.kill()
    time.sleep(0.5)
    ver = subprocess.run([a.chrome, '--version'], capture_output=True, text=True).stdout.strip()
    with open(a.out, 'w') as f:
        f.write(json.dumps({'chrome_version': ver, 'flags': flags + a.flag}) + '\n')
        for r in recs:
            f.write(r.hex() + '\n')
    print('%d ClientHellos (%s) -> %s' % (len(recs), ver, a.out))


def cmd_fixture(a):
    lines = open(a.input).read().split('\n')
    meta = json.loads(lines[0])
    recs = [bytes.fromhex(l) for l in lines[1:] if l]
    cold, ech_lens = [], set()
    for r in recs:
        ciphers, exts = parse(r)
        if any(t == 41 for t, _ in exts):
            continue  # a resumption (pre_shared_key) hello, not the cold one
        cold.append((ciphers, exts))
        ech_lens.update(len(d) for t, d in exts if t == 0xFE0D)
    assert cold, 'no cold ClientHello in the capture'
    views = [canon(c, e) for c, e in cold]
    for v in views[1:]:
        assert v == views[0], 'samples disagree: %s' % [k for k in v if v[k] != views[0][k]]
    out = dict(views[0])
    out['ech_payload_lens'] = sorted(set(int(x) for x in a.ech_lens.split(','))) if a.ech_lens else sorted(ech_lens)
    out['ext_orders_seen'] = len(set(tuple(t for t, _ in e) for _, e in cold))
    out['source'] = {'browser': meta['chrome_version'], 'flags': meta['flags'], 'samples': len(cold),
                     'captured': time.strftime('%Y-%m-%d')}
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    with open(a.out, 'w') as f:
        json.dump(out, f, indent=1)
        f.write('\n')
    print('%s: %d cold samples agree, JA4 %s' % (a.out, len(cold), out['ja4']))


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest='cmd', required=True)
    c = sub.add_parser('capture')
    c.add_argument('--chrome', required=True)
    c.add_argument('--out', required=True)
    c.add_argument('-n', type=int, default=12)
    c.add_argument('--flag', action='append', default=[], help='extra browser flag (repeatable)')
    c.set_defaults(fn=cmd_capture)
    f = sub.add_parser('fixture')
    f.add_argument('--in', dest='input', required=True)
    f.add_argument('--label', required=True)
    f.add_argument('--out', required=True)
    f.add_argument('--ech-lens', default='186,218,250,282',
                   help='allowed ECH GREASE extension lengths; BoringSSL picks one at random per connection')
    f.set_defaults(fn=cmd_fixture)
    a = ap.parse_args()
    a.fn(a)


if __name__ == '__main__':
    main()
