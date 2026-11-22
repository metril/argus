//! Small built-in set of uBlock-compatible `$redirect` resources, so redirects work offline.
//!
//! Every payload here is original: trivial text bodies, or binary files assembled in code from
//! the GIF / PNG / zlib / MPEG specifications (nothing copied from uBlock Origin). Only the
//! resource *names* follow the uBO convention so existing rules resolve.
//!
//! A loaded resource library (see `SharedEngine::set_resources_from_json`) overrides these by name.

use adblock::resources::Resource;
use base64::Engine as _;

/// 1x1 transparent GIF89a, assembled field by field from the GIF specification.
fn gif_1x1() -> Vec<u8> {
    let mut g = Vec::with_capacity(43);
    g.extend_from_slice(b"GIF89a");
    g.extend_from_slice(&[1, 0, 1, 0]); // logical screen 1x1
    g.extend_from_slice(&[0x80, 0, 0]); // global colour table (2 entries), bg 0, no aspect
    g.extend_from_slice(&[0, 0, 0, 0xff, 0xff, 0xff]); // palette: black, white
    g.extend_from_slice(&[0x21, 0xf9, 4, 1, 0, 0, 0, 0]); // graphic control: transparent index 0
    g.extend_from_slice(&[0x2c, 0, 0, 0, 0, 1, 0, 1, 0, 0]); // image descriptor 1x1
    g.extend_from_slice(&[2, 2, 0x44, 1, 0]); // LZW min code size 2, one data block (pixel 0)
    g.push(0x3b); // trailer
    g
}

fn crc32(data: &[u8]) -> u32 {
    let mut c = !0u32;
    for &b in data {
        c ^= b as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 {
                0xedb8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
        }
    }
    !c
}

fn adler32(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for &x in data {
        a = (a + x as u32) % 65521;
        b = (b + a) % 65521;
    }
    (b << 16) | a
}

/// 1x1 fully transparent RGBA PNG, built from the PNG/zlib specifications (stored deflate block).
fn png_1x1() -> Vec<u8> {
    fn chunk(out: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        let mut body = kind.to_vec();
        body.extend_from_slice(data);
        out.extend_from_slice(&body);
        out.extend_from_slice(&crc32(&body).to_be_bytes());
    }
    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&1u32.to_be_bytes());
    ihdr.extend_from_slice(&1u32.to_be_bytes());
    ihdr.extend_from_slice(&[8, 6, 0, 0, 0]); // 8-bit RGBA, no interlace
    let raw = [0u8; 5]; // filter byte + one transparent pixel
    let mut z = vec![
        0x78,
        0x01,
        0x01,
        raw.len() as u8,
        0,
        !(raw.len() as u8),
        0xff,
    ];
    z.extend_from_slice(&raw);
    z.extend_from_slice(&adler32(&raw).to_be_bytes());
    let mut png = vec![0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
    chunk(&mut png, b"IHDR", &ihdr);
    chunk(&mut png, b"IDAT", &z);
    chunk(&mut png, b"IEND", &[]);
    png
}

/// A few silent MPEG-1 Layer III frames (44.1 kHz, 128 kbit/s: header + zeroed payload, 417 bytes
/// each, about 26 ms per frame).
fn mp3_silent() -> Vec<u8> {
    let mut v = Vec::new();
    for _ in 0..4 {
        v.extend_from_slice(&[0xff, 0xfb, 0x90, 0x64]);
        v.resize(v.len() + 413, 0);
    }
    v
}

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}

fn res(name: &str, aliases: &[&str], mime: &str, content_b64: String) -> Resource {
    serde_json::from_value(serde_json::json!({
        "name": name,
        "aliases": aliases,
        "kind": {"mime": mime},
        "content": content_b64,
    }))
    .expect("built-in resource is valid")
}

fn text(name: &str, aliases: &[&str], mime: &str, body: &str) -> Resource {
    res(
        name,
        aliases,
        mime,
        base64::engine::general_purpose::STANDARD.encode(body),
    )
}

/// The built-in redirect resources (noop.js, noop.css, noopframe, 1x1.gif, ...).
pub fn builtin_redirect_resources() -> Vec<Resource> {
    vec![
        text(
            "noop.js",
            &["noopjs"],
            "application/javascript",
            "(function(){})();",
        ),
        text("noop.css", &["noopcss"], "text/css", ""),
        text(
            "noop.html",
            &["noopframe"],
            "text/html",
            "<!DOCTYPE html><html><head><meta charset=\"utf-8\"></head><body></body></html>",
        ),
        text("noop.txt", &["nooptext"], "text/plain", ""),
        text("noop.json", &["noopjson"], "application/json", "{}"),
        text(
            "noop-vmap1.0.xml",
            &["noopvmap-1.0"],
            "text/xml",
            "<VMAP version=\"1.0\"/>",
        ),
        res(
            "1x1.gif",
            &["1x1-transparent.gif"],
            "image/gif",
            b64(&gif_1x1()),
        ),
        res(
            "1x1.png",
            &[
                "2x2.png",
                "2x2-transparent.png",
                "3x2.png",
                "3x2-transparent.png",
                "32x32.png",
                "32x32-transparent.png",
            ],
            "image/png",
            b64(&png_1x1()),
        ),
        res(
            "noop-0.1s.mp3",
            &["noopmp3-0.1s"],
            "audio/mp3",
            b64(&mp3_silent()),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtins_parse() {
        assert!(builtin_redirect_resources().len() >= 8);
    }

    #[test]
    fn generated_binaries_are_well_formed() {
        let g = gif_1x1();
        assert_eq!(
            (g.len(), &g[..6], g[g.len() - 1]),
            (43, &b"GIF89a"[..], 0x3b)
        );
        // Walk the PNG chunks and verify every CRC.
        let p = png_1x1();
        assert_eq!(&p[..8], &[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]);
        let (mut i, mut kinds) = (8, Vec::new());
        while i < p.len() {
            let n = u32::from_be_bytes(p[i..i + 4].try_into().unwrap()) as usize;
            let body = &p[i + 4..i + 8 + n];
            let crc = u32::from_be_bytes(p[i + 8 + n..i + 12 + n].try_into().unwrap());
            assert_eq!(crc32(body), crc);
            kinds.push(body[..4].to_vec());
            i += 12 + n;
        }
        assert_eq!(
            kinds,
            [b"IHDR".to_vec(), b"IDAT".to_vec(), b"IEND".to_vec()]
        );
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
        assert_eq!(adler32(b"Wikipedia"), 0x11e6_0398);
        assert_eq!(mp3_silent().len(), 4 * 417);
    }
}
