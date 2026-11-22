//! Charset detection: BOM, then `Content-Type`, then the HTML `<meta>` prescan of the first 1024
//! bytes (WHATWG "prescan a byte stream to determine its encoding").

use encoding_rs::{Encoding, UTF_16BE, UTF_16LE, UTF_8};

/// Bytes the prescan looks at.
pub const PRESCAN_LEN: usize = 1024;

/// Where the encoding came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Bom,
    Header,
    Meta,
    Default,
}

#[derive(Debug, Clone, Copy)]
pub struct Detected {
    pub encoding: &'static Encoding,
    pub source: Source,
    pub bom_len: usize,
}

/// Detect the document encoding from the response header value and the first bytes.
pub fn detect(content_type: Option<&str>, prefix: &[u8]) -> Detected {
    if let Some((enc, len)) = Encoding::for_bom(prefix) {
        return Detected {
            encoding: enc,
            source: Source::Bom,
            bom_len: len,
        };
    }
    if let Some(enc) = content_type.and_then(header_charset) {
        return Detected {
            encoding: enc,
            source: Source::Header,
            bom_len: 0,
        };
    }
    if let Some(enc) = prescan_meta(&prefix[..prefix.len().min(PRESCAN_LEN)]) {
        return Detected {
            encoding: enc,
            source: Source::Meta,
            bom_len: 0,
        };
    }
    Detected {
        encoding: UTF_8,
        source: Source::Default,
        bom_len: 0,
    }
}

/// The `charset` parameter of a `Content-Type` value.
pub fn header_charset(ct: &str) -> Option<&'static Encoding> {
    let mut parts = ct.split(';');
    parts.next();
    for p in parts {
        let p = p.trim();
        if p.len() > 8 && p[..8].eq_ignore_ascii_case("charset=") {
            let v = p[8..].trim().trim_matches('"').trim_matches('\'');
            return Encoding::for_label(v.as_bytes());
        }
    }
    None
}

/// `Content-Type` with its charset parameter set to `label` (other parameters kept).
pub fn with_charset(ct: &str, label: &str) -> String {
    let mut out: Vec<String> = Vec::new();
    let mut parts = ct.split(';');
    out.push(parts.next().unwrap_or("text/html").trim().to_string());
    for p in parts {
        let p = p.trim();
        if p.len() >= 8 && p[..8].eq_ignore_ascii_case("charset=") {
            continue;
        }
        if !p.is_empty() {
            out.push(p.to_string());
        }
    }
    out.push(format!("charset={label}"));
    out.join("; ")
}

/// Encodings lol_html cannot be told about (not ASCII-compatible): the body is transcoded.
pub fn needs_transcode(enc: &'static Encoding) -> bool {
    enc == UTF_16LE || enc == UTF_16BE || enc == encoding_rs::ISO_2022_JP
}

/// `replacement` (HZ, ISO-2022-KR, ...) decodes to U+FFFD only: leave such pages alone.
pub fn is_unusable(enc: &'static Encoding) -> bool {
    enc == encoding_rs::REPLACEMENT
}

fn is_ws(b: u8) -> bool {
    matches!(b, b'\t' | b'\n' | 0x0c | b'\r' | b' ')
}

/// Parse one attribute at `*i` (per the spec's "get an attribute"); `None` at `>` / end.
fn attribute(b: &[u8], i: &mut usize) -> Option<(Vec<u8>, Vec<u8>)> {
    while *i < b.len() && (is_ws(b[*i]) || b[*i] == b'/') {
        *i += 1;
    }
    if *i >= b.len() || b[*i] == b'>' {
        return None;
    }
    let mut name = Vec::new();
    while *i < b.len() {
        let c = b[*i];
        if c == b'=' && !name.is_empty() {
            break;
        }
        if is_ws(c) || c == b'/' || c == b'>' {
            break;
        }
        name.push(c.to_ascii_lowercase());
        *i += 1;
    }
    while *i < b.len() && is_ws(b[*i]) {
        *i += 1;
    }
    if *i >= b.len() || b[*i] != b'=' {
        return Some((name, Vec::new()));
    }
    *i += 1;
    while *i < b.len() && is_ws(b[*i]) {
        *i += 1;
    }
    let mut value = Vec::new();
    if *i < b.len() && (b[*i] == b'"' || b[*i] == b'\'') {
        let q = b[*i];
        *i += 1;
        while *i < b.len() && b[*i] != q {
            value.push(b[*i].to_ascii_lowercase());
            *i += 1;
        }
        *i += 1;
    } else {
        while *i < b.len() && !is_ws(b[*i]) && b[*i] != b'>' {
            value.push(b[*i].to_ascii_lowercase());
            *i += 1;
        }
    }
    Some((name, value))
}

/// `charset=` inside a `content` attribute value.
fn charset_in_content(v: &[u8]) -> Option<Vec<u8>> {
    let mut i = 0;
    while i + 7 <= v.len() {
        if &v[i..i + 7] == b"charset" {
            let mut j = i + 7;
            while j < v.len() && is_ws(v[j]) {
                j += 1;
            }
            if j < v.len() && v[j] == b'=' {
                j += 1;
                while j < v.len() && is_ws(v[j]) {
                    j += 1;
                }
                if j < v.len() && (v[j] == b'"' || v[j] == b'\'') {
                    let q = v[j];
                    let rest = &v[j + 1..];
                    let end = rest.iter().position(|&c| c == q)?;
                    return Some(rest[..end].to_vec());
                }
                let rest = &v[j..];
                let end = rest
                    .iter()
                    .position(|&c| is_ws(c) || c == b';')
                    .unwrap_or(rest.len());
                return Some(rest[..end].to_vec());
            }
        }
        i += 1;
    }
    None
}

fn meta_encoding(label: &[u8]) -> Option<&'static Encoding> {
    let enc = Encoding::for_label(label)?;
    // Per spec: a meta-declared UTF-16 means UTF-8; x-user-defined means windows-1252.
    if enc == UTF_16LE || enc == UTF_16BE {
        return Some(UTF_8);
    }
    if enc == encoding_rs::X_USER_DEFINED {
        return Some(encoding_rs::WINDOWS_1252);
    }
    Some(enc)
}

/// The HTML prescan: the encoding declared by the first applicable `<meta>` in `b`.
pub fn prescan_meta(b: &[u8]) -> Option<&'static Encoding> {
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'<' {
            i += 1;
            continue;
        }
        if b[i..].starts_with(b"<!--") {
            match b[i + 4..].windows(3).position(|w| w == b"-->") {
                Some(p) => i += 4 + p + 3,
                None => return None,
            }
            continue;
        }
        let tag = &b[i + 1..];
        if tag.len() >= 5
            && tag[..4].eq_ignore_ascii_case(b"meta")
            && (is_ws(tag[4]) || tag[4] == b'/')
        {
            let mut j = i + 5;
            let (mut charset, mut equiv_ct, mut content) = (None, false, None);
            while let Some((n, v)) = attribute(b, &mut j) {
                match n.as_slice() {
                    b"charset" if charset.is_none() => charset = Some(v),
                    b"http-equiv" => equiv_ct |= v == b"content-type",
                    b"content" if content.is_none() => content = Some(v),
                    _ => {}
                }
            }
            if let Some(c) = charset {
                if let Some(e) = meta_encoding(&c) {
                    return Some(e);
                }
            } else if equiv_ct {
                if let Some(e) = content
                    .and_then(|c| charset_in_content(&c))
                    .and_then(|c| meta_encoding(&c))
                {
                    return Some(e);
                }
            }
            i = j;
        } else if !tag.is_empty() && (tag[0].is_ascii_alphabetic() || tag[0] == b'/') {
            // Other tag: skip its name and attributes.
            let mut j = i + 1;
            if tag[0] == b'/' {
                j += 1;
            }
            while j < b.len() && !is_ws(b[j]) && b[j] != b'>' && b[j] != b'/' {
                j += 1;
            }
            while attribute(b, &mut j).is_some() {}
            i = j;
        } else if !tag.is_empty() && matches!(tag[0], b'!' | b'?') {
            match b[i..].iter().position(|&c| c == b'>') {
                Some(p) => i += p + 1,
                None => return None,
            }
        } else {
            i += 1;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use encoding_rs::{GBK, SHIFT_JIS, WINDOWS_1252};

    #[test]
    fn detection_table() {
        let cases: &[(Option<&str>, &[u8], &'static Encoding, Source)] = &[
            (None, b"\xef\xbb\xbf<html>", UTF_8, Source::Bom),
            (None, b"\xff\xfe<\0h\0", UTF_16LE, Source::Bom),
            (None, b"\xfe\xff\0<\0h", UTF_16BE, Source::Bom),
            // BOM beats header and meta.
            (
                Some("text/html; charset=gbk"),
                b"\xef\xbb\xbf<meta charset=sjis>",
                UTF_8,
                Source::Bom,
            ),
            // Header beats meta.
            (
                Some("text/html; charset=Shift_JIS"),
                b"<meta charset=gbk>",
                SHIFT_JIS,
                Source::Header,
            ),
            (
                Some("text/html;charset=\"gbk\""),
                b"<p>",
                GBK,
                Source::Header,
            ),
            (None, b"<meta charset=\"gbk\">", GBK, Source::Meta),
            (
                None,
                b"<META CHARSET=windows-1252>",
                WINDOWS_1252,
                Source::Meta,
            ),
            (
                None,
                b"<meta http-equiv=\"Content-Type\" content=\"text/html; charset=shift_jis\">",
                SHIFT_JIS,
                Source::Meta,
            ),
            (
                None,
                b"<meta http-equiv=content-type content='text/html;charset=gbk'>",
                GBK,
                Source::Meta,
            ),
            // Commented-out meta is ignored.
            (
                None,
                b"<!-- <meta charset=gbk> --><p>",
                UTF_8,
                Source::Default,
            ),
            // Meta UTF-16 means UTF-8.
            (None, b"<meta charset=utf-16>", UTF_8, Source::Meta),
            // Unknown label falls through.
            (
                Some("text/html; charset=bogus"),
                b"<p>",
                UTF_8,
                Source::Default,
            ),
            // Meta after other tags with attributes.
            (
                None,
                b"<html lang=ja><head><title>x</title><meta charset=euc-jp>",
                encoding_rs::EUC_JP,
                Source::Meta,
            ),
            (None, b"", UTF_8, Source::Default),
        ];
        for (ct, bytes, enc, src) in cases {
            let d = detect(*ct, bytes);
            assert_eq!(
                (d.encoding.name(), d.source),
                (enc.name(), *src),
                "{ct:?} {}",
                String::from_utf8_lossy(bytes)
            );
        }
    }

    #[test]
    fn prescan_is_limited_to_1024_bytes() {
        let mut v = vec![b' '; 1100];
        v.extend_from_slice(b"<meta charset=gbk>");
        assert_eq!(detect(None, &v).source, Source::Default);
    }

    #[test]
    fn charset_param_rewrite() {
        assert_eq!(
            with_charset("text/html; charset=shift_jis; x=1", "utf-8"),
            "text/html; x=1; charset=utf-8"
        );
        assert_eq!(
            with_charset("text/html", "utf-8"),
            "text/html; charset=utf-8"
        );
    }

    #[test]
    fn transcode_classification() {
        assert!(needs_transcode(UTF_16LE));
        assert!(needs_transcode(encoding_rs::ISO_2022_JP));
        assert!(!needs_transcode(SHIFT_JIS));
        assert!(is_unusable(encoding_rs::REPLACEMENT));
    }
}
