//! Unit and property tests for the rewriting stages.

use super::html::{sniff_html, RewriteStage};
use super::pipeline::encode_stream;
use super::{HtmlPlan, InjectPos, Injection, TextReplacement};
use bytes::Bytes;
use futures_util::StreamExt;
use proptest::prelude::*;
use std::sync::Arc;

const MARK: &str = "<!--INJ-->";

fn plan() -> HtmlPlan {
    HtmlPlan {
        head_html: MARK.to_string(),
        ..Default::default()
    }
}

/// Run `input` through a stage in windows of the given sizes (cycled).
fn run_chunked(
    plan: &HtmlPlan,
    enc: &'static encoding_rs::Encoding,
    transcode: bool,
    bom: usize,
    input: &[u8],
    sizes: &[usize],
) -> Vec<u8> {
    let mut stage = RewriteStage::new(plan, enc, transcode, bom).unwrap();
    let mut out = Vec::new();
    let mut i = 0;
    let mut k = 0;
    while i < input.len() {
        let n = sizes[k % sizes.len()].max(1).min(input.len() - i);
        out.extend_from_slice(&stage.push(&input[i..i + n]).unwrap());
        i += n;
        k += 1;
    }
    out.extend_from_slice(&stage.finish().unwrap());
    out
}

fn run(input: &str) -> String {
    String::from_utf8(run_chunked(
        &plan(),
        encoding_rs::UTF_8,
        false,
        0,
        input.as_bytes(),
        &[usize::MAX],
    ))
    .unwrap()
}

/// Adversarial documents: each must get exactly one injection, at the right place.
const DOCS: &[(&str, &str)] = &[
    (
        "<!DOCTYPE html><html><head><title>t</title></head><body>b</body></html>",
        "<!DOCTYPE html><html><head><!--INJ--><title>t</title></head><body>b</body></html>",
    ),
    (
        "<html><body>x</body></html>",
        "<html><!--INJ--><body>x</body></html>",
    ),
    ("<p>fragment</p>", "<!--INJ--><p>fragment</p>"),
    (
        "<!DOCTYPE html><div>no head</div>",
        "<!DOCTYPE html><!--INJ--><div>no head</div>",
    ),
    (
        "<!doctype html public \"-//W3C//DTD HTML 4.01//EN\"><html><HEAD lang=x><meta charset=utf-8>",
        "<!doctype html public \"-//W3C//DTD HTML 4.01//EN\"><html><HEAD lang=x><!--INJ--><meta charset=utf-8>",
    ),
    (
        "<!-- <head> --><html><head><script>var s = '<head></head>';</script></head>",
        "<!-- <head> --><html><head><!--INJ--><script>var s = '<head></head>';</script></head>",
    ),
    (
        "<html><head><!-- </head><body> --><title>x</title></head><body></body></html>",
        "<html><head><!--INJ--><!-- </head><body> --><title>x</title></head><body></body></html>",
    ),
    (
        "<html><head data-x=\"</head><body>\"><title>x</title></head>",
        "<html><head data-x=\"</head><body>\"><!--INJ--><title>x</title></head>",
    ),
    (
        "<svg><![CDATA[<head>]]></svg><p>1</p>",
        "<!--INJ--><svg><![CDATA[<head>]]></svg><p>1</p>",
    ),
    (
        "<html><title>t</title><body>b</body></html>",
        "<html><!--INJ--><title>t</title><body>b</body></html>",
    ),
    (
        "<?xml version=\"1.0\"?><html><head></head></html>",
        "<?xml version=\"1.0\"?><html><head><!--INJ--></head></html>",
    ),
    (
        "<script>document.write('<head>')</script><head></head>",
        "<!--INJ--><script>document.write('<head>')</script><head></head>",
    ),
    (
        "<textarea><head></textarea><p>x</p>",
        "<!--INJ--><textarea><head></textarea><p>x</p>",
    ),
];

#[test]
fn adversarial_documents() {
    for (input, want) in DOCS {
        assert_eq!(run(input), *want, "input: {input}");
    }
}

#[test]
fn text_without_elements_gets_nothing() {
    assert_eq!(run("just text"), "just text");
    assert_eq!(run(""), "");
    assert_eq!(run("<!DOCTYPE html>"), "<!DOCTYPE html>");
}

#[test]
fn one_byte_chunks_match_one_big_chunk() {
    for (input, _) in DOCS {
        let big = run_chunked(
            &plan(),
            encoding_rs::UTF_8,
            false,
            0,
            input.as_bytes(),
            &[usize::MAX],
        );
        let tiny = run_chunked(
            &plan(),
            encoding_rs::UTF_8,
            false,
            0,
            input.as_bytes(),
            &[1],
        );
        assert_eq!(big, tiny, "input: {input}");
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(400))]

    /// Any chunking of any document yields the same bytes as feeding it whole.
    #[test]
    fn chunk_boundaries_do_not_matter(
        doc in 0..DOCS.len(),
        sizes in proptest::collection::vec(1usize..40, 1..12),
        repeat in 1usize..30,
    ) {
        let mut input = DOCS[doc].0.to_string().into_bytes();
        // Pad the body so boundaries land in many places.
        input.extend_from_slice("<p class=\"a\">filler & text</p>".repeat(repeat).as_bytes());
        let whole = run_chunked(&plan(), encoding_rs::UTF_8, false, 0, &input, &[usize::MAX]);
        let split = run_chunked(&plan(), encoding_rs::UTF_8, false, 0, &input, &sizes);
        prop_assert_eq!(whole, split);
    }

    /// Same property on random bytes: no panic, identical output.
    #[test]
    fn arbitrary_bytes_are_chunk_stable(
        input in proptest::collection::vec(any::<u8>(), 0..300),
        sizes in proptest::collection::vec(1usize..17, 1..8),
    ) {
        let mut doc = b"<html><head>".to_vec();
        doc.extend_from_slice(&input);
        let whole = run_chunked(&plan(), encoding_rs::UTF_8, false, 0, &doc, &[usize::MAX]);
        let split = run_chunked(&plan(), encoding_rs::UTF_8, false, 0, &doc, &sizes);
        prop_assert_eq!(whole, split);
    }
}

#[test]
fn shift_jis_bytes_are_preserved_around_the_injection() {
    let doc = "<html><head><meta charset=shift_jis></head><body><p>\u{65e5}\u{672c}\u{8a9e}\u{30c6}\u{30b9}\u{30c8}</p></body></html>";
    let bytes = encoding_rs::SHIFT_JIS.encode(doc).0.into_owned();
    for sizes in [&[usize::MAX][..], &[1], &[3, 5, 7]] {
        let out = run_chunked(&plan(), encoding_rs::SHIFT_JIS, false, 0, &bytes, sizes);
        let restored = String::from_utf8(out.clone())
            .map(|s| s.replace(MARK, ""))
            .unwrap_or_else(|_| {
                // Not valid UTF-8 (Shift_JIS bytes): strip the marker bytewise.
                String::from_utf8_lossy(&out).replace(MARK, "")
            });
        let mut expect = bytes.clone();
        // Marker goes right after <head>.
        let at = expect.windows(6).position(|w| w == b"<head>").unwrap() + 6;
        let mut want = expect.split_off(at);
        let mut all = expect;
        all.extend_from_slice(MARK.as_bytes());
        all.append(&mut want);
        assert_eq!(out, all, "sizes {sizes:?}");
        let _ = restored;
    }
}

#[test]
fn utf16_is_transcoded_and_meta_fixed() {
    let doc = "<html><head><meta charset=\"utf-16\"></head><body>\u{65e5}\u{672c}</body></html>";
    for (enc, le) in [
        (encoding_rs::UTF_16LE, true),
        (encoding_rs::UTF_16BE, false),
    ] {
        let mut bytes = if le {
            vec![0xff, 0xfe]
        } else {
            vec![0xfe, 0xff]
        };
        for u in doc.encode_utf16() {
            bytes.extend_from_slice(&if le { u.to_le_bytes() } else { u.to_be_bytes() });
        }
        for sizes in [&[usize::MAX][..], &[1], &[3, 1, 2]] {
            let out = run_chunked(&plan(), enc, true, 2, &bytes, sizes);
            let s = String::from_utf8(out).expect("utf-8 output");
            assert_eq!(
                s,
                "<html><head><!--INJ--><meta charset=\"utf-8\"></head><body>\u{65e5}\u{672c}</body></html>",
                "{enc:?} {sizes:?}"
            );
        }
    }
}

#[test]
fn iso_2022_jp_is_transcoded() {
    let (bytes, _, _) =
        encoding_rs::ISO_2022_JP.encode("<html><head></head><body>\u{65e5}\u{672c}</body></html>");
    let out = run_chunked(&plan(), encoding_rs::ISO_2022_JP, true, 0, &bytes, &[2]);
    assert_eq!(
        String::from_utf8(out).unwrap(),
        "<html><head><!--INJ--></head><body>\u{65e5}\u{672c}</body></html>"
    );
}

#[test]
fn removal_replacement_and_extra_injections() {
    let p = HtmlPlan {
        head_html: MARK.into(),
        injections: vec![
            Injection {
                pos: InjectPos::HeadStart,
                html: "<!--A-->".into(),
            },
            Injection {
                pos: InjectPos::BodyStart,
                html: "<!--B-->".into(),
            },
            Injection {
                pos: InjectPos::BodyEnd,
                html: "<!--C-->".into(),
            },
            Injection {
                pos: InjectPos::HeadEnd,
                html: "<!--D-->".into(),
            },
        ],
        remove_selectors: vec!["div.ad".into(), "!!bad selector".into()],
        replacements: vec![TextReplacement {
            selector: Some("p".into()),
            find: regex::Regex::new("secret").unwrap(),
            replace: "[x]".into(),
        }],
        meta_csp: Some(Arc::new(|c: &str| Some(format!("{c} added")))),
    };
    let input = "<html><head><meta http-equiv=\"Content-Security-Policy\" content=\"a\"></head><body><div class=\"ad\">no</div><p>a secret and another secret</p></body></html>";
    for sizes in [&[usize::MAX][..], &[1], &[7]] {
        let out = String::from_utf8(run_chunked(
            &p,
            encoding_rs::UTF_8,
            false,
            0,
            input.as_bytes(),
            sizes,
        ))
        .unwrap();
        assert_eq!(
            out,
            "<html><head><!--A--><!--INJ--><meta http-equiv=\"Content-Security-Policy\" content=\"a added\"><!--D--></head><body><!--B--><p>a [x] and another [x]</p><!--C--></body></html>",
            "{sizes:?}"
        );
    }
}

#[test]
fn sniff_table() {
    let yes: &[&[u8]] = &[
        b"<!DOCTYPE html><html>",
        b"  \n<!doctype HTML>",
        b"<html>",
        b"<p>x",
        b"<!-- c --><html>",
        b"\xef\xbb\xbf<html>",
        b"<!DOCTYPE html PUBLIC \"x\">",
        b"<div",
        b"<!-- unterminated comment",
    ];
    let no: &[&[u8]] = &[
        b"{\"a\":1}",
        b"[1,2]",
        b"<?xml version=\"1.0\"?><html>",
        b"var x = '<html>';",
        b"plain text <html>",
        b"<svg xmlns=\"x\">",
        b"<rss version=\"2.0\">",
        b"<!DOCTYPE svg>",
        b"",
        b"   ",
        b"<1>",
        b"/* <head> */",
    ];
    for y in yes {
        assert!(sniff_html(y), "{}", String::from_utf8_lossy(y));
    }
    for n in no {
        assert!(!sniff_html(n), "{}", String::from_utf8_lossy(n));
    }
}

#[tokio::test]
async fn encoder_flushes_when_upstream_goes_quiet() {
    use async_compression::tokio::bufread::ZstdDecoder;
    use tokio::io::AsyncReadExt;
    let (tx, rx) = tokio::sync::mpsc::channel::<std::io::Result<Bytes>>(4);
    let input =
        futures_util::stream::unfold(rx, |mut rx| async move { rx.recv().await.map(|v| (v, rx)) });
    let mut out = Box::pin(encode_stream(input, Some(super::codec::Coding::Zstd)));
    tx.send(Ok(Bytes::from_static(b"<html><head>")))
        .await
        .unwrap();
    let first = tokio::time::timeout(std::time::Duration::from_secs(2), out.next())
        .await
        .expect("flushed without waiting for more input")
        .unwrap()
        .unwrap();
    // A decoder fed only this prefix already yields the text.
    let mut dec = ZstdDecoder::new(tokio::io::BufReader::new(std::io::Cursor::new(
        first.to_vec(),
    )));
    let mut got = Vec::new();
    let mut buf = [0u8; 64];
    while let Ok(n) = dec.read(&mut buf).await {
        if n == 0 {
            break;
        }
        got.extend_from_slice(&buf[..n]);
    }
    assert_eq!(got, b"<html><head>");
    drop(tx);
    while out.next().await.is_some() {}
}

#[tokio::test]
async fn encoder_batches_when_input_is_ready() {
    let chunks: Vec<std::io::Result<Bytes>> = (0..200)
        .map(|_| Ok(Bytes::from_static(b"<p>some text that compresses well</p>")))
        .collect();
    let outs: Vec<_> = encode_stream(
        futures_util::stream::iter(chunks),
        Some(super::codec::Coding::Gzip),
    )
    .collect()
    .await;
    // Ready input is not flushed per chunk.
    assert!(outs.len() < 10, "{} output chunks", outs.len());
}
