//! Content codings: streaming decode (stacked encodings, in order) and re-encode.
//!
//! Decoding uses the read-side decoders (pull-driven, so backpressure and cancellation flow
//! through). Encoding uses the write-side encoders so the stage can flush exactly when the
//! upstream has nothing more ready (latency) and otherwise let the compressor batch (ratio).

use async_compression::tokio::bufread as dec;
use async_compression::tokio::write as enc;
use async_compression::Level;
use bytes::Bytes;
use hyper::header::{HeaderMap, ACCEPT_ENCODING, CONTENT_ENCODING};
use std::io;
use std::pin::Pin;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt, BufReader};

/// A content coding we can decode and (except where noted) encode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Coding {
    Gzip,
    /// `deflate` (zlib-wrapped; raw deflate is accepted when decoding).
    Deflate,
    Brotli,
    Zstd,
}

impl Coding {
    pub fn token(self) -> &'static str {
        match self {
            Coding::Gzip => "gzip",
            Coding::Deflate => "deflate",
            Coding::Brotli => "br",
            Coding::Zstd => "zstd",
        }
    }

    fn from_token(t: &str) -> Option<Self> {
        match t.to_ascii_lowercase().as_str() {
            "gzip" | "x-gzip" => Some(Coding::Gzip),
            "deflate" => Some(Coding::Deflate),
            "br" => Some(Coding::Brotli),
            "zstd" => Some(Coding::Zstd),
            _ => None,
        }
    }
}

/// Compression levels used when re-encoding (chosen with the `rewrite` bench: fast, close to
/// the origin's ratio, a small fraction of a millisecond per 32 KiB chunk).
const LEVEL_ZSTD: i32 = 3;
const LEVEL_BROTLI: i32 = 4;
const LEVEL_GZIP: i32 = 4;

/// The codings applied to a body, in the order they were applied (the `Content-Encoding` order).
/// `Err(())` when any listed coding is one we cannot decode (the body must pass through).
#[allow(clippy::result_unit_err)]
pub fn response_codings(headers: &HeaderMap) -> Result<Vec<Coding>, ()> {
    let mut out = Vec::new();
    for v in headers.get_all(CONTENT_ENCODING) {
        let v = v.to_str().map_err(|_| ())?;
        for t in v.split(',').map(str::trim).filter(|t| !t.is_empty()) {
            if t.eq_ignore_ascii_case("identity") {
                continue;
            }
            out.push(Coding::from_token(t).ok_or(())?);
        }
    }
    Ok(out)
}

/// Pick the response coding from the client's `Accept-Encoding`: zstd, then br, then gzip, then
/// deflate; `None` (identity) when the client accepts none (or sent no header).
pub fn choose_encoding(request_headers: &HeaderMap) -> Option<Coding> {
    let mut q: [Option<f32>; 4] = [None; 4]; // zstd, br, gzip, deflate
    let mut star: Option<f32> = None;
    for v in request_headers.get_all(ACCEPT_ENCODING) {
        let Ok(v) = v.to_str() else { continue };
        for item in v.split(',') {
            let mut parts = item.split(';');
            let name = parts.next().unwrap_or("").trim().to_ascii_lowercase();
            let weight = parts
                .find_map(|p| {
                    let p = p.trim();
                    p.strip_prefix("q=").or_else(|| p.strip_prefix("Q="))
                })
                .and_then(|w| w.trim().parse::<f32>().ok())
                .unwrap_or(1.0);
            match name.as_str() {
                "zstd" => q[0] = Some(weight),
                "br" => q[1] = Some(weight),
                "gzip" | "x-gzip" => q[2] = Some(weight),
                "deflate" => q[3] = Some(weight),
                "*" => star = Some(weight),
                _ => {}
            }
        }
    }
    let order = [Coding::Zstd, Coding::Brotli, Coding::Gzip, Coding::Deflate];
    // An explicit `*` does not make us pick a coding the client never named.
    let _ = star;
    order
        .into_iter()
        .zip(q)
        .find(|(_, w)| w.is_some_and(|w| w > 0.0))
        .map(|(c, _)| c)
}

pub type DynBufRead = Pin<Box<dyn AsyncBufRead + Send>>;

/// Wrap `input` in the decoders for `codings`, outermost (last applied) first.
pub async fn decode_chain(mut input: DynBufRead, codings: &[Coding]) -> io::Result<DynBufRead> {
    for coding in codings.iter().rev() {
        input = match coding {
            Coding::Gzip => {
                let mut d = dec::GzipDecoder::new(input);
                d.multiple_members(true);
                Box::pin(BufReader::with_capacity(32 * 1024, d))
            }
            Coding::Brotli => Box::pin(BufReader::with_capacity(
                32 * 1024,
                dec::BrotliDecoder::new(input),
            )),
            Coding::Zstd => {
                let mut d = dec::ZstdDecoder::new(input);
                d.multiple_members(true);
                Box::pin(BufReader::with_capacity(32 * 1024, d))
            }
            Coding::Deflate => {
                // Servers send both zlib-wrapped (the RFC) and raw deflate: look at the header.
                let head = input.fill_buf().await?;
                let zlib = head.len() >= 2
                    && head[0] & 0x0f == 8
                    && ((u16::from(head[0]) << 8) | u16::from(head[1])) % 31 == 0;
                if zlib {
                    Box::pin(BufReader::with_capacity(
                        32 * 1024,
                        dec::ZlibDecoder::new(input),
                    ))
                } else {
                    Box::pin(BufReader::with_capacity(
                        32 * 1024,
                        dec::DeflateDecoder::new(input),
                    ))
                }
            }
        };
    }
    Ok(input)
}

/// Incremental encoder into an in-memory buffer that the caller drains with [`Encoder::take`].
#[allow(clippy::large_enum_variant)]
pub enum Encoder {
    Identity(Vec<u8>),
    Gzip(enc::GzipEncoder<Vec<u8>>),
    Deflate(enc::ZlibEncoder<Vec<u8>>),
    Brotli(enc::BrotliEncoder<Vec<u8>>),
    Zstd(enc::ZstdEncoder<Vec<u8>>),
}

impl Encoder {
    pub fn new(coding: Option<Coding>) -> Self {
        match coding {
            None => Encoder::Identity(Vec::new()),
            Some(Coding::Gzip) => Encoder::Gzip(enc::GzipEncoder::with_quality(
                Vec::new(),
                Level::Precise(LEVEL_GZIP),
            )),
            Some(Coding::Deflate) => Encoder::Deflate(enc::ZlibEncoder::with_quality(
                Vec::new(),
                Level::Precise(LEVEL_GZIP),
            )),
            Some(Coding::Brotli) => Encoder::Brotli(enc::BrotliEncoder::with_quality(
                Vec::new(),
                Level::Precise(LEVEL_BROTLI),
            )),
            Some(Coding::Zstd) => Encoder::Zstd(enc::ZstdEncoder::with_quality(
                Vec::new(),
                Level::Precise(LEVEL_ZSTD),
            )),
        }
    }

    pub async fn write(&mut self, data: &[u8]) -> io::Result<()> {
        match self {
            Encoder::Identity(v) => v.extend_from_slice(data),
            Encoder::Gzip(e) => e.write_all(data).await?,
            Encoder::Deflate(e) => e.write_all(data).await?,
            Encoder::Brotli(e) => e.write_all(data).await?,
            Encoder::Zstd(e) => e.write_all(data).await?,
        }
        Ok(())
    }

    /// Force out everything written so far (a sync flush point for the client).
    pub async fn flush(&mut self) -> io::Result<()> {
        match self {
            Encoder::Identity(_) => Ok(()),
            Encoder::Gzip(e) => e.flush().await,
            Encoder::Deflate(e) => e.flush().await,
            Encoder::Brotli(e) => e.flush().await,
            Encoder::Zstd(e) => e.flush().await,
        }
    }

    /// Drain the bytes produced so far.
    pub fn take(&mut self) -> Bytes {
        let v = match self {
            Encoder::Identity(v) => v,
            Encoder::Gzip(e) => e.get_mut(),
            Encoder::Deflate(e) => e.get_mut(),
            Encoder::Brotli(e) => e.get_mut(),
            Encoder::Zstd(e) => e.get_mut(),
        };
        Bytes::from(std::mem::take(v))
    }

    /// Finish the stream (trailer) and drain the rest.
    pub async fn finish(&mut self) -> io::Result<Bytes> {
        match self {
            Encoder::Identity(_) => {}
            Encoder::Gzip(e) => e.shutdown().await?,
            Encoder::Deflate(e) => e.shutdown().await?,
            Encoder::Brotli(e) => e.shutdown().await?,
            Encoder::Zstd(e) => e.shutdown().await?,
        }
        Ok(self.take())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    fn sample() -> Vec<u8> {
        (0..50_000u32)
            .flat_map(|i| format!("<p class=\"x{}\">line {i}</p>\n", i % 17).into_bytes())
            .collect()
    }

    async fn encode(coding: Option<Coding>, data: &[u8], chunk: usize) -> Vec<u8> {
        let mut e = Encoder::new(coding);
        let mut out = Vec::new();
        for c in data.chunks(chunk) {
            e.write(c).await.unwrap();
            out.extend_from_slice(&e.take());
        }
        out.extend_from_slice(&e.finish().await.unwrap());
        out
    }

    async fn decode(bytes: Vec<u8>, codings: &[Coding]) -> io::Result<Vec<u8>> {
        let input: DynBufRead = Box::pin(BufReader::new(io::Cursor::new(bytes)));
        let mut r = decode_chain(input, codings).await?;
        let mut out = Vec::new();
        r.read_to_end(&mut out).await?;
        Ok(out)
    }

    #[tokio::test]
    async fn roundtrip_every_coding() {
        let data = sample();
        for c in [Coding::Gzip, Coding::Deflate, Coding::Brotli, Coding::Zstd] {
            for chunk in [1000, 32 * 1024, data.len()] {
                let enc = encode(Some(c), &data, chunk).await;
                assert!(enc.len() < data.len() / 3, "{c:?} compressed");
                assert_eq!(
                    decode(enc, &[c]).await.unwrap(),
                    data,
                    "{c:?} chunk {chunk}"
                );
            }
        }
        assert_eq!(
            decode(encode(None, &data, 777).await, &[]).await.unwrap(),
            data
        );
    }

    #[tokio::test]
    async fn stacked_encodings_decode_in_order() {
        let data = sample();
        // Content-Encoding: gzip, br  => gzip applied first, then br.
        let inner = encode(Some(Coding::Gzip), &data, 8192).await;
        let outer = encode(Some(Coding::Brotli), &inner, 8192).await;
        assert_eq!(
            decode(outer, &[Coding::Gzip, Coding::Brotli])
                .await
                .unwrap(),
            data
        );
        let inner = encode(Some(Coding::Zstd), &data, 8192).await;
        let outer = encode(Some(Coding::Deflate), &inner, 8192).await;
        assert_eq!(
            decode(outer, &[Coding::Zstd, Coding::Deflate])
                .await
                .unwrap(),
            data
        );
    }

    #[tokio::test]
    async fn raw_deflate_is_accepted() {
        use async_compression::tokio::write::DeflateEncoder;
        let data = sample();
        let mut e = DeflateEncoder::new(Vec::new());
        e.write_all(&data).await.unwrap();
        e.shutdown().await.unwrap();
        let raw = e.into_inner();
        assert_eq!(decode(raw, &[Coding::Deflate]).await.unwrap(), data);
    }

    #[tokio::test]
    async fn truncated_input_is_an_error() {
        let data = sample();
        for c in [Coding::Gzip, Coding::Brotli, Coding::Zstd, Coding::Deflate] {
            let mut enc = encode(Some(c), &data, 8192).await;
            enc.truncate(enc.len() / 2);
            assert!(decode(enc, &[c]).await.is_err(), "{c:?}");
        }
    }

    #[tokio::test]
    async fn flush_emits_decodable_prefix() {
        let mut e = Encoder::new(Some(Coding::Zstd));
        e.write(b"<html><head>").await.unwrap();
        e.flush().await.unwrap();
        let first = e.take();
        assert!(!first.is_empty(), "flush must emit bytes");
        e.write(b"</head></html>").await.unwrap();
        let mut all = first.to_vec();
        all.extend_from_slice(&e.finish().await.unwrap());
        assert_eq!(
            decode(all, &[Coding::Zstd]).await.unwrap(),
            b"<html><head></head></html>"
        );
    }

    fn hm(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(
                hyper::header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                v.parse().unwrap(),
            );
        }
        h
    }

    #[test]
    fn negotiation_table() {
        let cases: &[(&str, Option<Coding>)] = &[
            ("gzip, deflate, br, zstd", Some(Coding::Zstd)),
            ("gzip, br", Some(Coding::Brotli)),
            ("gzip", Some(Coding::Gzip)),
            ("gzip;q=0, br;q=0.5", Some(Coding::Brotli)),
            ("zstd;q=0, gzip", Some(Coding::Gzip)),
            ("identity", None),
            ("", None),
            ("compress", None),
            ("deflate", Some(Coding::Deflate)),
            ("*", None),
        ];
        for (ae, want) in cases {
            assert_eq!(
                choose_encoding(&hm(&[("accept-encoding", ae)])),
                *want,
                "{ae}"
            );
        }
        assert_eq!(choose_encoding(&HeaderMap::new()), None);
    }

    #[test]
    fn response_coding_parsing() {
        assert_eq!(response_codings(&HeaderMap::new()), Ok(vec![]));
        assert_eq!(
            response_codings(&hm(&[("content-encoding", "gzip, br")])),
            Ok(vec![Coding::Gzip, Coding::Brotli])
        );
        assert_eq!(
            response_codings(&hm(&[("content-encoding", "identity")])),
            Ok(vec![])
        );
        assert_eq!(
            response_codings(&hm(&[
                ("content-encoding", "gzip"),
                ("content-encoding", "zstd")
            ])),
            Ok(vec![Coding::Gzip, Coding::Zstd])
        );
        assert!(response_codings(&hm(&[("content-encoding", "gzip, dcb")])).is_err());
        assert!(response_codings(&hm(&[("content-encoding", "compress")])).is_err());
    }
}
