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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{ready, Context, Poll};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncWriteExt, BufReader, ReadBuf};

/// Most content codings accepted on one response. Every layer costs a decoder, a buffer and a
/// recursion level per read, so a hostile origin could otherwise stack hundreds of them; real
/// servers send one (two at the very most). More than this is "undecodable": the body passes
/// through untouched with its original headers.
pub const MAX_CODINGS: usize = 2;
/// Largest zstd window the decoder accepts: 8 MiB (`windowLog` 23), the RFC 9659 limit browsers
/// enforce for `Content-Encoding: zstd`. A frame that asks for more fails on the first read.
const ZSTD_WINDOW_LOG_MAX: u32 = 23;
/// Decoded bytes allowed before the expansion ratio is checked at all.
const RATIO_GRACE: u64 = 16 * 1024 * 1024;
/// Largest decoded : compressed ratio once past the grace amount. Real documents compress
/// 5-50x (a few hundred at the very extreme); a zip-bomb is 1000x and up.
const MAX_RATIO: u64 = 250;

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
            if out.len() > MAX_CODINGS {
                return Err(());
            }
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

/// Counts the bytes the decoders consume from the wire.
struct Counting {
    inner: DynBufRead,
    n: Arc<AtomicU64>,
}

impl AsyncRead for Counting {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        ready!(self.inner.as_mut().poll_read(cx, buf))?;
        self.n
            .fetch_add((buf.filled().len() - before) as u64, Ordering::Relaxed);
        Poll::Ready(Ok(()))
    }
}

impl AsyncBufRead for Counting {
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        self.get_mut().inner.as_mut().poll_fill_buf(cx)
    }
    fn consume(mut self: Pin<&mut Self>, amt: usize) {
        self.n.fetch_add(amt as u64, Ordering::Relaxed);
        self.inner.as_mut().consume(amt);
    }
}

/// Fails the stream once the decoded output outgrows [`MAX_RATIO`] times what was read from the
/// wire (past [`RATIO_GRACE`]).
///
/// What happens then depends on how far the response got: while the pipeline is still peeking or
/// buffering nothing has been sent, so it falls back to forwarding the origin's bytes untouched;
/// once rewritten bytes have gone out that is impossible, so the error aborts the response
/// stream (the browser sees a failed load rather than a silently truncated page).
struct Guard {
    inner: DynBufRead,
    compressed: Arc<AtomicU64>,
    decoded: u64,
}

impl AsyncRead for Guard {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let data = ready!(self.as_mut().poll_fill_buf(cx))?;
        let n = data.len().min(buf.remaining());
        buf.put_slice(&data[..n]);
        self.consume(n);
        Poll::Ready(Ok(()))
    }
}

impl AsyncBufRead for Guard {
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        let this = self.get_mut();
        if this.decoded > RATIO_GRACE
            && this.decoded
                > MAX_RATIO.saturating_mul(this.compressed.load(Ordering::Relaxed).max(1))
        {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "decoded body exceeds the expansion limit",
            )));
        }
        this.inner.as_mut().poll_fill_buf(cx)
    }
    fn consume(self: Pin<&mut Self>, amt: usize) {
        let this = self.get_mut();
        this.decoded += amt as u64;
        this.inner.as_mut().consume(amt);
    }
}

/// Brotli decoder that refuses the "large window" extension (windows beyond 16 MiB).
/// `async-compression`'s brotli decoder enables it (up to a 1 GiB window), so the decoder is
/// driven directly here with a strict state.
struct StrictBrotli {
    inner: DynBufRead,
    state: Box<
        brotli::BrotliState<
            brotli::enc::StandardAlloc,
            brotli::enc::StandardAlloc,
            brotli::enc::StandardAlloc,
        >,
    >,
    done: bool,
}

impl StrictBrotli {
    fn new(inner: DynBufRead) -> Self {
        let a = brotli::enc::StandardAlloc::default;
        Self {
            inner,
            state: Box::new(brotli::BrotliState::new_strict(a(), a(), a())),
            done: false,
        }
    }
}

impl AsyncRead for StrictBrotli {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if this.done || buf.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
            let input = ready!(this.inner.as_mut().poll_fill_buf(cx))?;
            let eof = input.is_empty();
            let out = buf.initialize_unfilled();
            let (mut avail_in, mut in_off) = (input.len(), 0usize);
            let (mut avail_out, mut out_off) = (out.len(), 0usize);
            let mut total = 0usize;
            let res = brotli::BrotliDecompressStream(
                &mut avail_in,
                &mut in_off,
                input,
                &mut avail_out,
                &mut out_off,
                out,
                &mut total,
                &mut this.state,
            );
            this.inner.as_mut().consume(in_off);
            buf.advance(out_off);
            match res {
                brotli::BrotliResult::ResultSuccess => {
                    this.done = true;
                    return Poll::Ready(Ok(()));
                }
                brotli::BrotliResult::NeedsMoreOutput => return Poll::Ready(Ok(())),
                brotli::BrotliResult::NeedsMoreInput => {
                    if out_off > 0 {
                        return Poll::Ready(Ok(()));
                    }
                    if eof {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "truncated brotli stream",
                        )));
                    }
                }
                brotli::BrotliResult::ResultFailure => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "brotli error",
                    )))
                }
            }
        }
    }
}

fn buffered<R: AsyncRead + Send + 'static>(r: R) -> DynBufRead {
    Box::pin(BufReader::with_capacity(32 * 1024, r))
}

/// Wrap `input` in the decoders for `codings`, outermost (last applied) first, behind the
/// expansion-ratio guard. At most [`MAX_CODINGS`] layers.
pub async fn decode_chain(input: DynBufRead, codings: &[Coding]) -> io::Result<DynBufRead> {
    if codings.is_empty() {
        return Ok(input);
    }
    if codings.len() > MAX_CODINGS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "too many content codings",
        ));
    }
    let compressed = Arc::new(AtomicU64::new(0));
    let mut input: DynBufRead = Box::pin(Counting {
        inner: input,
        n: compressed.clone(),
    });
    for coding in codings.iter().rev() {
        input = match coding {
            Coding::Gzip => {
                let mut d = dec::GzipDecoder::new(input);
                d.multiple_members(true);
                buffered(d)
            }
            Coding::Brotli => buffered(StrictBrotli::new(input)),
            Coding::Zstd => {
                let mut d = dec::ZstdDecoder::with_codec(
                    input,
                    async_compression::codecs::zstd::ZstdDecoder::new_with_params(&[
                        async_compression::zstd::DParameter::window_log_max(ZSTD_WINDOW_LOG_MAX),
                    ]),
                );
                d.multiple_members(true);
                buffered(d)
            }
            Coding::Deflate => {
                // Servers send both zlib-wrapped (the RFC) and raw deflate: look at the header.
                let head = input.fill_buf().await?;
                let zlib = head.len() >= 2
                    && head[0] & 0x0f == 8
                    && ((u16::from(head[0]) << 8) | u16::from(head[1])) % 31 == 0;
                if zlib {
                    buffered(dec::ZlibDecoder::new(input))
                } else {
                    buffered(dec::DeflateDecoder::new(input))
                }
            }
        };
    }
    Ok(Box::pin(Guard {
        inner: input,
        compressed,
        decoded: 0,
    }))
}

enum Op {
    Write(Bytes),
    Flush,
    Finish,
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

    /// [`Self::write`] on the blocking pool: compression is CPU-bound (a brotli encoder's first
    /// write takes tens of milliseconds, a 32 KiB gzip chunk about a millisecond), which must not
    /// be spent on an async worker.
    pub async fn write_off(&mut self, data: Bytes) -> io::Result<()> {
        self.run_off(Op::Write(data)).await.map(drop)
    }

    /// [`Self::flush`] on the blocking pool.
    pub async fn flush_off(&mut self) -> io::Result<()> {
        self.run_off(Op::Flush).await.map(drop)
    }

    /// [`Self::finish`] on the blocking pool.
    pub async fn finish_off(&mut self) -> io::Result<Bytes> {
        self.run_off(Op::Finish).await
    }

    async fn apply(&mut self, op: Op) -> io::Result<Bytes> {
        match op {
            Op::Write(d) => self.write(&d).await.map(|()| Bytes::new()),
            Op::Flush => self.flush().await.map(|()| Bytes::new()),
            Op::Finish => self.finish().await,
        }
    }

    async fn run_off(&mut self, op: Op) -> io::Result<Bytes> {
        if let Encoder::Identity(_) = self {
            return self.apply(op).await;
        }
        let mut taken = std::mem::replace(self, Encoder::Identity(Vec::new()));
        let handle = tokio::runtime::Handle::current();
        let (enc, r) = tokio::task::spawn_blocking(move || {
            // The encoders write into a `Vec`: their futures never wait on I/O.
            let r = handle.block_on(taken.apply(op));
            (taken, r)
        })
        .await
        .map_err(io::Error::other)?;
        *self = enc;
        r
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
        // Stacked beyond the cap (also across separate header lines).
        assert!(response_codings(&hm(&[("content-encoding", "gzip, gzip, gzip")])).is_err());
        assert!(response_codings(&hm(&[
            ("content-encoding", "gzip, gzip"),
            ("content-encoding", "gzip")
        ]))
        .is_err());
        let many = vec!["gzip"; 500].join(", ");
        assert!(response_codings(&hm(&[("content-encoding", &many)])).is_err());
        assert!(response_codings(&hm(&[("content-encoding", "compress")])).is_err());
    }

    #[tokio::test]
    async fn expansion_bomb_is_cut_off() {
        // 64 MiB of zeros gzips to ~64 KiB (1000:1): past the grace amount and the ratio limit.
        let zeros = vec![0u8; 64 * 1024 * 1024];
        let bomb = encode(Some(Coding::Gzip), &zeros, 1 << 20).await;
        let err = decode(bomb, &[Coding::Gzip]).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        // An ordinary document is unaffected (covered by roundtrip_every_coding).
    }

    #[tokio::test]
    async fn too_many_layers_are_refused_by_decode_chain() {
        let data = sample();
        let enc = encode(Some(Coding::Gzip), &data, 8192).await;
        let input: DynBufRead = Box::pin(BufReader::new(io::Cursor::new(enc)));
        assert!(decode_chain(input, &[Coding::Gzip; 3]).await.is_err());
    }

    #[tokio::test]
    async fn zstd_window_above_8_mib_is_rejected() {
        use async_compression::zstd::CParameter;
        let data = sample();
        let mut e = enc::ZstdEncoder::with_quality_and_params(
            Vec::new(),
            Level::Default,
            &[
                CParameter::window_log(26),
                CParameter::enable_long_distance_matching(true),
            ],
        );
        e.write_all(&data).await.unwrap();
        e.shutdown().await.unwrap();
        let big_window = e.into_inner();
        assert!(decode(big_window, &[Coding::Zstd]).await.is_err());
        // 8 MiB (windowLog 23) still decodes.
        let mut e = enc::ZstdEncoder::with_quality_and_params(
            Vec::new(),
            Level::Default,
            &[CParameter::window_log(23)],
        );
        e.write_all(&data).await.unwrap();
        e.shutdown().await.unwrap();
        assert_eq!(decode(e.into_inner(), &[Coding::Zstd]).await.unwrap(), data);
    }

    #[tokio::test]
    async fn brotli_large_window_is_rejected() {
        use std::io::Write;
        let data = sample();
        let params = brotli::enc::BrotliEncoderParams {
            large_window: true,
            lgwin: 26,
            quality: 5,
            ..Default::default()
        };
        let mut out = Vec::new();
        {
            let mut w = brotli::CompressorWriter::with_params(&mut out, 4096, &params);
            w.write_all(&data).unwrap();
        }
        assert!(decode(out, &[Coding::Brotli]).await.is_err());
        // The standard 16 MiB window is fine.
        let std_params = brotli::enc::BrotliEncoderParams {
            lgwin: 24,
            quality: 5,
            ..Default::default()
        };
        let mut out = Vec::new();
        {
            let mut w = brotli::CompressorWriter::with_params(&mut out, 4096, &std_params);
            w.write_all(&data).unwrap();
        }
        assert_eq!(decode(out, &[Coding::Brotli]).await.unwrap(), data);
    }

    /// Manual measurement (`cargo test --release -p proxy-core --lib encode_chunk_timing --
    /// --ignored --nocapture`): CPU time of one encoder write, which is what a single poll of the
    /// response stream spends on compression.
    #[tokio::test]
    #[ignore]
    async fn encode_chunk_timing() {
        let mut x = 0x2545_f491_4f6c_dd1du64;
        let mut doc = String::new();
        while doc.len() < 8 * 1024 * 1024 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            doc.push_str(&format!(
                "<div class=\"c{}\" data-id=\"{}\"><a href=\"/p/{}?ref={:x}\">item {} title text</a></div>\n",
                x % 23,
                x % 100_000,
                x % 977,
                x,
                x % 5000
            ));
        }
        let data = doc.as_bytes();
        for coding in [Coding::Zstd, Coding::Brotli, Coding::Gzip, Coding::Deflate] {
            for chunk in [32 * 1024usize, 256 * 1024] {
                let mut e = Encoder::new(Some(coding));
                let (mut max, mut sum, mut n) =
                    (std::time::Duration::ZERO, std::time::Duration::ZERO, 0u32);
                for c in data.chunks(chunk) {
                    let t = std::time::Instant::now();
                    e.write(c).await.unwrap();
                    let d = t.elapsed();
                    max = max.max(d);
                    sum += d;
                    n += 1;
                    let _ = e.take();
                }
                let t = std::time::Instant::now();
                e.flush().await.unwrap();
                let fl = t.elapsed();
                println!(
                    "{coding:?} chunk {:>3} KiB: mean {:>7.1?} max {:>7.1?} flush {:>7.1?}",
                    chunk / 1024,
                    sum / n,
                    max,
                    fl
                );
            }
        }
    }
}
