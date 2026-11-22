//! Streaming body assembly: peek, decide, transform, re-encode.

use super::charset::{self, Detected};
use super::codec::{decode_chain, Coding, DynBufRead, Encoder};
use super::html::{sniff_html, RewriteStage};
use super::{BodyTransform, HtmlPlan};
use crate::inject::{full_body, ProxyBody};
use bytes::Bytes;
use futures_util::stream::{self, BoxStream};
use futures_util::{FutureExt, Stream, StreamExt, TryStreamExt};
use http_body_util::{BodyExt, StreamBody};
use hyper::body::Frame;
use parking_lot::Mutex;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::AsyncBufReadExt;
use tokio_util::io::StreamReader;

/// Decoded bytes inspected before deciding (charset prescan window).
const PEEK_LEN: usize = charset::PRESCAN_LEN;
/// Longest the first window waits for more bytes once some content has arrived.
const PEEK_WAIT: Duration = Duration::from_millis(250);
/// Yield to the scheduler after this many bytes of CPU-bound work.
const YIELD_EVERY: usize = 256 * 1024;

static PEAK_BUFFERED: AtomicUsize = AtomicUsize::new(0);

/// Largest number of body bytes any rewrite stage held at once since the last
/// [`reset_peak_buffered`] (input window + output window; fixed-size codec buffers excluded).
pub fn peak_buffered_bytes() -> usize {
    PEAK_BUFFERED.load(Ordering::Relaxed)
}

/// Reset the gauge (tests).
pub fn reset_peak_buffered() {
    PEAK_BUFFERED.store(0, Ordering::Relaxed);
}

fn note_buffered(n: usize) {
    PEAK_BUFFERED.fetch_max(n, Ordering::Relaxed);
}

/// The upstream body stream, shared so that the original bytes consumed while peeking can be
/// replayed when the response turns out not to be transformable.
struct Raw {
    inner: BoxStream<'static, io::Result<Bytes>>,
    recorded: Vec<Bytes>,
    recording: bool,
}

#[derive(Clone)]
struct SharedRaw(Arc<Mutex<Raw>>);

impl SharedRaw {
    fn new(inner: BoxStream<'static, io::Result<Bytes>>) -> Self {
        Self(Arc::new(Mutex::new(Raw {
            inner,
            recorded: Vec::new(),
            recording: true,
        })))
    }

    fn stop_recording(&self) {
        let mut g = self.0.lock();
        g.recording = false;
        g.recorded = Vec::new();
    }

    fn recorded_len(&self) -> usize {
        self.0.lock().recorded.iter().map(Bytes::len).sum()
    }

    /// Everything the origin sent: recorded chunks, then the rest of the stream.
    fn replay(self) -> ProxyBody {
        let recorded = {
            let mut g = self.0.lock();
            g.recording = false;
            std::mem::take(&mut g.recorded)
        };
        stream_body(stream::iter(recorded.into_iter().map(Ok)).chain(self))
    }
}

impl Stream for SharedRaw {
    type Item = io::Result<Bytes>;
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut g = self.0.lock();
        let p = g.inner.poll_next_unpin(cx);
        if let Poll::Ready(Some(Ok(b))) = &p {
            if g.recording {
                g.recorded.push(b.clone());
            }
        }
        p
    }
}

fn stream_body<S>(s: S) -> ProxyBody
where
    S: Stream<Item = io::Result<Bytes>> + Send + 'static,
{
    BodyExt::boxed_unsync(StreamBody::new(s.map(|r| r.map(Frame::data))))
}

/// Result of running a body through the pipeline.
pub enum Outcome {
    /// The body is exactly what the origin sent (headers must stay as they were).
    Untouched(ProxyBody),
    /// A rewritten HTML body.
    Html {
        body: ProxyBody,
        /// The document was transcoded to UTF-8: the `Content-Type` charset must say so.
        utf8_charset: bool,
    },
    /// A rewritten whole-body (JSON/text) response.
    Text { body: ProxyBody },
}

fn open(
    resp: reqwest::Response,
    codings: &[Coding],
) -> (SharedRaw, impl std::future::Future<Output = io::Result<DynBufRead>> + '_) {
    let raw = SharedRaw::new(resp.bytes_stream().map_err(io::Error::other).boxed());
    let input: DynBufRead = Box::pin(StreamReader::new(raw.clone()));
    (raw, decode_chain(input, codings))
}

/// Read decoded bytes into `peek` until it holds `PEEK_LEN` bytes, EOF, or (once some
/// non-whitespace has arrived) the peek wait expires. Returns `(eof)`.
async fn fill_peek(reader: &mut DynBufRead, peek: &mut Vec<u8>) -> io::Result<bool> {
    let started = tokio::time::Instant::now();
    loop {
        if peek.len() >= PEEK_LEN {
            return Ok(false);
        }
        let has_content = peek.iter().any(|b| !b.is_ascii_whitespace());
        let fut = reader.fill_buf();
        let buf = if has_content {
            let left = PEEK_WAIT.saturating_sub(started.elapsed());
            match tokio::time::timeout(left, fut).await {
                Ok(r) => r?,
                Err(_) => return Ok(false),
            }
        } else {
            fut.await?
        };
        if buf.is_empty() {
            return Ok(true);
        }
        let take = buf.len().min(PEEK_LEN * 4);
        peek.extend_from_slice(&buf[..take]);
        reader.consume(take);
    }
}

/// Decode a prefix to UTF-8 for sniffing (transcode path only).
fn utf8_prefix(det: &Detected, peek: &[u8]) -> Vec<u8> {
    let mut dec = det.encoding.new_decoder_without_bom_handling();
    let src = &peek[det.bom_len.min(peek.len())..];
    let mut out = vec![0u8; dec.max_utf8_buffer_length(src.len()).unwrap_or(src.len() * 3 + 16)];
    let (_, _, written, _) = dec.decode_to_utf8(src, &mut out, false);
    out.truncate(written);
    out
}

/// Run an HTML document through decode → charset → `plan` → re-encode.
pub async fn transform_html(
    resp: reqwest::Response,
    codings: Vec<Coding>,
    out_coding: Option<Coding>,
    content_type: Option<String>,
    plan: HtmlPlan,
) -> Outcome {
    let (raw, opening) = open(resp, &codings);
    let Ok(mut reader) = opening.await else {
        return Outcome::Untouched(raw.replay());
    };
    let mut peek = Vec::with_capacity(PEEK_LEN + 512);
    match fill_peek(&mut reader, &mut peek).await {
        Ok(_) => {}
        Err(_) => return Outcome::Untouched(raw.replay()),
    }

    let det = charset::detect(content_type.as_deref(), &peek);
    if charset::is_unusable(det.encoding) {
        return Outcome::Untouched(raw.replay());
    }
    let transcode = charset::needs_transcode(det.encoding);
    let is_html = if transcode {
        sniff_html(&utf8_prefix(&det, &peek))
    } else {
        sniff_html(&peek)
    };
    if !is_html {
        return Outcome::Untouched(raw.replay());
    }
    let Ok(stage) = RewriteStage::new(&plan, det.encoding, transcode, det.bom_len) else {
        return Outcome::Untouched(raw.replay());
    };
    raw.stop_recording();

    let rewritten = rewrite_stream(reader, peek, stage);
    let body = match out_coding {
        Some(_) => stream_body(encode_stream(rewritten, out_coding)),
        None => stream_body(rewritten),
    };
    Outcome::Html {
        body,
        utf8_charset: transcode,
    }
}

fn rewrite_stream(
    mut reader: DynBufRead,
    peek: Vec<u8>,
    mut stage: RewriteStage,
) -> impl Stream<Item = io::Result<Bytes>> + Send {
    async_stream::try_stream! {
        let out = stage.push(&peek)?;
        note_buffered(peek.len() + out.len());
        drop(peek);
        if !out.is_empty() {
            yield out;
        }
        let mut since_yield = 0usize;
        loop {
            let buf = reader.fill_buf().await?;
            if buf.is_empty() {
                break;
            }
            let n = buf.len();
            let out = stage.push(buf)?;
            note_buffered(n + out.len());
            reader.consume(n);
            if !out.is_empty() {
                yield out;
            }
            since_yield += n;
            if since_yield >= YIELD_EVERY {
                since_yield = 0;
                tokio::task::yield_now().await;
            }
        }
        let tail = stage.finish()?;
        if !tail.is_empty() {
            yield tail;
        }
    }
}

/// Compress `input` chunks. The encoder is flushed whenever the upstream has nothing ready, so a
/// slowly streaming page still reaches the browser promptly, and left to batch otherwise.
pub fn encode_stream<S>(
    input: S,
    coding: Option<Coding>,
) -> impl Stream<Item = io::Result<Bytes>> + Send
where
    S: Stream<Item = io::Result<Bytes>> + Send + 'static,
{
    async_stream::try_stream! {
        let mut input = Box::pin(input);
        let mut enc = Encoder::new(coding);
        let mut since_yield = 0usize;
        loop {
            let next = match input.next().now_or_never() {
                Some(n) => n,
                None => {
                    enc.flush().await?;
                    let out = enc.take();
                    if !out.is_empty() {
                        yield out;
                    }
                    input.next().await
                }
            };
            match next {
                None => break,
                Some(Err(e)) => Err(e)?,
                Some(Ok(chunk)) => {
                    enc.write(&chunk).await?;
                    note_buffered(chunk.len());
                    since_yield += chunk.len();
                    let out = enc.take();
                    if !out.is_empty() {
                        yield out;
                    }
                    if since_yield >= YIELD_EVERY {
                        since_yield = 0;
                        tokio::task::yield_now().await;
                    }
                }
            }
        }
        let tail = enc.finish().await?;
        if !tail.is_empty() {
            yield tail;
        }
    }
}

/// Buffer a decoded non-HTML body (up to the transform's cap) and apply `transform`.
pub async fn transform_text(
    resp: reqwest::Response,
    codings: Vec<Coding>,
    out_coding: Option<Coding>,
    transform: Arc<dyn BodyTransform>,
) -> Outcome {
    let cap = transform.max_body_bytes();
    let (raw, opening) = open(resp, &codings);
    let Ok(mut reader) = opening.await else {
        return Outcome::Untouched(raw.replay());
    };
    let mut body: Vec<u8> = Vec::new();
    loop {
        let buf = match reader.fill_buf().await {
            Ok(b) => b,
            Err(_) => return Outcome::Untouched(raw.replay()),
        };
        if buf.is_empty() {
            break;
        }
        let n = buf.len();
        body.extend_from_slice(buf);
        reader.consume(n);
        if body.len() > cap || raw.recorded_len() > cap.saturating_mul(2) {
            // Too big: send what the origin sent, unmodified.
            return Outcome::Untouched(raw.replay());
        }
    }
    note_buffered(body.len());
    let Some(new) = transform.apply(&body) else {
        return Outcome::Untouched(raw.replay());
    };
    let mut enc = Encoder::new(out_coding);
    let encoded = async {
        enc.write(&new).await?;
        let mut v = enc.take().to_vec();
        v.extend_from_slice(&enc.finish().await?);
        io::Result::Ok(v)
    }
    .await;
    match encoded {
        Ok(v) => Outcome::Text {
            body: full_body(Bytes::from(v)),
        },
        Err(_) => Outcome::Untouched(raw.replay()),
    }
}
