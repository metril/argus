//! Streaming body assembly: peek, decide, transform, re-encode.

use super::charset::{self, Detected};
use super::codec::{decode_chain, Coding, DynBufRead, Encoder};
use super::html::{sniff_html, sniff_prefix, RewriteStage, Sniff};
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

/// Largest decoded document buffered for body transforms / content-dependent removals.
const MAX_HTML_BUFFER: usize = 4 * 1024 * 1024;

static PEAK_BUFFERED: AtomicUsize = AtomicUsize::new(0);
static OVER_CAP: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// How many responses were left untouched (by a body transform or content-dependent removal)
/// because their decoded body exceeded the size cap.
pub fn over_cap_total() -> u64 {
    OVER_CAP.load(Ordering::Relaxed)
}

fn note_over_cap() {
    OVER_CAP.fetch_add(1, Ordering::Relaxed);
}

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
        /// A body transform or removal changed the document's own bytes (not just injections).
        body_changed: bool,
    },
    /// A rewritten whole-body (JSON/text) response.
    Text { body: ProxyBody },
}

fn open(
    resp: reqwest::Response,
    codings: &[Coding],
) -> (
    SharedRaw,
    impl std::future::Future<Output = io::Result<DynBufRead>> + '_,
) {
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
    let mut out = vec![
        0u8;
        dec.max_utf8_buffer_length(src.len())
            .unwrap_or(src.len() * 3 + 16)
    ];
    let (_, _, written, _) = dec.decode_to_utf8(src, &mut out, false);
    out.truncate(written);
    out
}

/// Run an HTML document through decode → charset → `plan` → re-encode.
///
/// `pre` (a `$replace`-style body transform) runs on the whole decoded document first; then the
/// HTML stages run on its result (content-dependent removals, injection, cosmetics). Both need
/// the document buffered, up to [`MAX_HTML_BUFFER`] and the transform's own cap; a larger one is
/// streamed through the HTML stages without them and counted ([`over_cap_total`]).
pub async fn transform_html(
    resp: reqwest::Response,
    codings: Vec<Coding>,
    out_coding: Option<Coding>,
    content_type: Option<String>,
    plan: HtmlPlan,
    pre: Option<Arc<dyn BodyTransform>>,
) -> Outcome {
    let (raw, opening) = open(resp, &codings);
    let Ok(mut reader) = opening.await else {
        return Outcome::Untouched(raw.replay());
    };
    let mut changed_body = false;
    if pre.is_some() || !plan.element_filters.is_empty() {
        let cap = pre
            .as_ref()
            .map_or(MAX_HTML_BUFFER, |p| p.max_body_bytes().min(MAX_HTML_BUFFER));
        let mut buf: Vec<u8> = Vec::new();
        let mut too_big = false;
        loop {
            let chunk = match reader.fill_buf().await {
                Ok(b) => b,
                Err(_) => return Outcome::Untouched(raw.replay()),
            };
            if chunk.is_empty() {
                break;
            }
            let n = chunk.len();
            buf.extend_from_slice(chunk);
            reader.consume(n);
            if buf.len() > cap {
                too_big = true;
                break;
            }
        }
        if too_big {
            note_over_cap();
            reader = Box::pin(tokio::io::AsyncReadExt::chain(io::Cursor::new(buf), reader));
        } else {
            note_buffered(buf.len());
            let det = charset::detect(content_type.as_deref(), &buf[..buf.len().min(PEEK_LEN)]);
            let eligible = !charset::is_unusable(det.encoding)
                && !charset::needs_transcode(det.encoding)
                && sniff_html(&buf[..buf.len().min(PEEK_LEN)]);
            if eligible {
                if let Some(t) = &pre {
                    if let Some(new) = t.apply(&buf) {
                        buf = new;
                        changed_body = true;
                    }
                }
                if !plan.element_filters.is_empty() {
                    if let Ok(new) = super::html::apply_element_filters(
                        &buf,
                        det.encoding,
                        &plan.element_filters,
                    ) {
                        changed_body |= new != buf;
                        buf = new;
                    }
                }
            }
            reader = Box::pin(io::Cursor::new(buf));
        }
    }
    let mut peek = Vec::with_capacity(PEEK_LEN + 512);
    let eof = match fill_peek(&mut reader, &mut peek).await {
        Ok(eof) => eof,
        Err(_) => return Outcome::Untouched(raw.replay()),
    };

    let det = charset::detect(content_type.as_deref(), &peek);
    if charset::is_unusable(det.encoding) {
        return Outcome::Untouched(raw.replay());
    }
    let transcode = charset::needs_transcode(det.encoding);
    // This is a document navigation answered as `text/html`: sniffing only vetoes bodies that are
    // plainly something else (JSON, XML, text...). A start that has not fully arrived when the
    // wait expires is not a veto, so an origin cannot drip bytes to make us skip injection.
    let verdict = if transcode {
        sniff_prefix(&utf8_prefix(&det, &peek))
    } else {
        sniff_prefix(&peek)
    };
    let is_html = match verdict {
        Sniff::Html => true,
        Sniff::NotHtml => false,
        Sniff::Undecided => !eof,
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
        body_changed: changed_body,
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
                    enc.flush_off().await?;
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
                    let n = chunk.len();
                    enc.write_off(chunk).await?;
                    note_buffered(n);
                    since_yield += n;
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
        let tail = enc.finish_off().await?;
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
            note_over_cap();
            return Outcome::Untouched(raw.replay());
        }
    }
    note_buffered(body.len());
    let Some(new) = transform.apply(&body) else {
        return Outcome::Untouched(raw.replay());
    };
    let mut enc = Encoder::new(out_coding);
    let encoded = async {
        enc.write_off(Bytes::from(new)).await?;
        let mut v = enc.take().to_vec();
        v.extend_from_slice(&enc.finish_off().await?);
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Re-encoding is CPU-bound (a brotli encoder's first write alone takes tens of
    /// milliseconds): it must not run on the async worker, where it would stall every other
    /// connection scheduled there. The CPU time the polling thread spends inside any single
    /// poll of the stream is measured (thread CPU clock, so a loaded machine's scheduling
    /// delays do not count): a poll that encodes inline costs tens of milliseconds of it.
    fn thread_cpu_us() -> u64 {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: valid pointer to a timespec.
        unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut ts) };
        ts.tv_sec as u64 * 1_000_000 + ts.tv_nsec as u64 / 1000
    }

    #[tokio::test]
    async fn reencoding_does_not_stall_the_async_worker() {
        let mut x = 0x2545_f491_4f6c_dd1du64;
        let chunks: Vec<Bytes> = (0..24)
            .map(|_| {
                let mut s = String::new();
                while s.len() < 32 * 1024 {
                    x ^= x << 13;
                    x ^= x >> 7;
                    x ^= x << 17;
                    s.push_str(&format!(
                        "<div class=\"c{}\"><a href=\"/p/{x:x}\">item {}</a></div>\n",
                        x % 23,
                        x % 5000
                    ));
                }
                Bytes::from(s)
            })
            .collect();
        for coding in [Coding::Brotli, Coding::Zstd, Coding::Gzip] {
            let input = stream::iter(chunks.clone().into_iter().map(Ok));
            let mut out = Box::pin(encode_stream(input, Some(coding)));
            let mut worst = 0u64;
            let mut timed = Box::pin(stream::poll_fn(|cx| {
                let t0 = thread_cpu_us();
                let r = out.as_mut().poll_next(cx);
                worst = worst.max(thread_cpu_us() - t0);
                r
            }));
            let mut n = 0usize;
            while let Some(c) = timed.next().await {
                n += c.unwrap().len();
            }
            drop(timed);
            assert!(n > 0);
            assert!(
                worst < 12_000,
                "{coding:?}: one poll held the async worker for {worst} us of CPU"
            );
        }
    }
}
