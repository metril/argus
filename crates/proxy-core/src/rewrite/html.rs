//! The HTML stage: a `lol_html` rewriter driven in small windows.
//!
//! Charset strategy: ASCII-compatible encodings (UTF-8, windows-125x, Shift_JIS, GBK, EUC-*,
//! Big5, ...) are handed to `lol_html` as they are: the page's bytes are never transcoded, and
//! everything we insert is pure ASCII (non-ASCII is escaped in CSS/JSON), so text around the
//! injection stays byte-identical. Encodings `lol_html` cannot take (UTF-16, ISO-2022-JP) are
//! decoded to UTF-8 with `encoding_rs`, and the declared charset is fixed up in the header and
//! in `<meta>`.

use super::{HtmlPlan, InjectPos};
use bytes::Bytes;
use encoding_rs::{Decoder, Encoding};
use lol_html::html_content::ContentType;
use lol_html::{element, text, MemorySettings, Selector};
use parking_lot::Mutex;
use std::io;
use std::sync::Arc;

/// Hard cap on memory `lol_html` may hold for one document (partial tags, long attributes).
const REWRITER_MEMORY_LIMIT: usize = 2 * 1024 * 1024;
/// Largest text node held for replacement rules; longer ones pass unmodified.
const MAX_TEXT_NODE: usize = 256 * 1024;

type Sink = Box<dyn FnMut(&[u8]) + Send>;
type Rewriter = lol_html::send::HtmlRewriter<'static, Sink>;

/// First bytes decide whether a `text/html` body is really an HTML document: it must start with
/// a tag-like token (after whitespace, a BOM and comments), not JSON, XML, JS or plain text.
pub fn sniff_html(b: &[u8]) -> bool {
    let mut i = 0;
    if b.starts_with(&[0xef, 0xbb, 0xbf]) {
        i = 3;
    }
    loop {
        while i < b.len() && matches!(b[i], b' ' | b'\t' | b'\n' | b'\r' | 0x0c) {
            i += 1;
        }
        if i >= b.len() || b[i] != b'<' {
            return false;
        }
        let rest = &b[i + 1..];
        if rest.starts_with(b"!--") {
            match rest[3..].windows(3).position(|w| w == b"-->") {
                Some(p) => {
                    i += 1 + 3 + p + 3;
                    continue;
                }
                // A comment longer than the peek window: the document is HTML-like.
                None => return true,
            }
        }
        if rest.len() >= 8 && rest[..8].eq_ignore_ascii_case(b"!doctype") {
            let after =
                String::from_utf8_lossy(&rest[8..rest.len().min(8 + 24)]).to_ascii_lowercase();
            let after = after.trim_start();
            return after.starts_with("html")
                && after[4..].starts_with(|c: char| c.is_ascii_whitespace() || c == '>')
                || after.len() <= 4 && "html".starts_with(after);
        }
        if rest.first().is_some_and(|c| c.is_ascii_alphabetic()) {
            let end = rest
                .iter()
                .position(|c| !(c.is_ascii_alphanumeric() || *c == b'-' || *c == b':'))
                .unwrap_or(rest.len());
            let name = String::from_utf8_lossy(&rest[..end]).to_ascii_lowercase();
            return !matches!(
                name.as_str(),
                "svg"
                    | "rss"
                    | "feed"
                    | "xml"
                    | "urlset"
                    | "sitemapindex"
                    | "opml"
                    | "plist"
                    | "math"
            );
        }
        return false;
    }
}

/// One document's rewriter plus (for non-ASCII-compatible encodings) its decoder.
pub struct RewriteStage {
    rewriter: Option<Rewriter>,
    out: Arc<Mutex<Vec<u8>>>,
    decoder: Option<Decoder>,
    scratch: Vec<u8>,
    skip: usize,
}

impl RewriteStage {
    /// `encoding`: the document's encoding; `transcode`: decode to UTF-8 first (and fix declared
    /// charsets); `bom_len`: leading BOM bytes to drop when transcoding.
    pub fn new(
        plan: &HtmlPlan,
        encoding: &'static Encoding,
        transcode: bool,
        bom_len: usize,
    ) -> Result<Self, io::Error> {
        let out = Arc::new(Mutex::new(Vec::with_capacity(48 * 1024)));
        let sink_out = out.clone();
        let sink: Sink = Box::new(move |c: &[u8]| sink_out.lock().extend_from_slice(c));

        let mut handlers = Vec::new();

        // Our injection: right after <head> opens, or before the first element that is not
        // <html>; never before the doctype (doctype tokens are not elements).
        let head_html = plan.head_html.clone();
        let head_inj: Vec<String> = plan
            .injections
            .iter()
            .filter(|i| i.pos == InjectPos::HeadStart)
            .map(|i| i.html.clone())
            .collect();
        if !head_html.is_empty() || !head_inj.is_empty() {
            let full: String = head_inj.concat() + &head_html;
            let mut done = false;
            handlers.push(element!("*", move |el| {
                if done {
                    return Ok(());
                }
                let name = el.tag_name();
                if name == "html" {
                    return Ok(());
                }
                done = true;
                if name == "head" {
                    el.prepend(&full, ContentType::Html);
                } else {
                    el.before(&full, ContentType::Html);
                }
                Ok(())
            }));
        }

        for (pos, tag) in [
            (InjectPos::HeadEnd, "head"),
            (InjectPos::BodyStart, "body"),
            (InjectPos::BodyEnd, "body"),
        ] {
            let html: String = plan
                .injections
                .iter()
                .filter(|i| i.pos == pos)
                .map(|i| i.html.as_str())
                .collect();
            if html.is_empty() {
                continue;
            }
            handlers.push(element!(tag, move |el| {
                match pos {
                    InjectPos::BodyStart => el.prepend(&html, ContentType::Html),
                    _ => el.append(&html, ContentType::Html),
                }
                Ok(())
            }));
        }

        for sel in &plan.remove_selectors {
            if sel.parse::<Selector>().is_ok() {
                handlers.push(element!(sel.as_str(), |el| {
                    el.remove();
                    Ok(())
                }));
            } else {
                tracing::debug!("ignoring invalid removal selector {sel:?}");
            }
        }

        for rep in &plan.replacements {
            let sel = rep.selector.clone().unwrap_or_else(|| "*".to_string());
            if sel.parse::<Selector>().is_err() {
                continue;
            }
            let find = rep.find.clone();
            let with = rep.replace.clone();
            let skip_code = rep.selector.is_none();
            let mut buf = String::new();
            handlers.push(text!(sel.as_str(), move |t| {
                if skip_code
                    && matches!(
                        t.text_type(),
                        lol_html::html_content::TextType::ScriptData
                            | lol_html::html_content::TextType::RCData
                            | lol_html::html_content::TextType::RawText
                    )
                {
                    return Ok(());
                }
                buf.push_str(t.as_str());
                if t.last_in_text_node() {
                    let whole = std::mem::take(&mut buf);
                    if whole.len() <= MAX_TEXT_NODE {
                        let new = find.replace_all(&whole, with.as_str());
                        t.replace(&new, ContentType::Text);
                    } else {
                        t.replace(&whole, ContentType::Text);
                    }
                } else if buf.len() > MAX_TEXT_NODE {
                    let whole = std::mem::take(&mut buf);
                    t.replace(&whole, ContentType::Text);
                } else {
                    t.remove();
                }
                Ok(())
            }));
        }

        let meta_csp = plan.meta_csp.clone();
        if meta_csp.is_some() || transcode {
            handlers.push(element!("meta", move |el| {
                if let Some(he) = el.get_attribute("http-equiv") {
                    if he.eq_ignore_ascii_case("content-security-policy") {
                        if let (Some(f), Some(c)) = (&meta_csp, el.get_attribute("content")) {
                            if let Some(new) = f(&c) {
                                el.set_attribute("content", &new)?;
                            }
                        }
                    } else if transcode && he.eq_ignore_ascii_case("content-type") {
                        el.set_attribute("content", "text/html; charset=utf-8")?;
                    }
                }
                if transcode && el.has_attribute("charset") {
                    el.set_attribute("charset", "utf-8")?;
                }
                Ok(())
            }));
        }

        let lol_enc = if transcode {
            encoding_rs::UTF_8
        } else {
            encoding
        };
        let lol_encoding = lol_html::AsciiCompatibleEncoding::new(lol_enc)
            .ok_or_else(|| io::Error::other("encoding is not ASCII-compatible"))?;
        let settings = lol_html::send::Settings {
            element_content_handlers: handlers,
            encoding: lol_encoding,
            memory_settings: MemorySettings {
                max_allowed_memory_usage: REWRITER_MEMORY_LIMIT,
                ..MemorySettings::new()
            },
            strict: false,
            ..lol_html::send::Settings::new_send()
        };
        Ok(Self {
            rewriter: Some(lol_html::send::HtmlRewriter::new(settings, sink)),
            out,
            decoder: transcode.then(|| encoding.new_decoder_without_bom_handling()),
            scratch: vec![0u8; 16 * 1024],
            skip: if transcode { bom_len } else { 0 },
        })
    }

    fn write(&mut self, data: &[u8]) -> io::Result<()> {
        self.rewriter
            .as_mut()
            .ok_or_else(|| io::Error::other("rewriter finished"))?
            .write(data)
            .map_err(|e| io::Error::other(format!("html rewrite: {e}")))
    }

    fn drain(&mut self) -> Bytes {
        let mut g = self.out.lock();
        if g.is_empty() {
            return Bytes::new();
        }
        let cap = g.capacity().min(256 * 1024);
        Bytes::from(std::mem::replace(
            &mut *g,
            Vec::with_capacity(cap.min(64 * 1024)),
        ))
    }

    /// Feed the next window of (decoded-from-transport) document bytes; returns rewritten bytes.
    pub fn push(&mut self, mut input: &[u8]) -> io::Result<Bytes> {
        if self.decoder.is_some() {
            let skip = self.skip.min(input.len());
            self.skip -= skip;
            input = &input[skip..];
            let mut decoder = self.decoder.take().expect("checked");
            let mut scratch = std::mem::take(&mut self.scratch);
            let mut result = Ok(());
            loop {
                let (res, read, written, _) = decoder.decode_to_utf8(input, &mut scratch, false);
                if written > 0 {
                    if let Err(e) = self.write(&scratch[..written]) {
                        result = Err(e);
                        break;
                    }
                }
                input = &input[read..];
                if res == encoding_rs::CoderResult::InputEmpty {
                    break;
                }
            }
            self.decoder = Some(decoder);
            self.scratch = scratch;
            result?;
        } else {
            self.write(input)?;
        }
        Ok(self.drain())
    }

    /// Flush the decoder and the rewriter; call once after the last window.
    pub fn finish(&mut self) -> io::Result<Bytes> {
        if let Some(mut decoder) = self.decoder.take() {
            let mut scratch = std::mem::take(&mut self.scratch);
            loop {
                let (res, _, written, _) = decoder.decode_to_utf8(&[], &mut scratch, true);
                if written > 0 {
                    self.write(&scratch[..written])?;
                }
                if res == encoding_rs::CoderResult::InputEmpty {
                    break;
                }
            }
        }
        if let Some(r) = self.rewriter.take() {
            r.end()
                .map_err(|e| io::Error::other(format!("html rewrite: {e}")))?;
        }
        Ok(self.drain())
    }
}
