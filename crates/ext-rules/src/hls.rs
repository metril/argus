//! `$hls`: remove segments / tags from an HLS (`.m3u8`) playlist.
//!
//! AdGuard KB "$hls" and uBO `m3u-prune`: the playlist is split into segments, each being the run
//! of `#` tag lines followed by the URI line they describe; a segment whose text (tag lines and URI
//! joined by `\n`) matches the regular expression is removed whole. Trailing tags without a URI are
//! tested as one group. Playlist-level tags (`#EXTM3U`, `#EXT-X-VERSION`, `#EXT-X-TARGETDURATION`,
//! `#EXT-X-MEDIA-SEQUENCE`, `#EXT-X-ENDLIST`, ...) are never removed. The value is `/regex/flags`
//! (flags `i`, `s`, `m`) or a plain string matched literally.

use std::borrow::Cow;

use regex::{Regex, RegexBuilder};

pub const MAX_HLS_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct HlsPrune {
    /// The option value as written.
    pub value: String,
    re: Regex,
}

impl HlsPrune {
    pub fn parse(value: &str) -> Result<Self, String> {
        let v = value.trim();
        if v.is_empty() {
            return Err("empty pattern".into());
        }
        let (src, flags) = match v
            .strip_prefix('/')
            .and_then(|r| r.rfind('/').map(|i| (&r[..i], &r[i + 1..])))
        {
            Some((s, f)) if !s.is_empty() => (s.replace("\\/", "/"), f),
            _ => (regex::escape(v), ""),
        };
        let mut b = RegexBuilder::new(&src);
        b.size_limit(1 << 20);
        for f in flags.chars() {
            match f {
                'i' => b.case_insensitive(true),
                's' => b.dot_matches_new_line(true),
                'm' => b.multi_line(true),
                'g' => &mut b,
                o => return Err(format!("unknown regex flag `{o}`")),
            };
        }
        let re = b.build().map_err(|e| format!("unsupported regex: {e}"))?;
        Ok(Self {
            value: value.to_string(),
            re,
        })
    }
}

fn is_playlist_tag(l: &str) -> bool {
    const KEEP: [&str; 9] = [
        "#EXTM3U",
        "#EXT-X-VERSION",
        "#EXT-X-TARGETDURATION",
        "#EXT-X-MEDIA-SEQUENCE",
        "#EXT-X-DISCONTINUITY-SEQUENCE",
        "#EXT-X-ENDLIST",
        "#EXT-X-PLAYLIST-TYPE",
        "#EXT-X-INDEPENDENT-SEGMENTS",
        "#EXT-X-I-FRAMES-ONLY",
    ];
    KEEP.iter().any(|k| l.starts_with(k))
}

/// Remove matching segments. Non-playlists, oversized bodies and playlists with no match are
/// returned untouched.
pub fn apply_hls<'a>(body: &'a [u8], specs: &[&HlsPrune]) -> Cow<'a, [u8]> {
    if body.len() > MAX_HLS_BYTES || specs.is_empty() {
        return Cow::Borrowed(body);
    }
    let Ok(text) = std::str::from_utf8(body) else {
        return Cow::Borrowed(body);
    };
    if !text
        .trim_start_matches('\u{feff}')
        .trim_start()
        .starts_with("#EXTM3U")
    {
        return Cow::Borrowed(body);
    }
    let hit = |group: &[&str]| {
        let joined = group
            .iter()
            .map(|l| l.trim_end_matches(['\r', '\n']))
            .collect::<Vec<_>>()
            .join("\n");
        specs.iter().any(|s| s.re.is_match(&joined))
    };
    let mut out = String::with_capacity(text.len());
    let mut pending: Vec<&str> = Vec::new();
    let mut removed = false;
    let flush = |pending: &mut Vec<&str>, out: &mut String, removed: &mut bool| {
        if pending.is_empty() {
            return;
        }
        if hit(pending) {
            *removed = true;
        } else {
            pending.iter().for_each(|l| out.push_str(l));
        }
        pending.clear();
    };
    for line in text.split_inclusive('\n') {
        let t = line.trim();
        if t.is_empty() {
            flush(&mut pending, &mut out, &mut removed);
            out.push_str(line);
        } else if t.starts_with('#') {
            if is_playlist_tag(t) {
                flush(&mut pending, &mut out, &mut removed);
                out.push_str(line);
            } else {
                pending.push(line);
            }
        } else {
            pending.push(line);
            flush(&mut pending, &mut out, &mut removed);
        }
    }
    flush(&mut pending, &mut out, &mut removed);
    if removed {
        Cow::Owned(out.into_bytes())
    } else {
        Cow::Borrowed(body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PL: &str = "#EXTM3U\n#EXT-X-VERSION:3\n#EXT-X-TARGETDURATION:6\n#EXTINF:6,\nseg1.ts\n#EXT-X-DISCONTINUITY\n#EXTINF:5,ad\nhttps://ads.example/ad1.ts\n#EXTINF:6,\nseg2.ts\n#EXT-X-ENDLIST\n";

    fn run(v: &str, pl: &str) -> String {
        let p = HlsPrune::parse(v).unwrap();
        String::from_utf8(apply_hls(pl.as_bytes(), &[&p]).into_owned()).unwrap()
    }

    #[test]
    fn removes_matching_segments() {
        assert_eq!(
            run("/ads\\.example/", PL),
            "#EXTM3U\n#EXT-X-VERSION:3\n#EXT-X-TARGETDURATION:6\n#EXTINF:6,\nseg1.ts\n#EXTINF:6,\nseg2.ts\n#EXT-X-ENDLIST\n"
        );
        assert_eq!(run("ads.example/ad1", PL).matches("ad1").count(), 0);
        assert_eq!(run("/#EXTINF:5,AD/i", PL).matches("seg").count(), 2);
        assert_eq!(run("/nomatch/", PL), PL);
        // CRLF preserved
        assert!(run("ad1", &PL.replace('\n', "\r\n")).contains("seg2.ts\r\n"));
        // not a playlist
        assert_eq!(run("ad", "hello ad"), "hello ad");
    }

    #[test]
    fn never_removes_playlist_tags() {
        assert_eq!(
            run("/EXT/", "#EXTM3U\n#EXT-X-ENDLIST\n"),
            "#EXTM3U\n#EXT-X-ENDLIST\n"
        );
    }
}
