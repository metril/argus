//! Compression helpers for building origin bodies and checking proxy output.

use async_compression::tokio::bufread as dec;
use async_compression::tokio::write as enc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Coding {
    Gzip,
    Deflate,
    Br,
    Zstd,
}

impl Coding {
    pub fn token(self) -> &'static str {
        match self {
            Coding::Gzip => "gzip",
            Coding::Deflate => "deflate",
            Coding::Br => "br",
            Coding::Zstd => "zstd",
        }
    }
}

pub async fn encode(c: Coding, data: &[u8]) -> Vec<u8> {
    macro_rules! go {
        ($e:ty) => {{
            let mut e = <$e>::new(Vec::new());
            e.write_all(data).await.unwrap();
            e.shutdown().await.unwrap();
            e.into_inner()
        }};
    }
    match c {
        Coding::Gzip => go!(enc::GzipEncoder<Vec<u8>>),
        Coding::Deflate => go!(enc::ZlibEncoder<Vec<u8>>),
        Coding::Br => go!(enc::BrotliEncoder<Vec<u8>>),
        Coding::Zstd => go!(enc::ZstdEncoder<Vec<u8>>),
    }
}

/// Encode with several codings, in order (`Content-Encoding: a, b` = `a` applied first).
pub async fn encode_stacked(codings: &[Coding], data: &[u8]) -> Vec<u8> {
    let mut cur = data.to_vec();
    for c in codings {
        cur = encode(*c, &cur).await;
    }
    cur
}

/// Decode `data` as `Content-Encoding: codings` (listed order = applied order).
pub async fn decode(codings: &[Coding], data: &[u8]) -> Vec<u8> {
    let mut cur = data.to_vec();
    for c in codings.iter().rev() {
        let r = BufReader::new(std::io::Cursor::new(cur));
        let mut out = Vec::new();
        match c {
            Coding::Gzip => dec::GzipDecoder::new(r).read_to_end(&mut out).await,
            Coding::Deflate => dec::ZlibDecoder::new(r).read_to_end(&mut out).await,
            Coding::Br => dec::BrotliDecoder::new(r).read_to_end(&mut out).await,
            Coding::Zstd => dec::ZstdDecoder::new(r).read_to_end(&mut out).await,
        }
        .unwrap_or_else(|e| panic!("{c:?} decode: {e}"));
        cur = out;
    }
    cur
}
