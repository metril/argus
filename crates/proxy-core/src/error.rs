//! Error types for the proxy core

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("HTTP error: {0}")]
    Http(String),

    #[error("TLS error: {0}")]
    Tls(String),

    #[error("Certificate generation error: {0}")]
    Certificate(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Connection error: {0}")]
    Connection(String),

    #[error("Destination refused: {0}")]
    DestinationRefused(String),

    /// The client refused the certificate we presented (alert or immediate close).
    #[error("client rejected the proxy certificate: {0}")]
    ClientRejectedCert(String),

    /// A blocked request deliberately failed instead of being answered (`proxy.block_response =
    /// fail`). Returned from the service: hyper resets that one HTTP/2 stream with the `h2`
    /// reason found in the error's source chain (CANCEL), and closes an HTTP/1 connection
    /// without a response. Not a fault: nothing counts or logs it as one.
    #[error("request blocked: aborted")]
    Blocked(#[source] h2::Error),

    /// An upstream failure (no DNS answer, refused, reset, TLS failure, timeout) on a
    /// non-document request, surfaced as a network error like a direct connection would give,
    /// instead of a synthesized 502/504 the page would read as "reachable". Aborts the request
    /// like [`Error::Blocked`] (HTTP/2: stream reset; HTTP/1: connection closed) but is a real
    /// upstream fault, never a block.
    #[error("upstream unreachable: aborted")]
    UpstreamUnreachable(#[source] h2::Error),

    #[error("Timeout error")]
    Timeout,

    #[error("Internal error: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl From<common::Error> for Error {
    fn from(err: common::Error) -> Self {
        Error::Internal(err.to_string())
    }
}

impl Error {
    /// The abort answering a blocked request (HTTP/2: RST_STREAM CANCEL).
    pub fn blocked() -> Self {
        Error::Blocked(h2::Error::from(h2::Reason::CANCEL))
    }

    /// The abort answering an unreachable upstream (HTTP/2: RST_STREAM CONNECT_ERROR).
    pub fn upstream_unreachable() -> Self {
        Error::UpstreamUnreachable(h2::Error::from(h2::Reason::CONNECT_ERROR))
    }

    /// Whether this is a deliberate block abort, not a failure.
    pub fn is_blocked(&self) -> bool {
        matches!(self, Error::Blocked(_))
    }

    /// Whether this error carries any deliberate abort (block or unreachable upstream).
    pub fn chain_is_abort(err: &(dyn std::error::Error + 'static)) -> bool {
        let mut cur = Some(err);
        while let Some(e) = cur {
            if matches!(
                e.downcast_ref::<Error>(),
                Some(Error::Blocked(_) | Error::UpstreamUnreachable(_))
            ) {
                return true;
            }
            cur = e.source();
        }
        false
    }

    /// Whether this error carries a deliberate block abort anywhere in its source chain.
    pub fn chain_is_blocked(err: &(dyn std::error::Error + 'static)) -> bool {
        let mut cur = Some(err);
        while let Some(e) = cur {
            if matches!(e.downcast_ref::<Error>(), Some(Error::Blocked(_))) {
                return true;
            }
            cur = e.source();
        }
        false
    }
}
