use thiserror::Error;

/// Errors from the list service.
#[derive(Debug, Error)]
pub enum Error {
    #[error("storage error: {0}")]
    Storage(String),
    #[error("{0}")]
    Other(String),
}

impl From<sled::Error> for Error {
    fn from(e: sled::Error) -> Self {
        Error::Storage(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
