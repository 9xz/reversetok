use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    #[error("hex decoding failed: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("base64 decoding failed: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("URL failed: {0}")]
    Url(#[from] url::ParseError),
    #[error("unsupported dynamic seed version: {0}")]
    UnsupportedDynVersion(u32),
    #[error("invalid padding")]
    Padding,
    #[error("wreq error: {0}")]
    Wreq(String),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
