use ps_hash::HashError;
use thiserror::Error;

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum PsCypherError {
    #[error(transparent)]
    PsDeflateError(#[from] ps_deflate::PsDeflateError),
    #[error("Encryption/Decryption failure (from chacha20poly1305)")]
    ChaChaError,
    #[error(transparent)]
    HashError(#[from] HashError),
    #[error("Reading from a slice failed.")]
    TryFromSliceError,
}

impl From<chacha20poly1305::Error> for PsCypherError {
    fn from(_error: chacha20poly1305::Error) -> Self {
        Self::ChaChaError
    }
}

impl From<std::array::TryFromSliceError> for PsCypherError {
    fn from(_: std::array::TryFromSliceError) -> Self {
        Self::TryFromSliceError
    }
}
