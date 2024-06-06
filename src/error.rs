use thiserror::Error;

#[derive(Error, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PsCypherError {
    #[error(transparent)]
    PsDeflateError(#[from] ps_deflate::PsDeflateError),
    #[error("Encryption/Decryption failure (from chacha20poly1305)")]
    ChaChaError,
    #[error("Reading from a slice failed.")]
    TryFromSliceError,
}

impl From<chacha20poly1305::Error> for PsCypherError {
    fn from(_error: chacha20poly1305::Error) -> Self {
        PsCypherError::ChaChaError
    }
}

impl From<std::array::TryFromSliceError> for PsCypherError {
    fn from(_: std::array::TryFromSliceError) -> Self {
        PsCypherError::TryFromSliceError
    }
}
