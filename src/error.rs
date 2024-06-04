use thiserror::Error;

#[derive(Error, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PsCypherError {
    #[error(transparent)]
    PsDeflateError(#[from] ps_deflate::PsDeflateError),
    #[error("Encryption/Decryption failure (from chacha20poly1305)")]
    ChaChaError,
}

impl From<chacha20poly1305::Error> for PsCypherError {
    fn from(_error: chacha20poly1305::Error) -> Self {
        PsCypherError::ChaChaError
    }
}
