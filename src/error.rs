#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PsCypherError {
    PsDeflateError(ps_deflate::PsDeflateError),
    ChaChaError,
}

impl From<ps_deflate::PsDeflateError> for PsCypherError {
    fn from(error: ps_deflate::PsDeflateError) -> Self {
        PsCypherError::PsDeflateError(error)
    }
}

impl From<chacha20poly1305::Error> for PsCypherError {
    fn from(_error: chacha20poly1305::Error) -> Self {
        PsCypherError::ChaChaError
    }
}
