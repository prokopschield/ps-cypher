#![allow(clippy::module_name_repetitions)]

use ps_compress::{CompressionError, DecompressionError};
use ps_ecc::DecodeError;
use ps_hash::HashError;
use thiserror::Error;

#[derive(Clone, Debug, Error)]
pub enum EncryptionError {
    #[error("Encryption/Decryption failure (from chacha20poly1305)")]
    ChaChaError,
    #[error("Compression error: {0}")]
    CompressionError(#[from] CompressionError),
    #[error(transparent)]
    EccError(#[from] ps_ecc::EncodeError),
    #[error(transparent)]
    HashError(#[from] HashError),
}

#[derive(Clone, Debug, Error)]
pub enum DecryptionError {
    #[error("Encryption/Decryption failure (from chacha20poly1305)")]
    ChaChaError,
    #[error("Decompression error: {0}")]
    DecompressionError(#[from] DecompressionError),
    #[error(transparent)]
    EccError(#[from] DecodeError),
}

#[derive(Error, Debug, Clone)]
pub enum PsCypherError {
    #[error(transparent)]
    DecryptionError(#[from] DecryptionError),
    #[error(transparent)]
    EncryptionError(#[from] EncryptionError),
}
