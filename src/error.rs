#![allow(clippy::module_name_repetitions)]

use ps_compress::{CompressionError, DecompressionError};
use ps_ecc::DecodeError;
use ps_hash::HashError;
use thiserror::Error;

#[derive(Clone, Debug, Error)]
pub enum EncryptionError {
    #[error("Encryption/Decryption failure (from chacha20poly1305)")]
    ChaCha,
    #[error("Compression error: {0}")]
    Compression(#[from] CompressionError),
    #[error(transparent)]
    Ecc(#[from] ps_ecc::EncodeError),
    #[error(transparent)]
    Hash(#[from] HashError),
}

#[derive(Clone, Debug, Error)]
pub enum DecryptionError {
    #[error("Encryption/Decryption failure (from chacha20poly1305)")]
    ChaCha,
    #[error("Decompression error: {0}")]
    Decompression(#[from] DecompressionError),
    #[error(transparent)]
    Ecc(#[from] DecodeError),
}
