#![allow(clippy::module_name_repetitions)]

use std::{array::TryFromSliceError, num::TryFromIntError};

use ps_deflate::PsDeflateError;
use ps_hash::HashError;
use thiserror::Error;

#[derive(Clone, Copy, Debug, Error)]
pub enum ParseKeyError {
    #[error("Key length of {0} is insufficient.")]
    InsufficientKeyLength(u8),
    #[error(transparent)]
    TryFromIntError(#[from] TryFromIntError),
    #[error(transparent)]
    TryFromSliceError(#[from] TryFromSliceError),
}

#[derive(Clone, Debug, Error)]
pub enum EncryptionError {
    #[error("Encryption/Decryption failure (from chacha20poly1305)")]
    ChaChaError,
    #[error(transparent)]
    HashError(#[from] HashError),
    #[error(transparent)]
    ParseKeyError(#[from] ParseKeyError),
    #[error(transparent)]
    PsDeflateError(#[from] PsDeflateError),
}

#[derive(Clone, Debug, Error)]
pub enum DecryptionError {
    #[error("Encryption/Decryption failure (from chacha20poly1305)")]
    ChaChaError,
    #[error(transparent)]
    ParseKeyError(#[from] ParseKeyError),
    #[error(transparent)]
    PsDeflateError(#[from] PsDeflateError),
}

#[derive(Error, Debug, Clone)]
pub enum PsCypherError {
    #[error(transparent)]
    DecryptionError(#[from] DecryptionError),
    #[error(transparent)]
    EncryptionError(#[from] EncryptionError),
}

impl From<chacha20poly1305::Error> for EncryptionError {
    fn from(_error: chacha20poly1305::Error) -> Self {
        Self::ChaChaError
    }
}

impl From<chacha20poly1305::Error> for DecryptionError {
    fn from(_error: chacha20poly1305::Error) -> Self {
        Self::ChaChaError
    }
}
