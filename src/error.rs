#![allow(clippy::module_name_repetitions)]

use std::{array::TryFromSliceError, num::TryFromIntError};

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

#[derive(Error, Debug, Clone)]
pub enum PsCypherError {
    #[error(transparent)]
    PsDeflateError(#[from] ps_deflate::PsDeflateError),
    #[error("Encryption/Decryption failure (from chacha20poly1305)")]
    ChaChaError,
    #[error(transparent)]
    HashError(#[from] HashError),
    #[error(transparent)]
    ParseKeyError(#[from] ParseKeyError),
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
