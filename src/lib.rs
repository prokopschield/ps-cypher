mod error;

use error::ParseKeyError;
pub use error::PsCypherError;
pub use ps_buffer::Buffer;

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::ChaCha20Poly1305;
use ps_deflate::{compress, decompress};
use ps_hash::Hash;
use ps_pint16::PackedInt;
use std::ops::Deref;
use std::sync::Arc;

pub struct Encrypted {
    pub bytes: Vec<u8>,
    pub hash: Arc<Hash>,
    pub key: Arc<Hash>,
}

const KSIZE: usize = 32;
const NSIZE: usize = 12;

pub struct ParsedKey {
    key: [u8; KSIZE],
    nonce: [u8; NSIZE],
    length: usize,
}

pub fn parse_key<K: AsRef<[u8]>>(key: K) -> Result<ParsedKey, ParseKeyError> {
    let key = key.as_ref();

    let key = if key.len() > ps_hash::HASH_SIZE_TOTAL_BIN {
        &ps_base64::decode(key)
    } else {
        key
    };

    let len = key.len().min(48);

    if len < 34 {
        return Err(ParseKeyError::InsufficientKeyLength(len.try_into()?));
    }

    let parsed = ParsedKey {
        key: key[0..32].try_into()?,
        length: PackedInt::from_16_bits(key[32..34].try_into()?).to_usize(),
        nonce: key[len - NSIZE..len].try_into()?,
    };

    Ok(parsed)
}

pub fn encrypt<D: AsRef<[u8]>>(data: D) -> Result<Encrypted, PsCypherError> {
    let compressed_data = compress(data.as_ref())?;
    let hash_of_raw_data = ps_hash::hash(data)?;

    let ParsedKey {
        key: encryption_key,
        length: _,
        nonce,
    } = parse_key(hash_of_raw_data.as_bytes())?;

    let chacha = ChaCha20Poly1305::new(&encryption_key.into());
    let encrypted_data = chacha.encrypt(&nonce.into(), compressed_data.as_ref())?;
    let hash_of_encrypted_data = ps_hash::hash(&encrypted_data)?;

    let encrypted = Encrypted {
        bytes: encrypted_data,
        hash: hash_of_encrypted_data.into(),
        key: hash_of_raw_data.into(),
    };

    Ok(encrypted)
}

pub fn decrypt<D: AsRef<[u8]>, K: AsRef<[u8]>>(data: D, key: K) -> Result<Buffer, PsCypherError> {
    let ParsedKey {
        key: encryption_key,
        length: out_size,
        nonce,
    } = parse_key(key)?;

    let chacha = ChaCha20Poly1305::new(&encryption_key.into());
    let compressed_data = chacha.decrypt(&nonce.into(), data.as_ref())?;

    Ok(decompress(&compressed_data, out_size)?)
}

impl AsRef<[u8]> for Encrypted {
    fn as_ref(&self) -> &[u8] {
        self
    }
}

impl Deref for Encrypted {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_and_decrypt() -> Result<(), PsCypherError> {
        let original_data = b"Hello, World!";

        let encrypted_data = encrypt(original_data)?;

        let decrypted_data = decrypt(&encrypted_data.bytes, encrypted_data.key.as_bytes())?;

        assert_ne!(
            original_data.to_vec(),
            encrypted_data.bytes,
            "Encryption should modify the data"
        );

        assert_eq!(
            encrypted_data.bytes.len(),
            31,
            "Encrypted data should be 31 bytes long"
        );

        assert_eq!(
            original_data,
            &decrypted_data[..],
            "Decryption should reverse encryption"
        );

        Ok(())
    }
}
