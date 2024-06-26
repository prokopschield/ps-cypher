mod error;

pub use error::PsCypherError;
pub use ps_deflate::Compressor;

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::ChaCha20Poly1305;
use ps_hash::Hash;
use ps_pint16::PackedInt;
use std::sync::Arc;

pub struct Encrypted {
    pub bytes: Vec<u8>,
    pub hash: Arc<Hash>,
    pub key: Arc<Hash>,
}

const KSIZE: usize = 32;
const NSIZE: usize = 12;

pub fn parse_key(key: &[u8]) -> ([u8; KSIZE], [u8; NSIZE]) {
    let raw_key = ps_base64::decode(key);

    let mut encryption_key = [0u8; KSIZE];
    let mut nonce = [0u8; NSIZE];

    encryption_key.copy_from_slice(&raw_key[0..KSIZE]);
    nonce.copy_from_slice(&raw_key[raw_key.len() - NSIZE..raw_key.len()]);

    return (encryption_key, nonce);
}

pub fn encrypt(data: &[u8], compressor: &Compressor) -> Result<Encrypted, PsCypherError> {
    let compressed_data = compressor.compress(data)?;
    let hash_of_raw_data = ps_hash::hash(data);
    let (encryption_key, nonce) = parse_key(hash_of_raw_data.as_bytes());
    let chacha = ChaCha20Poly1305::new(&encryption_key.into());
    let encrypted_data = chacha.encrypt(&nonce.into(), compressed_data.as_ref())?;
    let hash_of_encrypted_data = ps_hash::hash(&encrypted_data);

    Ok(Encrypted {
        bytes: encrypted_data,
        hash: hash_of_encrypted_data.into(),
        key: hash_of_raw_data.into(),
    })
}

pub fn decrypt(data: &[u8], key: &[u8], compressor: &Compressor) -> Result<Vec<u8>, PsCypherError> {
    let (encryption_key, nonce) = parse_key(key);
    let chacha = ChaCha20Poly1305::new(&encryption_key.into());
    let compressed_data = chacha.decrypt(&nonce.into(), data)?;

    let out_size = &key[48..50];
    let out_size = ps_base64::decode(out_size);
    let out_size = out_size[0..2].try_into()?;
    let out_size = PackedInt::from_12_bits(out_size).to_usize();

    Ok(compressor.decompress(&compressed_data, out_size)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_and_decrypt() -> Result<(), PsCypherError> {
        let original_data = b"Hello, World!";
        let compressor = Compressor::new();

        let encrypted_data = encrypt(original_data, &compressor)?;

        let decrypted_data = decrypt(
            &encrypted_data.bytes,
            encrypted_data.key.as_bytes(),
            &compressor,
        )?;

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
            original_data.to_vec(),
            decrypted_data,
            "Decryption should reverse encryption"
        );

        Ok(())
    }
}
