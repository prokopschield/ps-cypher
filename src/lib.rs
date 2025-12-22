mod error;

pub use error::{DecryptionError, EncryptionError, PsCypherError};
pub use ps_buffer::Buffer;

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::ChaCha20Poly1305;
use ps_deflate::{compress, decompress};
use ps_ecc::{decode, encode, Codeword, DecodeError};
use ps_hash::{Hash, PARITY_SIZE};
use ps_util::subarray;
use std::ops::Deref;
use std::sync::Arc;

#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Encrypted {
    pub bytes: Buffer,
    pub hash: Arc<Hash>,
    pub key: Arc<Hash>,
}

const KSIZE: usize = 32;
const NSIZE: usize = 12;

const PARITY: u8 = 12;

#[derive(Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct ParsedKey {
    key: [u8; KSIZE],
    nonce: [u8; NSIZE],
    length: usize,
}

impl From<&Hash> for ParsedKey {
    fn from(value: &Hash) -> Self {
        Self {
            key: *value.digest(),
            length: value.data_max_len().to_usize(),
            nonce: *subarray(value.parity(), PARITY_SIZE - NSIZE),
        }
    }
}

/// Encrypts a message.
/// # Errors
/// - [`PsCypherError::PsDeflateError`] is returned if compression fails.
/// - [`PsCypherError::ChaChaError`] is returned if encryption fails.
/// - [`PsCypherError::HashError`] is returned if hashing fails.
pub fn encrypt(data: &[u8]) -> Result<Encrypted, EncryptionError> {
    let compressed_data = compress(data)?;
    let hash_of_raw_data = ps_hash::hash(data)?;

    let ParsedKey {
        key: encryption_key,
        length: _,
        nonce,
    } = (&hash_of_raw_data).into();

    let chacha = ChaCha20Poly1305::new(&encryption_key.into());
    let encrypted_data = chacha
        .encrypt(&nonce.into(), compressed_data.as_ref())
        .map_err(|_| EncryptionError::ChaChaError)?;

    let bytes = encode(&encrypted_data, PARITY)?;
    let hash = Hash::hash(&bytes)?.into();

    let encrypted = Encrypted {
        bytes,
        hash,
        key: hash_of_raw_data.into(),
    };

    Ok(encrypted)
}

/// Attempts the decryption of encrypted data.
/// # Errors
/// [`PsCypherError::ChaChaError`] is returned if decryption fails.
/// [`PsCypherError::PsDeflateError`] is returned if decompression fails.
pub fn decrypt(data: &[u8], key: &Hash) -> Result<Buffer, DecryptionError> {
    let ParsedKey {
        key: encryption_key,
        length: out_size,
        nonce,
    } = key.into();

    let ecc_decoded = extract_encrypted(data)?;
    let chacha = ChaCha20Poly1305::new(&encryption_key.into());
    let compressed_data = chacha
        .decrypt(&nonce.into(), &ecc_decoded[..])
        .map_err(|_| DecryptionError::ChaChaError)?;

    Ok(decompress(&compressed_data, out_size)?)
}

#[inline]
/// Extracts the raw ChaCha-encrypted content from the provided slice.
/// # Errors
/// Returns [`DecodeError`] if `data` is invalid or irrecoverably corrupted.
pub fn extract_encrypted(data: &[u8]) -> Result<Codeword<'_>, DecodeError> {
    decode(data, PARITY)
}

#[inline]
#[must_use]
/// Checks whether `data` has been corrupted or tampered with.
///
/// Returns `true` if the data's checksum is intact and no errors are detected.
///
/// # Parameters
/// * `data` - The encrypted data buffer to validate
///
/// # Examples
/// ```
/// # use ps_cypher::{encrypt, validate};
/// let data = b"important data";
/// let encrypted = encrypt(data).expect("encryption failed");
/// assert!(validate(&encrypted));
/// ```
pub fn validate(data: &[u8]) -> bool {
    ps_ecc::validate(data, PARITY)
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
#[allow(clippy::unwrap_used)]
mod tests {
    use ps_buffer::ToBuffer;
    use ps_hash::hash;

    use super::*;

    #[test]
    fn test_encrypt_and_decrypt() -> Result<(), PsCypherError> {
        let original_data = b"Hello, World!";

        let encrypted_data = encrypt(original_data)?;

        let decrypted_data = decrypt(&encrypted_data.bytes, &encrypted_data.key)?;

        assert_ne!(
            original_data.to_buffer().unwrap(),
            encrypted_data.bytes,
            "Encryption should modify the data"
        );

        assert_eq!(
            encrypted_data.bytes.len(),
            31 + 2 * usize::from(PARITY),
            "Encrypted data should be 31 bytes long"
        );

        assert_eq!(
            original_data,
            &decrypted_data[..],
            "Decryption should reverse encryption"
        );

        Ok(())
    }

    // Helper function to create a sample key (for testing purposes)
    fn create_test_key() -> Hash {
        hash("Hello, world!").unwrap()
    }

    #[test]
    fn test_parse_key() {
        let key = &create_test_key();

        let ParsedKey {
            key: encryption_key,
            length: _,
            nonce,
        } = key.into();

        assert_eq!(encryption_key.len(), 32);
        assert_eq!(nonce.len(), 12);
        // Basic check of the key and nonce values.
        assert_eq!(&encryption_key[0..4], &[220, 186, 155, 106]); // First 4 bytes of key
        assert_eq!(&nonce[0..4], &[46, 215, 220, 44]); // First 4 bytes of nonce
    }

    #[test]
    fn test_encrypt_decrypt() {
        let data = b"This is some data to encrypt";
        let encrypted = encrypt(data).unwrap();
        let decrypted = decrypt(&encrypted, &encrypted.key).unwrap();
        assert_eq!(&*decrypted, data);
    }

    #[test]
    fn test_encrypt_decrypt_empty_data() {
        let data = b"";
        let encrypted = encrypt(data).unwrap();
        let decrypted = decrypt(&encrypted, &encrypted.key).unwrap();
        assert_eq!(&*decrypted, data);
    }

    #[test]
    fn test_encrypt_decrypt_long_data() {
        let data = "This is a very long string to test the encryption and decryption with a large amount of data.  We want to make sure that the compression and decompression work correctly, and that the encryption and decryption can handle a significant amount of data without any issues.  This should be longer than any reasonable message.  Let's add some more to be absolutely sure. And even more, just to be safe.".as_bytes();
        let encrypted = encrypt(data).unwrap();
        let decrypted = decrypt(&encrypted, &encrypted.key).unwrap();
        assert_eq!(&*decrypted, data);
    }

    #[test]
    fn test_encrypt_decrypt_different_key() {
        let data = b"This is some data";
        let encrypted = encrypt(data).unwrap();
        let different_key = create_test_key(); // Use a different key.

        let result = decrypt(&encrypted, &different_key);
        assert!(result.is_err());
        match result.unwrap_err() {
            DecryptionError::ChaChaError => {} // Expected error type.
            _ => panic!("Unexpected error type"),
        }
    }

    #[test]
    fn test_encrypt_decrypt_tampered_data() -> Result<(), PsCypherError> {
        let data = b"This is some data";
        let mut encrypted = encrypt(data).unwrap();
        // Tamper with the encrypted data
        encrypted.bytes[0] ^= 0x01; // Flip a bit

        let decrypted = decrypt(&encrypted, &encrypted.key)?;

        assert_eq!(decrypted.slice(..), data);

        Ok(())
    }

    #[test]
    fn test_as_ref_encrypted() {
        let data = b"Test data";
        let encrypted = encrypt(data).unwrap();
        let as_ref_data: &[u8] = encrypted.as_ref();
        assert_eq!(as_ref_data, &*encrypted);
        assert_eq!(as_ref_data, &encrypted.bytes[..]);
    }

    #[test]
    fn test_deref_encrypted() {
        let data = b"More test data";
        let encrypted = encrypt(data).unwrap();
        let deref_data: &[u8] = &encrypted; // Use the Deref trait
        assert_eq!(deref_data, &encrypted.bytes[..]);
    }

    #[test]
    fn test_key_from_hash() {
        let data = b"Test data for key derivation";
        let h = hash(data).unwrap();

        let ParsedKey {
            key,
            length: _,
            nonce: _,
        } = (&h).into();

        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_encrypt_large_data() {
        // Create a large amount of data (1MB)
        let data = vec![b'A'; 1024 * 1024];
        let encrypted = encrypt(&data).unwrap();
        let decrypted = decrypt(&encrypted, &encrypted.key).unwrap();
        assert_eq!(&*decrypted, &data[..]);
    }

    #[test]
    fn test_ps_cypher_error_display() {
        let data = b"test";
        let encrypted = encrypt(data).unwrap();
        let bad_key = hash(b"invalid_key").unwrap();
        let result = decrypt(&encrypted, &bad_key);

        if let Err(e) = result {
            let error_message = format!("{e}");
            assert_eq!(
                error_message,
                "Encryption/Decryption failure (from chacha20poly1305)"
            ); // Check for a substring.
        } else {
            panic!("Expected an error, but got success");
        }
    }

    #[test]
    fn test_ps_cypher_error_source() {
        let data = b"test";
        let encrypted = encrypt(data).unwrap();
        let bad_key = hash(b"invalid_key").unwrap();
        let result = decrypt(&encrypted, &bad_key);

        if let Err(e) = result {
            let source = std::error::Error::source(&e);
            if let Some(err) = source {
                let _ = format!("{err}"); //check it does not panic
            }
        } else {
            panic!("Expected an error, but got success");
        }
    }
}
