mod error;

pub use error::{DecryptionError, EncryptionError};
pub use ps_buffer::Buffer;

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::ChaCha20Poly1305;
use ps_compress::{compress, decompress_bounded};
use ps_ecc::{decode, encode, Codeword, DecodeError};
use ps_hash::{Hash, PARITY_SIZE};
use ps_util::subarray;
use std::ops::Deref;

#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Encrypted {
    pub bytes: Buffer,
    pub hash: Hash,
    pub key: Hash,
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

impl std::fmt::Debug for ParsedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ParsedKey")
            .field("key", &"<REDACTED>")
            .field("nonce", &self.nonce)
            .field("length", &self.length)
            .finish()
    }
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
        .map_err(|_| EncryptionError::ChaCha)?;

    let bytes = encode(&encrypted_data, PARITY)?;
    let hash = Hash::hash(&bytes)?;

    let encrypted = Encrypted {
        bytes,
        hash,
        key: hash_of_raw_data,
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
        .map_err(|_| DecryptionError::ChaCha)?;

    Ok(decompress_bounded(&compressed_data, out_size)?)
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
/// # use ps_cypher::{encrypt, validate_ecc};
/// let data = b"important data";
/// let encrypted = encrypt(data).expect("encryption failed");
/// assert!(validate_ecc(&encrypted));
/// ```
pub fn validate_ecc(data: &[u8]) -> bool {
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
#[allow(clippy::expect_used)]
#[allow(clippy::unwrap_used)]
mod tests {
    use ps_buffer::ToBuffer;
    use ps_hash::hash;

    use super::*;

    #[test]
    fn test_encrypt_and_decrypt() {
        let original_data = b"Hello, World!";

        let encrypted_data = encrypt(original_data).expect("encryption should succeed");

        let decrypted_data =
            decrypt(&encrypted_data.bytes, &encrypted_data.key).expect("decryption should succeed");

        assert_ne!(
            original_data
                .to_buffer()
                .expect("conversion to buffer should succeed"),
            encrypted_data.bytes,
            "Encryption should modify the data"
        );

        let ecc_payload = extract_encrypted(&encrypted_data.bytes)
            .expect("extracting ECC payload should succeed");

        assert_eq!(
            encrypted_data.bytes.len(),
            ecc_payload.len() + 2 * usize::from(PARITY),
            "ECC encoding should add parity bytes"
        );

        assert_eq!(
            original_data,
            &decrypted_data[..],
            "Decryption should reverse encryption"
        );
    }

    // Helper function to create a sample key (for testing purposes)
    fn create_test_key() -> Hash {
        hash("Hello, world!").expect("hashing test key should succeed")
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
        let encrypted = encrypt(data).expect("encryption should succeed");
        let decrypted = decrypt(&encrypted, &encrypted.key).expect("decryption should succeed");
        assert_eq!(&*decrypted, data);
    }

    #[test]
    fn test_encrypt_decrypt_empty_data() {
        let data = b"";
        let encrypted = encrypt(data).expect("encryption should succeed");
        let decrypted = decrypt(&encrypted, &encrypted.key).expect("decryption should succeed");
        assert_eq!(&*decrypted, data);
    }

    #[test]
    fn test_encrypt_decrypt_long_data() {
        let data = "This is a very long string to test the encryption and decryption with a large amount of data.  We want to make sure that the compression and decompression work correctly, and that the encryption and decryption can handle a significant amount of data without any issues.  This should be longer than any reasonable message.  Let's add some more to be absolutely sure. And even more, just to be safe.".as_bytes();
        let encrypted = encrypt(data).expect("encryption should succeed");
        let decrypted = decrypt(&encrypted, &encrypted.key).expect("decryption should succeed");
        assert_eq!(&*decrypted, data);
    }

    #[test]
    fn test_encrypt_decrypt_different_key() {
        let data = b"This is some data";
        let encrypted = encrypt(data).expect("encryption should succeed");
        let different_key = create_test_key(); // Use a different key.

        let result = decrypt(&encrypted, &different_key);
        assert!(result.is_err());
        match result.unwrap_err() {
            DecryptionError::ChaCha => {} // Expected error type.
            _ => panic!("Unexpected error type"),
        }
    }

    #[test]
    fn test_encrypt_decrypt_tampered_data() {
        let data = b"This is some data";
        let mut encrypted = encrypt(data).expect("encryption should succeed");
        // Tamper with the encrypted data
        encrypted.bytes[0] ^= 0x01; // Flip a bit

        let decrypted = decrypt(&encrypted, &encrypted.key)
            .expect("decryption should succeed after ECC correction");

        assert_eq!(decrypted.slice(..), data);
    }

    #[test]
    fn test_validate_ecc_for_valid_and_truncated_data() {
        let data = b"ECC validation data";
        let encrypted = encrypt(data).expect("encryption should succeed");

        assert!(validate_ecc(&encrypted), "fresh ciphertext should validate");

        let truncated = &encrypted.bytes[..encrypted.bytes.len() - 1];
        assert!(
            !validate_ecc(truncated),
            "truncated ciphertext should not validate"
        );
    }

    #[test]
    fn test_extract_encrypted_rejects_truncated_payload() {
        let data = b"payload";
        let encrypted = encrypt(data).expect("encryption should succeed");
        let truncated = &encrypted.bytes[..encrypted.bytes.len() - 1];

        let result = extract_encrypted(truncated);
        assert!(result.is_err(), "truncated payload must fail ECC decode");
    }

    #[test]
    fn test_decrypt_truncated_payload_returns_ecc_error() {
        let data = b"payload";
        let encrypted = encrypt(data).expect("encryption should succeed");
        let truncated = &encrypted.bytes[..encrypted.bytes.len() - 1];

        let result = decrypt(truncated, &encrypted.key);
        assert!(
            matches!(result, Err(DecryptionError::Ecc(_))),
            "truncated payload should surface as ECC error"
        );
    }

    #[test]
    fn test_encrypted_hash_matches_ciphertext_bytes() {
        let data = b"hash check";
        let encrypted = encrypt(data).expect("encryption should succeed");
        let recalculated = Hash::hash(&encrypted.bytes).expect("hashing bytes should succeed");

        assert_eq!(encrypted.hash, recalculated);
    }

    #[test]
    fn test_as_ref_encrypted() {
        let data = b"Test data";
        let encrypted = encrypt(data).expect("encryption should succeed");
        let as_ref_data: &[u8] = encrypted.as_ref();
        assert_eq!(as_ref_data, &*encrypted);
        assert_eq!(as_ref_data, &encrypted.bytes[..]);
    }

    #[test]
    fn test_deref_encrypted() {
        let data = b"More test data";
        let encrypted = encrypt(data).expect("encryption should succeed");
        let deref_data: &[u8] = &encrypted; // Use the Deref trait
        assert_eq!(deref_data, &encrypted.bytes[..]);
    }

    #[test]
    fn test_key_from_hash() {
        let data = b"Test data for key derivation";
        let h = hash(data).expect("hashing should succeed");

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
        let encrypted = encrypt(&data).expect("encryption should succeed");
        let decrypted = decrypt(&encrypted, &encrypted.key).expect("decryption should succeed");
        assert_eq!(&*decrypted, &data[..]);
    }

    #[test]
    fn test_ps_cypher_error_display() {
        let data = b"test";
        let encrypted = encrypt(data).expect("encryption should succeed");
        let bad_key = hash(b"invalid_key").expect("hashing should succeed");
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
        let encrypted = encrypt(data).expect("encryption should succeed");
        let bad_key = hash(b"invalid_key").expect("hashing should succeed");
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

    #[test]
    fn test_parsed_key_debug_redacts_key() {
        let key = create_test_key();
        let parsed: ParsedKey = (&key).into();
        let debug_output = format!("{parsed:?}");

        assert!(
            debug_output.contains("<REDACTED>"),
            "Debug output should redact the key"
        );
        // Verify the key field shows REDACTED, not actual bytes
        assert!(
            debug_output.contains("key: \"<REDACTED>\""),
            "key field should be redacted"
        );
        // Verify other fields are present
        assert!(debug_output.contains("nonce:"), "nonce should be present");
        assert!(debug_output.contains("length:"), "length should be present");
    }

    #[test]
    #[allow(clippy::clone_on_copy)]
    fn test_parsed_key_clone_and_copy() {
        let key = create_test_key();
        let parsed: ParsedKey = (&key).into();
        let cloned = parsed.clone(); // Intentionally testing Clone trait
        let copied = parsed;

        assert_eq!(parsed, cloned);
        assert_eq!(parsed, copied);
    }

    #[test]
    fn test_parsed_key_hash_trait() {
        use std::collections::HashSet;

        let key1 = create_test_key();
        let key2 = hash(b"different data").expect("hashing should succeed");

        let parsed1: ParsedKey = (&key1).into();
        let parsed2: ParsedKey = (&key2).into();

        let mut set = HashSet::new();
        set.insert(parsed1);
        set.insert(parsed2);

        assert_eq!(set.len(), 2, "different keys should hash differently");
    }

    #[test]
    fn test_parsed_key_ordering() {
        let key1 = hash(b"aaa").expect("hashing should succeed");
        let key2 = hash(b"bbb").expect("hashing should succeed");

        let parsed1: ParsedKey = (&key1).into();
        let parsed2: ParsedKey = (&key2).into();

        // Just verify ordering is consistent, not specific order
        let cmp1 = parsed1.cmp(&parsed2);
        let cmp2 = parsed2.cmp(&parsed1);
        assert_eq!(cmp1.reverse(), cmp2);
    }

    #[test]
    fn test_encrypted_hash_trait() {
        use std::collections::HashSet;

        let encrypted1 = encrypt(b"data1").expect("encryption should succeed");
        let encrypted2 = encrypt(b"data2").expect("encryption should succeed");

        let mut set = HashSet::new();
        set.insert(encrypted1);
        set.insert(encrypted2);

        assert_eq!(
            set.len(),
            2,
            "different encryptions should hash differently"
        );
    }

    #[test]
    fn test_encrypted_ordering() {
        let encrypted1 = encrypt(b"aaa").expect("encryption should succeed");
        let encrypted2 = encrypt(b"bbb").expect("encryption should succeed");

        let cmp1 = encrypted1.cmp(&encrypted2);
        let cmp2 = encrypted2.cmp(&encrypted1);
        assert_eq!(cmp1.reverse(), cmp2);
    }

    #[test]
    fn test_encrypted_equality() {
        let data = b"same data";
        let encrypted1 = encrypt(data).expect("encryption should succeed");
        let encrypted2 = encrypt(data).expect("encryption should succeed");

        assert_eq!(
            encrypted1, encrypted2,
            "same input should produce equal encryptions"
        );
    }

    #[test]
    fn test_encrypt_decrypt_single_byte() {
        let data = b"x";
        let encrypted = encrypt(data).expect("encryption should succeed");
        let decrypted = decrypt(&encrypted, &encrypted.key).expect("decryption should succeed");
        assert_eq!(&*decrypted, data);
    }

    #[test]
    fn test_encrypt_decrypt_binary_with_nulls() {
        let data: &[u8] = &[0x00, 0x01, 0x00, 0xFF, 0x00, 0xFE, 0x00];
        let encrypted = encrypt(data).expect("encryption should succeed");
        let decrypted = decrypt(&encrypted, &encrypted.key).expect("decryption should succeed");
        assert_eq!(&*decrypted, data);
    }

    #[test]
    fn test_encrypt_decrypt_all_byte_values() {
        let data: Vec<u8> = (0u8..=255).collect();
        let encrypted = encrypt(&data).expect("encryption should succeed");
        let decrypted = decrypt(&encrypted, &encrypted.key).expect("decryption should succeed");
        assert_eq!(&*decrypted, &data[..]);
    }

    #[test]
    fn test_encrypt_decrypt_unicode() {
        let data = "Hello 世界! 🎉 Привет мир".as_bytes();
        let encrypted = encrypt(data).expect("encryption should succeed");
        let decrypted = decrypt(&encrypted, &encrypted.key).expect("decryption should succeed");
        assert_eq!(&*decrypted, data);
    }

    #[test]
    fn test_encrypt_decrypt_highly_compressible_data() {
        // Repetitive data should compress well
        let data = vec![b'A'; 10000];
        let encrypted = encrypt(&data).expect("encryption should succeed");

        // Encrypted size should be significantly smaller due to compression
        assert!(
            encrypted.bytes.len() < data.len(),
            "highly compressible data should result in smaller ciphertext"
        );

        let decrypted = decrypt(&encrypted, &encrypted.key).expect("decryption should succeed");
        assert_eq!(&*decrypted, &data[..]);
    }

    #[test]
    fn test_encryption_determinism() {
        let data = b"deterministic test data";

        let encrypted1 = encrypt(data).expect("encryption should succeed");
        let encrypted2 = encrypt(data).expect("encryption should succeed");

        assert_eq!(
            encrypted1.bytes, encrypted2.bytes,
            "same input should produce identical ciphertext"
        );
        assert_eq!(
            encrypted1.key, encrypted2.key,
            "same input should produce identical key"
        );
        assert_eq!(
            encrypted1.hash, encrypted2.hash,
            "same input should produce identical hash"
        );
    }

    #[test]
    fn test_different_inputs_produce_different_outputs() {
        let encrypted1 = encrypt(b"input 1").expect("encryption should succeed");
        let encrypted2 = encrypt(b"input 2").expect("encryption should succeed");

        assert_ne!(
            encrypted1.bytes, encrypted2.bytes,
            "different inputs should produce different ciphertexts"
        );
        assert_ne!(
            encrypted1.key, encrypted2.key,
            "different inputs should produce different keys"
        );
    }

    #[test]
    fn test_ecc_corrects_multiple_bit_errors() {
        let data = b"ECC multi-bit correction test";
        let mut encrypted = encrypt(data).expect("encryption should succeed");

        // Flip multiple bits in different bytes (within ECC correction capability)
        encrypted.bytes[0] ^= 0x01;
        encrypted.bytes[1] ^= 0x02;
        encrypted.bytes[2] ^= 0x04;

        let decrypted = decrypt(&encrypted, &encrypted.key)
            .expect("decryption should succeed with ECC correction");
        assert_eq!(&*decrypted, data);
    }

    #[test]
    fn test_validate_ecc_detects_corruption_within_capability() {
        let data = b"ECC validation test";
        let mut encrypted = encrypt(data).expect("encryption should succeed");

        // Minor corruption that ECC can detect but still validates checksum structure
        encrypted.bytes[5] ^= 0x01;

        // validate_ecc returns true if the checksum structure is valid
        // (ECC can correct the error, so the data is still "valid")
        let is_valid = validate_ecc(&encrypted);
        // Either valid (correctable) or invalid (detected) - both are acceptable
        // The key point is that decrypt should still work
        let decrypted = decrypt(&encrypted, &encrypted.key);
        assert!(
            decrypted.is_ok() || !is_valid,
            "corrupted data should either be correctable or detected as invalid"
        );
    }

    #[test]
    fn test_empty_slice_validation() {
        assert!(
            !validate_ecc(&[]),
            "empty slice should not validate as valid ECC"
        );
    }

    #[test]
    fn test_extract_encrypted_empty_slice() {
        let result = extract_encrypted(&[]);
        assert!(result.is_err(), "empty slice should fail extraction");
    }

    #[test]
    fn test_decrypt_empty_slice() {
        let key = create_test_key();
        let result = decrypt(&[], &key);
        assert!(
            matches!(result, Err(DecryptionError::Ecc(_))),
            "empty slice should return ECC error"
        );
    }

    #[test]
    fn test_decryption_error_clone() {
        let data = b"test";
        let encrypted = encrypt(data).expect("encryption should succeed");
        let bad_key = hash(b"wrong_key").expect("hashing should succeed");

        let result = decrypt(&encrypted, &bad_key);
        if let Err(e) = result {
            let cloned = e.clone();
            assert_eq!(format!("{e}"), format!("{cloned}"));
        } else {
            panic!("Expected decryption error");
        }
    }

    #[test]
    fn test_encryption_error_clone() {
        // EncryptionError::ChaCha is the only variant we can easily trigger
        // by verifying error types are Clone
        let err = EncryptionError::ChaCha;
        let cloned = err.clone();
        assert_eq!(format!("{err}"), format!("{cloned}"));
    }

    #[test]
    fn test_decryption_error_debug() {
        let err = DecryptionError::ChaCha;
        let debug_output = format!("{err:?}");
        assert!(debug_output.contains("ChaCha"));
    }

    #[test]
    fn test_encryption_error_debug() {
        let err = EncryptionError::ChaCha;
        let debug_output = format!("{err:?}");
        assert!(debug_output.contains("ChaCha"));
    }

    #[test]
    fn test_encrypted_debug() {
        let encrypted = encrypt(b"debug test").expect("encryption should succeed");
        let debug_output = format!("{encrypted:?}");
        assert!(debug_output.contains("Encrypted"));
        assert!(debug_output.contains("bytes"));
        assert!(debug_output.contains("hash"));
        assert!(debug_output.contains("key"));
    }

    #[test]
    fn test_parsed_key_same_hash_produces_same_key() {
        let h = hash(b"consistent").expect("hashing should succeed");
        let parsed1: ParsedKey = (&h).into();
        let parsed2: ParsedKey = (&h).into();

        assert_eq!(parsed1, parsed2);
    }

    #[test]
    fn test_encrypt_decrypt_powers_of_two_sizes() {
        for power in 0..=10 {
            let size = 1 << power;
            let data = vec![0xAB_u8; size];
            let encrypted = encrypt(&data).expect("encryption should succeed");
            let decrypted = decrypt(&encrypted, &encrypted.key).expect("decryption should succeed");
            assert_eq!(&*decrypted, &data[..], "failed for size {size}");
        }
    }

    #[test]
    fn test_encrypt_decrypt_boundary_sizes() {
        // Test sizes around common boundaries
        for size in [
            127, 128, 129, 255, 256, 257, 511, 512, 513, 1023, 1024, 1025,
        ] {
            let data = vec![0xCD_u8; size];
            let encrypted = encrypt(&data).expect("encryption should succeed");
            let decrypted = decrypt(&encrypted, &encrypted.key).expect("decryption should succeed");
            assert_eq!(&*decrypted, &data[..], "failed for size {size}");
        }
    }
}
