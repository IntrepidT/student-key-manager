use crate::errors::EncryptionError;
use crate::models::{EncryptedPackage, EncryptionResult, MappingData};

use aes_gcm::{aead::Aead, Aes256Gcm, Key, KeyInit, Nonce};
use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Argon2, PasswordHasher,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chrono::Utc;
use rand;
use sha2::{Digest, Sha256};

/// Main encryption service for student data
pub struct EncryptionService {
    argon2: Argon2<'static>,
}

impl EncryptionService {
    /// Create a new encryption service instance
    pub fn new() -> Self {
        Self {
            argon2: Argon2::default(),
        }
    }

    /// Generate a cryptographically secure salt
    pub fn generate_salt(&self) -> SaltString {
        SaltString::generate(&mut OsRng)
    }

    /// Generate a secure download token
    pub fn generate_download_token(&self) -> String {
        let bytes: [u8; 32] = rand::random();
        hex::encode(bytes)
    }

    /// Derive 256-bit encryption key from password using Argon2
    pub fn derive_key_from_password(
        &self,
        password: &str,
        salt: &SaltString,
    ) -> Result<[u8; 32], EncryptionError> {
        let password_hash = self
            .argon2
            .hash_password(password.as_bytes(), salt)
            .map_err(|e| EncryptionError::PasswordHashError(e.to_string()))?;

        let hash = password_hash.hash.ok_or_else(|| {
            EncryptionError::PasswordHashError("Failed to extract hash".to_string())
        })?;

        let hash_bytes = hash.as_bytes();

        if hash_bytes.len() < 32 {
            return Err(EncryptionError::KeyTooShort);
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&hash_bytes[..32]);
        Ok(key)
    }

    /// Create SHA-256 hash of mapping data for integrity verification
    pub fn create_data_hash(&self, mapping_data: &MappingData) -> Result<String, EncryptionError> {
        let json_data = serde_json::to_string(mapping_data)?;
        let mut hasher = Sha256::new();
        hasher.update(json_data.as_bytes());
        Ok(hex::encode(hasher.finalize()))
    }

    /// Encrypt student mapping data with password-based encryption
    pub fn encrypt_mapping_data(
        &self,
        mapping_data: &MappingData,
        user_password: &str,
    ) -> Result<EncryptionResult, EncryptionError> {
        // Generate salt and derive key
        let salt = self.generate_salt();
        let key_bytes = self.derive_key_from_password(user_password, &salt)?;
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);

        // Create cipher
        let cipher = Aes256Gcm::new(key);

        // Generate random nonce
        let nonce_bytes: [u8; 12] = rand::random();
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Serialize and encrypt data
        let json_data = serde_json::to_string(mapping_data)?;
        let ciphertext = cipher
            .encrypt(nonce, json_data.as_bytes())
            .map_err(|e| EncryptionError::EncryptionFailed(e.to_string()))?;

        // Create encrypted package
        let package = EncryptedPackage {
            salt: salt.to_string(),
            nonce: BASE64.encode(&nonce_bytes),
            ciphertext: BASE64.encode(&ciphertext),
            algorithm: "AES-256-GCM".to_string(),
            timestamp: Utc::now().timestamp(),
        };

        // Serialize package
        let encrypted_data = serde_json::to_string(&package)?;

        // Create data hash
        let data_hash = self.create_data_hash(mapping_data)?;

        Ok(EncryptionResult {
            encrypted_data,
            data_hash,
            salt: salt.to_string(),
        })
    }

    /// Decrypt student mapping data
    pub fn decrypt_mapping_data(
        &self,
        encrypted_data: &str,
        user_password: &str,
    ) -> Result<MappingData, EncryptionError> {
        // Parse encrypted package
        let package: EncryptedPackage = serde_json::from_str(encrypted_data)
            .map_err(|e| EncryptionError::InvalidKeyFormat(e.to_string()))?;

        // Validate algorithm
        if package.algorithm != "AES-256-GCM" {
            return Err(EncryptionError::InvalidKeyFormat(format!(
                "Unsupported algorithm: {}",
                package.algorithm
            )));
        }

        // Parse salt and derive key
        let salt =
            SaltString::from_b64(&package.salt).map_err(|_| EncryptionError::InvalidSaltFormat)?;
        let key_bytes = self.derive_key_from_password(user_password, &salt)?;
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);

        // Create cipher
        let cipher = Aes256Gcm::new(key);

        // Decode components
        let nonce_bytes = BASE64
            .decode(&package.nonce)
            .map_err(|e| EncryptionError::InvalidKeyFormat(e.to_string()))?;

        if nonce_bytes.len() != 12 {
            return Err(EncryptionError::InvalidKeyFormat(
                "Invalid nonce length".to_string(),
            ));
        }

        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = BASE64
            .decode(&package.ciphertext)
            .map_err(|e| EncryptionError::InvalidKeyFormat(e.to_string()))?;

        // Decrypt
        let plaintext = cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|e| EncryptionError::DecryptionFailed(e.to_string()))?;

        // Deserialize
        let json_str = String::from_utf8(plaintext)
            .map_err(|e| EncryptionError::DecryptionFailed(e.to_string()))?;

        let mapping_data: MappingData = serde_json::from_str(&json_str)?;

        Ok(mapping_data)
    }

    /// Verify data integrity
    pub fn verify_data_integrity(
        &self,
        mapping_data: &MappingData,
        expected_hash: &str,
    ) -> Result<bool, EncryptionError> {
        let actual_hash = self.create_data_hash(mapping_data)?;
        Ok(actual_hash == expected_hash)
    }

    /// Validate password strength (basic implementation)
    pub fn validate_password_strength(&self, password: &str) -> Result<(), EncryptionError> {
        if password.len() < 8 {
            return Err(EncryptionError::InvalidKeyFormat(
                "Password must be at least 8 characters".to_string(),
            ));
        }

        let has_uppercase = password.chars().any(|c| c.is_uppercase());
        let has_lowercase = password.chars().any(|c| c.is_lowercase());
        let has_digit = password.chars().any(|c| c.is_numeric());

        if !has_uppercase || !has_lowercase || !has_digit {
            return Err(EncryptionError::InvalidKeyFormat(
                "Password must contain uppercase, lowercase, and digit".to_string(),
            ));
        }

        Ok(())
    }
}

impl Default for EncryptionService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::StudentMapping;

    fn create_test_mapping_data() -> MappingData {
        MappingData {
            students: vec![
                StudentMapping {
                    original_id: 1,
                    anonymized_id: 100001,
                    firstname: "John".to_string(),
                    lastname: "Doe".to_string(),
                    pin: 1234,
                },
                StudentMapping {
                    original_id: 2,
                    anonymized_id: 100002,
                    firstname: "Jane".to_string(),
                    lastname: "Smith".to_string(),
                    pin: 5678,
                },
            ],
            created_at: Utc::now(),
            user_id: 1,
            key_version: 1,
        }
    }

    #[test]
    fn test_encryption_roundtrip() {
        let service = EncryptionService::new();
        let password = "TestPassword123!";
        let mapping_data = create_test_mapping_data();

        // Encrypt
        let encrypted = service
            .encrypt_mapping_data(&mapping_data, password)
            .expect("Encryption should succeed");

        // Verify encrypted data is not empty
        assert!(!encrypted.encrypted_data.is_empty());
        assert!(!encrypted.data_hash.is_empty());
        assert!(!encrypted.salt.is_empty());

        // Decrypt
        let decrypted = service
            .decrypt_mapping_data(&encrypted.encrypted_data, password)
            .expect("Decryption should succeed");

        // Verify data matches
        assert_eq!(mapping_data.students.len(), decrypted.students.len());
        assert_eq!(mapping_data.user_id, decrypted.user_id);
        assert_eq!(mapping_data.key_version, decrypted.key_version);

        for (original, decrypted) in mapping_data.students.iter().zip(decrypted.students.iter()) {
            assert_eq!(original.original_id, decrypted.original_id);
            assert_eq!(original.anonymized_id, decrypted.anonymized_id);
            assert_eq!(original.firstname, decrypted.firstname);
            assert_eq!(original.lastname, decrypted.lastname);
            assert_eq!(original.pin, decrypted.pin);
        }

        // Verify integrity
        let is_valid = service
            .verify_data_integrity(&decrypted, &encrypted.data_hash)
            .expect("Integrity check should succeed");
        assert!(is_valid);
    }

    #[test]
    fn test_wrong_password_fails() {
        let service = EncryptionService::new();
        let password = "CorrectPassword123!";
        let wrong_password = "WrongPassword123!";
        let mapping_data = create_test_mapping_data();

        let encrypted = service
            .encrypt_mapping_data(&mapping_data, password)
            .expect("Encryption should succeed");

        let result = service.decrypt_mapping_data(&encrypted.encrypted_data, wrong_password);

        assert!(result.is_err());
        match result.unwrap_err() {
            EncryptionError::DecryptionFailed(_) => {}
            _ => panic!("Expected DecryptionFailed error"),
        }
    }

    #[test]
    fn test_corrupted_data_fails() {
        let service = EncryptionService::new();
        let password = "TestPassword123!";
        let mapping_data = create_test_mapping_data();

        let encrypted = service
            .encrypt_mapping_data(&mapping_data, password)
            .expect("Encryption should succeed");

        // Corrupt the encrypted data
        let mut corrupted_data = encrypted.encrypted_data;
        corrupted_data.push_str("corrupted");

        let result = service.decrypt_mapping_data(&corrupted_data, password);
        assert!(result.is_err());
    }

    #[test]
    fn test_password_strength_validation() {
        let service = EncryptionService::new();

        // Too short
        assert!(service.validate_password_strength("short").is_err());

        // Missing uppercase
        assert!(service.validate_password_strength("lowercase123").is_err());

        // Missing lowercase
        assert!(service.validate_password_strength("UPPERCASE123").is_err());

        // Missing digit
        assert!(service.validate_password_strength("PasswordOnly").is_err());

        // Valid passwords
        assert!(service
            .validate_password_strength("ValidPassword123")
            .is_ok());
        assert!(service
            .validate_password_strength("Another_Valid_Pass1")
            .is_ok());
        assert!(service
            .validate_password_strength("Complex!Password9")
            .is_ok());
    }

    #[test]
    fn test_token_generation() {
        let service = EncryptionService::new();
        let token1 = service.generate_download_token();
        let token2 = service.generate_download_token();

        // Tokens should be different
        assert_ne!(token1, token2);

        // Tokens should be hex strings of expected length
        assert_eq!(token1.len(), 64); // 32 bytes * 2 (hex encoding)
        assert_eq!(token2.len(), 64);

        // Tokens should be valid hex
        assert!(hex::decode(&token1).is_ok());
        assert!(hex::decode(&token2).is_ok());
    }

    #[test]
    fn test_data_hash_consistency() {
        let service = EncryptionService::new();
        let mapping_data = create_test_mapping_data();

        let hash1 = service
            .create_data_hash(&mapping_data)
            .expect("Hash creation should succeed");
        let hash2 = service
            .create_data_hash(&mapping_data)
            .expect("Hash creation should succeed");

        // Same data should produce same hash
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64); // SHA-256 hex string

        // Different data should produce different hash
        let mut different_data = mapping_data.clone();
        different_data.user_id = 999;

        let hash3 = service
            .create_data_hash(&different_data)
            .expect("Hash creation should succeed");

        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_integrity_verification() {
        let service = EncryptionService::new();
        let mapping_data = create_test_mapping_data();
        let hash = service.create_data_hash(&mapping_data).unwrap();

        // Valid integrity check
        assert!(service.verify_data_integrity(&mapping_data, &hash).unwrap());

        // Invalid integrity check
        let mut modified_data = mapping_data.clone();
        modified_data.user_id = 999;

        assert!(!service
            .verify_data_integrity(&modified_data, &hash)
            .unwrap());
    }

    #[test]
    fn test_different_salts_produce_different_encryption() {
        let service = EncryptionService::new();
        let password = "SamePassword123!";
        let mapping_data = create_test_mapping_data();

        let encrypted1 = service
            .encrypt_mapping_data(&mapping_data, password)
            .expect("First encryption should succeed");

        let encrypted2 = service
            .encrypt_mapping_data(&mapping_data, password)
            .expect("Second encryption should succeed");

        // Even with same password and data, encrypted output should be different due to salt
        assert_ne!(encrypted1.encrypted_data, encrypted2.encrypted_data);
        assert_ne!(encrypted1.salt, encrypted2.salt);

        // But both should decrypt to the same data
        let decrypted1 = service
            .decrypt_mapping_data(&encrypted1.encrypted_data, password)
            .unwrap();
        let decrypted2 = service
            .decrypt_mapping_data(&encrypted2.encrypted_data, password)
            .unwrap();

        assert_eq!(decrypted1.user_id, decrypted2.user_id);
        assert_eq!(decrypted1.students.len(), decrypted2.students.len());
    }

    #[test]
    fn test_empty_student_list() {
        let service = EncryptionService::new();
        let password = "TestPassword123!";
        let mapping_data = MappingData {
            students: vec![], // Empty list
            created_at: Utc::now(),
            user_id: 1,
            key_version: 1,
        };

        let encrypted = service
            .encrypt_mapping_data(&mapping_data, password)
            .expect("Should encrypt empty student list");

        let decrypted = service
            .decrypt_mapping_data(&encrypted.encrypted_data, password)
            .expect("Should decrypt empty student list");

        assert_eq!(decrypted.students.len(), 0);
        assert_eq!(decrypted.user_id, 1);
    }

    #[test]
    fn test_large_student_list() {
        let service = EncryptionService::new();
        let password = "TestPassword123!";

        // Create a large student list
        let students: Vec<StudentMapping> = (1..=1000)
            .map(|i| StudentMapping {
                original_id: i,
                anonymized_id: 100000 + i,
                firstname: format!("Student{}", i),
                lastname: format!("Last{}", i),
                pin: 1000 + i,
            })
            .collect();

        let mapping_data = MappingData {
            students,
            created_at: Utc::now(),
            user_id: 1,
            key_version: 1,
        };

        let encrypted = service
            .encrypt_mapping_data(&mapping_data, password)
            .expect("Should encrypt large student list");

        let decrypted = service
            .decrypt_mapping_data(&encrypted.encrypted_data, password)
            .expect("Should decrypt large student list");

        assert_eq!(decrypted.students.len(), 1000);
        assert_eq!(decrypted.students[0].firstname, "Student1");
        assert_eq!(decrypted.students[999].firstname, "Student1000");
    }
}
