#[cfg(feature = "database")]
use crate::database::DatabaseService;
#[cfg(feature = "database")]
use crate::encryption::EncryptionService;
#[cfg(feature = "database")]
use crate::errors::KeyManagementError;
#[cfg(feature = "database")]
use crate::models::{
    DistributionResult, KeyGenerationConfig, KeyGenerationResult, MappingData, RekeyStatus,
    StudentMapping,
};
#[cfg(feature = "database")]
use chrono::{Duration, Utc};
#[cfg(feature = "database")]
use sqlx::postgres::PgPool;
#[cfg(feature = "database")]
use std::net::IpAddr;

#[cfg(feature = "database")]
pub struct KeyManagementService {
    db: DatabaseService,
    encryption: EncryptionService,
    base_url: String,
}

#[cfg(feature = "database")]
impl KeyManagementService {
    pub fn new(pool: PgPool, base_url: String) -> Self {
        Self {
            db: DatabaseService::new(pool),
            encryption: EncryptionService::new(),
            base_url,
        }
    }

    /// Check if user needs a new key
    pub async fn check_rekey_status(
        &self,
        user_id: i32,
    ) -> Result<RekeyStatus, KeyManagementError> {
        self.db.check_rekey_status(user_id).await
    }

    /// Generate new anonymization key
    pub async fn generate_new_key(
        &self,
        user_id: i32,
        user_password: &str,
        config: KeyGenerationConfig,
    ) -> Result<KeyGenerationResult, KeyManagementError> {
        // Validate password strength
        self.encryption
            .validate_password_strength(user_password)
            .map_err(KeyManagementError::Encryption)?;

        // Check if rekey is needed
        let rekey_status = self.check_rekey_status(user_id).await?;
        if !rekey_status.needs_rekey {
            return Err(KeyManagementError::RekeyNotNeeded(rekey_status.reason));
        }

        // Get student data
        let student_data = self.db.get_user_students(user_id).await?;

        // Create mappings with anonymized IDs
        let mut students = Vec::new();
        let mut anonymized_id = 100000;

        for (original_id, firstname, lastname, pin) in student_data {
            students.push(StudentMapping {
                original_id,
                anonymized_id,
                firstname: firstname.unwrap_or_default(),
                lastname: lastname.unwrap_or_default(),
                pin: pin.unwrap_or_default(),
            });
            anonymized_id += 1;
        }

        // Get next version
        let key_version = self.db.get_next_key_version(user_id).await?;

        // Create mapping data
        let mapping_data = MappingData {
            students: students.clone(),
            created_at: Utc::now(),
            user_id,
            key_version,
        };

        // Encrypt the data
        let encryption_result = self
            .encryption
            .encrypt_mapping_data(&mapping_data, user_password)
            .map_err(KeyManagementError::Encryption)?;

        // Store in database
        let expires_at = Utc::now() + Duration::days(config.key_expiry_days);
        let key_id = self
            .db
            .store_anonymization_key(
                user_id,
                key_version,
                &encryption_result.salt,
                &encryption_result.encrypted_data,
                &encryption_result.data_hash,
                students.len() as i32,
                expires_at,
            )
            .await?;

        // Update student mappings table
        let mappings: Vec<_> = students
            .iter()
            .map(|s| {
                (
                    s.original_id,
                    s.anonymized_id,
                    s.firstname.clone(),
                    s.lastname.clone(),
                    s.pin,
                )
            })
            .collect();
        self.db
            .update_student_mappings(&mappings, key_version, user_id)
            .await?;

        // Create distribution result
        let distribution_result = if config.create_download_link {
            let token = self.encryption.generate_download_token();
            let download_expires = Utc::now() + Duration::hours(config.download_expiry_hours);

            self.db
                .create_secure_download(
                    key_id,
                    user_id,
                    &token,
                    download_expires,
                    config.max_downloads,
                )
                .await?;

            DistributionResult {
                download_url: Some(format!("{}/api/keys/download/{}", self.base_url, token)),
                download_token: Some(token),
                expires_at: download_expires,
                instructions: "Download link expires in 24 hours. Save the key file securely."
                    .to_string(),
            }
        } else {
            DistributionResult {
                download_url: None,
                download_token: None,
                expires_at: expires_at,
                instructions: "Key generated successfully. Use your account password to decrypt."
                    .to_string(),
            }
        };

        // Log success
        self.db
            .log_key_access(Some(key_id), user_id, "generate", true, None, None)
            .await?;

        // Update global protection status
        self.db
            .update_student_protection_status(user_id, true)
            .await?;

        Ok(KeyGenerationResult {
            key_version,
            students_count: students.len() as i32,
            distribution_result,
            reason: rekey_status.reason,
        })
    }

    /// Download key using secure token
    pub async fn download_key(
        &self,
        token: &str,
        client_ip: Option<IpAddr>,
    ) -> Result<String, KeyManagementError> {
        // Get download record
        let download = self
            .db
            .get_secure_download(token)
            .await?
            .ok_or(KeyManagementError::InvalidDownloadToken)?;

        // Check download limits
        if download.download_count >= download.max_downloads {
            return Err(KeyManagementError::MaxDownloadsExceeded);
        }

        // Get the key data
        let key = self
            .db
            .get_anonymization_key(download.key_id)
            .await?
            .ok_or(KeyManagementError::KeyNotFound)?;

        // Update download count
        self.db
            .update_download_count(download.id, client_ip)
            .await?;

        // Log access
        self.db
            .log_key_access(
                Some(download.key_id),
                download.user_id,
                "download",
                true,
                client_ip,
                None,
            )
            .await?;

        Ok(key.encrypted_mapping_data)
    }

    /// Validate and decrypt key
    pub async fn validate_key(
        &self,
        user_id: i32,
        encrypted_key: &str,
        user_password: &str,
        key_version: Option<i32>,
    ) -> Result<MappingData, KeyManagementError> {
        // Get key record from database
        let key_record = self
            .db
            .get_user_active_key(user_id, key_version)
            .await?
            .ok_or(KeyManagementError::KeyNotFound)?;

        // Check if key has expired
        if let Some(expires_at) = key_record.expires_at {
            if expires_at < Utc::now() {
                return Err(KeyManagementError::KeyExpired);
            }
        }

        // Decrypt the key
        let mapping_data = self
            .encryption
            .decrypt_mapping_data(encrypted_key, user_password)
            .map_err(KeyManagementError::Encryption)?;

        // Verify data integrity
        let is_valid = self
            .encryption
            .verify_data_integrity(&mapping_data, &key_record.data_hash)
            .map_err(KeyManagementError::Encryption)?;

        if !is_valid {
            self.db
                .log_key_access(
                    Some(key_record.id),
                    user_id,
                    "validate",
                    false,
                    None,
                    Some("Data integrity check failed"),
                )
                .await?;
            return Err(KeyManagementError::Encryption(
                crate::errors::EncryptionError::IntegrityCheckFailed,
            ));
        }

        // Log successful validation
        self.db
            .log_key_access(Some(key_record.id), user_id, "validate", true, None, None)
            .await?;

        Ok(mapping_data)
    }

    /// Clean up expired resources
    pub async fn cleanup_expired(&self) -> Result<u64, KeyManagementError> {
        self.db.cleanup_expired_downloads().await
    }
}
