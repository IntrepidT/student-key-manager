use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Student mapping between original and anonymized data
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StudentMapping {
    pub original_id: i32,
    pub anonymized_id: i32,
    pub firstname: String,
    pub lastname: String,
    pub pin: i32,
}

/// Complete mapping data for a user's students
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MappingData {
    pub students: Vec<StudentMapping>,
    pub created_at: DateTime<Utc>,
    pub user_id: i32,
    pub key_version: i32,
}

/// Encrypted package structure for secure transport
#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedPackage {
    pub salt: String,
    pub nonce: String,
    pub ciphertext: String,
    pub algorithm: String,
    pub timestamp: i64,
}

/// Result of encryption operation
#[derive(Debug)]
pub struct EncryptionResult {
    pub encrypted_data: String,
    pub data_hash: String,
    pub salt: String,
}

/// Key generation configuration
#[derive(Debug, Clone)]
pub struct KeyGenerationConfig {
    pub create_download_link: bool,
    pub download_expiry_hours: i64,
    pub max_downloads: i32,
    pub key_expiry_days: i64,
}

impl Default for KeyGenerationConfig {
    fn default() -> Self {
        Self {
            create_download_link: true,
            download_expiry_hours: 24,
            max_downloads: 3,
            key_expiry_days: 30,
        }
    }
}

/// Status of whether a user needs to regenerate their key
#[derive(Debug, Serialize, Deserialize)]
pub struct RekeyStatus {
    pub needs_rekey: bool,
    pub reason: String,
    pub current_students: i32,
    pub mapped_students: i32,
    pub new_students: i32,
    pub removed_students: i32,
    pub last_key_date: Option<DateTime<Utc>>,
}

/// Result of key generation
#[derive(Debug, Serialize, Deserialize)]
pub struct KeyGenerationResult {
    pub key_version: i32,
    pub students_count: i32,
    pub distribution_result: DistributionResult,
    pub reason: String,
}

/// How the key was distributed to the user
#[derive(Debug, Serialize, Deserialize)]
pub struct DistributionResult {
    pub download_url: Option<String>,
    pub download_token: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub instructions: String,
}

// Database models (only available with database feature)
#[cfg(feature = "database")]
pub mod db {
    use super::*;
    use chrono::{DateTime, Utc};
    use std::net::IpAddr;

    #[derive(Debug, sqlx::FromRow)]
    pub struct AnonymizationKey {
        pub id: i32,
        pub user_id: i32,
        pub key_version: i32,
        pub encryption_salt: String,
        pub encrypted_mapping_data: String,
        pub data_hash: String,
        pub students_count: i32,
        pub created_at: DateTime<Utc>,
        pub expires_at: Option<DateTime<Utc>>,
        pub is_active: bool,
        pub download_count: i32,
        pub last_accessed: Option<DateTime<Utc>>,
    }

    #[derive(Debug, sqlx::FromRow)]
    pub struct SecureDownload {
        pub id: i32,
        pub user_id: i32,
        pub key_id: i32,
        pub download_token: String,
        pub expires_at: DateTime<Utc>,
        pub downloaded_at: Option<DateTime<Utc>>,
        pub download_ip: Option<String>, // Changed from IpAddr to String
        pub max_downloads: i32,
        pub download_count: i32,
        pub created_at: DateTime<Utc>,
    }

    #[derive(Debug, sqlx::FromRow)]
    pub struct KeyAccessLog {
        pub id: i32,
        pub key_id: Option<i32>,
        pub user_id: i32,
        pub access_type: String,
        pub ip_address: Option<String>, // Changed from IpAddr to String
        pub user_agent: Option<String>,
        pub success: bool,
        pub error_message: Option<String>,
        pub accessed_at: DateTime<Utc>,
    }
}
