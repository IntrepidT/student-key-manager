use thiserror::Error;

#[derive(Error, Debug)]
pub enum EncryptionError {
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("Invalid key format: {0}")]
    InvalidKeyFormat(String),

    #[error("Data integrity check failed")]
    IntegrityCheckFailed,

    #[error("Password hash error: {0}")]
    PasswordHashError(String),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("Invalid salt format")]
    InvalidSaltFormat,

    #[error("Encryption key too short")]
    KeyTooShort,
}

#[cfg(feature = "database")]
#[derive(Error, Debug)]
pub enum KeyManagementError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Encryption error: {0}")]
    Encryption(#[from] EncryptionError),

    #[error("Key not found")]
    KeyNotFound,

    #[error("Download token expired or invalid")]
    InvalidDownloadToken,

    #[error("Maximum downloads exceeded")]
    MaxDownloadsExceeded,

    #[error("Re-key not needed: {0}")]
    RekeyNotNeeded(String),

    #[error("User not authorized")]
    Unauthorized,

    #[error("Key has expired")]
    KeyExpired,

    #[error("Invalid user credentials")]
    InvalidCredentials,
}
