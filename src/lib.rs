pub mod encryption;
pub mod errors;
pub mod models;

#[cfg(feature = "database")]
pub mod database;

#[cfg(feature = "database")]
pub mod key_management;

// Re-export main types
pub use encryption::EncryptionService;
pub use errors::EncryptionError;
pub use models::{EncryptedPackage, KeyGenerationConfig, MappingData, StudentMapping};

#[cfg(feature = "database")]
pub use errors::KeyManagementError;

#[cfg(feature = "database")]
pub use key_management::KeyManagementService;

// Prelude for easy imports
pub mod prelude {
    pub use crate::encryption::EncryptionService;
    pub use crate::errors::EncryptionError;
    pub use crate::models::{KeyGenerationConfig, MappingData, StudentMapping};

    #[cfg(feature = "database")]
    pub use crate::key_management::KeyManagementService;

    #[cfg(feature = "database")]
    pub use crate::errors::KeyManagementError;
}

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[test]
    fn test_basic_encryption() {
        let service = EncryptionService::new();
        assert!(service.generate_download_token().len() > 0);
    }

    #[tokio::test]
    #[cfg(feature = "database")]
    async fn test_key_generation_config() {
        let config = KeyGenerationConfig::default();
        assert_eq!(config.download_expiry_hours, 24);
        assert_eq!(config.max_downloads, 3);
        assert_eq!(config.key_expiry_days, 30);
        assert!(config.create_download_link);
    }
}
