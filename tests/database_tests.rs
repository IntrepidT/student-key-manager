#[cfg(feature = "database")]
mod database_integration_tests {
    use student_key_manager::prelude::*;
    use student_key_manager::models::{KeyGenerationConfig, StudentMapping, MappingData};
    use student_key_manager::database::DatabaseService;
    use sqlx::postgres::{PgPool, PgPoolOptions};
    use chrono::{Utc, Duration};
    use std::env;

    // Helper function to setup test database
    async fn setup_test_db() -> PgPool {
        // You'll need to set TEST_DATABASE_URL in your environment
        let database_url = env::var("TEST_DATABASE_URL")
            .unwrap_or_else(|_| "postgresql://postgres:password@localhost/student_key_manager_test".to_string());
        
        PgPoolOptions::new()
            .max_connections(5)
            .connect(&database_url)
            .await
            .expect("Failed to connect to test database")
    }

    // Helper function to clean up test data
    async fn cleanup_test_data(pool: &PgPool, user_id: i32) {
        let _ = sqlx::query("DELETE FROM key_access_log WHERE user_id = $1")
            .bind(user_id)
            .execute(pool)
            .await;
            
        let _ = sqlx::query("DELETE FROM secure_key_downloads WHERE user_id = $1")
            .bind(user_id)
            .execute(pool)
            .await;
            
        let _ = sqlx::query("DELETE FROM anonymization_keys WHERE user_id = $1")
            .bind(user_id)
            .execute(pool)
            .await;
            
        let _ = sqlx::query("DELETE FROM student_id_mapping WHERE created_by = $1")
            .bind(user_id)
            .execute(pool)
            .await;
    }

    // Helper to create test students in database
    async fn create_test_students(pool: &PgPool, user_id: i32) -> Vec<i32> {
        // First create a test class
        let class_id: i32 = sqlx::query_scalar(
            "INSERT INTO classes (name, user_id, created_at) VALUES ($1, $2, NOW()) RETURNING id"
        )
        .bind(format!("Test Class {}", user_id))
        .bind(user_id)
        .fetch_one(pool)
        .await
        .expect("Should create test class");

        // Create test students
        let mut student_ids = Vec::new();
        for i in 1..=3 {
            let student_id: i32 = sqlx::query_scalar(
                "INSERT INTO students (firstname, lastname, pin, created_at) VALUES ($1, $2, $3, NOW()) RETURNING student_id"
            )
            .bind(format!("TestStudent{}", i))
            .bind(format!("TestLast{}", i))
            .bind(1000 + i)
            .fetch_one(pool)
            .await
            .expect("Should create test student");

            // Enroll student in class
            sqlx::query(
                "INSERT INTO student_enrollments (student_id, class_id, enrolled_at) VALUES ($1, $2, NOW())"
            )
            .bind(student_id)
            .bind(class_id)
            .execute(pool)
            .await
            .expect("Should enroll student");

            student_ids.push(student_id);
        }

        student_ids
    }

    #[tokio::test]
    #[ignore] // Run with: cargo test -- --ignored
    async fn test_database_connection() {
        let pool = setup_test_db().await;
        
        // Test basic query
        let result: (i32,) = sqlx::query_as("SELECT 1")
            .fetch_one(&pool)
            .await
            .expect("Should be able to query database");
        
        assert_eq!(result.0, 1);
        println!("✓ Database connection working");
    }

    #[tokio::test]
    #[ignore]
    async fn test_rekey_status_check() {
        let pool = setup_test_db().await;
        let db_service = DatabaseService::new(pool.clone());
        let test_user_id = 9999;
        
        // Cleanup any existing test data
        cleanup_test_data(&pool, test_user_id).await;
        
        // Test with user that has no keys
        let status = db_service.check_rekey_status(test_user_id).await.unwrap();
        assert!(status.needs_rekey);
        assert_eq!(status.reason, "No anonymization key exists");
        assert_eq!(status.current_students, 0);
        assert_eq!(status.mapped_students, 0);
        
        println!("✓ Rekey status check working for user with no keys");
    }

    #[tokio::test]
    #[ignore]
    async fn test_key_storage_and_retrieval() {
        let pool = setup_test_db().await;
        let db_service = DatabaseService::new(pool.clone());
        let test_user_id = 9998;
        
        cleanup_test_data(&pool, test_user_id).await;
        
        let test_data = "encrypted_test_data";
        let test_salt = "test_salt_123";
        let test_hash = "test_hash_456";
        let expires_at = Utc::now() + Duration::days(30);
        
        // Store key
        let key_id = db_service.store_anonymization_key(
            test_user_id,
            1,
            test_salt,
            test_data,
            test_hash,
            3,
            expires_at,
        ).await.unwrap();
        
        assert!(key_id > 0);
        
        // Retrieve key
        let retrieved_key = db_service.get_anonymization_key(key_id).await.unwrap();
        assert!(retrieved_key.is_some());
        
        let key = retrieved_key.unwrap();
        assert_eq!(key.user_id, test_user_id);
        assert_eq!(key.key_version, 1);
        assert_eq!(key.encryption_salt, test_salt);
        assert_eq!(key.encrypted_mapping_data, test_data);
        assert_eq!(key.data_hash, test_hash);
        assert_eq!(key.students_count, 3);
        assert!(key.is_active);
        
        cleanup_test_data(&pool, test_user_id).await;
        println!("✓ Key storage and retrieval working");
    }

    #[tokio::test]
    #[ignore]
    async fn test_secure_download_flow() {
        let pool = setup_test_db().await;
        let db_service = DatabaseService::new(pool.clone());
        let test_user_id = 9997;
        
        cleanup_test_data(&pool, test_user_id).await;
        
        // First create a key
        let key_id = db_service.store_anonymization_key(
            test_user_id,
            1,
            "salt",
            "encrypted_data",
            "hash",
            1,
            Utc::now() + Duration::days(30),
        ).await.unwrap();
        
        // Create secure download
        let token = "test_download_token_123";
        let expires_at = Utc::now() + Duration::hours(24);
        
        db_service.create_secure_download(
            key_id,
            test_user_id,
            token,
            expires_at,
            3,
        ).await.unwrap();
        
        // Retrieve download
        let download = db_service.get_secure_download(token).await.unwrap();
        assert!(download.is_some());
        
        let download = download.unwrap();
        assert_eq!(download.user_id, test_user_id);
        assert_eq!(download.key_id, key_id);
        assert_eq!(download.download_token, token);
        assert_eq!(download.max_downloads, 3);
        assert_eq!(download.download_count, 0);
        
        // Update download count
        let client_ip = Some("192.168.1.1".parse().unwrap());
        db_service.update_download_count(download.id, client_ip).await.unwrap();
        
        // Verify count updated
        let updated_download = db_service.get_secure_download(token).await.unwrap().unwrap();
        assert_eq!(updated_download.download_count, 1);
        assert!(updated_download.downloaded_at.is_some());
        assert!(updated_download.download_ip.is_some());
        
        cleanup_test_data(&pool, test_user_id).await;
        println!("✓ Secure download flow working");
    }

    #[tokio::test]
    #[ignore]
    async fn test_access_logging() {
        let pool = setup_test_db().await;
        let db_service = DatabaseService::new(pool.clone());
        let test_user_id = 9996;
        
        cleanup_test_data(&pool, test_user_id).await;
        
        // Log successful access
        let client_ip = Some("10.0.0.1".parse().unwrap());
        db_service.log_key_access(
            Some(123),
            test_user_id,
            "generate",
            true,
            client_ip,
            None,
        ).await.unwrap();
        
        // Log failed access
        db_service.log_key_access(
            None,
            test_user_id,
            "validate",
            false,
            client_ip,
            Some("Invalid password"),
        ).await.unwrap();
        
        // Verify logs were created
        let log_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM key_access_log WHERE user_id = $1"
        )
        .bind(test_user_id)
        .fetch_one(&pool)
        .await.unwrap();
        
        assert_eq!(log_count, 2);
        
        cleanup_test_data(&pool, test_user_id).await;
        println!("✓ Access logging working");
    }

    #[tokio::test]
    #[ignore]
    async fn test_expired_download_cleanup() {
        let pool = setup_test_db().await;
        let db_service = DatabaseService::new(pool.clone());
        let test_user_id = 9995;
        
        cleanup_test_data(&pool, test_user_id).await;
        
        // Create a key first
        let key_id = db_service.store_anonymization_key(
            test_user_id,
            1,
            "salt",
            "data",
            "hash",
            1,
            Utc::now() + Duration::days(30),
        ).await.unwrap();
        
        // Create expired download
        let expired_token = "expired_token";
        let expired_time = Utc::now() - Duration::hours(1); // 1 hour ago
        
        db_service.create_secure_download(
            key_id,
            test_user_id,
            expired_token,
            expired_time,
            1,
        ).await.unwrap();
        
        // Create valid download
        let valid_token = "valid_token";
        let valid_time = Utc::now() + Duration::hours(1); // 1 hour from now
        
        db_service.create_secure_download(
            key_id,
            test_user_id,
            valid_token,
            valid_time,
            1,
        ).await.unwrap();
        
        // Cleanup expired downloads
        let cleaned_count = db_service.cleanup_expired_downloads().await.unwrap();
        assert_eq!(cleaned_count, 1);
        
        // Verify expired is gone, valid remains
        let expired_result = db_service.get_secure_download(expired_token).await.unwrap();
        assert!(expired_result.is_none());
        
        let valid_result = db_service.get_secure_download(valid_token).await.unwrap();
        assert!(valid_result.is_some());
        
        cleanup_test_data(&pool, test_user_id).await;
        println!("✓ Expired download cleanup working");
    }

    #[tokio::test]
    #[ignore]
    async fn test_student_mapping_updates() {
        let pool = setup_test_db().await;
        let db_service = DatabaseService::new(pool.clone());
        let test_user_id = 9994;
        
        cleanup_test_data(&pool, test_user_id).await;
        
        // Test data
        let mappings = vec![
            (1, 100001, "Alice".to_string(), "Johnson".to_string(), 1111),
            (2, 100002, "Bob".to_string(), "Smith".to_string(), 2222),
        ];
        
        // Update mappings
        db_service.update_student_mappings(&mappings, 1, test_user_id).await.unwrap();
        
        // Verify mappings were stored
        let stored_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM student_id_mapping WHERE created_by = $1 AND key_version = $2"
        )
        .bind(test_user_id)
        .bind(1)
        .fetch_one(&pool)
        .await.unwrap();
        
        assert_eq!(stored_count, 2);
        
        // Test update (should overwrite)
        let updated_mappings = vec![
            (1, 100001, "Alice Updated".to_string(), "Johnson Updated".to_string(), 1111),
            (3, 100003, "Charlie".to_string(), "Brown".to_string(), 3333),
        ];
        
        db_service.update_student_mappings(&updated_mappings, 2, test_user_id).await.unwrap();
        
        // Should now have 3 total mappings (1 updated, 1 unchanged, 1 new)
        let total_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM student_id_mapping WHERE created_by = $1"
        )
        .bind(test_user_id)
        .fetch_one(&pool)
        .await.unwrap();
        
        assert_eq!(total_count, 3);
        
        cleanup_test_data(&pool, test_user_id).await;
        println!("✓ Student mapping updates working");
    }
}
