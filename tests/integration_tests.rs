use student_key_manager::prelude::*;
use student_key_manager::models::{MappingData, StudentMapping, KeyGenerationConfig};
use chrono::Utc;

fn init_logger() {
    let _ = env_logger::builder()
        .is_test(true)
        .filter_level(log::LevelFilter::Debug)
        .try_init();
}

fn create_test_students() -> Vec<StudentMapping> {
    vec![
        StudentMapping {
            original_id: 1,
            anonymized_id: 100001,
            firstname: "Alice".to_string(),
            lastname: "Johnson".to_string(),
            pin: 1111,
        },
        StudentMapping {
            original_id: 2,
            anonymized_id: 100002,
            firstname: "Bob".to_string(),
            lastname: "Smith".to_string(),
            pin: 2222,
        },
        StudentMapping {
            original_id: 3,
            anonymized_id: 100003,
            firstname: "Charlie".to_string(),
            lastname: "Brown".to_string(),
            pin: 3333,
        },
    ]
}

#[test]
fn test_full_encryption_workflow() {
    init_logger();
    
    let encryption_service = EncryptionService::new();
    let password = "SecurePassword123!";
    
    // Create test data
    let mapping_data = MappingData {
        students: create_test_students(),
        created_at: Utc::now(),
        user_id: 42,
        key_version: 1,
    };
    
    // Step 1: Encrypt the data
    let encrypted_result = encryption_service
        .encrypt_mapping_data(&mapping_data, password)
        .expect("Encryption should succeed");
    
    println!("✓ Data encrypted successfully");
    println!("  - Encrypted data size: {} bytes", encrypted_result.encrypted_data.len());
    println!("  - Data hash: {}...", &encrypted_result.data_hash[..16]);
    
    // Step 2: Decrypt the data
    let decrypted_data = encryption_service
        .decrypt_mapping_data(&encrypted_result.encrypted_data, password)
        .expect("Decryption should succeed");
    
    println!("✓ Data decrypted successfully");
    
    // Step 3: Verify all student data
    assert_eq!(mapping_data.students.len(), decrypted_data.students.len());
    assert_eq!(mapping_data.user_id, decrypted_data.user_id);
    assert_eq!(mapping_data.key_version, decrypted_data.key_version);
    
    for (original, decrypted) in mapping_data.students.iter().zip(decrypted_data.students.iter()) {
        assert_eq!(original.original_id, decrypted.original_id);
        assert_eq!(original.anonymized_id, decrypted.anonymized_id);
        assert_eq!(original.firstname, decrypted.firstname);
        assert_eq!(original.lastname, decrypted.lastname);
        assert_eq!(original.pin, decrypted.pin);
    }
    
    // Step 4: Verify data integrity
    let is_valid = encryption_service
        .verify_data_integrity(&decrypted_data, &encrypted_result.data_hash)
        .expect("Integrity verification should succeed");
    
    assert!(is_valid);
    println!("✓ Data integrity verified");
    
    println!("✓ Full encryption workflow completed successfully");
}

#[test]
fn test_multiple_users_different_keys() {
    init_logger();
    
    let encryption_service = EncryptionService::new();
    let password = "SharedPassword123!";
    
    // User 1 data
    let user1_data = MappingData {
        students: vec![
            StudentMapping {
                original_id: 10,
                anonymized_id: 100010,
                firstname: "User1Student1".to_string(),
                lastname: "Lastname1".to_string(),
                pin: 1010,
            },
        ],
        created_at: Utc::now(),
        user_id: 1,
        key_version: 1,
    };
    
    // User 2 data (different user, same password)
    let user2_data = MappingData {
        students: vec![
            StudentMapping {
                original_id: 20,
                anonymized_id: 100020,
                firstname: "User2Student1".to_string(),
                lastname: "Lastname2".to_string(),
                pin: 2020,
            },
        ],
        created_at: Utc::now(),
        user_id: 2,
        key_version: 1,
    };
    
    // Encrypt both
    let encrypted1 = encryption_service.encrypt_mapping_data(&user1_data, password).unwrap();
    let encrypted2 = encryption_service.encrypt_mapping_data(&user2_data, password).unwrap();
    
    // Encrypted data should be different even with same password
    assert_ne!(encrypted1.encrypted_data, encrypted2.encrypted_data);
    assert_ne!(encrypted1.salt, encrypted2.salt);
    assert_ne!(encrypted1.data_hash, encrypted2.data_hash);
    
    // Both should decrypt correctly
    let decrypted1 = encryption_service.decrypt_mapping_data(&encrypted1.encrypted_data, password).unwrap();
    let decrypted2 = encryption_service.decrypt_mapping_data(&encrypted2.encrypted_data, password).unwrap();
    
    assert_eq!(decrypted1.user_id, 1);
    assert_eq!(decrypted2.user_id, 2);
    assert_eq!(decrypted1.students[0].firstname, "User1Student1");
    assert_eq!(decrypted2.students[0].firstname, "User2Student1");
    
    println!("✓ Multiple users with different keys working correctly");
}

#[test]
fn test_key_generation_config() {
    let config = KeyGenerationConfig::default();
    
    assert_eq!(config.download_expiry_hours, 24);
    assert_eq!(config.max_downloads, 3);
    assert_eq!(config.key_expiry_days, 30);
    assert!(config.create_download_link);
    
    // Test custom config
    let custom_config = KeyGenerationConfig {
        create_download_link: false,
        download_expiry_hours: 12,
        max_downloads: 1,
        key_expiry_days: 7,
    };
    
    assert!(!custom_config.create_download_link);
    assert_eq!(custom_config.download_expiry_hours, 12);
    assert_eq!(custom_config.max_downloads, 1);
    assert_eq!(custom_config.key_expiry_days, 7);
    
    println!("✓ Key generation config working correctly");
}

#[test]
fn test_encryption_with_special_characters() {
    init_logger();
    
    let encryption_service = EncryptionService::new();
    let password = "P@ssw0rd!With$pecial#Ch@rs";
    
    let mapping_data = MappingData {
        students: vec![
            StudentMapping {
                original_id: 1,
                anonymized_id: 100001,
                firstname: "José".to_string(),
                lastname: "García-López".to_string(),
                pin: 1234,
            },
            StudentMapping {
                original_id: 2,
                anonymized_id: 100002,
                firstname: "李".to_string(),
                lastname: "小明".to_string(),
                pin: 5678,
            },
            StudentMapping {
                original_id: 3,
                anonymized_id: 100003,
                firstname: "Müller".to_string(),
                lastname: "O'Connor".to_string(),
                pin: 9999,
            },
        ],
        created_at: Utc::now(),
        user_id: 1,
        key_version: 1,
    };
    
    // Encrypt and decrypt
    let encrypted = encryption_service.encrypt_mapping_data(&mapping_data, password).unwrap();
    let decrypted = encryption_service.decrypt_mapping_data(&encrypted.encrypted_data, password).unwrap();
    
    // Verify special characters are preserved
    assert_eq!(decrypted.students[0].firstname, "José");
    assert_eq!(decrypted.students[0].lastname, "García-López");
    assert_eq!(decrypted.students[1].firstname, "李");
    assert_eq!(decrypted.students[1].lastname, "小明");
    assert_eq!(decrypted.students[2].firstname, "Müller");
    assert_eq!(decrypted.students[2].lastname, "O'Connor");
    
    println!("✓ Special characters and Unicode handled correctly");
}

#[test]
fn test_error_handling() {
    init_logger();
    
    let encryption_service = EncryptionService::new();
    
    // Test invalid JSON
    let invalid_json = "not valid json";
    let result = encryption_service.decrypt_mapping_data(invalid_json, "password");
    assert!(result.is_err());
    match result.unwrap_err() {
        EncryptionError::InvalidKeyFormat(_) => {},
        _ => panic!("Expected InvalidKeyFormat error"),
    }
    
    // Test weak passwords
    let weak_passwords = vec![
        "short",
        "nouppercase123",
        "NOLOWERCASE123",
        "NoNumbers",
        "",
    ];
    
    for weak_password in weak_passwords {
        let result = encryption_service.validate_password_strength(weak_password);
        assert!(result.is_err(), "Password '{}' should be rejected", weak_password);
    }
    
    println!("✓ Error handling working correctly");
}

#[test]
fn test_performance_with_large_dataset() {
    init_logger();
    
    let encryption_service = EncryptionService::new();
    let password = "PerformanceTest123!";
    
    // Create a large dataset
    let students: Vec<StudentMapping> = (1..=5000)
        .map(|i| StudentMapping {
            original_id: i,
            anonymized_id: 100000 + i,
            firstname: format!("FirstName{}", i),
            lastname: format!("LastName{}", i),
            pin: 1000 + (i % 9999),
        })
        .collect();
    
    let mapping_data = MappingData {
        students,
        created_at: Utc::now(),
        user_id: 1,
        key_version: 1,
    };
    
    println!("Testing with {} students", mapping_data.students.len());
    
    // Time the encryption
    let start = std::time::Instant::now();
    let encrypted = encryption_service.encrypt_mapping_data(&mapping_data, password).unwrap();
    let encrypt_duration = start.elapsed();
    
    // Time the decryption
    let start = std::time::Instant::now();
    let decrypted = encryption_service.decrypt_mapping_data(&encrypted.encrypted_data, password).unwrap();
    let decrypt_duration = start.elapsed();
    
    // Verify the data
    assert_eq!(mapping_data.students.len(), decrypted.students.len());
    assert_eq!(decrypted.students[0].firstname, "FirstName1");
    assert_eq!(decrypted.students[4999].firstname, "FirstName5000");
    
    println!("✓ Performance test completed:");
    println!("  - Encryption: {:?}", encrypt_duration);
    println!("  - Decryption: {:?}", decrypt_duration);
    println!("  - Total size: {} bytes", encrypted.encrypted_data.len());
    
    // Performance assertions (these are reasonable for 5000 students)
    assert!(encrypt_duration.as_millis() < 1000, "Encryption took too long: {:?}", encrypt_duration);
    assert!(decrypt_duration.as_millis() < 1000, "Decryption took too long: {:?}", decrypt_duration);
}
