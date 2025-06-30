#[cfg(feature = "database")]
use crate::errors::KeyManagementError;
#[cfg(feature = "database")]
use crate::models::{db::*, RekeyStatus};
#[cfg(feature = "database")]
use chrono::{DateTime, Utc};
#[cfg(feature = "database")]
use sqlx::{postgres::PgPool, Row};
#[cfg(feature = "database")]
use std::net::IpAddr;

#[cfg(feature = "database")]
pub struct DatabaseService {
    pool: PgPool,
}

#[cfg(feature = "database")]
impl DatabaseService {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Check if user needs a new key by calling the PostgreSQL function
    pub async fn check_rekey_status(
        &self,
        user_id: i32,
    ) -> Result<RekeyStatus, KeyManagementError> {
        let row = sqlx::query("SELECT * FROM check_rekey_needed($1)")
            .bind(user_id)
            .fetch_one(&self.pool)
            .await?;

        Ok(RekeyStatus {
            needs_rekey: row.get("needs_rekey"),
            reason: row.get("reason"),
            current_students: row.get("current_students"),
            mapped_students: row.get("mapped_students"),
            new_students: row.get("new_students"),
            removed_students: row.get("removed_students"),
            last_key_date: row.get("last_key_date"),
        })
    }

    /// Get student data for a user to create mappings
    pub async fn get_user_students(
        &self,
        user_id: i32,
    ) -> Result<Vec<(i32, Option<String>, Option<String>, Option<i32>)>, KeyManagementError> {
        let rows = sqlx::query(
            r#"
            SELECT DISTINCT s.student_id, s.firstname, s.lastname, s.pin
            FROM students s 
            JOIN student_enrollments se ON s.student_id = se.student_id
            JOIN classes c ON se.class_id = c.id
            WHERE c.user_id = $1
            ORDER BY s.student_id
        "#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|row| {
                (
                    row.get("student_id"),
                    row.get("firstname"),
                    row.get("lastname"),
                    row.get("pin"),
                )
            })
            .collect())
    }

    /// Store a new anonymization key
    pub async fn store_anonymization_key(
        &self,
        user_id: i32,
        key_version: i32,
        encryption_salt: &str,
        encrypted_data: &str,
        data_hash: &str,
        students_count: i32,
        expires_at: DateTime<Utc>,
    ) -> Result<i32, KeyManagementError> {
        // Start transaction
        let mut tx = self.pool.begin().await?;

        // Deactivate old keys
        sqlx::query("UPDATE anonymization_keys SET is_active = false WHERE user_id = $1")
            .bind(user_id)
            .execute(&mut *tx)
            .await?;

        // Insert new key
        let key_id: i32 = sqlx::query_scalar(r#"
            INSERT INTO anonymization_keys 
            (user_id, key_version, encryption_salt, encrypted_mapping_data, data_hash, students_count, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING id
        "#)
        .bind(user_id)
        .bind(key_version)
        .bind(encryption_salt)
        .bind(encrypted_data)
        .bind(data_hash)
        .bind(students_count)
        .bind(expires_at)
        .fetch_one(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(key_id)
    }

    /// Update student mappings table
    pub async fn update_student_mappings(
        &self,
        mappings: &[(i32, i32, String, String, i32)], // (original_id, anon_id, firstname, lastname, pin)
        key_version: i32,
        user_id: i32,
    ) -> Result<(), KeyManagementError> {
        let mut tx = self.pool.begin().await?;

        for (original_id, anon_id, firstname, lastname, pin) in mappings {
            sqlx::query(
                r#"
                INSERT INTO student_id_mapping 
                (old_student_id, new_student_id, firstname, lastname, pin, key_version, created_by)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                ON CONFLICT (old_student_id) DO UPDATE SET
                    new_student_id = EXCLUDED.new_student_id,
                    firstname = EXCLUDED.firstname,
                    lastname = EXCLUDED.lastname,
                    pin = EXCLUDED.pin,
                    key_version = EXCLUDED.key_version,
                    created_at = NOW()
            "#,
            )
            .bind(original_id)
            .bind(anon_id)
            .bind(firstname)
            .bind(lastname)
            .bind(pin)
            .bind(key_version)
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(())
    }

    /// Create secure download token
    pub async fn create_secure_download(
        &self,
        key_id: i32,
        user_id: i32,
        download_token: &str,
        expires_at: DateTime<Utc>,
        max_downloads: i32,
    ) -> Result<(), KeyManagementError> {
        sqlx::query(
            r#"
            INSERT INTO secure_key_downloads 
            (user_id, key_id, download_token, expires_at, max_downloads)
            VALUES ($1, $2, $3, $4, $5)
        "#,
        )
        .bind(user_id)
        .bind(key_id)
        .bind(download_token)
        .bind(expires_at)
        .bind(max_downloads)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get secure download by token
    pub async fn get_secure_download(
        &self,
        token: &str,
    ) -> Result<Option<SecureDownload>, KeyManagementError> {
        let download = sqlx::query_as::<_, SecureDownload>(
            r#"
            SELECT * FROM secure_key_downloads 
            WHERE download_token = $1 AND expires_at > NOW()
        "#,
        )
        .bind(token)
        .fetch_optional(&self.pool)
        .await?;

        Ok(download)
    }

    /// Update download count
    pub async fn update_download_count(
        &self,
        download_id: i32,
        client_ip: Option<IpAddr>,
    ) -> Result<(), KeyManagementError> {
        let ip_string = client_ip.map(|ip| ip.to_string());

        sqlx::query(
            r#"
            UPDATE secure_key_downloads 
            SET download_count = download_count + 1,
                downloaded_at = CASE WHEN downloaded_at IS NULL THEN NOW() ELSE downloaded_at END,
                download_ip = COALESCE(download_ip, $2)
            WHERE id = $1
        "#,
        )
        .bind(download_id)
        .bind(ip_string)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get anonymization key by ID
    pub async fn get_anonymization_key(
        &self,
        key_id: i32,
    ) -> Result<Option<AnonymizationKey>, KeyManagementError> {
        let key = sqlx::query_as::<_, AnonymizationKey>(
            r#"
            SELECT * FROM anonymization_keys 
            WHERE id = $1 AND is_active = true
        "#,
        )
        .bind(key_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(key)
    }

    /// Get user's active key
    pub async fn get_user_active_key(
        &self,
        user_id: i32,
        key_version: Option<i32>,
    ) -> Result<Option<AnonymizationKey>, KeyManagementError> {
        let key = if let Some(version) = key_version {
            sqlx::query_as::<_, AnonymizationKey>(
                r#"
                SELECT * FROM anonymization_keys 
                WHERE user_id = $1 AND key_version = $2 AND is_active = true
            "#,
            )
            .bind(user_id)
            .bind(version)
            .fetch_optional(&self.pool)
            .await?
        } else {
            sqlx::query_as::<_, AnonymizationKey>(
                r#"
                SELECT * FROM anonymization_keys 
                WHERE user_id = $1 AND is_active = true
                ORDER BY key_version DESC
                LIMIT 1
            "#,
            )
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await?
        };

        Ok(key)
    }

    /// Log key access
    pub async fn log_key_access(
        &self,
        key_id: Option<i32>,
        user_id: i32,
        access_type: &str,
        success: bool,
        ip_address: Option<IpAddr>,
        error_message: Option<&str>,
    ) -> Result<(), KeyManagementError> {
        let ip_string = ip_address.map(|ip| ip.to_string());

        sqlx::query(
            r#"
            INSERT INTO key_access_log 
            (key_id, user_id, access_type, success, ip_address, error_message)
            VALUES ($1, $2, $3, $4, $5, $6)
        "#,
        )
        .bind(key_id)
        .bind(user_id)
        .bind(access_type)
        .bind(success)
        .bind(ip_string)
        .bind(error_message)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get next key version for user
    pub async fn get_next_key_version(&self, user_id: i32) -> Result<i32, KeyManagementError> {
        let version: i32 = sqlx::query_scalar(
            "SELECT COALESCE(MAX(key_version), 0) + 1 FROM anonymization_keys WHERE user_id = $1",
        )
        .bind(user_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(version)
    }

    /// Clean up expired download tokens
    pub async fn cleanup_expired_downloads(&self) -> Result<u64, KeyManagementError> {
        let result = sqlx::query("DELETE FROM secure_key_downloads WHERE expires_at < NOW()")
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected())
    }

    /// Update global settings for student protections
    pub async fn update_student_protection_status(
        &self,
        user_id: i32,
        protected: bool,
    ) -> Result<(), KeyManagementError> {
        sqlx::query(
            r#"
            INSERT INTO global_settings (key, value, updated_by) 
            VALUES ('student_protections', $1, $2) 
            ON CONFLICT (key) DO UPDATE SET 
                value = EXCLUDED.value,
                updated_at = CURRENT_TIMESTAMP,
                updated_by = EXCLUDED.updated_by
        "#,
        )
        .bind(if protected { "true" } else { "false" })
        .bind(user_id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }
}
