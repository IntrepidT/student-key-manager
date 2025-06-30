-- migrations/001_student_key_management.sql
-- Student Key Management System Schema

-- Enhanced anonymization keys table
CREATE TABLE IF NOT EXISTS anonymization_keys (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id),
  key_version INTEGER NOT NULL DEFAULT 1,
  encryption_salt VARCHAR(255) NOT NULL, -- For password-based encryption
  encrypted_mapping_data TEXT NOT NULL,   -- The actual encrypted student mapping
  data_hash VARCHAR(255) NOT NULL,       -- Hash for integrity verification
  students_count INTEGER NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  expires_at TIMESTAMP WITH TIME ZONE NULL,
  is_active BOOLEAN DEFAULT true,
  download_count INTEGER DEFAULT 0,
  last_accessed TIMESTAMP WITH TIME ZONE NULL,
  UNIQUE(user_id, key_version)
);

-- Key access and download tracking
CREATE TABLE IF NOT EXISTS key_access_log (
  id SERIAL PRIMARY KEY,
  key_id INTEGER REFERENCES anonymization_keys(id),
  user_id INTEGER REFERENCES users(id),
  access_type VARCHAR(50) NOT NULL, -- 'generate', 'download', 'decrypt', 'validate'
  ip_address TEXT, -- Store IP as text for compatibility
  user_agent TEXT,
  success BOOLEAN DEFAULT true,
  error_message TEXT,
  accessed_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Secure download tokens (for temporary download links)
CREATE TABLE IF NOT EXISTS secure_key_downloads (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id),
  key_id INTEGER REFERENCES anonymization_keys(id),
  download_token VARCHAR(255) UNIQUE NOT NULL,
  expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
  downloaded_at TIMESTAMP WITH TIME ZONE NULL,
  download_ip TEXT, -- Store IP as text for compatibility
  max_downloads INTEGER DEFAULT 1,
  download_count INTEGER DEFAULT 0,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Update your existing student_id_mapping to include key version
ALTER TABLE student_id_mapping ADD COLUMN IF NOT EXISTS key_version INTEGER DEFAULT 1;
ALTER TABLE student_id_mapping ADD COLUMN IF NOT EXISTS created_by INTEGER REFERENCES users(id);

-- Add indexes for performance
CREATE INDEX IF NOT EXISTS idx_anonymization_keys_user_active ON anonymization_keys(user_id, is_active);
CREATE INDEX IF NOT EXISTS idx_key_access_log_user_time ON key_access_log(user_id, accessed_at);
CREATE INDEX IF NOT EXISTS idx_secure_downloads_token ON secure_key_downloads(download_token);
CREATE INDEX IF NOT EXISTS idx_secure_downloads_expires ON secure_key_downloads(expires_at);

-- Function to check if user needs new key
CREATE OR REPLACE FUNCTION check_rekey_needed(p_user_id INTEGER)
RETURNS TABLE(
  needs_rekey BOOLEAN,
  reason TEXT,
  current_students INTEGER,
  mapped_students INTEGER,
  new_students INTEGER,
  removed_students INTEGER,
  last_key_date TIMESTAMP WITH TIME ZONE
) AS $$
DECLARE
  current_count INTEGER;
  mapped_count INTEGER;
  latest_key_version INTEGER;
  latest_key_date TIMESTAMP WITH TIME ZONE;
BEGIN
  -- Get current student count for user (students in user's classes)
  SELECT COUNT(DISTINCT s.student_id) INTO current_count 
  FROM students s 
  JOIN student_enrollments se ON s.student_id = se.student_id
  JOIN classes c ON se.class_id = c.id
  WHERE c.user_id = p_user_id;
  
  -- Get latest key info
  SELECT 
    COALESCE(MAX(key_version), 0),
    COALESCE(MAX(students_count), 0),
    MAX(created_at)
  INTO latest_key_version, mapped_count, latest_key_date
  FROM anonymization_keys 
  WHERE user_id = p_user_id AND is_active = true;
  
  -- Determine if re-keying is needed
  IF latest_key_version = 0 THEN
    RETURN QUERY SELECT 
      true, 
      'No anonymization key exists'::TEXT,
      current_count,
      0,
      current_count,
      0,
      NULL::TIMESTAMP WITH TIME ZONE;
  ELSIF current_count != mapped_count THEN
    RETURN QUERY SELECT 
      true,
      CASE 
        WHEN current_count > mapped_count THEN 'New students added to classes'
        WHEN current_count < mapped_count THEN 'Students removed from classes'
        ELSE 'Student enrollment changes detected'
      END::TEXT,
      current_count,
      mapped_count,
      GREATEST(0, current_count - mapped_count),
      GREATEST(0, mapped_count - current_count),
      latest_key_date;
  ELSE
    RETURN QUERY SELECT 
      false,
      'Anonymization key is current'::TEXT,
      current_count,
      mapped_count,
      0,
      0,
      latest_key_date;
  END IF;
END;
$$ LANGUAGE plpgsql;

-- Function to cleanup expired download tokens
CREATE OR REPLACE FUNCTION cleanup_expired_downloads()
RETURNS INTEGER AS $$
DECLARE
  deleted_count INTEGER;
BEGIN
  DELETE FROM secure_key_downloads 
  WHERE expires_at < NOW();
  
  GET DIAGNOSTICS deleted_count = ROW_COUNT;
  RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;
