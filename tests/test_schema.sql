-- tests/test_schema.sql
-- Minimal schema for testing the student key manager

-- Users table (simplified for testing)
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Classes table (simplified for testing)
CREATE TABLE IF NOT EXISTS classes (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    user_id INTEGER REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Students table (simplified for testing)
CREATE TABLE IF NOT EXISTS students (
    student_id SERIAL PRIMARY KEY,
    firstname VARCHAR(100),
    lastname VARCHAR(100),
    pin INTEGER,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Student enrollments (simplified for testing)
CREATE TABLE IF NOT EXISTS student_enrollments (
    id SERIAL PRIMARY KEY,
    student_id INTEGER REFERENCES students(student_id),
    class_id INTEGER REFERENCES classes(id),
    enrolled_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Global settings (from your existing schema)
CREATE TABLE IF NOT EXISTS global_settings (
  id SERIAL PRIMARY KEY,
  key VARCHAR(255) UNIQUE NOT NULL,
  value JSONB NOT NULL,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_by INTEGER REFERENCES users(id)
);

-- Student ID mapping (from your existing schema)
CREATE TABLE IF NOT EXISTS student_id_mapping (
    old_student_id INTEGER NOT NULL,
    new_student_id INTEGER NOT NULL,
    firstname VARCHAR(100) NOT NULL,
    lastname VARCHAR(100) NOT NULL,
    pin INT NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    key_version INTEGER DEFAULT 1,
    created_by INTEGER REFERENCES users(id),
    PRIMARY KEY (old_student_id)
);

-- Key management tables (from our new schema)
CREATE TABLE IF NOT EXISTS anonymization_keys (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id),
  key_version INTEGER NOT NULL DEFAULT 1,
  encryption_salt VARCHAR(255) NOT NULL,
  encrypted_mapping_data TEXT NOT NULL,
  data_hash VARCHAR(255) NOT NULL,
  students_count INTEGER NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  expires_at TIMESTAMP WITH TIME ZONE NULL,
  is_active BOOLEAN DEFAULT true,
  download_count INTEGER DEFAULT 0,
  last_accessed TIMESTAMP WITH TIME ZONE NULL,
  UNIQUE(user_id, key_version)
);

CREATE TABLE IF NOT EXISTS key_access_log (
  id SERIAL PRIMARY KEY,
  key_id INTEGER REFERENCES anonymization_keys(id),
  user_id INTEGER REFERENCES users(id),
  access_type VARCHAR(50) NOT NULL,
  ip_address TEXT,
  user_agent TEXT,
  success BOOLEAN DEFAULT true,
  error_message TEXT,
  accessed_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS secure_key_downloads (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id),
  key_id INTEGER REFERENCES anonymization_keys(id),
  download_token VARCHAR(255) UNIQUE NOT NULL,
  expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
  downloaded_at TIMESTAMP WITH TIME ZONE NULL,
  download_ip TEXT,
  max_downloads INTEGER DEFAULT 1,
  download_count INTEGER DEFAULT 0,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_anonymization_keys_user_active ON anonymization_keys(user_id, is_active);
CREATE INDEX IF NOT EXISTS idx_key_access_log_user_time ON key_access_log(user_id, accessed_at);
CREATE INDEX IF NOT EXISTS idx_secure_downloads_token ON secure_key_downloads(download_token);
CREATE INDEX IF NOT EXISTS idx_secure_downloads_expires ON secure_key_downloads(expires_at);

-- Functions
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
  SELECT COUNT(DISTINCT s.student_id) INTO current_count 
  FROM students s 
  JOIN student_enrollments se ON s.student_id = se.student_id
  JOIN classes c ON se.class_id = c.id
  WHERE c.user_id = p_user_id;
  
  SELECT 
    COALESCE(MAX(key_version), 0),
    COALESCE(MAX(students_count), 0),
    MAX(created_at)
  INTO latest_key_version, mapped_count, latest_key_date
  FROM anonymization_keys 
  WHERE user_id = p_user_id AND is_active = true;
  
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

-- Insert test user for consistent testing
INSERT INTO users (id, username, email) VALUES (9999, 'test_user', 'test@example.com') ON CONFLICT DO NOTHING;
