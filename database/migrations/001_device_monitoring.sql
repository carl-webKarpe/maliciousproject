-- Migration 001: device enrollment, file events, agent scans, audit log
--
-- Adds only. No existing table is dropped and no existing row is deleted.
-- Run once, after database/malwareguard.sql. `php database_setup.php` applies
-- it automatically and records it in schema_migrations; if you run it by hand
-- in MySQL Workbench first, database_setup.php notices the columns already
-- exist and simply marks the migration as applied.

USE `malwareguard`;

CREATE TABLE IF NOT EXISTS schema_migrations (
    version VARCHAR(100) NOT NULL,
    applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (version)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Registered computers: extend the existing endpoint_devices table.
ALTER TABLE endpoint_devices ADD COLUMN display_name VARCHAR(255) NULL DEFAULT NULL AFTER device_id;
ALTER TABLE endpoint_devices ADD COLUMN agent_version VARCHAR(32) NULL DEFAULT NULL;
ALTER TABLE endpoint_devices ADD COLUMN ip_address VARCHAR(45) NULL DEFAULT NULL;
ALTER TABLE endpoint_devices ADD COLUMN credential_hash CHAR(64) NULL DEFAULT NULL;
ALTER TABLE endpoint_devices ADD COLUMN pending_credential_hash CHAR(64) NULL DEFAULT NULL;
ALTER TABLE endpoint_devices ADD COLUMN credential_rotated_at DATETIME NULL DEFAULT NULL;
ALTER TABLE endpoint_devices ADD COLUMN rotate_requested TINYINT(1) NOT NULL DEFAULT 0;
ALTER TABLE endpoint_devices ADD COLUMN status VARCHAR(32) NOT NULL DEFAULT 'active';
ALTER TABLE endpoint_devices ADD COLUMN enrollment_token_id BIGINT UNSIGNED NULL DEFAULT NULL;
ALTER TABLE endpoint_devices ADD COLUMN registered_at DATETIME NULL DEFAULT NULL;
ALTER TABLE endpoint_devices ADD COLUMN last_heartbeat_at DATETIME NULL DEFAULT NULL;
ALTER TABLE endpoint_devices ADD COLUMN heartbeat_interval INT UNSIGNED NOT NULL DEFAULT 30;
ALTER TABLE endpoint_devices ADD COLUMN last_auth_failure_at DATETIME NULL DEFAULT NULL;
ALTER TABLE endpoint_devices ADD COLUMN last_agent_error VARCHAR(500) NULL DEFAULT NULL;
ALTER TABLE endpoint_devices ADD COLUMN queue_depth INT UNSIGNED NOT NULL DEFAULT 0;
ALTER TABLE endpoint_devices ADD COLUMN monitored_paths TEXT NULL;
ALTER TABLE endpoint_devices ADD COLUMN revoked_at DATETIME NULL DEFAULT NULL;
ALTER TABLE endpoint_devices ADD KEY idx_endpoint_devices_heartbeat (last_heartbeat_at);

-- Devices reported by the old shared-token PowerShell agent have no
-- per-device credential; they stay visible but can never authenticate.
UPDATE endpoint_devices SET status = 'legacy' WHERE credential_hash IS NULL AND status = 'active';

-- One-time enrollment tokens. Only a SHA-256 hash of each token is stored.
CREATE TABLE IF NOT EXISTS enrollment_tokens (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    token_hash CHAR(64) NOT NULL,
    token_hint VARCHAR(16) NOT NULL,
    label VARCHAR(100) NOT NULL,
    created_by INT UNSIGNED NULL DEFAULT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    used_at DATETIME NULL DEFAULT NULL,
    used_by_device VARCHAR(128) NULL DEFAULT NULL,
    revoked_at DATETIME NULL DEFAULT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY unique_enrollment_token_hash (token_hash),
    KEY idx_enrollment_tokens_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- File activity reported by agents. (device_id, event_uid) makes retries idempotent.
CREATE TABLE IF NOT EXISTS file_events (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    device_id VARCHAR(128) NOT NULL,
    event_uid CHAR(64) NOT NULL,
    event_type VARCHAR(32) NOT NULL,
    file_path VARCHAR(1024) NOT NULL,
    previous_path VARCHAR(1024) NULL DEFAULT NULL,
    file_name VARCHAR(255) NOT NULL,
    file_size BIGINT UNSIGNED NULL DEFAULT NULL,
    sha256 CHAR(64) NULL DEFAULT NULL,
    hash_note VARCHAR(255) NULL DEFAULT NULL,
    is_potential_download TINYINT(1) NOT NULL DEFAULT 0,
    occurred_at DATETIME NOT NULL,
    received_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY unique_file_event (device_id, event_uid),
    KEY idx_file_events_occurred (occurred_at),
    KEY idx_file_events_sha256 (sha256),
    CONSTRAINT fk_file_events_device FOREIGN KEY (device_id)
        REFERENCES endpoint_devices (device_id) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Scans an administrator (or the optional auto-scan setting) asked an agent to perform.
CREATE TABLE IF NOT EXISTS scan_requests (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    device_id VARCHAR(128) NOT NULL,
    file_event_id BIGINT UNSIGNED NULL DEFAULT NULL,
    file_path VARCHAR(1024) NOT NULL,
    sha256 CHAR(64) NULL DEFAULT NULL,
    requested_by INT UNSIGNED NULL DEFAULT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'pending',
    attempts INT UNSIGNED NOT NULL DEFAULT 0,
    error_message VARCHAR(500) NULL DEFAULT NULL,
    scan_id BIGINT UNSIGNED NULL DEFAULT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    dispatched_at DATETIME NULL DEFAULT NULL,
    completed_at DATETIME NULL DEFAULT NULL,
    PRIMARY KEY (id),
    KEY idx_scan_requests_device_status (device_id, status),
    KEY idx_scan_requests_event (file_event_id),
    CONSTRAINT fk_scan_requests_device FOREIGN KEY (device_id)
        REFERENCES endpoint_devices (device_id) ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT fk_scan_requests_event FOREIGN KEY (file_event_id)
        REFERENCES file_events (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Extra evidence columns on the existing scans table.
ALTER TABLE scans ADD COLUMN scan_source VARCHAR(32) NOT NULL DEFAULT 'upload';
ALTER TABLE scans ADD COLUMN device_id VARCHAR(128) NULL DEFAULT NULL;
ALTER TABLE scans ADD COLUMN scan_request_id BIGINT UNSIGNED NULL DEFAULT NULL;
ALTER TABLE scans ADD COLUMN source_path VARCHAR(1024) NULL DEFAULT NULL;
ALTER TABLE scans ADD COLUMN vt_status VARCHAR(32) NULL DEFAULT NULL;
ALTER TABLE scans ADD COLUMN vt_malicious INT UNSIGNED NULL DEFAULT NULL;
ALTER TABLE scans ADD COLUMN vt_suspicious INT UNSIGNED NULL DEFAULT NULL;
ALTER TABLE scans ADD COLUMN vt_engines INT UNSIGNED NULL DEFAULT NULL;
ALTER TABLE scans ADD COLUMN detection_source VARCHAR(255) NULL DEFAULT NULL;
ALTER TABLE scans ADD COLUMN recommended_action VARCHAR(500) NULL DEFAULT NULL;
ALTER TABLE scans ADD COLUMN error_message VARCHAR(500) NULL DEFAULT NULL;
ALTER TABLE scans ADD KEY idx_scans_device_id (device_id);
ALTER TABLE scans ADD KEY idx_scans_file_hash (file_hash);

-- VirusTotal hash lookups are cached so repeat files do not spend API quota.
CREATE TABLE IF NOT EXISTS vt_cache (
    sha256 CHAR(64) NOT NULL,
    status VARCHAR(16) NOT NULL,
    malicious INT UNSIGNED NOT NULL DEFAULT 0,
    suspicious INT UNSIGNED NOT NULL DEFAULT 0,
    engines INT UNSIGNED NOT NULL DEFAULT 0,
    last_analysis_at DATETIME NULL DEFAULT NULL,
    fetched_at DATETIME NOT NULL,
    PRIMARY KEY (sha256)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Fixed-window request counters for login, enrollment, agent API and VirusTotal.
CREATE TABLE IF NOT EXISTS rate_limits (
    bucket VARCHAR(191) NOT NULL,
    window_start INT UNSIGNED NOT NULL,
    hits INT UNSIGNED NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Who did what: administrator actions and security-relevant agent events.
CREATE TABLE IF NOT EXISTS audit_log (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    actor_type VARCHAR(16) NOT NULL,
    actor_id VARCHAR(128) NULL DEFAULT NULL,
    action VARCHAR(64) NOT NULL,
    target VARCHAR(255) NULL DEFAULT NULL,
    details TEXT NULL,
    ip_address VARCHAR(45) NULL DEFAULT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_audit_log_created (created_at),
    KEY idx_audit_log_action (action)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
