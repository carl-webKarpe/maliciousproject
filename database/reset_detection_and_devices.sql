-- MalwareGuard: RESET detection data and all devices (XAMPP / phpMyAdmin)
--
-- What it does, in one import:
--   1. Creates the `malwareguard` database and any missing table (safe on a
--      new server and on an existing one).
--   2. DELETES all detection data and every registered computer:
--        file events, search activity, scans and findings, scan requests,
--        VirusTotal cache, alerts, devices, enrollment tokens, sign-in lockouts.
--   3. KEEPS user and admin accounts, sign-in history and the audit log, so you
--      can still sign in afterwards.
--
-- This cannot be undone. Back up first if you may need the old data:
--   phpMyAdmin -> malwareguard -> Export -> Go.
--
-- How to import: http://localhost/phpmyadmin -> Import -> choose this file -> Import.
--
-- After the reset every agent's key is gone, so each PC must be added again:
--   dashboard -> Add a computer -> Generate token, then on the PC delete the
--   agent's "data" folder and run INSTALL_AGENT.bat with the new token.
-- No accounts yet? Create one:  C:\xampp\php\php.exe reset_account.php

CREATE DATABASE IF NOT EXISTS `malwareguard` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE `malwareguard`;
SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- ---------------------------------------------------------------------------
-- 1. Tables (created only if missing; existing tables are left as they are)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS `audit_log` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `actor_type` varchar(16) NOT NULL,
  `actor_id` varchar(128) DEFAULT NULL,
  `action` varchar(64) NOT NULL,
  `target` varchar(255) DEFAULT NULL,
  `details` text DEFAULT NULL,
  `ip_address` varchar(45) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `idx_audit_log_created` (`created_at`),
  KEY `idx_audit_log_action` (`action`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
CREATE TABLE IF NOT EXISTS `detection_results` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `scan_id` bigint(20) unsigned NOT NULL,
  `detection_type` varchar(64) NOT NULL DEFAULT 'general',
  `detection_name` varchar(128) NOT NULL,
  `severity` varchar(32) NOT NULL DEFAULT 'low',
  `description` text NOT NULL,
  `evidence` text DEFAULT NULL,
  `score` int(11) NOT NULL DEFAULT 0,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `idx_detection_results_scan_id` (`scan_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
CREATE TABLE IF NOT EXISTS `endpoint_alerts` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `device_id` varchar(128) NOT NULL,
  `alert_type` varchar(64) NOT NULL,
  `severity` varchar(32) NOT NULL DEFAULT 'medium',
  `message` text NOT NULL,
  `status` varchar(32) NOT NULL DEFAULT 'open',
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `idx_endpoint_alerts_device_id` (`device_id`),
  KEY `idx_endpoint_alerts_created_at` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
CREATE TABLE IF NOT EXISTS `endpoint_devices` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `device_id` varchar(128) NOT NULL,
  `display_name` varchar(255) DEFAULT NULL,
  `hostname` varchar(255) DEFAULT NULL,
  `username` varchar(255) DEFAULT NULL,
  `os_name` varchar(255) DEFAULT NULL,
  `last_seen_at` datetime DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `agent_version` varchar(32) DEFAULT NULL,
  `ip_address` varchar(45) DEFAULT NULL,
  `credential_hash` char(64) DEFAULT NULL,
  `pending_credential_hash` char(64) DEFAULT NULL,
  `credential_rotated_at` datetime DEFAULT NULL,
  `rotate_requested` tinyint(1) NOT NULL DEFAULT 0,
  `status` varchar(32) NOT NULL DEFAULT 'active',
  `enrollment_token_id` bigint(20) unsigned DEFAULT NULL,
  `registered_at` datetime DEFAULT NULL,
  `last_heartbeat_at` datetime DEFAULT NULL,
  `heartbeat_interval` int(10) unsigned NOT NULL DEFAULT 30,
  `last_auth_failure_at` datetime DEFAULT NULL,
  `last_agent_error` varchar(500) DEFAULT NULL,
  `queue_depth` int(10) unsigned NOT NULL DEFAULT 0,
  `monitored_paths` text DEFAULT NULL,
  `revoked_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_device_id` (`device_id`),
  KEY `idx_endpoint_devices_last_seen` (`last_seen_at`),
  KEY `idx_endpoint_devices_heartbeat` (`last_heartbeat_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
CREATE TABLE IF NOT EXISTS `endpoint_processes` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `device_id` varchar(128) NOT NULL,
  `process_name` varchar(255) NOT NULL,
  `process_id` int(10) unsigned NOT NULL,
  `cpu_percent` decimal(5,2) DEFAULT 0.00,
  `memory_mb` decimal(10,2) DEFAULT 0.00,
  `window_title` varchar(255) DEFAULT NULL,
  `status` varchar(32) NOT NULL DEFAULT 'running',
  `seen_at` datetime DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `idx_endpoint_processes_device_id` (`device_id`),
  KEY `idx_endpoint_processes_seen_at` (`seen_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
CREATE TABLE IF NOT EXISTS `endpoint_sessions` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `device_id` varchar(128) NOT NULL,
  `session_id` varchar(128) NOT NULL,
  `user_name` varchar(255) DEFAULT NULL,
  `active_window` varchar(255) DEFAULT NULL,
  `cpu_percent` decimal(5,2) DEFAULT 0.00,
  `memory_mb` decimal(10,2) DEFAULT 0.00,
  `network_status` varchar(64) DEFAULT 'unknown',
  `seen_at` datetime DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `idx_endpoint_sessions_device_id` (`device_id`),
  KEY `idx_endpoint_sessions_seen_at` (`seen_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
CREATE TABLE IF NOT EXISTS `enrollment_tokens` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `token_hash` char(64) NOT NULL,
  `token_hint` varchar(16) NOT NULL,
  `label` varchar(100) NOT NULL,
  `created_by` int(10) unsigned DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `expires_at` datetime NOT NULL,
  `used_at` datetime DEFAULT NULL,
  `used_by_device` varchar(128) DEFAULT NULL,
  `revoked_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_enrollment_token_hash` (`token_hash`),
  KEY `idx_enrollment_tokens_expires` (`expires_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
CREATE TABLE IF NOT EXISTS `file_events` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `device_id` varchar(128) NOT NULL,
  `event_uid` char(64) NOT NULL,
  `event_type` varchar(32) NOT NULL,
  `file_path` varchar(1024) NOT NULL,
  `previous_path` varchar(1024) DEFAULT NULL,
  `file_name` varchar(255) NOT NULL,
  `file_size` bigint(20) unsigned DEFAULT NULL,
  `sha256` char(64) DEFAULT NULL,
  `user_account` varchar(255) DEFAULT NULL,
  `hash_note` varchar(255) DEFAULT NULL,
  `is_potential_download` tinyint(1) NOT NULL DEFAULT 0,
  `occurred_at` datetime NOT NULL,
  `detected_at` datetime DEFAULT NULL,
  `received_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_file_event` (`device_id`,`event_uid`),
  KEY `idx_file_events_occurred` (`occurred_at`),
  KEY `idx_file_events_sha256` (`sha256`),
  KEY `idx_file_events_event_type` (`event_type`),
  CONSTRAINT `fk_file_events_device` FOREIGN KEY (`device_id`) REFERENCES `endpoint_devices` (`device_id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
CREATE TABLE IF NOT EXISTS `login_activity` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `user_id` int(10) unsigned NOT NULL,
  `email` varchar(255) NOT NULL,
  `ip_address` varchar(45) DEFAULT NULL,
  `user_agent` text DEFAULT NULL,
  `status` varchar(32) NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `idx_login_activity_user_id` (`user_id`),
  KEY `idx_login_activity_created_at` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
CREATE TABLE IF NOT EXISTS `rate_limits` (
  `bucket` varchar(191) NOT NULL,
  `window_start` int(10) unsigned NOT NULL,
  `hits` int(10) unsigned NOT NULL DEFAULT 0,
  PRIMARY KEY (`bucket`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
CREATE TABLE IF NOT EXISTS `scan_requests` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `device_id` varchar(128) NOT NULL,
  `file_event_id` bigint(20) unsigned DEFAULT NULL,
  `file_path` varchar(1024) NOT NULL,
  `sha256` char(64) DEFAULT NULL,
  `requested_by` int(10) unsigned DEFAULT NULL,
  `status` varchar(32) NOT NULL DEFAULT 'pending',
  `attempts` int(10) unsigned NOT NULL DEFAULT 0,
  `error_message` varchar(500) DEFAULT NULL,
  `scan_id` bigint(20) unsigned DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `dispatched_at` datetime DEFAULT NULL,
  `completed_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_scan_requests_device_status` (`device_id`,`status`),
  KEY `idx_scan_requests_event` (`file_event_id`),
  CONSTRAINT `fk_scan_requests_device` FOREIGN KEY (`device_id`) REFERENCES `endpoint_devices` (`device_id`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `fk_scan_requests_event` FOREIGN KEY (`file_event_id`) REFERENCES `file_events` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
CREATE TABLE IF NOT EXISTS `scans` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `user_id` int(10) unsigned NOT NULL,
  `file_name` varchar(255) NOT NULL,
  `original_file_name` varchar(255) NOT NULL,
  `file_path` varchar(255) NOT NULL,
  `file_size` bigint(20) unsigned NOT NULL,
  `file_type` varchar(255) DEFAULT NULL,
  `file_extension` varchar(64) DEFAULT NULL,
  `file_hash` char(64) NOT NULL,
  `threat_level` varchar(32) NOT NULL DEFAULT 'safe',
  `detection_status` varchar(32) NOT NULL DEFAULT 'safe',
  `security_score` int(11) NOT NULL DEFAULT 0,
  `detection_count` int(11) NOT NULL DEFAULT 0,
  `analysis_result` text DEFAULT NULL,
  `scan_engine` varchar(128) NOT NULL DEFAULT 'MalwareGuard Engine',
  `scanned_at` datetime DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `scan_source` varchar(32) NOT NULL DEFAULT 'upload',
  `device_id` varchar(128) DEFAULT NULL,
  `scan_request_id` bigint(20) unsigned DEFAULT NULL,
  `source_path` varchar(1024) DEFAULT NULL,
  `vt_status` varchar(32) DEFAULT NULL,
  `vt_malicious` int(10) unsigned DEFAULT NULL,
  `vt_suspicious` int(10) unsigned DEFAULT NULL,
  `vt_engines` int(10) unsigned DEFAULT NULL,
  `detection_source` varchar(255) DEFAULT NULL,
  `recommended_action` varchar(500) DEFAULT NULL,
  `error_message` varchar(500) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_scans_user_id` (`user_id`),
  KEY `idx_scans_scanned_at` (`scanned_at`),
  KEY `idx_scans_device_id` (`device_id`),
  KEY `idx_scans_file_hash` (`file_hash`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
CREATE TABLE IF NOT EXISTS `schema_migrations` (
  `version` varchar(100) NOT NULL,
  `applied_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`version`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
CREATE TABLE IF NOT EXISTS `search_events` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `device_id` varchar(128) NOT NULL,
  `event_uid` char(64) NOT NULL,
  `source` varchar(64) NOT NULL,
  `search_term` varchar(500) NOT NULL,
  `query_url` varchar(2048) DEFAULT NULL,
  `occurred_at` datetime NOT NULL,
  `received_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_search_event` (`device_id`,`event_uid`),
  KEY `idx_search_events_occurred` (`occurred_at`),
  KEY `idx_search_events_source` (`source`),
  CONSTRAINT `fk_search_events_device` FOREIGN KEY (`device_id`) REFERENCES `endpoint_devices` (`device_id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
CREATE TABLE IF NOT EXISTS `users` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `name` varchar(100) NOT NULL,
  `email` varchar(255) NOT NULL,
  `password` varchar(255) NOT NULL,
  `role` varchar(32) NOT NULL DEFAULT 'user',
  `status` varchar(32) NOT NULL DEFAULT 'active',
  `last_login` datetime DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_email` (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
CREATE TABLE IF NOT EXISTS `vt_cache` (
  `sha256` char(64) NOT NULL,
  `status` varchar(16) NOT NULL,
  `malicious` int(10) unsigned NOT NULL DEFAULT 0,
  `suspicious` int(10) unsigned NOT NULL DEFAULT 0,
  `engines` int(10) unsigned NOT NULL DEFAULT 0,
  `last_analysis_at` datetime DEFAULT NULL,
  `fetched_at` datetime NOT NULL,
  PRIMARY KEY (`sha256`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

INSERT IGNORE INTO `schema_migrations` (`version`) VALUES ('001_device_monitoring'), ('002_search_activity'), ('003_file_event_details');

-- ---------------------------------------------------------------------------
-- 2. Reset detection data and devices
--    DELETE in child-to-parent order (not TRUNCATE), so it works on XAMPP's
--    MariaDB even when phpMyAdmin keeps foreign key checks on.
-- ---------------------------------------------------------------------------

DELETE FROM `scan_requests`;
DELETE FROM `file_events`;
DELETE FROM `search_events`;
DELETE FROM `detection_results`;
DELETE FROM `scans`;
DELETE FROM `vt_cache`;
DELETE FROM `endpoint_alerts`;
DELETE FROM `endpoint_sessions`;
DELETE FROM `endpoint_processes`;
DELETE FROM `endpoint_devices`;
DELETE FROM `enrollment_tokens`;
DELETE FROM `rate_limits`;

-- Restart the ID counters at 1.
ALTER TABLE `scan_requests` AUTO_INCREMENT = 1;
ALTER TABLE `file_events` AUTO_INCREMENT = 1;
ALTER TABLE `search_events` AUTO_INCREMENT = 1;
ALTER TABLE `detection_results` AUTO_INCREMENT = 1;
ALTER TABLE `scans` AUTO_INCREMENT = 1;
ALTER TABLE `endpoint_alerts` AUTO_INCREMENT = 1;
ALTER TABLE `endpoint_sessions` AUTO_INCREMENT = 1;
ALTER TABLE `endpoint_processes` AUTO_INCREMENT = 1;
ALTER TABLE `endpoint_devices` AUTO_INCREMENT = 1;
ALTER TABLE `enrollment_tokens` AUTO_INCREMENT = 1;

SET FOREIGN_KEY_CHECKS = 1;

-- Record the reset in the audit log.
INSERT INTO `audit_log` (`actor_type`, `action`, `details`)
VALUES ('system', 'database.reset', '{"cleared": "detection data and all devices", "source": "reset_detection_and_devices.sql"}');
