-- Migration 002: richer file-event details
--
-- Adds only. No existing table is dropped and no existing row is deleted.
-- Run once, after 001_device_monitoring.sql. `php database_setup.php` applies
-- it automatically; running it by hand in MySQL Workbench / phpMyAdmin also
-- works, and database_setup.php then records it as applied.

USE `malwareguard`;

-- The Windows user account the event was seen under (when the agent knows it).
ALTER TABLE file_events ADD COLUMN user_account VARCHAR(255) NULL DEFAULT NULL AFTER sha256;

-- When the agent observed the event, separate from occurred_at (the file's own
-- time) and received_at (when the server stored it). NULL for older rows.
ALTER TABLE file_events ADD COLUMN detected_at DATETIME NULL DEFAULT NULL AFTER occurred_at;

-- Filtering the dashboard by event type.
ALTER TABLE file_events ADD KEY idx_file_events_event_type (event_type);
