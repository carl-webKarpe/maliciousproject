-- Migration 002: authorized search activity
--
-- Browser history is used only to extract recognized search-engine queries.
-- Windows Search stores the recent Explorer search terms in this account.

CREATE TABLE IF NOT EXISTS search_events (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    device_id VARCHAR(128) NOT NULL,
    event_uid CHAR(64) NOT NULL,
    source VARCHAR(64) NOT NULL,
    search_term VARCHAR(500) NOT NULL,
    query_url VARCHAR(2048) NULL DEFAULT NULL,
    occurred_at DATETIME NOT NULL,
    received_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY unique_search_event (device_id, event_uid),
    KEY idx_search_events_occurred (occurred_at),
    KEY idx_search_events_source (source),
    CONSTRAINT fk_search_events_device FOREIGN KEY (device_id)
        REFERENCES endpoint_devices (device_id) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
