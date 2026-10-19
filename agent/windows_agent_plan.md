# Windows Endpoint Activity Monitor Plan

## Goal

Track local device activity from a separate Windows service and send only consented telemetry to the MalwareGuard web app. This is not possible from a browser-only PHP application.

## Scope

The app can monitor:

- running processes
- window titles / active app
- CPU and memory usage
- drive and network activity
- login/logout timestamps
- browser process activity for the local user session

The app should not monitor:

- keystrokes without explicit consent
- webcam / microphone without explicit consent
- file contents beyond the user-approved scan flow
- unrelated users or system-level telemetry without legal notice

## Recommended architecture

### 1. Windows service agent

Create a small Windows service or scheduled background process that runs under the user session and uploads JSON telemetry to a secure PHP endpoint.

Core components:

- process collector
- session monitor
- network usage sampler
- telemetry serializer
- encrypted HTTPS uploader

### 2. Secure API endpoint

Add a separate endpoint in the PHP app to receive telemetry:

- POST /api/agent/heartbeat
- POST /api/agent/processes
- POST /api/agent/session

All requests must require:

- an agent token
- HTTPS only
- timestamp validation
- user consent record

### 3. Data model

Suggested database tables:

- endpoint_devices
- endpoint_sessions
- endpoint_processes
- endpoint_events
- endpoint_alerts

Example fields:

- device_id
- hostname
- user_sid
- session_id
- process_name
- process_id
- cpu_percent
- memory_mb
- window_title
- started_at
- ended_at
- event_type

## Privacy and compliance

- show clear consent before installation
- log the scope of telemetry
- allow opt-out
- local retention only if allowed
- provide delete/export controls

## Implementation order

1. Add the consent and device registration flow in the web app.
2. Create the backend endpoint for agent registration.
3. Build the Windows agent to send heartbeat and process data.
4. Add alerting rules for suspicious process chains.
5. Add a dashboard screen for endpoint telemetry.

## Important note

This must be a separate local agent, not a browser script. A PHP page in the browser cannot inspect the host operating system in a reliable or consent-safe way.
