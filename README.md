# MalwareGuard

MalwareGuard monitors **authorized** Windows PCs and laptops for new and changed files in administrator-approved folders, scans files for malware indicators on request, and shows the evidence in a central web dashboard.

- **Server:** PHP (built-in web server for a lab, or a real web server for longer-running use) with MySQL Server.
- **Agent:** a small Python program installed on each monitored computer.
- **Dashboard:** user scanning pages, an admin scan-activity dashboard, a device management page, and a super-admin user database.

**New here? Follow [SETUP.md](SETUP.md)** for a step-by-step installation and start-up guide.

> Install the agent only on computers you own or are authorized to monitor, and tell the people who use them. The agent watches only the folders listed in its configuration (by default the user's Downloads folder). It does not collect passwords, browser history, messages or keystrokes, and it never runs, deletes or moves files.

---

## Contents

1. [How it works](#how-it-works)
2. [Server setup (Windows)](#server-setup-windows)
3. [Database with MySQL Workbench](#database-with-mysql-workbench)
4. [Start and stop the server](#start-and-stop-the-server)
5. [Register a computer (agent setup)](#register-a-computer-agent-setup)
6. [Networks: Ethernet, Wi-Fi, hotspot](#networks-ethernet-wi-fi-hotspot)
7. [Scanning and risk levels](#scanning-and-risk-levels)
8. [Accounts and passwords](#accounts-and-passwords)
9. [Security notes](#security-notes)
10. [Running for longer (production)](#running-for-longer-production)
11. [Troubleshooting](#troubleshooting)
12. [Project layout](#project-layout)
13. [Test status](#test-status)

---

## How it works

```
 Monitored PC / laptop                                Server PC
 ┌───────────────────────────┐   HTTP(S) + per-device   ┌──────────────────────────────┐
 │ agent.py                  │   credential              │ PHP (router.php)             │
 │  • watches approved dirs  │ ───────────────────────▶ │  api/agent.php               │
 │  • queues events offline  │   heartbeat / events      │  admin/devices.php           │
 │  • uploads a file only    │ ◀─────────────────────── │  includes/scan_engine.php    │
 │    when a scan is asked   │   scan jobs               │            │                 │
 └───────────────────────────┘                           │        MySQL Server          │
                                                         └────────────┬─────────────────┘
                                                                      │ SHA-256 hash only
                                                                      ▼ (optional)
                                                                  VirusTotal
```

1. An administrator generates a one-time **enrollment token** on the Devices page.
2. `INSTALL_AGENT.bat` on the target computer sends the token to the server. The server checks it (valid, unexpired, unused, not revoked), registers the device, and issues a **unique device credential**. Only a hash of the token and of the credential is stored on the server; on Windows the agent encrypts its credential with DPAPI.
3. The agent sends a **heartbeat** every 30 seconds. A device is shown as online only while authenticated heartbeats keep arriving.
4. When a file appears, changes, is renamed or is deleted in a monitored folder, the agent waits for the file to stop changing, hashes it (SHA-256) and sends a **file event**. Events are queued on disk while the server is unreachable and delivered later; each event has a unique ID, so retries never create duplicates.
5. An administrator clicks **Scan** next to an event (or enables `AUTO_SCAN_NEW_FILES`). On its next heartbeat the agent checks that the file is still inside an approved folder, uploads it to the MalwareGuard server, and the server runs the same analysis used for browser uploads. Only the hash is sent to VirusTotal.

---

## Server setup (Windows)

You need, on the server PC:

| Component | Notes |
| --- | --- |
| **PHP 8.1 or newer** (8.3 recommended) | Download the *Thread Safe* zip from <https://windows.php.net/download>, extract it to `C:\php`, and add `C:\php` to `PATH` (or set the environment variable `MALWAREGUARD_PHP` to the full path of `php.exe`). |
| **PHP extensions** | Copy `C:\php\php.ini-development` to `C:\php\php.ini`, set `extension_dir = "ext"`, and remove the leading `;` from: `extension=curl`, `extension=fileinfo`, `extension=mbstring`, `extension=mysqli`, `extension=openssl`, `extension=pdo_mysql`. |
| **Composer** | <https://getcomposer.org/download/>. Then, in the project folder: `composer install` |
| **MySQL Server 8** | Installed with MySQL Installer. MySQL Workbench is only the management tool; the **MySQL80** Windows service must be installed and running. |
| Python 3.8+ | Only on computers that run the agent (it can be the server too). |

XAMPP and Apache are **not** required. To run it on XAMPP instead (Apache + MariaDB + phpMyAdmin), follow [XAMPP.md](XAMPP.md).

Then:

1. Copy `.env.example` to `.env` and edit it (database account, optional Gmail and VirusTotal settings). `.env` is ignored by Git; never commit it.
2. Create the database account and schema (next section).
3. Double-click `START_MALICIOUSPROJECT.bat`.

---

## Database with MySQL Workbench

The schema is in [`database/malwareguard.sql`](database/malwareguard.sql) (the tables the app always used) plus the migrations in [`database/migrations/`](database/migrations) (new tables for devices, tokens, file events, scan requests, VirusTotal cache, rate limits and the audit log). Migrations only **add** tables and columns; they never drop tables or delete records.

### 1. Check that MySQL Server is running

`Win + R` → `services.msc` → find **MySQL80** → Status must be *Running* (right-click → Start if not). Set *Startup type* to *Automatic* if you want it to start with Windows. `START_MALICIOUSPROJECT.bat` also checks this.

### 2. Create a dedicated database account

In MySQL Workbench, connect as `root`, open a new query tab and run (choose your own password):

```sql
CREATE DATABASE IF NOT EXISTS malwareguard CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS 'malwareguard_app'@'localhost' IDENTIFIED BY 'choose-a-long-password';
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX, REFERENCES ON malwareguard.* TO 'malwareguard_app'@'localhost';
FLUSH PRIVILEGES;
```

Put the same values in `.env`: `DB_USER=malwareguard_app`, `DB_PASS=choose-a-long-password`.

### 3. Create or upgrade the tables

**Option A (recommended):** run `php database_setup.php` in the project folder, or just start the server. `START_MALICIOUSPROJECT.bat` runs it every time, and it applies only what is missing. `php database_setup.php --check` reports pending migrations without changing anything.

**Option B (MySQL Workbench):** *File → Open SQL Script…* → `database/malwareguard.sql` → *Query → Execute All* (lightning icon). Then do the same for each file in `database/migrations/` in name order (`001_…`, `002_…`). If you later run `database_setup.php`, it detects that the changes are already present and records them as applied.

To look at the data: in Workbench's *Schemas* panel, right-click **malwareguard** → *Refresh All*, expand *Tables*, right-click a table → *Select Rows*.

---

## Start and stop the server

### `START_MALICIOUSPROJECT.bat`

Double-click it. It:

1. finds `php.exe` (`MALWAREGUARD_PHP`, `PATH`, or `C:\php\php.exe`) and reports whether Python is available;
2. checks the MySQL Windows service and stops with instructions if it is installed but stopped;
3. checks the PHP version and extensions, Composer packages and `.env` (creating `.env` from the example if it is missing);
4. connects to MySQL with the `.env` account, and checks that `APP_HOST:APP_PORT` is free;
5. applies pending database migrations;
6. starts PHP's built-in server with `router.php` (which blocks `.env`, `vendor/`, `database/` and other private files) and a 50 MB upload limit;
7. waits for `/api/health.php` to answer, then prints the dashboard URL and, when listening on the network, each LAN address agents can use;
8. keeps running until you press **Ctrl+C** in that window or run `STOP_MALICIOUSPROJECT.bat`.

The listening address is configurable in `.env`:

| `APP_HOST` | Who can connect |
| --- | --- |
| `127.0.0.1` (default) | Only this PC. Agents on other computers cannot connect. |
| This PC's LAN IP, e.g. `192.168.1.10` | Computers on that network. **Recommended for a lab.** |
| `0.0.0.0` | Every network this PC is connected to. Use only if you need it. |

### `STOP_MALICIOUSPROJECT.bat`

Stops the server process recorded in `runtime\server.pid`. Before stopping it, it checks that the PID still belongs to a `php` process running this project's `router.php` with the same start time. Other PHP or Python programs are never touched.

### Allow other PCs through Windows Firewall

Once, in an **Administrator** PowerShell on the server (adjust the port):

```powershell
New-NetFirewallRule -DisplayName "MalwareGuard 8000" -Direction Inbound -Protocol TCP -LocalPort 8000 -Action Allow -Profile Private
```

Make sure the network is set to **Private** (Settings → Network & Internet → your connection → Network profile type). On a *Public* profile the rule above does not apply; avoid allowing the port on public networks.

---

## Register a computer (agent setup)

### On the dashboard

1. Sign in as an admin (or verified super admin) → **Devices** (`/admin/devices.php`).
2. Under **Enrollment tokens**, enter a label (for example `Lab PC 04`) and an expiry (1–168 hours, default 24) → **Generate token**.
3. Copy the token. It is shown **once**, works for **one** computer, and can be revoked while unused.

### On the computer to monitor

1. Install Python 3.8+ from <https://www.python.org/downloads/windows/> (tick *Add python.exe to PATH*).
2. Copy the project's `agent` folder to the computer, for example `C:\MalwareGuardAgent`.
3. Double-click `INSTALL_AGENT.bat`. It:
   - creates a private Python environment (`agent\.venv`) and installs `requests` and `watchdog`;
   - asks for the server address (shown by the start script, e.g. `http://192.168.1.10:8000`), the token and a name;
   - registers the device and stores its credential encrypted for the current Windows user;
   - runs connection diagnostics (`agent.py check`);
   - optionally creates a scheduled task **MalwareGuard Agent** that starts the agent hidden whenever this user signs in;
   - optionally starts the agent now.
4. The computer appears on the Devices page and turns **Online** within one heartbeat.

| File | Purpose |
| --- | --- |
| `agent/agent.py` | The agent: `enroll`, `run`, `check`, `status` |
| `agent/requirements.txt` | Python dependencies |
| `agent/agent_config.example.json` | Configuration template (no secrets) |
| `agent/INSTALL_AGENT.bat` | Install, enroll, diagnose, optional auto-start |
| `agent/START_AGENT.bat` | Start in a console window (`--background` runs hidden; used by the scheduled task) |
| `agent/STOP_AGENT.bat` | Stop cleanly; force-stops only the PID in `data\agent.pid` if it really is `agent.py` |

### Agent configuration (`agent\data\agent_config.json`)

| Key | Meaning |
| --- | --- |
| `server_url` | Server address including the port, e.g. `http://192.168.1.10:8000` |
| `device_id` | Filled in automatically at enrollment |
| `enrollment_token` | Leave empty; the installer passes it once and it is never stored |
| `watch_directories` | **Approved folders.** `{DOWNLOADS}` = the user's Downloads folder (honours folder redirection). Add only folders an administrator approved, e.g. `"C:\\LabSamples"` |
| `recursive` | `true` also watches subfolders |
| `heartbeat_interval` | Seconds between heartbeats (the server's `AGENT_HEARTBEAT_SECONDS` is used at enrollment) |
| `settle_seconds` | How long a file must stop changing before it is hashed and reported |
| `max_hash_mb` | Larger files are reported without a hash |
| `log_directory` | Log folder (relative to `data\`). Logs rotate at 1 MB × 5 |
| `ca_bundle` | Path to a CA certificate file when the server uses HTTPS with a private certificate |
| `allow_http_on_public_networks` | Keep `false`: plain HTTP is allowed only to private/LAN addresses |

Restart the agent after editing (`STOP_AGENT.bat`, then `START_AGENT.bat`).

### Useful commands (in the `agent` folder)

```bat
.venv\Scripts\python.exe agent.py status   :: enrollment, running state, queued events, watched folders
.venv\Scripts\python.exe agent.py check    :: DNS, TCP port, server health and authentication
.venv\Scripts\python.exe agent.py enroll --server http://192.168.1.10:8000 --token mg_...
```

### Revoke, rotate, re-enroll, update, uninstall

- **Rotate key:** Devices → *Rotate key*. The agent gets a new credential on its next heartbeat; the old one keeps working until the new one is used, so a lost response cannot lock the agent out.
- **Revoke:** Devices → *Revoke*. The credential is erased; the agent is refused with "revoked" and pending scans are cancelled. To use the computer again, generate a new token and run `INSTALL_AGENT.bat` (answer *y* to enroll again).
- **Update the agent:** `STOP_AGENT.bat`, replace `agent.py` and `requirements.txt`, run `INSTALL_AGENT.bat` (answer *N* to keep the existing enrollment), start it again. The version appears on the Devices page.
- **Uninstall:** `STOP_AGENT.bat`, `schtasks /delete /tn "MalwareGuard Agent" /f`, delete the agent folder, then revoke the device on the dashboard.

### How file events are detected

| What happens on disk | Reported as |
| --- | --- |
| New file in a monitored folder | `created`, marked *potential download* |
| Browser download (`file.pdf.crdownload` / `.part` renamed to `file.pdf`) | one `created` event for `file.pdf`, *potential download*, with the temporary name as `previous_path` |
| File content changed | `modified` |
| File renamed or moved within monitored folders | `moved`, with `previous_path` |
| File deleted | `deleted` (no hash, since the file is gone) |

"Potential download" means only that a new file appeared in a watched folder; it is not proof that a browser downloaded it. Temporary files (`.crdownload`, `.part`, `.tmp`, `~$…`) are ignored, a file is reported only after it stops changing and can be opened, and repeated notifications for the same file state collapse into one event.

---

## Networks: Ethernet, Wi-Fi, hotspot

In every case the agent connects to the **explicit server address** you give it, and the server only accepts it after token enrollment. Being on the same network is not enough on its own: the address, port and firewall must also allow it. No automatic network scanning or discovery is performed.

**Find the server's IP:** on the server run `ipconfig` and use the *IPv4 Address* of the adapter connected to the lab network. The start script also prints it. Set `APP_HOST` to that address.

### A. Ethernet / LAN (recommended)

- Connect the server and lab PCs to the same **switch** (or router). A direct cable between two PCs also works with modern network cards (auto MDI-X).
- **DHCP** (router hands out addresses) is simplest. Give the server a fixed address (a DHCP reservation in the router, or a static IP) so agents do not lose it.
- **No router (switch only or direct cable):** set static IPs on each PC, e.g. server `192.168.50.1`, clients `192.168.50.11`, `.12`… with subnet mask `255.255.255.0` (Control Panel → Network Connections → adapter → IPv4 → Properties).
- Allow the port in Windows Firewall (above) and set the network profile to Private.

### B. Same Wi-Fi network

Works when the access point lets clients talk to each other. Many guest, school and public networks enable **client/AP isolation**, which blocks this even though both devices are online. The server's address can also change when it reconnects; use a DHCP reservation if you can.

### C. Mobile hotspot

Connect the server and the clients to the same phone hotspot (or a Windows *Mobile hotspot*). Hotspot addresses (often `192.168.43.x`, `172.20.10.x` or `192.168.137.x`) change between sessions, so re-check `ipconfig` and update `APP_HOST` and the agents' `server_url` if needed. Some phones isolate hotspot clients from each other; then the connection cannot work. The PC's firewall profile for a hotspot is often *Public*; switch it to Private.

### Diagnose a computer that does not connect

Run `agent.py check` on that computer:

| Message | Meaning / fix |
| --- | --- |
| `Port … refused the connection` | Server not running, wrong port, or `APP_HOST=127.0.0.1` on the server. |
| `No answer on port …` | Wrong IP, Windows Firewall on the server, or Wi-Fi/hotspot client isolation. |
| `different subnets` note | The two devices are on different networks; they need a router between them. |
| `Server answered HTTP 503` | The server runs but its database is down or migrations are pending. |
| `Authentication: … revoked` / `failed` | Re-enroll with a new token. |

### Status on the dashboard

| Status | Meaning |
| --- | --- |
| **Online** | An authenticated heartbeat arrived within `AGENT_OFFLINE_AFTER_SECONDS` (default 90 s, at least 3 heartbeat intervals). |
| **Online (agent reported a problem)** | Connected, but the agent reported an error (shown underneath). |
| **Offline** | No recent heartbeat. The last connection problem the agent reported, if any, is shown. |
| **Registered, no heartbeat yet** | Enrolled, but the agent has not started monitoring. |
| **Awaiting registration** | A token is issued and unused (Enrollment tokens table, and the counter at the top). |
| **Authentication failed** | A request with a wrong credential arrived after the last good heartbeat. |
| **Revoked** / **Re-enroll required** | Revoked by an admin / reported by the old shared-token agent. |

Agent-side connection errors (refused, timed out, DNS, TLS) are written to `agent\data\logs\agent.log`. They are also reported to the server with the next successful heartbeat, so the dashboard shows what went wrong while the device was offline.

---

## Scanning and risk levels

Two ways to scan, both using `includes/scan_engine.php`:

- **Browser upload:** *File Scanner* (users and admins). Files up to 50 MB are stored in a quarantine folder outside the project under a random `.quarantine` name.
- **Agent scan:** Devices → *Scan* next to a file event. The agent uploads the file to this server (never to a third party). The file must still exist inside an approved folder; otherwise the job fails with the reason. Jobs not answered within 10 minutes are offered again, up to 3 attempts.

**Evidence sources**

1. **MalwareGuard static rules:** deceptive double extensions, executable and script types, suspicious filename patterns, Windows executable content hidden behind another extension (`MZ` header), and suspicious command strings (`powershell`, `cmd.exe`, `WScript.Shell`, `CreateObject`).
2. **VirusTotal hash reputation** (optional, `VIRUSTOTAL_API_KEY`): only the SHA-256 hash is sent. Results are cached per hash for `VT_CACHE_HOURS` (default 24 h; "unknown to VirusTotal" for 1 h), and lookups are limited to `VT_REQUESTS_PER_MINUTE` / `VT_REQUESTS_PER_DAY` (defaults 4 and 500, the free API quota). When the quota is used up, VirusTotal is unreachable, or the key is wrong, the result says so and the verdict is based on static rules only.

**Risk classification** (the stronger source wins)

| Level | Rule |
| --- | --- |
| **Critical** | Static points ≥ 70, or VirusTotal malicious ≥ 3 |
| **High** | Static points ≥ 45, or VirusTotal malicious 1–2 |
| **Medium** | Static points ≥ 20, or VirusTotal suspicious only |
| **Low** | Static points 1–19 |
| **Safe** | No indicator from the checks that ran. This is not a guarantee, and the result text says which checks ran. |
| **Unknown** | The file could not be analysed |
| **Not scanned** | A file event with no completed scan |

The **score** shown (0–100) is 100 minus the points of matched indicators. It is a rule-based score, **not** a probability or confidence level. The **detection ratio** (e.g. `5/70`) is shown only when VirusTotal knew the hash. Each result also shows file name, path, size, SHA-256, computer name and ID, scan status, detection source, timestamp, recommended next action and any error.

High and Critical agent scans also create an alert in the super-admin dashboard (*Recent Detections*). MalwareGuard never deletes, moves or executes a file.

---

## Accounts and passwords

No default accounts exist. Passwords are stored as hashes.

| Account type | How it is created |
| --- | --- |
| User | Self-registration with an email verification code (needs `MAIL_USER`/`MAIL_PASS`; on the server PC itself the code is shown on screen when email is not configured). |
| Admin | Created by a super admin (*Manage Admins*), or an existing row with `role = 'admin'`. |
| Super admin | `php super_admin/create_account.php` (set `SUPER_ADMIN_PASSWORD` in `.env` first, then remove it). Sign-in requires a code emailed to the account. |

Reset passwords from the command line (not through a browser): `php rotate_user_password.php`, `php rotate_admin_password.php`.

Gmail: enable 2-Step Verification and create an **App Password** for `MAIL_PASS`. If an App Password was ever committed or shared, revoke it in your Google account and create a new one.

Sign-in is limited to 8 attempts per account and 20 per IP address every 15 minutes.

---

## Security notes

- Enrollment tokens: 192-bit random, stored as SHA-256 hashes, single use, expiring (default 24 h), revocable.
- Device credentials: 256-bit random, unique per device, stored as hashes; rotation and revocation from the dashboard; DPAPI-encrypted on the agent.
- The agent API accepts only a fixed set of actions. It cannot run commands on a computer or read files outside the approved folders; the agent enforces this itself, even if the server were compromised.
- Rate limits: agent API per IP (120/min), enrollment (10 per 10 min per IP), failed device authentication, sign-in, uploads, VirusTotal.
- Audit log (`audit_log` table): token creation and revocation, enrollments and rejections, authentication failures, rotations, revocations, scan requests and results, uploads.
- `router.php` keeps `.env`, `vendor/`, `database/`, `includes/`, `tools/`, `runtime/`, `agent/` and `.sql`/`.md`/`.bat` files out of reach of the built-in server.
- **HTTPS:** PHP's built-in server speaks HTTP only. On an isolated lab LAN that is a reasonable trade-off, and the agent refuses plain HTTP to public addresses. For anything beyond a closed lab, put the app behind HTTPS (next section) and set the agents' `server_url` to `https://…`.

---

## Running for longer (production)

PHP's built-in server handles one request at a time and has no TLS, which is fine for a lab of a few dozen PCs. For a permanent deployment:

- Serve the project with **IIS + PHP (FastCGI)**, **Apache httpd**, or **nginx + php-cgi** on Windows, with the document root set to the project folder. Deny web access to `.env`, `vendor/`, `database/`, `includes/`, `tools/`, `runtime/` and `agent/` (on Apache, `AllowOverride` plus deny rules; on IIS, *Request Filtering → Hidden Segments*).
- Set `upload_max_filesize = 55M` and `post_max_size = 60M` in `php.ini`.
- Enable HTTPS with a certificate (an internal CA works; give agents its certificate via `ca_bundle`).
- Run MySQL with the dedicated account above, never `root`, and back up the `malwareguard` schema regularly (Workbench → *Server → Data Export*).
- Start the agent at sign-in with the scheduled task, or as a service with a wrapper such as NSSM.

---

## Troubleshooting

| Problem | Fix |
| --- | --- |
| `PHP extension 'pdo_mysql' is not enabled` | Edit `php.ini` as in the setup table. Check which file is used with `php --ini`. |
| `MySQL Server is not answering` | Start the **MySQL80** service. |
| `MySQL rejected user …` | `DB_USER`/`DB_PASS` in `.env` do not match the account created in Workbench. |
| `Cannot listen on …` | Port in use (run `STOP_MALICIOUSPROJECT.bat` or change `APP_PORT`), or `APP_HOST` is not an address of this PC. |
| Uploads over 2 MB fail | Start through `START_MALICIOUSPROJECT.bat` (it raises the limits), or edit `php.ini`. |
| Agent shows Offline | On that PC run `agent.py status` and `agent.py check`; read `agent\data\logs\agent.log`. |
| "Windows could not decrypt the device credential" | The agent runs under a different Windows user than the one who enrolled it. Enroll again as that user. |

---

## Project layout

| Path | Contents |
| --- | --- |
| `START_MALICIOUSPROJECT.bat`, `STOP_MALICIOUSPROJECT.bat` | Server start/stop |
| `router.php` | Built-in server router (blocks private files) |
| `database/` | `malwareguard.sql` base schema and `migrations/` |
| `database_setup.php` | Applies the schema and pending migrations |
| `api/agent.php`, `api/health.php` | Agent API and health check |
| `admin/devices.php` | Devices, tokens, file events, agent scans |
| `admin/`, `super_admin/` | Admin scan activity; super-admin users, logs, admins |
| `includes/bootstrap.php` | PDO connection, settings, rate limits, audit log |
| `includes/scan_engine.php` | Static analysis, VirusTotal lookup and cache, classification |
| `includes/devices.php` | Device status rules |
| `upload.php`, `results.php`, `history.php`, `scan.php`, `dashboard.php` | User scanning pages |
| `agent/` | Python agent and its batch files |
| `tools/` | Preflight checks and server process scripts |

---

## Test status

Tested on Linux with PHP 8.3, MariaDB 10.11 (MySQL-compatible) and Python 3.13, with the agent and server on the same machine and over a private address. **Not yet tested on Windows.**

| # | Check | Result |
| --- | --- | --- |
| 1 | Server starts from `START_MALICIOUSPROJECT.bat` | Not yet tested (Windows only). `tools/preflight.php`, `database_setup.php` and the server command it runs were tested. |
| 2 | PHP connects to MySQL | Passed |
| 3 | Existing schema preserved | Passed: base tables unchanged, migration only adds; re-running and "already applied in Workbench" both handled |
| 4 | Valid token registers a device | Passed (token generated on the dashboard) |
| 5 | Invalid, expired, reused or revoked token rejected | Passed |
| 6 | Authenticated heartbeats | Passed; wrong credential rejected and shown as *Authentication failed* |
| 7 | Disconnected device turns Offline | Passed (after 90 s) |
| 8 | File creation → event (incl. browser-style `.crdownload` rename) | Passed |
| 9 | Deletion, modification and rename → events | Passed |
| 10 | Events on dashboard and in MySQL, with filters | Passed |
| 11 | Admin requests a scan; agent uploads; result stored | Passed; also auto-scan mode |
| 12 | Results reflect real evidence | Passed for static rules. VirusTotal: parsing, cache and classification tested with cached records; **a live VirusTotal call was not tested** (no network access to VirusTotal in the test environment), but the "unreachable" path was. |
| 13 | API and network failures handled | Passed: server down, connection refused, VirusTotal unreachable, scan outside approved folders, missing file |
| 14 | Queued events delivered after reconnect, no duplicates | Passed |
| 15 | Stop script leaves other processes alone | Not yet tested (Windows only). PID + start-time + command-line checks are implemented; the agent's stop-file mechanism and single-instance guard were tested. |
| – | DPAPI credential encryption, `{DOWNLOADS}` folder lookup, scheduled task | Not yet tested (Windows only) |
| – | User registration with email code, login rate limit, credential rotation, revocation | Passed |
