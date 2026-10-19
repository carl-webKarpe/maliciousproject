# MalwareGuard Setup Guide

A step-by-step guide from a fresh Windows PC to a working system: a server with a dashboard, plus monitored computers reporting file activity. Work through the steps in order and tick each box as you go.

For deeper explanations (risk levels, security design, production hosting) see [README.md](README.md).

**Two kinds of computers:**

| Role | What runs there | How many |
| --- | --- | --- |
| **Server PC** | PHP web server, MySQL Server, dashboard | One |
| **Monitored PC** | The Python agent | One or more (the server can also be one) |

> Only monitor computers you own or are authorized to monitor, and tell the people who use them.

---

## Part 1: Install software on the server PC

### 1.1 PHP

- [ ] Download the latest **PHP 8.3 VS16 x64 Thread Safe** zip from <https://windows.php.net/download>.
- [ ] Extract it to `C:\php` (so `C:\php\php.exe` exists).
- [ ] Add `C:\php` to PATH: press Start, type **environment variables**, open *Edit the system environment variables* → *Environment Variables…* → under *System variables* select **Path** → *Edit* → *New* → `C:\php` → OK on every window.
- [ ] In `C:\php`, copy `php.ini-development` and rename the copy to `php.ini`.
- [ ] Open `php.ini` in Notepad and make these changes (use Ctrl+F to find each line):
  - `;extension_dir = "ext"` → remove the `;` so it reads `extension_dir = "ext"`
  - Remove the `;` at the start of each of these lines:
    ```ini
    extension=curl
    extension=fileinfo
    extension=mbstring
    extension=mysqli
    extension=openssl
    extension=pdo_mysql
    ```
- [ ] Open a **new** Command Prompt and check:
  ```bat
  php -v
  php -m
  ```
  `php -v` shows the version; `php -m` must list `curl`, `fileinfo`, `mbstring`, `mysqli`, `openssl` and `pdo_mysql`.

### 1.2 Composer

- [ ] Download and run **Composer-Setup.exe** from <https://getcomposer.org/download/>. When it asks for PHP, choose `C:\php\php.exe`.
- [ ] In a new Command Prompt, `composer --version` should print a version.

### 1.3 MySQL Server and MySQL Workbench

- [ ] Download **MySQL Installer for Windows** from <https://dev.mysql.com/downloads/installer/>.
- [ ] Choose **Custom** (or *Developer Default*) and make sure both **MySQL Server 8** and **MySQL Workbench** are selected.
- [ ] During configuration:
  - keep port **3306**;
  - set a strong **root password** and write it down;
  - keep **Configure MySQL Server as a Windows Service** ticked, service name **MySQL80**, *Start at System Startup* ticked.
- [ ] Check the service: press `Win + R`, type `services.msc`, press Enter, find **MySQL80**. Status must say **Running**. If not, right-click → **Start**.

> MySQL Workbench is only the management program. The **MySQL80 service** is the actual database and must be running.

### 1.4 Git (to download and update the project)

- [ ] Install Git from <https://git-scm.com/download/win> (default options are fine).

---

## Part 2: Get the project

- [ ] Open Command Prompt and run:
  ```bat
  cd C:\
  git clone https://github.com/carl-webKarpe/maliciousproject.git
  cd maliciousproject
  git checkout claude/amazing-pascal-kdv5cx
  composer install
  ```
  (If you already have the project, run `git fetch origin`, then `git checkout claude/amazing-pascal-kdv5cx`, then `git pull`, then `composer install`.)
- [ ] Check that a `vendor` folder now exists in `C:\maliciousproject`.

The rest of this guide assumes the project is in `C:\maliciousproject`.

---

## Part 3: Create the database

### 3.1 Create a database account

- [ ] Open **MySQL Workbench** → click the **Local instance MySQL80** tile → enter the root password.
- [ ] In the query tab, paste the following, change `choose-a-long-password` to your own password, then click the **lightning bolt** (Execute):
  ```sql
  CREATE DATABASE IF NOT EXISTS malwareguard CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
  CREATE USER IF NOT EXISTS 'malwareguard_app'@'localhost' IDENTIFIED BY 'choose-a-long-password';
  GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX, REFERENCES ON malwareguard.* TO 'malwareguard_app'@'localhost';
  FLUSH PRIVILEGES;
  ```
- [ ] The *Output* panel at the bottom should show green ticks.

### 3.2 Create the tables

You don't need to do anything here: the start script in Part 5 creates the tables automatically. If you prefer to do it by hand in Workbench:

- [ ] *File → Open SQL Script…* → `C:\maliciousproject\database\malwareguard.sql` → lightning bolt.
- [ ] Repeat for `C:\maliciousproject\database\migrations\001_device_monitoring.sql`.
- [ ] In the *Schemas* panel on the left, right-click → *Refresh All*. Under **malwareguard → Tables** you should see tables such as `users`, `scans`, `endpoint_devices`, `file_events` and `enrollment_tokens`.

---

## Part 4: Configure the project (`.env`)

- [ ] In `C:\maliciousproject`, copy `.env.example` and rename the copy to `.env`.
  (In File Explorer, turn on *View → Show → File name extensions* so you can see the full name.)
- [ ] Open `.env` in Notepad and set at least:
  ```env
  DB_HOST=127.0.0.1
  DB_PORT=3306
  DB_NAME=malwareguard
  DB_USER=malwareguard_app
  DB_PASS=choose-a-long-password
  ```
- [ ] **Optional: email** (needed for user self-registration and super-admin sign-in codes):
  1. On the Gmail account that will send the emails, turn on 2-Step Verification.
  2. Create an **App Password** at <https://myaccount.google.com/apppasswords>.
  3. Set `MAIL_USER=that-account@gmail.com` and `MAIL_PASS=` the 16-letter App Password (no spaces). Never use the normal Gmail password.
- [ ] **Optional: VirusTotal** (stronger results): create a free account at <https://www.virustotal.com>, copy your API key from your profile, and set `VIRUSTOTAL_API_KEY=`. Only file hashes are sent to VirusTotal, never the files.
- [ ] Leave `APP_HOST=127.0.0.1` for now. You'll change it in Part 7 when other PCs need to connect.

> `.env` contains passwords. It is excluded from Git; never upload it or share it.

---

## Part 5: Start the server

- [ ] Double-click **`START_MALICIOUSPROJECT.bat`** in `C:\maliciousproject`.
- [ ] Each check should show `[OK]`:
  ```
  [OK]    Python found (needed only for the agent)
  [OK]    MySQL service running (MySQL80)
  [OK]    PHP 8.3.x
  [OK]    Required PHP extensions are enabled
  [OK]    Composer packages installed
  [OK]    Port 8000 is free on 127.0.0.1
  [OK]    MySQL Server reachable at 127.0.0.1:3306 as 'malwareguard_app'
  Database schema is ready.
  [OK]    MalwareGuard is running (PID ...).
    Dashboard on this PC : http://127.0.0.1:8000/
  ```
  If a line says `[FAIL]`, it tells you what to fix. See [Troubleshooting](#troubleshooting) at the end.
- [ ] Open a browser at **http://127.0.0.1:8000/**. The MalwareGuard home page should load.
- [ ] **Keep this window open** while you use MalwareGuard. Closing it stops the server.

**To stop the server:** press `Ctrl+C` in that window, or double-click **`STOP_MALICIOUSPROJECT.bat`**. Only MalwareGuard's own PHP process is stopped.

---

## Part 6: Create your accounts

There are no default accounts. Do this once, with the server running.

### Option A: Admin account (no email needed, quickest)

- [ ] In MySQL Workbench, run (use your own name and email):
  ```sql
  INSERT INTO malwareguard.users (name, email, password, role, status)
  VALUES ('Lab Admin', 'admin@example.com', 'not-set', 'admin', 'active');
  ```
- [ ] In Command Prompt, in `C:\maliciousproject`, set the real password (12+ characters):
  ```bat
  php rotate_admin_password.php
  ```
  Enter the same email and the new password when asked.
- [ ] Sign in at **http://127.0.0.1:8000/admin/login.html**.

### Option B: Super-admin account (needs Gmail settings from Part 4)

The super admin can manage users and admins. Signing in requires a code emailed to the account.

- [ ] In `.env`, set `SUPER_ADMIN_PASSWORD=` to a strong password (12+ characters).
- [ ] Run:
  ```bat
  php super_admin\create_account.php
  ```
  Enter the super admin's Gmail address and name.
- [ ] Remove the password from `.env` again (leave `SUPER_ADMIN_PASSWORD=` empty).
- [ ] Sign in at **http://127.0.0.1:8000/super_admin/login.html**, then enter the emailed code.
- [ ] Create more admins under **Manage Admins**.

### Regular users

Users register themselves at **http://127.0.0.1:8000/registration.html** and confirm with an emailed code. On the server PC itself the code appears on screen if email isn't configured.

---

## Part 7: Let other PCs reach the server

Skip this part if you only monitor the server PC itself.

### 7.1 Connect the computers

Choose one (Ethernet is the most reliable):

| Network | What to do |
| --- | --- |
| **Ethernet / LAN** | Plug the server and the monitored PCs into the same switch or router. Without a router, give each PC a static IP in the same range, e.g. server `192.168.50.1`, PCs `192.168.50.11`, `.12`…, mask `255.255.255.0`. |
| **Same Wi-Fi** | Connect all PCs to the same Wi-Fi. Guest, school and public Wi-Fi often block PCs from talking to each other ("client isolation"); if so, use Ethernet or a hotspot. |
| **Mobile hotspot** | Connect all PCs to the same phone hotspot. The addresses can change each time; recheck the IP (7.2) whenever you reconnect. |

### 7.2 Find the server's IP address

- [ ] On the server, open Command Prompt and run `ipconfig`.
- [ ] Find the adapter you're using (*Ethernet* or *Wi-Fi*) and note its **IPv4 Address**, e.g. `192.168.1.10`.

### 7.3 Listen on that address

- [ ] Stop the server (`STOP_MALICIOUSPROJECT.bat`).
- [ ] In `.env`, set `APP_HOST=` to the IPv4 address, e.g. `APP_HOST=192.168.1.10`.
- [ ] Start the server again. It now prints a line like:
  ```
  Agents / other PCs   : http://192.168.1.10:8000/
  ```
  That address is the **server address** you'll give the agents.

### 7.4 Allow the port through Windows Firewall (once)

- [ ] Make the network **Private**: Settings → Network & Internet → click your connection → *Network profile type* → **Private**.
- [ ] Right-click Start → **Terminal (Admin)** or **Windows PowerShell (Admin)**, and run:
  ```powershell
  New-NetFirewallRule -DisplayName "MalwareGuard 8000" -Direction Inbound -Protocol TCP -LocalPort 8000 -Action Allow -Profile Private
  ```
- [ ] From another PC on the network, open `http://192.168.1.10:8000/api/health.php` in a browser. You should see `"ok":true`.

---

## Part 8: Register a computer (install the agent)

Repeat this for every computer you want to monitor.

### 8.1 On the dashboard: create a token

- [ ] Sign in as an admin → click **Devices** in the sidebar (or open `http://SERVER-IP:8000/admin/devices.php`).
- [ ] Under **Enrollment tokens**, type a label (e.g. `Lab PC 04`), keep the expiry at 24 hours, and click **Generate token**.
- [ ] Copy the token (it starts with `mg_`). It is shown **only once** and works for **one** computer. If you lose it, revoke it and generate a new one.

### 8.2 On the computer to monitor

- [ ] Install **Python 3** from <https://www.python.org/downloads/windows/>. On the first installer screen, tick **"Add python.exe to PATH"**.
- [ ] Copy the project's **`agent`** folder to the computer, e.g. to `C:\MalwareGuardAgent`. A USB stick works, or clone the project there.
- [ ] Double-click **`INSTALL_AGENT.bat`** in that folder and answer the questions:

  | Question | Answer |
  | --- | --- |
  | Server address | The address from step 7.3, e.g. `http://192.168.1.10:8000` (on the server PC itself: `http://127.0.0.1:8000`) |
  | Enrollment token | The `mg_…` token from 8.1 |
  | Name for this computer | Press Enter for the Windows name, or type one |
  | Start automatically when this user signs in? | `y` for permanent monitoring |
  | Start the agent now? | Press Enter (yes) |

- [ ] The installer runs a connection check. Every line should start with `OK`:
  ```
  OK    TCP port 8000 is reachable
  OK    Server health: MalwareGuard (database ok)
  OK    Authenticated as device ...
  ```
- [ ] A window titled **MalwareGuard agent** opens and shows `Monitoring C:\Users\...\Downloads`.

### 8.3 Check it works

- [ ] On the dashboard's **Devices** page, the computer appears under **Computers** with status **Online** (the page updates every 15 seconds).
- [ ] On the monitored computer, save any file into **Downloads** (or download one).
- [ ] Within a few seconds it appears under **File events** on the Devices page.
- [ ] Click **Scan** next to it. Within about 30 seconds (one heartbeat) the result appears. Click the result to see its full details.

### Which folders are watched?

By default, only the user's **Downloads** folder. To add an approved folder, open `agent\data\agent_config.json` on that computer and edit `watch_directories`, for example:
```json
"watch_directories": ["{DOWNLOADS}", "C:\\LabSamples"],
```
Then restart the agent (`STOP_AGENT.bat`, then `START_AGENT.bat`). Use double backslashes in paths.

---

## Part 9: Everyday use

| Task | How |
| --- | --- |
| Start the server | Make sure MySQL80 is running, then double-click `START_MALICIOUSPROJECT.bat` |
| Stop the server | `Ctrl+C` in its window, or `STOP_MALICIOUSPROJECT.bat` |
| Start an agent | `agent\START_AGENT.bat` (or it starts by itself at sign-in if you chose that) |
| Stop an agent | `agent\STOP_AGENT.bat` |
| Agent status | In the agent folder: `.venv\Scripts\python.exe agent.py status` |
| Test an agent's connection | In the agent folder: `.venv\Scripts\python.exe agent.py check` |
| Scan a file manually | Dashboard → *File Scanner* (upload up to 50 MB) |
| Remove a computer | Devices → **Revoke**; on that computer run `STOP_AGENT.bat` and `schtasks /delete /tn "MalwareGuard Agent" /f` |
| Get a new key for a computer | Devices → **Rotate key** (happens automatically on its next heartbeat) |
| Update the project | Stop the server, run `git pull` and `composer install`, start the server again (new database changes are applied automatically) |

If the server PC restarts: MySQL80 starts by itself, but you must double-click `START_MALICIOUSPROJECT.bat` again. Agents that were offline keep their events and send them once the server is back.

---

## Final checklist

- [ ] `START_MALICIOUSPROJECT.bat` shows only `[OK]` lines.
- [ ] `http://127.0.0.1:8000/` opens on the server.
- [ ] You can sign in as an admin.
- [ ] (Other PCs) `http://SERVER-IP:8000/api/health.php` opens from another PC.
- [ ] A monitored PC shows **Online** on the Devices page.
- [ ] A new file in its Downloads folder appears under **File events**.
- [ ] **Scan** on that event produces a result.
- [ ] After `STOP_AGENT.bat`, the PC turns **Offline** within about 90 seconds.

---

## Troubleshooting

| Message or symptom | Fix |
| --- | --- |
| `PHP was not found` | `C:\php` isn't in PATH (Part 1.1), or open a new Command Prompt after changing PATH. |
| `PHP extension '…' is not enabled` | Edit `C:\php\php.ini` (Part 1.1). Run `php --ini` to see which `php.ini` is being used. |
| `Composer packages are missing` | Run `composer install` in `C:\maliciousproject`. |
| `The MySQL service … is installed but stopped` | `services.msc` → **MySQL80** → Start. |
| `MySQL rejected user …` | `DB_USER` / `DB_PASS` in `.env` don't match Part 3.1. |
| `Cannot listen on …` | The server is already running (run `STOP_MALICIOUSPROJECT.bat`), another program uses port 8000 (change `APP_PORT` in `.env` and in the firewall rule), or `APP_HOST` isn't this PC's current IP (re-run `ipconfig`). |
| `.env` was created, edit it and start again | Normal on first start: complete Part 4. |
| Agent: `Port … refused the connection` | Server not running, wrong port, or `APP_HOST` is still `127.0.0.1` (Part 7.3). |
| Agent: `No answer on port …` | Wrong IP, firewall rule missing or network set to Public (Part 7.4), or Wi-Fi/hotspot client isolation. |
| Agent: `enrollment token is invalid, expired, revoked or already used` | Generate a new token (Part 8.1). Each token works once. |
| Agent: `This device has been revoked` | Generate a new token and run `INSTALL_AGENT.bat` again, answering `y` to enroll again. |
| Agent: `Python 3 was not found` | Reinstall Python with "Add python.exe to PATH" ticked. |
| Device shows **Offline** | On that PC run `agent.py check` and read `agent\data\logs\agent.log`. |
| Super-admin code email never arrives | Check `MAIL_USER` / `MAIL_PASS` (App Password, Part 4) and the spam folder. |

Server logs: `C:\maliciousproject\runtime\server.log`. Agent logs: `agent\data\logs\agent.log` on each computer.
