# MalwareGuard Setup Guide

This guide has three parts. Do them in order.

| Part | Where | Goal |
| --- | --- | --- |
| [**Part 1: Run the server**](#part-1-run-the-server) | Server PC | The dashboard runs and other PCs can reach it |
| [**Part 2: Install the agent on other PCs**](#part-2-install-the-agent-on-other-pcs) | Each PC or laptop to monitor | The PC is registered and shows **Online** |
| [**Part 3: Detect downloaded files**](#part-3-detect-downloaded-files) | Dashboard + monitored PC | New downloads appear on the dashboard and can be scanned |

> Only install the agent on computers you own or are allowed to monitor, and tell the people who use them. The agent only watches the folders you configure (by default **Downloads**). It never opens, runs, deletes or moves files.

```
  Monitored PC (agent)  ──── same network (Ethernet / Wi-Fi / hotspot) ────▶  Server PC (dashboard + MySQL)
  watches Downloads                                                            http://SERVER-IP:8000
```

---

## Part 1: Run the server

Do this on the **server PC** (the computer that will hold the dashboard and the database).

### Step 1.1: Install what the server needs (one time)

| Install | Where to get it | Notes |
| --- | --- | --- |
| **PHP 8.1+** | <https://windows.php.net/download> (VS16 x64 Thread Safe zip) | Extract to `C:\php` and add `C:\php` to PATH |
| **Composer** | <https://getcomposer.org/download/> | Choose `C:\php\php.exe` when asked |
| **MySQL Server 8 + MySQL Workbench** | <https://dev.mysql.com/downloads/installer/> | Keep port 3306, set a root password, keep the **MySQL80** Windows service |
| **Git** | <https://git-scm.com/download/win> | Default options are fine |

**Turn on the PHP extensions:** in `C:\php`, copy `php.ini-development` to `php.ini`, open it in Notepad, and remove the `;` at the start of these lines:

```ini
extension_dir = "ext"
extension=curl
extension=fileinfo
extension=mbstring
extension=mysqli
extension=openssl
extension=pdo_mysql
```

**Check:** open a **new** Command Prompt. `php -v` shows a version, and `php -m` lists `pdo_mysql`, `mysqli`, `curl`, `fileinfo`, `openssl` and `mbstring`.

### Step 1.2: Download the project (one time)

```bat
cd C:\
git clone https://github.com/carl-webKarpe/maliciousproject.git
cd maliciousproject
git checkout claude/amazing-pascal-kdv5cx
composer install
```

The project is now in `C:\maliciousproject`, and it contains a `vendor` folder.

### Step 1.3: Create the database account (one time)

1. Open **MySQL Workbench** → click **Local instance MySQL80** → enter the root password.
2. Paste this, change the password, and click the **lightning bolt** to run it:
   ```sql
   CREATE DATABASE IF NOT EXISTS malwareguard CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
   CREATE USER IF NOT EXISTS 'malwareguard_app'@'localhost' IDENTIFIED BY 'choose-a-long-password';
   GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX, REFERENCES ON malwareguard.* TO 'malwareguard_app'@'localhost';
   FLUSH PRIVILEGES;
   ```

The tables are created automatically the first time you start the server.

### Step 1.4: Find the server's IP address

1. Connect the server to the network the other PCs will use (see the table below).
2. Open Command Prompt and run `ipconfig`.
3. Under your adapter (*Ethernet* or *Wi-Fi*), note the **IPv4 Address**, for example `192.168.1.10`.

| Network | Notes |
| --- | --- |
| **Ethernet / LAN** (best) | Plug all PCs into the same switch or router. Without a router, give each PC a static IP, e.g. server `192.168.50.1`, PCs `192.168.50.11`, `.12`…, mask `255.255.255.0`. |
| **Same Wi-Fi** | All PCs on the same Wi-Fi. Guest or school Wi-Fi may block PCs from reaching each other ("client isolation"). |
| **Mobile hotspot** | All PCs on the same hotspot. The IP can change every time; run `ipconfig` again after reconnecting. |

### Step 1.5: Configure `.env` (one time)

1. In `C:\maliciousproject`, copy `.env.example` and rename the copy to **`.env`**.
2. Open `.env` in Notepad and set:
   ```env
   APP_HOST=192.168.1.10        # the IPv4 address from Step 1.4
   APP_PORT=8000

   DB_HOST=127.0.0.1
   DB_PORT=3306
   DB_NAME=malwareguard
   DB_USER=malwareguard_app
   DB_PASS=choose-a-long-password
   ```
3. Optional: set `VIRUSTOTAL_API_KEY=` (free key from <https://www.virustotal.com>) for stronger scan results. Only file hashes are sent to VirusTotal, never the files.

> `APP_HOST=127.0.0.1` means only the server itself can connect. For other PCs, it must be the server's IPv4 address.

### Step 1.6: Open the firewall (one time)

1. Settings → Network & Internet → click your connection → set **Network profile type** to **Private**.
2. Right-click Start → **Terminal (Admin)** → run:
   ```powershell
   New-NetFirewallRule -DisplayName "MalwareGuard 8000" -Direction Inbound -Protocol TCP -LocalPort 8000 -Action Allow -Profile Private
   ```

### Step 1.7: Start the server

1. Check that MySQL is running: `Win + R` → `services.msc` → **MySQL80** must say **Running** (right-click → Start if not).
2. Double-click **`START_MALICIOUSPROJECT.bat`** in `C:\maliciousproject`.
3. Every line should say `[OK]`, ending with:
   ```
   [OK]    MalwareGuard is running (PID ...).
     Dashboard on this PC : http://192.168.1.10:8000/
     Agents / other PCs   : http://192.168.1.10:8000/   (Ethernet)
   ```
   Write down the **Agents / other PCs** address: this is the **server address** you'll need in Part 2.
4. **Leave this window open.** Closing it stops the server.

If a line says `[FAIL]`, it explains what to fix (see [Troubleshooting](#troubleshooting)).

### Step 1.8: Create an admin account (one time)

1. In MySQL Workbench, run (use your own name and email):
   ```sql
   INSERT INTO malwareguard.users (name, email, password, role, status)
   VALUES ('Lab Admin', 'admin@example.com', 'not-set', 'admin', 'active');
   ```
2. In Command Prompt, in `C:\maliciousproject`, set the password (at least 12 characters):
   ```bat
   php rotate_admin_password.php
   ```
3. Open **http://SERVER-IP:8000/admin/login.html** and sign in.

### Step 1.9: Check that other PCs can reach the server

On any other PC on the same network, open a browser at:

```
http://192.168.1.10:8000/api/health.php
```

You should see `"ok":true`. If the page doesn't load, go back to Steps 1.4–1.6.

**Part 1 is done** when the server window shows `[OK]`, you can sign in, and another PC can open the health page.

### Stopping and restarting the server

- **Stop:** press `Ctrl+C` in the server window, or double-click **`STOP_MALICIOUSPROJECT.bat`**.
- **After the server PC restarts:** MySQL starts by itself; double-click `START_MALICIOUSPROJECT.bat` again. If the IP changed, update `APP_HOST` first.

---

## Part 2: Install the agent on other PCs

Repeat this part for **every PC or laptop** you want to monitor. Each one needs its own token.

### Step 2.1: Create an enrollment token (on the dashboard)

1. Sign in as an admin → click **Devices** in the sidebar (`http://SERVER-IP:8000/admin/devices.php`).
2. Under **Enrollment tokens**, type a label for the PC, e.g. `Lab PC 04`.
3. Click **Generate token**.
4. Copy the token (it starts with `mg_`). It is shown **only once**, works for **one** PC, and expires after 24 hours. If you lose it, click **Revoke** and generate a new one.

The token now shows as **Awaiting registration**.

### Step 2.2: Install Python (on the PC to monitor)

1. Download Python 3 from <https://www.python.org/downloads/windows/>.
2. On the first installer screen, tick **"Add python.exe to PATH"**, then click **Install Now**.

### Step 2.3: Copy the agent folder (on the PC to monitor)

1. From the server's project, copy the **`agent`** folder (`C:\maliciousproject\agent`) to a USB stick.
2. On the PC to monitor, paste it as `C:\MalwareGuardAgent`.

The folder must contain `agent.py`, `requirements.txt`, `INSTALL_AGENT.bat`, `START_AGENT.bat` and `STOP_AGENT.bat`.

### Step 2.4: Run the installer (on the PC to monitor)

1. Double-click **`INSTALL_AGENT.bat`** in `C:\MalwareGuardAgent`.
2. Wait while it installs its dependencies (needs internet the first time).
3. Answer the questions:

   | Question | What to type |
   | --- | --- |
   | `Server address` | The address from Step 1.7, e.g. `http://192.168.1.10:8000` |
   | `Enrollment token` | The `mg_…` token from Step 2.1 |
   | `Name for this computer` | Press Enter to use the Windows PC name, or type a name |
   | `Start the agent automatically when this user signs in?` | `y` (recommended) |
   | `Start the agent now?` | Press Enter |

4. The installer checks the connection. All lines should start with `OK`:
   ```
   OK    TCP port 8000 is reachable
   OK    Server health: MalwareGuard (database ok)
   OK    Authenticated as device 1f0c...
   ```
5. A window titled **MalwareGuard agent** opens and shows:
   ```
   Monitoring C:\Users\<name>\Downloads
   MalwareGuard agent 1.0.0 running as device ...
   ```

### Step 2.5: Confirm the PC is registered (on the dashboard)

1. Go back to **Devices** on the dashboard.
2. Under **Computers**, the new PC appears with:
   - status **Online** (green),
   - its IP address, registration time and last heartbeat,
   - `Watching: C:\Users\<name>\Downloads`.
3. Under **Enrollment tokens**, the token now shows **Used**.

The page refreshes the status by itself every 15 seconds.

**Part 2 is done** when the PC shows **Online**. Repeat Steps 2.1–2.5 for the next PC.

### Managing the agent on a PC

| Task | How |
| --- | --- |
| Start the agent | Double-click `START_AGENT.bat` (it also starts by itself at sign-in if you answered `y`) |
| Stop the agent | Double-click `STOP_AGENT.bat` |
| See its status | In the agent folder: `.venv\Scripts\python.exe agent.py status` |
| Test the connection | In the agent folder: `.venv\Scripts\python.exe agent.py check` |
| Read its log | `C:\MalwareGuardAgent\data\logs\agent.log` |
| Remove it | `STOP_AGENT.bat`, then `schtasks /delete /tn "MalwareGuard Agent" /f`, delete the folder, and click **Revoke** on the dashboard |

---

## Part 3: Detect downloaded files

Once a PC is **Online**, the agent watches its Downloads folder. Nothing else needs to be turned on.

### How detection works

1. A file is downloaded (or saved, or copied) into **Downloads** on the monitored PC.
2. The agent waits until the file stops changing. Browsers first write `.crdownload` or `.part` files; the agent ignores those and waits for the final file.
3. It calculates the file's SHA-256 hash and sends a **file event** to the server: file name, full path, size, hash, time and PC.
4. The event appears on the dashboard within a few seconds.
5. If the server can't be reached, events are saved on the PC and sent when the connection returns, with no duplicates.

"Potential download" means a new file appeared in a watched folder. It is not proof that it came from a browser.

### Step 3.1: Download a test file (on the monitored PC)

1. On the monitored PC, open a browser and download any file, for example a PDF or an image. It goes to **Downloads**.
2. In the **MalwareGuard agent** window you'll see a line like:
   ```
   CREATED C:\Users\<name>\Downloads\report.pdf (sha256 9f2c4a1b7e30...)
   ```

### Step 3.2: See the download on the dashboard

1. On the dashboard, open **Devices** → scroll to **File events** (or click **File events** in the sidebar).
2. The new file appears at the top:

   | Column | Shows |
   | --- | --- |
   | Time | When the file appeared |
   | Computer | Which PC |
   | Event | `Created` + **Potential download** |
   | File | File name, full path and, for browser downloads, the temporary name it was renamed from |
   | Size / SHA-256 | Size and fingerprint of the file |
   | Scan | **Not scanned** + a **Scan** button |

3. To find files quickly, use the filters above the table:
   - **Device:** one PC only
   - **Event:** Created, Modified, Moved or Deleted
   - **Search:** part of a file name, path or hash
   - **Potential downloads only:** tick it to hide everything else

Other activity in Downloads is also recorded: **Modified** (content changed), **Moved** (renamed) and **Deleted**.

### Step 3.3: Scan the downloaded file

1. In **File events**, click **Scan** next to the file.
2. The row shows **Scan pending**. On its next heartbeat (within about 30 seconds) the agent uploads that file to **your** server, which analyses it. Only the hash is sent to VirusTotal.
3. Refresh the page. The **Scan** column now shows a risk badge: **Safe**, **Low**, **Medium**, **High**, **Critical** or **Unknown**.
4. Click the badge to open the full result:
   - file name, path, size and SHA-256
   - computer name and ID
   - risk classification and detection ratio (e.g. `3/70` VirusTotal engines, when available)
   - detection source, findings with evidence, time of analysis
   - **recommended next action**

All scans are also listed under **Agent scans**, with a filter by risk level.

### Step 3.4 (optional): Scan every new download automatically

To scan new downloads without clicking **Scan**:

1. On the server, open `.env` and set:
   ```env
   AUTO_SCAN_NEW_FILES=true
   ```
2. Save. No restart needed. From now on, every new file in a watched folder is uploaded to your server and scanned. **Requested by** shows **Automatic**.

**High** and **Critical** results also appear as alerts in the super-admin dashboard under **Recent Detections**.

### Step 3.5 (optional): Watch more folders

1. On the monitored PC, open `C:\MalwareGuardAgent\data\agent_config.json` in Notepad.
2. Edit `watch_directories` (use double backslashes):
   ```json
   "watch_directories": ["{DOWNLOADS}", "C:\\Users\\Public\\Downloads", "D:\\LabFiles"],
   ```
   `{DOWNLOADS}` means the signed-in user's Downloads folder. Set `"recursive": true` to include subfolders.
3. Restart the agent: `STOP_AGENT.bat`, then `START_AGENT.bat`.
4. The new folders appear under **Watching:** on the Devices page.

Only add folders you are allowed to monitor.

**Part 3 is done** when a file downloaded on the monitored PC shows up under **File events**, and **Scan** produces a result.

### What the risk levels mean

| Level | Meaning | What to do |
| --- | --- | --- |
| **Critical** | Strong signs of malware (e.g. 3+ VirusTotal engines) | Don't open it; disconnect the PC if it was run; investigate |
| **High** | Strong suspicious evidence | Don't open it; check where it came from |
| **Medium** | Suspicious indicators | Review the findings before opening |
| **Low** | Minor indicators only | Confirm the source if unexpected |
| **Safe** | Nothing found by the checks that ran | Not a guarantee; stay careful |
| **Unknown** | The file couldn't be analysed | Scan again later |
| **Not scanned** | No scan yet | Click **Scan** |

MalwareGuard never deletes or runs files. Deciding what to do with a dangerous file is up to you.

---

## Troubleshooting

### Server (Part 1)

| Problem | Fix |
| --- | --- |
| `PHP was not found` | Add `C:\php` to PATH and open a new Command Prompt. |
| `PHP extension '…' is not enabled` | Edit `C:\php\php.ini` (Step 1.1). `php --ini` shows which file is used. |
| `Composer packages are missing` | Run `composer install` in `C:\maliciousproject`. |
| `MySQL service … is stopped` | `services.msc` → **MySQL80** → Start. |
| `MySQL rejected user …` | `DB_USER` / `DB_PASS` in `.env` don't match Step 1.3. |
| `Cannot listen on …` | The server is already running (`STOP_MALICIOUSPROJECT.bat`), or `APP_HOST` isn't the current IP (run `ipconfig` again). |
| `.env` was created, edit it and start again | Normal the first time: do Step 1.5. |

### Agent and connection (Part 2)

| Message | Fix |
| --- | --- |
| `Python 3 was not found` | Reinstall Python with **Add python.exe to PATH** ticked. |
| `Port … refused the connection` | Server not started, wrong port, or `APP_HOST` is still `127.0.0.1`. |
| `No answer on port …` | Wrong IP, firewall rule missing or network set to Public (Step 1.6), or Wi-Fi/hotspot client isolation. Try Ethernet. |
| `different subnets` | The PC and server are on different networks. Connect them to the same one. |
| `enrollment token is invalid, expired, revoked or already used` | Generate a new token (Step 2.1). |
| `This device has been revoked` | Generate a new token and run `INSTALL_AGENT.bat` again; answer `y` to enroll again. |
| PC shows **Offline** | Is the agent window open? Run `agent.py check` on that PC; read `data\logs\agent.log`. |

### Detection (Part 3)

| Problem | Fix |
| --- | --- |
| Download doesn't appear | Check the agent window is running and the file was saved in a folder listed under **Watching** on the Devices page. Check that the PC shows **Online**. |
| File appears without a hash | The file is larger than `max_hash_mb` (200 MB) or was locked; the event is still recorded. |
| Scan stays **pending** | The agent must be running and Online; it picks up scans on its next heartbeat. After 3 unanswered attempts the scan shows **failed**. |
| Scan **failed: file_missing** | The file was moved or deleted before the scan. |
| Scan **failed: too_large** | The file is over 50 MB (`AGENT_MAX_UPLOAD_MB` in `.env`). |
| Detection ratio says "not configured" | Add `VIRUSTOTAL_API_KEY` in `.env` (Step 1.5). Without it, static rules still work. |
| Windows Defender removes a test file first | That's Windows protecting the PC. The agent may record **Created** and then **Deleted**. |

**Logs:** server `C:\maliciousproject\runtime\server.log`, agent `C:\MalwareGuardAgent\data\logs\agent.log`.

For more detail (security design, production hosting, risk rules) see [README.md](README.md).
