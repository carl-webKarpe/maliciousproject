# MalwareGuard Setup (Quick Guide)

Three parts. Do them in order.

1. **Run the server** (on the main PC)
2. **Install the agent** (on each PC you want to monitor)
3. **See downloaded files** (on the dashboard)

> Only monitor PCs you own or are allowed to monitor.

---

## Part 1: Run the server

Do this on the **main PC**.

**1. Install these (one time):**
- PHP 8.1+ in `C:\php` ([download](https://windows.php.net/download)). In `C:\php\php.ini`, remove the `;` in front of `extension_dir = "ext"` and `extension=curl`, `fileinfo`, `mbstring`, `mysqli`, `openssl`, `pdo_mysql`.
- [Composer](https://getcomposer.org/download/)
- [MySQL Server + MySQL Workbench](https://dev.mysql.com/downloads/installer/)

**2. Get the project (one time):**
```bat
cd C:\
git clone https://github.com/carl-webKarpe/maliciousproject.git
cd maliciousproject
git checkout claude/amazing-pascal-kdv5cx
composer install
```

**3. Create the database user (one time).** In MySQL Workbench, run:
```sql
CREATE DATABASE IF NOT EXISTS malwareguard;
CREATE USER IF NOT EXISTS 'malwareguard_app'@'localhost' IDENTIFIED BY 'MyPassword123!';
GRANT ALL ON malwareguard.* TO 'malwareguard_app'@'localhost';
```

**4. Find your IP.** Run `ipconfig` and note the **IPv4 Address** (example: `192.168.1.10`).

**5. Edit settings.** Copy `.env.example` to `.env`, open it, and change:
```env
APP_HOST=192.168.1.10
DB_USER=malwareguard_app
DB_PASS=MyPassword123!
```

**6. Allow other PCs (one time).** In **PowerShell (Admin)**:
```powershell
New-NetFirewallRule -DisplayName "MalwareGuard" -Direction Inbound -Protocol TCP -LocalPort 8000 -Action Allow -Profile Private
```

**7. Start it.** Double-click **`START_MALICIOUSPROJECT.bat`**.
All lines should say `[OK]`. **Keep the window open.**

**8. Make an admin account (one time).** In MySQL Workbench:
```sql
INSERT INTO malwareguard.users (name, email, password, role, status)
VALUES ('Admin', 'admin@example.com', 'x', 'admin', 'active');
```
Then in the project folder run `php rotate_admin_password.php` and set a password (12+ characters).

✅ Open `http://192.168.1.10:8000/admin/login.html` and sign in.

To stop the server: double-click **`STOP_MALICIOUSPROJECT.bat`**.

---

## Part 2: Install the agent on another PC

Do this for **each PC** you want to monitor.

**1. Get a token.** On the dashboard, go to **Devices**, then **Generate token**. Copy it (it starts with `mg_`, and it works once).

**2. Install Python** on that PC ([download](https://www.python.org/downloads/windows/)). Tick **"Add python.exe to PATH"**.

**3. Copy the `agent` folder** from the project to that PC (for example with a USB stick).

**4. Double-click `INSTALL_AGENT.bat`** and type:
- Server address: `http://192.168.1.10:8000`
- Token: your `mg_...` token
- Start automatically? `y`

✅ On the dashboard's **Devices** page, the PC shows **Online**.

---

## Part 3: See downloaded files

**1.** On the monitored PC, download any file. It goes to the **Downloads** folder.

**2.** On the dashboard, open **Devices**, then **File events**. The file appears within a few seconds.

**3.** Click **Scan**. After about 30 seconds you'll see the result: **Safe, Low, Medium, High** or **Critical**. Click it for details.

✅ Done!

*Optional:* to scan every new download automatically, add `AUTO_SCAN_NEW_FILES=true` to `.env`.

---

## Problems?

| Problem | Fix |
| --- | --- |
| `[FAIL]` when starting | Read the message. Usually MySQL isn't running (`services.msc`, then start **MySQL80**) or `.env` is wrong. |
| PC can't connect | Same network? Correct IP in `APP_HOST`? Firewall rule added (step 6)? |
| Token rejected | It was already used or expired. Generate a new one. |
| PC shows Offline | Open `START_AGENT.bat` on that PC. |

More details: [README.md](README.md)
