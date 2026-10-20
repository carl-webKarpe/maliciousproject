# Run MalwareGuard on XAMPP

This moves MalwareGuard from **PHP's built-in server + MySQL80 (MySQL Workbench)** to **XAMPP** (Apache + MariaDB + phpMyAdmin). Your existing data can come along.

| | Before | With XAMPP |
| --- | --- | --- |
| Web server | `START_MALICIOUSPROJECT.bat` | XAMPP Control Panel → **Apache** |
| Database | MySQL80 service (MySQL Workbench) | XAMPP Control Panel → **MySQL** (phpMyAdmin) |
| Dashboard address | `http://IP:8000/` | `http://IP/maliciousproject/` |
| Agent server address | `http://IP:8000` | `http://IP/maliciousproject` |

> Do Part 2 (export your data) **before** stopping MySQL80, or skip it to start with an empty database.

---

## Part 1: Install XAMPP

1. Download XAMPP for Windows (PHP 8.1 or newer) from <https://www.apachefriends.org> and install it to `C:\xampp` (keep **Apache**, **MySQL**, **PHP** and **phpMyAdmin** ticked).
2. Don't start anything yet.

## Part 2: Export your current data (optional, keeps your accounts, computers and scans)

1. Open **MySQL Workbench** → connect to **Local instance MySQL80**.
2. Menu **Server → Data Export**.
3. Tick the **malwareguard** schema.
4. Choose **Export to Self-Contained File**, for example `C:\Users\USER\Desktop\malwareguard.sql`, and tick **Include Create Schema**.
5. Click **Start Export**.

## Part 3: Stop MySQL80 (frees port 3306 for XAMPP)

Both databases use port 3306, so only one can run.

1. `Win + R` → `services.msc` → **MySQL80** → right-click → **Stop**.
2. Right-click **MySQL80** → **Properties** → *Startup type*: **Manual** → OK. (It won't start with Windows any more. You can switch back any time.)

## Part 4: Put the project in XAMPP

Copy your whole project folder into `C:\xampp\htdocs\` and name it **`maliciousproject`**:

```
C:\xampp\htdocs\maliciousproject\
    .env              ← copy this too (it is not in Git)
    .htaccess         ← protects .env and private folders under Apache
    vendor\           ← copy this too (or run composer install)
    admin\  api\  agent\  ...
```

If `vendor` is missing, open Command Prompt in that folder and run `composer install`.

> If you work with Git, you can instead clone the project straight into `C:\xampp\htdocs\maliciousproject`, then copy your `.env` into it and run `composer install`.

## Part 5: Start XAMPP

1. Open **XAMPP Control Panel** (`C:\xampp\xampp-control.exe`).
2. Click **Start** next to **Apache** and **MySQL**. Both turn green.
   - If Windows Firewall asks about Apache, tick **Private networks** and allow.

## Part 6: Point `.env` at XAMPP's database

Open `C:\xampp\htdocs\maliciousproject\.env` in Notepad and set (XAMPP's default user is `root` with an **empty** password):

```env
DB_HOST=127.0.0.1
DB_PORT=3306
DB_NAME=malwareguard
DB_USER=root
DB_PASS=
```

`APP_HOST` and `APP_PORT` are not used with XAMPP; Apache decides the address.

## Part 7: Create the database

**Option A: import your data from Part 2**

1. Convert the export (MySQL Workbench files use MySQL 8 settings that XAMPP's MariaDB rejects):
   ```bat
   cd C:\xampp\htdocs\maliciousproject
   C:\xampp\php\php.exe tools\convert_dump_for_xampp.php C:\Users\USER\Desktop\malwareguard.sql
   ```
   This creates `malwareguard-xampp.sql` next to the original.
2. Import it. Either:
   - open <http://localhost/phpmyadmin> → **Import** → choose `malwareguard-xampp.sql` → **Import**, or
   - run: `C:\xampp\mysql\bin\mysql.exe -u root < C:\Users\USER\Desktop\malwareguard-xampp.sql`
3. Then make sure the schema is complete:
   ```bat
   C:\xampp\php\php.exe database_setup.php
   ```

**Option B: start with an empty database**

```bat
cd C:\xampp\htdocs\maliciousproject
C:\xampp\php\php.exe database_setup.php
C:\xampp\php\php.exe reset_account.php
```

`reset_account.php` creates your admin (choose 1) or super admin (choose 2).

## Part 8: Open the dashboard

- Admin: <http://localhost/maliciousproject/admin/login.html>
- Users: <http://localhost/maliciousproject/>

Check: <http://localhost/maliciousproject/api/health.php> shows `"ok":true`.

## Part 9: Connect the agents

1. On the server, run `ipconfig` and note the **IPv4 Address** (e.g. `192.168.1.87`).
2. The agent server address is now **`http://192.168.1.87/maliciousproject`** (no `:8000`). The **Add a computer** page shows it for you.
3. **Computers already installed:** open `agent\data\agent_config.json` on each one, change
   ```json
   "server_url": "http://192.168.1.87/maliciousproject",
   ```
   then `STOP_AGENT.bat` and `START_AGENT.bat`. No new token needed.
4. **New computers:** run `INSTALL_AGENT.bat` and type that address.
5. Firewall (once, **Terminal (Admin)** on the server), if other PCs can't open the dashboard:
   ```powershell
   New-NetFirewallRule -DisplayName "MalwareGuard Apache" -Direction Inbound -Protocol TCP -LocalPort 80 -Action Allow -Profile Private
   ```

## Everyday use

| Task | How |
| --- | --- |
| Start | XAMPP Control Panel → **Start** Apache and MySQL |
| Stop | XAMPP Control Panel → **Stop** both |
| Manage the database | <http://localhost/phpmyadmin> |
| Reset a password | `C:\xampp\php\php.exe reset_account.php` |
| New network or IP | Only the agents' `server_url` changes (Part 9, step 3) |

You no longer need `START_MALICIOUSPROJECT.bat` / `STOP_MALICIOUSPROJECT.bat`.

## Troubleshooting

| Problem | Fix |
| --- | --- |
| MySQL won't start in XAMPP ("port 3306 in use") | MySQL80 is still running. Stop it (Part 3). |
| Apache won't start ("port 80 in use") | Another program uses port 80 (IIS, Skype, VMware). Close it, or in XAMPP click **Config → httpd.conf**, change `Listen 80` to `Listen 8080`, and use `http://IP:8080/maliciousproject` everywhere. |
| Page says "The database is unavailable" | MySQL isn't started in XAMPP, or `DB_USER`/`DB_PASS` in `.env` are wrong. |
| Import error "Unknown collation utf8mb4_0900_ai_ci" | You imported the original export. Convert it first (Part 7, Option A step 1). |
| You can open `http://IP/maliciousproject/.env` in a browser | The `.htaccess` file is missing from the project folder. Copy it in. |
| Uploads over 40 MB fail | `.htaccess` raises the limit; if it still fails, edit `C:\xampp\php\php.ini`: `upload_max_filesize=55M`, `post_max_size=60M`, then restart Apache. |
| Agent: "Connection refused" | Apache isn't started, or the address still has `:8000`. |

> XAMPP's MySQL `root` account has no password by default. That is acceptable on a closed lab network; otherwise set one in phpMyAdmin (**User accounts → root → Change password**) and put it in `DB_PASS`.
