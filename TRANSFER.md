# Move MalwareGuard from the Laptop to a Server PC

This guide moves the whole system from your **laptop** to a **PC that will be the server** from now on, and gives that PC a **fixed IP address on the router** so the monitored computers can always find it.

Five parts, in order:

1. [On the laptop: prepare the files](#part-1-on-the-laptop-prepare-the-files)
2. [On the server PC: install and import](#part-2-on-the-server-pc-install-and-import)
3. [On the router: give the server PC a fixed IP](#part-3-on-the-router-give-the-server-pc-a-fixed-ip)
4. [On the server PC: keep it reachable](#part-4-on-the-server-pc-keep-it-reachable)
5. [On each monitored PC: reconnect the agent](#part-5-on-each-monitored-pc-reconnect-the-agent)

> The new server starts as a **brand-new system with your same logins**: no old file events, scans or computers. Each monitored PC is added again with a new token (Part 5).

---

## Part 1: On the laptop: prepare the files

**1. Get the latest code** (Command Prompt or VS Code terminal):
```bat
cd C:\xampp1\htdocs\MaliciousProject
git pull
```

**2. Make sure XAMPP's Apache and MySQL are running**, then create the transfer database file:
```bat
C:\xampp1\php\php.exe tools\export_for_transfer.php
```
It lists the accounts it kept and creates:
```
C:\xampp1\htdocs\MaliciousProject\database\maliciousproject_xampp.sql
```

**3. Copy the whole `MaliciousProject` folder to a USB stick.** Check that these are included:

| Must be on the USB | Why |
| --- | --- |
| `MaliciousProject\` (the whole folder) | the system itself |
| `MaliciousProject\.env` | database and email settings (hidden file; turn on *View → Show → Hidden items* to see it) |
| `MaliciousProject\vendor\` | PHP packages (or run `composer install` on the new PC) |
| `MaliciousProject\database\maliciousproject_xampp.sql` | your accounts + empty system |

Use a USB stick, **not** Google Drive or GitHub: the `.sql` file holds password hashes, and Windows blocks `.bat` files that came from the internet.

---

## Part 2: On the server PC: install and import

**1. Install XAMPP** from <https://www.apachefriends.org> into `C:\xampp` (keep Apache, MySQL, PHP, phpMyAdmin ticked).

**2. If this PC has MySQL Server (MySQL80) installed, stop it**, because it uses the same port as XAMPP's MySQL:
`Win + R` → `services.msc` → **MySQL80** → right-click **Stop** → **Properties** → *Startup type*: **Disabled**.

**3. Copy the folder** from the USB to:
```
C:\xampp\htdocs\MaliciousProject
```

**4. Check `.env`** (`C:\xampp\htdocs\MaliciousProject\.env`, open with Notepad). For XAMPP it must say:
```env
DB_HOST=127.0.0.1
DB_PORT=3306
DB_NAME=malwareguard
DB_USER=root
DB_PASS=
```

**5. Start XAMPP:** open `C:\xampp\xampp-control.exe` → **Start** next to **Apache** and **MySQL** (both turn green). If Windows Firewall asks about Apache, tick **Private networks** → **Allow**.

**6. Import the database:** open <http://localhost/phpmyadmin> → **Import** → **Choose File** → `C:\xampp\htdocs\MaliciousProject\database\maliciousproject_xampp.sql` → **Import**. A green message confirms it.

**7. Test on the server PC:**
- <http://localhost/MaliciousProject/api/health.php> shows `"ok":true`
- <http://localhost/MaliciousProject/admin/login.html> → sign in with the **same email and password** as on the laptop

If `health.php` says the database is unavailable, MySQL isn't started or `.env` is wrong (step 4).

---

## Part 3: On the router: give the server PC a fixed IP

Monitored PCs connect to the server by its IP address. Routers hand out addresses automatically and can change them after a restart, which would make every PC go Offline. A **DHCP reservation** tells the router to always give the server PC the same address.

> Use an **Ethernet cable** between the server PC and the router if you can. It's more reliable than Wi-Fi, and Wi-Fi and cable have different MAC addresses, so the reservation must match the one you use.

**1. Find the server PC's details.** On the server PC, open Command Prompt:
```bat
ipconfig /all
```
Under the adapter you use (**Ethernet adapter** for cable, **Wireless LAN adapter Wi-Fi** for Wi-Fi), write down:

| Line | Example | What it is |
| --- | --- | --- |
| **Physical Address** | `A4-5E-60-12-34-56` | the MAC address (identifies the PC) |
| **IPv4 Address** | `192.168.0.103` | its current IP |
| **Default Gateway** | `192.168.1.1` | the router's address |

**2. Open the router's settings.** In a browser on any PC connected to it, go to the **Default Gateway** address, e.g. `http://192.168.0.1`. Sign in with the router's admin username and password. These are usually printed on a sticker on the router; ask your ISP or network admin if they were changed.

**3. Find the DHCP reservation page.** The name depends on the router:

| Router (examples) | Where to look |
| --- | --- |
| TP-Link | **DHCP → Address Reservation** (or *Advanced → Network → DHCP Server → Address Reservation*) |
| PLDT Fibr / Huawei / ZTE | **LAN → DHCP Server → Static IP / DHCP Binding / Reserved IP** |
| Converge / Globe / others | look for **DHCP Static Lease**, **Address Reservation**, **IP-MAC Binding** or **Static DHCP** |

**4. Add a reservation:**
- **MAC address:** the server's **Physical Address** from step 1 (some routers want `:` instead of `-`, e.g. `A4:5E:60:12:34:56`)
- **IP address:** the address the server should always get. The simplest choice is the one it has now (e.g. `192.168.0.103`), or pick an easy one in the same range, such as `192.168.0.103`
- **Save / Apply**

**5. Make the server pick up the address.** On the server PC, in Command Prompt **as Administrator**:
```bat
ipconfig /release
ipconfig /renew
ipconfig
```
(or just restart the PC). The **IPv4 Address** must now be the reserved one. **This is your server address from now on**, for example:
```
http://192.168.0.103/MaliciousProject
```

**No access to the router?** Ask the network admin to reserve an IP for the server PC's MAC address. As a last resort you can set a static IP in Windows (*Settings → Network & internet → Ethernet → IP assignment → Edit → Manual*), using an address **outside** the router's automatic range plus the same gateway and DNS. A reservation on the router is safer because it can't clash with another device.

---

## Part 4: On the server PC: keep it reachable

**1. Allow other PCs through the firewall** (once). Right-click Start → **Terminal (Admin)**:
```powershell
New-NetFirewallRule -DisplayName "MalwareGuard Apache" -Direction Inbound -Protocol TCP -LocalPort 80 -Action Allow -Profile Private
```
and set the network to **Private**: *Settings → Network & internet → Ethernet (or Wi-Fi) → your network → Private network*.

**2. Start Apache and MySQL automatically when the PC turns on.** Open XAMPP Control Panel **as Administrator** (right-click → *Run as administrator*) and tick the **Svc** box next to **Apache** and next to **MySQL** (confirm with **Yes**). They now run as Windows services, so the server works even before anyone signs in.

**3. Don't let the server sleep:** *Settings → System → Power → Screen and sleep* → **When plugged in, put my device to sleep after: Never**.

**4. Test from another PC** on the same network, in a browser:
```
http://192.168.0.103/MaliciousProject/api/health.php
```
It must show `"ok":true`. If it doesn't load, recheck step 1 and that both PCs are on the same router.

---

## Part 5: On each monitored PC: reconnect the agent

The new server has no registered computers, so each PC joins again **once** with a new token. After that, auto-start keeps it connected.

**1. On the server dashboard:** open `http://192.168.0.103/MaliciousProject/admin/login.html` → **Add a computer** → type the PC's name → **Generate token** → copy it.

**2. On the monitored PC**, in its `agent` folder:
1. Run **`STOP_AGENT.bat`**.
2. Delete the **`data`** folder (it belongs to the old server).
3. Run **`INSTALL_AGENT.bat`** and enter:
   - **Server address:** `http://192.168.0.103/MaliciousProject` (your reserved IP from Part 3)
   - **Token:** the token from step 1
   - **Start automatically?** press Enter (Yes)

**3. Check the dashboard:** the PC shows **Online** under **Computers**. Create or download a file on it; it appears under **File events** within a few seconds.

Repeat Part 5 for every monitored PC.

> To save typing on new PCs: in the server's project folder, edit `agent\INSTALL_AGENT.bat` and change the `DEFAULT_SERVER=` line at the top to your new address, e.g. `set "DEFAULT_SERVER=http://192.168.0.103/MaliciousProject"`. Then copy the `agent` folder (without `.venv` and `data`) to each PC; at the address question just press Enter.

---

## Final checklist

- [ ] `http://localhost/MaliciousProject/api/health.php` shows `"ok":true` on the server
- [ ] You can sign in with your old email and password
- [ ] `ipconfig` on the server shows the reserved IP, also after a restart
- [ ] Another PC can open `http://RESERVED-IP/MaliciousProject/api/health.php`
- [ ] Apache and MySQL start by themselves after the server restarts (Svc boxes ticked)
- [ ] Each monitored PC shows **Online** and its file activity appears

## Troubleshooting

| Problem | Fix |
| --- | --- |
| MySQL won't start in XAMPP ("port 3306 in use") | MySQL80 is still running: stop and disable it (Part 2, step 2). |
| Apache won't start ("port 80 in use") | Another program uses port 80 (IIS, Skype, VMware). Close it, or change Apache's port and add it to every address (`http://IP:8080/MaliciousProject`). |
| "The database is unavailable" | MySQL not started, or `.env` not set to `root` with an empty password. |
| Can't sign in with the old password | The import used a different file. Re-run Part 1 step 2 on the laptop and import that file, or reset with `C:\xampp\php\php.exe reset_account.php`. |
| The server's IP changed after a restart | The reservation uses the wrong MAC (Wi-Fi vs cable) or wasn't saved. Redo Part 3 with the adapter you actually use. |
| PC stays Offline | On that PC run `.venv\Scripts\python.exe agent.py check` in the agent folder. The address must be `http://RESERVED-IP/MaliciousProject` (no `:8000`). |
| `.bat` blocked by "Smart App Control" | The files came from the internet. Copy them by USB instead, or run `Get-ChildItem -Recurse \| Unblock-File` in PowerShell inside the agent folder. |

After everything works on the server PC, you can stop XAMPP on the laptop. Keep the laptop's copy until you're sure nothing is missing.
