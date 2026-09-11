---
title: "Building an AI-Assisted Purple Team Lab — Part 1: Environment Setup"
date: 2026-09-11 10:00:00 +0100
categories: [Personal Projects, AI-Assisted Purple Team]
tags: [active-directory, goad, virtualbox, vagrant, ansible, ai, cybersecurity, soc, pentesting]
---

> **🚧 Project status: In progress.**
> This post documents the project as it's being built, so some sections will be updated, expanded, or corrected as I go. Consider this a living writeup rather than a finished retrospective.
{: .prompt-warning }

## Objective

As part of preparing for my *alternance* search, I wanted a personal project that goes beyond the usual box-by-box writeups I already post here from THM/HTB. The goal: build an **AI-assisted purple team lab** that combines two things I care about — offensive Active Directory security, and practical, hands-on use of LLMs in a security engineering context (not as a gimmick, but as an actual functional component of the tooling).

The project is split into two connected phases:

| Phase | Focus | Status |
|---|---|---|
| **Phase 1** | Automated AD recon + attack chain, with an LLM-based attack-path advisor | 🔧 In progress — lab environment set up |
| **Phase 2** | SIEM + AI-based SOC alert triage (true positive / false positive classification) | ⏳ Not started |

This post covers the **environment setup** stage of Phase 1: getting a vulnerable Active Directory lab running locally, which turned out to be its own small project in the debugging sense.

## Why this project

Most student cybersecurity portfolios fall into one of two buckets: CTF writeups, or a basic web app. I wanted something that demonstrates:

- Actual offensive AD knowledge (not just "I ran a tool")
- The ability to build and debug real infrastructure, not just follow a tutorial
- A genuine, functional use of AI in a security workflow — using an LLM to reason over recon data and suggest attack paths, and later, to triage SOC alerts
- Enough engineering maturity to document scope, limitations, and safety considerations properly

## Tools chosen, and why

| Tool | Purpose | Why this one |
|---|---|---|
| [GOAD](https://github.com/Orange-Cyberdefense/GOAD) (MINILAB variant) | Vulnerable Active Directory lab | Purpose-built for AD attack practice, actively maintained, realistic misconfigurations instead of contrived CTF logic |
| VirtualBox | Hypervisor | Free, already familiar with it from coursework, sufficient for a local lab of this size |
| Vagrant | VM provisioning automation | Required by GOAD to declaratively spin up lab machines |
| Ansible | Configuration management | Used internally by GOAD to configure the domain, users, and intentional vulnerabilities |
| Kali Linux (cloned VM) | Attacker machine | Standard offensive toolkit, kept as a dedicated clone separate from my main Kali VM (see below) |
| Python | Orchestration / automation layer | Language I'm most comfortable with; will wrap recon tools and handle the LLM API calls |
| Claude / OpenAI API *(planned)* | Attack-path reasoning, later SOC alert triage | Practical LLM integration via simple prompt-in/JSON-out API calls — no model training required |

## Lab environment: design decisions

### Isolating the lab from my personal Kali VM

My existing Kali VM has coursework data on it, so instead of reusing it directly, I **cloned it** in VirtualBox (full clone, new hardware UUID, reinitialized MAC address) and dedicated the clone entirely to this project. This keeps my original environment untouched and lets me snapshot/roll back the attack VM freely without any risk to unrelated files.

The lab itself runs on an isolated VirtualBox network, separate from my host and home network, to avoid any accidental exposure of intentionally vulnerable machines.

> All testing in this project is performed exclusively against a self-hosted, isolated vulnerable AD lab (GOAD). No third-party systems are involved at any point.
{: .prompt-info }

### Choosing GOAD-Light / MINILAB over full GOAD

Full GOAD recommends around 24GB of RAM, GOAD-Light around 20GB. My laptop has 16GB total. Rather than fight that constraint, I opted for **MINILAB** — GOAD's lightest variant (2 VMs: one domain controller, one workstation), recommended around 16GB. This trades away cross-forest and some advanced ADCS/relay scenarios for a setup that actually fits my hardware. I plan to revisit full GOAD or GOAD-Light later, possibly on a temporary cloud VM, once the core pipeline (recon automation → AI attack-path advisor → SOC triage) is working end-to-end.

| Lab variant | VMs | Approx. RAM needed | Chosen? |
|---|---|---|---|
| GOAD (full) | 5 (2 forests, 3 domains) | ~24 GB | No |
| GOAD-Light | 3 | ~20 GB | No |
| **MINILAB** | **2** | **~16 GB** | **✅ Yes** |

*(Screenshot placeholder: VirtualBox Manager showing DC01, WS01, and PROVISIONING VMs)*

## Setup process and difficulties encountered

Getting from "clone the repo" to "lab successfully provisioned" was not a smooth straight line, and honestly, working through the issues was as valuable as the end result — this is the kind of debugging a recruiter should actually care about.

### 1. Windows host: Hyper-V vs VirtualBox conflict

My host machine is Windows 11. VirtualBox and Windows' built-in Hyper-V (often silently enabled via WSL2, Docker Desktop, or Core Isolation / Memory Integrity) compete for low-level virtualization access, which can cause VirtualBox VMs to fail to start or run significantly slower.

**Fix:** confirmed via `bcdedit /enum` that Hyper-V wasn't set to auto-launch, then double-checked and disabled "Virtual Machine Platform" and Memory Integrity under Windows Security to be safe.

```powershell
bcdedit /enum
```

### 2. WSL/Debian install path not needed

GOAD's official Windows install guide suggests installing Debian via WSL to run its installer script. Partway through, this hit a WSL error:

```
WslRegisterDistribution failed with error: 0x80370114
```

Rather than fixing this, I realized the guide has a **WSL-free path** specifically for local VirtualBox/VMware installs — installing Python and Git directly on Windows instead. Since I wasn't deploying to a cloud provider, WSL wasn't needed at all, which also avoided reintroducing the Hyper-V conflict from step 1.

```powershell
git clone https://github.com/Orange-Cyberdefense/GOAD
cd GOAD/
python -m venv .env
.env\Scripts\activate
pip install -r noansible_requirements.yml
```

### 3. A genuine bug in GOAD's Windows compatibility code

Running `py goad.py -m vm` for the first time threw:

```
TypeError: WindowsCommand.is_in_path() takes 2 positional arguments but 3 were given
```

Tracing this through GOAD's source (`goad/command/windows.py` vs the Linux equivalent) showed that the Windows-specific `is_in_path()` method was missing a `show_log` parameter that the shared `on_ludus()` startup check calls with. This wasn't config-related — it happened regardless of provider, because GOAD's startup instantiates every available provider (including Ludus, which I'm not using) for every lab definition.

**Fix — patched locally:**

```python
# Before
def is_in_path(self, bin_file):
    ...

# After
def is_in_path(self, bin_file, show_log=True):
    command = f'where {bin_file} >nul'
    try:
        subprocess.run(command, shell=True, check=True)
        if show_log:
            Log.success(f'{bin_file} found in PATH')
        return True
    except subprocess.CalledProcessError as e:
        if show_log:
            Log.error(f'{bin_file} not found in PATH')
        return False
```

*(Screenshot placeholder: terminal output before/after the patch)*

### 4. Config file: provider/lab case sensitivity

The generated `goad.ini` defaulted to `lab = GOAD` / `provider = vmware`. Editing the file to `lab = goad-light` / `provider = virtualbox` didn't work as expected — GOAD matches lab names against folder names **exactly**, case included. The actual fix was using the exact on-disk casing:

```powershell
py goad.py -l MINILAB -p virtualbox -m vm
```

### 5. Vagrant box downloads and disk placement

Worth flagging for anyone following along on a multi-drive Windows setup: Vagrant's box cache (the large Windows Server / Windows 10 base images) downloads to `C:\Users\<user>\.vagrant.d\boxes\` **by default, regardless of which drive the project itself lives on.** I confirmed available space on C: before letting a ~20% downloaded box continue, since interrupting it would have wasted the progress. For future projects, setting `VAGRANT_HOME` before starting would redirect this to a drive with more headroom.

### 6. RAM pressure causing a provisioning race condition

The first full `install` run got most of the way through — DC01 completed 9/10 provisioning tasks — before failing on WS01 with:

```
ssl: HTTPSConnectionPool(host='192.168.56.31', port=5986): Max retries exceeded with url: /wsman
(Caused by NewConnectionError(... 'No route to host'))
```

Checking VirtualBox directly showed the actual cause: **WS01 had shut down partway through the automated boot sequence**, most likely due to RAM pressure (system sitting at 71–90% usage with three VMs — DC01, WS01, and GOAD's internal Linux "PROVISIONING" jumpbox — running concurrently on 16GB total). This wasn't a configuration error, it was infrastructure flakiness under a tight memory budget.

**Fix:** manually started all three VMs, confirmed each was fully up via `status` in the GOAD console, then re-ran provisioning with:

```
provision_lab
```

Ansible's idempotency meant already-completed tasks were quickly re-verified rather than redone, and the run completed successfully on the second attempt.

*(Screenshot placeholder: final "lab successfully provisioned" output)*

### Summary of issues and fixes

| Issue | Root cause | Resolution |
|---|---|---|
| Debian/WSL install failure | Unnecessary install path for local VirtualBox setup | Switched to native Windows Python/Git install path |
| `is_in_path()` TypeError | Missing parameter in GOAD's Windows-specific code (genuine upstream bug) | Patched `windows.py` locally to accept `show_log` argument |
| Wrong provider/lab loaded | Case-sensitive matching against folder names | Used exact casing (`MINILAB`, `virtualbox`) |
| WS01 unreachable during provisioning | VM shut down mid-boot under RAM pressure | Manually restarted all VMs, re-ran `provision_lab` |

## Current state

The MINILAB environment (DC01 + WS01) is up and fully provisioned. A clean snapshot has been taken immediately after provisioning so the lab can be reverted to a known-good state after each round of testing:

```
snapshot
```

*(Screenshot placeholder: VirtualBox snapshot tree showing the clean baseline)*

## Next steps

- [ ] Confirm connectivity from the dedicated Kali attack VM (same isolated VirtualBox network)
- [ ] First manual recon pass (`nmap`) against the lab, to validate visibility before any automation
- [ ] Manually walk the full AD attack chain once (enumeration → BloodHound → escalation → DCSync) before writing any automation, to make sure the automation reflects real understanding rather than copy-pasted tooling
- [ ] Begin the Python recon/attack orchestration layer
- [ ] First experiment with feeding structured recon data to an LLM for attack-path suggestions

This post will be updated as the project moves into the actual offensive phase. Next writeup will cover the manual attack chain against MINILAB.
