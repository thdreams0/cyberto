# Cyber Security Toolkit

A modular Python CLI toolkit for defensive security work on infrastructure

> **Authorization notice:** Only scan/test hosts and networks you own or
> have explicit written permission to test. Unauthorized scanning of
> third-party systems can be illegal.

## Install

```bash
pip install -r requirements.txt --break-system-packages
```

`yara-python` is optional; the `yara-scan` command degrades gracefully
(with a clear error message) if it isn't installed.

## Modules

| File | Category | Covers |
|---|---|---|
| `toolkit/recon.py` | Reconnaissance & Inventory | host/device discovery, port scanning, service banners, subdomain enum (bruteforce + crt.sh), TLS certificate lookup, web tech fingerprinting |
| `toolkit/vuln.py` | Vulnerability Analysis | CVE lookup (NVD), dependency vuln check (OSV), outdated apt packages, sshd_config audit, risky-port flagging, severity prioritization |
| `toolkit/web_security.py` | Web/API Security | HTTP security headers, cookie flags, CORS policy, TLS/cipher audit, basic auth-endpoint / OWASP checks |
| `toolkit/files_analysis.py` | File / Static Malware Triage | MD5/SHA1/SHA256 hashing, magic-byte file typing (spoofed-extension detection), basic metadata, YARA scanning (with sample rules), MalwareBazaar/VirusTotal hash lookups |
| `toolkit/crypto_iam.py` | Crypto & IAM | generic hashing, local certificate audit (expiry/key size/sig algo), password strength scoring, password-policy-document review, MFA coverage self-assessment, local credential file permission checks |
| `toolkit/report.py` | Reporting | aggregates any findings dict into a JSON file and a styled, self-contained HTML report |

## CLI usage

```bash
python main.py discover-hosts 192.168.1.0/24
python main.py scan-ports 192.168.1.97 --ports 22,80,443
python main.py tls-cert example.com
python main.py subdomains example.com --crtsh
python main.py fingerprint https://example.com
python main.py resolve github.com                     # inclui ISP/cidade/região/país
python main.py resolve github.com --ping --count 4
python main.py resolve github.com --no-geo             # resolve rápido, sem geolocalização
python main.py cve-lookup "openssh 8.2"
python main.py check-deps requirements.txt
python main.py apt-outdated
python main.py ssh-audit /etc/ssh/sshd_config
python main.py http-headers https://example.com
python main.py tls-audit example.com
python main.py cors-check https://example.com/api
python main.py owasp-check https://example.com
python main.py hash-file /path/to/file
python main.py identify-file /path/to/file
python main.py file-metadata /path/to/file
python main.py yara-scan /path/to/file --rules rules.yar
python main.py hash-lookup <sha256>
python main.py cert-audit /path/to/cert.pem
python main.py password-check "MyP@ssw0rd123"
python main.py mfa-checklist
python main.py creds-audit
```

## Programmatic report generation

```python
from toolkit import recon, vuln, report

hosts = recon.discover_hosts("192.168.1.0/24")
port_results = [recon.scan_ports(h.ip) for h in hosts]
risky = [vuln.flag_risky_ports(pr.open_ports) for pr in port_results]

report.generate_html_report({
    "Host Discovery": [h.__dict__ for h in hosts],
    "Port Scans": [pr.__dict__ for pr in port_results],
    "Risky Ports": risky,
}, out_path="home_network_report.html")
```

## Scope notes / what is intentionally NOT included

- No exploit code or automated exploitation of discovered vulnerabilities.
- No dynamic malware sandboxing/detonation (static triage only). For
  dynamic analysis, use a dedicated isolated sandbox (e.g. an offline VM).
- MFA/IAM "audits" for cloud providers (AWS/Azure/GCP) are provided as a
  self-assessment questionnaire, not a live API integration - wiring
  those up requires your own cloud credentials and IAM read permissions
  (e.g. via `boto3` for AWS `iam:Get*`/`iam:List*` calls) and is a
  natural next step once you tell me which provider you use.


