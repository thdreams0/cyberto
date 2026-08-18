#!/usr/bin/env python3
"""
Cyber Security Toolkit - CLI
================================
A modular command-line toolkit covering:
  - Reconnaissance & asset inventory
  - Vulnerability analysis
  - Web/API security testing
  - File / static malware triage
  - Cryptography & IAM auditing
  - Report generation

IMPORTANT: Only use against systems and networks you own or are
explicitly authorized to test. Unauthorized scanning of third-party
systems may be illegal in your jurisdiction.

Usage examples:
  python main.py discover-hosts 192.168.1.0/24
  python main.py scan-ports 192.168.1.97 --ports 22,80,443
  python main.py tls-cert example.com
  python main.py subdomains example.com --crtsh
  python main.py fingerprint https://example.com
  python main.py cve-lookup "openssh 8.2"
  python main.py check-deps requirements.txt
  python main.py ssh-audit /etc/ssh/sshd_config
  python main.py http-headers https://example.com
  python main.py tls-audit example.com
  python main.py cors-check https://example.com/api
  python main.py owasp-check https://example.com
  python main.py hash-file /path/to/file
  python main.py identify-file /path/to/file
  python main.py yara-scan /path/to/file --rules rules.yar
  python main.py cert-audit /path/to/cert.pem
  python main.py password-check "MyP@ssw0rd123"
  python main.py mfa-checklist
  python main.py creds-audit
"""

import argparse
import json
import sys

from toolkit import recon, vuln, web_security, files_analysis, crypto_iam, report


def out(data):
    print(json.dumps(data, indent=2, default=str))


def main():
    p = argparse.ArgumentParser(description="Cyber Security Toolkit")
    sub = p.add_subparsers(dest="command", required=True)

    # --- Recon ---
    s = sub.add_parser("discover-hosts", help="Ping-sweep a CIDR range")
    s.add_argument("cidr")

    s = sub.add_parser("scan-ports", help="TCP port scan a host")
    s.add_argument("ip")
    s.add_argument("--ports", help="comma-separated ports (default: common ports)")

    s = sub.add_parser("tls-cert", help="Fetch TLS certificate info")
    s.add_argument("host")
    s.add_argument("--port", type=int, default=443)

    s = sub.add_parser("subdomains", help="Enumerate subdomains")
    s.add_argument("domain")
    s.add_argument("--crtsh", action="store_true", help="also query crt.sh")

    s = sub.add_parser("fingerprint", help="Fingerprint web technologies")
    s.add_argument("url")

    s = sub.add_parser("resolve", help="Resolve a domain to IP(s), with ISP/geolocation and optional ping")
    s.add_argument("domain")
    s.add_argument("--ping", action="store_true", help="also ping the first resolved IP")
    s.add_argument("--count", type=int, default=4, help="number of ping packets (default: 4)")
    s.add_argument("--no-geo", action="store_true", help="skip ISP/geolocation lookup")

    # --- Vulnerability ---
    s = sub.add_parser("cve-lookup", help="Search CVEs by keyword")
    s.add_argument("keyword")

    s = sub.add_parser("check-deps", help="Check requirements.txt for known vulns")
    s.add_argument("path")

    s = sub.add_parser("apt-outdated", help="List upgradable apt packages")

    s = sub.add_parser("ssh-audit", help="Audit sshd_config for insecure settings")
    s.add_argument("path", nargs="?", default="/etc/ssh/sshd_config")

    # --- Web/API security ---
    s = sub.add_parser("http-headers", help="Analyze HTTP security headers")
    s.add_argument("url")

    s = sub.add_parser("tls-audit", help="Audit TLS versions/ciphers")
    s.add_argument("host")
    s.add_argument("--port", type=int, default=443)

    s = sub.add_parser("cors-check", help="Check CORS policy")
    s.add_argument("url")

    s = sub.add_parser("owasp-check", help="Run aggregate OWASP-style checks")
    s.add_argument("url")

    # --- Files / malware triage ---
    s = sub.add_parser("hash-file", help="Compute MD5/SHA1/SHA256 for a file")
    s.add_argument("path")

    s = sub.add_parser("identify-file", help="Identify file type via magic bytes")
    s.add_argument("path")

    s = sub.add_parser("file-metadata", help="Extract basic file metadata")
    s.add_argument("path")

    s = sub.add_parser("yara-scan", help="Scan a file with YARA rules")
    s.add_argument("path")
    s.add_argument("--rules", help="path to .yar rules file (default: built-in sample rules)")

    s = sub.add_parser("hash-lookup", help="Check a hash against MalwareBazaar")
    s.add_argument("file_hash")

    # --- Crypto / IAM ---
    s = sub.add_parser("cert-audit", help="Audit a local certificate file")
    s.add_argument("path")

    s = sub.add_parser("password-check", help="Audit a single password's strength")
    s.add_argument("password")

    s = sub.add_parser("mfa-checklist", help="Print the MFA coverage checklist")

    s = sub.add_parser("creds-audit", help="Check common local credential file permissions")

    args = p.parse_args()

    if args.command == "discover-hosts":
        out([h.__dict__ for h in recon.discover_hosts(args.cidr)])

    elif args.command == "scan-ports":
        ports = [int(x) for x in args.ports.split(",")] if args.ports else None
        out(recon.scan_ports(args.ip, ports).__dict__)

    elif args.command == "tls-cert":
        out(recon.get_tls_certificate(args.host, args.port))

    elif args.command == "subdomains":
        result = {"bruteforce": recon.enumerate_subdomains(args.domain)}
        if args.crtsh:
            result["crtsh"] = recon.subdomains_from_crtsh(args.domain)
        out(result)

    elif args.command == "fingerprint":
        out(recon.fingerprint_web_tech(args.url))

    elif args.command == "resolve":
        ips = recon.resolve_domain(args.domain)
        result = {"domain": args.domain, "ips": ips}
        if ips and not args.no_geo:
            result["geolocation"] = recon.lookup_ip_geolocation(ips[0])
        if args.ping and ips:
            result["ping"] = recon.ping_ip(ips[0], args.count)
        out(result)

    elif args.command == "cve-lookup":
        out(vuln.lookup_cve(args.keyword))

    elif args.command == "check-deps":
        packages = vuln.parse_requirements_txt(args.path)
        out(vuln.check_dependencies(packages))

    elif args.command == "apt-outdated":
        out(vuln.check_outdated_apt_packages())

    elif args.command == "ssh-audit":
        out(vuln.audit_sshd_config(args.path))

    elif args.command == "http-headers":
        out(web_security.analyze_http_headers(args.url))

    elif args.command == "tls-audit":
        out(web_security.audit_tls(args.host, args.port))

    elif args.command == "cors-check":
        out(web_security.check_cors(args.url))

    elif args.command == "owasp-check":
        out(web_security.owasp_quick_checklist(args.url))

    elif args.command == "hash-file":
        out(files_analysis.hash_file(args.path))

    elif args.command == "identify-file":
        out(files_analysis.identify_file_type(args.path))

    elif args.command == "file-metadata":
        out(files_analysis.extract_basic_metadata(args.path))

    elif args.command == "yara-scan":
        rules_path = args.rules
        if not rules_path:
            rules_path = "/tmp/default_rules.yar"
            files_analysis.write_default_yara_ruleset(rules_path)
        out(files_analysis.scan_with_yara(args.path, rules_path))

    elif args.command == "hash-lookup":
        out(files_analysis.check_hash_malwarebazaar(args.file_hash))

    elif args.command == "cert-audit":
        out(crypto_iam.audit_local_certificate(args.path))

    elif args.command == "password-check":
        out(crypto_iam.audit_password(args.password))

    elif args.command == "mfa-checklist":
        print("MFA Coverage Self-Assessment Checklist:\n")
        for i, item in enumerate(crypto_iam.MFA_CHECKLIST_ITEMS, 1):
            print(f"  [{i}] {item}")

    elif args.command == "creds-audit":
        out(crypto_iam.audit_common_credential_files())


if __name__ == "__main__":
    sys.exit(main())
