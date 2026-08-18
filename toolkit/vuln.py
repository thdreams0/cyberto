"""
vuln.py - Vulnerability Analysis
===================================
CVE lookup (NVD API), dependency vulnerability checks (OSV API), basic
insecure-configuration checks, outdated-package detection, and
severity-based prioritization / reporting helpers.
"""

import json
import subprocess
import time
from typing import List, Dict, Optional

import requests

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OSV_API = "https://api.osv.dev/v1/querybatch"

RISKY_OPEN_PORTS = {
    21: "FTP exposed (often plaintext credentials)",
    23: "Telnet exposed (unencrypted remote access)",
    445: "SMB exposed (common ransomware/lateral-movement vector)",
    3389: "RDP exposed to the network (brute-force / exploit target)",
    6379: "Redis exposed (frequently unauthenticated)",
    9200: "Elasticsearch exposed (frequently unauthenticated)",
    27017: "MongoDB exposed (frequently unauthenticated)",
    5900: "VNC exposed (weak default auth common)",
}


def flag_risky_ports(open_ports: List[int]) -> List[Dict]:
    """Flag well-known high-risk services found open during recon."""
    findings = []
    for port in open_ports:
        if port in RISKY_OPEN_PORTS:
            findings.append({
                "port": port,
                "severity": "high" if port in (23, 445, 3389, 6379, 9200, 27017) else "medium",
                "description": RISKY_OPEN_PORTS[port],
            })
    return findings


def lookup_cve(keyword: str, results_limit: int = 10, timeout: int = 15) -> List[Dict]:
    """Search NVD for CVEs matching a keyword (e.g. product/version string)."""
    params = {"keywordSearch": keyword, "resultsPerPage": results_limit}
    try:
        resp = requests.get(NVD_API, params=params, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
    except (requests.RequestException, ValueError) as exc:
        return [{"error": str(exc)}]

    findings = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        descriptions = cve.get("descriptions", [])
        desc_en = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
        metrics = cve.get("metrics", {})
        score = None
        severity = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics:
                m = metrics[key][0]
                score = m.get("cvssData", {}).get("baseScore")
                severity = m.get("cvssData", {}).get("baseSeverity") or m.get("baseSeverity")
                break
        findings.append({
            "cve_id": cve_id,
            "score": score,
            "severity": severity,
            "description": desc_en[:300],
        })
    return findings


def check_dependencies(packages: List[Dict[str, str]], timeout: int = 20) -> List[Dict]:
    """
    Check a list of {"name": ..., "version": ..., "ecosystem": ...} packages
    against the OSV.dev vulnerability database (supports PyPI, npm, Go, etc).
    """
    queries = [
        {"package": {"name": p["name"], "ecosystem": p.get("ecosystem", "PyPI")},
         "version": p.get("version")}
        for p in packages
    ]
    try:
        resp = requests.post(OSV_API, json={"queries": queries}, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
    except (requests.RequestException, ValueError) as exc:
        return [{"error": str(exc)}]

    results = []
    for pkg, res in zip(packages, data.get("results", [])):
        vulns = res.get("vulns", [])
        results.append({
            "package": pkg["name"],
            "version": pkg.get("version"),
            "vulnerabilities": [v.get("id") for v in vulns],
            "count": len(vulns),
        })
    return results


def parse_requirements_txt(path: str) -> List[Dict[str, str]]:
    """Parse a requirements.txt into OSV-ready package dicts (best effort)."""
    packages = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            for sep in ("==", ">=", "<="):
                if sep in line:
                    name, version = line.split(sep, 1)
                    packages.append({"name": name.strip(), "version": version.strip(),
                                      "ecosystem": "PyPI"})
                    break
    return packages


def check_outdated_apt_packages(timeout: int = 30) -> Dict:
    """
    On Debian/Ubuntu systems, list packages with available upgrades.
    Requires apt/apt-get to be present; safe read-only (list only).
    """
    try:
        subprocess.run(["apt-get", "update"], stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL, timeout=timeout, check=False)
        result = subprocess.run(["apt", "list", "--upgradable"],
                                 capture_output=True, text=True, timeout=timeout)
        lines = [l for l in result.stdout.splitlines() if "/" in l and "Listing" not in l]
        return {"upgradable_count": len(lines), "packages": lines}
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return {"error": str(exc)}


INSECURE_SSH_CHECKS = {
    "PermitRootLogin yes": "Root login over SSH should be disabled",
    "PasswordAuthentication yes": "Password auth enabled; prefer key-based auth",
    "Protocol 1": "SSH protocol 1 is obsolete and insecure",
    "PermitEmptyPasswords yes": "Empty passwords must never be permitted",
    "X11Forwarding yes": "X11 forwarding increases attack surface if unused",
}


def audit_sshd_config(path: str = "/etc/ssh/sshd_config") -> List[Dict]:
    """Static check of a local sshd_config for common insecure directives."""
    findings = []
    try:
        with open(path) as f:
            content = f.read()
    except (FileNotFoundError, PermissionError) as exc:
        return [{"error": str(exc)}]

    for directive, warning in INSECURE_SSH_CHECKS.items():
        if directive.lower() in content.lower():
            findings.append({"directive": directive, "severity": "medium", "warning": warning})
    return findings


def prioritize(findings: List[Dict]) -> List[Dict]:
    """Sort findings by severity (critical > high > medium > low > info)."""
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, None: 5}
    return sorted(findings, key=lambda f: order.get(str(f.get("severity")).lower(), 5))
