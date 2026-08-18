"""
crypto_iam.py - Cryptography, Certificates & Identity/Access Management
===========================================================================
General-purpose hashing, local certificate auditing, password-policy
strength checks, an MFA-coverage self-assessment checklist, and basic
IAM/config sanity checks (e.g. AWS credentials file permissions).
"""

import datetime
import hashlib
import math
import os
import re
import ssl
from typing import Dict, List, Optional

from cryptography import x509
from cryptography.hazmat.backends import default_backend


def generate_hash(data: str, algorithm: str = "sha256") -> str:
    """Generate a hash of a string using the given algorithm."""
    h = hashlib.new(algorithm)
    h.update(data.encode())
    return h.hexdigest()


def audit_local_certificate(path: str) -> Dict:
    """Parse a local PEM/DER certificate file and report key security facts."""
    with open(path, "rb") as f:
        raw = f.read()
    try:
        cert = x509.load_pem_x509_certificate(raw, default_backend())
    except ValueError:
        cert = x509.load_der_x509_certificate(raw, default_backend())

    now = datetime.datetime.utcnow()
    not_after = cert.not_valid_after
    days_left = (not_after - now).days

    pub_key = cert.public_key()
    key_size = getattr(pub_key, "key_size", None)

    issues = []
    if days_left < 0:
        issues.append("Certificate is EXPIRED")
    elif days_left < 30:
        issues.append(f"Certificate expires soon ({days_left} days)")
    if key_size and key_size < 2048:
        issues.append(f"Weak key size: {key_size} bits (recommend >= 2048)")
    sig_algo = cert.signature_algorithm_oid._name
    if "sha1" in sig_algo.lower() or "md5" in sig_algo.lower():
        issues.append(f"Weak signature algorithm: {sig_algo}")

    return {
        "path": path,
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "not_before": cert.not_valid_before.isoformat(),
        "not_after": not_after.isoformat(),
        "days_until_expiry": days_left,
        "key_size_bits": key_size,
        "signature_algorithm": sig_algo,
        "issues": issues,
    }


# ---------------------------------------------------------------------------
# Password policy auditing
# ---------------------------------------------------------------------------

def estimate_entropy_bits(password: str) -> float:
    """Rough Shannon-style entropy estimate based on character pool size."""
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"[0-9]", password):
        pool += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        pool += 33
    if pool == 0:
        return 0.0
    return round(len(password) * math.log2(pool), 1)


COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "qwerty", "abc123",
    "111111", "123123", "admin", "letmein", "welcome", "iloveyou",
    "monkey", "dragon", "football", "password1", "changeme",
}


def audit_password(password: str, min_length: int = 12) -> Dict:
    """Evaluate a single password against a basic strength policy."""
    issues = []
    if len(password) < min_length:
        issues.append(f"Shorter than recommended minimum ({min_length} chars)")
    if password.lower() in COMMON_PASSWORDS:
        issues.append("Found in common/breached password list")
    if not re.search(r"[A-Z]", password):
        issues.append("Missing uppercase letter")
    if not re.search(r"[a-z]", password):
        issues.append("Missing lowercase letter")
    if not re.search(r"[0-9]", password):
        issues.append("Missing digit")
    if not re.search(r"[^a-zA-Z0-9]", password):
        issues.append("Missing special character")
    if re.search(r"(.)\1{2,}", password):
        issues.append("Contains repeated character sequences")

    entropy = estimate_entropy_bits(password)
    if entropy < 40:
        strength = "weak"
    elif entropy < 60:
        strength = "moderate"
    elif entropy < 80:
        strength = "strong"
    else:
        strength = "very strong"

    return {
        "length": len(password),
        "estimated_entropy_bits": entropy,
        "strength": strength,
        "issues": issues,
    }


def audit_password_policy_document(rules: Dict) -> List[str]:
    """
    Evaluate an organization's *stated* password policy (not a live password)
    against common baseline recommendations (NIST SP 800-63B inspired).
    Expected keys: min_length, require_mfa, max_age_days, lockout_threshold,
    allows_common_passwords_check (bool).
    """
    recs = []
    if rules.get("min_length", 0) < 8:
        recs.append("NIST 800-63B recommends a minimum length of at least 8, "
                     "ideally 12+, over complex composition rules.")
    if rules.get("max_age_days") and rules["max_age_days"] < 9999:
        recs.append("Mandatory periodic password rotation is discouraged by current "
                     "NIST guidance unless there is evidence of compromise; consider "
                     "removing forced expiry in favor of MFA + breach monitoring.")
    if not rules.get("require_mfa", False):
        recs.append("MFA is not required - this is the single highest-impact control "
                     "to add for reducing account-takeover risk.")
    if not rules.get("lockout_threshold"):
        recs.append("No account lockout / rate-limiting threshold defined - "
                     "increases exposure to brute-force and credential-stuffing attacks.")
    if not rules.get("allows_common_passwords_check", False):
        recs.append("Policy does not check against known-breached password lists.")
    return recs


# ---------------------------------------------------------------------------
# MFA coverage self-assessment (questionnaire-style; no live integrations)
# ---------------------------------------------------------------------------

MFA_CHECKLIST_ITEMS = [
    "Is MFA enforced for all privileged/admin accounts?",
    "Is MFA enforced for all standard user accounts?",
    "Is MFA enforced for VPN / remote access?",
    "Is MFA enforced for cloud console access (AWS/Azure/GCP)?",
    "Are phishing-resistant methods (FIDO2/WebAuthn, hardware keys) available?",
    "Is SMS-based OTP avoided as the only second factor for privileged accounts?",
    "Are backup/recovery codes stored securely and their use logged/alerted?",
    "Is there a documented process for MFA reset requests (to prevent social engineering)?",
]


def mfa_self_assessment(answers: Dict[str, bool]) -> Dict:
    """
    answers: dict mapping each MFA_CHECKLIST_ITEMS entry -> True/False.
    Returns a coverage score and the list of gaps.
    """
    total = len(MFA_CHECKLIST_ITEMS)
    answered_yes = sum(1 for item in MFA_CHECKLIST_ITEMS if answers.get(item))
    gaps = [item for item in MFA_CHECKLIST_ITEMS if not answers.get(item)]
    return {
        "score": f"{answered_yes}/{total}",
        "coverage_percent": round(100 * answered_yes / total, 1),
        "gaps": gaps,
    }


# ---------------------------------------------------------------------------
# Basic IAM / local credential hygiene checks
# ---------------------------------------------------------------------------

def audit_file_permissions(path: str, max_mode: str = "600") -> Dict:
    """
    Check that a sensitive file (SSH private key, AWS credentials, .env, etc.)
    is not world/group readable.
    """
    if not os.path.exists(path):
        return {"path": path, "error": "file not found"}
    mode = oct(os.stat(path).st_mode)[-3:]
    issues = []
    if mode > max_mode:
        issues.append(f"Permissions are {mode}; expected {max_mode} or stricter")
    return {"path": path, "current_mode": mode, "issues": issues}


SENSITIVE_PATHS_TO_CHECK = [
    "~/.ssh/id_rsa",
    "~/.ssh/id_ed25519",
    "~/.aws/credentials",
    "~/.kube/config",
    "~/.netrc",
]


def audit_common_credential_files() -> List[Dict]:
    """Sweep well-known local credential file locations for loose permissions."""
    results = []
    for rel_path in SENSITIVE_PATHS_TO_CHECK:
        path = os.path.expanduser(rel_path)
        if os.path.exists(path):
            results.append(audit_file_permissions(path))
    return results
