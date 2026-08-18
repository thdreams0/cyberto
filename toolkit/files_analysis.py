"""
files_analysis.py - File & Static Malware-Triage Utilities
==============================================================
Hashing, file-type identification, metadata extraction, YARA rule
scanning, and hash-based threat-intel lookups (VirusTotal / MalwareBazaar,
if the user supplies API keys).

NOTE: This module performs static, read-only analysis only. It does not
execute, detonate, or sandbox files - dynamic sandboxing requires an
isolated environment outside the scope of this toolkit.
"""

import hashlib
import mimetypes
import os
import struct
from typing import Dict, List, Optional

import requests

try:
    import yara  # yara-python
    HAVE_YARA = True
except ImportError:
    HAVE_YARA = False


def hash_file(path: str) -> Dict[str, str]:
    """Compute MD5, SHA-1 and SHA-256 for a file."""
    md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return {"path": path, "md5": md5.hexdigest(), "sha1": sha1.hexdigest(),
            "sha256": sha256.hexdigest(), "size_bytes": os.path.getsize(path)}


MAGIC_SIGNATURES = [
    (b"\x4D\x5A", "PE executable (Windows .exe/.dll)"),
    (b"\x7fELF", "ELF executable (Linux)"),
    (b"%PDF", "PDF document"),
    (b"PK\x03\x04", "ZIP archive (also docx/xlsx/pptx/jar/apk)"),
    (b"\x89PNG", "PNG image"),
    (b"\xFF\xD8\xFF", "JPEG image"),
    (b"GIF8", "GIF image"),
    (b"Rar!", "RAR archive"),
    (b"\x1F\x8B", "GZIP archive"),
    (b"#!", "Script with shebang"),
]


def identify_file_type(path: str) -> Dict:
    """Identify file type via magic-byte signature (does not trust extension)."""
    with open(path, "rb") as f:
        header = f.read(16)

    matched = next((desc for sig, desc in MAGIC_SIGNATURES if header.startswith(sig)), None)
    guessed_mime, _ = mimetypes.guess_type(path)
    ext = os.path.splitext(path)[1]

    mismatch_warning = None
    if matched and ext:
        # crude sanity check: exe/elf with a "safe" looking extension is suspicious
        if "executable" in matched.lower() and ext.lower() in (
                ".jpg", ".png", ".pdf", ".txt", ".doc", ".docx", ".mp3", ".mp4"):
            mismatch_warning = (
                f"File has extension '{ext}' but magic bytes indicate {matched}. "
                "Possible extension spoofing / disguised executable."
            )

    return {
        "path": path,
        "magic_match": matched or "unknown (no signature matched)",
        "guessed_mime_type": guessed_mime,
        "extension": ext,
        "mismatch_warning": mismatch_warning,
    }


def extract_basic_metadata(path: str) -> Dict:
    """
    Lightweight, dependency-free metadata extraction. For rich metadata
    (EXIF, PDF author/producer, Office document properties) install and
    use exiftool or a library such as Pillow / pypdf as needed.
    """
    stat = os.stat(path)
    info = {
        "path": path,
        "size_bytes": stat.st_size,
        "modified": stat.st_mtime,
        "created": getattr(stat, "st_birthtime", stat.st_ctime),
        "permissions_octal": oct(stat.st_mode)[-3:],
    }
    with open(path, "rb") as f:
        header = f.read(8)
    if header.startswith(b"\x89PNG"):
        with open(path, "rb") as f:
            f.seek(16)
            width, height = struct.unpack(">II", f.read(8))
        info["image_dimensions"] = f"{width}x{height}"
    return info


def scan_with_yara(path: str, rules_path: str) -> Dict:
    """
    Compile a YARA rules file/directory and scan a target file.
    Requires the optional 'yara-python' package (pip install yara-python).
    """
    if not HAVE_YARA:
        return {"error": "yara-python is not installed. Run: pip install yara-python"}
    try:
        rules = yara.compile(filepath=rules_path)
        matches = rules.match(path)
        return {
            "path": path,
            "rules_file": rules_path,
            "matches": [{"rule": m.rule, "tags": m.tags,
                         "strings": [str(s) for s in m.strings]} for m in matches],
        }
    except yara.Error as exc:
        return {"error": str(exc)}


DEFAULT_YARA_RULES = r"""
rule Suspicious_Base64_PowerShell
{
    meta:
        description = "Detects base64-encoded PowerShell often used in droppers"
    strings:
        $s1 = "-enc " nocase
        $s2 = "-EncodedCommand" nocase
        $s3 = "FromBase64String" nocase
    condition:
        any of them
}

rule Suspicious_Macro_AutoOpen
{
    meta:
        description = "Detects Office macro auto-execution keywords"
    strings:
        $a = "AutoOpen" nocase
        $b = "Document_Open" nocase
        $c = "Shell(" nocase
    condition:
        2 of them
}

rule EICAR_Test_File
{
    meta:
        description = "Standard antivirus test string (EICAR)"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}
"""


def write_default_yara_ruleset(dest_path: str) -> str:
    with open(dest_path, "w") as f:
        f.write(DEFAULT_YARA_RULES)
    return dest_path


def check_hash_virustotal(file_hash: str, api_key: str, timeout: int = 15) -> Dict:
    """Look up a hash against VirusTotal (requires a free/paid API key)."""
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}
    try:
        resp = requests.get(url, headers=headers, timeout=timeout)
        if resp.status_code == 404:
            return {"hash": file_hash, "found": False}
        resp.raise_for_status()
        data = resp.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return {"hash": file_hash, "found": True, "analysis_stats": stats}
    except requests.RequestException as exc:
        return {"hash": file_hash, "error": str(exc)}


def check_hash_malwarebazaar(file_hash: str, timeout: int = 15) -> Dict:
    """Look up a hash against abuse.ch MalwareBazaar (free, no API key needed)."""
    url = "https://mb-api.abuse.ch/api/v1/"
    try:
        resp = requests.post(url, data={"query": "get_info", "hash": file_hash}, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
        return {"hash": file_hash, "query_status": data.get("query_status"),
                "data": data.get("data")}
    except requests.RequestException as exc:
        return {"hash": file_hash, "error": str(exc)}
