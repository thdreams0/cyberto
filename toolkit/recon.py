"""
recon.py - Reconnaissance & Asset Inventory
=============================================
Host/device discovery, open port detection, OS/service fingerprinting,
subdomain enumeration, TLS certificate lookup and web technology
fingerprinting.

Intended for use ONLY against hosts/networks you own or are explicitly
authorized to test.
"""

import concurrent.futures
import ipaddress
import socket
import ssl
import subprocess
import datetime
import json
from dataclasses import dataclass, field, asdict
from typing import List, Optional

import requests

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    993, 995, 1723, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 9200, 27017,
]

SERVICE_HINTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCbind", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1723: "PPTP", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8000: "HTTP-alt", 8080: "HTTP-proxy",
    8443: "HTTPS-alt", 9200: "Elasticsearch", 27017: "MongoDB",
}


@dataclass
class HostResult:
    ip: str
    alive: bool
    hostname: Optional[str] = None
    open_ports: List[int] = field(default_factory=list)
    services: dict = field(default_factory=dict)
    banners: dict = field(default_factory=dict)


def ping_host(ip: str, timeout: int = 1) -> bool:
    """Cross-platform single ping check."""
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", str(timeout), ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return result.returncode == 0
    except FileNotFoundError:
        return False


def discover_hosts(cidr: str, max_workers: int = 64) -> List[HostResult]:
    """Sweep a CIDR range (e.g. '192.168.1.0/24') for live hosts."""
    network = ipaddress.ip_network(cidr, strict=False)
    results: List[HostResult] = []

    def check(ip):
        ip_str = str(ip)
        alive = ping_host(ip_str)
        hostname = None
        if alive:
            try:
                hostname = socket.gethostbyaddr(ip_str)[0]
            except (socket.herror, socket.gaierror):
                hostname = None
        return HostResult(ip=ip_str, alive=alive, hostname=hostname)

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        for res in ex.map(check, network.hosts()):
            if res.alive:
                results.append(res)
    return results


def grab_banner(ip: str, port: int, timeout: float = 1.5) -> Optional[str]:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            try:
                s.sendall(b"\r\n")
            except OSError:
                pass
            data = s.recv(256)
            return data.decode(errors="ignore").strip() or None
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


def scan_ports(ip: str, ports: Optional[List[int]] = None,
                timeout: float = 0.6, max_workers: int = 100) -> HostResult:
    """TCP connect scan against a single host, with banner grabbing."""
    ports = ports or COMMON_PORTS
    open_ports: List[int] = []
    services = {}
    banners = {}

    def check_port(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((ip, port)) == 0:
                    return port
        except OSError:
            return None
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        for port, r in zip(ports, ex.map(check_port, ports)):
            if r is not None:
                open_ports.append(r)

    for p in sorted(open_ports):
        services[p] = SERVICE_HINTS.get(p, "unknown")
        banner = grab_banner(ip, p)
        if banner:
            banners[p] = banner

    return HostResult(ip=ip, alive=True, open_ports=sorted(open_ports),
                       services=services, banners=banners)


def resolve_domain(domain: str) -> List[str]:
    """Resolve a domain name to all its known IPv4/IPv6 addresses."""
    infos = socket.getaddrinfo(domain, None)
    ips = []
    for info in infos:
        ip = info[4][0]
        if ip not in ips:
            ips.append(ip)
    return ips


def lookup_ip_geolocation(ip: str, timeout: int = 8) -> dict:
    """
    Look up ISP, city, region and country for an IP address using the
    free ip-api.com endpoint (no API key required, rate-limited to
    ~45 requests/minute). Only works for public IPs, not private/LAN ones.
    """
    if ipaddress.ip_address(ip).is_private:
        return {"ip": ip, "error": "IP privado/local - geolocalização pública não aplicável"}

    url = f"http://ip-api.com/json/{ip}"
    params = {"fields": "status,message,isp,org,city,regionName,country,countryCode,query"}
    try:
        resp = requests.get(url, params=params, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
    except (requests.RequestException, ValueError) as exc:
        return {"ip": ip, "error": str(exc)}

    if data.get("status") != "success":
        return {"ip": ip, "error": data.get("message", "lookup failed")}

    return {
        "ip": data.get("query", ip),
        "isp": data.get("isp"),
        "org": data.get("org"),
        "city": data.get("city"),
        "region": data.get("regionName"),
        "country": data.get("country"),
        "country_code": data.get("countryCode"),
    }


def ping_ip(ip: str, count: int = 4, timeout: int = 1) -> dict:
    """Ping an IP address 'count' times and return a summary of the results."""
    try:
        result = subprocess.run(
            ["ping", "-c", str(count), "-W", str(timeout), ip],
            capture_output=True, text=True,
        )
        return {
            "ip": ip,
            "packets_sent": count,
            "reachable": result.returncode == 0,
            "raw_output": result.stdout.strip(),
        }
    except FileNotFoundError:
        return {"ip": ip, "error": "ping command not found on this system"}


def get_tls_certificate(host: str, port: int = 443, timeout: float = 4.0) -> dict:
    """Fetch and parse the TLS certificate served on host:port."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert(binary_form=False)
            cipher = ssock.cipher()
            tls_version = ssock.version()
    if not cert:
        # some servers only expose cert via binary form; fall back
        return {"host": host, "port": port, "error": "no certificate returned"}

    not_after = cert.get("notAfter")
    expires = None
    days_left = None
    if not_after:
        expires_dt = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        expires = expires_dt.isoformat()
        days_left = (expires_dt - datetime.datetime.utcnow()).days

    return {
        "host": host,
        "port": port,
        "subject": dict(x[0] for x in cert.get("subject", [])),
        "issuer": dict(x[0] for x in cert.get("issuer", [])),
        "not_before": cert.get("notBefore"),
        "not_after": expires,
        "days_until_expiry": days_left,
        "san": cert.get("subjectAltName"),
        "tls_version": tls_version,
        "cipher": cipher[0] if cipher else None,
    }


def enumerate_subdomains(domain: str, wordlist: Optional[List[str]] = None,
                          max_workers: int = 50) -> List[str]:
    """Brute-force common subdomains via DNS resolution."""
    wordlist = wordlist or [
        "www", "mail", "ftp", "api", "dev", "staging", "test", "vpn",
        "admin", "portal", "webmail", "ns1", "ns2", "cdn", "static",
        "blog", "shop", "app", "m", "beta", "git", "docs", "status",
    ]
    found = []

    def resolve(sub):
        fqdn = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(fqdn)
            return fqdn, ip
        except socket.gaierror:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        for r in ex.map(resolve, wordlist):
            if r:
                found.append({"subdomain": r[0], "ip": r[1]})
    return found


def subdomains_from_crtsh(domain: str, timeout: int = 10) -> List[str]:
    """Query crt.sh certificate transparency logs for known subdomains."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        resp = requests.get(url, timeout=timeout)
        resp.raise_for_status()
        entries = resp.json()
    except (requests.RequestException, ValueError):
        return []
    names = set()
    for e in entries:
        for n in e.get("name_value", "").split("\n"):
            n = n.strip().lstrip("*.")
            if n.endswith(domain):
                names.add(n)
    return sorted(names)


def fingerprint_web_tech(url: str, timeout: int = 8) -> dict:
    """Lightweight technology fingerprinting via headers and page content."""
    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=True)
    except requests.RequestException as exc:
        return {"url": url, "error": str(exc)}

    headers = resp.headers
    hints = []
    server = headers.get("Server")
    powered_by = headers.get("X-Powered-By")
    if server:
        hints.append(f"Server header: {server}")
    if powered_by:
        hints.append(f"X-Powered-By: {powered_by}")

    body = resp.text[:20000].lower()
    fingerprints = {
        "WordPress": ["wp-content", "wp-includes"],
        "Drupal": ["drupal.settings", "/sites/default/"],
        "Joomla": ["joomla"],
        "React": ["__react", "data-reactroot"],
        "Vue.js": ["__vue__", "data-v-"],
        "Next.js": ["__next_data__"],
        "Laravel": ["laravel_session"],
        "Django": ["csrfmiddlewaretoken"],
        "jQuery": ["jquery"],
        "Bootstrap": ["bootstrap"],
        "Nginx (page)": ["nginx"],
    }
    detected = [name for name, needles in fingerprints.items()
                if any(n in body for n in needles)]

    cookies_flags = {
        c.name: {"secure": c.secure, "httponly": "httponly" in
                 (c._rest.keys() if hasattr(c, "_rest") else [])}
        for c in resp.cookies
    }

    return {
        "url": url,
        "status_code": resp.status_code,
        "server": server,
        "x_powered_by": powered_by,
        "detected_technologies": detected,
        "cookies": cookies_flags,
        "hints": hints,
    }


def results_to_json(results) -> str:
    def default(o):
        if hasattr(o, "__dataclass_fields__"):
            return asdict(o)
        return str(o)
    return json.dumps(results, default=default, indent=2)
