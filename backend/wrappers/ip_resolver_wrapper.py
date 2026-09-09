import socket
import ssl
import time
import ipaddress
import hashlib
from datetime import datetime
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

def get_http_session():
    session = requests.Session()
    retry = Retry(
        total=3,
        backoff_factor=0.5,
        status_forcelist=[500, 502, 503, 504]
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    session.headers.update({"User-Agent": "CyberX-Forensics/2.0"})
    return session

def scan_ports_and_latency(ip_str: str, timeout: float = 1.0) -> dict:
    """Scans common forensic ports and measures network RTT latency."""
    common_ports = {
        21: "FTP",
        22: "SSH",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        443: "HTTPS",
        3389: "RDP",
        8080: "HTTP-ALT"
    }
    open_ports = []
    rtt_ms = None

    for port, service in common_ports.items():
        start = time.time()
        s = socket.socket(socket.AF_INET if ":" not in ip_str else socket.AF_INET6, socket.SOCK_STREAM)
        s.settimeout(timeout)
        res = s.connect_ex((ip_str, port))
        elapsed = (time.time() - start) * 1000
        s.close()

        if res == 0:
            open_ports.append({"port": port, "service": service, "latency_ms": round(elapsed, 2)})
            if rtt_ms is None or elapsed < rtt_ms:
                rtt_ms = round(elapsed, 2)

    return {
        "open_ports": open_ports,
        "primary_rtt_ms": rtt_ms
    }

def inspect_ssl_certificate(ip_str: str, port: int = 443, timeout: float = 3.0) -> dict:
    """Fetches SSL/TLS Certificate details if port 443 is active."""
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        s = socket.socket(socket.AF_INET if ":" not in ip_str else socket.AF_INET6, socket.SOCK_STREAM)
        s.settimeout(timeout)
        ssl_sock = context.wrap_socket(s, server_hostname=ip_str)
        ssl_sock.connect((ip_str, port))
        cert = ssl_sock.getpeercert(binary_form=False)
        der_cert = ssl_sock.getpeercert(binary_form=True)
        cipher = ssl_sock.cipher()
        tls_version = ssl_sock.version()
        ssl_sock.close()

        sha256_fp = hashlib.sha256(der_cert).hexdigest() if der_cert else None

        # Extract Subject CN & Issuer CN
        subject = dict(x[0] for x in cert.get("subject", [])) if cert else {}
        issuer = dict(x[0] for x in cert.get("issuer", [])) if cert else {}

        sans = [item[1] for item in cert.get("subjectAltName", [])] if cert else []

        return {
            "ssl_enabled": True,
            "subject_cn": subject.get("commonName"),
            "issuer_cn": issuer.get("commonName"),
            "issuer_org": issuer.get("organizationName"),
            "valid_from": cert.get("notBefore"),
            "valid_to": cert.get("notAfter"),
            "sans": sans[:10],
            "sha256_fingerprint": sha256_fp,
            "tls_version": tls_version,
            "cipher_suite": cipher[0] if cipher else None
        }
    except Exception as e:
        return {"ssl_enabled": False, "error": str(e)}

def fetch_rdap_whois(session, ip_str: str) -> dict:
    """Queries RDAP (HTTPS) for WHOIS, RIR, Network Name, CIDR, and Abuse Contacts."""
    try:
        res = session.get(f"https://rdap.org/ip/{ip_str}", timeout=6)
        if res.status_code == 200:
            data = res.json()
            net = data.get("network", {})
            
            # Find RIR and Abuse Emails
            rir = data.get("port43", "").split(".")[0].upper() if data.get("port43") else net.get("type", "UNKNOWN")
            abuse_emails = []
            
            entities = data.get("entities", [])
            for entity in entities:
                roles = entity.get("roles", [])
                if "abuse" in roles or "technical" in roles:
                    vcard = entity.get("vcardArray", [])
                    if len(vcard) > 1:
                        for entry in vcard[1]:
                            if entry[0] == "email":
                                abuse_emails.append(entry[3])

            cidr_list = []
            if "cidr0_cidrs" in net:
                for c in net["cidr0_cidrs"]:
                    v = f"{c.get('v4prefix') or c.get('v6prefix')}/{c.get('length')}"
                    cidr_list.append(v)

            return {
                "network_name": net.get("name"),
                "handle": net.get("handle"),
                "cidr": cidr_list[0] if cidr_list else net.get("cidr"),
                "cidrs": cidr_list,
                "rir": rir,
                "country": net.get("country"),
                "abuse_emails": list(set(abuse_emails)),
                "start_address": net.get("startAddress"),
                "end_address": net.get("endAddress")
            }
    except Exception:
        pass
    return {}

def resolve_ip(target: str) -> dict:
    """
    Enterprise Forensics IP Resolver (HTTPS, Port Scan, SSL, RDAP, Risk Score).
    """
    results = {}
    session = get_http_session()

    # ── 1. Parse & classify IP ───────────────────────────────────────────────
    try:
        ip_obj = ipaddress.ip_address(target.strip())
        version = ip_obj.version
        ip_str = str(ip_obj)
        results["ip"] = ip_str
        results["version"] = f"IPv{version}"
        results["is_private"] = ip_obj.is_private
        results["is_loopback"] = ip_obj.is_loopback
        results["is_multicast"] = ip_obj.is_multicast
        results["is_link_local"] = ip_obj.is_link_local
        results["is_global"] = ip_obj.is_global
        results["is_reserved"] = ip_obj.is_reserved

        if ip_obj.is_loopback:
            ip_type = "Loopback"
        elif ip_obj.is_link_local:
            ip_type = "Link-Local"
        elif ip_obj.is_multicast:
            ip_type = "Multicast"
        elif ip_obj.is_private:
            ip_type = "Private"
        elif ip_obj.is_reserved:
            ip_type = "Reserved"
        elif ip_obj.is_global:
            ip_type = "Public"
        else:
            ip_type = "Unknown"
        results["ip_type"] = ip_type
        results["compressed"] = ip_obj.compressed
        if version == 6:
            results["expanded"] = ip_obj.exploded
    except ValueError as e:
        return {"error": f"Invalid IP address: {e}", "status": "Failed"}

    # ── 2. Socket addresses & Reverse PTR Verification ───────────────────────
    try:
        addr_info = socket.getaddrinfo(ip_str, None)
        results["socket_addresses"] = list({entry[4][0] for entry in addr_info})
    except Exception:
        results["socket_addresses"] = [ip_str]

    ptr_record = None
    ptr_mismatch = False
    try:
        ptr_record, _, _ = socket.gethostbyaddr(ip_str)
        results["reverse_dns"] = ptr_record

        # Check if PTR resolves back to target IP (anti-spoofing check)
        try:
            back_ips = socket.gethostbyname_ex(ptr_record)[2]
            if ip_str not in back_ips:
                ptr_mismatch = True
        except Exception:
            ptr_mismatch = True
    except Exception:
        results["reverse_dns"] = None

    results["ptr_mismatch"] = ptr_mismatch

    # ── 3. Geolocation & ASN via HTTPS (ipwho.is & ipinfo.io) ──────────────
    geo_data = {}
    try:
        # Provider 1: ipwho.is (HTTPS, free, zero key required)
        res = session.get(f"https://ipwho.is/{ip_str}", timeout=6)
        if res.status_code == 200:
            gw = res.json()
            if gw.get("success"):
                asn_str = gw.get("connection", {}).get("asn", "")
                asn_raw = f"AS{asn_str}" if isinstance(asn_str, int) else str(asn_str)
                asn_org = gw.get("connection", {}).get("org") or gw.get("connection", {}).get("isp", "")

                geo_data = {
                    "country": gw.get("country"),
                    "country_code": gw.get("country_code"),
                    "region": gw.get("region"),
                    "city": gw.get("city"),
                    "latitude": gw.get("latitude"),
                    "longitude": gw.get("longitude"),
                    "timezone": gw.get("timezone", {}).get("id"),
                    "isp": gw.get("connection", {}).get("isp"),
                    "org": gw.get("connection", {}).get("org"),
                    "asn_number": asn_raw,
                    "asn_org": asn_org,
                    "domain": gw.get("connection", {}).get("domain"),
                    "is_proxy": gw.get("security", {}).get("proxy", False) or gw.get("security", {}).get("vpn", False),
                    "is_tor": gw.get("security", {}).get("tor", False),
                    "is_hosting": gw.get("security", {}).get("hosting", False),
                    "bogon": gw.get("security", {}).get("bogon", False),
                }

                if gw.get("latitude") and gw.get("longitude"):
                    geo_data["google_maps_url"] = f"https://www.google.com/maps?q={gw['latitude']},{gw['longitude']}"
    except Exception:
        pass

    # Fallback/supplement via ipinfo.io (HTTPS)
    if not geo_data.get("country"):
        try:
            res = session.get(f"https://ipinfo.io/{ip_str}/json", timeout=6)
            if res.status_code == 200:
                ii = res.json()
                loc = ii.get("loc", "").split(",")
                lat = float(loc[0]) if len(loc) == 2 else None
                lon = float(loc[1]) if len(loc) == 2 else None

                asn_parts = ii.get("org", "").split(" ", 1)
                asn_num = asn_parts[0] if len(asn_parts) > 0 else ""
                asn_org_name = asn_parts[1] if len(asn_parts) > 1 else ""

                geo_data.update({
                    "country": ii.get("country"),
                    "region": ii.get("region"),
                    "city": ii.get("city"),
                    "latitude": lat,
                    "longitude": lon,
                    "timezone": ii.get("timezone"),
                    "org": ii.get("org"),
                    "asn_number": asn_num,
                    "asn_org": asn_org_name,
                    "bogon": ii.get("bogon", False)
                })
                if lat and lon:
                    geo_data["google_maps_url"] = f"https://www.google.com/maps?q={lat},{lon}"
        except Exception:
            pass

    results["geo"] = geo_data

    # ── 4. WHOIS / RDAP & RIR Lookup ─────────────────────────────────────────
    results["whois_rdap"] = fetch_rdap_whois(session, ip_str)

    # ── 5. Open Ports, Latency (RTT) & SSL Inspection (Public IPs only) ──────
    if not ip_obj.is_private and not ip_obj.is_loopback:
        network_scan = scan_ports_and_latency(ip_str)
        results["open_ports"] = network_scan["open_ports"]
        results["rtt_ms"] = network_scan["primary_rtt_ms"]

        # If port 443 is open, inspect SSL certificate
        if any(p["port"] == 443 for p in network_scan["open_ports"]):
            results["ssl_info"] = inspect_ssl_certificate(ip_str)
    else:
        results["open_ports"] = []
        results["rtt_ms"] = 0.0

    # ── 6. Weighted Forensics Risk Calculation ──────────────────────────────
    risk_score = 0
    reasons = []

    if geo_data.get("bogon") or ip_obj.is_reserved:
        risk_score += 100
        reasons.append("Bogon / Reserved IP (should not route on public internet)")

    if geo_data.get("is_tor"):
        risk_score += 60
        reasons.append("Active Tor Exit Node (+60)")

    if geo_data.get("is_proxy"):
        risk_score += 40
        reasons.append("Proxy / VPN endpoint detected (+40)")

    if geo_data.get("is_hosting"):
        risk_score += 25
        reasons.append("Datacenter / Hosting provider ASN (+25)")

    if ptr_mismatch:
        risk_score += 20
        reasons.append("Reverse DNS (PTR) mismatch — hostname does not resolve back to target IP (+20)")

    # Check for sensitive open ports
    open_port_nums = [p["port"] for p in results.get("open_ports", [])]
    if 22 in open_port_nums or 3389 in open_port_nums or 21 in open_port_nums:
        risk_score += 15
        reasons.append(f"Exposed remote management ports open: {[p for p in open_port_nums if p in (22, 3389, 21)]} (+15)")

    if ip_obj.is_private or ip_obj.is_loopback:
        reasons.append("Internal LAN / Loopback address")

    risk_score = min(risk_score, 100)

    if risk_score >= 75:
        risk_level = "CRITICAL"
    elif risk_score >= 50:
        risk_level = "HIGH"
    elif risk_score >= 20:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    results["threat_intelligence"] = {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "confidence": "High" if geo_data.get("asn_number") else "Medium",
        "reasons": reasons if reasons else ["Clean reputation — no active risk indicators detected."]
    }

    results["status"] = "Success"
    return results
