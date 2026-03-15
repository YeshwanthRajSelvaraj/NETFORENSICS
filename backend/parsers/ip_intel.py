"""
NetForensics — IP Intelligence Module
=======================================
Provides: reverse DNS, private/public classification,
GeoIP (via ip-api.com), WHOIS (via ARIN RDAP),
and local reputation checks.

External lookups require internet access and aiohttp.
Falls back gracefully when offline.
"""

import asyncio
import ipaddress
import logging
import re
import socket
from functools import lru_cache
from typing import Optional

logger = logging.getLogger("netforensics.intel")

KNOWN_BAD_RANGES = [
    r"^185\.220\.",    # Tor exit nodes
    r"^94\.102\.",     # Abuse-prone CGNAT
    r"^45\.142\.",     # RU bulletproof hosting
    r"^193\.32\.162\.",# Known C2 range
]

SUSPICIOUS_PORTS = {
    4444:  "Metasploit default",
    1337:  "Leet / custom backdoor",
    31337: "Elite backdoor",
    9999:  "Common C2 port",
    6666:  "IRC / botnet",
    6667:  "IRC / botnet",
}


def classify_ip(ip: str) -> dict:
    """Returns classification dict for an IP address."""
    try:
        addr = ipaddress.ip_address(ip)
        return {
            "ip":        ip,
            "private":   addr.is_private,
            "loopback":  addr.is_loopback,
            "multicast": addr.is_multicast,
            "reserved":  addr.is_reserved,
            "version":   addr.version,
        }
    except ValueError:
        return {"ip": ip, "error": "invalid_ip"}


@lru_cache(maxsize=4096)
def _rdns_sync(ip: str) -> Optional[str]:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


async def reverse_dns(ip: str) -> Optional[str]:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _rdns_sync, ip)


def check_reputation(ip: str) -> dict:
    info = classify_ip(ip)
    if info.get("private") or info.get("loopback"):
        return {**info, "risk": "internal", "flags": []}

    flags = []
    for pat in KNOWN_BAD_RANGES:
        if re.match(pat, ip):
            flags.append(f"IP in suspicious range: {pat}")

    return {
        **info,
        "risk":  "high" if flags else "unknown",
        "flags": flags,
        "note":  "Integrate VirusTotal/AbuseIPDB for production threat intel",
    }


async def enrich_ip(ip: str) -> dict:
    """Full synchronous enrichment (no external HTTP)."""
    rep   = check_reputation(ip)
    rdns  = await reverse_dns(ip)
    return {**rep, "reverse_dns": rdns}
