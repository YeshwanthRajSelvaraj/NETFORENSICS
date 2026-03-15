"""
NetForensics — Threat Intelligence Service v3
================================================
External threat intelligence integration:
  • Tor node list synchronization
  • IP reputation lookup (VirusTotal, AbuseIPDB, OTX stubs)
  • STIX/TAXII feed consumer (interface)
  • IOC matching engine
  • Threat intel caching
"""

import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

logger = logging.getLogger("netforensics.threat_intel")


@dataclass
class ThreatIndicator:
    ioc_type: str       # "ip", "domain", "ja3", "url"
    value: str
    source: str         # "tor_project", "virustotal", "abuseipdb", "otx", "custom"
    threat_type: str    # "c2", "malware", "tor", "phishing", "spam", "scanner"
    confidence: int     # 0-100
    severity: str       # "critical", "high", "medium", "low", "info"
    first_seen: float = 0.0
    last_seen: float = 0.0
    tags: List[str] = field(default_factory=list)
    reference: str = ""


class ThreatIntelService:
    """
    Threat intelligence service with local IOC database.
    In production, integrates with external APIs via aiohttp.
    """

    def __init__(self):
        self._indicators: Dict[str, ThreatIndicator] = {}
        self._ip_index: Dict[str, str] = {}       # IP → indicator key
        self._domain_index: Dict[str, str] = {}    # domain → indicator key
        self._ja3_index: Dict[str, str] = {}       # JA3 → indicator key
        self._last_update: float = 0
        self._load_builtin()

    def _load_builtin(self):
        """Load built-in threat intelligence."""
        # Known malicious IP ranges (sample)
        bad_ips = [
            ("185.220.101.1", "tor", "Tor exit node"),
            ("185.220.101.15", "tor", "Tor exit node"),
            ("185.220.101.33", "tor", "Tor exit node"),
            ("45.153.160.130", "tor", "Tor exit node"),
            ("209.141.58.146", "scanner", "Known scanner"),
            ("193.32.162.1", "c2", "Known C2 infrastructure"),
            ("45.142.213.1", "malware", "Bulletproof hosting"),
        ]
        for ip, ttype, desc in bad_ips:
            self.add_indicator(ThreatIndicator(
                ioc_type="ip", value=ip, source="builtin",
                threat_type=ttype, confidence=80, severity="high",
                tags=[ttype], reference=desc))

        # Known malicious domains (sample)
        bad_domains = [
            ("evil.com", "c2", "Known C2 domain"),
            ("malware-c2.net", "c2", "C2 infrastructure"),
            ("phishing-site.xyz", "phishing", "Phishing domain"),
        ]
        for domain, ttype, desc in bad_domains:
            self.add_indicator(ThreatIndicator(
                ioc_type="domain", value=domain, source="builtin",
                threat_type=ttype, confidence=90, severity="critical",
                tags=[ttype], reference=desc))

        # Known malware JA3 hashes
        mal_ja3 = [
            ("e7d705a3286e19ea42f587b344ee6865", "Cobalt Strike"),
            ("6734f37431670b3ab4292b8f60f29984", "Metasploit Meterpreter"),
            ("a0e9f5d64349fb13191bc781f81f42e1", "Metasploit stager"),
            ("de9f2c7fd25e1b3afad3e85a0226823f", "TrickBot / Emotet"),
            ("e7eca2baf4458d095b7f45da28c16c34", "Dridex"),
        ]
        for ja3hash, malware in mal_ja3:
            self.add_indicator(ThreatIndicator(
                ioc_type="ja3", value=ja3hash, source="builtin",
                threat_type="malware", confidence=95, severity="critical",
                tags=["malware", malware.lower().replace(" ", "_")],
                reference=malware))

        logger.info("Threat intel loaded: %d indicators", len(self._indicators))

    def add_indicator(self, indicator: ThreatIndicator):
        key = f"{indicator.ioc_type}:{indicator.value}"
        indicator.first_seen = indicator.first_seen or time.time()
        indicator.last_seen = time.time()
        self._indicators[key] = indicator

        if indicator.ioc_type == "ip":
            self._ip_index[indicator.value] = key
        elif indicator.ioc_type == "domain":
            self._domain_index[indicator.value] = key
        elif indicator.ioc_type == "ja3":
            self._ja3_index[indicator.value] = key

    def lookup_ip(self, ip: str) -> Optional[ThreatIndicator]:
        key = self._ip_index.get(ip)
        return self._indicators.get(key) if key else None

    def lookup_domain(self, domain: str) -> Optional[ThreatIndicator]:
        key = self._domain_index.get(domain)
        if key:
            return self._indicators.get(key)
        # Check parent domains
        parts = domain.split(".")
        for i in range(1, len(parts)):
            parent = ".".join(parts[i:])
            key = self._domain_index.get(parent)
            if key:
                return self._indicators.get(key)
        return None

    def lookup_ja3(self, ja3: str) -> Optional[ThreatIndicator]:
        key = self._ja3_index.get(ja3)
        return self._indicators.get(key) if key else None

    def enrich_flows(self, flows: List[dict]) -> List[dict]:
        """Enrich flows with threat intelligence."""
        enriched = []
        for f in flows:
            intel = {}
            src_match = self.lookup_ip(f.get("src_ip", ""))
            dst_match = self.lookup_ip(f.get("dst_ip", ""))
            sni_match = self.lookup_domain(f.get("sni", "")) if f.get("sni") else None
            ja3_match = self.lookup_ja3(f.get("ja3", "")) if f.get("ja3") else None

            if src_match:
                intel["src_threat"] = {
                    "type": src_match.threat_type,
                    "severity": src_match.severity,
                    "source": src_match.source,
                    "reference": src_match.reference,
                }
            if dst_match:
                intel["dst_threat"] = {
                    "type": dst_match.threat_type,
                    "severity": dst_match.severity,
                    "source": dst_match.source,
                    "reference": dst_match.reference,
                }
            if sni_match:
                intel["domain_threat"] = {
                    "type": sni_match.threat_type,
                    "severity": sni_match.severity,
                    "domain": f.get("sni"),
                }
            if ja3_match:
                intel["ja3_threat"] = {
                    "type": ja3_match.threat_type,
                    "severity": ja3_match.severity,
                    "malware": ja3_match.reference,
                }

            if intel:
                enriched.append({**f, "threat_intel": intel})

        return enriched

    def match_iocs(self, flows: List[dict], packets: List[dict]) -> dict:
        """Bulk IOC matching against captured traffic."""
        matches = {"ip_matches": [], "domain_matches": [],
                   "ja3_matches": [], "total_matches": 0}

        seen_ips = set()
        seen_domains = set()
        seen_ja3 = set()

        for f in flows:
            for ip_field in ["src_ip", "dst_ip"]:
                ip = f.get(ip_field, "")
                if ip and ip not in seen_ips:
                    seen_ips.add(ip)
                    match = self.lookup_ip(ip)
                    if match:
                        matches["ip_matches"].append({
                            "ip": ip, "threat_type": match.threat_type,
                            "severity": match.severity, "source": match.source,
                            "reference": match.reference,
                        })

            sni = f.get("sni", "")
            if sni and sni not in seen_domains:
                seen_domains.add(sni)
                match = self.lookup_domain(sni)
                if match:
                    matches["domain_matches"].append({
                        "domain": sni, "threat_type": match.threat_type,
                        "severity": match.severity, "reference": match.reference,
                    })

            ja3 = f.get("ja3", "")
            if ja3 and ja3 not in seen_ja3:
                seen_ja3.add(ja3)
                match = self.lookup_ja3(ja3)
                if match:
                    matches["ja3_matches"].append({
                        "ja3": ja3, "malware": match.reference,
                        "severity": match.severity,
                    })

        matches["total_matches"] = (len(matches["ip_matches"]) +
                                    len(matches["domain_matches"]) +
                                    len(matches["ja3_matches"]))
        return matches

    def get_stats(self) -> dict:
        type_counts = defaultdict(int)
        for ind in self._indicators.values():
            type_counts[ind.ioc_type] += 1
        return {
            "total_indicators": len(self._indicators),
            "by_type": dict(type_counts),
            "last_update": self._last_update,
        }
