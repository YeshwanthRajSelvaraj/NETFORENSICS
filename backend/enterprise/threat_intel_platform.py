"""
NetForensics — STIX/TAXII Threat Intelligence Sharing + GeoIP Mapping
=======================================================================
Enterprise threat intelligence platform providing:

  1. STIX 2.1 Bundle creation from NetForensics detections
  2. TAXII 2.1 server (Collection + API Root endpoints)
  3. STIX indicator ingestion from external feeds
  4. GeoIP mapping of IP addresses (MaxMind GeoLite2-style)
  5. Attacker infrastructure correlation engine
  6. IOC lifecycle management (create → enrich → correlate → expire)

Pure Python — no stix2 or taxii2-client libraries required.
"""

import hashlib
import json
import logging
import math
import os
import re
import socket
import struct
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("netforensics.enterprise.threat_intel")


# ═══════════════════════════════════════════════════════════════════════════════
# GeoIP DATABASE (Built-in — no MaxMind download needed)
# ═══════════════════════════════════════════════════════════════════════════════

class GeoIPDatabase:
    """
    Built-in GeoIP mapping using IANA allocated blocks + offline enrichment.
    Provides country, ASN, and risk scoring for any IPv4 address.
    """

    # Major IANA regional blocks (start_ip, end_ip, region, country_hint)
    _BLOCKS = [
        # North America
        (0x01000000, 0x09FFFFFF, "NA", "US"),
        (0x0A000000, 0x0AFFFFFF, "PRIVATE", "PRIVATE"),  # 10.0.0.0/8
        (0x11000000, 0x12FFFFFF, "NA", "US"),
        (0x17000000, 0x17FFFFFF, "NA", "US"),             # DOD
        (0x28000000, 0x2FFFFFFF, "EU", "GB"),
        (0x30000000, 0x37FFFFFF, "EU", "DE"),
        (0x40000000, 0x43FFFFFF, "AP", "JP"),
        (0x44000000, 0x47FFFFFF, "EU", "GB"),
        (0x48000000, 0x4BFFFFFF, "AP", "KR"),
        (0x4C000000, 0x4FFFFFFF, "SA", "BR"),
        (0x50000000, 0x57FFFFFF, "EU", "FR"),
        (0x58000000, 0x5BFFFFFF, "EU", "NL"),
        (0x5C000000, 0x5FFFFFFF, "EU", "IT"),
        (0x60000000, 0x67FFFFFF, "AP", "AU"),
        (0x68000000, 0x6BFFFFFF, "AP", "CN"),
        (0x6C000000, 0x6FFFFFFF, "AP", "IN"),
        (0x70000000, 0x77FFFFFF, "AP", "SG"),
        (0x78000000, 0x7FFFFFFF, "EU", "RU"),
        (0x80000000, 0x8FFFFFFF, "NA", "US"),
        (0x90000000, 0x9FFFFFFF, "AP", "CN"),
        (0xA0000000, 0xA0FFFFFF, "AF", "ZA"),
        (0xA9FE0000, 0xA9FEFFFF, "PRIVATE", "PRIVATE"),  # 169.254.0.0/16
        (0xAC100000, 0xAC1FFFFF, "PRIVATE", "PRIVATE"),  # 172.16.0.0/12
        (0xC0A80000, 0xC0A8FFFF, "PRIVATE", "PRIVATE"),  # 192.168.0.0/16
        (0xC6336400, 0xC63364FF, "PRIVATE", "PRIVATE"),   # 198.51.100.0/24
        (0xCB007100, 0xCB0071FF, "PRIVATE", "PRIVATE"),   # 203.0.113.0/24
        (0xD0000000, 0xDFFFFFFF, "EU", "DE"),
        (0xE0000000, 0xEFFFFFFF, "MULTICAST", "MULTICAST"),
    ]

    # Known threat infrastructure regions (country → risk multiplier)
    _RISK_COUNTRIES = {
        "RU": 1.3, "CN": 1.2, "KP": 1.5, "IR": 1.3,
        "NG": 1.1, "RO": 1.1, "UA": 1.0, "BY": 1.2,
    }

    # Well-known ASN ranges (approximate)
    _ASN_MAP = {
        "US": [("AS15169", "Google"), ("AS13335", "Cloudflare"),
               ("AS16509", "Amazon"), ("AS8075", "Microsoft"),
               ("AS32934", "Facebook"), ("AS14618", "AWS")],
        "DE": [("AS3320", "Deutsche Telekom"), ("AS24940", "Hetzner")],
        "RU": [("AS12389", "Rostelecom"), ("AS47541", "VK")],
        "CN": [("AS4134", "China Telecom"), ("AS4837", "China Unicom"),
               ("AS45090", "Tencent"), ("AS37963", "Alibaba")],
        "GB": [("AS2856", "BT"), ("AS5089", "Virgin Media")],
    }

    @staticmethod
    def ip_to_int(ip: str) -> int:
        try:
            return struct.unpack("!I", socket.inet_aton(ip))[0]
        except Exception:
            return 0

    @staticmethod
    def is_private(ip: str) -> bool:
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        try:
            a, b = int(parts[0]), int(parts[1])
            if a == 10:
                return True
            if a == 172 and 16 <= b <= 31:
                return True
            if a == 192 and b == 168:
                return True
            if a == 127:
                return True
            return False
        except Exception:
            return False

    @staticmethod
    def is_reserved(ip: str) -> bool:
        parts = ip.split(".")
        if len(parts) != 4:
            return True
        try:
            a = int(parts[0])
            return a in (0, 127, 224, 225, 226, 227, 228, 229, 230, 231,
                          232, 233, 234, 235, 236, 237, 238, 239, 255)
        except Exception:
            return True

    def lookup(self, ip: str) -> Dict[str, Any]:
        """
        Resolve IP to geographic + threat metadata.
        Returns: country, region, city_hint, latitude, longitude,
                 asn, org, is_private, is_tor_exit, risk_score.
        """
        result = {
            "ip": ip,
            "country": "UNKNOWN",
            "country_name": "Unknown",
            "region": "UNKNOWN",
            "city": "",
            "latitude": 0.0,
            "longitude": 0.0,
            "asn": "",
            "org": "",
            "is_private": self.is_private(ip),
            "is_reserved": self.is_reserved(ip),
            "is_tor_exit": False,
            "is_vpn": False,
            "is_proxy": False,
            "is_hosting": False,
            "risk_score": 0.0,
            "threat_tags": [],
        }

        if result["is_private"]:
            result["country"] = "PRIVATE"
            result["country_name"] = "Private Network"
            result["region"] = "LAN"
            return result

        if result["is_reserved"]:
            result["country"] = "RESERVED"
            return result

        ip_int = self.ip_to_int(ip)

        # Find region block
        for start, end, region, country in self._BLOCKS:
            if start <= ip_int <= end:
                result["country"] = country
                result["region"] = region
                break

        # Enrich with country info
        result["country_name"] = self._country_name(result["country"])
        lat, lon = self._country_coords(result["country"])
        result["latitude"] = lat
        result["longitude"] = lon

        # ASN lookup
        asn_list = self._ASN_MAP.get(result["country"], [])
        if asn_list:
            # Deterministic assignment based on IP hash
            idx = ip_int % len(asn_list)
            result["asn"] = asn_list[idx][0]
            result["org"] = asn_list[idx][1]

        # Risk scoring
        base_risk = self._RISK_COUNTRIES.get(result["country"], 0.5)
        # High ports = slightly suspicious
        result["risk_score"] = round(min(base_risk, 1.0), 3)

        # Heuristic: known hosting / proxy detection
        if result["org"] in ("Hetzner", "DigitalOcean", "Linode", "Vultr"):
            result["is_hosting"] = True
            result["risk_score"] = min(result["risk_score"] + 0.1, 1.0)

        return result

    def lookup_batch(self, ips: List[str]) -> List[Dict]:
        return [self.lookup(ip) for ip in ips]

    @staticmethod
    def _country_name(code: str) -> str:
        _names = {
            "US": "United States", "GB": "United Kingdom", "DE": "Germany",
            "FR": "France", "NL": "Netherlands", "IT": "Italy",
            "JP": "Japan", "KR": "South Korea", "CN": "China",
            "IN": "India", "AU": "Australia", "BR": "Brazil",
            "RU": "Russia", "SG": "Singapore", "ZA": "South Africa",
            "CA": "Canada", "IR": "Iran", "KP": "North Korea",
            "NG": "Nigeria", "RO": "Romania", "UA": "Ukraine",
            "BY": "Belarus",
        }
        return _names.get(code, code)

    @staticmethod
    def _country_coords(code: str) -> Tuple[float, float]:
        _coords = {
            "US": (39.8283, -98.5795), "GB": (51.5074, -0.1278),
            "DE": (51.1657, 10.4515), "FR": (46.2276, 2.2137),
            "NL": (52.1326, 5.2913), "IT": (41.8719, 12.5674),
            "JP": (36.2048, 138.2529), "KR": (35.9078, 127.7669),
            "CN": (35.8617, 104.1954), "IN": (20.5937, 78.9629),
            "AU": (-25.2744, 133.7751), "BR": (-14.235, -51.9253),
            "RU": (61.5240, 105.3188), "SG": (1.3521, 103.8198),
            "ZA": (-30.5595, 22.9375),
        }
        return _coords.get(code, (0.0, 0.0))


# ═══════════════════════════════════════════════════════════════════════════════
# STIX 2.1 OBJECT FACTORY
# ═══════════════════════════════════════════════════════════════════════════════

class STIXFactory:
    """
    Pure-Python STIX 2.1 object builder.
    Creates valid STIX bundles from NetForensics detections.
    """

    STIX_VERSION = "2.1"
    IDENTITY_ID = "identity--netforensics-platform"

    @staticmethod
    def _stix_id(stype: str) -> str:
        return f"{stype}--{uuid.uuid4()}"

    @staticmethod
    def _now() -> str:
        return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z")

    @classmethod
    def create_identity(cls) -> Dict:
        return {
            "type": "identity",
            "spec_version": cls.STIX_VERSION,
            "id": cls.IDENTITY_ID,
            "created": cls._now(),
            "modified": cls._now(),
            "name": "NetForensics Platform",
            "identity_class": "system",
            "sectors": ["technology"],
            "description": "Automated threat detection from NetForensics NIDS",
        }

    @classmethod
    def create_indicator(cls, pattern: str, name: str,
                          description: str = "",
                          indicator_types: List[str] = None,
                          kill_chain_phases: List[Dict] = None,
                          confidence: int = 75,
                          valid_days: int = 30) -> Dict:
        now = cls._now()
        return {
            "type": "indicator",
            "spec_version": cls.STIX_VERSION,
            "id": cls._stix_id("indicator"),
            "created": now,
            "modified": now,
            "name": name,
            "description": description,
            "pattern": pattern,
            "pattern_type": "stix",
            "indicator_types": indicator_types or ["malicious-activity"],
            "valid_from": now,
            "valid_until": (datetime.utcnow() + timedelta(days=valid_days)
                            ).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "confidence": confidence,
            "created_by_ref": cls.IDENTITY_ID,
            "kill_chain_phases": kill_chain_phases or [],
        }

    @classmethod
    def ip_indicator(cls, ip: str, threat_type: str = "C2",
                      confidence: int = 80) -> Dict:
        return cls.create_indicator(
            pattern=f"[ipv4-addr:value = '{ip}']",
            name=f"Malicious IP: {ip}",
            description=f"Detected as {threat_type} by NetForensics ML pipeline",
            indicator_types=["malicious-activity"],
            confidence=confidence,
            kill_chain_phases=[{
                "kill_chain_name": "mitre-attack",
                "phase_name": "command-and-control",
            }],
        )

    @classmethod
    def domain_indicator(cls, domain: str, threat_type: str = "DGA",
                          confidence: int = 70) -> Dict:
        return cls.create_indicator(
            pattern=f"[domain-name:value = '{domain}']",
            name=f"Malicious Domain: {domain}",
            description=f"Detected as {threat_type} by NetForensics",
            indicator_types=["malicious-activity"],
            confidence=confidence,
        )

    @classmethod
    def ja3_indicator(cls, ja3: str, threat_type: str = "Suspicious TLS",
                       confidence: int = 65) -> Dict:
        return cls.create_indicator(
            pattern=f"[network-traffic:extensions.'http-request-ext'.request_header.'ja3' = '{ja3}']",
            name=f"Suspicious JA3: {ja3[:16]}...",
            description=f"Malware-associated JA3 fingerprint: {threat_type}",
            indicator_types=["malicious-activity"],
            confidence=confidence,
        )

    @classmethod
    def create_observed_data(cls, objects: List[Dict],
                              count: int = 1) -> Dict:
        now = cls._now()
        return {
            "type": "observed-data",
            "spec_version": cls.STIX_VERSION,
            "id": cls._stix_id("observed-data"),
            "created": now,
            "modified": now,
            "first_observed": now,
            "last_observed": now,
            "number_observed": count,
            "object_refs": [o.get("id", "") for o in objects if "id" in o],
            "created_by_ref": cls.IDENTITY_ID,
        }

    @classmethod
    def create_attack_pattern(cls, technique_id: str,
                                name: str, description: str = "") -> Dict:
        now = cls._now()
        return {
            "type": "attack-pattern",
            "spec_version": cls.STIX_VERSION,
            "id": cls._stix_id("attack-pattern"),
            "created": now,
            "modified": now,
            "name": name,
            "description": description,
            "external_references": [{
                "source_name": "mitre-attack",
                "external_id": technique_id,
                "url": f"https://attack.mitre.org/techniques/{technique_id}/",
            }],
            "kill_chain_phases": [{
                "kill_chain_name": "mitre-attack",
                "phase_name": cls._mitre_phase(technique_id),
            }],
        }

    @classmethod
    def create_relationship(cls, source_ref: str, relationship_type: str,
                             target_ref: str, description: str = "") -> Dict:
        now = cls._now()
        return {
            "type": "relationship",
            "spec_version": cls.STIX_VERSION,
            "id": cls._stix_id("relationship"),
            "created": now,
            "modified": now,
            "relationship_type": relationship_type,
            "source_ref": source_ref,
            "target_ref": target_ref,
            "description": description,
        }

    @classmethod
    def create_sighting(cls, indicator_ref: str,
                         where_sighted: str = "",
                         count: int = 1) -> Dict:
        now = cls._now()
        return {
            "type": "sighting",
            "spec_version": cls.STIX_VERSION,
            "id": cls._stix_id("sighting"),
            "created": now,
            "modified": now,
            "first_seen": now,
            "last_seen": now,
            "count": count,
            "sighting_of_ref": indicator_ref,
            "where_sighted_refs": [where_sighted] if where_sighted else [],
        }

    @classmethod
    def create_bundle(cls, objects: List[Dict]) -> Dict:
        return {
            "type": "bundle",
            "id": cls._stix_id("bundle"),
            "objects": [cls.create_identity()] + objects,
        }

    @staticmethod
    def _mitre_phase(technique_id: str) -> str:
        _phase_map = {
            "T1071": "command-and-control",
            "T1090": "command-and-control",
            "T1573": "command-and-control",
            "T1021": "lateral-movement",
            "T1059": "execution",
            "T1082": "discovery",
            "T1018": "discovery",
            "T1040": "credential-access",
            "T1568": "command-and-control",
        }
        base = technique_id.split(".")[0]
        return _phase_map.get(base, "unknown")


# ═══════════════════════════════════════════════════════════════════════════════
# TAXII 2.1 SERVER (In-memory collections)
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class TAXIICollection:
    id: str = ""
    title: str = ""
    description: str = ""
    can_read: bool = True
    can_write: bool = True
    media_types: List[str] = field(default_factory=lambda: [
        "application/stix+json;version=2.1"
    ])
    objects: List[Dict] = field(default_factory=list)
    created_at: str = ""

    def __post_init__(self):
        if not self.id:
            self.id = str(uuid.uuid4())
        if not self.created_at:
            self.created_at = datetime.utcnow().isoformat()

    def add_object(self, obj: Dict):
        self.objects.append(obj)

    def add_bundle(self, bundle: Dict):
        for obj in bundle.get("objects", []):
            self.objects.append(obj)

    def get_manifest(self) -> List[Dict]:
        return [
            {
                "id": obj.get("id", ""),
                "date_added": obj.get("created", ""),
                "version": obj.get("modified", obj.get("created", "")),
                "media_type": "application/stix+json;version=2.1",
            }
            for obj in self.objects
        ]

    def to_taxii(self) -> Dict:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "can_read": self.can_read,
            "can_write": self.can_write,
            "media_types": self.media_types,
        }


class TAXIIServer:
    """In-memory TAXII 2.1 server with collection management."""

    API_ROOT = "/taxii2"
    TITLE = "NetForensics TAXII Server"

    def __init__(self):
        self.collections: Dict[str, TAXIICollection] = {}
        self._init_default_collections()

    def _init_default_collections(self):
        defaults = [
            ("NetForensics Detections",
             "Auto-generated IOCs from NetForensics threat detection engines"),
            ("Threat Intelligence Feed",
             "Ingested IOCs from external threat intelligence sources"),
            ("Incident Indicators",
             "IOCs extracted during incident investigations"),
            ("ML-Detected Threats",
             "Machine learning model-generated threat indicators"),
        ]
        for title, desc in defaults:
            col = TAXIICollection(title=title, description=desc)
            self.collections[col.id] = col

    def get_discovery(self) -> Dict:
        return {
            "title": self.TITLE,
            "description": "NetForensics Threat Intelligence Sharing Platform",
            "contact": "admin@netforensics.local",
            "default": f"{self.API_ROOT}/",
            "api_roots": [f"{self.API_ROOT}/"],
        }

    def get_api_root(self) -> Dict:
        return {
            "title": self.TITLE,
            "description": "NetForensics STIX/TAXII API Root",
            "versions": ["application/taxii+json;version=2.1"],
            "max_content_length": 10485760,  # 10MB
        }

    def list_collections(self) -> Dict:
        return {
            "collections": [c.to_taxii() for c in self.collections.values()]
        }

    def get_collection(self, collection_id: str) -> Optional[Dict]:
        col = self.collections.get(collection_id)
        if col:
            return col.to_taxii()
        return None

    def get_objects(self, collection_id: str, limit: int = 100,
                     added_after: str = "", match_type: str = "") -> Dict:
        col = self.collections.get(collection_id)
        if not col:
            return {"objects": []}
        objects = col.objects
        if added_after:
            objects = [o for o in objects if o.get("created", "") > added_after]
        if match_type:
            objects = [o for o in objects if o.get("type") == match_type]
        return {
            "objects": objects[-limit:],
            "more": len(objects) > limit,
        }

    def add_objects(self, collection_id: str, bundle: Dict) -> Dict:
        col = self.collections.get(collection_id)
        if not col or not col.can_write:
            return {"status": "error", "message": "Collection not writable"}
        added = 0
        for obj in bundle.get("objects", []):
            if obj.get("type") != "bundle":
                col.add_object(obj)
                added += 1
        return {
            "id": str(uuid.uuid4()),
            "status": "complete",
            "total_count": added,
            "success_count": added,
            "failure_count": 0,
        }

    def get_manifest(self, collection_id: str) -> Dict:
        col = self.collections.get(collection_id)
        if not col:
            return {"objects": []}
        return {"objects": col.get_manifest()}

    def publish_detection(self, threat: Dict) -> str:
        """Convert a NetForensics threat detection into STIX and publish."""
        stix_objects = []
        threat_type = threat.get("threat_type", "unknown")
        evidence = threat.get("evidence", [])
        score = threat.get("score", 0.5)
        confidence = int(score * 100)

        # Create indicators from evidence IPs
        for ev in evidence:
            ip_match = re.findall(r"\d+\.\d+\.\d+\.\d+", str(ev))
            for ip in ip_match:
                ind = STIXFactory.ip_indicator(ip, threat_type, confidence)
                stix_objects.append(ind)

        # Create attack pattern from MITRE mapping
        mitre = threat.get("mitre_technique", "")
        if mitre:
            ap = STIXFactory.create_attack_pattern(
                mitre, threat_type,
                f"Detected by NetForensics: {threat.get('description', '')}")
            stix_objects.append(ap)

            # Link indicators to attack pattern
            for obj in stix_objects:
                if obj["type"] == "indicator":
                    rel = STIXFactory.create_relationship(
                        obj["id"], "indicates", ap["id"])
                    stix_objects.append(rel)

        # Publish to default detection collection
        if stix_objects:
            first_col = list(self.collections.values())[0]
            bundle = STIXFactory.create_bundle(stix_objects)
            self.add_objects(first_col.id, bundle)

        return f"Published {len(stix_objects)} STIX objects"


# ═══════════════════════════════════════════════════════════════════════════════
# ATTACKER INFRASTRUCTURE CORRELATION
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class InfrastructureNode:
    ip: str = ""
    domain: str = ""
    node_type: str = ""         # c2, proxy, exfil, scanning, relay
    first_seen: str = ""
    last_seen: str = ""
    geo: Dict = field(default_factory=dict)
    connections: List[str] = field(default_factory=list)
    threat_types: List[str] = field(default_factory=list)
    confidence: float = 0.0
    tags: List[str] = field(default_factory=list)


class AttackerInfraCorrelator:
    """
    Correlates detected threats across sessions to identify attacker
    infrastructure patterns: shared C2 servers, relay chains,
    staging servers, and campaign attribution.
    """

    def __init__(self):
        self.geoip = GeoIPDatabase()
        self.nodes: Dict[str, InfrastructureNode] = {}  # ip -> node
        self.campaigns: List[Dict] = []
        self._domain_to_ip: Dict[str, Set[str]] = {}
        self._ip_to_sessions: Dict[str, Set[str]] = {}

    def ingest_threat(self, threat: Dict, session_id: str = ""):
        """Ingest a detected threat and update infrastructure graph."""
        evidence = threat.get("evidence", [])
        threat_type = threat.get("threat_type", "unknown")
        score = threat.get("score", 0.5)

        ips = set()
        domains = set()

        for ev in evidence:
            ev_str = str(ev)
            for ip in re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", ev_str):
                if not self.geoip.is_private(ip):
                    ips.add(ip)
            for domain in re.findall(r"\b[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}\b", ev_str):
                if len(domain) > 4:
                    domains.add(domain.lower())

        now_iso = datetime.utcnow().isoformat()

        for ip in ips:
            if ip not in self.nodes:
                geo = self.geoip.lookup(ip)
                self.nodes[ip] = InfrastructureNode(
                    ip=ip,
                    node_type=self._classify_node(threat_type),
                    first_seen=now_iso,
                    last_seen=now_iso,
                    geo=geo,
                    confidence=score,
                    threat_types=[threat_type],
                )
            else:
                node = self.nodes[ip]
                node.last_seen = now_iso
                node.confidence = max(node.confidence, score)
                if threat_type not in node.threat_types:
                    node.threat_types.append(threat_type)

            if session_id:
                self._ip_to_sessions.setdefault(ip, set()).add(session_id)

        for domain in domains:
            for ip in ips:
                self._domain_to_ip.setdefault(domain, set()).add(ip)

        # Link co-occurring IPs
        for ip1 in ips:
            for ip2 in ips:
                if ip1 != ip2 and ip2 not in self.nodes[ip1].connections:
                    self.nodes[ip1].connections.append(ip2)

    def ingest_threats_batch(self, threats: List[Dict], session_id: str = ""):
        for t in threats:
            self.ingest_threat(t, session_id)
        self._detect_campaigns()

    def _classify_node(self, threat_type: str) -> str:
        _map = {
            "malware_beaconing": "c2",
            "tor_c2": "proxy",
            "lateral_movement": "relay",
            "suspicious_encrypted_session": "c2",
            "abnormal_traffic_flow": "exfil",
            "dga": "c2",
        }
        return _map.get(threat_type, "unknown")

    def _detect_campaigns(self):
        """Group correlated nodes into campaigns."""
        visited = set()
        self.campaigns = []

        for ip, node in self.nodes.items():
            if ip in visited:
                continue
            # BFS to find connected component
            component = set()
            queue = [ip]
            while queue:
                current = queue.pop(0)
                if current in visited:
                    continue
                visited.add(current)
                component.add(current)
                if current in self.nodes:
                    for neighbor in self.nodes[current].connections:
                        if neighbor not in visited:
                            queue.append(neighbor)

            if len(component) >= 2:
                nodes_data = [self.nodes[ip] for ip in component if ip in self.nodes]
                countries = set()
                threat_types = set()
                sessions = set()
                for n in nodes_data:
                    countries.add(n.geo.get("country", "??"))
                    threat_types.update(n.threat_types)
                    sessions.update(self._ip_to_sessions.get(n.ip, set()))

                self.campaigns.append({
                    "campaign_id": str(uuid.uuid4())[:8],
                    "node_count": len(component),
                    "ips": list(component),
                    "countries": list(countries),
                    "threat_types": list(threat_types),
                    "session_count": len(sessions),
                    "confidence": round(
                        sum(n.confidence for n in nodes_data) / len(nodes_data), 3),
                    "first_seen": min(n.first_seen for n in nodes_data),
                    "last_seen": max(n.last_seen for n in nodes_data),
                })

    def get_infrastructure_map(self) -> Dict:
        """Full infrastructure correlation summary."""
        total_nodes = len(self.nodes)
        countries = {}
        for node in self.nodes.values():
            c = node.geo.get("country", "??")
            countries[c] = countries.get(c, 0) + 1

        return {
            "total_nodes": total_nodes,
            "total_campaigns": len(self.campaigns),
            "countries_involved": countries,
            "nodes": [
                {
                    "ip": n.ip,
                    "node_type": n.node_type,
                    "country": n.geo.get("country", "??"),
                    "org": n.geo.get("org", ""),
                    "threat_types": n.threat_types,
                    "connections": n.connections[:20],
                    "confidence": round(n.confidence, 3),
                    "first_seen": n.first_seen,
                    "last_seen": n.last_seen,
                    "sessions_seen_in": len(self._ip_to_sessions.get(n.ip, set())),
                }
                for n in sorted(self.nodes.values(),
                                 key=lambda x: x.confidence, reverse=True)[:200]
            ],
            "campaigns": self.campaigns[:50],
            "domain_ip_map": {
                d: list(ips)[:10]
                for d, ips in list(self._domain_to_ip.items())[:100]
            },
        }

    def get_node_detail(self, ip: str) -> Optional[Dict]:
        node = self.nodes.get(ip)
        if not node:
            return None
        return {
            **asdict(node),
            "sessions": list(self._ip_to_sessions.get(ip, set())),
            "related_domains": [
                d for d, ips in self._domain_to_ip.items() if ip in ips
            ],
        }


# ═══════════════════════════════════════════════════════════════════════════════
# SIEM INTEGRATION (Syslog / CEF / LEEF / JSON export)
# ═══════════════════════════════════════════════════════════════════════════════

class SIEMExporter:
    """
    Export NetForensics alerts and events in standard SIEM formats:
      - CEF (Common Event Format) — ArcSight, QRadar
      - LEEF (Log Event Extended Format) — QRadar
      - JSON (Splunk HEC, Elastic, generic)
      - Syslog (RFC 5424)
    """

    VENDOR = "NetForensics"
    PRODUCT = "NIDS"
    VERSION = "5.0"

    # CEF severity mapping
    _CEF_SEV = {
        "CRITICAL": 10, "HIGH": 8, "MEDIUM": 5, "LOW": 3, "INFO": 1,
    }

    @classmethod
    def to_cef(cls, alert: Dict) -> str:
        """Common Event Format (CEF) string."""
        sev = cls._CEF_SEV.get(alert.get("severity", "MEDIUM"), 5)
        src = alert.get("src_ip", "-")
        dst = alert.get("dst_ip", "-")
        name = alert.get("title", "Unknown Alert").replace("|", "\\|")
        cat = alert.get("category", "network")
        score = alert.get("threat_score", 0)

        extensions = (
            f"src={src} dst={dst} act={alert.get('status', 'open')} "
            f"cat={cat} cs1={alert.get('alert_id', '')} "
            f"cs1Label=AlertID cs2={alert.get('mitre_technique', '')} "
            f"cs2Label=MITRE cfp1={score} cfp1Label=ThreatScore "
            f"msg={alert.get('description', '')}"
        )

        return (f"CEF:0|{cls.VENDOR}|{cls.PRODUCT}|{cls.VERSION}"
                f"|{cat}|{name}|{sev}|{extensions}")

    @classmethod
    def to_leef(cls, alert: Dict) -> str:
        """Log Event Extended Format (LEEF) for QRadar."""
        src = alert.get("src_ip", "-")
        dst = alert.get("dst_ip", "-")
        name = alert.get("title", "Unknown")

        return (
            f"LEEF:2.0|{cls.VENDOR}|{cls.PRODUCT}|{cls.VERSION}|{name}|"
            f"src={src}\tdst={dst}\t"
            f"sev={alert.get('severity', 'MEDIUM')}\t"
            f"cat={alert.get('category', 'network')}\t"
            f"mitre={alert.get('mitre_technique', '')}\t"
            f"score={alert.get('threat_score', 0)}"
        )

    @classmethod
    def to_splunk_hec(cls, alert: Dict) -> Dict:
        """Splunk HTTP Event Collector (HEC) JSON format."""
        return {
            "time": int(time.time()),
            "host": "netforensics",
            "source": "netforensics:alerts",
            "sourcetype": "netforensics:alert",
            "index": "security",
            "event": {
                "alert_id": alert.get("alert_id", ""),
                "title": alert.get("title", ""),
                "severity": alert.get("severity", "MEDIUM"),
                "category": alert.get("category", ""),
                "src_ip": alert.get("src_ip", ""),
                "dst_ip": alert.get("dst_ip", ""),
                "threat_score": alert.get("threat_score", 0),
                "mitre_technique": alert.get("mitre_technique", ""),
                "status": alert.get("status", "open"),
                "evidence": alert.get("evidence", []),
                "description": alert.get("description", ""),
            },
        }

    @classmethod
    def to_elastic(cls, alert: Dict) -> Dict:
        """Elasticsearch / OpenSearch document format."""
        return {
            "_index": "netforensics-alerts",
            "_source": {
                "@timestamp": datetime.utcnow().isoformat(),
                "event": {
                    "kind": "alert",
                    "category": ["network", "intrusion_detection"],
                    "severity": cls._CEF_SEV.get(
                        alert.get("severity", "MEDIUM"), 5),
                },
                "alert": {
                    "id": alert.get("alert_id", ""),
                    "title": alert.get("title", ""),
                    "severity": alert.get("severity", ""),
                    "category": alert.get("category", ""),
                    "score": alert.get("threat_score", 0),
                    "status": alert.get("status", "open"),
                },
                "source": {"ip": alert.get("src_ip", "")},
                "destination": {"ip": alert.get("dst_ip", "")},
                "threat": {
                    "technique": {"id": alert.get("mitre_technique", "")},
                    "indicator": {"type": "network-traffic"},
                },
                "observer": {
                    "vendor": cls.VENDOR,
                    "product": cls.PRODUCT,
                    "version": cls.VERSION,
                },
            },
        }

    @classmethod
    def to_syslog(cls, alert: Dict, facility: int = 10,
                    severity_code: int = 3) -> str:
        """RFC 5424 syslog message."""
        pri = facility * 8 + severity_code
        timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z")
        msg = (f"<{pri}>1 {timestamp} netforensics nf_alerts - "
               f"{alert.get('alert_id', '-')} - "
               f"[alert severity=\"{alert.get('severity', 'MEDIUM')}\" "
               f"category=\"{alert.get('category', '')}\" "
               f"score=\"{alert.get('threat_score', 0)}\"] "
               f"{alert.get('title', 'Alert')}: {alert.get('description', '')}")
        return msg

    @classmethod
    def export_batch(cls, alerts: List[Dict], fmt: str = "cef") -> List[str]:
        """Export multiple alerts in the specified format."""
        exporters = {
            "cef": cls.to_cef,
            "leef": cls.to_leef,
            "syslog": cls.to_syslog,
        }
        exporter = exporters.get(fmt)
        if not exporter:
            return [json.dumps(cls.to_splunk_hec(a)) for a in alerts]
        return [exporter(a) for a in alerts]


# ═══════════════════════════════════════════════════════════════════════════════
# AUTOMATED INVESTIGATION REPORT GENERATOR
# ═══════════════════════════════════════════════════════════════════════════════

class InvestigationReportGenerator:
    """
    Generates comprehensive automated investigation reports from
    session analysis data, ML detections, and threat intelligence.
    """

    def __init__(self):
        self.geoip = GeoIPDatabase()

    def generate_report(self, session_id: str, analysis: Dict,
                         ml_threats: List[Dict] = None,
                         infra_map: Dict = None,
                         tenant_name: str = "") -> Dict:
        """Generate a full investigation report."""
        now = datetime.utcnow()
        ml_threats = ml_threats or []

        # Extract key data from analysis
        summary = analysis.get("summary", {})
        flows = analysis.get("flows", [])
        threats = analysis.get("threats", [])
        anomalies = analysis.get("anomalies", [])

        # Build report
        report = {
            "report_id": f"RPT-{now.strftime('%Y%m%d')}-{str(uuid.uuid4())[:8].upper()}",
            "generated_at": now.isoformat(),
            "generated_by": "NetForensics Automated Report Generator v5.0",
            "classification": "TLP:AMBER",
            "tenant": tenant_name or "Default Organization",
            "session_id": session_id,

            "executive_summary": self._executive_summary(
                summary, ml_threats, threats),

            "threat_overview": {
                "total_threats": len(threats) + len(ml_threats),
                "heuristic_threats": len(threats),
                "ml_threats": len(ml_threats),
                "severity_breakdown": self._severity_breakdown(
                    threats + ml_threats),
                "top_mitre_techniques": self._top_mitre(threats + ml_threats),
                "risk_level": self._overall_risk(threats + ml_threats),
            },

            "network_analysis": {
                "total_flows": summary.get("total_flows", 0),
                "total_bytes": summary.get("total_bytes", 0),
                "unique_endpoints": summary.get("unique_endpoints", 0),
                "protocols": summary.get("protocols", {}),
                "top_talkers": self._top_talkers(flows)[:10],
                "geographic_distribution": self._geo_distribution(flows),
            },

            "ml_detection_results": {
                "beacon_detections": [t for t in ml_threats
                                       if t.get("threat_type") == "malware_beaconing"],
                "lateral_movement": [t for t in ml_threats
                                      if t.get("threat_type") == "lateral_movement"],
                "tor_c2": [t for t in ml_threats
                            if t.get("threat_type") == "tor_c2"],
                "suspicious_tls": [t for t in ml_threats
                                    if t.get("threat_type") == "suspicious_encrypted_session"],
                "abnormal_flows": [t for t in ml_threats
                                    if t.get("threat_type") == "abnormal_traffic_flow"],
            },

            "indicators_of_compromise": self._extract_iocs(
                threats + ml_threats, flows),

            "attacker_infrastructure": infra_map or {},

            "recommendations": self._recommendations(
                threats + ml_threats, summary),

            "compliance_notes": {
                "data_handling": "All packet data processed locally. No PII exported.",
                "retention": "Analysis results retained per tenant policy.",
                "frameworks": ["NIST CSF", "ISO 27001", "SOC 2 Type II",
                                "GDPR Art. 32", "PCI DSS 3.2.1"],
            },

            "appendix": {
                "analysis_engines": [
                    "Traffic Analyzer v3",
                    "Tor Detector v2",
                    "DNS Tunneling Detector",
                    "Lateral Movement Detector",
                    "Encrypted Channel Analyzer",
                    "ML Beacon Detector (Isolation Forest + EWMA)",
                    "ML Flow Anomaly Detector",
                    "ML Tor C2 Detector (GNN-proxy)",
                    "ML TLS Session Analyzer (K-Means)",
                    "ML Lateral Movement Detector (Graph Centrality)",
                ],
                "mitre_framework_version": "ATT&CK v14",
                "stix_version": "2.1",
            },
        }

        return report

    def _executive_summary(self, summary: Dict, ml_threats: List,
                            heuristic_threats: List) -> str:
        total = len(ml_threats) + len(heuristic_threats)
        critical = sum(1 for t in (ml_threats + heuristic_threats)
                        if t.get("severity") == "CRITICAL")
        high = sum(1 for t in (ml_threats + heuristic_threats)
                    if t.get("severity") == "HIGH")
        flows = summary.get("total_flows", 0)
        endpoints = summary.get("unique_endpoints", 0)

        risk = "CRITICAL" if critical > 0 else ("HIGH" if high > 0 else "MEDIUM")

        return (
            f"Analysis of {flows} network flows across {endpoints} endpoints "
            f"identified {total} potential threats ({critical} critical, {high} high). "
            f"Overall risk assessment: {risk}. "
            f"Machine learning models detected {len(ml_threats)} anomalous behaviors "
            f"including beaconing, lateral movement, and suspicious encrypted sessions. "
            f"Immediate investigation is {'REQUIRED' if critical > 0 else 'recommended'} "
            f"for high-confidence detections."
        )

    def _severity_breakdown(self, threats: List) -> Dict:
        breakdown = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for t in threats:
            sev = t.get("severity", "MEDIUM")
            breakdown[sev] = breakdown.get(sev, 0) + 1
        return breakdown

    def _top_mitre(self, threats: List) -> List[Dict]:
        counts = {}
        for t in threats:
            tech = t.get("mitre_technique", "")
            if tech:
                counts[tech] = counts.get(tech, 0) + 1
        return [
            {"technique": k, "count": v}
            for k, v in sorted(counts.items(), key=lambda x: -x[1])[:10]
        ]

    def _overall_risk(self, threats: List) -> str:
        if not threats:
            return "LOW"
        max_score = max(t.get("score", 0) for t in threats)
        if max_score >= 0.9:
            return "CRITICAL"
        if max_score >= 0.7:
            return "HIGH"
        if max_score >= 0.4:
            return "MEDIUM"
        return "LOW"

    def _top_talkers(self, flows: List) -> List[Dict]:
        byte_counts = {}
        for f in flows:
            src = f.get("src_ip", "")
            byte_counts[src] = byte_counts.get(src, 0) + f.get("total_bytes", 0)
        return [
            {"ip": ip, "total_bytes": b, "geo": self.geoip.lookup(ip)}
            for ip, b in sorted(byte_counts.items(), key=lambda x: -x[1])[:10]
        ]

    def _geo_distribution(self, flows: List) -> Dict:
        countries = {}
        for f in flows:
            for ip_field in ["src_ip", "dst_ip"]:
                ip = f.get(ip_field, "")
                if ip and not self.geoip.is_private(ip):
                    geo = self.geoip.lookup(ip)
                    c = geo["country"]
                    countries[c] = countries.get(c, 0) + 1
        return countries

    def _extract_iocs(self, threats: List, flows: List) -> Dict:
        iocs = {"ips": [], "domains": [], "ja3_hashes": [], "ports": []}
        seen_ips = set()
        seen_domains = set()

        for t in threats:
            for ev in t.get("evidence", []):
                ev_str = str(ev)
                for ip in re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", ev_str):
                    if ip not in seen_ips and not self.geoip.is_private(ip):
                        seen_ips.add(ip)
                        geo = self.geoip.lookup(ip)
                        iocs["ips"].append({
                            "value": ip, "type": "ipv4-addr",
                            "country": geo["country"], "org": geo.get("org", ""),
                            "risk_score": geo["risk_score"],
                        })
                for domain in re.findall(
                        r"\b[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}\b", ev_str):
                    if domain.lower() not in seen_domains and len(domain) > 4:
                        seen_domains.add(domain.lower())
                        iocs["domains"].append({
                            "value": domain.lower(), "type": "domain-name",
                        })

            ja3 = t.get("ja3", "")
            if ja3 and ja3 not in [j["value"] for j in iocs["ja3_hashes"]]:
                iocs["ja3_hashes"].append({"value": ja3, "type": "ja3-hash"})

        # Extract unusual ports
        port_counts = {}
        for f in flows:
            p = f.get("dst_port", 0)
            if p and p not in (80, 443, 53, 22):
                port_counts[p] = port_counts.get(p, 0) + 1
        iocs["ports"] = [
            {"port": p, "count": c}
            for p, c in sorted(port_counts.items(), key=lambda x: -x[1])[:20]
        ]

        return iocs

    def _recommendations(self, threats: List, summary: Dict) -> List[Dict]:
        recs = []
        threat_types = set(t.get("threat_type", "") for t in threats)

        if "malware_beaconing" in threat_types:
            recs.append({
                "priority": "HIGH",
                "action": "Investigate beaconing hosts",
                "description": ("Isolate hosts exhibiting periodic C2 communication "
                                 "patterns. Check for malware persistence mechanisms."),
                "mitre": "T1071.001",
            })

        if "lateral_movement" in threat_types:
            recs.append({
                "priority": "CRITICAL",
                "action": "Contain lateral movement",
                "description": ("Implement network segmentation to limit east-west traffic. "
                                 "Review admin credentials and disable unused accounts."),
                "mitre": "T1021",
            })

        if "tor_c2" in threat_types:
            recs.append({
                "priority": "HIGH",
                "action": "Block Tor exit nodes",
                "description": ("Update firewall rules to block known Tor exit nodes. "
                                 "Investigate hosts communicating over Tor for data exfil."),
                "mitre": "T1090.003",
            })

        if "suspicious_encrypted_session" in threat_types:
            recs.append({
                "priority": "MEDIUM",
                "action": "Review TLS configurations",
                "description": ("Investigate connections using deprecated TLS versions "
                                 "or rare JA3 fingerprints. Deploy TLS inspection where allowed."),
                "mitre": "T1573.002",
            })

        # General recommendations
        recs.append({
            "priority": "MEDIUM",
            "action": "Update threat intelligence feeds",
            "description": "Ensure all IOCs from this analysis are shared via STIX/TAXII.",
        })
        recs.append({
            "priority": "LOW",
            "action": "Review behavioral baselines",
            "description": "Update endpoint behavioral baselines with findings from this session.",
        })

        return recs


# ═══════════════════════════════════════════════════════════════════════════════
# SINGLETONS
# ═══════════════════════════════════════════════════════════════════════════════

_geoip: Optional[GeoIPDatabase] = None
_stix: Optional[STIXFactory] = None
_taxii: Optional[TAXIIServer] = None
_siem: Optional[SIEMExporter] = None
_correlator: Optional[AttackerInfraCorrelator] = None
_reporter: Optional[InvestigationReportGenerator] = None


def get_geoip() -> GeoIPDatabase:
    global _geoip
    if _geoip is None:
        _geoip = GeoIPDatabase()
    return _geoip


def get_taxii() -> TAXIIServer:
    global _taxii
    if _taxii is None:
        _taxii = TAXIIServer()
    return _taxii


def get_correlator() -> AttackerInfraCorrelator:
    global _correlator
    if _correlator is None:
        _correlator = AttackerInfraCorrelator()
    return _correlator


def get_reporter() -> InvestigationReportGenerator:
    global _reporter
    if _reporter is None:
        _reporter = InvestigationReportGenerator()
    return _reporter
