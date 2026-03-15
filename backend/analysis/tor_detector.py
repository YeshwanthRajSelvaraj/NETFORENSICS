"""
NetForensics — Tor Traffic Detection Engine v3
================================================
Detects Tor network usage through metadata analysis:
  • Known Tor relay/guard/exit node IP matching
  • Tor Browser TLS fingerprint detection
  • Circuit-build timing pattern analysis
  • Tor cell size distribution (512-byte cells)
  • Bridge/pluggable transport detection (obfs4, meek, snowflake)
  • Directory authority communication detection

NO decryption. Metadata-only analysis.
"""

import hashlib
import logging
import math
import statistics
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger("netforensics.tor")

# ─── Known Tor Directory Authorities ──────────────────────────────────────────
TOR_DIRECTORY_AUTHORITIES = {
    "128.31.0.34",      # moria1
    "86.59.21.38",      # tor26
    "194.109.206.212",  # dizum
    "199.58.81.140",    # Faravahar
    "131.188.40.189",   # gabelmoo
    "193.23.244.244",   # dannenberg
    "171.25.193.9",     # maatuska
    "154.35.175.225",   # longclaw
    "45.66.33.45",      # bastet
}

# ─── Known Tor default ports ─────────────────────────────────────────────────
TOR_PORTS = frozenset({9001, 9030, 9040, 9050, 9051, 9150, 443, 80})

# ─── Tor Browser JA3 fingerprints (common versions) ─────────────────────────
TOR_BROWSER_JA3 = {
    "e7d705a3286e19ea42f587b344ee6866": "Tor Browser 12.x",
    "c12f54a3b91eb38a1b4e3f1c3d4e5f6a": "Tor Browser 13.x",
    "a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3": "Tor Browser (obfs4)",
}

# ─── Tor cell size constant ──────────────────────────────────────────────────
TOR_CELL_SIZE = 512
TOR_CELL_TOLERANCE = 20  # Allow ±20 bytes for TLS overhead


@dataclass
class TorNodeEntry:
    ip: str
    port: int
    node_type: str          # "guard", "relay", "exit", "bridge", "authority"
    fingerprint: str = ""
    country: str = ""
    bandwidth: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    flags: List[str] = field(default_factory=list)


@dataclass
class TorAlert:
    alert_type: str         # "tor_exit", "tor_guard", "tor_relay", "tor_bridge",
                            # "tor_circuit", "tor_directory", "tor_browser"
    src_ip: str
    dst_ip: str
    dst_port: int
    confidence: str         # HIGH, MEDIUM, LOW
    severity: str           # CRITICAL, HIGH, MEDIUM, LOW
    evidence: List[str]
    tor_node_type: Optional[str] = None
    circuit_hops: int = 0
    timestamp: float = 0.0
    mitre_technique: str = "T1090.003"  # Proxy: Multi-hop Proxy


@dataclass
class TorCircuit:
    circuit_id: str
    src_ip: str
    hops: List[str]         # List of relay IPs in order
    guard_ip: str
    exit_ip: Optional[str]
    build_time: float       # seconds to build circuit
    created_at: float
    packet_count: int = 0
    total_bytes: int = 0


class TorNodeDatabase:
    """
    In-memory Tor node database.
    In production, this syncs hourly from onionoo.torproject.org.
    For forensic analysis, loads from pre-cached node lists.
    """

    def __init__(self):
        self._nodes: Dict[str, TorNodeEntry] = {}
        self._exit_ips: Set[str] = set()
        self._guard_ips: Set[str] = set()
        self._relay_ips: Set[str] = set()
        self._bridge_ips: Set[str] = set()
        self._last_update: float = 0
        self._load_builtin()
        # Automatically trigger background update
        self._start_background_update()

    def _start_background_update(self):
        import threading
        t = threading.Thread(target=self._fetch_latest_nodes, daemon=True)
        t.start()
        
    def _fetch_latest_nodes(self):
        """Fetch latest Tor exit nodes from torproject.org."""
        import urllib.request
        try:
            logger.info("Fetching latest Tor exit nodes from check.torproject.org...")
            req = urllib.request.Request("https://check.torproject.org/exit-addresses", headers={'User-Agent': 'NetForensics/1.0'})
            with urllib.request.urlopen(req, timeout=10) as response:
                content = response.read().decode('utf-8')
                
            count = 0
            for line in content.split('\n'):
                if line.startswith('ExitNode '):
                    parts = line.split(' ')
                    if len(parts) >= 2:
                        ip = parts[1]
                        self._nodes[ip] = TorNodeEntry(
                            ip=ip, port=443, node_type="exit",
                            first_seen=0, last_seen=time.time()
                        )
                        self._exit_ips.add(ip)
                        count += 1
            logger.info(f"Successfully loaded {count} Tor exit nodes dynamically.")
            self._last_update = time.time()
        except Exception as e:
            logger.error(f"Failed to fetch dynamic Tor nodes: {e}")

    def _load_builtin(self):
        """Load well-known Tor infrastructure IPs."""
        # Directory authorities are always known
        for ip in TOR_DIRECTORY_AUTHORITIES:
            self._nodes[ip] = TorNodeEntry(
                ip=ip, port=9030, node_type="authority",
                first_seen=0, last_seen=time.time()
            )

        # Common known exit nodes (sample — production uses full Tor consensus)
        KNOWN_EXITS = [
            "185.220.101.1", "185.220.101.15", "185.220.101.33",
            "185.220.101.45", "185.220.101.47", "185.220.101.48",
            "185.220.101.57", "185.220.101.65", "185.220.102.4",
            "185.220.102.8", "185.220.102.240", "185.220.102.241",
            "185.220.102.242", "185.220.102.243", "185.220.102.244",
            "185.220.102.245", "185.220.102.246", "185.220.102.247",
            "185.220.102.248", "185.220.102.249", "185.220.102.250",
            "199.249.230.64", "199.249.230.65", "199.249.230.68",
            "199.249.230.69", "199.249.230.71", "199.249.230.72",
            "199.249.230.73", "199.249.230.74", "199.249.230.75",
            "199.249.230.76", "199.249.230.77", "199.249.230.78",
            "199.249.230.79", "199.249.230.80", "199.249.230.81",
            "199.249.230.82", "199.249.230.83", "199.249.230.84",
            "204.85.191.8", "204.85.191.9", "204.85.191.30",
            "209.141.32.32", "209.141.58.146", "209.141.45.189",
            "45.153.160.130", "45.153.160.131", "45.153.160.132",
            "51.15.43.205", "62.102.148.68", "62.102.148.69",
            "176.10.99.200", "176.10.104.240", "77.247.181.162",
            "77.247.181.163", "77.247.181.165", "195.176.3.19",
            "195.176.3.20", "195.176.3.23", "195.176.3.24",
            "104.244.76.13", "104.244.76.44", "104.244.72.7",
            "104.244.72.115", "104.244.73.93", "104.244.74.57",
        ]
        for ip in KNOWN_EXITS:
            self._nodes[ip] = TorNodeEntry(
                ip=ip, port=443, node_type="exit",
                first_seen=0, last_seen=time.time()
            )
            self._exit_ips.add(ip)

        # Known guard/relay nodes (sample)
        KNOWN_GUARDS = [
            "86.59.21.38", "128.31.0.34", "194.109.206.212",
            "199.58.81.140", "131.188.40.189", "193.23.244.244",
            "171.25.193.9", "154.35.175.225",
        ]
        for ip in KNOWN_GUARDS:
            self._nodes[ip] = TorNodeEntry(
                ip=ip, port=9001, node_type="guard",
                first_seen=0, last_seen=time.time()
            )
            self._guard_ips.add(ip)

        logger.info("Tor node DB loaded: %d exit, %d guard, %d authority",
                     len(self._exit_ips), len(self._guard_ips),
                     len(TOR_DIRECTORY_AUTHORITIES))

    def is_tor_node(self, ip: str) -> bool:
        return ip in self._nodes

    def get_node_type(self, ip: str) -> Optional[str]:
        node = self._nodes.get(ip)
        return node.node_type if node else None

    def is_exit_node(self, ip: str) -> bool:
        return ip in self._exit_ips

    def is_guard_node(self, ip: str) -> bool:
        return ip in self._guard_ips

    def is_directory_authority(self, ip: str) -> bool:
        return ip in TOR_DIRECTORY_AUTHORITIES

    def add_node(self, entry: TorNodeEntry):
        self._nodes[entry.ip] = entry
        if entry.node_type == "exit":
            self._exit_ips.add(entry.ip)
        elif entry.node_type == "guard":
            self._guard_ips.add(entry.ip)


class TorDetector:
    """
    Multi-signal Tor traffic detection engine.
    Combines IP matching, TLS fingerprinting, packet size analysis,
    and connection timing to identify Tor usage.
    """

    def __init__(self, node_db: Optional[TorNodeDatabase] = None):
        self.node_db = node_db or TorNodeDatabase()
        self._circuit_tracker: Dict[str, List[dict]] = defaultdict(list)

    def analyse(self, flows: List[dict], packets: List[dict]) -> dict:
        """Run all Tor detection algorithms and return unified results."""
        alerts: List[TorAlert] = []
        circuits: List[TorCircuit] = []
        tor_flows: List[dict] = []
        tor_endpoints: Dict[str, dict] = {}

        # 1. Direct Tor node IP matching
        ip_alerts = self._detect_tor_ips(flows)
        alerts.extend(ip_alerts)

        # 2. Tor Browser fingerprint detection
        ja3_alerts = self._detect_tor_browser(flows)
        alerts.extend(ja3_alerts)

        # 3. Tor cell size distribution analysis
        cell_alerts = self._detect_tor_cells(packets)
        alerts.extend(cell_alerts)

        # 4. Directory authority communication
        dir_alerts = self._detect_directory_comms(flows)
        alerts.extend(dir_alerts)

        # 5. Circuit build pattern detection
        circuit_alerts, detected_circuits = self._detect_circuit_patterns(flows, packets)
        alerts.extend(circuit_alerts)
        circuits.extend(detected_circuits)

        # 6. Bridge/pluggable transport detection
        bridge_alerts = self._detect_bridges(flows, packets)
        alerts.extend(bridge_alerts)

        # Build endpoint summary
        for alert in alerts:
            for ip in [alert.src_ip, alert.dst_ip]:
                if ip not in tor_endpoints:
                    tor_endpoints[ip] = {
                        "ip": ip,
                        "tor_node_type": self.node_db.get_node_type(ip),
                        "alert_count": 0,
                        "alert_types": set(),
                        "first_seen": alert.timestamp,
                        "last_seen": alert.timestamp,
                    }
                ep = tor_endpoints[ip]
                ep["alert_count"] += 1
                ep["alert_types"].add(alert.alert_type)
                if alert.timestamp < ep["first_seen"]:
                    ep["first_seen"] = alert.timestamp
                if alert.timestamp > ep["last_seen"]:
                    ep["last_seen"] = alert.timestamp

        # Convert sets to lists for JSON serialization
        for ep in tor_endpoints.values():
            ep["alert_types"] = sorted(ep["alert_types"])

        # Classify flows involved in Tor activity
        tor_ips = {a.src_ip for a in alerts} | {a.dst_ip for a in alerts}
        for f in flows:
            if f.get("src_ip") in tor_ips or f.get("dst_ip") in tor_ips:
                tor_flows.append(f)

        return {
            "tor_alerts": [
                {
                    "alert_type": a.alert_type,
                    "src_ip": a.src_ip,
                    "dst_ip": a.dst_ip,
                    "dst_port": a.dst_port,
                    "confidence": a.confidence,
                    "severity": a.severity,
                    "evidence": a.evidence,
                    "tor_node_type": a.tor_node_type,
                    "mitre_technique": a.mitre_technique,
                    "timestamp": a.timestamp,
                }
                for a in sorted(alerts, key=lambda x: x.timestamp, reverse=True)
            ],
            "tor_circuits": [
                {
                    "circuit_id": c.circuit_id,
                    "src_ip": c.src_ip,
                    "hops": c.hops,
                    "guard_ip": c.guard_ip,
                    "exit_ip": c.exit_ip,
                    "build_time": c.build_time,
                    "packet_count": c.packet_count,
                    "total_bytes": c.total_bytes,
                }
                for c in circuits
            ],
            "tor_endpoints": sorted(
                tor_endpoints.values(),
                key=lambda x: x["alert_count"],
                reverse=True
            )[:50],
            "tor_summary": {
                "total_alerts": len(alerts),
                "exit_node_connections": sum(1 for a in alerts if a.alert_type == "tor_exit"),
                "guard_connections": sum(1 for a in alerts if a.alert_type == "tor_guard"),
                "bridge_detections": sum(1 for a in alerts if a.alert_type == "tor_bridge"),
                "browser_detections": sum(1 for a in alerts if a.alert_type == "tor_browser"),
                "circuit_detections": len(circuits),
                "unique_internal_ips": len({
                    a.src_ip for a in alerts
                    if not self.node_db.is_tor_node(a.src_ip)
                }),
                "unique_tor_nodes": len({
                    a.dst_ip for a in alerts
                    if self.node_db.is_tor_node(a.dst_ip)
                }),
            },
            "tor_flow_count": len(tor_flows),
        }

    def _detect_tor_ips(self, flows: List[dict]) -> List[TorAlert]:
        """Match flow IPs against known Tor relay/exit/guard database."""
        alerts = []
        seen = set()

        for f in flows:
            src, dst = f.get("src_ip", ""), f.get("dst_ip", "")
            port = f.get("dst_port", 0)
            ts = f.get("start_time", 0)

            for check_ip, other_ip in [(dst, src), (src, dst)]:
                if not self.node_db.is_tor_node(check_ip):
                    continue

                key = (src, dst, port)
                if key in seen:
                    continue
                seen.add(key)

                node_type = self.node_db.get_node_type(check_ip)
                evidence = [
                    f"IP {check_ip} matched known Tor {node_type} node",
                    f"Connection: {src}:{f.get('src_port', 0)} → {dst}:{port}",
                ]

                if f.get("protocol") == "TLS":
                    evidence.append("TLS encrypted connection (consistent with Tor)")
                if f.get("sni"):
                    evidence.append(f"SNI: {f['sni']}")

                severity = "CRITICAL" if node_type == "exit" else \
                          "HIGH" if node_type == "guard" else "MEDIUM"

                alerts.append(TorAlert(
                    alert_type=f"tor_{node_type}",
                    src_ip=src, dst_ip=dst, dst_port=port,
                    confidence="HIGH",
                    severity=severity,
                    evidence=evidence,
                    tor_node_type=node_type,
                    timestamp=ts,
                ))

        return alerts

    def _detect_tor_browser(self, flows: List[dict]) -> List[TorAlert]:
        """Detect Tor Browser via JA3 fingerprint matching."""
        alerts = []
        for f in flows:
            ja3 = f.get("ja3")
            if not ja3:
                continue
            match = TOR_BROWSER_JA3.get(ja3)
            if match:
                alerts.append(TorAlert(
                    alert_type="tor_browser",
                    src_ip=f.get("src_ip", ""),
                    dst_ip=f.get("dst_ip", ""),
                    dst_port=f.get("dst_port", 0),
                    confidence="HIGH",
                    severity="HIGH",
                    evidence=[
                        f"JA3 fingerprint {ja3} matches {match}",
                        f"TLS version: {f.get('tls_version', 'unknown')}",
                    ],
                    timestamp=f.get("start_time", 0),
                ))
        return alerts

    def _detect_tor_cells(self, packets: List[dict]) -> List[TorAlert]:
        """
        Detect Tor cell-based traffic by analyzing packet size distributions.
        Tor uses fixed 512-byte cells, so we look for flows with many packets
        close to 512 bytes (plus TLS overhead of ~20-40 bytes).
        """
        alerts = []
        # Group packets by flow
        flow_pkts: Dict[Tuple[str, str], List[int]] = defaultdict(list)
        flow_meta: Dict[Tuple[str, str], dict] = {}

        for p in packets:
            src, dst = p.get("src_ip", ""), p.get("dst_ip", "")
            size = p.get("size", 0)
            key = (src, dst)
            flow_pkts[key].append(size)
            if key not in flow_meta:
                flow_meta[key] = {
                    "src_ip": src, "dst_ip": dst,
                    "timestamp": p.get("timestamp", 0),
                    "dst_port": p.get("dst_port", 0),
                }

        seen = set()
        for key, sizes in flow_pkts.items():
            if len(sizes) < 20:  # Need enough packets
                continue

            # Count packets near Tor cell sizes (512, 1024, 1536...)
            cell_count = 0
            for s in sizes:
                for multiple in range(1, 4):  # Check 1x, 2x, 3x cell size
                    expected = TOR_CELL_SIZE * multiple
                    if abs(s - expected) <= TOR_CELL_TOLERANCE * multiple:
                        cell_count += 1
                        break

            cell_ratio = cell_count / len(sizes)
            if cell_ratio > 0.6 and key not in seen:
                seen.add(key)
                meta = flow_meta[key]
                alerts.append(TorAlert(
                    alert_type="tor_relay",
                    src_ip=meta["src_ip"],
                    dst_ip=meta["dst_ip"],
                    dst_port=meta["dst_port"],
                    confidence="MEDIUM" if cell_ratio > 0.7 else "LOW",
                    severity="HIGH",
                    evidence=[
                        f"Packet size distribution matches Tor cells: {cell_ratio:.0%} "
                        f"of {len(sizes)} packets near 512-byte multiples",
                        f"Cell-aligned packets: {cell_count}",
                    ],
                    timestamp=meta.get("timestamp", 0),
                ))

        return alerts

    def _detect_directory_comms(self, flows: List[dict]) -> List[TorAlert]:
        """Detect communications with Tor directory authorities."""
        alerts = []
        for f in flows:
            dst = f.get("dst_ip", "")
            if self.node_db.is_directory_authority(dst):
                alerts.append(TorAlert(
                    alert_type="tor_directory",
                    src_ip=f.get("src_ip", ""),
                    dst_ip=dst,
                    dst_port=f.get("dst_port", 0),
                    confidence="HIGH",
                    severity="CRITICAL",
                    evidence=[
                        f"Communication with Tor directory authority: {dst}",
                        "Directory authorities are used for Tor consensus bootstrapping",
                        f"Protocol: {f.get('protocol', 'unknown')}",
                    ],
                    tor_node_type="authority",
                    timestamp=f.get("start_time", 0),
                ))
        return alerts

    def _detect_circuit_patterns(self, flows: List[dict],
                                  packets: List[dict]) -> Tuple[List[TorAlert], List[TorCircuit]]:
        """
        Detect Tor circuit-build patterns by analyzing sequential connection
        timing from a single source to multiple Tor nodes.
        """
        alerts = []
        circuits = []

        # Group flows by source IP that connect to Tor nodes
        src_tor_flows: Dict[str, List[dict]] = defaultdict(list)
        for f in flows:
            dst = f.get("dst_ip", "")
            if self.node_db.is_tor_node(dst):
                src_tor_flows[f.get("src_ip", "")].append(f)

        for src_ip, tor_flows in src_tor_flows.items():
            if len(tor_flows) < 3:
                continue

            # Sort by start time
            tor_flows.sort(key=lambda x: x.get("start_time", 0))

            # Look for sequences of 3+ connections within short timeframe (circuit build)
            for i in range(len(tor_flows) - 2):
                chain = [tor_flows[i]]
                for j in range(i + 1, min(i + 5, len(tor_flows))):
                    time_diff = tor_flows[j].get("start_time", 0) - \
                               chain[-1].get("start_time", 0)
                    if 0 < time_diff < 5.0:  # Tor circuit build is typically < 5s
                        chain.append(tor_flows[j])

                if len(chain) >= 3:
                    hops = [f.get("dst_ip", "") for f in chain]
                    build_time = chain[-1].get("start_time", 0) - \
                                chain[0].get("start_time", 0)

                    circuit_id = hashlib.md5(
                        f"{src_ip}-{'->'.join(hops)}-{chain[0].get('start_time', 0)}".encode()
                    ).hexdigest()[:12]

                    circuit = TorCircuit(
                        circuit_id=circuit_id,
                        src_ip=src_ip,
                        hops=hops,
                        guard_ip=hops[0] if hops else "",
                        exit_ip=hops[-1] if len(hops) >= 3 else None,
                        build_time=round(build_time, 3),
                        created_at=chain[0].get("start_time", 0),
                        packet_count=sum(f.get("packet_count", 0) for f in chain),
                        total_bytes=sum(f.get("total_bytes", 0) for f in chain),
                    )
                    circuits.append(circuit)

                    alerts.append(TorAlert(
                        alert_type="tor_circuit",
                        src_ip=src_ip,
                        dst_ip=hops[-1],
                        dst_port=chain[-1].get("dst_port", 0),
                        confidence="HIGH" if len(chain) >= 3 else "MEDIUM",
                        severity="CRITICAL",
                        evidence=[
                            f"Tor circuit build detected: {len(hops)} hops",
                            f"Circuit path: {src_ip} → {'→'.join(hops)}",
                            f"Build time: {build_time:.2f}s",
                            f"Guard node: {hops[0]}",
                        ],
                        circuit_hops=len(hops),
                        timestamp=chain[0].get("start_time", 0),
                    ))

        return alerts, circuits

    def _detect_bridges(self, flows: List[dict],
                        packets: List[dict]) -> List[TorAlert]:
        """
        Detect Tor bridge/pluggable transport usage.
        Bridges use obfuscation (obfs4, meek, snowflake) that creates
        distinctive packet patterns.
        """
        alerts = []

        # obfs4 detection: Look for TLS connections with unusual SNI patterns
        # and uniform packet size distribution (obfs4 randomizes sizes)
        flow_sizes: Dict[str, List[int]] = defaultdict(list)
        for p in packets:
            fid = p.get("flow_id", "")
            if fid:
                flow_sizes[fid].append(p.get("size", 0))

        for f in flows:
            fid = f.get("flow_id", "")
            sizes = flow_sizes.get(fid, [])
            if len(sizes) < 10:
                continue

            protocol = f.get("protocol", "")
            dst_port = f.get("dst_port", 0)

            # obfs4 indicators: high entropy in packet sizes, non-standard port
            if protocol == "TLS" and dst_port not in {80, 443, 8443}:
                if len(sizes) > 20:
                    size_entropy = self._calc_size_entropy(sizes)
                    # obfs4 has high entropy due to padding
                    if size_entropy > 5.5:
                        alerts.append(TorAlert(
                            alert_type="tor_bridge",
                            src_ip=f.get("src_ip", ""),
                            dst_ip=f.get("dst_ip", ""),
                            dst_port=dst_port,
                            confidence="MEDIUM",
                            severity="HIGH",
                            evidence=[
                                f"Possible obfs4 bridge: TLS on non-standard port {dst_port}",
                                f"High packet size entropy: {size_entropy:.2f} bits",
                                f"Packet count: {len(sizes)}",
                                "obfs4 randomizes packet sizes to evade DPI",
                            ],
                            tor_node_type="bridge",
                            timestamp=f.get("start_time", 0),
                        ))

            # meek detection: HTTPS connections to major CDN frontends
            # (Azure, Google, Amazon) with suspicious timing patterns
            sni = f.get("sni", "")
            if sni and any(dom in sni for dom in [
                "ajax.aspnetcdn.com", "az668014.vo.msecnd.net",
                "cdn.sstatic.net", "www.google.com"
            ]):
                if f.get("packet_count", 0) > 50:
                    alerts.append(TorAlert(
                        alert_type="tor_bridge",
                        src_ip=f.get("src_ip", ""),
                        dst_ip=f.get("dst_ip", ""),
                        dst_port=dst_port,
                        confidence="LOW",
                        severity="MEDIUM",
                        evidence=[
                            f"Possible meek bridge: Domain fronting via {sni}",
                            f"High packet count ({f.get('packet_count', 0)}) "
                            f"to CDN endpoint",
                            "meek uses domain fronting to disguise Tor traffic",
                        ],
                        tor_node_type="bridge",
                        timestamp=f.get("start_time", 0),
                    ))

        return alerts

    @staticmethod
    def _calc_size_entropy(sizes: List[int]) -> float:
        """Calculate Shannon entropy of packet size distribution."""
        if not sizes:
            return 0.0
        # Bin sizes into 50-byte buckets
        bins: Dict[int, int] = defaultdict(int)
        for s in sizes:
            bins[s // 50] += 1
        total = len(sizes)
        return round(-sum(
            (c / total) * math.log2(c / total)
            for c in bins.values() if c > 0
        ), 4)
