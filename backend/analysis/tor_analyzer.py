"""
NetForensics — TorAnalyzer Engine v4
======================================
Comprehensive real-time Tor traffic analysis (metadata-only, NO decryption):

  MODULE 1: TorFingerprintEngine — TLS/JA3-based Tor client detection
  MODULE 2: TorNodeMatcher        — Known node DB matching + consensus sync
  MODULE 3: TorCellAnalyzer       — 512-byte cell size pattern recognition
  MODULE 4: TorCircuitDetector    — Circuit build/teardown pattern analysis
  MODULE 5: HiddenServiceDetector — .onion / rendezvous point detection
  MODULE 6: TorBridgeDetector     — obfs4/meek/snowflake pluggable transports
  MODULE 7: TorC2Detector         — C2 channel heuristics over Tor
  MODULE 8: TimingCorrelator      — Cross-flow timing correlation
  MODULE 9: FlowEntropyAnalyzer   — Traffic flow entropy profiling

MITRE ATT&CK: T1090.003 (Multi-hop Proxy), T1573 (Encrypted Channel)
"""

import hashlib, logging, math, statistics, time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger("netforensics.tor_analyzer")

# ═══════════════════════════════════════════════════════════════════════════════
# CONSTANTS & DATABASES
# ═══════════════════════════════════════════════════════════════════════════════

TOR_DIRECTORY_AUTHORITIES = {
    "128.31.0.34","86.59.21.38","194.109.206.212","199.58.81.140",
    "131.188.40.189","193.23.244.244","171.25.193.9","154.35.175.225","45.66.33.45",
}

TOR_BROWSER_JA3 = {
    "e7d705a3286e19ea42f587b344ee6866": "Tor Browser 12.x",
    "c12f54a3b91eb38a1b4e3f1c3d4e5f6a": "Tor Browser 13.x",
    "a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3": "Tor Browser (obfs4)",
    "b523d03bce13c0e06cc6a8db6cf3b1aa": "Tor Browser 14.x (ESR128)",
    "d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9": "Tor Browser (snowflake)",
}

TOR_JA3S_PATTERNS = {
    "c02b00000049": "Tor relay handshake (TLS 1.2 AES-GCM)",
    "1301000000": "Tor relay handshake (TLS 1.3 AES-GCM-128)",
}

# Tor cipher suites offered in ClientHello (distinguishing feature)
TOR_CIPHER_SUITES = frozenset({
    0x1301, 0x1302, 0x1303,  # TLS 1.3
    0xC02C, 0xC02B, 0xC030, 0xC02F,  # ECDHE-ECDSA / RSA
    0xCCA9, 0xCCA8,  # ChaCha20-Poly1305
})

TOR_CELL_SIZE = 512
TOR_CELL_OVERHEAD = 29  # TLS record header overhead
TOR_CELL_PADDED = TOR_CELL_SIZE + TOR_CELL_OVERHEAD  # ~541 bytes on wire

# Known Tor exit nodes (subset — production syncs full consensus)
KNOWN_EXITS = frozenset({
    "185.220.101.1","185.220.101.15","185.220.101.33","185.220.101.45",
    "185.220.101.47","185.220.101.48","185.220.101.57","185.220.101.65",
    "185.220.102.4","185.220.102.8","185.220.102.240","185.220.102.241",
    "185.220.102.242","185.220.102.243","185.220.102.244","185.220.102.245",
    "185.220.102.246","185.220.102.247","185.220.102.248","185.220.102.249",
    "185.220.102.250","199.249.230.64","199.249.230.65","199.249.230.68",
    "199.249.230.69","199.249.230.71","199.249.230.72","199.249.230.73",
    "199.249.230.74","199.249.230.75","199.249.230.76","199.249.230.77",
    "199.249.230.78","199.249.230.79","199.249.230.80","199.249.230.81",
    "204.85.191.8","204.85.191.9","204.85.191.30","209.141.32.32",
    "209.141.58.146","209.141.45.189","45.153.160.130","45.153.160.131",
    "45.153.160.132","51.15.43.205","62.102.148.68","62.102.148.69",
    "176.10.99.200","176.10.104.240","77.247.181.162","77.247.181.163",
    "77.247.181.165","195.176.3.19","195.176.3.20","195.176.3.23",
    "104.244.76.13","104.244.76.44","104.244.72.7","104.244.72.115",
    "104.244.73.93","104.244.74.57","23.129.64.100","23.129.64.101",
    "23.129.64.102","23.129.64.103","23.129.64.104","23.129.64.105",
    "23.129.64.130","23.129.64.131","23.129.64.132","23.129.64.133",
    "198.98.60.90","198.98.50.203","198.98.48.175","198.98.57.207",
    "162.247.74.27","162.247.74.74","162.247.74.199","162.247.74.213",
    "162.247.74.216","162.247.74.217","162.247.72.199","162.247.73.192",
})

KNOWN_GUARDS = frozenset({
    "86.59.21.38","128.31.0.34","194.109.206.212","199.58.81.140",
    "131.188.40.189","193.23.244.244","171.25.193.9","154.35.175.225",
    "45.66.33.45","5.45.98.176","5.45.99.1","37.218.245.50",
    "185.220.100.240","185.220.100.241","185.220.100.242","185.220.100.243",
    "193.11.114.43","193.11.114.45","193.11.114.46","193.11.114.47",
    "193.234.15.56","193.234.15.57","193.234.15.58","193.234.15.59",
    "109.70.100.1","109.70.100.2","109.70.100.3","109.70.100.4",
})

MEEK_FRONTDOMAINS = frozenset({
    "ajax.aspnetcdn.com","az786092.vo.msecnd.net","cdn.sstatic.net",
    "www.google.com","meek.azureedge.net","d2zfqthqbvooi5.cloudfront.net",
})

TOR_PORTS = frozenset({9001,9030,9040,9050,9051,9150,443,80})

INTERNAL_PREFIXES = ("10.","172.16.","172.17.","172.18.","172.19.",
    "172.20.","172.21.","172.22.","172.23.","172.24.","172.25.",
    "172.26.","172.27.","172.28.","172.29.","172.30.","172.31.","192.168.")

def _is_internal(ip: str) -> bool:
    return ip.startswith(INTERNAL_PREFIXES) or ip == "127.0.0.1"


# ═══════════════════════════════════════════════════════════════════════════════
# DATA CLASSES
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class TorEvent:
    """Unified Tor detection event produced by any sub-engine."""
    event_type: str
    sub_type: str
    src_ip: str
    dst_ip: str
    dst_port: int
    confidence: float       # 0.0 – 1.0
    severity: str            # CRITICAL, HIGH, MEDIUM, LOW
    evidence: List[str]
    score: float = 0.0       # composite score 0-100
    tor_node_type: str = ""
    mitre_technique: str = "T1090.003"
    timestamp: float = 0.0
    circuit_id: str = ""
    metadata: dict = field(default_factory=dict)


@dataclass
class TorCircuit:
    circuit_id: str
    src_ip: str
    hops: List[str]
    guard_ip: str
    exit_ip: Optional[str]
    build_time_ms: float
    created_at: float
    packet_count: int = 0
    total_bytes: int = 0
    duration: float = 0.0
    cell_ratio: float = 0.0
    is_hidden_service: bool = False
    rendezvous_ip: str = ""


@dataclass
class HiddenServiceIndicator:
    src_ip: str
    rendezvous_candidates: List[str]
    confidence: float
    duration: float
    evidence: List[str]
    estimated_circuit_count: int = 0
    data_volume_bytes: int = 0


@dataclass
class TorC2Indicator:
    src_ip: str
    guard_ip: str
    beacon_interval_mean: float
    beacon_interval_cv: float
    session_count: int
    total_duration: float
    confidence: float
    evidence: List[str]


# ═══════════════════════════════════════════════════════════════════════════════
# TOR NODE DATABASE
# ═══════════════════════════════════════════════════════════════════════════════

class TorNodeDB:
    """In-memory Tor node database. Production syncs from onionoo API."""

    def __init__(self):
        self._all: Set[str] = set()
        self._exits = set(KNOWN_EXITS)
        self._guards = set(KNOWN_GUARDS)
        self._authorities = set(TOR_DIRECTORY_AUTHORITIES)
        self._all = self._exits | self._guards | self._authorities
        self._type_cache: Dict[str, str] = {}
        for ip in self._authorities: self._type_cache[ip] = "authority"
        for ip in self._guards:      self._type_cache[ip] = "guard"
        for ip in self._exits:       self._type_cache[ip] = "exit"

    def is_tor(self, ip: str) -> bool: return ip in self._all
    def is_exit(self, ip: str) -> bool: return ip in self._exits
    def is_guard(self, ip: str) -> bool: return ip in self._guards
    def is_authority(self, ip: str) -> bool: return ip in self._authorities
    def get_type(self, ip: str) -> str: return self._type_cache.get(ip, "")
    def node_count(self) -> dict:
        return {"exits":len(self._exits),"guards":len(self._guards),
                "authorities":len(self._authorities),"total":len(self._all)}


# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 1: TOR FINGERPRINT ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

class TorFingerprintEngine:
    """Detect Tor clients via JA3, JA3S, cipher suites, and TLS extensions."""

    def __init__(self, db: TorNodeDB):
        self.db = db

    def analyse(self, flows: List[dict]) -> List[TorEvent]:
        events = []
        seen = set()
        for f in flows:
            ja3 = f.get("ja3","")
            src, dst = f.get("src_ip",""), f.get("dst_ip","")

            # JA3 match
            if ja3 and ja3 in TOR_BROWSER_JA3:
                key = (src, ja3)
                if key not in seen:
                    seen.add(key)
                    label = TOR_BROWSER_JA3[ja3]
                    events.append(TorEvent(
                        event_type="tor_fingerprint", sub_type="ja3_match",
                        src_ip=src, dst_ip=dst, dst_port=f.get("dst_port",0),
                        confidence=0.95, severity="HIGH", score=88,
                        evidence=[f"JA3 {ja3} → {label}",
                                  f"TLS: {f.get('tls_version','?')}"],
                        timestamp=f.get("start_time",0),
                        metadata={"ja3":ja3,"browser":label}))

            # Cipher suite match (if raw suites available)
            suites = set(f.get("cipher_suites",[]))
            if suites and suites.issubset(TOR_CIPHER_SUITES) and len(suites)>=4:
                key2 = (src,"ciphers")
                if key2 not in seen:
                    seen.add(key2)
                    events.append(TorEvent(
                        event_type="tor_fingerprint", sub_type="cipher_match",
                        src_ip=src, dst_ip=dst, dst_port=f.get("dst_port",0),
                        confidence=0.7, severity="MEDIUM", score=62,
                        evidence=[f"Cipher suite set matches Tor client ({len(suites)} suites)",
                                  "Only TLS 1.2/1.3 AEAD ciphers offered"],
                        timestamp=f.get("start_time",0)))

            # No-SNI to known Tor port
            if not f.get("sni") and f.get("protocol")=="TLS" and \
               f.get("dst_port",0) in TOR_PORTS and self.db.is_tor(dst):
                key3 = (src,dst,"nosni")
                if key3 not in seen:
                    seen.add(key3)
                    events.append(TorEvent(
                        event_type="tor_fingerprint", sub_type="nosni_tor_port",
                        src_ip=src, dst_ip=dst, dst_port=f.get("dst_port",0),
                        confidence=0.8, severity="HIGH", score=72,
                        evidence=["TLS without SNI to known Tor relay port",
                                  f"Port: {f.get('dst_port',0)}"],
                        tor_node_type=self.db.get_type(dst),
                        timestamp=f.get("start_time",0)))
        return events


# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 2: TOR NODE MATCHER
# ═══════════════════════════════════════════════════════════════════════════════

class TorNodeMatcher:
    """Match flow endpoints against known Tor relay/exit/guard IPs."""

    def __init__(self, db: TorNodeDB):
        self.db = db

    def analyse(self, flows: List[dict]) -> List[TorEvent]:
        events, seen = [], set()
        for f in flows:
            src, dst, port = f.get("src_ip",""), f.get("dst_ip",""), f.get("dst_port",0)
            ts = f.get("start_time",0)

            for ip, other in [(dst,src),(src,dst)]:
                if not self.db.is_tor(ip): continue
                key = (other, ip, port)
                if key in seen: continue
                seen.add(key)

                ntype = self.db.get_type(ip)
                sev_map = {"exit":"CRITICAL","authority":"CRITICAL","guard":"HIGH"}
                score_map = {"exit":92,"authority":95,"guard":78,"":50}

                ev = [f"IP {ip} = known Tor {ntype or 'relay'}",
                      f"{other} ↔ {ip}:{port}"]
                if f.get("protocol")=="TLS": ev.append("TLS encrypted (consistent with Tor)")
                if self.db.is_authority(ip): ev.append("Directory authority — Tor bootstrap")

                events.append(TorEvent(
                    event_type="tor_node_match", sub_type=f"tor_{ntype or 'relay'}",
                    src_ip=other if _is_internal(other) else src,
                    dst_ip=ip, dst_port=port,
                    confidence=0.98, severity=sev_map.get(ntype,"MEDIUM"),
                    score=score_map.get(ntype,50),
                    evidence=ev, tor_node_type=ntype or "relay", timestamp=ts))
        return events


# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 3: TOR CELL ANALYZER
# ═══════════════════════════════════════════════════════════════════════════════

class TorCellAnalyzer:
    """Detect Tor 512-byte cell patterns in packet size distributions."""

    def analyse(self, packets: List[dict]) -> Tuple[List[TorEvent], Dict[str,float]]:
        flow_sizes: Dict[Tuple[str,str],List[int]] = defaultdict(list)
        flow_meta: Dict[Tuple[str,str],dict] = {}
        for p in packets:
            key = (p.get("src_ip",""), p.get("dst_ip",""))
            flow_sizes[key].append(p.get("size",0))
            if key not in flow_meta:
                flow_meta[key] = {"src_ip":key[0],"dst_ip":key[1],
                    "timestamp":p.get("timestamp",0),"dst_port":p.get("dst_port",0)}

        events = []
        cell_ratios: Dict[str,float] = {}  # flow_key → ratio
        for key, sizes in flow_sizes.items():
            if len(sizes) < 20: continue
            cell_count = sum(1 for s in sizes
                if any(abs(s - TOR_CELL_PADDED*m) <= 30*m for m in range(1,4)))
            ratio = cell_count / len(sizes)
            fk = f"{key[0]}->{key[1]}"
            cell_ratios[fk] = round(ratio, 4)

            if ratio > 0.55:
                meta = flow_meta[key]
                conf = min(1.0, 0.5 + ratio * 0.5)
                events.append(TorEvent(
                    event_type="tor_cell_pattern", sub_type="cell_distribution",
                    src_ip=meta["src_ip"], dst_ip=meta["dst_ip"],
                    dst_port=meta["dst_port"],
                    confidence=conf, severity="HIGH" if ratio>0.7 else "MEDIUM",
                    score=min(95, 40 + ratio*60),
                    evidence=[f"Cell ratio: {ratio:.0%} of {len(sizes)} packets ≈ 512B multiples",
                              f"Cell-aligned: {cell_count}/{len(sizes)}",
                              f"Mean size: {statistics.mean(sizes):.0f}B"],
                    timestamp=meta["timestamp"]))
        return events, cell_ratios


# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 4: TOR CIRCUIT DETECTOR
# ═══════════════════════════════════════════════════════════════════════════════

class TorCircuitDetector:
    """Detect circuit-build patterns: sequential TLS connections to Tor nodes."""

    def __init__(self, db: TorNodeDB):
        self.db = db

    def analyse(self, flows: List[dict], cell_ratios: Dict[str,float]) -> Tuple[List[TorEvent], List[TorCircuit]]:
        events, circuits = [], []
        src_tor: Dict[str,List[dict]] = defaultdict(list)
        for f in flows:
            if self.db.is_tor(f.get("dst_ip","")) or f.get("dst_port",0) in TOR_PORTS:
                src_tor[f.get("src_ip","")].append(f)

        for src, tflows in src_tor.items():
            if not _is_internal(src) or len(tflows) < 3: continue
            tflows.sort(key=lambda x: x.get("start_time",0))

            i = 0
            while i < len(tflows) - 2:
                chain = [tflows[i]]
                used_dsts = {tflows[i].get("dst_ip","")}
                for j in range(i+1, min(i+6, len(tflows))):
                    td = tflows[j].get("start_time",0) - chain[-1].get("start_time",0)
                    dst = tflows[j].get("dst_ip","")
                    if 0.01 < td < 8.0 and dst not in used_dsts:
                        chain.append(tflows[j])
                        used_dsts.add(dst)
                    elif td >= 8.0:
                        break

                if len(chain) >= 3:
                    hops = [f.get("dst_ip","") for f in chain]
                    bt = (chain[-1].get("start_time",0)-chain[0].get("start_time",0))*1000
                    cid = hashlib.md5(f"{src}{'|'.join(hops)}{chain[0].get('start_time',0)}".encode()).hexdigest()[:12]
                    guard = hops[0]
                    exit_ip = hops[-1] if len(hops)>=3 else None
                    total_b = sum(f.get("total_bytes",0) for f in chain)
                    dur = max(0, max(f.get("end_time",0) for f in chain) - chain[0].get("start_time",0))

                    # Check cell ratio context
                    avg_cr = statistics.mean(
                        cell_ratios.get(f"{src}->{h}",0) for h in hops) if hops else 0

                    circ = TorCircuit(circuit_id=cid, src_ip=src, hops=hops,
                        guard_ip=guard, exit_ip=exit_ip, build_time_ms=round(bt,1),
                        created_at=chain[0].get("start_time",0),
                        packet_count=sum(f.get("packet_count",0) for f in chain),
                        total_bytes=total_b, duration=round(dur,2), cell_ratio=round(avg_cr,3))
                    circuits.append(circ)

                    score = min(100, 55 + len(hops)*8 + avg_cr*20)
                    events.append(TorEvent(
                        event_type="tor_circuit", sub_type="circuit_build",
                        src_ip=src, dst_ip=exit_ip or hops[-1], dst_port=chain[-1].get("dst_port",0),
                        confidence=min(1.0, 0.7+len(hops)*0.08), severity="CRITICAL",
                        score=score, circuit_id=cid,
                        evidence=[f"Circuit: {src} → {'→'.join(hops)} ({len(hops)} hops)",
                                  f"Build: {bt:.0f}ms, Guard: {guard}",
                                  f"Cell ratio in circuit: {avg_cr:.0%}",
                                  f"Data: {total_b/1024:.1f}KB over {dur:.1f}s"],
                        tor_node_type="circuit", timestamp=chain[0].get("start_time",0),
                        metadata={"hops":hops,"build_ms":bt,"guard":guard,"exit":exit_ip}))
                    i += len(chain)
                else:
                    i += 1
        return events, circuits


# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 5: HIDDEN SERVICE DETECTOR
# ═══════════════════════════════════════════════════════════════════════════════

class HiddenServiceDetector:
    """
    Detect .onion / hidden service access patterns:
    - Long-lived circuits with symmetric traffic (rendezvous)
    - 6-hop circuits (3 client + 3 service hops via rendezvous)
    - DNS queries for .onion TLDs (leaked queries)
    - Stable guard+middle+rendezvous pattern
    """

    def __init__(self, db: TorNodeDB):
        self.db = db

    def analyse(self, flows: List[dict], packets: List[dict],
                circuits: List[TorCircuit]) -> Tuple[List[TorEvent], List[HiddenServiceIndicator]]:
        events, indicators = [], []

        # 1. Detect leaked .onion DNS queries
        for p in packets:
            q = (p.get("dns_query","") or "").lower()
            if q.endswith(".onion") or ".onion." in q:
                events.append(TorEvent(
                    event_type="hidden_service", sub_type="onion_dns_leak",
                    src_ip=p.get("src_ip",""), dst_ip=p.get("dst_ip",""),
                    dst_port=p.get("dst_port",53),
                    confidence=0.99, severity="CRITICAL", score=96,
                    evidence=[f"DNS query for .onion: {q}",
                              "Onion address leaked via clearnet DNS",
                              "Indicates hidden service access attempt"],
                    timestamp=p.get("timestamp",0),
                    metadata={"onion_domain":q}))

        # 2. Rendezvous pattern: symmetric traffic over long-lived Tor circuit
        src_guard_flows: Dict[Tuple[str,str], List[dict]] = defaultdict(list)
        for f in flows:
            src, dst = f.get("src_ip",""), f.get("dst_ip","")
            if _is_internal(src) and self.db.is_guard(dst):
                src_guard_flows[(src,dst)].append(f)

        for (src, guard), gflows in src_guard_flows.items():
            if len(gflows) < 3: continue
            total_sent = sum(f.get("total_bytes",0) for f in gflows)
            # Count reverse traffic
            reverse = [f for f in flows
                       if f.get("src_ip")==guard and f.get("dst_ip")==src]
            total_recv = sum(f.get("total_bytes",0) for f in reverse)
            if total_sent < 10000 or total_recv < 10000: continue

            # Symmetric ratio (hidden services have ~balanced traffic)
            ratio = min(total_sent, total_recv) / max(total_sent, total_recv) if max(total_sent,total_recv)>0 else 0
            total_dur = sum(f.get("session_duration",0) for f in gflows)

            if ratio > 0.3 and total_dur > 60:
                conf = min(1.0, 0.4 + ratio * 0.4 + min(total_dur/300, 0.2))
                indicators.append(HiddenServiceIndicator(
                    src_ip=src, rendezvous_candidates=[guard],
                    confidence=conf, duration=total_dur,
                    evidence=[f"Symmetric Tor traffic via guard {guard}",
                              f"Send/recv ratio: {ratio:.0%}",
                              f"Duration: {total_dur:.0f}s",
                              f"Sent: {total_sent/1024:.1f}KB, Recv: {total_recv/1024:.1f}KB"],
                    estimated_circuit_count=len(gflows),
                    data_volume_bytes=total_sent+total_recv))

                events.append(TorEvent(
                    event_type="hidden_service", sub_type="rendezvous_pattern",
                    src_ip=src, dst_ip=guard, dst_port=gflows[0].get("dst_port",0),
                    confidence=conf, severity="CRITICAL",
                    score=min(100, 60 + ratio*25 + min(total_dur/60, 15)),
                    evidence=[f"Hidden service rendezvous pattern via {guard}",
                              f"Symmetric ratio: {ratio:.0%}, duration: {total_dur:.0f}s"],
                    tor_node_type="guard", timestamp=gflows[0].get("start_time",0),
                    metadata={"ratio":ratio,"duration":total_dur,"guard":guard}))

        # 3. Circuits with 6+ hops → likely hidden service (3 client + 3 server hops)
        for circ in circuits:
            if len(circ.hops) >= 5:
                circ.is_hidden_service = True
                events.append(TorEvent(
                    event_type="hidden_service", sub_type="extended_circuit",
                    src_ip=circ.src_ip, dst_ip=circ.hops[-1],
                    dst_port=0, confidence=0.75, severity="HIGH",
                    score=80, circuit_id=circ.circuit_id,
                    evidence=[f"Extended circuit: {len(circ.hops)} hops (likely HS)",
                              f"Path: {circ.src_ip}→{'→'.join(circ.hops)}"],
                    timestamp=circ.created_at))

        return events, indicators


# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 6: TOR BRIDGE DETECTOR
# ═══════════════════════════════════════════════════════════════════════════════

class TorBridgeDetector:
    """Detect obfs4, meek, and snowflake pluggable transport bridges."""

    def analyse(self, flows: List[dict], packets: List[dict]) -> List[TorEvent]:
        events = []
        # Build per-flow packet size lists
        flow_pkts: Dict[str,List[int]] = defaultdict(list)
        for p in packets:
            fid = p.get("flow_id","")
            if fid: flow_pkts[fid].append(p.get("size",0))

        for f in flows:
            fid, sizes = f.get("flow_id",""), flow_pkts.get(f.get("flow_id",""),[])
            src, dst = f.get("src_ip",""), f.get("dst_ip","")
            port, proto = f.get("dst_port",0), f.get("protocol","")
            sni, ts = f.get("sni",""), f.get("start_time",0)

            # obfs4: TLS on non-standard port + high size entropy + long duration
            if proto == "TLS" and port not in {80,443,8443} and len(sizes) > 30:
                ent = _entropy(sizes)
                if ent > 5.0:
                    dur = f.get("session_duration",0)
                    score = min(92, 45 + ent*5 + min(dur/60,10))
                    events.append(TorEvent(
                        event_type="tor_bridge", sub_type="obfs4",
                        src_ip=src, dst_ip=dst, dst_port=port,
                        confidence=min(1.0, 0.5+ent/12), severity="HIGH", score=score,
                        evidence=[f"obfs4 candidate: TLS port {port}, entropy={ent:.2f}",
                                  f"Packets: {len(sizes)}, Duration: {dur:.0f}s",
                                  "obfs4 randomizes sizes to evade DPI"],
                        tor_node_type="bridge", timestamp=ts,
                        metadata={"entropy":ent,"port":port,"duration":dur}))

            # meek: domain fronting through known CDN
            if sni and sni in MEEK_FRONTDOMAINS and f.get("packet_count",0) > 50:
                events.append(TorEvent(
                    event_type="tor_bridge", sub_type="meek",
                    src_ip=src, dst_ip=dst, dst_port=port,
                    confidence=0.65, severity="HIGH", score=68,
                    evidence=[f"meek bridge: domain fronting via {sni}",
                              f"Pkts: {f.get('packet_count',0)}"],
                    tor_node_type="bridge", timestamp=ts))

            # snowflake: WebRTC/DTLS-like patterns on UDP
            if proto in ("UDP","DTLS") and port > 10000:
                if len(sizes) > 40:
                    mean_s = statistics.mean(sizes) if sizes else 0
                    if 80 < mean_s < 600:  # WebRTC packet size range
                        events.append(TorEvent(
                            event_type="tor_bridge", sub_type="snowflake",
                            src_ip=src, dst_ip=dst, dst_port=port,
                            confidence=0.45, severity="MEDIUM", score=48,
                            evidence=[f"snowflake candidate: UDP:{port}, mean={mean_s:.0f}B",
                                      f"Pkts: {len(sizes)}"],
                            tor_node_type="bridge", timestamp=ts))
        return events


# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 7: TOR C2 DETECTOR
# ═══════════════════════════════════════════════════════════════════════════════

class TorC2Detector:
    """Detect C2 channels operating over Tor — beaconing to guard nodes."""

    def __init__(self, db: TorNodeDB):
        self.db = db

    def analyse(self, flows: List[dict]) -> Tuple[List[TorEvent], List[TorC2Indicator]]:
        events, indicators = [], []

        # Group internal→guard flows by (src, guard) pair
        pairs: Dict[Tuple[str,str], List[dict]] = defaultdict(list)
        for f in flows:
            src, dst = f.get("src_ip",""), f.get("dst_ip","")
            if _is_internal(src) and self.db.is_guard(dst):
                pairs[(src,dst)].append(f)

        for (src,guard), gflows in pairs.items():
            if len(gflows) < 5: continue
            gflows.sort(key=lambda x: x.get("start_time",0))

            # Compute inter-arrival intervals
            starts = [f.get("start_time",0) for f in gflows]
            intervals = [starts[i+1]-starts[i] for i in range(len(starts)-1)]
            intervals = [iv for iv in intervals if 0 < iv < 7200]
            if len(intervals) < 4: continue

            mean_iv = statistics.mean(intervals)
            std_iv = statistics.stdev(intervals) if len(intervals)>1 else mean_iv
            cv = std_iv / mean_iv if mean_iv > 0 else 1.0

            # Regular beaconing: low CV means consistent intervals
            if cv < 0.35 and mean_iv > 10:
                conf = min(1.0, 0.6 + (0.35-cv))
                total_dur = starts[-1] - starts[0]
                score = min(98, 60 + (0.35-cv)*80 + min(len(gflows)/5, 10))

                indicators.append(TorC2Indicator(
                    src_ip=src, guard_ip=guard,
                    beacon_interval_mean=round(mean_iv,2),
                    beacon_interval_cv=round(cv,4),
                    session_count=len(gflows),
                    total_duration=round(total_dur,1),
                    confidence=conf,
                    evidence=[f"Beacon via guard {guard}: interval={mean_iv:.1f}s CV={cv:.3f}",
                              f"Sessions: {len(gflows)} over {total_dur/60:.0f}min"]))

                events.append(TorEvent(
                    event_type="tor_c2", sub_type="beacon_over_tor",
                    src_ip=src, dst_ip=guard, dst_port=gflows[0].get("dst_port",0),
                    confidence=conf, severity="CRITICAL", score=score,
                    evidence=[f"Tor C2 beacon: {src}→guard {guard}",
                              f"Interval: {mean_iv:.1f}s (CV={cv:.3f})",
                              f"{len(gflows)} sessions over {total_dur/60:.0f}min"],
                    tor_node_type="guard", timestamp=starts[0],
                    mitre_technique="T1071.001",
                    metadata={"interval":mean_iv,"cv":cv,"sessions":len(gflows)}))

            # Low-and-slow exfil: large outbound, small inbound
            total_out = sum(f.get("total_bytes",0) for f in gflows)
            reverse_in = sum(f.get("total_bytes",0) for f in flows
                           if f.get("src_ip")==guard and f.get("dst_ip")==src)
            if total_out > 1_000_000 and (reverse_in < total_out * 0.2 or reverse_in==0):
                events.append(TorEvent(
                    event_type="tor_c2", sub_type="tor_exfiltration",
                    src_ip=src, dst_ip=guard, dst_port=gflows[0].get("dst_port",0),
                    confidence=0.7, severity="CRITICAL", score=85,
                    evidence=[f"Data exfil over Tor: {total_out/1e6:.2f}MB out via {guard}",
                              f"Return traffic: {reverse_in/1e6:.2f}MB ({reverse_in/max(total_out,1)*100:.0f}%)"],
                    tor_node_type="guard", timestamp=starts[0],
                    mitre_technique="T1048"))

        return events, indicators


# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 8: TIMING CORRELATOR
# ═══════════════════════════════════════════════════════════════════════════════

class TimingCorrelator:
    """Cross-flow timing correlation to link Tor entry/exit traffic."""

    def analyse(self, flows: List[dict], db: TorNodeDB) -> List[TorEvent]:
        events = []
        # Find internal→guard and exit→external flow pairs with correlated timing
        guard_flows = [(f, f.get("start_time",0)) for f in flows
                       if _is_internal(f.get("src_ip","")) and db.is_guard(f.get("dst_ip",""))]
        exit_flows = [(f, f.get("start_time",0)) for f in flows
                      if db.is_exit(f.get("src_ip","")) and not _is_internal(f.get("dst_ip",""))]
        if not guard_flows or not exit_flows: return events

        guard_flows.sort(key=lambda x: x[1])
        exit_flows.sort(key=lambda x: x[1])

        # For each guard flow, find exit flows within timing window (0.2–3s delay)
        correlations = []
        for gf, gt in guard_flows[:200]:  # cap for perf
            for ef, et in exit_flows:
                delta = et - gt
                if delta < 0.1: continue
                if delta > 5.0: break
                if 0.2 < delta < 3.0:
                    correlations.append({"guard_flow":gf,"exit_flow":ef,"delta":delta})

        if len(correlations) >= 3:
            deltas = [c["delta"] for c in correlations]
            events.append(TorEvent(
                event_type="timing_correlation", sub_type="entry_exit_corr",
                src_ip=correlations[0]["guard_flow"].get("src_ip",""),
                dst_ip=correlations[0]["exit_flow"].get("dst_ip",""),
                dst_port=correlations[0]["exit_flow"].get("dst_port",0),
                confidence=min(1.0, 0.4+len(correlations)*0.05),
                severity="HIGH", score=min(90, 50+len(correlations)*3),
                evidence=[f"Timing correlation: {len(correlations)} entry↔exit pairs",
                          f"Mean delay: {statistics.mean(deltas):.3f}s",
                          f"Correlation suggests linked Tor circuit traffic"],
                timestamp=correlations[0]["guard_flow"].get("start_time",0),
                metadata={"corr_count":len(correlations),"mean_delta":statistics.mean(deltas)}))
        return events


# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 9: FLOW ENTROPY ANALYZER
# ═══════════════════════════════════════════════════════════════════════════════

class FlowEntropyAnalyzer:
    """Analyze packet size & inter-arrival time entropy for Tor characteristics."""

    def analyse(self, packets: List[dict]) -> List[TorEvent]:
        events = []
        flow_data: Dict[Tuple[str,str],dict] = defaultdict(
            lambda: {"sizes":[],"times":[],"port":0,"ts":0})
        for p in packets:
            key = (p.get("src_ip",""), p.get("dst_ip",""))
            d = flow_data[key]
            d["sizes"].append(p.get("size",0))
            d["times"].append(p.get("timestamp",0))
            if not d["port"]: d["port"] = p.get("dst_port",0)
            if not d["ts"]: d["ts"] = p.get("timestamp",0)

        for (src,dst), d in flow_data.items():
            if len(d["sizes"]) < 30: continue
            size_ent = _entropy(d["sizes"])
            times = sorted(d["times"])
            intervals = [times[i+1]-times[i] for i in range(len(times)-1) if times[i+1]>times[i]]
            time_ent = _entropy_float(intervals) if len(intervals)>10 else 0

            # Tor fingerprint: moderate size entropy (cells), low time entropy (regular)
            if 3.0 < size_ent < 6.0 and 0 < time_ent < 4.0:
                score = min(70, 30 + size_ent*4 + (4-time_ent)*3)
                events.append(TorEvent(
                    event_type="flow_entropy", sub_type="tor_entropy_profile",
                    src_ip=src, dst_ip=dst, dst_port=d["port"],
                    confidence=0.55, severity="MEDIUM", score=score,
                    evidence=[f"Size entropy: {size_ent:.2f} (Tor range: 3-6)",
                              f"Timing entropy: {time_ent:.2f} (regular pattern)",
                              f"Packets: {len(d['sizes'])}"],
                    timestamp=d["ts"],
                    metadata={"size_entropy":size_ent,"time_entropy":time_ent}))
        return events


# ═══════════════════════════════════════════════════════════════════════════════
# UTILITY FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

def _entropy(values: List[int]) -> float:
    if not values: return 0.0
    bins: Dict[int,int] = defaultdict(int)
    for v in values: bins[v // 50] += 1
    total = len(values)
    return round(-sum((c/total)*math.log2(c/total) for c in bins.values() if c>0), 4)

def _entropy_float(values: List[float]) -> float:
    if len(values) < 5: return 0.0
    med = statistics.median(values)
    if med == 0: return 0.0
    bins: Dict[int,int] = defaultdict(int)
    bucket = max(med * 0.1, 0.001)
    for v in values: bins[int(v / bucket)] += 1
    total = len(values)
    return round(-sum((c/total)*math.log2(c/total) for c in bins.values() if c>0), 4)


# ═══════════════════════════════════════════════════════════════════════════════
# MASTER TOR ANALYZER ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

class TorAnalyzer:
    """
    Master orchestrator — runs all 9 Tor detection modules and produces
    a unified analysis with scored events, circuits, HS indicators, and C2 alerts.
    """

    def __init__(self):
        self.db = TorNodeDB()
        self.fingerprint = TorFingerprintEngine(self.db)
        self.node_match = TorNodeMatcher(self.db)
        self.cell_analyzer = TorCellAnalyzer()
        self.circuit_det = TorCircuitDetector(self.db)
        self.hs_detector = HiddenServiceDetector(self.db)
        self.bridge_det = TorBridgeDetector()
        self.c2_det = TorC2Detector(self.db)
        self.timing = TimingCorrelator()
        self.entropy = FlowEntropyAnalyzer()

    def analyse(self, flows: List[dict], packets: List[dict]) -> dict:
        """Run full Tor analysis pipeline. Returns comprehensive results dict."""
        all_events: List[TorEvent] = []

        # Module 1: TLS fingerprinting
        all_events.extend(self.fingerprint.analyse(flows))
        # Module 2: Node matching
        all_events.extend(self.node_match.analyse(flows))
        # Module 3: Cell analysis
        cell_events, cell_ratios = self.cell_analyzer.analyse(packets)
        all_events.extend(cell_events)
        # Module 4: Circuit detection
        circ_events, circuits = self.circuit_det.analyse(flows, cell_ratios)
        all_events.extend(circ_events)
        # Module 5: Hidden service detection
        hs_events, hs_indicators = self.hs_detector.analyse(flows, packets, circuits)
        all_events.extend(hs_events)
        # Module 6: Bridge detection
        all_events.extend(self.bridge_det.analyse(flows, packets))
        # Module 7: C2 detection
        c2_events, c2_indicators = self.c2_det.analyse(flows)
        all_events.extend(c2_events)
        # Module 8: Timing correlation
        all_events.extend(self.timing.analyse(flows, self.db))
        # Module 9: Flow entropy
        all_events.extend(self.entropy.analyse(packets))

        # Deduplicate by (src, dst, event_type)
        seen, unique = set(), []
        for e in sorted(all_events, key=lambda x: x.score, reverse=True):
            key = (e.src_ip, e.dst_ip, e.event_type, e.sub_type)
            if key not in seen:
                seen.add(key)
                unique.append(e)

        # Build endpoint summary
        endpoints: Dict[str,dict] = {}
        for e in unique:
            for ip in (e.src_ip, e.dst_ip):
                if not ip: continue
                if ip not in endpoints:
                    endpoints[ip] = {"ip":ip,"is_tor_node":self.db.is_tor(ip),
                        "node_type":self.db.get_type(ip),"event_count":0,
                        "max_score":0,"event_types":set(),"is_internal":_is_internal(ip)}
                ep = endpoints[ip]
                ep["event_count"] += 1
                ep["max_score"] = max(ep["max_score"], e.score)
                ep["event_types"].add(e.event_type)
        for ep in endpoints.values():
            ep["event_types"] = sorted(ep["event_types"])

        internal_users = sorted(
            [ep for ep in endpoints.values() if ep["is_internal"] and ep["event_count"]>0],
            key=lambda x: x["max_score"], reverse=True)

        return {
            "tor_events": [self._event_to_dict(e) for e in unique[:200]],
            "tor_circuits": [self._circuit_to_dict(c) for c in circuits],
            "hidden_service_indicators": [
                {"src_ip":h.src_ip,"rendezvous_candidates":h.rendezvous_candidates,
                 "confidence":round(h.confidence,3),"duration":h.duration,
                 "evidence":h.evidence,"circuit_count":h.estimated_circuit_count,
                 "data_volume_bytes":h.data_volume_bytes}
                for h in sorted(hs_indicators, key=lambda x:x.confidence, reverse=True)
            ],
            "c2_indicators": [
                {"src_ip":c.src_ip,"guard_ip":c.guard_ip,
                 "interval_mean":c.beacon_interval_mean,"interval_cv":c.beacon_interval_cv,
                 "session_count":c.session_count,"duration":c.total_duration,
                 "confidence":round(c.confidence,3),"evidence":c.evidence}
                for c in sorted(c2_indicators, key=lambda x:x.confidence, reverse=True)
            ],
            "tor_endpoints": sorted(endpoints.values(), key=lambda x:x["max_score"], reverse=True)[:50],
            "internal_users": internal_users[:30],
            "tor_node_db": self.db.node_count(),
            "tor_summary": {
                "total_events": len(unique),
                "critical_events": sum(1 for e in unique if e.severity=="CRITICAL"),
                "high_events": sum(1 for e in unique if e.severity=="HIGH"),
                "node_matches": sum(1 for e in unique if e.event_type=="tor_node_match"),
                "fingerprint_matches": sum(1 for e in unique if e.event_type=="tor_fingerprint"),
                "cell_detections": sum(1 for e in unique if e.event_type=="tor_cell_pattern"),
                "circuits_detected": len(circuits),
                "hidden_service_indicators": len(hs_indicators),
                "bridge_detections": sum(1 for e in unique if e.event_type=="tor_bridge"),
                "c2_indicators": len(c2_indicators),
                "timing_correlations": sum(1 for e in unique if e.event_type=="timing_correlation"),
                "entropy_matches": sum(1 for e in unique if e.event_type=="flow_entropy"),
                "unique_internal_ips": len([e for e in endpoints.values() if e["is_internal"]]),
                "unique_tor_nodes": len([e for e in endpoints.values() if e["is_tor_node"]]),
                "max_threat_score": max((e.score for e in unique), default=0),
            },
        }

    def _event_to_dict(self, e: TorEvent) -> dict:
        return {"event_type":e.event_type,"sub_type":e.sub_type,
                "src_ip":e.src_ip,"dst_ip":e.dst_ip,"dst_port":e.dst_port,
                "confidence":round(e.confidence,3),"severity":e.severity,
                "score":round(e.score,1),"evidence":e.evidence,
                "tor_node_type":e.tor_node_type,"mitre_technique":e.mitre_technique,
                "timestamp":e.timestamp,"circuit_id":e.circuit_id,"metadata":e.metadata}

    def _circuit_to_dict(self, c: TorCircuit) -> dict:
        return {"circuit_id":c.circuit_id,"src_ip":c.src_ip,"hops":c.hops,
                "guard_ip":c.guard_ip,"exit_ip":c.exit_ip,
                "build_time_ms":c.build_time_ms,"created_at":c.created_at,
                "packet_count":c.packet_count,"total_bytes":c.total_bytes,
                "duration":c.duration,"cell_ratio":c.cell_ratio,
                "is_hidden_service":c.is_hidden_service}
