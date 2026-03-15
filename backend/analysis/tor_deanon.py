"""
NetForensics — Tor De-Anonymization Research Engine v5
========================================================
Advanced Tor circuit analysis for research purposes:

  MODULE 1: TimingCorrelationEngine   — Statistical timing analysis (entry ↔ exit)
  MODULE 2: VolumeCorrelationEngine   — Traffic volume correlation across circuits
  MODULE 3: CircuitFingerprintEngine  — Unique circuit behavioral fingerprinting
  MODULE 4: GuardPersistenceTracker   — Long-term guard relay usage patterns
  MODULE 5: TorFlowClassifier         — ML-free flow classification (interactive vs bulk)

NOTE: This module is for RESEARCH/DETECTION purposes only. It analyzes
metadata patterns to identify Tor traffic and potential de-anonymization
vectors — it does NOT decrypt or intercept Tor traffic.

MITRE ATT&CK: T1090.003 (Multi-hop Proxy)
"""

import hashlib
import logging
import math
import statistics
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger("netforensics.tor_deanon")


# ═══════════════════════════════════════════════════════════════════════════════
# DATA CLASSES
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class TimingCorrelation:
    """Timing correlation result between entry and exit flows."""
    correlation_id: str
    entry_ip: str            # Internal client
    guard_ip: str            # Entry guard
    exit_ip: str             # Exit node
    destination_ip: str      # Final external destination
    correlation_score: float  # 0-1 (1 = perfect correlation)
    delay_mean: float        # Mean delay between entry and exit packets
    delay_std: float         # Delay standard deviation
    sample_count: int        # Number of correlated packet pairs
    confidence: str          # CRITICAL, HIGH, MEDIUM, LOW
    evidence: List[str]
    time_window: float       # Duration of observed correlation


@dataclass
class VolumeCorrelation:
    """Volume-based correlation between entry/exit traffic."""
    entry_ip: str
    guard_ip: str
    exit_ip: str
    entry_bytes: int
    exit_bytes: int
    volume_ratio: float      # exit_bytes / entry_bytes (1.0 = perfect match)
    correlation_score: float
    time_overlap: float      # Percentage of overlapping active periods
    evidence: List[str]


@dataclass
class CircuitFingerprint:
    """Behavioral fingerprint of a Tor circuit."""
    circuit_id: str
    entry_ip: str
    guard_ip: str
    packet_size_entropy: float
    inter_arrival_entropy: float
    burst_frequency: float
    idle_ratio: float
    avg_packet_size: float
    classification: str      # "interactive", "bulk_download", "streaming",
                             # "c2_beacon", "file_transfer"
    fingerprint_hash: str    # MD5 of behavioral features


@dataclass
class GuardProfile:
    """Long-term guard relay usage profile for an endpoint."""
    client_ip: str
    preferred_guards: List[str]
    guard_switch_count: int
    avg_guard_duration: float    # seconds per guard session
    total_circuits: int
    total_data_bytes: int
    persistence_score: float     # Higher = more stable (Tor client behavior)
    evidence: List[str]


# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 1: TIMING CORRELATION ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

class TimingCorrelationEngine:
    """
    Statistical timing analysis for entry ↔ exit node correlation.

    Methodology:
    1. Capture packet timestamps for internal→guard and exit→external flows
    2. Compute cross-correlation of inter-packet intervals
    3. Measure delay distribution between entry/exit packet bursts
    4. Use Pearson correlation coefficient for burst timing

    Known limitation: Tor uses padding and traffic shaping that reduces
    effectiveness, but imperfect padding still leaks timing signatures.
    """

    MAX_DELAY = 5.0       # Max acceptable delay (seconds) for correlation
    MIN_DELAY = 0.05      # Min delay (sub-50ms suggests same machine)
    MIN_SAMPLES = 10      # Minimum packet pairs for statistical significance

    def analyse(self, flows: List[dict], packets: List[dict],
                known_guards: Set[str], known_exits: Set[str]) -> List[TimingCorrelation]:
        results = []

        # Build per-flow packet timestamp maps
        entry_flows = self._extract_entry_flows(flows, packets, known_guards)
        exit_flows = self._extract_exit_flows(flows, packets, known_exits)

        if not entry_flows or not exit_flows:
            return results

        # For each entry flow, find correlated exit flows
        for entry_key, entry_data in entry_flows.items():
            for exit_key, exit_data in exit_flows.items():
                correlation = self._compute_correlation(
                    entry_key, entry_data, exit_key, exit_data)
                if correlation:
                    results.append(correlation)

        return sorted(results, key=lambda r: r.correlation_score, reverse=True)[:20]

    def _extract_entry_flows(self, flows, packets, guards) -> Dict[str, Dict]:
        """Extract internal→guard flow data with packet timestamps."""
        entry_flows = {}
        # Group packets by flow
        flow_packets = defaultdict(list)
        for p in packets:
            flow_packets[p.get("flow_id", "")].append(p)

        for f in flows:
            src, dst = f.get("src_ip", ""), f.get("dst_ip", "")
            if self._is_internal(src) and dst in guards:
                key = f"{src}→{dst}"
                pkts = sorted(flow_packets.get(f.get("flow_id", ""), []),
                             key=lambda p: p.get("timestamp", 0))
                timestamps = [p.get("timestamp", 0) for p in pkts if p.get("timestamp")]
                sizes = [p.get("size", 0) for p in pkts]
                if len(timestamps) >= self.MIN_SAMPLES:
                    entry_flows[key] = {
                        "client_ip": src,
                        "guard_ip": dst,
                        "timestamps": timestamps,
                        "sizes": sizes,
                        "flow": f,
                        "intervals": self._compute_intervals(timestamps),
                    }
        return entry_flows

    def _extract_exit_flows(self, flows, packets, exits) -> Dict[str, Dict]:
        """Extract exit→external flow data."""
        exit_flows = {}
        flow_packets = defaultdict(list)
        for p in packets:
            flow_packets[p.get("flow_id", "")].append(p)

        for f in flows:
            src, dst = f.get("src_ip", ""), f.get("dst_ip", "")
            if src in exits and not self._is_internal(dst):
                key = f"{src}→{dst}"
                pkts = sorted(flow_packets.get(f.get("flow_id", ""), []),
                             key=lambda p: p.get("timestamp", 0))
                timestamps = [p.get("timestamp", 0) for p in pkts if p.get("timestamp")]
                sizes = [p.get("size", 0) for p in pkts]
                if len(timestamps) >= self.MIN_SAMPLES:
                    exit_flows[key] = {
                        "exit_ip": src,
                        "dest_ip": dst,
                        "timestamps": timestamps,
                        "sizes": sizes,
                        "flow": f,
                        "intervals": self._compute_intervals(timestamps),
                    }
        return exit_flows

    def _compute_correlation(self, entry_key, entry_data,
                             exit_key, exit_data) -> Optional[TimingCorrelation]:
        """Compute timing correlation between entry and exit flows."""
        entry_ts = entry_data["timestamps"]
        exit_ts = exit_data["timestamps"]

        # Check time overlap
        entry_span = (min(entry_ts), max(entry_ts))
        exit_span = (min(exit_ts), max(exit_ts))
        overlap_start = max(entry_span[0], exit_span[0])
        overlap_end = min(entry_span[1], exit_span[1])
        if overlap_end <= overlap_start:
            return None

        # Find correlated packet pairs (entry packet followed by exit packet
        #     within the delay window)
        pairs = []
        exit_idx = 0
        for et in entry_ts:
            while exit_idx < len(exit_ts) and exit_ts[exit_idx] < et + self.MIN_DELAY:
                exit_idx += 1
            if exit_idx >= len(exit_ts):
                break
            if exit_ts[exit_idx] <= et + self.MAX_DELAY:
                delay = exit_ts[exit_idx] - et
                pairs.append(delay)
                exit_idx += 1

        if len(pairs) < self.MIN_SAMPLES:
            return None

        # Compute correlation metrics
        delay_mean = statistics.mean(pairs)
        delay_std = statistics.stdev(pairs) if len(pairs) > 1 else 0
        delay_cv = delay_std / delay_mean if delay_mean > 0 else 1.0

        # Interval correlation (Pearson)
        entry_intervals = entry_data["intervals"]
        exit_intervals = exit_data["intervals"]
        interval_corr = self._pearson_correlation(
            entry_intervals[:min(len(entry_intervals), len(exit_intervals))],
            exit_intervals[:min(len(entry_intervals), len(exit_intervals))]
        )

        # Score: combines delay consistency + interval correlation + pair count
        pair_score = min(1.0, len(pairs) / (len(entry_ts) * 0.5))
        delay_score = max(0, 1 - delay_cv)
        corr_score = max(0, interval_corr)
        final_score = 0.3 * pair_score + 0.3 * delay_score + 0.4 * corr_score

        if final_score < 0.3:
            return None

        confidence = ("CRITICAL" if final_score > 0.8 else
                     "HIGH" if final_score > 0.6 else
                     "MEDIUM" if final_score > 0.4 else "LOW")

        corr_id = hashlib.md5(f"{entry_key}|{exit_key}".encode()).hexdigest()[:12]

        return TimingCorrelation(
            correlation_id=corr_id,
            entry_ip=entry_data["client_ip"],
            guard_ip=entry_data["guard_ip"],
            exit_ip=exit_data["exit_ip"],
            destination_ip=exit_data["dest_ip"],
            correlation_score=round(final_score, 4),
            delay_mean=round(delay_mean, 4),
            delay_std=round(delay_std, 4),
            sample_count=len(pairs),
            confidence=confidence,
            evidence=[
                f"Timing correlation: {entry_data['client_ip']}→guard→exit→{exit_data['dest_ip']}",
                f"Correlated pairs: {len(pairs)}/{len(entry_ts)} "
                f"(delay: {delay_mean:.3f}±{delay_std:.3f}s)",
                f"Interval correlation: {interval_corr:.3f}",
                f"Score: pair={pair_score:.2f}, delay={delay_score:.2f}, corr={corr_score:.2f}",
            ],
            time_window=overlap_end - overlap_start,
        )

    def _compute_intervals(self, timestamps: List[float]) -> List[float]:
        return [timestamps[i + 1] - timestamps[i]
                for i in range(len(timestamps) - 1)
                if timestamps[i + 1] > timestamps[i]]

    def _pearson_correlation(self, x: List[float], y: List[float]) -> float:
        """Compute Pearson correlation coefficient."""
        n = min(len(x), len(y))
        if n < 5:
            return 0.0
        x, y = x[:n], y[:n]
        mx, my = statistics.mean(x), statistics.mean(y)
        num = sum((xi - mx) * (yi - my) for xi, yi in zip(x, y))
        dx = math.sqrt(sum((xi - mx) ** 2 for xi in x))
        dy = math.sqrt(sum((yi - my) ** 2 for yi in y))
        if dx * dy == 0:
            return 0.0
        return round(num / (dx * dy), 4)

    def _is_internal(self, ip: str) -> bool:
        return ip.startswith(("10.", "192.168.", "172."))


# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 2: VOLUME CORRELATION ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

class VolumeCorrelationEngine:
    """
    Correlate traffic volumes between entry and exit paths.

    If InternalClient→Guard sends X bytes and ExitNode→ExternalDest sends ~X bytes
    (minus Tor overhead ~3-5%), they may be the same circuit.
    """

    TOR_OVERHEAD = 0.05  # ~5% overhead from cell padding + encryption

    def analyse(self, flows: List[dict],
                known_guards: Set[str], known_exits: Set[str]) -> List[VolumeCorrelation]:
        results = []

        # Group entry/exit by time windows
        entry_volumes: Dict[str, Dict] = {}
        exit_volumes: Dict[str, Dict] = {}

        for f in flows:
            src, dst = f.get("src_ip", ""), f.get("dst_ip", "")
            total_bytes = f.get("total_bytes", 0)
            start = f.get("start_time", 0)
            end = f.get("end_time", start)

            if self._is_internal(src) and dst in known_guards and total_bytes > 10000:
                key = f"{src}→{dst}"
                if key not in entry_volumes:
                    entry_volumes[key] = {"ip": src, "guard": dst, "bytes": 0,
                                         "start": start, "end": end}
                entry_volumes[key]["bytes"] += total_bytes
                entry_volumes[key]["end"] = max(entry_volumes[key]["end"], end)

            if src in known_exits and not self._is_internal(dst) and total_bytes > 10000:
                key = f"{src}→{dst}"
                if key not in exit_volumes:
                    exit_volumes[key] = {"exit": src, "dest": dst, "bytes": 0,
                                        "start": start, "end": end}
                exit_volumes[key]["bytes"] += total_bytes
                exit_volumes[key]["end"] = max(exit_volumes[key]["end"], end)

        # Cross-match volumes
        for ekey, entry in entry_volumes.items():
            for xkey, exit in exit_volumes.items():
                # Check time overlap
                overlap = min(entry["end"], exit["end"]) - max(entry["start"], exit["start"])
                total_span = max(entry["end"], exit["end"]) - min(entry["start"], exit["start"])
                time_overlap = overlap / total_span if total_span > 0 else 0

                if time_overlap < 0.3:
                    continue

                # Volume ratio (accounting for Tor overhead)
                expected_exit = entry["bytes"] * (1 - self.TOR_OVERHEAD)
                ratio = exit["bytes"] / expected_exit if expected_exit > 0 else 0

                # Good correlation: ratio near 1.0
                if 0.5 < ratio < 2.0:
                    score = max(0, 1 - abs(1 - ratio)) * time_overlap
                    if score > 0.3:
                        results.append(VolumeCorrelation(
                            entry_ip=entry["ip"],
                            guard_ip=entry["guard"],
                            exit_ip=exit["exit"],
                            entry_bytes=entry["bytes"],
                            exit_bytes=exit["bytes"],
                            volume_ratio=round(ratio, 4),
                            correlation_score=round(score, 4),
                            time_overlap=round(time_overlap, 4),
                            evidence=[
                                f"Volume match: {entry['ip']}→guard {entry['bytes'] / 1024:.1f}KB "
                                f"≈ exit→{exit['dest']} {exit['bytes'] / 1024:.1f}KB",
                                f"Ratio: {ratio:.2f} (expected ~0.95 w/ overhead)",
                                f"Time overlap: {time_overlap:.0%}",
                            ],
                        ))

        return sorted(results, key=lambda r: r.correlation_score, reverse=True)[:15]

    def _is_internal(self, ip: str) -> bool:
        return ip.startswith(("10.", "192.168.", "172."))


# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 3: CIRCUIT FINGERPRINT ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

class CircuitFingerprintEngine:
    """
    Create behavioral fingerprints for Tor circuits based on traffic patterns.
    Different applications (web browsing, file transfer, streaming) produce
    distinct packet size/timing distributions over Tor.
    """

    def analyse(self, flows: List[dict], packets: List[dict],
                known_guards: Set[str]) -> List[CircuitFingerprint]:
        results = []
        # Group by (internal_ip, guard_ip) pairs
        circuit_data: Dict[str, Dict] = defaultdict(
            lambda: {"sizes": [], "timestamps": [], "flow": None})

        for p in packets:
            src, dst = p.get("src_ip", ""), p.get("dst_ip", "")
            if self._is_internal(src) and dst in known_guards:
                key = f"{src}→{dst}"
                circuit_data[key]["sizes"].append(p.get("size", 0))
                circuit_data[key]["timestamps"].append(p.get("timestamp", 0))
            elif src in known_guards and self._is_internal(dst):
                key = f"{dst}→{src}"
                circuit_data[key]["sizes"].append(p.get("size", 0))
                circuit_data[key]["timestamps"].append(p.get("timestamp", 0))

        for key, data in circuit_data.items():
            sizes = data["sizes"]
            timestamps = sorted(data["timestamps"])
            if len(sizes) < 30:
                continue

            # Compute features
            size_entropy = self._entropy(sizes)
            intervals = [timestamps[i + 1] - timestamps[i]
                        for i in range(len(timestamps) - 1)
                        if timestamps[i + 1] > timestamps[i]]
            ia_entropy = self._entropy_float(intervals) if len(intervals) > 10 else 0

            # Burst detection
            burst_count = sum(1 for iv in intervals if iv < 0.01) if intervals else 0
            burst_freq = burst_count / len(intervals) if intervals else 0

            # Idle ratio
            idle_count = sum(1 for iv in intervals if iv > 2.0) if intervals else 0
            idle_ratio = idle_count / len(intervals) if intervals else 0

            avg_size = statistics.mean(sizes)

            # Classify
            classification = self._classify_circuit(
                size_entropy, ia_entropy, burst_freq, idle_ratio, avg_size, len(sizes))

            # Create fingerprint hash
            fp_features = f"{size_entropy:.2f}|{ia_entropy:.2f}|{burst_freq:.2f}|{idle_ratio:.2f}|{avg_size:.0f}"
            fp_hash = hashlib.md5(fp_features.encode()).hexdigest()

            parts = key.split("→")
            results.append(CircuitFingerprint(
                circuit_id=hashlib.md5(key.encode()).hexdigest()[:12],
                entry_ip=parts[0] if parts else "",
                guard_ip=parts[1] if len(parts) > 1 else "",
                packet_size_entropy=round(size_entropy, 4),
                inter_arrival_entropy=round(ia_entropy, 4),
                burst_frequency=round(burst_freq, 4),
                idle_ratio=round(idle_ratio, 4),
                avg_packet_size=round(avg_size, 1),
                classification=classification,
                fingerprint_hash=fp_hash,
            ))

        return results

    def _classify_circuit(self, size_ent, ia_ent, burst_freq,
                          idle_ratio, avg_size, packet_count) -> str:
        # Interactive (web browsing): bursty, variable sizes, high idle
        if burst_freq > 0.3 and idle_ratio > 0.2:
            return "interactive"
        # Bulk download: consistent sizes, low idle
        if size_ent < 3.0 and idle_ratio < 0.05 and packet_count > 100:
            return "bulk_download"
        # Streaming: consistent timing, medium size variation
        if ia_ent < 3.0 and 3.0 < size_ent < 5.0:
            return "streaming"
        # C2 beacon: very regular timing, small packets
        if ia_ent < 2.0 and avg_size < 200:
            return "c2_beacon"
        # File transfer: large packets, bursty
        if avg_size > 1000 and burst_freq > 0.5:
            return "file_transfer"
        return "unknown"

    def _entropy(self, values: List[int]) -> float:
        if not values: return 0.0
        bins: Dict[int, int] = defaultdict(int)
        for v in values: bins[v // 50] += 1
        total = len(values)
        return round(-sum((c / total) * math.log2(c / total)
                         for c in bins.values() if c > 0), 4)

    def _entropy_float(self, values: List[float]) -> float:
        if len(values) < 5: return 0.0
        med = statistics.median(values)
        if med == 0: return 0.0
        bins: Dict[int, int] = defaultdict(int)
        bucket = max(med * 0.1, 0.001)
        for v in values: bins[int(v / bucket)] += 1
        total = len(values)
        return round(-sum((c / total) * math.log2(c / total)
                         for c in bins.values() if c > 0), 4)

    def _is_internal(self, ip: str) -> bool:
        return ip.startswith(("10.", "192.168.", "172."))


# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 4: GUARD PERSISTENCE TRACKER
# ═══════════════════════════════════════════════════════════════════════════════

class GuardPersistenceTracker:
    """
    Track how Tor clients use entry guards over time.

    The Tor protocol pins clients to 2-3 guard relays for months.
    This persistence pattern can be used to:
    - Confirm Tor usage over time
    - Track guard relay changes (may indicate new circuits)
    - Estimate number of distinct Tor users behind a NAT
    """

    def analyse(self, flows: List[dict],
                known_guards: Set[str]) -> List[GuardProfile]:
        client_guards: Dict[str, Dict[str, Dict]] = defaultdict(dict)

        for f in flows:
            src, dst = f.get("src_ip", ""), f.get("dst_ip", "")
            if self._is_internal(src) and dst in known_guards:
                if dst not in client_guards[src]:
                    client_guards[src][dst] = {
                        "first_seen": f.get("start_time", 0),
                        "last_seen": f.get("start_time", 0),
                        "flows": 0, "bytes": 0,
                    }
                g = client_guards[src][dst]
                g["flows"] += 1
                g["bytes"] += f.get("total_bytes", 0)
                g["last_seen"] = max(g["last_seen"], f.get("start_time", 0))

        profiles = []
        for client, guards in client_guards.items():
            if not guards:
                continue

            sorted_guards = sorted(guards.items(),
                                  key=lambda x: x[1]["flows"], reverse=True)
            total_flows = sum(g["flows"] for _, g in sorted_guards)
            total_bytes = sum(g["bytes"] for _, g in sorted_guards)

            # Duration per guard
            durations = [g["last_seen"] - g["first_seen"]
                        for _, g in sorted_guards if g["last_seen"] > g["first_seen"]]
            avg_dur = statistics.mean(durations) if durations else 0

            # Persistence: prefer few guards used consistently (Tor default behavior)
            persistence = 1.0 / max(1, len(guards))  # Fewer guards = more Tor-like
            if avg_dur > 3600:
                persistence += 0.2
            if len(guards) <= 3:
                persistence += 0.3
            persistence = min(1.0, persistence)

            evidence = [f"Guards used: {len(guards)}"]
            for guard_ip, gdata in sorted_guards[:3]:
                evidence.append(
                    f"  {guard_ip}: {gdata['flows']} flows, "
                    f"{gdata['bytes'] / 1024:.1f}KB, "
                    f"duration: {gdata['last_seen'] - gdata['first_seen']:.0f}s")

            profiles.append(GuardProfile(
                client_ip=client,
                preferred_guards=[g[0] for g in sorted_guards[:3]],
                guard_switch_count=max(0, len(guards) - 1),
                avg_guard_duration=round(avg_dur, 1),
                total_circuits=total_flows,
                total_data_bytes=total_bytes,
                persistence_score=round(persistence, 4),
                evidence=evidence,
            ))

        return sorted(profiles, key=lambda p: p.total_circuits, reverse=True)

    def _is_internal(self, ip: str) -> bool:
        return ip.startswith(("10.", "192.168.", "172."))


# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 5: TOR FLOW CLASSIFIER
# ═══════════════════════════════════════════════════════════════════════════════

class TorFlowClassifier:
    """
    Classify Tor traffic by application type using statistical features.
    No ML required — uses rule-based heuristics on traffic patterns.
    """

    def classify(self, flows: List[dict], packets: List[dict],
                 known_guards: Set[str]) -> Dict:
        classifications = defaultdict(list)

        # Group by internal→guard
        guard_flows: Dict[str, List[dict]] = defaultdict(list)
        for f in flows:
            src, dst = f.get("src_ip", ""), f.get("dst_ip", "")
            if src.startswith(("10.", "192.168.", "172.")) and dst in known_guards:
                guard_flows[f"{src}→{dst}"].append(f)

        for key, gflows in guard_flows.items():
            total_bytes = sum(f.get("total_bytes", 0) for f in gflows)
            total_pkts = sum(f.get("packet_count", 0) for f in gflows)
            avg_dur = statistics.mean([f.get("session_duration", 0) for f in gflows]) if gflows else 0
            avg_bpp = total_bytes / total_pkts if total_pkts else 0

            if avg_bpp < 200 and avg_dur < 5:
                label = "dns_over_tor"
            elif avg_bpp > 800 and total_bytes > 500_000:
                label = "file_download"
            elif 200 < avg_bpp < 600 and avg_dur > 30:
                label = "web_browsing"
            elif avg_bpp < 150 and len(gflows) > 20:
                label = "c2_beaconing"
            elif total_bytes > 5_000_000 and avg_dur > 120:
                label = "streaming"
            else:
                label = "general"

            parts = key.split("→")
            classifications[label].append({
                "client_ip": parts[0],
                "guard_ip": parts[1] if len(parts) > 1 else "",
                "flows": len(gflows),
                "bytes": total_bytes,
                "avg_bpp": round(avg_bpp, 1),
                "avg_duration": round(avg_dur, 2),
            })

        return {
            "classifications": {
                label: entries for label, entries in classifications.items()
            },
            "summary": {
                label: len(entries) for label, entries in classifications.items()
            },
        }


# ═══════════════════════════════════════════════════════════════════════════════
# MASTER TOR DE-ANONYMIZATION ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

class TorDeanonEngine:
    """
    Orchestrates all Tor de-anonymization research modules.
    Produces comprehensive analysis with timing/volume correlations,
    circuit fingerprints, and guard persistence tracking.
    """

    # Known Tor relay sets (in production, synced from TorNodeListService)
    KNOWN_GUARDS = frozenset({
        "86.59.21.38", "128.31.0.34", "194.109.206.212", "199.58.81.140",
        "131.188.40.189", "193.23.244.244", "171.25.193.9", "154.35.175.225",
        "45.66.33.45", "5.45.98.176", "5.45.99.1", "37.218.245.50",
        "185.220.100.240", "185.220.100.241", "185.220.100.242",
    })

    KNOWN_EXITS = frozenset({
        "185.220.101.1", "185.220.101.15", "185.220.101.33", "185.220.101.45",
        "185.220.101.47", "185.220.101.48", "185.220.101.57", "185.220.101.65",
        "185.220.102.4", "185.220.102.8", "199.249.230.64", "199.249.230.65",
        "204.85.191.8", "209.141.32.32", "209.141.58.146",
    })

    def __init__(self):
        self.timing = TimingCorrelationEngine()
        self.volume = VolumeCorrelationEngine()
        self.fingerprint = CircuitFingerprintEngine()
        self.guard_tracker = GuardPersistenceTracker()
        self.classifier = TorFlowClassifier()

    def analyse(self, flows: List[dict], packets: List[dict]) -> Dict:
        guards = set(self.KNOWN_GUARDS)
        exits = set(self.KNOWN_EXITS)

        # Run all modules
        timing_results = self.timing.analyse(flows, packets, guards, exits)
        volume_results = self.volume.analyse(flows, guards, exits)
        fingerprints = self.fingerprint.analyse(flows, packets, guards)
        guard_profiles = self.guard_tracker.analyse(flows, guards)
        classifications = self.classifier.classify(flows, packets, guards)

        return {
            "timing_correlations": [
                {"id": t.correlation_id, "entry": t.entry_ip, "guard": t.guard_ip,
                 "exit": t.exit_ip, "dest": t.destination_ip,
                 "score": t.correlation_score, "delay_mean": t.delay_mean,
                 "delay_std": t.delay_std, "samples": t.sample_count,
                 "confidence": t.confidence, "evidence": t.evidence,
                 "window": t.time_window}
                for t in timing_results
            ],
            "volume_correlations": [
                {"entry": v.entry_ip, "guard": v.guard_ip, "exit": v.exit_ip,
                 "entry_bytes": v.entry_bytes, "exit_bytes": v.exit_bytes,
                 "ratio": v.volume_ratio, "score": v.correlation_score,
                 "time_overlap": v.time_overlap, "evidence": v.evidence}
                for v in volume_results
            ],
            "circuit_fingerprints": [
                {"id": fp.circuit_id, "entry": fp.entry_ip, "guard": fp.guard_ip,
                 "size_entropy": fp.packet_size_entropy,
                 "timing_entropy": fp.inter_arrival_entropy,
                 "burst_freq": fp.burst_frequency, "idle_ratio": fp.idle_ratio,
                 "avg_size": fp.avg_packet_size,
                 "classification": fp.classification,
                 "fingerprint": fp.fingerprint_hash}
                for fp in fingerprints
            ],
            "guard_profiles": [
                {"client": g.client_ip, "guards": g.preferred_guards,
                 "switches": g.guard_switch_count,
                 "avg_duration": g.avg_guard_duration,
                 "circuits": g.total_circuits,
                 "data_bytes": g.total_data_bytes,
                 "persistence": g.persistence_score,
                 "evidence": g.evidence}
                for g in guard_profiles[:20]
            ],
            "flow_classifications": classifications,
            "summary": {
                "timing_correlations": len(timing_results),
                "high_confidence_correlations": sum(
                    1 for t in timing_results if t.confidence in ("CRITICAL", "HIGH")),
                "volume_correlations": len(volume_results),
                "circuit_fingerprints": len(fingerprints),
                "guard_profiles": len(guard_profiles),
                "tor_users_estimate": len(guard_profiles),
                "classification_breakdown": classifications.get("summary", {}),
            },
        }
