"""
NetForensics — ML Feature Extraction Pipeline v4
===================================================
Unified feature engineering for all ML detection models.

Feature Groups
--------------
  A. Timing Features     (6)  — inter-packet intervals, jitter, periodicity
  B. Volume Features     (5)  — bytes, packets, rates, size distribution
  C. Flow Features       (5)  — duration, protocol ratio, port entropy
  D. TLS Features        (4)  — JA3 rarity, SNI entropy, cert anomaly, version
  E. DNS Features        (3)  — query entropy, label length, consonant ratio
  F. Graph Features      (3)  — fan-out, fan-in, betweenness proxy

Total: 26 features per flow/endpoint, all computed from metadata only.
No deep-packet inspection — fully encrypted-traffic compatible.
"""

import logging
import math
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("netforensics.ml.features")


# ═══════════════════════════════════════════════════════════════════════════════
# Feature Vector Container
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class FeatureVector:
    """26-dimensional feature vector for a single flow or endpoint."""
    entity_id: str                      # flow_id or IP
    entity_type: str = "flow"           # "flow" | "endpoint"

    # A. Timing Features
    interval_mean: float = 0.0          # Mean inter-packet interval (seconds)
    interval_stdev: float = 0.0         # Stdev of intervals
    interval_cv: float = 1.0            # Coefficient of variation (regularity)
    interval_jitter: float = 0.0        # Mean |interval[i] − interval[i−1]|
    periodicity_score: float = 0.0      # FFT-free autocorrelation proxy
    burst_ratio: float = 0.0            # Fraction of intervals < median/2

    # B. Volume Features
    total_bytes: float = 0.0
    total_packets: float = 0.0
    bytes_per_packet: float = 0.0
    bytes_per_second: float = 0.0
    pkt_size_stdev: float = 0.0         # Packet-size distribution spread

    # C. Flow Features
    flow_duration: float = 0.0
    protocol_code: float = 0.0          # Encoded protocol (TCP=0.2, TLS=0.5, …)
    dst_port_norm: float = 0.0          # dst_port / 65535
    port_entropy: float = 0.0           # Entropy of destination ports (endpoint)
    unique_dst_ratio: float = 0.0       # unique_dsts / total_flows

    # D. TLS Features
    ja3_rarity: float = 0.0             # 1 − (ja3_count / total_tls)
    sni_entropy: float = 0.0            # Character entropy of SNI
    sni_length_norm: float = 0.0        # len(SNI) / 50 (capped)
    tls_version_score: float = 0.0      # 1.0 for deprecated, 0 for modern

    # E. DNS Features
    dns_query_entropy: float = 0.0
    dns_label_length: float = 0.0       # Normalised label length
    dns_consonant_ratio: float = 0.0

    # F. Graph Features
    fan_out: float = 0.0                # Unique outbound destinations
    fan_in: float = 0.0                 # Unique inbound sources
    betweenness_proxy: float = 0.0      # Simplified centrality estimate

    def to_vector(self) -> List[float]:
        """Return flat 26-element vector for ML models."""
        return [
            self.interval_mean, self.interval_stdev, self.interval_cv,
            self.interval_jitter, self.periodicity_score, self.burst_ratio,
            self.total_bytes, self.total_packets, self.bytes_per_packet,
            self.bytes_per_second, self.pkt_size_stdev,
            self.flow_duration, self.protocol_code, self.dst_port_norm,
            self.port_entropy, self.unique_dst_ratio,
            self.ja3_rarity, self.sni_entropy, self.sni_length_norm,
            self.tls_version_score,
            self.dns_query_entropy, self.dns_label_length,
            self.dns_consonant_ratio,
            self.fan_out, self.fan_in, self.betweenness_proxy,
        ]

    @staticmethod
    def feature_names() -> List[str]:
        return [
            "interval_mean", "interval_stdev", "interval_cv",
            "interval_jitter", "periodicity_score", "burst_ratio",
            "total_bytes", "total_packets", "bytes_per_packet",
            "bytes_per_second", "pkt_size_stdev",
            "flow_duration", "protocol_code", "dst_port_norm",
            "port_entropy", "unique_dst_ratio",
            "ja3_rarity", "sni_entropy", "sni_length_norm",
            "tls_version_score",
            "dns_query_entropy", "dns_label_length",
            "dns_consonant_ratio",
            "fan_out", "fan_in", "betweenness_proxy",
        ]


# ═══════════════════════════════════════════════════════════════════════════════
# Protocol Encoding
# ═══════════════════════════════════════════════════════════════════════════════

PROTOCOL_MAP = {
    "TCP": 0.2, "UDP": 0.3, "TLS": 0.5, "DNS": 0.6,
    "ICMP": 0.1, "HTTP": 0.4, "HTTPS": 0.5, "SSH": 0.7,
    "SMB": 0.8, "RDP": 0.9,
}

DEPRECATED_TLS = {"TLS 1.0", "TLS 1.1", "SSL 3.0", "SSL 2.0"}
VOWELS = set("aeiou")
CONSONANTS = set("bcdfghjklmnpqrstvwxyz")


# ═══════════════════════════════════════════════════════════════════════════════
# Helper Functions
# ═══════════════════════════════════════════════════════════════════════════════

def _char_entropy(text: str) -> float:
    """Shannon entropy of character distribution."""
    if not text:
        return 0.0
    freq = Counter(text.lower())
    n = len(text)
    return round(-sum((c / n) * math.log2(c / n) for c in freq.values()), 4)


def _consonant_ratio(text: str) -> float:
    label = text.split(".")[0].lower() if text else ""
    if not label:
        return 0.0
    return sum(1 for c in label if c in CONSONANTS) / len(label)


def _port_entropy(ports: List[int]) -> float:
    if not ports:
        return 0.0
    freq = Counter(ports)
    n = len(ports)
    return round(-sum((c / n) * math.log2(c / n) for c in freq.values()), 4)


def _autocorrelation_proxy(intervals: List[float], lag: int = 1) -> float:
    """Simplified autocorrelation at given lag — no numpy needed."""
    if len(intervals) < lag + 2:
        return 0.0
    mean = statistics.mean(intervals)
    var = statistics.variance(intervals)
    if var == 0:
        return 1.0  # perfectly periodic
    n = len(intervals)
    cov = sum((intervals[i] - mean) * (intervals[i + lag] - mean)
              for i in range(n - lag)) / (n - lag)
    return round(max(-1.0, min(1.0, cov / var)), 4)


# ═══════════════════════════════════════════════════════════════════════════════
# Main Feature Extractor
# ═══════════════════════════════════════════════════════════════════════════════

class MLFeatureExtractor:
    """
    Extracts 26-dimensional feature vectors from flow/packet metadata.

    Usage
    -----
        extractor = MLFeatureExtractor()
        flow_features = extractor.extract_flow_features(flows, packets)
        endpoint_features = extractor.extract_endpoint_features(flows, packets)
    """

    def __init__(self):
        self._ja3_counts: Dict[str, int] = {}
        self._total_tls: int = 0

    # ─── Flow-level Features ──────────────────────────────────────────────────

    def extract_flow_features(self, flows: List[dict],
                               packets: List[dict]) -> List[FeatureVector]:
        """Extract feature vectors for every flow."""
        # Pre-compute JA3 rarity
        self._compute_ja3_stats(flows)

        # Group packets by flow_id
        pkt_by_flow: Dict[str, List[dict]] = defaultdict(list)
        for p in packets:
            fid = p.get("flow_id", "")
            if fid:
                pkt_by_flow[fid].append(p)

        # Build graph for fan-out/fan-in
        graph = self._build_graph(flows)

        features = []
        for f in flows:
            fid = f.get("flow_id", "")
            fv = FeatureVector(entity_id=fid, entity_type="flow")

            # A. Timing features from packets
            flow_pkts = sorted(pkt_by_flow.get(fid, []),
                               key=lambda x: x.get("timestamp", 0))
            self._fill_timing(fv, flow_pkts)

            # B. Volume features
            self._fill_volume(fv, f, flow_pkts)

            # C. Flow features
            self._fill_flow(fv, f, graph)

            # D. TLS features
            self._fill_tls(fv, f)

            # E. DNS features
            self._fill_dns(fv, f, flow_pkts)

            features.append(fv)

        logger.info("Extracted flow features: %d vectors × %d dims",
                     len(features), 26)
        return features

    # ─── Endpoint-level Features ──────────────────────────────────────────────

    def extract_endpoint_features(self, flows: List[dict],
                                   packets: List[dict]) -> List[FeatureVector]:
        """Extract feature vectors aggregated per source IP."""
        self._compute_ja3_stats(flows)
        graph = self._build_graph(flows)

        # Group flows by src_ip
        ip_flows: Dict[str, List[dict]] = defaultdict(list)
        for f in flows:
            src = f.get("src_ip", "")
            if src:
                ip_flows[src].append(f)

        # Group packets by src_ip
        ip_pkts: Dict[str, List[dict]] = defaultdict(list)
        for p in packets:
            src = p.get("src_ip", "")
            if src:
                ip_pkts[src].append(p)

        features = []
        for ip, ip_fl in ip_flows.items():
            fv = FeatureVector(entity_id=ip, entity_type="endpoint")

            # Aggregate timing across all flows
            all_pkts = sorted(ip_pkts.get(ip, []),
                              key=lambda x: x.get("timestamp", 0))
            self._fill_timing(fv, all_pkts)

            # Aggregate volume
            fv.total_bytes = math.log1p(
                sum(f.get("total_bytes", 0) for f in ip_fl))
            fv.total_packets = math.log1p(
                sum(f.get("packet_count", 0) for f in ip_fl))
            total_dur = sum(f.get("session_duration", 0) for f in ip_fl)
            fv.flow_duration = math.log1p(total_dur)
            fv.bytes_per_second = (
                math.exp(fv.total_bytes) / max(total_dur, 0.1))
            sizes = [p.get("size", 0) for p in all_pkts if p.get("size")]
            fv.pkt_size_stdev = (
                statistics.stdev(sizes) if len(sizes) > 1 else 0.0)
            fv.bytes_per_packet = (
                math.exp(fv.total_bytes) /
                max(math.exp(fv.total_packets), 1))

            # Flow-level aggregates
            ports = [f.get("dst_port", 0) for f in ip_fl]
            fv.port_entropy = _port_entropy(ports)
            unique_dsts = len({f.get("dst_ip", "") for f in ip_fl})
            fv.unique_dst_ratio = unique_dsts / max(len(ip_fl), 1)
            fv.dst_port_norm = (
                statistics.median(ports) / 65535 if ports else 0)

            # Protocol: most common
            proto_counts = Counter(f.get("protocol", "") for f in ip_fl)
            dominant = proto_counts.most_common(1)[0][0] if proto_counts else ""
            fv.protocol_code = PROTOCOL_MAP.get(dominant, 0.0)

            # TLS aggregate
            tls_flows = [f for f in ip_fl if f.get("protocol") == "TLS"]
            if tls_flows:
                ja3s = [f.get("ja3", "") for f in tls_flows if f.get("ja3")]
                if ja3s:
                    rarest = min(
                        self._ja3_counts.get(j, 1) for j in ja3s)
                    fv.ja3_rarity = round(
                        1.0 - rarest / max(self._total_tls, 1), 4)
                snis = [f.get("sni", "") for f in tls_flows if f.get("sni")]
                if snis:
                    fv.sni_entropy = statistics.mean(
                        _char_entropy(s) for s in snis)
                    fv.sni_length_norm = min(1.0, statistics.mean(
                        len(s) for s in snis) / 50)
                deprecated = sum(
                    1 for f in tls_flows
                    if f.get("tls_version", "") in DEPRECATED_TLS)
                fv.tls_version_score = deprecated / max(len(tls_flows), 1)

            # DNS aggregate
            dns_pkts = [p for p in all_pkts if p.get("dns_query")]
            if dns_pkts:
                queries = [p["dns_query"] for p in dns_pkts]
                fv.dns_query_entropy = statistics.mean(
                    _char_entropy(q) for q in queries)
                labels = [q.split(".")[0] for q in queries]
                fv.dns_label_length = min(
                    1.0, statistics.mean(len(l) for l in labels) / 30)
                fv.dns_consonant_ratio = statistics.mean(
                    _consonant_ratio(q) for q in queries)

            # Graph features
            g = graph.get(ip, {})
            fv.fan_out = math.log1p(g.get("fan_out", 0))
            fv.fan_in = math.log1p(g.get("fan_in", 0))
            fv.betweenness_proxy = g.get("betweenness", 0.0)

            features.append(fv)

        logger.info("Extracted endpoint features: %d vectors", len(features))
        return features

    # ─── Timing Sequence Features (for LSTM-style input) ──────────────────────

    def extract_timing_sequences(self, packets: List[dict],
                                  flow_meta: Dict[str, dict],
                                  seq_len: int = 32
                                  ) -> Dict[str, List[List[float]]]:
        """
        Extract fixed-length timing sequences per flow for the
        LSTM beacon detector.

        Returns
        -------
        dict mapping flow_id → list of [interval, size, direction] triples.
        Each list has exactly `seq_len` elements (zero-padded).
        """
        pkt_by_flow: Dict[str, List[dict]] = defaultdict(list)
        for p in packets:
            fid = p.get("flow_id", "")
            if fid:
                pkt_by_flow[fid].append(p)

        sequences: Dict[str, List[List[float]]] = {}
        for fid, pkts in pkt_by_flow.items():
            if len(pkts) < 4:
                continue
            pkts.sort(key=lambda x: x.get("timestamp", 0))
            meta = flow_meta.get(fid, {})
            src_ip = meta.get("src_ip", pkts[0].get("src_ip", ""))

            seq: List[List[float]] = []
            for i in range(1, len(pkts)):
                interval = pkts[i].get("timestamp", 0) - pkts[i-1].get("timestamp", 0)
                size = math.log1p(pkts[i].get("size", 0))
                direction = 1.0 if pkts[i].get("src_ip") == src_ip else -1.0
                seq.append([
                    min(interval, 300.0),  # Cap at 5 minutes
                    size,
                    direction,
                ])

            # Pad or truncate to seq_len
            if len(seq) > seq_len:
                seq = seq[-seq_len:]  # Take most recent
            while len(seq) < seq_len:
                seq.insert(0, [0.0, 0.0, 0.0])

            sequences[fid] = seq

        return sequences

    # ─── Internal Helpers ─────────────────────────────────────────────────────

    def _fill_timing(self, fv: FeatureVector, pkts: List[dict]):
        """Compute timing features from sorted packet list."""
        if len(pkts) < 2:
            return
        timestamps = [p.get("timestamp", 0) for p in pkts]
        intervals = [timestamps[i+1] - timestamps[i]
                      for i in range(len(timestamps) - 1)
                      if timestamps[i+1] - timestamps[i] > 0.001]
        if not intervals:
            return

        fv.interval_mean = statistics.mean(intervals)
        fv.interval_stdev = (
            statistics.stdev(intervals) if len(intervals) > 1 else 0.0)
        fv.interval_cv = (
            fv.interval_stdev / fv.interval_mean
            if fv.interval_mean > 0 else 1.0)

        # Jitter: mean of consecutive interval differences
        if len(intervals) > 1:
            jitters = [abs(intervals[i+1] - intervals[i])
                       for i in range(len(intervals) - 1)]
            fv.interval_jitter = statistics.mean(jitters)

        # Periodicity: autocorrelation at lag 1
        if len(intervals) >= 4:
            fv.periodicity_score = max(0.0,
                                        _autocorrelation_proxy(intervals, 1))

        # Burst ratio
        median_iv = statistics.median(intervals)
        if median_iv > 0:
            fv.burst_ratio = sum(
                1 for iv in intervals if iv < median_iv / 2) / len(intervals)

    def _fill_volume(self, fv: FeatureVector, flow: dict, pkts: List[dict]):
        """Compute volume features."""
        fv.total_bytes = math.log1p(flow.get("total_bytes", 0))
        fv.total_packets = math.log1p(flow.get("packet_count", 0))
        pkt_count = flow.get("packet_count", 0) or 1
        fv.bytes_per_packet = flow.get("total_bytes", 0) / pkt_count
        dur = flow.get("session_duration", 0) or 0.1
        fv.bytes_per_second = flow.get("total_bytes", 0) / dur
        fv.flow_duration = math.log1p(dur)

        # Packet size stdev
        sizes = [p.get("size", 0) for p in pkts if p.get("size")]
        fv.pkt_size_stdev = (
            statistics.stdev(sizes) if len(sizes) > 1 else 0.0)

    def _fill_flow(self, fv: FeatureVector, flow: dict,
                    graph: Dict[str, dict]):
        """Compute flow-level features."""
        fv.protocol_code = PROTOCOL_MAP.get(
            flow.get("protocol", ""), 0.0)
        fv.dst_port_norm = flow.get("dst_port", 0) / 65535

        src = flow.get("src_ip", "")
        g = graph.get(src, {})
        fv.fan_out = math.log1p(g.get("fan_out", 0))
        fv.fan_in = math.log1p(g.get("fan_in", 0))
        fv.betweenness_proxy = g.get("betweenness", 0.0)

    def _fill_tls(self, fv: FeatureVector, flow: dict):
        """Compute TLS fingerprint features."""
        ja3 = flow.get("ja3")
        if ja3:
            count = self._ja3_counts.get(ja3, 1)
            fv.ja3_rarity = round(
                1.0 - count / max(self._total_tls, 1), 4)

        sni = flow.get("sni")
        if sni:
            fv.sni_entropy = _char_entropy(sni)
            fv.sni_length_norm = min(1.0, len(sni) / 50)

        ver = flow.get("tls_version", "")
        fv.tls_version_score = 1.0 if ver in DEPRECATED_TLS else 0.0

    def _fill_dns(self, fv: FeatureVector, flow: dict, pkts: List[dict]):
        """Compute DNS features from flow or packet metadata."""
        sni = flow.get("sni", "")
        dns_queries = [p.get("dns_query", "") for p in pkts
                       if p.get("dns_query")]

        if dns_queries:
            fv.dns_query_entropy = statistics.mean(
                _char_entropy(q) for q in dns_queries)
            labels = [q.split(".")[0] for q in dns_queries]
            fv.dns_label_length = min(
                1.0, statistics.mean(len(l) for l in labels) / 30)
            fv.dns_consonant_ratio = statistics.mean(
                _consonant_ratio(q) for q in dns_queries)
        elif sni:
            fv.dns_query_entropy = _char_entropy(sni)
            fv.dns_label_length = min(
                1.0, len(sni.split(".")[0]) / 30)
            fv.dns_consonant_ratio = _consonant_ratio(sni)

    def _compute_ja3_stats(self, flows: List[dict]):
        """Pre-compute JA3 frequency distribution."""
        self._ja3_counts.clear()
        self._total_tls = 0
        for f in flows:
            if f.get("protocol") == "TLS":
                self._total_tls += 1
                ja3 = f.get("ja3", "")
                if ja3:
                    self._ja3_counts[ja3] = self._ja3_counts.get(ja3, 0) + 1

    def _build_graph(self, flows: List[dict]) -> Dict[str, dict]:
        """Build simplified communication graph metrics."""
        out_map: Dict[str, set] = defaultdict(set)
        in_map: Dict[str, set] = defaultdict(set)
        for f in flows:
            src, dst = f.get("src_ip", ""), f.get("dst_ip", "")
            if src and dst:
                out_map[src].add(dst)
                in_map[dst].add(src)

        # All IPs
        all_ips = set(out_map.keys()) | set(in_map.keys())

        graph: Dict[str, dict] = {}
        for ip in all_ips:
            fan_out = len(out_map.get(ip, set()))
            fan_in = len(in_map.get(ip, set()))
            # Betweenness proxy: nodes that connect many unique src↔dst pairs
            # Approximation: (fan_in × fan_out) / total_possible_pairs
            total_ips = max(len(all_ips), 1)
            betweenness = (fan_in * fan_out) / (total_ips ** 2)
            graph[ip] = {
                "fan_out": fan_out,
                "fan_in": fan_in,
                "betweenness": round(min(1.0, betweenness * 10), 4),
            }

        return graph


# ═══════════════════════════════════════════════════════════════════════════════
# Normalizer (Min-Max per-feature, learned from training data)
# ═══════════════════════════════════════════════════════════════════════════════

class FeatureNormalizer:
    """Min-Max feature normalizer — no sklearn dependency."""

    def __init__(self):
        self.mins: Optional[List[float]] = None
        self.maxs: Optional[List[float]] = None
        self._fitted = False

    def fit(self, vectors: List[List[float]]):
        if not vectors:
            return
        dim = len(vectors[0])
        self.mins = [min(v[i] for v in vectors) for i in range(dim)]
        self.maxs = [max(v[i] for v in vectors) for i in range(dim)]
        self._fitted = True

    def transform(self, vector: List[float]) -> List[float]:
        if not self._fitted:
            return vector
        result = []
        for i, val in enumerate(vector):
            rng = self.maxs[i] - self.mins[i]
            if rng == 0:
                result.append(0.0)
            else:
                result.append(max(0.0, min(1.0,
                    (val - self.mins[i]) / rng)))
        return result

    def transform_batch(self, vectors: List[List[float]]) -> List[List[float]]:
        return [self.transform(v) for v in vectors]

    def fit_transform(self, vectors: List[List[float]]) -> List[List[float]]:
        self.fit(vectors)
        return self.transform_batch(vectors)

    def to_dict(self) -> dict:
        return {"mins": self.mins, "maxs": self.maxs, "fitted": self._fitted}

    @classmethod
    def from_dict(cls, d: dict) -> "FeatureNormalizer":
        n = cls()
        n.mins = d.get("mins")
        n.maxs = d.get("maxs")
        n._fitted = d.get("fitted", False)
        return n
