"""
NetForensics — Endpoint Correlation Engine
===========================================
Correlates communication endpoints by:
  • Shared JA3 fingerprints
  • Common destination IPs
  • Behavioural similarity (flow timing, size distributions)
  • Repeated session patterns
"""

from collections import defaultdict
from typing import Dict, List, Set, Tuple


def correlate_by_ja3(flows: List[dict]) -> Dict[str, List[str]]:
    """Group source IPs that share the same JA3 fingerprint."""
    ja3_to_ips: Dict[str, Set[str]] = defaultdict(set)
    for f in flows:
        if f.get("ja3") and f.get("src_ip"):
            ja3_to_ips[f["ja3"]].add(f["src_ip"])
    return {ja3: sorted(ips) for ja3, ips in ja3_to_ips.items() if len(ips) > 1}


def correlate_by_destination(flows: List[dict]) -> Dict[str, List[str]]:
    """Group source IPs that communicate with the same external destination."""
    dst_to_srcs: Dict[str, Set[str]] = defaultdict(set)
    for f in flows:
        src, dst = f.get("src_ip",""), f.get("dst_ip","")
        if src and dst:
            dst_to_srcs[dst].add(src)
    return {dst: sorted(srcs) for dst, srcs in dst_to_srcs.items() if len(srcs) > 2}


def find_repeated_sessions(flows: List[dict], min_repeat: int = 5) -> List[dict]:
    """Detect (src, dst, port) tuples seen repeatedly — possible C2 keep-alive."""
    counter: Dict[Tuple, int] = defaultdict(int)
    for f in flows:
        key = (f.get("src_ip",""), f.get("dst_ip",""), f.get("dst_port",0))
        counter[key] += 1
    return [
        {"src_ip": k[0], "dst_ip": k[1], "dst_port": k[2], "count": v}
        for k, v in counter.items() if v >= min_repeat
    ]


def session_similarity(f1: dict, f2: dict) -> float:
    """
    Cosine-like similarity between two flows based on:
    packet_count, total_bytes, session_duration, dst_port.
    Returns 0.0–1.0.
    """
    import math
    v1 = [f1.get("packet_count",0), f1.get("total_bytes",0)/1e6,
          f1.get("session_duration",0), f1.get("dst_port",0)/65535]
    v2 = [f2.get("packet_count",0), f2.get("total_bytes",0)/1e6,
          f2.get("session_duration",0), f2.get("dst_port",0)/65535]
    dot   = sum(a*b for a,b in zip(v1,v2))
    mag1  = math.sqrt(sum(a*a for a in v1)) or 1
    mag2  = math.sqrt(sum(b*b for b in v2)) or 1
    return round(dot / (mag1 * mag2), 4)


def find_similar_flows(flows: List[dict], threshold: float = 0.95) -> List[dict]:
    """Find pairs of flows that are highly similar (possible replays / automation)."""
    pairs = []
    for i in range(len(flows)):
        for j in range(i+1, min(i+50, len(flows))):   # limit O(n²) window
            sim = session_similarity(flows[i], flows[j])
            if sim >= threshold:
                pairs.append({
                    "flow_a": flows[i].get("flow_id",""),
                    "flow_b": flows[j].get("flow_id",""),
                    "similarity": sim,
                    "src_a": flows[i].get("src_ip",""),
                    "src_b": flows[j].get("src_ip",""),
                })
    return pairs
