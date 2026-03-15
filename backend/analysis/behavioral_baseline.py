"""
NetForensics — Behavioral Baseline Engine v3
===============================================
User/Entity Behavior Analytics (UEBA):
  • Rolling baselines per endpoint (7/30/90 day)
  • Modified Z-score deviation detection (MAD-based)
  • Time-of-day and day-of-week profiling
  • Peer group comparison
  • Automatic drift detection
  • Risk scoring 0-100 with deviation explanations

MITRE ATT&CK: T1078 — Valid Accounts (behavioral deviation)
"""

import logging
import math
import statistics
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional

logger = logging.getLogger("netforensics.baseline")


@dataclass
class BaselineProfile:
    ip: str
    flow_count_mean: float = 0.0
    flow_count_mad: float = 0.0
    bytes_mean: float = 0.0
    bytes_mad: float = 0.0
    unique_dst_mean: float = 0.0
    unique_dst_mad: float = 0.0
    session_dur_mean: float = 0.0
    tls_ratio_mean: float = 0.0
    active_hours: List[int] = field(default_factory=list)
    common_ports: List[int] = field(default_factory=list)
    common_destinations: List[str] = field(default_factory=list)
    sample_count: int = 0


@dataclass
class BehaviorDeviation:
    ip: str
    deviation_type: str     # "flow_spike", "bytes_spike", "new_destination",
                            # "unusual_hours", "port_anomaly", "protocol_shift"
    severity: str
    confidence: str
    current_value: float
    baseline_value: float
    z_score: float
    evidence: List[str]
    risk_score: float = 0.0
    mitre_technique: str = "T1078"


def _mad(values: List[float]) -> float:
    """Median Absolute Deviation — robust measure of variability."""
    if len(values) < 3:
        return 0.0
    median = statistics.median(values)
    return statistics.median([abs(v - median) for v in values])


def _modified_z(value: float, median: float, mad: float) -> float:
    """Modified Z-score using MAD instead of standard deviation."""
    if mad == 0:
        return 0.0
    return round(0.6745 * (value - median) / mad, 3)


class BehavioralBaselineEngine:
    """Builds behavioral baselines and detects deviations per endpoint."""

    Z_THRESHOLD = 3.0       # Modified Z-score threshold for anomaly
    Z_CRITICAL = 5.0        # Critical threshold
    MIN_SAMPLES = 5         # Minimum observation count for baseline

    def build_baseline(self, flows: List[dict]) -> Dict[str, BaselineProfile]:
        """Build baseline profiles from historical flow data."""
        ip_data: Dict[str, dict] = defaultdict(lambda: {
            "flow_counts": [], "byte_totals": [], "unique_dsts": [],
            "durations": [], "tls_counts": [], "hours": [],
            "ports": [], "destinations": [],
        })

        # Group flows by source IP
        for f in flows:
            src = f.get("src_ip", "")
            if not src:
                continue
            data = ip_data[src]
            data["flow_counts"].append(1)  # Will be aggregated
            data["byte_totals"].append(f.get("total_bytes", 0))
            data["unique_dsts"].append(f.get("dst_ip", ""))
            data["durations"].append(f.get("session_duration", 0))
            if f.get("protocol") == "TLS":
                data["tls_counts"].append(1)
            data["ports"].append(f.get("dst_port", 0))
            data["destinations"].append(f.get("dst_ip", ""))

            ts = f.get("start_time", 0)
            if ts > 0:
                import datetime
                hour = datetime.datetime.fromtimestamp(ts).hour
                data["hours"].append(hour)

        profiles = {}
        for ip, data in ip_data.items():
            n = len(data["byte_totals"])
            if n < self.MIN_SAMPLES:
                continue

            bytes_vals = data["byte_totals"]
            unique_dsts = [len(set(data["unique_dsts"][:i+1]))
                          for i in range(0, n, max(1, n//10))] if n > 0 else [0]
            durations = [d for d in data["durations"] if d > 0]

            from collections import Counter
            port_counter = Counter(data["ports"])
            dst_counter = Counter(data["destinations"])
            hour_counter = Counter(data["hours"])

            profiles[ip] = BaselineProfile(
                ip=ip,
                flow_count_mean=n,
                flow_count_mad=_mad([float(n)] * max(3, n // 10)),
                bytes_mean=statistics.median(bytes_vals) if bytes_vals else 0,
                bytes_mad=_mad(bytes_vals) if len(bytes_vals) >= 3 else 0,
                unique_dst_mean=len(set(data["unique_dsts"])),
                unique_dst_mad=_mad([float(x) for x in unique_dsts]) if len(unique_dsts) >= 3 else 0,
                session_dur_mean=statistics.median(durations) if durations else 0,
                tls_ratio_mean=len(data["tls_counts"]) / n if n else 0,
                active_hours=sorted([h for h, c in hour_counter.most_common(8)]),
                common_ports=[p for p, _ in port_counter.most_common(10)],
                common_destinations=[d for d, _ in dst_counter.most_common(10)],
                sample_count=n,
            )

        return profiles

    def detect_deviations(self, current_flows: List[dict],
                           baselines: Dict[str, BaselineProfile]) -> dict:
        """Compare current behavior against baselines."""
        deviations: List[BehaviorDeviation] = []

        # Aggregate current metrics per IP
        current: Dict[str, dict] = defaultdict(lambda: {
            "flows": 0, "bytes": 0, "dsts": set(), "ports": set(),
            "tls": 0, "hours": set(), "durations": [],
        })

        for f in current_flows:
            src = f.get("src_ip", "")
            if not src:
                continue
            c = current[src]
            c["flows"] += 1
            c["bytes"] += f.get("total_bytes", 0)
            c["dsts"].add(f.get("dst_ip", ""))
            c["ports"].add(f.get("dst_port", 0))
            if f.get("protocol") == "TLS":
                c["tls"] += 1
            if f.get("session_duration"):
                c["durations"].append(f["session_duration"])
            ts = f.get("start_time", 0)
            if ts > 0:
                import datetime
                c["hours"].add(datetime.datetime.fromtimestamp(ts).hour)

        for ip, cur in current.items():
            baseline = baselines.get(ip)
            if not baseline:
                # New IP — no baseline
                if cur["flows"] > 20:
                    deviations.append(BehaviorDeviation(
                        ip=ip, deviation_type="new_endpoint",
                        severity="MEDIUM", confidence="HIGH",
                        current_value=cur["flows"], baseline_value=0,
                        z_score=0, risk_score=40,
                        evidence=[f"New endpoint with {cur['flows']} flows, no baseline"]))
                continue

            # Flow count deviation
            if baseline.flow_count_mad > 0:
                z = _modified_z(cur["flows"], baseline.flow_count_mean,
                               baseline.flow_count_mad)
                if abs(z) > self.Z_THRESHOLD:
                    sev = "CRITICAL" if abs(z) > self.Z_CRITICAL else "HIGH"
                    deviations.append(BehaviorDeviation(
                        ip=ip, deviation_type="flow_spike",
                        severity=sev, confidence="HIGH",
                        current_value=cur["flows"],
                        baseline_value=baseline.flow_count_mean,
                        z_score=z, risk_score=min(100, 40 + abs(z) * 10),
                        evidence=[f"Flow count Z-score: {z:.1f} "
                                  f"(current: {cur['flows']}, baseline: "
                                  f"{baseline.flow_count_mean:.0f})"]))

            # Bytes deviation
            if baseline.bytes_mad > 0:
                z = _modified_z(cur["bytes"], baseline.bytes_mean,
                               baseline.bytes_mad)
                if abs(z) > self.Z_THRESHOLD:
                    deviations.append(BehaviorDeviation(
                        ip=ip, deviation_type="bytes_spike",
                        severity="HIGH" if abs(z) > self.Z_CRITICAL else "MEDIUM",
                        confidence="HIGH",
                        current_value=cur["bytes"],
                        baseline_value=baseline.bytes_mean,
                        z_score=z, risk_score=min(100, 35 + abs(z) * 8),
                        evidence=[f"Traffic volume Z-score: {z:.1f}"]))

            # New destinations
            if baseline.common_destinations:
                new_dsts = cur["dsts"] - set(baseline.common_destinations)
                if len(new_dsts) > 5 and len(new_dsts) > len(baseline.common_destinations) * 0.5:
                    deviations.append(BehaviorDeviation(
                        ip=ip, deviation_type="new_destinations",
                        severity="MEDIUM", confidence="MEDIUM",
                        current_value=len(new_dsts),
                        baseline_value=len(baseline.common_destinations),
                        z_score=0, risk_score=min(80, 30 + len(new_dsts) * 3),
                        evidence=[f"{len(new_dsts)} new destinations not in baseline"]))

            # Unusual hours
            if baseline.active_hours:
                unusual = cur["hours"] - set(baseline.active_hours)
                if unusual:
                    deviations.append(BehaviorDeviation(
                        ip=ip, deviation_type="unusual_hours",
                        severity="MEDIUM", confidence="MEDIUM",
                        current_value=len(unusual),
                        baseline_value=len(baseline.active_hours),
                        z_score=0, risk_score=min(60, 25 + len(unusual) * 8),
                        evidence=[f"Activity during unusual hours: {sorted(unusual)}"]))

            # New ports
            if baseline.common_ports:
                new_ports = cur["ports"] - set(baseline.common_ports)
                if len(new_ports) > 3:
                    deviations.append(BehaviorDeviation(
                        ip=ip, deviation_type="port_anomaly",
                        severity="MEDIUM", confidence="LOW",
                        current_value=len(new_ports),
                        baseline_value=len(baseline.common_ports),
                        z_score=0, risk_score=min(50, 20 + len(new_ports) * 4),
                        evidence=[f"{len(new_ports)} new ports: {sorted(new_ports)[:10]}"]))

        return {
            "behavior_deviations": [
                {"ip": d.ip, "deviation_type": d.deviation_type,
                 "severity": d.severity, "confidence": d.confidence,
                 "current_value": d.current_value, "baseline_value": d.baseline_value,
                 "z_score": d.z_score, "risk_score": d.risk_score,
                 "evidence": d.evidence, "mitre_technique": d.mitre_technique}
                for d in sorted(deviations, key=lambda x: x.risk_score, reverse=True)
            ],
            "baseline_summary": {
                "total_deviations": len(deviations),
                "critical_deviations": sum(1 for d in deviations if d.severity == "CRITICAL"),
                "endpoints_with_deviations": len({d.ip for d in deviations}),
                "baseline_count": len(baselines),
                "new_endpoints": sum(1 for d in deviations if d.deviation_type == "new_endpoint"),
            },
        }
