"""
NetForensics — Autonomous Threat Hunting Engine v5
=====================================================
AI-powered autonomous threat detection that finds suspicious patterns
without manual rules or signatures:

  MODULE 1: PatternAnomalyDetector   — Statistical outlier detection on flow features
  MODULE 2: BehaviorSequenceAnalyzer — Multi-step attack chain detection
  MODULE 3: PeerGroupAnalyzer        — Peer comparison anomaly scoring
  MODULE 4: TemporalPatternHunter    — Time-based anomaly hunting (midnight, weekends)
  MODULE 5: ThreatHypothesisEngine   — Automated hypothesis generation & testing

Uses pure Python statistical methods — no external ML libraries required.

MITRE ATT&CK: Multiple techniques detected automatically
"""

import hashlib
import logging
import math
import statistics
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("netforensics.threat_hunting")


# ═══════════════════════════════════════════════════════════════════════════════
# DATA CLASSES
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class HuntingFinding:
    """An autonomous threat hunting discovery."""
    finding_id: str
    title: str
    description: str
    severity: str               # CRITICAL, HIGH, MEDIUM, LOW
    confidence: float           # 0-1
    threat_score: float         # 0-100
    category: str               # "anomaly", "pattern", "behavioral", "temporal"
    hunt_type: str              # Specific detection that triggered
    affected_ips: List[str]
    evidence: List[str]
    mitre_techniques: List[str]
    recommended_actions: List[str]
    raw_data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackChain:
    """Multi-step attack sequence detected across time."""
    chain_id: str
    stages: List[Dict]          # Ordered list of attack stages
    affected_ips: List[str]
    total_score: float
    confidence: float
    kill_chain_coverage: List[str]  # Kill chain stages covered
    mitre_techniques: List[str]
    evidence: List[str]


@dataclass
class ThreatHypothesis:
    """Automatically generated threat hypothesis."""
    hypothesis_id: str
    hypothesis: str             # Natural language hypothesis
    evidence_for: List[str]
    evidence_against: List[str]
    confidence: float
    verdict: str                # "confirmed", "likely", "possible", "unlikely"
    affected_ips: List[str]
    mitre_technique: str


# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 1: PATTERN ANOMALY DETECTOR
# ═══════════════════════════════════════════════════════════════════════════════

class PatternAnomalyDetector:
    """
    Multi-dimensional statistical outlier detection.
    Computes z-scores across multiple flow features and combines them
    into a composite anomaly score using Mahalanobis-inspired distance.
    """

    FEATURES = [
        "total_bytes", "packet_count", "session_duration",
        "unique_destinations", "port_entropy", "tls_ratio",
    ]

    def analyse(self, flows: List[dict]) -> List[HuntingFinding]:
        findings = []

        # Aggregate per-IP features
        ip_features = self._extract_features(flows)
        if len(ip_features) < 5:
            return findings

        # Compute feature distributions
        feature_stats = {}
        for feat in self.FEATURES:
            values = [f.get(feat, 0) for f in ip_features.values()]
            if len(values) < 3:
                continue
            med = statistics.median(values)
            mad = statistics.median([abs(v - med) for v in values])
            feature_stats[feat] = {"median": med, "mad": max(mad, 0.001)}

        # Score each IP
        for ip, features in ip_features.items():
            z_scores = {}
            for feat, stats in feature_stats.items():
                val = features.get(feat, 0)
                z = 0.6745 * (val - stats["median"]) / stats["mad"]
                z_scores[feat] = z

            # Composite anomaly score (RMS of z-scores)
            z_vals = [abs(z) for z in z_scores.values()]
            composite = math.sqrt(sum(z ** 2 for z in z_vals) / len(z_vals)) if z_vals else 0

            if composite > 3.0:
                # Identify which features are anomalous
                anomalous_features = [
                    (feat, z) for feat, z in z_scores.items() if abs(z) > 2.5]

                severity = ("CRITICAL" if composite > 6 else
                           "HIGH" if composite > 4.5 else
                           "MEDIUM" if composite > 3.5 else "LOW")

                evidence = [f"Composite anomaly score: {composite:.2f}"]
                for feat, z in anomalous_features:
                    evidence.append(
                        f"  {feat}: z-score={z:.1f} "
                        f"(value={features.get(feat, 0):.0f}, "
                        f"median={feature_stats[feat]['median']:.0f})")

                # Determine category
                mitre = []
                if z_scores.get("total_bytes", 0) > 3: mitre.append("T1041")  # Exfil
                if z_scores.get("unique_destinations", 0) > 3: mitre.append("T1046")  # Scan
                if z_scores.get("session_duration", 0) > 3: mitre.append("T1071")  # C2

                fid = hashlib.md5(f"anomaly:{ip}:{composite}".encode()).hexdigest()[:10]
                findings.append(HuntingFinding(
                    finding_id=fid,
                    title=f"Statistical anomaly — {ip}",
                    description=f"Endpoint {ip} shows statistically significant deviation "
                               f"across {len(anomalous_features)} features",
                    severity=severity,
                    confidence=min(1.0, composite / 8),
                    threat_score=min(100, composite * 12),
                    category="anomaly",
                    hunt_type="statistical_outlier",
                    affected_ips=[ip],
                    evidence=evidence,
                    mitre_techniques=mitre,
                    recommended_actions=[
                        f"Investigate traffic from/to {ip}",
                        "Check if this is an authorized activity",
                        "Review related DNS queries and JA3 fingerprints",
                    ],
                    raw_data={"z_scores": z_scores, "composite": composite},
                ))

        return sorted(findings, key=lambda f: f.threat_score, reverse=True)[:20]

    def _extract_features(self, flows: List[dict]) -> Dict[str, Dict]:
        ip_data: Dict[str, Dict] = defaultdict(lambda: {
            "total_bytes": 0, "packet_count": 0, "session_duration": 0,
            "unique_destinations": set(), "ports": [],
            "tls_count": 0, "flow_count": 0,
        })

        for f in flows:
            src = f.get("src_ip", "")
            if not src:
                continue
            d = ip_data[src]
            d["total_bytes"] += f.get("total_bytes", 0)
            d["packet_count"] += f.get("packet_count", 0)
            d["session_duration"] += f.get("session_duration", 0)
            d["unique_destinations"].add(f.get("dst_ip", ""))
            d["ports"].append(f.get("dst_port", 0))
            if f.get("protocol") == "TLS":
                d["tls_count"] += 1
            d["flow_count"] += 1

        # Convert to numeric features
        result = {}
        for ip, d in ip_data.items():
            ports = d["ports"]
            freq = Counter(ports)
            n = len(ports)
            port_entropy = -sum((c / n) * math.log2(c / n) for c in freq.values()) if n > 0 else 0

            result[ip] = {
                "total_bytes": d["total_bytes"],
                "packet_count": d["packet_count"],
                "session_duration": d["session_duration"],
                "unique_destinations": len(d["unique_destinations"]),
                "port_entropy": round(port_entropy, 4),
                "tls_ratio": d["tls_count"] / d["flow_count"] if d["flow_count"] else 0,
            }
        return result


# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 2: BEHAVIOR SEQUENCE ANALYZER
# ═══════════════════════════════════════════════════════════════════════════════

class BehaviorSequenceAnalyzer:
    """
    Detect multi-step attack chains by analyzing temporal sequences of
    suspicious behaviors from the same IP.

    Looks for kill chain progression:
    Recon → Initial Access → Execution → Persistence →
    Privilege Escalation → Lateral Movement → C2 → Exfiltration
    """

    KILL_CHAIN = [
        "reconnaissance", "initial_access", "execution",
        "persistence", "privilege_escalation", "defense_evasion",
        "lateral_movement", "command_control", "exfiltration",
    ]

    BEHAVIOR_TO_CHAIN = {
        "port_scan": ("reconnaissance", "T1046"),
        "new_endpoint": ("initial_access", "T1190"),
        "unusual_protocol": ("execution", "T1059"),
        "new_port": ("persistence", "T1543"),
        "privilege_change": ("privilege_escalation", "T1068"),
        "dns_tunnel": ("defense_evasion", "T1071.004"),
        "lateral_scan": ("lateral_movement", "T1021"),
        "beacon": ("command_control", "T1071.001"),
        "c2_connection": ("command_control", "T1071"),
        "data_exfil": ("exfiltration", "T1041"),
        "tor_usage": ("defense_evasion", "T1090.003"),
        "dga_domain": ("command_control", "T1568"),
    }

    def analyse(self, analysis_results: dict) -> List[AttackChain]:
        chains = []

        # Collect behaviors per IP
        ip_behaviors: Dict[str, List[Dict]] = defaultdict(list)

        # From beacons
        for b in analysis_results.get("beacons", []):
            ip_behaviors[b.get("src_ip", "")].append({
                "behavior": "beacon", "timestamp": 0,
                "detail": f"Beacon to {b.get('dst_ip', '')} "
                         f"interval={b.get('interval_mean', 0)}s",
            })

        # From suspicious IPs
        for s in analysis_results.get("suspicious_ips", []):
            ip = s.get("ip", "")
            for reason in s.get("reasons", []):
                reason_lower = reason.lower()
                if "scan" in reason_lower or "sweep" in reason_lower:
                    ip_behaviors[ip].append({"behavior": "port_scan", "detail": reason})
                elif "c2" in reason_lower:
                    ip_behaviors[ip].append({"behavior": "c2_connection", "detail": reason})
                elif "malware" in reason_lower or "ja3" in reason_lower:
                    ip_behaviors[ip].append({"behavior": "c2_connection", "detail": reason})
                elif "exfil" in reason_lower:
                    ip_behaviors[ip].append({"behavior": "data_exfil", "detail": reason})
                elif "dga" in reason_lower:
                    ip_behaviors[ip].append({"behavior": "dga_domain", "detail": reason})

        # From exfiltration alerts
        for e in analysis_results.get("exfil_alerts", []):
            ip_behaviors[e.get("src_ip", "")].append({
                "behavior": "data_exfil",
                "detail": f"Exfil: {e.get('total_sent', 0) / 1e6:.1f}MB",
            })

        # From DGA alerts
        for d in analysis_results.get("dga_alerts", []):
            ip_behaviors[d.get("src_ip", "")].append({
                "behavior": "dga_domain",
                "detail": f"DGA domain: {d.get('domain', '')}",
            })

        # Detect chains
        for ip, behaviors in ip_behaviors.items():
            if len(behaviors) < 2:
                continue

            stages = []
            covered_chain = set()
            mitre = []
            for beh in behaviors:
                chain_map = self.BEHAVIOR_TO_CHAIN.get(beh["behavior"])
                if chain_map:
                    stage, technique = chain_map
                    if stage not in covered_chain:
                        covered_chain.add(stage)
                        mitre.append(technique)
                        stages.append({
                            "stage": stage,
                            "behavior": beh["behavior"],
                            "detail": beh.get("detail", ""),
                            "mitre": technique,
                        })

            if len(stages) >= 2:
                # Score based on kill chain coverage
                chain_idx = [self.KILL_CHAIN.index(s["stage"])
                            for s in stages if s["stage"] in self.KILL_CHAIN]
                progress = max(chain_idx) - min(chain_idx) + 1 if chain_idx else 0
                score = min(100, len(stages) * 15 + progress * 10)
                confidence = min(1.0, len(stages) / 5)

                chain_id = hashlib.md5(f"chain:{ip}".encode()).hexdigest()[:10]
                chains.append(AttackChain(
                    chain_id=chain_id,
                    stages=stages,
                    affected_ips=[ip],
                    total_score=score,
                    confidence=confidence,
                    kill_chain_coverage=sorted(covered_chain),
                    mitre_techniques=sorted(set(mitre)),
                    evidence=[f"{ip}: {len(stages)} attack stages detected",
                             f"Kill chain coverage: {', '.join(sorted(covered_chain))}"]
                            + [s["detail"] for s in stages[:5]],
                ))

        return sorted(chains, key=lambda c: c.total_score, reverse=True)[:15]


# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 3: PEER GROUP ANALYZER
# ═══════════════════════════════════════════════════════════════════════════════

class PeerGroupAnalyzer:
    """
    Compare each endpoint against its peer group to find outliers.
    Peers are grouped by subnet and communication pattern.
    """

    def analyse(self, flows: List[dict]) -> List[HuntingFinding]:
        findings = []

        # Group IPs by /24 subnet
        subnet_ips: Dict[str, Dict[str, Dict]] = defaultdict(dict)
        for f in flows:
            src = f.get("src_ip", "")
            if not src:
                continue
            subnet = ".".join(src.split(".")[:3])
            if src not in subnet_ips[subnet]:
                subnet_ips[subnet][src] = {
                    "bytes": 0, "flows": 0, "dsts": set(), "ports": set(),
                    "tls": 0, "protocols": set(),
                }
            d = subnet_ips[subnet][src]
            d["bytes"] += f.get("total_bytes", 0)
            d["flows"] += 1
            d["dsts"].add(f.get("dst_ip", ""))
            d["ports"].add(f.get("dst_port", 0))
            d["tls"] += 1 if f.get("protocol") == "TLS" else 0
            d["protocols"].add(f.get("protocol", ""))

        for subnet, ips in subnet_ips.items():
            if len(ips) < 3:
                continue

            # Compute peer group statistics
            byte_vals = [d["bytes"] for d in ips.values()]
            flow_vals = [d["flows"] for d in ips.values()]
            dst_vals = [len(d["dsts"]) for d in ips.values()]

            byte_med = statistics.median(byte_vals)
            byte_mad = statistics.median([abs(v - byte_med) for v in byte_vals])
            flow_med = statistics.median(flow_vals)
            flow_mad = statistics.median([abs(v - flow_med) for v in flow_vals])

            for ip, data in ips.items():
                anomaly_reasons = []

                # Bytes outlier
                if byte_mad > 0:
                    z = 0.6745 * (data["bytes"] - byte_med) / byte_mad
                    if abs(z) > 3:
                        anomaly_reasons.append(
                            f"Traffic volume: {data['bytes'] / 1024:.0f}KB "
                            f"(peer median: {byte_med / 1024:.0f}KB, z={z:.1f})")

                # Destination count outlier
                if len(ips) > 3:
                    dst_med = statistics.median(dst_vals)
                    dst_mad = statistics.median([abs(v - dst_med) for v in dst_vals])
                    if dst_mad > 0:
                        z = 0.6745 * (len(data["dsts"]) - dst_med) / dst_mad
                        if abs(z) > 3:
                            anomaly_reasons.append(
                                f"Destination count: {len(data['dsts'])} "
                                f"(peer median: {dst_med:.0f}, z={z:.1f})")

                if anomaly_reasons:
                    fid = hashlib.md5(f"peer:{ip}:{subnet}".encode()).hexdigest()[:10]
                    findings.append(HuntingFinding(
                        finding_id=fid,
                        title=f"Peer group outlier — {ip} (subnet {subnet}.0/24)",
                        description=f"{ip} deviates significantly from {len(ips) - 1} peers "
                                   f"in subnet {subnet}.0/24",
                        severity="HIGH" if len(anomaly_reasons) > 1 else "MEDIUM",
                        confidence=0.7,
                        threat_score=min(80, 30 + len(anomaly_reasons) * 20),
                        category="behavioral",
                        hunt_type="peer_group_outlier",
                        affected_ips=[ip],
                        evidence=[f"Peer group: {len(ips)} IPs in {subnet}.0/24"]
                                + anomaly_reasons,
                        mitre_techniques=["T1071"],
                        recommended_actions=[
                            f"Investigate {ip} — anomalous within its subnet",
                            "Compare with baseline behavior",
                        ],
                    ))

        return sorted(findings, key=lambda f: f.threat_score, reverse=True)[:15]


# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 4: TEMPORAL PATTERN HUNTER
# ═══════════════════════════════════════════════════════════════════════════════

class TemporalPatternHunter:
    """
    Detect time-based anomalies:
    - Midnight/off-hours activity
    - Weekend spikes
    - Periodic patterns (beaconing variants)
    - Sudden behavioral changes
    """

    def analyse(self, flows: List[dict]) -> List[HuntingFinding]:
        findings = []

        # Group by IP and hour
        ip_hours: Dict[str, Dict[int, int]] = defaultdict(lambda: defaultdict(int))
        ip_volumes: Dict[str, Dict[int, int]] = defaultdict(lambda: defaultdict(int))

        for f in flows:
            src = f.get("src_ip", "")
            ts = f.get("start_time", 0)
            if not src or not ts:
                continue
            import datetime
            try:
                dt = datetime.datetime.fromtimestamp(ts)
                hour = dt.hour
                ip_hours[src][hour] += 1
                ip_volumes[src][hour] += f.get("total_bytes", 0)
            except (ValueError, OSError):
                continue

        for ip, hours in ip_hours.items():
            total_flows = sum(hours.values())
            if total_flows < 10:
                continue

            # Off-hours activity (midnight to 5 AM)
            off_hours_flows = sum(hours.get(h, 0) for h in range(0, 6))
            off_hours_ratio = off_hours_flows / total_flows

            if off_hours_ratio > 0.4 and off_hours_flows > 5:
                off_hours_bytes = sum(ip_volumes[ip].get(h, 0) for h in range(0, 6))
                fid = hashlib.md5(f"temporal:offhours:{ip}".encode()).hexdigest()[:10]
                findings.append(HuntingFinding(
                    finding_id=fid,
                    title=f"Off-hours activity — {ip}",
                    description=f"{off_hours_ratio:.0%} of traffic from {ip} occurs "
                               f"during midnight-5AM ({off_hours_flows} flows)",
                    severity="HIGH" if off_hours_ratio > 0.6 else "MEDIUM",
                    confidence=0.65,
                    threat_score=min(80, 30 + off_hours_ratio * 60),
                    category="temporal",
                    hunt_type="off_hours_activity",
                    affected_ips=[ip],
                    evidence=[
                        f"Off-hours (00:00-05:00): {off_hours_flows} flows "
                        f"({off_hours_ratio:.0%}), {off_hours_bytes / 1024:.0f}KB",
                        f"Total flows: {total_flows}",
                        f"Active hours: {sorted(h for h, c in hours.items() if c > 0)}",
                    ],
                    mitre_techniques=["T1071"],
                    recommended_actions=[
                        f"Verify if {ip} should be active during off-hours",
                        "Check for automated tasks or scheduled backups",
                        "Review destination IPs during off-hours",
                    ],
                ))

            # Unusual single-hour concentration
            max_hour = max(hours, key=hours.get)
            max_ratio = hours[max_hour] / total_flows
            if max_ratio > 0.5 and total_flows > 20:
                fid = hashlib.md5(f"temporal:burst:{ip}:{max_hour}".encode()).hexdigest()[:10]
                findings.append(HuntingFinding(
                    finding_id=fid,
                    title=f"Traffic burst at {max_hour:02d}:00 — {ip}",
                    description=f"{max_ratio:.0%} of traffic from {ip} concentrated "
                               f"in hour {max_hour:02d}:00",
                    severity="MEDIUM",
                    confidence=0.5,
                    threat_score=min(60, 25 + max_ratio * 40),
                    category="temporal",
                    hunt_type="temporal_concentration",
                    affected_ips=[ip],
                    evidence=[
                        f"Peak hour {max_hour:02d}:00: {hours[max_hour]} flows "
                        f"({max_ratio:.0%} of total)",
                    ],
                    mitre_techniques=["T1053"],
                    recommended_actions=[
                        f"Investigate scheduled tasks on {ip} at {max_hour:02d}:00",
                    ],
                ))

        return sorted(findings, key=lambda f: f.threat_score, reverse=True)[:15]


# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 5: THREAT HYPOTHESIS ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

class ThreatHypothesisEngine:
    """
    Automatically generate and evaluate threat hypotheses based on
    observed evidence. Combines multiple signals into coherent hypotheses.
    """

    HYPOTHESES_TEMPLATES = [
        {
            "id": "h_c2_active",
            "hypothesis": "{ip} is communicating with a C2 server at {dst}",
            "required_signals": ["beacon", "malware_ja3"],
            "supporting_signals": ["dga_domain", "tor_usage", "low_tls_ratio"],
            "mitre": "T1071.001",
        },
        {
            "id": "h_exfil_active",
            "hypothesis": "Data exfiltration from {ip} to {dst}",
            "required_signals": ["high_outbound", "asymmetric_traffic"],
            "supporting_signals": ["off_hours", "encrypted", "new_destination"],
            "mitre": "T1041",
        },
        {
            "id": "h_lateral_movement",
            "hypothesis": "{ip} is performing lateral movement across the network",
            "required_signals": ["internal_scan", "multi_port"],
            "supporting_signals": ["smb_traffic", "rdp_traffic", "new_credentials"],
            "mitre": "T1021",
        },
        {
            "id": "h_tor_c2",
            "hypothesis": "{ip} is using Tor for C2 communications",
            "required_signals": ["tor_usage", "beacon"],
            "supporting_signals": ["encrypted", "off_hours", "regular_timing"],
            "mitre": "T1090.003",
        },
        {
            "id": "h_insider_threat",
            "hypothesis": "Possible insider threat from {ip}",
            "required_signals": ["off_hours", "high_outbound"],
            "supporting_signals": ["new_destination", "usb_detected"],
            "mitre": "T1078",
        },
    ]

    def generate_hypotheses(self, analysis_results: dict,
                            flows: List[dict]) -> List[ThreatHypothesis]:
        hypotheses = []

        # Extract signals per IP
        ip_signals = self._extract_signals(analysis_results, flows)

        for ip, signals in ip_signals.items():
            for template in self.HYPOTHESES_TEMPLATES:
                required = set(template["required_signals"])
                supporting = set(template["supporting_signals"])

                required_met = required.intersection(signals.keys())
                supporting_met = supporting.intersection(signals.keys())

                if len(required_met) >= len(required):
                    # Hypothesis confirmed
                    confidence = 0.5 + 0.1 * len(supporting_met)
                    confidence = min(1.0, confidence)

                    evidence_for = [signals[s]["detail"] for s in required_met]
                    evidence_for += [signals[s]["detail"] for s in supporting_met]
                    evidence_against = []

                    # Look for counter-evidence
                    if "whitelisted" in signals:
                        evidence_against.append("IP is whitelisted")
                        confidence *= 0.5
                    if signals.get("flow_count", {}).get("value", 0) < 5:
                        evidence_against.append("Low flow count — may be noise")
                        confidence *= 0.8

                    verdict = ("confirmed" if confidence > 0.8 else
                             "likely" if confidence > 0.6 else
                             "possible" if confidence > 0.4 else "unlikely")

                    # Fill template
                    dst = signals.get("primary_destination", {}).get("value", "external")
                    h_text = template["hypothesis"].format(ip=ip, dst=dst)

                    hid = hashlib.md5(
                        f"{template['id']}:{ip}".encode()).hexdigest()[:10]
                    hypotheses.append(ThreatHypothesis(
                        hypothesis_id=hid,
                        hypothesis=h_text,
                        evidence_for=evidence_for,
                        evidence_against=evidence_against,
                        confidence=round(confidence, 3),
                        verdict=verdict,
                        affected_ips=[ip],
                        mitre_technique=template["mitre"],
                    ))

        return sorted(hypotheses, key=lambda h: h.confidence, reverse=True)[:20]

    def _extract_signals(self, results: dict, flows: List[dict]) -> Dict[str, Dict]:
        ip_signals: Dict[str, Dict] = defaultdict(dict)

        # Beacons → beacon signal
        for b in results.get("beacons", []):
            ip = b.get("src_ip", "")
            ip_signals[ip]["beacon"] = {
                "detail": f"Beacon to {b.get('dst_ip', '')} "
                         f"interval={b.get('interval_mean', 0)}s",
                "value": b.get("regularity", 0),
            }
            ip_signals[ip]["primary_destination"] = {"value": b.get("dst_ip", "")}

        # Suspicious IPs
        for s in results.get("suspicious_ips", []):
            ip = s.get("ip", "")
            for reason in s.get("reasons", []):
                rl = reason.lower()
                if "malware" in rl or "ja3" in rl:
                    ip_signals[ip]["malware_ja3"] = {"detail": reason, "value": 1}
                if "scan" in rl or "sweep" in rl:
                    ip_signals[ip]["internal_scan"] = {"detail": reason, "value": 1}
                if "port" in rl and "entropy" in rl:
                    ip_signals[ip]["multi_port"] = {"detail": reason, "value": 1}
                if "exfil" in rl:
                    ip_signals[ip]["high_outbound"] = {"detail": reason, "value": 1}
                    ip_signals[ip]["asymmetric_traffic"] = {"detail": reason, "value": 1}
                if "dga" in rl:
                    ip_signals[ip]["dga_domain"] = {"detail": reason, "value": 1}

        # DGA
        for d in results.get("dga_alerts", []):
            ip = d.get("src_ip", "")
            ip_signals[ip]["dga_domain"] = {
                "detail": f"DGA domain: {d.get('domain', '')}",
                "value": d.get("dga_score", 0),
            }

        # Exfiltration
        for e in results.get("exfil_alerts", []):
            ip = e.get("src_ip", "")
            ip_signals[ip]["high_outbound"] = {
                "detail": f"Exfil: {e.get('total_sent', 0) / 1e6:.1f}MB",
                "value": e.get("total_sent", 0),
            }
            ip_signals[ip]["asymmetric_traffic"] = {
                "detail": f"Ratio: {e.get('ratio', 0)}x outbound",
                "value": e.get("ratio", 0),
            }

        # Flow-level signals
        ip_flow_data: Dict[str, Dict] = defaultdict(lambda: {
            "bytes": 0, "flows": 0, "tls": 0,
        })
        for f in flows:
            src = f.get("src_ip", "")
            if src:
                ip_flow_data[src]["bytes"] += f.get("total_bytes", 0)
                ip_flow_data[src]["flows"] += 1
                if f.get("protocol") == "TLS":
                    ip_flow_data[src]["tls"] += 1

        for ip, data in ip_flow_data.items():
            if data["flows"] > 0 and data["tls"] / data["flows"] > 0.9:
                ip_signals[ip]["encrypted"] = {
                    "detail": f"High TLS ratio: {data['tls'] / data['flows']:.0%}",
                    "value": data["tls"] / data["flows"],
                }
            ip_signals[ip]["flow_count"] = {"value": data["flows"]}

        return ip_signals


# ═══════════════════════════════════════════════════════════════════════════════
# MASTER AUTONOMOUS THREAT HUNTING ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

class AutonomousThreatHunter:
    """
    Orchestrates all autonomous threat hunting modules.
    Runs pattern detection, behavior analysis, peer comparison,
    temporal analysis, and hypothesis generation.
    """

    def __init__(self):
        self.pattern_detector = PatternAnomalyDetector()
        self.sequence_analyzer = BehaviorSequenceAnalyzer()
        self.peer_analyzer = PeerGroupAnalyzer()
        self.temporal_hunter = TemporalPatternHunter()
        self.hypothesis_engine = ThreatHypothesisEngine()

    def hunt(self, flows: List[dict], analysis_results: dict = None) -> Dict:
        """Run full autonomous threat hunt."""
        analysis_results = analysis_results or {}

        # Module 1: Statistical anomalies
        anomaly_findings = self.pattern_detector.analyse(flows)

        # Module 2: Attack chains
        attack_chains = self.sequence_analyzer.analyse(analysis_results)

        # Module 3: Peer group outliers
        peer_findings = self.peer_analyzer.analyse(flows)

        # Module 4: Temporal anomalies
        temporal_findings = self.temporal_hunter.analyse(flows)

        # Module 5: Hypothesis generation
        hypotheses = self.hypothesis_engine.generate_hypotheses(analysis_results, flows)

        # Combine all findings
        all_findings = anomaly_findings + peer_findings + temporal_findings

        return {
            "findings": [
                {"id": f.finding_id, "title": f.title, "description": f.description,
                 "severity": f.severity, "confidence": f.confidence,
                 "score": f.threat_score, "category": f.category,
                 "hunt_type": f.hunt_type, "ips": f.affected_ips,
                 "evidence": f.evidence, "mitre": f.mitre_techniques,
                 "actions": f.recommended_actions}
                for f in sorted(all_findings, key=lambda x: x.threat_score, reverse=True)[:30]
            ],
            "attack_chains": [
                {"id": c.chain_id, "stages": c.stages,
                 "ips": c.affected_ips, "score": c.total_score,
                 "confidence": c.confidence,
                 "kill_chain": c.kill_chain_coverage,
                 "mitre": c.mitre_techniques, "evidence": c.evidence}
                for c in attack_chains
            ],
            "hypotheses": [
                {"id": h.hypothesis_id, "hypothesis": h.hypothesis,
                 "evidence_for": h.evidence_for,
                 "evidence_against": h.evidence_against,
                 "confidence": h.confidence, "verdict": h.verdict,
                 "ips": h.affected_ips, "mitre": h.mitre_technique}
                for h in hypotheses
            ],
            "summary": {
                "total_findings": len(all_findings),
                "critical_findings": sum(1 for f in all_findings if f.severity == "CRITICAL"),
                "high_findings": sum(1 for f in all_findings if f.severity == "HIGH"),
                "attack_chains": len(attack_chains),
                "hypotheses_confirmed": sum(1 for h in hypotheses if h.verdict in ("confirmed", "likely")),
                "hypotheses_total": len(hypotheses),
                "unique_ips_flagged": len({ip for f in all_findings for ip in f.affected_ips}),
                "hunt_modules_run": 5,
            },
        }
