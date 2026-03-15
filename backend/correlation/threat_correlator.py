"""
NetForensics — Threat Correlation Engine v3
=============================================
Cross-engine alert correlation:
  • Temporal correlation (alerts within time windows)
  • IP-based correlation (shared endpoints)
  • Kill chain progression detection
  • Campaign clustering
  • Alert de-duplication and priority scoring
  • Unified threat scoring (0-100)
"""

import logging
import hashlib
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

logger = logging.getLogger("netforensics.correlation")


@dataclass
class UnifiedThreat:
    threat_id: str
    title: str
    severity: str           # CRITICAL, HIGH, MEDIUM, LOW
    confidence: str
    threat_score: float     # 0-100
    category: str           # c2, exfiltration, lateral, recon, tor, dns_tunnel
    source_engines: List[str]
    affected_ips: List[str]
    mitre_techniques: List[str]
    evidence: List[str]
    alert_count: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    status: str = "open"    # open, investigating, resolved, false_positive
    kill_chain_stage: str = ""


class ThreatCorrelator:
    """Correlates alerts from all detection engines into unified threats."""

    # Correlation time window (seconds)
    TIME_WINDOW = 300  # 5 minutes

    def correlate(self, analysis_results: dict) -> dict:
        """Run correlation across all engine outputs."""
        threats: List[UnifiedThreat] = []

        # Extract all alerts from various engines
        all_alerts = self._collect_alerts(analysis_results)

        # 1. Group alerts by IP
        ip_alerts = self._group_by_ip(all_alerts)

        # 2. Temporal correlation
        temporal_groups = self._temporal_correlation(all_alerts)

        # 3. Build unified threats
        threats = self._build_threats(ip_alerts, temporal_groups, analysis_results)

        # 4. Score and prioritize
        threats.sort(key=lambda t: t.threat_score, reverse=True)

        # 5. Campaign detection
        campaigns = self._detect_campaigns(threats)

        return {
            "threats": [
                {"threat_id": t.threat_id, "title": t.title,
                 "severity": t.severity, "confidence": t.confidence,
                 "threat_score": t.threat_score, "category": t.category,
                 "source_engines": t.source_engines,
                 "affected_ips": t.affected_ips,
                 "mitre_techniques": t.mitre_techniques,
                 "evidence": t.evidence,
                 "alert_count": t.alert_count,
                 "kill_chain_stage": t.kill_chain_stage,
                 "status": t.status}
                for t in threats[:100]
            ],
            "campaigns": campaigns,
            "correlation_summary": {
                "total_threats": len(threats),
                "critical_threats": sum(1 for t in threats if t.severity == "CRITICAL"),
                "high_threats": sum(1 for t in threats if t.severity == "HIGH"),
                "unique_affected_ips": len({ip for t in threats for ip in t.affected_ips}),
                "source_engine_count": len({e for t in threats for e in t.source_engines}),
                "campaign_count": len(campaigns),
            },
        }

    def _collect_alerts(self, results):
        """Flatten all detection results into normalized alerts."""
        alerts = []

        # Beacons → C2 alerts
        for b in results.get("beacons", []):
            alerts.append({
                "engine": "beacon_detector", "category": "c2",
                "src_ip": b.get("src_ip",""), "dst_ip": b.get("dst_ip",""),
                "severity": "CRITICAL" if b.get("confidence")=="HIGH" else "HIGH",
                "score": 80 if b.get("confidence")=="HIGH" else 60,
                "evidence": f"Beacon: {b.get('src_ip','')}→{b.get('dst_ip','')} "
                           f"interval={b.get('interval_mean',0)}s",
                "mitre": "T1071.001",
                "timestamp": 0,
            })

        # DGA
        for d in results.get("dga_alerts", []):
            alerts.append({
                "engine": "dga_detector", "category": "c2",
                "src_ip": d.get("src_ip",""), "dst_ip": d.get("dst_ip",""),
                "severity": "HIGH" if d.get("dga_score",0) > 0.8 else "MEDIUM",
                "score": d.get("dga_score", 0) * 80,
                "evidence": f"DGA domain: {d.get('domain','')}",
                "mitre": "T1568", "timestamp": 0,
            })

        # Exfiltration
        for e in results.get("exfil_alerts", []):
            alerts.append({
                "engine": "exfil_detector", "category": "exfiltration",
                "src_ip": e.get("src_ip",""), "dst_ip": e.get("dst_ip",""),
                "severity": "CRITICAL" if e.get("ratio",0) > 50 else "HIGH",
                "score": min(95, 50 + e.get("ratio", 0)),
                "evidence": f"Exfil: {e.get('total_sent',0)/1e6:.1f}MB sent, ratio={e.get('ratio',0)}x",
                "mitre": "T1041", "timestamp": 0,
            })

        # Tor
        for t in results.get("tor_alerts", []):
            alerts.append({
                "engine": "tor_detector", "category": "tor",
                "src_ip": t.get("src_ip",""), "dst_ip": t.get("dst_ip",""),
                "severity": t.get("severity", "HIGH"),
                "score": 85 if t.get("confidence") == "HIGH" else 60,
                "evidence": f"Tor: {t.get('alert_type','')}",
                "mitre": "T1090.003", "timestamp": t.get("timestamp", 0),
            })

        # Lateral movement
        for l in results.get("lateral_alerts", []):
            alerts.append({
                "engine": "lateral_detector", "category": "lateral",
                "src_ip": l.get("src_ip",""), "dst_ip": l.get("dst_ip",""),
                "severity": l.get("severity", "HIGH"),
                "score": l.get("score", 60),
                "evidence": l.get("evidence",[""])[0] if l.get("evidence") else "",
                "mitre": l.get("mitre_technique", "T1021"),
                "timestamp": l.get("timestamp", 0),
            })

        # DNS tunneling
        for d in results.get("dns_tunnel_alerts", []):
            alerts.append({
                "engine": "dns_tunnel_detector", "category": "dns_tunnel",
                "src_ip": d.get("src_ip",""), "dst_ip": "",
                "severity": d.get("severity", "HIGH"),
                "score": d.get("score", 60),
                "evidence": f"DNS tunnel: {d.get('domain','')}",
                "mitre": "T1071.004", "timestamp": 0,
            })

        # TTL anomalies
        for t in results.get("ttl_profiles", []):
            if t.get("anomaly"):
                alerts.append({
                    "engine": "ttl_analyzer", "category": "evasion",
                    "src_ip": t.get("ip",""), "dst_ip": "",
                    "severity": "MEDIUM", "score": 40,
                    "evidence": f"TTL anomaly: {t.get('anomaly_reason','')}",
                    "mitre": "T1205", "timestamp": 0,
                })

        return alerts

    def _group_by_ip(self, alerts):
        ip_map = defaultdict(list)
        for a in alerts:
            if a["src_ip"]: ip_map[a["src_ip"]].append(a)
            if a["dst_ip"]: ip_map[a["dst_ip"]].append(a)
        return ip_map

    def _temporal_correlation(self, alerts):
        """Group alerts that occur within the time window."""
        if not alerts: return []
        timed = sorted([a for a in alerts if a.get("timestamp", 0) > 0],
                       key=lambda x: x["timestamp"])
        groups, current = [], []
        for a in timed:
            if current and a["timestamp"] - current[0]["timestamp"] > self.TIME_WINDOW:
                if len(current) > 1: groups.append(current)
                current = []
            current.append(a)
        if len(current) > 1: groups.append(current)
        return groups

    def _build_threats(self, ip_alerts, temporal_groups, results):
        threats = []
        seen_ips = set()

        # Build threats from IP-correlated alerts
        for ip, alerts in ip_alerts.items():
            if len(alerts) < 2 or ip in seen_ips:
                continue
            seen_ips.add(ip)

            engines = sorted({a["engine"] for a in alerts})
            categories = {a["category"] for a in alerts}
            max_score = max(a["score"] for a in alerts)
            mitres = sorted({a["mitre"] for a in alerts})

            # Multi-engine correlation boosts score
            corr_bonus = min(20, (len(engines) - 1) * 8)
            threat_score = min(100, max_score + corr_bonus)

            # Determine primary category
            cat_priority = ["c2", "exfiltration", "lateral", "tor", "dns_tunnel", "evasion"]
            primary_cat = "unknown"
            for cat in cat_priority:
                if cat in categories:
                    primary_cat = cat
                    break

            # Kill chain stage
            stage_map = {
                "c2": "Command & Control", "exfiltration": "Exfiltration",
                "lateral": "Lateral Movement", "tor": "Command & Control",
                "dns_tunnel": "Command & Control", "evasion": "Defense Evasion",
            }

            severity = ("CRITICAL" if threat_score >= 80 else
                       "HIGH" if threat_score >= 60 else
                       "MEDIUM" if threat_score >= 40 else "LOW")

            threat_id = hashlib.md5(f"{ip}-{'|'.join(engines)}".encode()).hexdigest()[:12]

            threats.append(UnifiedThreat(
                threat_id=threat_id,
                title=f"{primary_cat.replace('_',' ').title()} activity — {ip}",
                severity=severity,
                confidence="HIGH" if len(engines) > 2 else "MEDIUM",
                threat_score=round(threat_score, 1),
                category=primary_cat,
                source_engines=engines,
                affected_ips=[ip],
                mitre_techniques=mitres,
                evidence=[a["evidence"] for a in alerts[:8]],
                alert_count=len(alerts),
                kill_chain_stage=stage_map.get(primary_cat, "Unknown"),
            ))

        # Also create threats for high-severity single alerts
        for ip, alerts in ip_alerts.items():
            for a in alerts:
                if a["score"] >= 80 and ip not in seen_ips:
                    seen_ips.add(ip)
                    threat_id = hashlib.md5(f"{ip}-{a['engine']}".encode()).hexdigest()[:12]
                    threats.append(UnifiedThreat(
                        threat_id=threat_id,
                        title=f"{a['category'].title()} — {ip}",
                        severity=a["severity"], confidence="MEDIUM",
                        threat_score=a["score"], category=a["category"],
                        source_engines=[a["engine"]],
                        affected_ips=[ip],
                        mitre_techniques=[a["mitre"]],
                        evidence=[a["evidence"]],
                        alert_count=1,
                    ))

        return threats

    def _detect_campaigns(self, threats):
        """Cluster threats into potential campaigns."""
        campaigns = []
        if len(threats) < 2: return campaigns

        # Group threats sharing IPs or MITRE techniques
        groups = defaultdict(list)
        for t in threats:
            for ip in t.affected_ips:
                groups[ip].append(t)

        seen = set()
        for ip, ip_threats in groups.items():
            if len(ip_threats) < 2 or ip in seen: continue
            seen.add(ip)
            all_ips = set()
            all_techniques = set()
            for t in ip_threats:
                all_ips.update(t.affected_ips)
                all_techniques.update(t.mitre_techniques)

            if len(all_techniques) >= 3:
                campaigns.append({
                    "campaign_id": hashlib.md5(ip.encode()).hexdigest()[:8],
                    "name": f"Campaign targeting {ip}",
                    "threat_count": len(ip_threats),
                    "affected_ips": sorted(all_ips)[:20],
                    "mitre_techniques": sorted(all_techniques),
                    "max_severity": max(t.severity for t in ip_threats),
                    "total_score": round(sum(t.threat_score for t in ip_threats), 1),
                })

        return sorted(campaigns, key=lambda c: c["total_score"], reverse=True)[:10]
