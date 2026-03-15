"""
NetForensics — MITRE ATT&CK Mapper v3
========================================
Maps detected threats to MITRE ATT&CK framework:
  • Technique identification from detection results
  • Tactic chain reconstruction
  • Kill chain stage mapping
  • ATT&CK Navigator layer export
  • Campaign correlation via shared techniques
"""

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional

logger = logging.getLogger("netforensics.mitre")

# ─── MITRE ATT&CK Technique Database ──────────────────────────────────────────
TECHNIQUES: Dict[str, dict] = {
    # Reconnaissance
    "T1046": {"name": "Network Service Discovery", "tactic": "Discovery",
              "description": "Scanning internal network for services"},
    # Initial Access
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "Initial Access",
              "description": "Exploiting externally-accessible services"},
    # Execution
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "Execution",
              "description": "Using scripting for execution"},
    # Persistence
    "T1078": {"name": "Valid Accounts", "tactic": "Persistence",
              "description": "Using legitimate credentials"},
    # Lateral Movement
    "T1021": {"name": "Remote Services", "tactic": "Lateral Movement",
              "description": "Using remote services for lateral movement"},
    "T1021.001": {"name": "Remote Desktop Protocol", "tactic": "Lateral Movement",
                  "description": "RDP-based lateral movement"},
    "T1021.002": {"name": "SMB/Windows Admin Shares", "tactic": "Lateral Movement",
                  "description": "SMB-based lateral movement"},
    "T1021.003": {"name": "DCOM", "tactic": "Lateral Movement",
                  "description": "DCOM-based lateral movement"},
    "T1021.004": {"name": "SSH", "tactic": "Lateral Movement",
                  "description": "SSH-based lateral movement"},
    "T1021.005": {"name": "VNC", "tactic": "Lateral Movement",
                  "description": "VNC-based lateral movement"},
    "T1021.006": {"name": "Windows Remote Management", "tactic": "Lateral Movement",
                  "description": "WinRM-based lateral movement"},
    "T1550": {"name": "Use Alternate Authentication Material", "tactic": "Lateral Movement",
              "description": "Pass-the-hash/ticket attacks"},
    "T1570": {"name": "Lateral Tool Transfer", "tactic": "Lateral Movement",
              "description": "Transferring tools between systems"},
    # Collection
    "T1560": {"name": "Archive Collected Data", "tactic": "Collection",
              "description": "Compressing data before exfiltration"},
    # C2
    "T1071.001": {"name": "Web Protocols", "tactic": "Command and Control",
                  "description": "C2 over HTTP/HTTPS"},
    "T1071.004": {"name": "DNS", "tactic": "Command and Control",
                  "description": "C2 over DNS (DNS tunneling)"},
    "T1573": {"name": "Encrypted Channel", "tactic": "Command and Control",
              "description": "Encrypted C2 communication"},
    "T1573.002": {"name": "Asymmetric Cryptography", "tactic": "Command and Control",
                  "description": "TLS/SSL encrypted C2"},
    "T1090.003": {"name": "Multi-hop Proxy", "tactic": "Command and Control",
                  "description": "Using Tor or multi-hop proxies"},
    "T1568": {"name": "Dynamic Resolution", "tactic": "Command and Control",
              "description": "DGA domains for C2"},
    "T1095": {"name": "Non-Application Layer Protocol", "tactic": "Command and Control",
              "description": "C2 using raw TCP/UDP/ICMP"},
    "T1571": {"name": "Non-Standard Port", "tactic": "Command and Control",
              "description": "C2 on non-standard ports"},
    "T1572": {"name": "Protocol Tunneling", "tactic": "Command and Control",
              "description": "Tunneling C2 through allowed protocols"},
    # Exfiltration
    "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration",
              "description": "Data exfil over C2 channel"},
    "T1048": {"name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration",
              "description": "Data exfil over DNS, ICMP, etc."},
    # Credential Access
    "T1558": {"name": "Steal or Forge Kerberos Tickets", "tactic": "Credential Access",
              "description": "Kerberos ticket manipulation"},
    # Domain Trust Discovery
    "T1087.002": {"name": "Domain Account", "tactic": "Discovery",
                  "description": "LDAP enumeration of domain accounts"},
    # Defense Evasion
    "T1205": {"name": "Traffic Signaling", "tactic": "Defense Evasion",
              "description": "Using specific traffic patterns as signals"},
}

TACTIC_ORDER = [
    "Reconnaissance", "Initial Access", "Execution", "Persistence",
    "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection",
    "Command and Control", "Exfiltration", "Impact",
]

# Kill chain mapping
KILL_CHAIN = {
    "Reconnaissance": "reconnaissance",
    "Initial Access": "weaponization",
    "Execution": "delivery",
    "Persistence": "installation",
    "Lateral Movement": "lateral_movement",
    "Command and Control": "command_control",
    "Exfiltration": "actions_on_objectives",
    "Collection": "actions_on_objectives",
    "Discovery": "reconnaissance",
}


@dataclass
class MITREMapping:
    technique_id: str
    technique_name: str
    tactic: str
    kill_chain_phase: str
    confidence: str
    source_engine: str
    alert_count: int = 0
    affected_ips: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)


class MITREMapper:
    """Maps detection results to MITRE ATT&CK framework."""

    def map_analysis(self, analysis_results: dict) -> dict:
        """Map all detection engine results to MITRE techniques."""
        mappings: List[MITREMapping] = []

        # Map beacon detections → C2 techniques
        mappings.extend(self._map_beacons(analysis_results))
        # Map DGA → T1568
        mappings.extend(self._map_dga(analysis_results))
        # Map exfiltration → T1041/T1048
        mappings.extend(self._map_exfil(analysis_results))
        # Map Tor → T1090.003
        mappings.extend(self._map_tor(analysis_results))
        # Map lateral movement
        mappings.extend(self._map_lateral(analysis_results))
        # Map DNS tunneling → T1071.004
        mappings.extend(self._map_dns_tunnel(analysis_results))
        # Map encrypted channel anomalies → T1573
        mappings.extend(self._map_encrypted(analysis_results))

        # De-duplicate and aggregate
        tech_map: Dict[str, MITREMapping] = {}
        for m in mappings:
            if m.technique_id in tech_map:
                existing = tech_map[m.technique_id]
                existing.alert_count += m.alert_count
                existing.affected_ips.extend(m.affected_ips)
                existing.evidence.extend(m.evidence)
            else:
                tech_map[m.technique_id] = m

        # Unique IPs
        for m in tech_map.values():
            m.affected_ips = sorted(set(m.affected_ips))[:20]
            m.evidence = m.evidence[:10]

        # Build tactic chain
        tactic_chain = self._build_tactic_chain(list(tech_map.values()))

        # Generate ATT&CK Navigator layer
        navigator_layer = self._generate_navigator_layer(list(tech_map.values()))

        return {
            "mitre_mappings": [
                {"technique_id": m.technique_id, "technique_name": m.technique_name,
                 "tactic": m.tactic, "kill_chain_phase": m.kill_chain_phase,
                 "confidence": m.confidence, "source_engine": m.source_engine,
                 "alert_count": m.alert_count,
                 "affected_ips": m.affected_ips,
                 "evidence": m.evidence}
                for m in sorted(tech_map.values(),
                               key=lambda x: TACTIC_ORDER.index(x.tactic)
                               if x.tactic in TACTIC_ORDER else 99)
            ],
            "tactic_chain": tactic_chain,
            "navigator_layer": navigator_layer,
            "mitre_summary": {
                "total_techniques": len(tech_map),
                "total_tactics": len({m.tactic for m in tech_map.values()}),
                "kill_chain_coverage": sorted({
                    m.kill_chain_phase for m in tech_map.values()
                }),
                "highest_confidence": max(
                    (m.confidence for m in tech_map.values()), default="LOW"
                ),
            },
        }

    def _map_beacons(self, results):
        mappings = []
        beacons = results.get("beacons", [])
        if beacons:
            ips = sorted({b.get("src_ip","") for b in beacons})
            mappings.append(MITREMapping(
                technique_id="T1071.001", technique_name="Web Protocols",
                tactic="Command and Control",
                kill_chain_phase="command_control",
                confidence="HIGH" if any(b.get("confidence")=="HIGH" for b in beacons) else "MEDIUM",
                source_engine="beacon_detector",
                alert_count=len(beacons), affected_ips=ips,
                evidence=[f"{len(beacons)} beacon pattern(s) detected"]))
            # Add malware JA3 matches
            malware = [b for b in beacons if b.get("malware_match")]
            if malware:
                mappings.append(MITREMapping(
                    technique_id="T1573.002", technique_name="Asymmetric Cryptography",
                    tactic="Command and Control", kill_chain_phase="command_control",
                    confidence="HIGH", source_engine="ja3_fingerprinter",
                    alert_count=len(malware),
                    affected_ips=sorted({m.get("src_ip","") for m in malware}),
                    evidence=[f"Malware JA3: {m.get('malware_match')}" for m in malware[:5]]))
        return mappings

    def _map_dga(self, results):
        dga = results.get("dga_alerts", [])
        if not dga: return []
        return [MITREMapping(
            technique_id="T1568", technique_name="Dynamic Resolution",
            tactic="Command and Control", kill_chain_phase="command_control",
            confidence="HIGH" if any(d.get("dga_score",0)>0.8 for d in dga) else "MEDIUM",
            source_engine="dga_detector", alert_count=len(dga),
            affected_ips=sorted({d.get("src_ip","") for d in dga}),
            evidence=[f"DGA domain: {d.get('domain','')} (score: {d.get('dga_score',0):.0%})"
                      for d in dga[:5]])]

    def _map_exfil(self, results):
        exfil = results.get("exfil_alerts", [])
        if not exfil: return []
        return [MITREMapping(
            technique_id="T1041", technique_name="Exfiltration Over C2 Channel",
            tactic="Exfiltration", kill_chain_phase="actions_on_objectives",
            confidence="HIGH" if any(e.get("ratio",0)>20 for e in exfil) else "MEDIUM",
            source_engine="exfil_detector", alert_count=len(exfil),
            affected_ips=sorted({e.get("src_ip","") for e in exfil}),
            evidence=[f"Exfil: {e.get('src_ip','')}→{e.get('dst_ip','')} "
                      f"ratio={e.get('ratio',0):.1f}x" for e in exfil[:5]])]

    def _map_tor(self, results):
        tor = results.get("tor_alerts", [])
        if not tor: return []
        return [MITREMapping(
            technique_id="T1090.003", technique_name="Multi-hop Proxy (Tor)",
            tactic="Command and Control", kill_chain_phase="command_control",
            confidence="HIGH", source_engine="tor_detector",
            alert_count=len(tor),
            affected_ips=sorted({t.get("src_ip","") for t in tor}),
            evidence=[f"Tor {t.get('alert_type','')}: {t.get('src_ip','')}→{t.get('dst_ip','')}"
                      for t in tor[:5]])]

    def _map_lateral(self, results):
        mappings = []
        lateral = results.get("lateral_alerts", [])
        if not lateral: return mappings
        # Group by MITRE technique
        by_tech = defaultdict(list)
        for a in lateral:
            by_tech[a.get("mitre_technique", "T1021")].append(a)
        for tech_id, alerts in by_tech.items():
            info = TECHNIQUES.get(tech_id, {"name": tech_id, "tactic": "Lateral Movement"})
            mappings.append(MITREMapping(
                technique_id=tech_id, technique_name=info["name"],
                tactic=info.get("tactic", "Lateral Movement"),
                kill_chain_phase="lateral_movement",
                confidence="HIGH" if any(a.get("confidence")=="HIGH" for a in alerts) else "MEDIUM",
                source_engine="lateral_detector",
                alert_count=len(alerts),
                affected_ips=sorted({a.get("src_ip","") for a in alerts}),
                evidence=[a.get("evidence",[""])[0] for a in alerts[:5]]))
        return mappings

    def _map_dns_tunnel(self, results):
        tunnel = results.get("dns_tunnel_alerts", [])
        if not tunnel: return []
        return [MITREMapping(
            technique_id="T1071.004", technique_name="DNS",
            tactic="Command and Control", kill_chain_phase="command_control",
            confidence="HIGH", source_engine="dns_tunnel_detector",
            alert_count=len(tunnel),
            affected_ips=sorted({t.get("src_ip","") for t in tunnel}),
            evidence=[f"DNS tunnel: {t.get('domain','')} ({t.get('alert_type','')})"
                      for t in tunnel[:5]])]

    def _map_encrypted(self, results):
        enc = results.get("encrypted_alerts", [])
        if not enc: return []
        return [MITREMapping(
            technique_id="T1573", technique_name="Encrypted Channel",
            tactic="Command and Control", kill_chain_phase="command_control",
            confidence="MEDIUM", source_engine="encrypted_analyzer",
            alert_count=len(enc),
            affected_ips=sorted({e.get("src_ip","") for e in enc}),
            evidence=[f"{e.get('alert_type','')}: {e.get('evidence',[''])[0]}"
                      for e in enc[:5]])]

    def _build_tactic_chain(self, mappings):
        chain = {}
        for tactic in TACTIC_ORDER:
            techs = [m for m in mappings if m.tactic == tactic]
            if techs:
                chain[tactic] = {
                    "techniques": [m.technique_id for m in techs],
                    "alert_count": sum(m.alert_count for m in techs),
                    "phase": KILL_CHAIN.get(tactic, "unknown"),
                }
        return chain

    def _generate_navigator_layer(self, mappings):
        """Generate ATT&CK Navigator JSON layer."""
        techniques = []
        for m in mappings:
            score_map = {"HIGH": 100, "MEDIUM": 50, "LOW": 25}
            techniques.append({
                "techniqueID": m.technique_id,
                "score": score_map.get(m.confidence, 25),
                "comment": f"{m.alert_count} alerts from {m.source_engine}",
                "enabled": True,
            })
        return {
            "name": "NetForensics Detection Layer",
            "versions": {"attack": "14", "navigator": "4.9", "layer": "4.5"},
            "domain": "enterprise-attack",
            "techniques": techniques,
        }
