"""
NetForensics — Lateral Movement Detection Engine v3
=====================================================
Detects internal lateral movement through metadata analysis:
  • Internal scan/sweep detection
  • Admin tool port usage (SMB/RDP/SSH/WinRM)
  • Sequential access pattern detection
  • Pivot point identification
  • Credential relay detection

MITRE ATT&CK: T1021, T1570, T1550, T1210, T1046
"""

import logging
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple

logger = logging.getLogger("netforensics.lateral")

LATERAL_PORTS = {
    22: ("SSH", "T1021.004"), 135: ("DCOM/WMI", "T1021.003"),
    139: ("NetBIOS/SMB", "T1021.002"), 445: ("SMB", "T1021.002"),
    3389: ("RDP", "T1021.001"), 5985: ("WinRM", "T1021.006"),
    5986: ("WinRM HTTPS", "T1021.006"), 88: ("Kerberos", "T1558"),
    389: ("LDAP", "T1087.002"), 5900: ("VNC", "T1021.005"),
}

INTERNAL_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                     "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                     "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                     "172.30.", "172.31.", "192.168.")

def _is_internal(ip: str) -> bool:
    return ip.startswith(INTERNAL_PREFIXES) or ip == "127.0.0.1"

@dataclass
class LateralAlert:
    alert_type: str; src_ip: str; dst_ip: str; dst_port: int
    confidence: str; severity: str; evidence: List[str]
    targets: List[str] = field(default_factory=list)
    mitre_technique: str = "T1021"; score: float = 0.0
    timestamp: float = 0.0

@dataclass
class PivotPoint:
    ip: str; inbound_sources: List[str]; outbound_targets: List[str]
    admin_ports_used: List[int]; total_lateral_flows: int
    risk_score: float; evidence: List[str] = field(default_factory=list)

class LateralMovementDetector:
    SCAN_THRESHOLD = 10
    RAPID_CONN_WINDOW = 30.0
    MIN_LATERAL_FLOWS = 3

    def analyse(self, flows: List[dict], packets: List[dict]) -> dict:
        internal = [f for f in flows
                     if _is_internal(f.get("src_ip","")) and _is_internal(f.get("dst_ip",""))]
        if not internal:
            return self._empty()
        alerts = []
        alerts.extend(self._detect_scans(internal))
        alerts.extend(self._detect_admin_lateral(internal))
        alerts.extend(self._detect_sequential(internal))
        alerts.extend(self._detect_cred_relay(internal))
        alerts.extend(self._detect_tool_transfer(internal))
        pivots = self._find_pivots(flows, internal)
        graph = self._build_graph(internal)
        return {
            "lateral_alerts": [
                {"alert_type":a.alert_type,"src_ip":a.src_ip,"dst_ip":a.dst_ip,
                 "dst_port":a.dst_port,"confidence":a.confidence,"severity":a.severity,
                 "evidence":a.evidence,"targets":a.targets,"mitre_technique":a.mitre_technique,
                 "score":a.score,"timestamp":a.timestamp}
                for a in sorted(alerts, key=lambda x: x.score, reverse=True)
            ],
            "pivot_points": [
                {"ip":p.ip,"inbound_sources":p.inbound_sources[:20],
                 "outbound_targets":p.outbound_targets[:20],
                 "admin_ports_used":p.admin_ports_used,
                 "total_lateral_flows":p.total_lateral_flows,
                 "risk_score":p.risk_score,"evidence":p.evidence}
                for p in sorted(pivots, key=lambda x: x.risk_score, reverse=True)[:20]
            ],
            "lateral_graph": graph,
            "lateral_summary": {
                "total_alerts": len(alerts),
                "scan_detections": sum(1 for a in alerts if a.alert_type=="scan_sweep"),
                "admin_lateral": sum(1 for a in alerts if "lateral" in a.alert_type),
                "credential_relays": sum(1 for a in alerts if a.alert_type=="credential_relay"),
                "tool_transfers": sum(1 for a in alerts if a.alert_type=="tool_transfer"),
                "pivot_points": len(pivots),
                "internal_flow_count": len(internal),
            },
        }

    def _detect_scans(self, flows):
        alerts = []
        src_dsts = defaultdict(set)
        src_ports = defaultdict(Counter)
        for f in flows:
            src_dsts[f.get("src_ip","")].add(f.get("dst_ip",""))
            src_ports[f.get("src_ip","")][f.get("dst_port",0)] += 1
        for src, dsts in src_dsts.items():
            if len(dsts) < self.SCAN_THRESHOLD: continue
            top = src_ports[src].most_common(5)
            admin = [p for p,_ in top if p in LATERAL_PORTS]
            score = min(100, 30 + len(dsts)*2 + len(admin)*15)
            alerts.append(LateralAlert(
                alert_type="scan_sweep", src_ip=src, dst_ip=sorted(dsts)[0],
                dst_port=top[0][0] if top else 0,
                confidence="HIGH" if len(dsts)>20 else "MEDIUM",
                severity="CRITICAL" if admin else "HIGH",
                evidence=[f"Scanned {len(dsts)} internal hosts",
                          f"Admin ports: {admin}" if admin else "General scan"],
                targets=sorted(dsts)[:30], mitre_technique="T1046", score=score))
        return alerts

    def _detect_admin_lateral(self, flows):
        alerts, seen = [], set()
        src_admin = defaultdict(list)
        for f in flows:
            if f.get("dst_port",0) in LATERAL_PORTS:
                src_admin[f.get("src_ip","")].append(f)
        for src, af in src_admin.items():
            if len(af) < self.MIN_LATERAL_FLOWS: continue
            port_g = defaultdict(list)
            for f in af: port_g[f.get("dst_port",0)].append(f)
            for port, pf in port_g.items():
                targets = sorted({f.get("dst_ip","") for f in pf})
                if len(targets)<2: continue
                key = (src, port)
                if key in seen: continue
                seen.add(key)
                svc, tech = LATERAL_PORTS.get(port, ("Unknown","T1021"))
                alerts.append(LateralAlert(
                    alert_type=f"{svc.lower().replace(' ','_')}_lateral",
                    src_ip=src, dst_ip=targets[0], dst_port=port,
                    confidence="HIGH" if len(targets)>3 else "MEDIUM",
                    severity="CRITICAL" if len(targets)>5 else "HIGH",
                    evidence=[f"{svc} lateral: {src}→{len(targets)} hosts"],
                    targets=targets, mitre_technique=tech,
                    score=min(100, 40+len(targets)*10)))
        return alerts

    def _detect_sequential(self, flows):
        alerts = []
        src_f = defaultdict(list)
        for f in flows: src_f[f.get("src_ip","")].append(f)
        for src, sf in src_f.items():
            sf.sort(key=lambda x:x.get("start_time",0))
            if len(sf)<5: continue
            i = 0
            while i < len(sf)-2:
                window, targets = [sf[i]], {sf[i].get("dst_ip","")}
                j = i+1
                while j < len(sf):
                    td = sf[j].get("start_time",0)-window[-1].get("start_time",0)
                    if td > self.RAPID_CONN_WINDOW: break
                    dst = sf[j].get("dst_ip","")
                    if dst not in targets:
                        targets.add(dst); window.append(sf[j])
                    j += 1
                if len(targets) >= 5:
                    tt = window[-1].get("start_time",0)-window[0].get("start_time",0)
                    alerts.append(LateralAlert(
                        alert_type="sequential_access", src_ip=src,
                        dst_ip=sorted(targets)[0], dst_port=window[0].get("dst_port",0),
                        confidence="HIGH", severity="CRITICAL",
                        evidence=[f"Rapid sequential: {len(targets)} hosts in {tt:.1f}s"],
                        targets=sorted(targets), mitre_technique="T1570",
                        score=min(100, 60+len(targets)*5)))
                i = j
        return alerts

    def _find_pivots(self, all_flows, internal):
        pivots = []
        ext_in = defaultdict(set)
        int_out = defaultdict(set)
        adm_ports = defaultdict(set)
        for f in all_flows:
            s, d = f.get("src_ip",""), f.get("dst_ip","")
            if not _is_internal(s) and _is_internal(d): ext_in[d].add(s)
        for f in internal:
            s, d, p = f.get("src_ip",""), f.get("dst_ip",""), f.get("dst_port",0)
            int_out[s].add(d)
            if p in LATERAL_PORTS: adm_ports[s].add(p)
        for ip in set(ext_in) & set(int_out):
            ext, ints, ap = sorted(ext_in[ip]), sorted(int_out[ip]), sorted(adm_ports.get(ip,set()))
            if len(ints)<2: continue
            sc = min(100, 20+len(ext)*10+len(ints)*8+len(ap)*12)
            lf = sum(1 for f in internal if f.get("src_ip")==ip)
            pivots.append(PivotPoint(ip=ip, inbound_sources=ext,
                outbound_targets=ints, admin_ports_used=ap,
                total_lateral_flows=lf, risk_score=round(sc,1),
                evidence=[f"{len(ext)} ext sources, {len(ints)} int targets"]))
        return pivots

    def _detect_cred_relay(self, flows):
        alerts = []
        auth = [f for f in flows if f.get("dst_port") in {88,389,636}]
        if not auth: return alerts
        auth_map = defaultdict(list)
        for f in auth: auth_map[f.get("src_ip","")].append(f)
        for f in auth:
            dst, src, ts = f.get("dst_ip",""), f.get("src_ip",""), f.get("start_time",0)
            following = [nf for nf in auth_map.get(dst,[])
                         if 0 < nf.get("start_time",0)-ts < 10
                         and nf.get("dst_ip","") != src]
            for nf in following:
                alerts.append(LateralAlert(
                    alert_type="credential_relay", src_ip=src,
                    dst_ip=nf.get("dst_ip",""), dst_port=nf.get("dst_port",0),
                    confidence="MEDIUM", severity="CRITICAL",
                    evidence=[f"Relay chain: {src}→{dst}→{nf.get('dst_ip','')}"],
                    mitre_technique="T1550", score=85, timestamp=ts))
        return alerts

    def _detect_tool_transfer(self, flows):
        alerts, seen = [], set()
        for f in flows:
            s, d, p, b = f.get("src_ip",""), f.get("dst_ip",""), f.get("dst_port",0), f.get("total_bytes",0)
            if p == 445 and b > 5_000_000:
                key = (s,d,445)
                if key not in seen:
                    seen.add(key)
                    alerts.append(LateralAlert(
                        alert_type="tool_transfer", src_ip=s, dst_ip=d, dst_port=p,
                        confidence="MEDIUM", severity="HIGH",
                        evidence=[f"Large SMB: {b/1e6:.1f}MB {s}→{d}"],
                        mitre_technique="T1570", score=min(100,40+b//1e6*5),
                        timestamp=f.get("start_time",0)))
        return alerts

    def _build_graph(self, flows):
        nodes, edges = set(), {}
        for f in flows:
            s, d, p = f.get("src_ip",""), f.get("dst_ip",""), f.get("dst_port",0)
            nodes.add(s); nodes.add(d)
            k = (s,d)
            if k not in edges:
                edges[k] = {"source":s,"target":d,"flows":0,"bytes":0,"ports":set(),"is_admin":False}
            edges[k]["flows"] += 1
            edges[k]["bytes"] += f.get("total_bytes",0)
            edges[k]["ports"].add(p)
            if p in LATERAL_PORTS: edges[k]["is_admin"] = True
        return {
            "nodes": [{"id":ip,"type":"internal"} for ip in sorted(nodes) if ip],
            "edges": [{"source":e["source"],"target":e["target"],"flows":e["flows"],
                        "bytes":e["bytes"],"ports":sorted(e["ports"]),"is_admin":e["is_admin"]}
                       for e in sorted(edges.values(), key=lambda x:x["bytes"], reverse=True)[:200]],
        }

    @staticmethod
    def _empty():
        return {"lateral_alerts":[],"pivot_points":[],"lateral_graph":{"nodes":[],"edges":[]},
                "lateral_summary":{"total_alerts":0,"scan_detections":0,"admin_lateral":0,
                "credential_relays":0,"tool_transfers":0,"pivot_points":0,"internal_flow_count":0}}
