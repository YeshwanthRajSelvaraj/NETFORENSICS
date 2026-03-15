"""
NetForensics — Traffic Analysis Engine  v2
===========================================
Algorithms for:
  • Beacon detection        — periodic C2 via Coefficient of Variation
  • Burst detection         — traffic spikes via sliding window PPS
  • Endpoint scoring        — heuristic suspicion 0-100 (8 factors)
  • Flow clustering         — 7 behavioural labels
  • TTL fingerprinting      — OS detection + spoofing/tunneling anomaly
  • SNI entropy / DGA       — Domain Generation Algorithm detection
  • Data exfiltration       — asymmetric bytes ratio detection
  • Port entropy            — scanning behaviour detection
  • Fan-out / fan-in        — connection graph topology metrics

No ML library required. Pure Python statistics.
"""

import logging
import math
import statistics
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("netforensics.analysis")

# ─── Malware JA3 Dictionary ───────────────────────────────────────────────────
MALWARE_JA3: Dict[str, str] = {
    "e7d705a3286e19ea42f587b344ee6865": "Cobalt Strike default",
    "6734f37431670b3ab4292b8f60f29984": "Metasploit Meterpreter",
    "a0e9f5d64349fb13191bc781f81f42e1": "Metasploit stager",
    "de9f2c7fd25e1b3afad3e85a0226823f": "TrickBot / Emotet",
    "e7eca2baf4458d095b7f45da28c16c34": "Dridex banking trojan",
    "b386946a5a44d1ddcc843bc75336dfce": "Trickbot HTTPS",
    "192a954d99b56e72cc6fcd974b862bb9": "AgentTesla stealer",
}

# ─── TTL → OS mapping ─────────────────────────────────────────────────────────
_TTL_OS = [
    ((60, 65),   "Linux / Android"),
    ((126, 129), "Windows"),
    ((253, 256), "Cisco / network device"),
    ((30, 35),   "Solaris / AIX"),
]

def classify_ttl(ttl: int) -> str:
    for (lo, hi), name in _TTL_OS:
        if lo <= ttl <= hi:
            return name
    return "Unknown"

# ─── DGA helpers ──────────────────────────────────────────────────────────────

def _label_entropy(domain: str) -> float:
    label = domain.split(".")[0] if domain else ""
    if not label:
        return 0.0
    freq = Counter(label)
    n = len(label)
    return round(-sum((c/n)*math.log2(c/n) for c in freq.values()), 4)

def _consonant_ratio(domain: str) -> float:
    label = domain.split(".")[0].lower() if domain else ""
    if not label:
        return 0.0
    return round(sum(1 for c in label if c in "bcdfghjklmnpqrstvwxyz") / len(label), 3)

def dga_score(domain: str) -> float:
    if not domain:
        return 0.0
    label = domain.split(".")[0]
    s = 0.0
    if _label_entropy(domain) > 3.5: s += 0.4
    if _consonant_ratio(domain) > 0.65: s += 0.3
    if len(label) > 12: s += 0.2
    if len(label) > 20: s += 0.1
    return round(min(1.0, s), 3)


# ─── Data Classes ─────────────────────────────────────────────────────────────

@dataclass
class BeaconResult:
    flow_id:        str
    src_ip:         str
    dst_ip:         str
    dst_port:       int
    interval_mean:  float
    interval_stdev: float
    regularity:     float
    packet_count:   int
    confidence:     str
    beacon_type:    str
    sni:   Optional[str] = None
    ja3:   Optional[str] = None
    malware_match: Optional[str] = None
    dga_score:     float = 0.0


@dataclass
class BurstEvent:
    src_ip: str; dst_ip: str
    start_time: float; end_time: float
    packet_count: int; total_bytes: int
    peak_pps: float; severity: str


@dataclass
class ExfilAlert:
    src_ip: str; dst_ip: str
    total_sent: int; total_recv: int
    ratio: float; session_count: int
    sni: Optional[str] = None


@dataclass
class EndpointProfile:
    ip:                   str
    total_flows:          int
    total_bytes:          int
    unique_destinations:  int
    unique_sources:       int
    protocols:            Dict[str, int]
    dst_ports:            List[int]
    first_seen:           float
    last_seen:            float
    suspicion_score:      float
    suspicion_reasons:    List[str]
    avg_session_duration: float
    tls_ratio:            float
    ja3_hashes:           List[str]
    sni_domains:          List[str]
    malware_ja3_matches:  List[str]
    dga_domains:          List[str] = field(default_factory=list)
    os_guess:             Optional[str] = None
    port_entropy:         float = 0.0
    exfil_ratio:          float = 0.0
    fan_out:              int = 0
    fan_in:               int = 0
    beacon_count:         int = 0


@dataclass
class ClusterResult:
    cluster_id: int; label: str; flow_count: int
    flow_ids: List[str]; dominant_port: int
    avg_bytes: float; avg_duration: float
    centroid_ip: Optional[str]


# ─── Beacon Detector ──────────────────────────────────────────────────────────

class BeaconDetector:
    MIN_CONNECTIONS = 5

    def analyse(self, flow_timestamps: Dict[str, List[float]],
                flow_meta: Dict[str, dict]) -> List[BeaconResult]:
        results = []
        for fid, timestamps in flow_timestamps.items():
            if len(timestamps) < self.MIN_CONNECTIONS:
                continue
            sorted_ts = sorted(timestamps)
            intervals = [sorted_ts[i+1]-sorted_ts[i] for i in range(len(sorted_ts)-1)
                         if sorted_ts[i+1]-sorted_ts[i] > 0.05]
            if len(intervals) < 3:
                continue
            mean_iv  = statistics.mean(intervals)
            stdev_iv = statistics.stdev(intervals) if len(intervals) > 1 else 0.0
            cv = stdev_iv / mean_iv if mean_iv > 0 else 1.0

            if   cv < 0.10: conf = "HIGH"
            elif cv < 0.25: conf = "MEDIUM"
            elif cv < 0.40: conf = "LOW"
            else: continue

            if   mean_iv < 10:   bt = "fast_beacon"
            elif mean_iv < 60:   bt = "short_beacon"
            elif mean_iv < 600:  bt = "medium_beacon"
            elif mean_iv < 3600: bt = "slow_beacon"
            else:                bt = "very_slow_beacon"

            meta = flow_meta.get(fid, {})
            ja3  = meta.get("ja3")
            sni  = meta.get("sni")
            results.append(BeaconResult(
                flow_id=fid, src_ip=meta.get("src_ip",""), dst_ip=meta.get("dst_ip",""),
                dst_port=meta.get("dst_port",0), interval_mean=round(mean_iv,3),
                interval_stdev=round(stdev_iv,3), regularity=round(max(0,1-cv),4),
                packet_count=len(timestamps), confidence=conf, beacon_type=bt,
                sni=sni, ja3=ja3, malware_match=MALWARE_JA3.get(ja3) if ja3 else None,
                dga_score=dga_score(sni) if sni else 0.0,
            ))
        return sorted(results, key=lambda r: r.regularity, reverse=True)


# ─── Burst Detector ───────────────────────────────────────────────────────────

class BurstDetector:
    WINDOW = 5.0

    def analyse(self, packets: List[dict]) -> List[BurstEvent]:
        if not packets:
            return []
        pairs: Dict[Tuple, List[dict]] = defaultdict(list)
        for p in packets:
            pairs[(p.get("src_ip",""), p.get("dst_ip",""))].append(p)
        bursts, seen = [], set()
        for (src, dst), pkts in pairs.items():
            pkts = sorted(pkts, key=lambda x: x.get("timestamp",0))
            if len(pkts) < 10:
                continue
            times = [p["timestamp"] for p in pkts]
            span  = times[-1] - times[0]
            if span < 1:
                continue
            baseline = len(pkts) / span
            lo = 0
            for i, p in enumerate(pkts):
                while pkts[lo]["timestamp"] < p["timestamp"] - self.WINDOW:
                    lo += 1
                w = pkts[lo:i+1]
                pps = len(w) / self.WINDOW
                if pps > baseline*3 and len(w) >= 5:
                    key = (src, dst, round(w[0]["timestamp"]))
                    if key not in seen:
                        seen.add(key)
                        tb  = sum(q.get("size",0) for q in w)
                        sev = "HIGH" if pps > baseline*5 else "MEDIUM" if pps > baseline*3 else "LOW"
                        bursts.append(BurstEvent(src_ip=src, dst_ip=dst,
                            start_time=w[0]["timestamp"], end_time=w[-1]["timestamp"],
                            packet_count=len(w), total_bytes=tb,
                            peak_pps=round(pps,2), severity=sev))
        return sorted(bursts, key=lambda b: b.peak_pps, reverse=True)


# ─── Exfiltration Detector ────────────────────────────────────────────────────

class ExfilDetector:
    MIN_SENT  = 10 * 1024 * 1024  # 10 MB
    MIN_RATIO = 10.0

    def analyse(self, flows: List[dict]) -> List[ExfilAlert]:
        sent: Dict[Tuple,int] = defaultdict(int)
        cnt:  Dict[Tuple,int] = defaultdict(int)
        snis: Dict[Tuple,Optional[str]] = {}
        for f in flows:
            key = (f.get("src_ip",""), f.get("dst_ip",""))
            sent[key] += f.get("total_bytes",0)
            cnt[key]  += 1
            if f.get("sni"):
                snis[key] = f["sni"]
        alerts, seen = [], set()
        for key, s in sent.items():
            if key in seen: continue
            rev  = (key[1], key[0])
            recv = sent.get(rev, 0)
            seen.add(key); seen.add(rev)
            if s >= self.MIN_SENT and recv > 0 and (s/recv) >= self.MIN_RATIO:
                alerts.append(ExfilAlert(src_ip=key[0], dst_ip=key[1],
                    total_sent=s, total_recv=recv, ratio=round(s/recv,1),
                    session_count=cnt[key], sni=snis.get(key)))
        return sorted(alerts, key=lambda a: a.total_sent, reverse=True)[:20]


# ─── TTL Analyser ─────────────────────────────────────────────────────────────

class TTLAnalyser:
    def analyse(self, packets: List[dict]) -> Dict[str, dict]:
        ip_ttls: Dict[str,List[int]] = defaultdict(list)
        for p in packets:
            if p.get("ttl") and p.get("src_ip"):
                ip_ttls[p["src_ip"]].append(p["ttl"])
        results = {}
        for ip, ttls in ip_ttls.items():
            if len(ttls) < 3: continue
            dominant = max(set(ttls), key=ttls.count)
            var      = statistics.variance(ttls) if len(ttls) > 1 else 0
            unique   = len(set(ttls))
            anomaly  = unique > 3 or var > 100
            results[ip] = {
                "ip": ip, "dominant_ttl": dominant,
                "os_guess": classify_ttl(dominant),
                "ttl_variance": round(var,2),
                "unique_ttls": unique,
                "anomaly": anomaly,
                "anomaly_reason": ("Multiple TTL values — possible spoofing/tunneling"
                                   if unique > 3 else "High TTL variance" if var > 100 else None),
            }
        return results


# ─── DGA Analyser ─────────────────────────────────────────────────────────────

class DGAAnalyser:
    THRESHOLD = 0.6

    def analyse(self, flows: List[dict]) -> List[dict]:
        seen = {}
        for f in flows:
            sni = f.get("sni")
            if not sni or sni in seen:
                continue
            score = dga_score(sni)
            if score >= self.THRESHOLD:
                seen[sni] = {
                    "domain": sni, "dga_score": score,
                    "entropy": _label_entropy(sni),
                    "consonant_ratio": _consonant_ratio(sni),
                    "label_length": len(sni.split(".")[0]),
                    "src_ip": f.get("src_ip"), "dst_ip": f.get("dst_ip"),
                    "ja3": f.get("ja3"),
                }
        return sorted(seen.values(), key=lambda x: x["dga_score"], reverse=True)


# ─── Endpoint Scorer ──────────────────────────────────────────────────────────

class EndpointScorer:
    C2_PORTS = frozenset({4444,1337,31337,8888,9999,6666,6667,1234,12345,55555})

    def _port_entropy(self, ports: List[int]) -> float:
        if not ports: return 0.0
        freq = Counter(ports)
        n = len(ports)
        return round(-sum((c/n)*math.log2(c/n) for c in freq.values()), 4)

    def profile(self, flows: List[dict],
                ttl_map: Dict[str, dict] = None) -> Dict[str, EndpointProfile]:
        ip_flows: Dict[str,List[dict]] = defaultdict(list)
        for f in flows:
            ip_flows[f.get("src_ip","")].append(f)
            ip_flows[f.get("dst_ip","")].append(f)
        ip_flows.pop("", None)

        profiles: Dict[str,EndpointProfile] = {}
        for ip, fl in ip_flows.items():
            score = 0.0; reasons: List[str] = []
            protos: Dict[str,int] = defaultdict(int)
            ports: List[int] = []
            bytes_total = ob = ib = 0
            unique_dst: set = set(); unique_src: set = set()
            durations: List[float] = []
            tls_count = 0
            ja3s: set = set(); snis: set = set()
            mal: List[str] = []; dga_d: List[str] = []
            first_seen = math.inf; last_seen = 0.0

            for f in fl:
                p = f.get("protocol","OTHER")
                protos[p] += 1
                bytes_total += f.get("total_bytes",0)
                if f.get("session_duration"): durations.append(f["session_duration"])
                if f.get("src_ip") == ip:
                    unique_dst.add(f.get("dst_ip",""))
                    ports.append(f.get("dst_port",0))
                    ob += f.get("total_bytes",0)
                else:
                    unique_src.add(f.get("src_ip",""))
                    ib += f.get("total_bytes",0)
                if p == "TLS": tls_count += 1
                if f.get("ja3"):
                    ja3s.add(f["ja3"])
                    m = MALWARE_JA3.get(f["ja3"])
                    if m and m not in mal: mal.append(m)
                if f.get("sni"):
                    snis.add(f["sni"])
                    if dga_score(f["sni"]) >= 0.6: dga_d.append(f["sni"])
                ts = f.get("start_time",0)
                if ts < first_seen: first_seen = ts
                if ts > last_seen:  last_seen = ts

            total = len(fl)
            tls_r = tls_count/total if total else 0
            avg_d = statistics.mean(durations) if durations else 0
            pe    = self._port_entropy(ports)
            exfr  = ob/ib if ib > 0 else 0

            if mal:               score+=40; reasons.append(f"Known malware JA3: {', '.join(mal)}")
            if len(unique_dst)>50:score+=20; reasons.append(f"Scan/sweep — {len(unique_dst)} unique destinations")
            if total>100:         score+=10; reasons.append(f"High flow count ({total})")
            if len(unique_dst)==1 and total>25: score+=20; reasons.append("Persistent single-destination (C2)")
            if ports and (set(ports)&self.C2_PORTS):
                bad=set(ports)&self.C2_PORTS; score+=20; reasons.append(f"C2 ports: {sorted(bad)}")
            if avg_d<2 and total>15: score+=10; reasons.append("Very short sessions (scan/probe)")
            if tls_r==1.0 and total>10: score+=5; reasons.append("All-TLS traffic (evasion)")
            if pe>3.5:            score+=15; reasons.append(f"High port entropy ({pe:.2f}) — scanning")
            if exfr>10 and ob>5_000_000: score+=25; reasons.append(f"Possible exfiltration — {exfr:.1f}× outbound")
            if dga_d:             score+=20; reasons.append(f"DGA domain: {dga_d[0]}")
            ttl_entry = (ttl_map or {}).get(ip, {})
            if ttl_entry.get("anomaly"): score+=10; reasons.append("TTL anomaly — spoofing/tunneling")

            profiles[ip] = EndpointProfile(
                ip=ip, total_flows=total, total_bytes=bytes_total,
                unique_destinations=len(unique_dst), unique_sources=len(unique_src),
                protocols=dict(protos), dst_ports=sorted(set(ports))[:20],
                first_seen=first_seen if first_seen!=math.inf else 0, last_seen=last_seen,
                suspicion_score=round(min(100,score),1), suspicion_reasons=reasons,
                avg_session_duration=round(avg_d,2), tls_ratio=round(tls_r,3),
                ja3_hashes=sorted(ja3s), sni_domains=sorted(snis)[:15],
                malware_ja3_matches=mal, dga_domains=list(set(dga_d))[:10],
                os_guess=ttl_entry.get("os_guess"), port_entropy=round(pe,3),
                exfil_ratio=round(exfr,2), fan_out=len(unique_dst), fan_in=len(unique_src),
            )
        return profiles


# ─── Flow Clusterer ───────────────────────────────────────────────────────────

class FlowClusterer:
    def cluster(self, flows: List[dict]) -> List[ClusterResult]:
        if not flows: return []
        groups: Dict[str,List[dict]] = defaultdict(list)
        for f in flows:
            bpp   = f.get("total_bytes",0) / max(f.get("packet_count",1),1)
            dur   = f.get("session_duration",0)
            proto = f.get("protocol","")
            pkts  = f.get("packet_count",0)
            dport = f.get("dst_port",0)
            if proto=="DNS" or dport==53:          label="dns_query"
            elif pkts<=3 and dur<0.5:              label="scan_probe"
            elif bpp>40_000 and dur>5:             label="bulk_transfer"
            elif dur>300:                          label="persistent_session"
            elif pkts>80 and bpp<500:              label="interactive"
            elif f.get("ja3"):                     label="tls_encrypted"
            else:                                  label="standard"
            groups[label].append(f)
        results = []
        for cid,(label,gf) in enumerate(sorted(groups.items())):
            ports = [f.get("dst_port",0) for f in gf]
            dsts  = [f.get("dst_ip","") for f in gf]
            results.append(ClusterResult(
                cluster_id=cid, label=label, flow_count=len(gf),
                flow_ids=[f.get("flow_id","") for f in gf][:100],
                dominant_port=max(set(ports),key=ports.count) if ports else 0,
                avg_bytes=round(statistics.mean(f.get("total_bytes",0) for f in gf)),
                avg_duration=round(statistics.mean(f.get("session_duration",0) for f in gf),2),
                centroid_ip=max(set(dsts),key=dsts.count) if dsts else None,
            ))
        return results


# ─── Main Orchestrator ────────────────────────────────────────────────────────

class TrafficAnalyzer:
    def __init__(self):
        self.beacon_detector = BeaconDetector()
        self.burst_detector  = BurstDetector()
        self.endpoint_scorer = EndpointScorer()
        self.flow_clusterer  = FlowClusterer()
        self.exfil_detector  = ExfilDetector()
        self.ttl_analyser    = TTLAnalyser()
        self.dga_analyser    = DGAAnalyser()

    def analyse(self, flows: List[dict], packets: List[dict]) -> dict:
        fid_ts: Dict[str,List[float]] = defaultdict(list)
        for p in packets:
            if p.get("flow_id"): fid_ts[p["flow_id"]].append(p["timestamp"])
        flow_meta: Dict[str,dict] = {}
        for f in flows:
            fid = f.get("flow_id","")
            flow_meta[fid] = f
            if f.get("packet_timestamps") and fid not in fid_ts:
                fid_ts[fid] = f["packet_timestamps"]

        beacons    = self.beacon_detector.analyse(fid_ts, flow_meta)
        bursts     = self.burst_detector.analyse(packets)
        ttl_map    = self.ttl_analyser.analyse(packets)
        dga_alerts = self.dga_analyser.analyse(flows)
        exfil      = self.exfil_detector.analyse(flows)
        ep_map     = self.endpoint_scorer.profile(flows, ttl_map)
        clusters   = self.flow_clusterer.cluster(flows)

        # Enrich endpoint profiles with beacon counts
        beacon_ips: Dict[str,int] = defaultdict(int)
        for b in beacons: beacon_ips[b.src_ip] += 1
        for ip, ep in ep_map.items():
            ep.beacon_count = beacon_ips.get(ip, 0)
            if ep.beacon_count > 0:
                ep.suspicion_score = min(100, ep.suspicion_score + 15)
                ep.suspicion_reasons.append(f"Involved in {ep.beacon_count} beacon flow(s)")

        suspicious = sorted(
            [p for p in ep_map.values() if p.suspicion_score > 10],
            key=lambda x: x.suspicion_score, reverse=True)[:50]

        proto_counts: Dict[str,int] = defaultdict(int)
        for f in flows: proto_counts[f.get("protocol","OTHER")] += 1

        dst_bytes: Dict[str,int] = defaultdict(int)
        src_flows: Dict[str,int] = defaultdict(int)
        for f in flows:
            dst_bytes[f.get("dst_ip","")] += f.get("total_bytes",0)
            src_flows[f.get("src_ip","")] += 1

        ja3_c: Dict[str,dict] = {}
        for f in flows:
            j = f.get("ja3")
            if j:
                if j not in ja3_c:
                    ja3_c[j] = {"ja3":j,"count":0,"tls_version":f.get("tls_version"),
                                "sni":f.get("sni"),"malware":MALWARE_JA3.get(j)}
                ja3_c[j]["count"] += 1

        dns_c: Dict[str,dict] = {}
        for p in packets:
            q = p.get("dns_query")
            if q:
                if q not in dns_c:
                    dns_c[q] = {"query":q,"type":p.get("dns_type","?"),"count":0,
                                "dga_score":dga_score(q)}
                dns_c[q]["count"] += 1

        conn_graph: Dict[str,dict] = {}
        for f in flows:
            src,dst = f.get("src_ip",""), f.get("dst_ip","")
            if src and dst:
                k = f"{src}->{dst}"
                if k not in conn_graph:
                    conn_graph[k] = {"src":src,"dst":dst,"flows":0,"bytes":0,
                                     "protocol":f.get("protocol","OTHER")}
                conn_graph[k]["flows"] += 1
                conn_graph[k]["bytes"] += f.get("total_bytes",0)

        high_conf = [b for b in beacons if b.confidence in ("HIGH","MEDIUM")]

        return {
            "summary": {
                "total_flows":         len(flows),
                "total_packets":       len(packets),
                "unique_ips":          len(ep_map),
                "beacon_count":        len(high_conf),
                "burst_count":         len(bursts),
                "suspicious_ip_count": len(suspicious),
                "tls_flows":           proto_counts.get("TLS",0),
                "dns_queries":         len(dns_c),
                "dga_domains":         len(dga_alerts),
                "exfil_alerts":        len(exfil),
                "ttl_anomalies":       sum(1 for v in ttl_map.values() if v.get("anomaly")),
            },
            "beacons": [
                {"flow_id":b.flow_id,"src_ip":b.src_ip,"dst_ip":b.dst_ip,
                 "dst_port":b.dst_port,"interval_mean":b.interval_mean,
                 "interval_stdev":b.interval_stdev,"regularity":b.regularity,
                 "packet_count":b.packet_count,"confidence":b.confidence,
                 "beacon_type":b.beacon_type,"sni":b.sni,"ja3":b.ja3,
                 "malware_match":b.malware_match,"dga_score":b.dga_score}
                for b in beacons[:100]
            ],
            "bursts": [
                {"src_ip":b.src_ip,"dst_ip":b.dst_ip,"start_time":b.start_time,
                 "end_time":b.end_time,"packet_count":b.packet_count,
                 "total_bytes":b.total_bytes,"peak_pps":b.peak_pps,"severity":b.severity}
                for b in bursts[:50]
            ],
            "suspicious_ips": [
                {"ip":p.ip,"suspicion_score":p.suspicion_score,"reasons":p.suspicion_reasons,
                 "total_flows":p.total_flows,"total_bytes":p.total_bytes,
                 "unique_destinations":p.unique_destinations,"protocols":p.protocols,
                 "tls_ratio":p.tls_ratio,"ja3_hashes":p.ja3_hashes,"sni_domains":p.sni_domains,
                 "malware_ja3_matches":p.malware_ja3_matches,"dga_domains":p.dga_domains,
                 "os_guess":p.os_guess,"port_entropy":p.port_entropy,
                 "exfil_ratio":p.exfil_ratio,"fan_out":p.fan_out,"fan_in":p.fan_in,
                 "beacon_count":p.beacon_count}
                for p in suspicious
            ],
            "clusters": [
                {"cluster_id":c.cluster_id,"label":c.label,"flow_count":c.flow_count,
                 "dominant_port":c.dominant_port,"avg_bytes":c.avg_bytes,
                 "avg_duration":c.avg_duration,"centroid_ip":c.centroid_ip}
                for c in clusters
            ],
            "exfil_alerts": [
                {"src_ip":e.src_ip,"dst_ip":e.dst_ip,"total_sent":e.total_sent,
                 "total_recv":e.total_recv,"ratio":e.ratio,
                 "session_count":e.session_count,"sni":e.sni}
                for e in exfil
            ],
            "dga_alerts":   dga_alerts[:30],
            "ttl_profiles": [v for v in ttl_map.values() if v.get("anomaly")][:20],
            "protocol_distribution": dict(proto_counts),
            "top_destinations": [{"ip":ip,"bytes":b} for ip,b in sorted(dst_bytes.items(),key=lambda x:x[1],reverse=True)[:20]],
            "top_sources":      [{"ip":ip,"flows":c} for ip,c in sorted(src_flows.items(),key=lambda x:x[1],reverse=True)[:20]],
            "ja3_fingerprints": sorted(ja3_c.values(),key=lambda x:x["count"],reverse=True)[:30],
            "dns_queries":      sorted(dns_c.values(),key=lambda x:x["count"],reverse=True)[:50],
            "connection_graph": sorted(conn_graph.values(),key=lambda x:x["bytes"],reverse=True)[:200],
        }
