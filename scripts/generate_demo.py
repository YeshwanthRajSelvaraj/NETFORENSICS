"""
NetForensics — Demo Data Generator
====================================
Generates a complete synthetic forensic scenario:
  • Normal HTTPS browsing (250 flows)
  • DNS queries (100 events)
  • C2 beaconing at 60s intervals — HIGH confidence (60 packets)
  • Port scan (100 short flows)
  • Bulk TLS transfer (50 packets)
  • ICMP host sweep (30 flows)
  • Malware JA3 (Cobalt Strike default hash)

Uses stdlib only (sqlite3). No network access required.
"""

import hashlib
import json
import math
import random
import sqlite3
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

DB_PATH = "/tmp/netforensics.db"

# ─── Schema ───────────────────────────────────────────────────────────────────
DDL = """
CREATE TABLE IF NOT EXISTS capture_sessions (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, source_type TEXT NOT NULL,
    source_path TEXT, interface TEXT, status TEXT DEFAULT 'running',
    started_at TEXT NOT NULL, ended_at TEXT,
    total_packets INTEGER DEFAULT 0, total_flows INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS flows (
    id TEXT PRIMARY KEY, session_id TEXT NOT NULL, flow_id TEXT,
    src_ip TEXT, dst_ip TEXT, src_port INTEGER, dst_port INTEGER,
    protocol TEXT, start_time REAL, end_time REAL,
    session_duration REAL DEFAULT 0, packet_count INTEGER DEFAULT 0,
    total_bytes INTEGER DEFAULT 0,
    tls_version TEXT, sni TEXT, ja3 TEXT, ja3_string TEXT
);
CREATE TABLE IF NOT EXISTS packets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT, flow_id TEXT,
    timestamp REAL, src_ip TEXT, dst_ip TEXT,
    src_port INTEGER, dst_port INTEGER, protocol TEXT,
    size INTEGER, ttl INTEGER, flags TEXT,
    payload_entropy REAL, dns_query TEXT, dns_type TEXT
);
CREATE TABLE IF NOT EXISTS analysis_results (
    id TEXT PRIMARY KEY, session_id TEXT NOT NULL,
    analysis_type TEXT, result_data TEXT, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_fl_sess ON flows(session_id);
CREATE INDEX IF NOT EXISTS idx_pk_sess ON packets(session_id);
"""

# ─── Helpers ─────────────────────────────────────────────────────────────────

def make_fid(s, d, sp, dp, p) -> str:
    pair = sorted([(s, sp), (d, dp)])
    raw  = f"{pair[0][0]}:{pair[0][1]}-{pair[1][0]}:{pair[1][1]}-{p}"
    return hashlib.md5(raw.encode()).hexdigest()[:16]

def now_iso():
    return datetime.now(timezone.utc).isoformat()

# ─── Constants ───────────────────────────────────────────────────────────────

INTERNAL = ["10.0.0.10","10.0.0.20","10.0.0.50","192.168.1.5","192.168.1.100"]
EXTERNAL = ["8.8.8.8","1.1.1.1","172.217.14.206","13.107.42.14",
            "52.96.0.0","151.101.1.140","104.21.25.218","216.58.215.110"]
C2_IP    = "185.220.101.47"
DOMAINS  = ["google.com","microsoft.com","api.github.com",
            "cdn.cloudflare.com","update.example.com","mail.proton.me"]
C2_SNI   = "a1b2c3d4.evil-c2.ru"
COBALT_JA3  = "e7d705a3286e19ea42f587b344ee6865"   # Cobalt Strike default
NORMAL_JA3S = ["abc123def456789abcdef0123456789a",
               "fed987cba654321fedcba9876543210f",
               "111aaa222bbb333ccc444ddd555eee66"]
TLS_VERSIONS = ["TLS 1.2", "TLS 1.3"]

# ─── Main ─────────────────────────────────────────────────────────────────────

def generate():
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(DDL)
    conn.commit()

    sid = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO capture_sessions(id,name,source_type,started_at,status)"
        " VALUES(?,?,?,?,?)",
        (sid, "Demo — Synthetic Forensic Scenario", "demo", now_iso(), "processing"))
    conn.commit()

    now = time.time() - 3600
    packets = []
    flows:  dict = {}

    def add_pkt(fid, ts, src, dst, sp, dp, proto, size, ttl=64,
                flags="SA", entropy=7.9, dns_q=None, dns_t=None):
        packets.append((sid, fid, ts, src, dst, sp, dp, proto,
                        size, ttl, flags, entropy, dns_q, dns_t))

    def upsert_flow(fid, src, dst, sp, dp, proto, ts, size,
                    tls_ver=None, sni=None, ja3=None):
        if fid not in flows:
            flows[fid] = {
                "flow_id": fid, "src_ip": src, "dst_ip": dst,
                "src_port": sp, "dst_port": dp, "protocol": proto,
                "start_time": ts, "end_time": ts,
                "packet_count": 0, "total_bytes": 0,
                "tls_version": tls_ver, "sni": sni, "ja3": ja3,
                "packet_timestamps": [],
            }
        f = flows[fid]
        f["end_time"]      = ts
        f["packet_count"] += 1
        f["total_bytes"]  += size
        f["packet_timestamps"].append(ts)
        if tls_ver: f["tls_version"] = tls_ver
        if sni:     f["sni"]         = sni
        if ja3:     f["ja3"]         = ja3

    # ── 1. Normal HTTPS browsing ─────────────────────────────────────────────
    for i in range(250):
        ts    = now + i * 12 + random.uniform(-3, 3)
        src   = random.choice(INTERNAL)
        dst   = random.choice(EXTERNAL[:6])
        proto = random.choice(["TLS", "TLS", "TCP"])
        sp, dp= random.randint(49152, 65535), (443 if proto=="TLS" else 80)
        sni   = random.choice(DOMAINS)
        ja3   = random.choice(NORMAL_JA3S)
        tver  = random.choice(TLS_VERSIONS)
        size  = random.randint(200, 1400)
        fid   = make_fid(src, dst, sp, dp, proto)
        upsert_flow(fid, src, dst, sp, dp, proto, ts, size, tver, sni, ja3)
        add_pkt(fid, ts, src, dst, sp, dp, proto, size)

    # ── 2. DNS queries ───────────────────────────────────────────────────────
    for i in range(100):
        ts  = now + i * 35 + random.uniform(-5, 5)
        src = random.choice(INTERNAL[:3])
        dom = random.choice(DOMAINS)
        sp  = random.randint(49152, 65535)
        fid = make_fid(src, "8.8.8.8", sp, 53, "DNS")
        upsert_flow(fid, src, "8.8.8.8", sp, 53, "DNS", ts, 80)
        add_pkt(fid, ts, src, "8.8.8.8", sp, 53, "DNS", 80,
                ttl=64, flags="", entropy=0.0, dns_q=dom, dns_t="A")

    # ── 3. C2 Beacon — 60s intervals, tiny jitter ────────────────────────────
    beacon_src = "10.0.0.50"
    bf = make_fid(beacon_src, C2_IP, 55555, 443, "TLS")
    for i in range(60):
        ts = now + i * 60 + random.uniform(-1.5, 1.5)
        upsert_flow(bf, beacon_src, C2_IP, 55555, 443, "TLS",
                    ts, 256, "TLS 1.2", C2_SNI, COBALT_JA3)
        add_pkt(bf, ts, beacon_src, C2_IP, 55555, 443, "TLS",
                256, ttl=128, flags="PA", entropy=7.98)

    # ── 4. Port Scan ─────────────────────────────────────────────────────────
    scanner = "192.168.1.5"
    for port in range(1, 101):
        ts  = now + 1800 + port * 0.05
        sp2 = random.randint(40000, 65535)
        fid = make_fid(scanner, "10.0.0.20", sp2, port, "TCP")
        upsert_flow(fid, scanner, "10.0.0.20", sp2, port, "TCP", ts, 60)
        add_pkt(fid, ts, scanner, "10.0.0.20", sp2, port, "TCP",
                60, ttl=64, flags="S", entropy=0.0)

    # ── 5. Bulk TLS Transfer ─────────────────────────────────────────────────
    bk = make_fid("10.0.0.10", "151.101.1.140", 44444, 443, "TLS")
    for i in range(50):
        ts = now + 2400 + i * 2.4
        upsert_flow(bk, "10.0.0.10", "151.101.1.140", 44444, 443,
                    "TLS", ts, 1400, "TLS 1.3", "cdn.cloudflare.com", NORMAL_JA3S[0])
        add_pkt(bk, ts, "10.0.0.10", "151.101.1.140", 44444, 443,
                "TLS", 1400, ttl=64, flags="PA", entropy=7.99)

    # ── 6. ICMP Sweep ────────────────────────────────────────────────────────
    for i in range(30):
        ts  = now + 2700 + i * 0.3
        tgt = f"10.0.0.{i + 1}"
        fid = make_fid("192.168.1.100", tgt, 0, 0, "ICMP")
        upsert_flow(fid, "192.168.1.100", tgt, 0, 0, "ICMP", ts, 64)
        add_pkt(fid, ts, "192.168.1.100", tgt, 0, 0, "ICMP", 64, ttl=64, flags="")

    # ── Store packets ─────────────────────────────────────────────────────────
    conn.executemany(
        "INSERT INTO packets(session_id,flow_id,timestamp,src_ip,dst_ip,"
        "src_port,dst_port,protocol,size,ttl,flags,payload_entropy,"
        "dns_query,dns_type) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)", packets)
    conn.commit()

    # ── Store flows ───────────────────────────────────────────────────────────
    for f in flows.values():
        f["session_duration"] = f["end_time"] - f["start_time"]
        conn.execute(
            "INSERT OR REPLACE INTO flows(id,session_id,flow_id,src_ip,dst_ip,"
            "src_port,dst_port,protocol,start_time,end_time,session_duration,"
            "packet_count,total_bytes,tls_version,sni,ja3) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (str(uuid.uuid4()), sid, f["flow_id"], f["src_ip"], f["dst_ip"],
             f.get("src_port",0), f.get("dst_port",0), f["protocol"],
             f["start_time"], f["end_time"], f["session_duration"],
             f["packet_count"], f["total_bytes"],
             f.get("tls_version"), f.get("sni"), f.get("ja3")))
    conn.commit()

    # ── Run analysis ──────────────────────────────────────────────────────────
    from backend.analysis.traffic_analyzer import TrafficAnalyzer
    fl  = list(flows.values())
    pl  = [{"flow_id": p[1], "src_ip": p[3], "dst_ip": p[4],
            "timestamp": p[2], "size": p[8],
            "dns_query": p[12], "dns_type": p[13]}
           for p in packets]
    res = TrafficAnalyzer().analyse(fl, pl)

    conn.execute(
        "INSERT INTO analysis_results(id,session_id,analysis_type,result_data,created_at)"
        " VALUES(?,?,?,?,?)",
        (str(uuid.uuid4()), sid, "full_analysis", json.dumps(res), now_iso()))
    conn.execute(
        "UPDATE capture_sessions SET status='completed',ended_at=?,"
        "total_packets=?,total_flows=? WHERE id=?",
        (now_iso(), len(packets), len(flows), sid))
    conn.commit()
    conn.close()

    print(f"\n{'='*50}")
    print(f"  Demo session created successfully")
    print(f"{'='*50}")
    print(f"  Session ID : {sid}")
    print(f"  Packets    : {len(packets)}")
    print(f"  Flows      : {len(flows)}")
    print(f"  Database   : {DB_PATH}")
    print(f"\n  Analysis Summary:")
    s = res.get("summary", {})
    print(f"    Total flows          : {s.get('total_flows',0)}")
    print(f"    Unique IPs           : {s.get('unique_ips',0)}")
    print(f"    Beacon alerts        : {s.get('beacon_count',0)}")
    print(f"    Suspicious IPs       : {s.get('suspicious_ip_count',0)}")
    print(f"\n  Suspicious Endpoints:")
    for ip_info in res.get("suspicious_ips", [])[:5]:
        print(f"    {ip_info['ip']:20} score={ip_info['suspicion_score']:.0f}"
              f"  {ip_info['reasons'][:1]}")
    print(f"\n  Beacons detected: {len(res.get('beacons',[]))}")
    for b in res.get("beacons", [])[:3]:
        print(f"    {b['src_ip']} → {b['dst_ip']}:{b['dst_port']}"
              f"  interval={b['interval_mean']}s"
              f"  regularity={b['regularity']:.3f}"
              f"  [{b['confidence']}]")
    print()
    return sid

if __name__ == "__main__":
    generate()
