"""
NetForensics — FastAPI Backend
================================
REST API + WebSocket real-time streaming.
SQLite for dev, PostgreSQL-compatible schema.

Endpoints
---------
GET  /api/health
GET  /api/sessions
POST /api/sessions
GET  /api/sessions/{sid}
DEL  /api/sessions/{sid}
POST /api/upload/pcap
POST /api/capture/start
POST /api/capture/stop
GET  /api/capture/status
GET  /api/sessions/{sid}/flows
GET  /api/sessions/{sid}/packets
GET  /api/sessions/{sid}/stats
GET  /api/sessions/{sid}/graph
GET  /api/sessions/{sid}/analysis
POST /api/sessions/{sid}/analyze
GET  /api/intel/ip/{ip}
WS   /ws
"""

import asyncio
import json
import logging
import os
import sys
import time
import threading
import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import List, Optional

import aiosqlite
from fastapi import (BackgroundTasks, FastAPI, File, HTTPException,
                     Query, UploadFile, WebSocket, WebSocketDisconnect)
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Resolve project root on sys.path
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
)
logger = logging.getLogger("netforensics.api")

DB_PATH    = os.environ.get("NF_DB", "/tmp/netforensics.db")
UPLOAD_DIR = Path("/tmp/nf_uploads")
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

# ─── WebSocket Manager ───────────────────────────────────────────────────────

class WSManager:
    def __init__(self):
        self._conns: List[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self._conns.append(ws)

    def disconnect(self, ws: WebSocket):
        self._conns = [c for c in self._conns if c is not ws]

    async def broadcast(self, msg: dict):
        dead = []
        for ws in self._conns:
            try:
                await ws.send_json(msg)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)

ws_mgr = WSManager()

# ─── DB Init ──────────────────────────────────────────────────────────────────

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
    tls_version TEXT, sni TEXT, ja3 TEXT, ja3_string TEXT,
    FOREIGN KEY (session_id) REFERENCES capture_sessions(id)
);
CREATE TABLE IF NOT EXISTS packets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT, flow_id TEXT,
    timestamp REAL, src_ip TEXT, dst_ip TEXT,
    src_port INTEGER, dst_port INTEGER, protocol TEXT,
    size INTEGER, ttl INTEGER, flags TEXT,
    payload_entropy REAL, dns_query TEXT, dns_type TEXT,
    FOREIGN KEY (session_id) REFERENCES capture_sessions(id)
);
CREATE TABLE IF NOT EXISTS analysis_results (
    id TEXT PRIMARY KEY, session_id TEXT NOT NULL,
    analysis_type TEXT, result_data TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (session_id) REFERENCES capture_sessions(id)
);
CREATE INDEX IF NOT EXISTS idx_fl_sess  ON flows(session_id);
CREATE INDEX IF NOT EXISTS idx_fl_src   ON flows(src_ip);
CREATE INDEX IF NOT EXISTS idx_fl_dst   ON flows(dst_ip);
CREATE INDEX IF NOT EXISTS idx_pk_sess  ON packets(session_id);
CREATE INDEX IF NOT EXISTS idx_pk_ts    ON packets(timestamp);
CREATE INDEX IF NOT EXISTS idx_ar_sess  ON analysis_results(session_id);
"""

async def get_db() -> aiosqlite.Connection:
    db = await aiosqlite.connect(DB_PATH)
    db.row_factory = aiosqlite.Row
    await db.execute("PRAGMA journal_mode=WAL")
    await db.execute("PRAGMA foreign_keys=ON")
    return db

async def init_db():
    db = await get_db()
    await db.executescript(DDL)
    await db.commit()
    await db.close()
    logger.info("DB ready at %s", DB_PATH)

# ─── App Lifecycle ────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    logger.info("NetForensics API v3.0.0 — Enterprise ready")
    yield
    logger.info("Shutting down")

app = FastAPI(
    title="NetForensics API",
    version="3.0.0",
    description="Enterprise Cybersecurity Intelligence Platform",
    lifespan=lifespan,
)
app.add_middleware(CORSMiddleware, allow_origins=["*"],
                   allow_methods=["*"], allow_headers=["*"])

# ─── Mount Enterprise v3 Routes ──────────────────────────────────────────────
try:
    from backend.api.enterprise_routes import router as v3_router
    app.include_router(v3_router)
    logger.info("Enterprise v3 routes loaded")
except ImportError as e:
    logger.warning("Enterprise routes not available: %s", e)

# ─── Mount Tor Analysis Routes ───────────────────────────────────────────────
try:
    from backend.api.tor_routes import router as tor_router
    app.include_router(tor_router)
    logger.info("Tor analysis routes loaded")
except ImportError as e:
    logger.warning("Tor analysis routes not available: %s", e)

# ─── Mount ML Threat Detection Routes (v4) ───────────────────────────────────
try:
    from backend.api.ml_routes import router as ml_router
    app.include_router(ml_router)
    logger.info("ML threat detection routes (v4) loaded")
except ImportError as e:
    logger.warning("ML routes not available: %s", e)

# ─── Mount Enterprise v5 Routes ──────────────────────────────────────────────
try:
    from backend.api.enterprise_v5_routes import router as v5_router
    app.include_router(v5_router)
    logger.info("Enterprise v5 routes loaded (RBAC, SOC, STIX/TAXII, GeoIP, SIEM, Reports)")
except ImportError as e:
    logger.warning("Enterprise v5 routes not available: %s", e)

# ─── Mount Intelligence & Hunting Routes ─────────────────────────────────────
try:
    from backend.api.intel_routes import router as intel_router
    app.include_router(intel_router)
    logger.info("Intelligence routes loaded (Threat Intel, Fingerprint, Graph AI, "
                "Tor Deanon, Autonomous Hunting)")
except ImportError as e:
    logger.warning("Intelligence routes not available: %s", e)

# ─── Pydantic ─────────────────────────────────────────────────────────────────

class SessionCreate(BaseModel):
    name: str
    interface: str = "eth0"

class CaptureStart(BaseModel):
    interface: str = "eth0"
    name: Optional[str] = None

# ─── Helpers ─────────────────────────────────────────────────────────────────

def now_iso():
    return datetime.utcnow().isoformat()

async def _run_analysis(session_id: str):
    """Run full heuristic + ML analysis on stored session data."""
    from backend.analysis.traffic_analyzer import TrafficAnalyzer
    db = await get_db()
    try:
        flow_rows = await db.execute_fetchall(
            "SELECT * FROM flows WHERE session_id=?", (session_id,))
        pkt_rows  = await db.execute_fetchall(
            "SELECT flow_id,src_ip,dst_ip,timestamp,size,dns_query,dns_type "
            "FROM packets WHERE session_id=? LIMIT 100000", (session_id,))

        flows   = [dict(r) for r in flow_rows]
        packets = [dict(r) for r in pkt_rows]

        # ── Heuristic analysis ────────────────────────────────────────────────
        analyzer = TrafficAnalyzer()
        results  = analyzer.analyse(flows, packets)

        # ── ML threat detection ───────────────────────────────────────────────
        try:
            from backend.api.ml_routes import _get_pipeline
            pipeline = _get_pipeline()
            if not pipeline._initialized:
                pipeline.initialize()
            ml_results = pipeline.predict(flows, packets)
            results["ml_threats"]   = ml_results.get("ml_threats", [])[:50]
            results["ml_clusters"]  = ml_results.get("ml_clusters", [])
            results["ml_summary"]   = ml_results.get("ml_summary", {})
            # Merge ML threat count into summary
            results["summary"]["ml_threat_count"] = len(
                results["ml_threats"])
        except Exception as ml_err:
            logger.warning("ML analysis skipped: %s", ml_err)
            results["ml_threats"]  = []
            results["ml_clusters"] = []
            results["ml_summary"]  = {}

        # ── Advanced Fingerprinting (JA3/JA3S/HASSH/HTTP2) ────────────────────
        try:
            from backend.analysis.advanced_fingerprinting import AdvancedFingerprintEngine
            fp_engine = AdvancedFingerprintEngine()
            results["fingerprinting"] = fp_engine.analyse(flows, packets)
            results["summary"]["fingerprint_count"] = results["fingerprinting"].get(
                "summary", {}).get("total_fingerprints", 0)
        except Exception as fp_err:
            logger.warning("Fingerprinting skipped: %s", fp_err)
            results["fingerprinting"] = {}

        # ── Network Graph AI (clusters, C2 mapping) ──────────────────────────
        try:
            from backend.analysis.network_graph_ai import NetworkGraphAI
            gai = NetworkGraphAI()
            suspicious = {s.get("ip", "") for s in results.get("suspicious_ips", [])}
            results["graph_ai"] = gai.analyse(
                flows, results.get("beacons", []), suspicious)
            results["summary"]["graph_clusters"] = results["graph_ai"].get(
                "graph_summary", {}).get("cluster_count", 0)
            results["summary"]["c2_candidates"] = results["graph_ai"].get(
                "graph_summary", {}).get("c2_candidates", 0)
        except Exception as gai_err:
            logger.warning("Graph AI skipped: %s", gai_err)
            results["graph_ai"] = {}

        # ── Autonomous Threat Hunting ─────────────────────────────────────────
        try:
            from backend.analysis.autonomous_hunting import AutonomousThreatHunter
            hunter = AutonomousThreatHunter()
            results["threat_hunting"] = hunter.hunt(flows, results)
            results["summary"]["hunt_findings"] = results["threat_hunting"].get(
                "summary", {}).get("total_findings", 0)
            results["summary"]["attack_chains"] = results["threat_hunting"].get(
                "summary", {}).get("attack_chains", 0)
        except Exception as hunt_err:
            logger.warning("Threat hunting skipped: %s", hunt_err)
            results["threat_hunting"] = {}

        await db.execute(
            "INSERT INTO analysis_results(id,session_id,analysis_type,result_data,created_at)"
            " VALUES(?,?,?,?,?)",
            (str(uuid.uuid4()), session_id, "full_analysis",
             json.dumps(results, default=str), now_iso()))
        await db.commit()

        await ws_mgr.broadcast({"event": "analysis_complete", "session_id": session_id,
                                  "summary": results.get("summary", {})})
        logger.info("Analysis complete for session %s (ml_threats=%d)",
                     session_id[:8], len(results.get("ml_threats", [])))
    finally:
        await db.close()

# ─── Sessions ─────────────────────────────────────────────────────────────────

@app.get("/api/sessions")
async def list_sessions():
    db = await get_db()
    rows = await db.execute_fetchall(
        "SELECT * FROM capture_sessions ORDER BY started_at DESC LIMIT 50")
    await db.close()
    return [dict(r) for r in rows]

@app.post("/api/sessions", status_code=201)
async def create_session(data: SessionCreate):
    db  = await get_db()
    sid = str(uuid.uuid4())
    await db.execute(
        "INSERT INTO capture_sessions(id,name,source_type,interface,started_at)"
        " VALUES(?,?,?,?,?)",
        (sid, data.name, "live", data.interface, now_iso()))
    await db.commit()
    await db.close()
    return {"session_id": sid}

@app.get("/api/sessions/{sid}")
async def get_session(sid: str):
    db  = await get_db()
    row = await db.execute_fetchall(
        "SELECT * FROM capture_sessions WHERE id=?", (sid,))
    await db.close()
    if not row:
        raise HTTPException(404, "Session not found")
    return dict(row[0])

@app.delete("/api/sessions/{sid}")
async def delete_session(sid: str):
    db = await get_db()
    await db.execute("DELETE FROM capture_sessions WHERE id=?", (sid,))
    await db.commit()
    await db.close()
    return {"deleted": sid}

# ─── PCAP Upload ──────────────────────────────────────────────────────────────

@app.post("/api/upload/pcap")
async def upload_pcap(bg: BackgroundTasks, file: UploadFile = File(...)):
    if not file.filename.lower().endswith(".pcap"):
        raise HTTPException(400, "Only .pcap files accepted")
    path = UPLOAD_DIR / f"{uuid.uuid4().hex}_{file.filename}"
    path.write_bytes(await file.read())

    db  = await get_db()
    sid = str(uuid.uuid4())
    await db.execute(
        "INSERT INTO capture_sessions(id,name,source_type,source_path,started_at,status)"
        " VALUES(?,?,?,?,?,?)",
        (sid, file.filename, "pcap", str(path), now_iso(), "processing"))
    await db.commit()
    await db.close()

    bg.add_task(_process_pcap, str(path), sid)
    return {"session_id": sid, "filename": file.filename, "status": "processing"}

async def _process_pcap(path: str, session_id: str):
    from backend.capture.packet_capture import PcapImporter
    db = await get_db()
    try:
        imp     = PcapImporter(path)
        packets = imp.parse()
        flows   = imp.flows()

        # Insert packets in batches
        batch = []
        for p in packets:
            batch.append((session_id, p.flow_id, p.timestamp,
                          p.src_ip, p.dst_ip, p.src_port, p.dst_port,
                          p.protocol, p.size, p.ttl, p.flags,
                          p.payload_entropy, p.dns_query, p.dns_type))
            if len(batch) >= 2000:
                await db.executemany(
                    "INSERT INTO packets(session_id,flow_id,timestamp,src_ip,dst_ip,"
                    "src_port,dst_port,protocol,size,ttl,flags,payload_entropy,"
                    "dns_query,dns_type) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)", batch)
                await db.commit()
                batch.clear()
        if batch:
            await db.executemany(
                "INSERT INTO packets(session_id,flow_id,timestamp,src_ip,dst_ip,"
                "src_port,dst_port,protocol,size,ttl,flags,payload_entropy,"
                "dns_query,dns_type) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)", batch)
            await db.commit()

        # Insert flows
        for f in flows:
            await db.execute(
                "INSERT OR REPLACE INTO flows(id,session_id,flow_id,src_ip,dst_ip,"
                "src_port,dst_port,protocol,start_time,end_time,session_duration,"
                "packet_count,total_bytes,tls_version,sni,ja3,ja3_string)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (str(uuid.uuid4()), session_id, f.flow_id, f.src_ip, f.dst_ip,
                 f.src_port, f.dst_port, f.protocol, f.start_time, f.end_time,
                 f.session_duration, f.packet_count, f.total_bytes,
                 f.tls_version, f.sni, f.ja3, f.ja3_string))
        await db.commit()

        await db.execute(
            "UPDATE capture_sessions SET status='completed',ended_at=?,"
            "total_packets=?,total_flows=? WHERE id=?",
            (now_iso(), len(packets), len(flows), session_id))
        await db.commit()

        await ws_mgr.broadcast({"event": "pcap_complete", "session_id": session_id,
                                  "packets": len(packets), "flows": len(flows)})
        await db.close()
        await _run_analysis(session_id)

    except Exception as exc:
        logger.error("PCAP error: %s", exc, exc_info=True)
        await db.execute("UPDATE capture_sessions SET status='error' WHERE id=?",
                         (session_id,))
        await db.commit()
        await db.close()

# ─── Flows ────────────────────────────────────────────────────────────────────

@app.get("/api/sessions/{sid}/flows")
async def get_flows(
    sid: str,
    page:     int            = Query(1, ge=1),
    limit:    int            = Query(50, le=500),
    src_ip:   Optional[str] = None,
    dst_ip:   Optional[str] = None,
    protocol: Optional[str] = None,
    has_sni:  Optional[bool]= None,
    has_ja3:  Optional[bool]= None,
):
    db = await get_db()
    where = ["session_id=?"]; params: list = [sid]
    if src_ip:   where.append("src_ip=?");    params.append(src_ip)
    if dst_ip:   where.append("dst_ip=?");    params.append(dst_ip)
    if protocol: where.append("protocol=?");  params.append(protocol.upper())
    if has_sni is True:  where.append("sni IS NOT NULL")
    if has_sni is False: where.append("sni IS NULL")
    if has_ja3 is True:  where.append("ja3 IS NOT NULL")
    if has_ja3 is False: where.append("ja3 IS NULL")

    wq     = " AND ".join(where)
    offset = (page - 1) * limit

    rows  = await db.execute_fetchall(
        f"SELECT * FROM flows WHERE {wq} ORDER BY start_time DESC LIMIT ? OFFSET ?",
        params + [limit, offset])
    total = (await db.execute_fetchall(
        f"SELECT COUNT(*) AS n FROM flows WHERE {wq}", params))[0]["n"]
    await db.close()
    return {"flows": [dict(r) for r in rows], "total": total, "page": page, "limit": limit}

# ─── Packets ─────────────────────────────────────────────────────────────────

@app.get("/api/sessions/{sid}/packets")
async def get_packets(
    sid:       str,
    limit:     int            = Query(200, le=2000),
    src_ip:    Optional[str] = None,
    protocol:  Optional[str] = None,
):
    db = await get_db()
    where = ["session_id=?"]; params: list = [sid]
    if src_ip:   where.append("src_ip=?");    params.append(src_ip)
    if protocol: where.append("protocol=?");  params.append(protocol)
    wq   = " AND ".join(where)
    rows = await db.execute_fetchall(
        f"SELECT * FROM packets WHERE {wq} ORDER BY timestamp DESC LIMIT ?",
        params + [limit])
    await db.close()
    return [dict(r) for r in rows]

# ─── Stats ────────────────────────────────────────────────────────────────────

@app.get("/api/sessions/{sid}/stats")
async def get_stats(sid: str):
    db = await get_db()
    proto_rows = await db.execute_fetchall(
        "SELECT protocol, COUNT(*) AS cnt, SUM(total_bytes) AS bytes"
        " FROM flows WHERE session_id=? GROUP BY protocol", (sid,))
    src_rows   = await db.execute_fetchall(
        "SELECT src_ip, COUNT(*) AS flows, SUM(total_bytes) AS bytes"
        " FROM flows WHERE session_id=? GROUP BY src_ip ORDER BY flows DESC LIMIT 20", (sid,))
    dst_rows   = await db.execute_fetchall(
        "SELECT dst_ip, COUNT(*) AS flows, SUM(total_bytes) AS bytes"
        " FROM flows WHERE session_id=? GROUP BY dst_ip ORDER BY flows DESC LIMIT 20", (sid,))
    tl_rows    = await db.execute_fetchall(
        "SELECT CAST(timestamp/60 AS INTEGER)*60 AS bucket,"
        " COUNT(*) AS cnt, SUM(size) AS bytes"
        " FROM packets WHERE session_id=?"
        " GROUP BY bucket ORDER BY bucket", (sid,))
    ja3_rows   = await db.execute_fetchall(
        "SELECT ja3, tls_version, sni, COUNT(*) AS cnt"
        " FROM flows WHERE session_id=? AND ja3 IS NOT NULL"
        " GROUP BY ja3 ORDER BY cnt DESC LIMIT 30", (sid,))
    dns_rows   = await db.execute_fetchall(
        "SELECT dns_query, dns_type, COUNT(*) AS cnt"
        " FROM packets WHERE session_id=? AND dns_query IS NOT NULL"
        " GROUP BY dns_query ORDER BY cnt DESC LIMIT 50", (sid,))
    await db.close()
    return {
        "protocol_distribution": [dict(r) for r in proto_rows],
        "top_sources":           [dict(r) for r in src_rows],
        "top_destinations":      [dict(r) for r in dst_rows],
        "timeline":              [dict(r) for r in tl_rows],
        "tls_fingerprints":      [dict(r) for r in ja3_rows],
        "dns_queries":           [dict(r) for r in dns_rows],
    }

# ─── Network Graph ────────────────────────────────────────────────────────────

@app.get("/api/sessions/{sid}/graph")
async def get_graph(sid: str):
    db = await get_db()
    rows = await db.execute_fetchall(
        "SELECT src_ip, dst_ip, protocol,"
        " SUM(total_bytes) AS bytes, COUNT(*) AS flows"
        " FROM flows WHERE session_id=?"
        " GROUP BY src_ip,dst_ip,protocol LIMIT 500", (sid,))
    await db.close()
    nodes: set = set()
    edges = []
    for r in rows:
        nodes.add(r["src_ip"]); nodes.add(r["dst_ip"])
        edges.append({"source": r["src_ip"], "target": r["dst_ip"],
                      "protocol": r["protocol"],
                      "bytes": r["bytes"], "flows": r["flows"]})
    return {
        "nodes": [{"id": ip,
                   "type": "internal" if ip.startswith(("10.","192.168.","172.")) else "external"}
                  for ip in nodes if ip],
        "edges": edges,
    }

# ─── Analysis ─────────────────────────────────────────────────────────────────

@app.get("/api/sessions/{sid}/analysis")
async def get_analysis(sid: str):
    db   = await get_db()
    rows = await db.execute_fetchall(
        "SELECT * FROM analysis_results WHERE session_id=?"
        " ORDER BY created_at DESC LIMIT 5", (sid,))
    await db.close()
    results = []
    for r in rows:
        d = dict(r)
        try:
            d["result_data"] = json.loads(d["result_data"])
        except Exception:
            pass
        results.append(d)
    return results

@app.post("/api/sessions/{sid}/analyze")
async def trigger_analysis(sid: str, bg: BackgroundTasks):
    bg.add_task(_run_analysis, sid)
    return {"status": "analysis_queued", "session_id": sid}

# ─── IP Intelligence ─────────────────────────────────────────────────────────

@app.get("/api/intel/ip/{ip}")
async def ip_intel(ip: str):
    import ipaddress, socket as _s
    result = {"ip": ip, "private": False, "hostname": None, "note": ""}
    try:
        addr = ipaddress.ip_address(ip)
        result["private"]   = addr.is_private
        result["loopback"]  = addr.is_loopback
        result["multicast"] = addr.is_multicast
        if addr.is_private:
            result["note"] = "RFC1918 private address space"
    except ValueError:
        result["note"] = "Invalid IP"
    try:
        hostname = await asyncio.get_event_loop().run_in_executor(
            None, lambda: _s.gethostbyaddr(ip)[0])
        result["hostname"] = hostname
    except Exception:
        pass
    return result

# ─── Live Capture ─────────────────────────────────────────────────────────────

# Holds a reference to the active RawSocketCapture so capture_stop() can call
# cap.stop() directly — otherwise the socket thread keeps running indefinitely.
cap_state = {"running": False, "session_id": None, "cap_obj": None}

@app.post("/api/capture/start")
async def capture_start(data: CaptureStart, bg: BackgroundTasks):
    if cap_state["running"]:
        raise HTTPException(400, "Capture already running")
    db  = await get_db()
    sid = str(uuid.uuid4())
    await db.execute(
        "INSERT INTO capture_sessions(id,name,source_type,interface,started_at,status)"
        " VALUES(?,?,?,?,?,?)",
        (sid, data.name or f"Live {now_iso()[:16]}", "live",
         data.interface, now_iso(), "running"))
    await db.commit()
    await db.close()
    cap_state["running"]    = True
    cap_state["session_id"] = sid
    cap_state["cap_obj"]    = None   # will be set inside task once cap is created
    bg.add_task(_live_capture_task, sid, data.interface)
    return {"session_id": sid, "status": "started"}

@app.post("/api/capture/stop")
async def capture_stop():
    # FIX Bug 3 & 4: signal the cap object to stop its socket thread directly
    cap_state["running"] = False
    cap = cap_state.get("cap_obj")
    if cap is not None:
        cap.stop()                   # sets cap.running=False, closes socket
        cap_state["cap_obj"] = None

    sid = cap_state.get("session_id")
    if sid:
        db = await get_db()
        await db.execute(
            "UPDATE capture_sessions SET status='completed',ended_at=? WHERE id=?",
            (now_iso(), sid))
        await db.commit()
        await db.close()
        # Run analysis on whatever was captured
        try:
            await _run_analysis(sid)
        except Exception as e:
            logger.warning("Post-capture analysis failed: %s", e)

    # FIX Bug 7: clear stale session_id so next start is clean
    cap_state["session_id"] = None
    return {"status": "stopped", "session_id": sid}

@app.get("/api/capture/status")
async def capture_status():
    return {"running": cap_state["running"], "session_id": cap_state.get("session_id")}

async def _live_capture_task(session_id: str, interface: str):
    """
    Runs as a FastAPI background task.
    Attempts real AF_PACKET capture; falls back to demo mode if no privilege.

    FIX Bug 1: PermissionError is raised inside a daemon thread and is NOT
               propagated to the coroutine. We use a threading.Event to signal
               success/failure before starting the flush loop.
    FIX Bug 2: Use asyncio.get_running_loop() instead of deprecated get_event_loop().
    FIX Bug 3: Store cap object in cap_state so capture_stop() can call cap.stop().
    FIX Bug 6: Wrap DB flush in try/finally to guarantee db.close().
    """
    from backend.capture.packet_capture import RawSocketCapture

    # FIX Bug 2: get_running_loop() is correct inside an async context
    loop = asyncio.get_running_loop()
    buf: list = []

    # FIX Bug 1: use an Event to communicate thread startup success/failure
    started_event  = threading.Event()
    perm_error_ref = [False]   # mutable container so inner function can write it

    cap = RawSocketCapture(interface=interface)
    cap_state["cap_obj"] = cap   # FIX Bug 3: expose to capture_stop()

    def _thread_target():
        try:
            cap.start_live()          # blocks; raises PermissionError if no privilege
        except PermissionError:
            perm_error_ref[0] = True
        finally:
            started_event.set()       # always unblock the waiting coroutine

    def on_pkt(pkt):
        buf.append(pkt)
        # Signal the coroutine that the socket is working (first packet arrived)
        if not started_event.is_set():
            started_event.set()
        asyncio.run_coroutine_threadsafe(
            ws_mgr.broadcast({"event": "packet", "data": {
                "src_ip":    pkt.src_ip,   "dst_ip":  pkt.dst_ip,
                "protocol":  pkt.protocol, "size":    pkt.size,
                "timestamp": pkt.timestamp,"sni":     pkt.sni,
                "ja3":       pkt.ja3,      "dns_query":pkt.dns_query,
                "ttl":       pkt.ttl,
            }}), loop)

    cap.add_callback(on_pkt)

    t = threading.Thread(target=_thread_target, daemon=True, name="nf-capture")
    t.start()

    # Wait up to 2 seconds for the thread to either open the socket or fail
    started_event.wait(timeout=2.0)

    if perm_error_ref[0]:
        # FIX Bug 1: PermissionError properly detected via Event, not thread exception
        logger.warning("No CAP_NET_RAW — falling back to demo mode (session %s)", session_id[:8])
        await _demo_mode(session_id)
        return

    # ── Flush loop: persist packets to DB every 5 seconds ──────────────────────
    logger.info("Live capture started on %s (session %s)", interface, session_id[:8])
    while cap_state["running"]:
        await asyncio.sleep(5)
        if not buf:
            continue
        # FIX Bug 5: safely drain exactly N items without list slice reassignment
        drain_count = min(len(buf), 1000)
        batch, buf[:drain_count] = buf[:drain_count], []
        rows = [(session_id, p.flow_id, p.timestamp, p.src_ip, p.dst_ip,
                 p.src_port, p.dst_port, p.protocol, p.size, p.ttl,
                 p.flags, p.payload_entropy, p.dns_query, p.dns_type)
                for p in batch]
        # FIX Bug 6: guarantee db.close() even if insert fails
        db = await get_db()
        try:
            await db.executemany(
                "INSERT INTO packets(session_id,flow_id,timestamp,src_ip,dst_ip,"
                "src_port,dst_port,protocol,size,ttl,flags,payload_entropy,"
                "dns_query,dns_type) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
            await db.commit()
        except Exception as e:
            logger.error("Packet flush error: %s", e)
        finally:
            await db.close()

    # Loop exited because cap_state["running"] became False (capture_stop called)
    # capture_stop() already called cap.stop(), but belt-and-suspenders:
    if cap.running:
        cap.stop()
    logger.info("Live capture task finished for session %s", session_id[:8])


async def _demo_mode(session_id: str):
    """
    Streams synthetic but realistic traffic when live capture is unavailable.

    FIX Bug 8: Packets are now persisted to the DB so that analysis can run
               on demo sessions. Previously only WebSocket broadcast happened.
    """
    import random

    INTERNAL = ["10.0.0.10", "10.0.0.20", "10.0.0.50",
                "192.168.1.5", "192.168.1.100"]
    EXTERNAL = ["8.8.8.8", "1.1.1.1", "172.217.14.206",
                "13.107.42.14", "185.220.101.47", "151.101.1.140"]
    PROTOS   = ["TCP", "UDP", "TLS", "TLS", "TLS", "DNS"]  # weighted toward TLS
    DOMAINS  = ["google.com", "cloudflare.com", "microsoft.com",
                "github.com", "office.com", None]
    JA3S     = [None, None, None,
                "abc123def456abc1",
                "e7d705a3286e19ea42f587b344ee6865"]  # Cobalt Strike occasionally

    pkt_rows: list = []
    flow_counter   = 0
    logger.info("Demo mode active for session %s", session_id[:8])

    while cap_state["running"]:
        proto   = random.choice(PROTOS)
        src_ip  = random.choice(INTERNAL)
        dst_ip  = random.choice(EXTERNAL)
        sni     = random.choice(DOMAINS) if proto in ("TLS", "DNS") else None
        ja3     = random.choice(JA3S)    if proto == "TLS"           else None
        size    = random.randint(64, 1500)
        ts      = time.time()
        flow_id = f"demo-{flow_counter // 20}"  # group ~20 pkts per flow
        flow_counter += 1

        pkt_data = {
            "src_ip": src_ip, "dst_ip": dst_ip, "protocol": proto,
            "size": size, "timestamp": ts, "sni": sni, "ja3": ja3,
            "dns_query": sni if proto == "DNS" else None,
        }

        # Broadcast to WebSocket (existing behaviour)
        await ws_mgr.broadcast({"event": "packet", "data": pkt_data})

        # FIX Bug 8: buffer for DB persistence
        pkt_rows.append((
            session_id, flow_id, ts, src_ip, dst_ip,
            random.randint(1024, 65535),  # src_port
            443 if proto == "TLS" else 53 if proto == "DNS" else random.randint(80, 8080),
            proto, size,
            random.choice([64, 64, 128]),  # TTL (mostly Linux)
            "S" if proto == "TCP" else "",  # flags
            round(random.uniform(6.5, 7.9), 4) if proto == "TLS" else None,  # entropy
            sni if proto == "DNS" else None,   # dns_query
            "A" if proto == "DNS" else None,   # dns_type
        ))

        # Flush to DB every 50 packets
        if len(pkt_rows) >= 50:
            batch, pkt_rows = pkt_rows[:], []
            db = await get_db()
            try:
                await db.executemany(
                    "INSERT INTO packets(session_id,flow_id,timestamp,src_ip,dst_ip,"
                    "src_port,dst_port,protocol,size,ttl,flags,payload_entropy,"
                    "dns_query,dns_type) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)", batch)
                await db.commit()
            except Exception as e:
                logger.error("Demo DB flush error: %s", e)
            finally:
                await db.close()

        await asyncio.sleep(0.25)

    # Persist any remaining buffered packets
    if pkt_rows:
        db = await get_db()
        try:
            await db.executemany(
                "INSERT INTO packets(session_id,flow_id,timestamp,src_ip,dst_ip,"
                "src_port,dst_port,protocol,size,ttl,flags,payload_entropy,"
                "dns_query,dns_type) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)", pkt_rows)
            await db.commit()
        finally:
            await db.close()

    logger.info("Demo mode ended for session %s", session_id[:8])

# ─── WebSocket ────────────────────────────────────────────────────────────────

@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    await ws_mgr.connect(ws)
    try:
        while True:
            raw = await ws.receive_text()
            msg = json.loads(raw)
            if msg.get("type") == "ping":
                await ws.send_json({"type": "pong", "ts": time.time()})
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        ws_mgr.disconnect(ws)

# ─── Health ───────────────────────────────────────────────────────────────────

@app.get("/api/health")
async def health():
    return {"status": "ok", "version": "1.0.0",
            "capture_running": cap_state["running"]}

# ─── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")

# ─── New v2 Endpoints ─────────────────────────────────────────────────────────

@app.get("/api/sessions/{sid}/threats")
async def get_threats(sid: str):
    """Unified threat registry from all detection engines."""
    db = await get_db()
    rows = await db.execute_fetchall(
        "SELECT result_data FROM analysis_results WHERE session_id=? AND analysis_type='full_analysis'"
        " ORDER BY created_at DESC LIMIT 1", (sid,))
    await db.close()
    if not rows:
        return {"threats": []}
    try:
        data = json.loads(rows[0]["result_data"])
        return {"threats": data.get("threats", [])}
    except Exception:
        return {"threats": []}

@app.get("/api/sessions/{sid}/anomalies")
async def get_anomalies(sid: str):
    """Statistical anomalies (Z-score > 3σ) across flow metrics."""
    db = await get_db()
    rows = await db.execute_fetchall(
        "SELECT result_data FROM analysis_results WHERE session_id=? AND analysis_type='full_analysis'"
        " ORDER BY created_at DESC LIMIT 1", (sid,))
    await db.close()
    if not rows:
        return {"anomalies": []}
    try:
        data = json.loads(rows[0]["result_data"])
        return {
            "anomalies": data.get("anomalies", []),
            "exfil_alerts": data.get("exfil_alerts", []),
            "lateral_alerts": data.get("lateral_alerts", []),
        }
    except Exception:
        return {"anomalies": [], "exfil_alerts": [], "lateral_alerts": []}

@app.get("/api/sessions/{sid}/sessions")
async def get_reconstructed_sessions(sid: str):
    """Reconstructed logical sessions from flow groupings."""
    db = await get_db()
    rows = await db.execute_fetchall(
        "SELECT result_data FROM analysis_results WHERE session_id=? AND analysis_type='full_analysis'"
        " ORDER BY created_at DESC LIMIT 1", (sid,))
    await db.close()
    if not rows:
        return {"sessions": []}
    try:
        data = json.loads(rows[0]["result_data"])
        return {"sessions": data.get("sessions", [])}
    except Exception:
        return {"sessions": []}

@app.get("/api/sessions/{sid}/clusters")
async def get_clusters(sid: str):
    """Flow behavioural clusters."""
    db = await get_db()
    rows = await db.execute_fetchall(
        "SELECT result_data FROM analysis_results WHERE session_id=? AND analysis_type='full_analysis'"
        " ORDER BY created_at DESC LIMIT 1", (sid,))
    await db.close()
    if not rows:
        return {"clusters": []}
    try:
        data = json.loads(rows[0]["result_data"])
        return {"clusters": data.get("clusters", [])}
    except Exception:
        return {"clusters": []}

@app.get("/api/sessions/{sid}/summary")
async def get_full_summary(sid: str):
    """Complete analysis summary with all module outputs."""
    db = await get_db()
    sess_rows = await db.execute_fetchall("SELECT * FROM capture_sessions WHERE id=?", (sid,))
    anal_rows = await db.execute_fetchall(
        "SELECT result_data FROM analysis_results WHERE session_id=? AND analysis_type='full_analysis'"
        " ORDER BY created_at DESC LIMIT 1", (sid,))
    await db.close()
    session = dict(sess_rows[0]) if sess_rows else {}
    analysis = {}
    if anal_rows:
        try:
            analysis = json.loads(anal_rows[0]["result_data"])
        except Exception:
            pass
    return {"session": session, "analysis_summary": analysis.get("summary", {}),
            "threat_count": len(analysis.get("threats", [])),
            "top_threats": analysis.get("threats", [])[:5]}
