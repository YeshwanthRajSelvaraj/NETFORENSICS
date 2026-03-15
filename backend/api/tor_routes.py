"""
NetForensics — Tor Analysis API Routes
=========================================
Dedicated endpoints for the TorAnalyzer Engine:
  /api/v3/tor/analyze/{sid}        — Full 9-module Tor analysis
  /api/v3/tor/events/{sid}         — Filtered Tor events
  /api/v3/tor/circuits/{sid}       — Detected circuits
  /api/v3/tor/hidden-services/{sid}— Hidden service indicators
  /api/v3/tor/c2/{sid}             — C2-over-Tor indicators
  /api/v3/tor/timeline/{sid}       — Event timeline
  /api/v3/tor/endpoints/{sid}      — Endpoint summary
  /api/v3/tor/entropy/{sid}        — Flow entropy profiles
  /api/v3/tor/nodes/stats          — Tor node DB statistics
  /api/v3/tor/dashboard/{sid}      — Full dashboard data
"""

import json, logging, os, time, uuid
from typing import Optional
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

logger = logging.getLogger("netforensics.api.tor")
router = APIRouter(prefix="/api/v3/tor", tags=["Tor Analysis"])

_analyzer = None

def _get_analyzer():
    global _analyzer
    if _analyzer is None:
        from backend.analysis.tor_analyzer import TorAnalyzer
        _analyzer = TorAnalyzer()
    return _analyzer

async def _load_data(sid: str):
    import aiosqlite
    DB = os.environ.get("NF_DB", "/tmp/netforensics.db")
    db = await aiosqlite.connect(DB)
    db.row_factory = aiosqlite.Row
    try:
        flows = [dict(r) for r in await db.execute_fetchall(
            "SELECT * FROM flows WHERE session_id=?", (sid,))]
        pkts = [dict(r) for r in await db.execute_fetchall(
            "SELECT * FROM packets WHERE session_id=? LIMIT 200000", (sid,))]
        return flows, pkts
    finally:
        await db.close()

async def _save_results(sid: str, results: dict):
    import aiosqlite
    DB = os.environ.get("NF_DB", "/tmp/netforensics.db")
    db = await aiosqlite.connect(DB)
    try:
        await db.execute(
            "INSERT INTO analysis_results(id,session_id,analysis_type,result_data,created_at)"
            " VALUES(?,?,?,?,?)",
            (str(uuid.uuid4()), sid, "tor_analysis",
             json.dumps(results, default=str), time.strftime("%Y-%m-%dT%H:%M:%S")))
        await db.commit()
    finally:
        await db.close()

# Cache analyzed results per session
_cache: dict = {}


@router.post("/analyze/{sid}")
async def run_tor_analysis(sid: str):
    """Run full 9-module TorAnalyzer on session traffic."""
    flows, pkts = await _load_data(sid)
    if not flows:
        raise HTTPException(404, "Session not found or has no flows")
    analyzer = _get_analyzer()
    results = analyzer.analyse(flows, pkts)
    _cache[sid] = results
    await _save_results(sid, results)
    return {
        "status": "complete",
        "session_id": sid,
        "summary": results.get("tor_summary", {}),
        "event_count": len(results.get("tor_events", [])),
        "circuit_count": len(results.get("tor_circuits", [])),
        "hs_indicators": len(results.get("hidden_service_indicators", [])),
        "c2_indicators": len(results.get("c2_indicators", [])),
    }


async def _get_cached(sid: str) -> dict:
    if sid in _cache:
        return _cache[sid]
    import aiosqlite
    DB = os.environ.get("NF_DB", "/tmp/netforensics.db")
    db = await aiosqlite.connect(DB)
    db.row_factory = aiosqlite.Row
    try:
        rows = await db.execute_fetchall(
            "SELECT result_data FROM analysis_results "
            "WHERE session_id=? AND analysis_type='tor_analysis' "
            "ORDER BY created_at DESC LIMIT 1", (sid,))
        if rows:
            data = json.loads(rows[0]["result_data"])
            _cache[sid] = data
            return data
    finally:
        await db.close()
    return {}


@router.get("/events/{sid}")
async def get_tor_events(
    sid: str,
    severity: Optional[str] = None,
    event_type: Optional[str] = None,
    min_score: float = Query(0, ge=0, le=100),
    limit: int = Query(100, le=500),
):
    """Get filtered Tor detection events."""
    data = await _get_cached(sid)
    if not data:
        raise HTTPException(404, "Run /analyze first")
    events = data.get("tor_events", [])
    if severity:
        events = [e for e in events if e.get("severity") == severity.upper()]
    if event_type:
        events = [e for e in events if e.get("event_type") == event_type]
    if min_score > 0:
        events = [e for e in events if e.get("score", 0) >= min_score]
    return {"events": events[:limit], "total": len(events)}


@router.get("/circuits/{sid}")
async def get_tor_circuits(sid: str):
    """Get detected Tor circuits with hop details."""
    data = await _get_cached(sid)
    if not data:
        raise HTTPException(404, "Run /analyze first")
    circuits = data.get("tor_circuits", [])
    hs_circuits = [c for c in circuits if c.get("is_hidden_service")]
    return {
        "circuits": circuits,
        "total": len(circuits),
        "hidden_service_circuits": len(hs_circuits),
        "avg_hops": round(sum(len(c.get("hops",[])) for c in circuits) /
                          max(len(circuits), 1), 1),
        "avg_build_time_ms": round(sum(c.get("build_time_ms",0) for c in circuits) /
                                    max(len(circuits), 1), 1),
    }


@router.get("/hidden-services/{sid}")
async def get_hidden_services(sid: str):
    """Get hidden service communication indicators."""
    data = await _get_cached(sid)
    if not data:
        raise HTTPException(404, "Run /analyze first")
    indicators = data.get("hidden_service_indicators", [])
    hs_events = [e for e in data.get("tor_events", [])
                 if e.get("event_type") == "hidden_service"]
    return {
        "indicators": indicators,
        "events": hs_events,
        "total_indicators": len(indicators),
        "onion_dns_leaks": sum(1 for e in hs_events if e.get("sub_type")=="onion_dns_leak"),
        "rendezvous_patterns": sum(1 for e in hs_events if e.get("sub_type")=="rendezvous_pattern"),
        "extended_circuits": sum(1 for e in hs_events if e.get("sub_type")=="extended_circuit"),
    }


@router.get("/c2/{sid}")
async def get_c2_indicators(sid: str):
    """Get Tor-based C2 channel indicators."""
    data = await _get_cached(sid)
    if not data:
        raise HTTPException(404, "Run /analyze first")
    indicators = data.get("c2_indicators", [])
    c2_events = [e for e in data.get("tor_events", [])
                 if e.get("event_type") == "tor_c2"]
    return {
        "indicators": indicators,
        "events": c2_events,
        "total_indicators": len(indicators),
        "beacon_alerts": sum(1 for e in c2_events if e.get("sub_type")=="beacon_over_tor"),
        "exfil_alerts": sum(1 for e in c2_events if e.get("sub_type")=="tor_exfiltration"),
    }


@router.get("/timeline/{sid}")
async def get_tor_timeline(sid: str, bucket_seconds: int = Query(60, ge=10, le=3600)):
    """Get event timeline bucketed by time interval."""
    data = await _get_cached(sid)
    if not data:
        raise HTTPException(404, "Run /analyze first")
    events = data.get("tor_events", [])
    if not events:
        return {"timeline": [], "buckets": 0}

    timestamps = [e.get("timestamp", 0) for e in events if e.get("timestamp", 0) > 0]
    if not timestamps:
        return {"timeline": [], "buckets": 0}

    t_min, t_max = min(timestamps), max(timestamps)
    buckets = {}
    for e in events:
        ts = e.get("timestamp", 0)
        if ts <= 0: continue
        bucket = int((ts - t_min) / bucket_seconds)
        if bucket not in buckets:
            buckets[bucket] = {"time_offset": bucket * bucket_seconds,
                "events": 0, "critical": 0, "high": 0, "medium": 0, "avg_score": 0, "scores": []}
        b = buckets[bucket]
        b["events"] += 1
        sev = e.get("severity", "").upper()
        if sev in b: b[sev.lower()] += 1
        b["scores"].append(e.get("score", 0))

    timeline = []
    for k in sorted(buckets.keys()):
        b = buckets[k]
        b["avg_score"] = round(sum(b["scores"]) / max(len(b["scores"]), 1), 1)
        del b["scores"]
        timeline.append(b)

    return {"timeline": timeline, "buckets": len(timeline),
            "time_range_seconds": t_max - t_min}


@router.get("/endpoints/{sid}")
async def get_tor_endpoints(sid: str):
    """Get endpoint summary showing internal users and contacted Tor nodes."""
    data = await _get_cached(sid)
    if not data:
        raise HTTPException(404, "Run /analyze first")
    return {
        "endpoints": data.get("tor_endpoints", []),
        "internal_users": data.get("internal_users", []),
        "total_endpoints": len(data.get("tor_endpoints", [])),
        "total_internal": len(data.get("internal_users", [])),
    }


@router.get("/entropy/{sid}")
async def get_entropy_profiles(sid: str):
    """Get flow entropy analysis results."""
    data = await _get_cached(sid)
    if not data:
        raise HTTPException(404, "Run /analyze first")
    entropy_events = [e for e in data.get("tor_events", [])
                      if e.get("event_type") == "flow_entropy"]
    return {
        "entropy_events": entropy_events,
        "total": len(entropy_events),
    }


@router.get("/nodes/stats")
async def get_node_stats():
    """Get Tor node database statistics."""
    analyzer = _get_analyzer()
    return {"node_database": analyzer.db.node_count()}


@router.get("/dashboard/{sid}")
async def get_tor_dashboard(sid: str):
    """Full dashboard data — summary, top events, circuits, HS, C2, timeline."""
    data = await _get_cached(sid)
    if not data:
        raise HTTPException(404, "Run POST /analyze/{sid} first")

    events = data.get("tor_events", [])
    return {
        "summary": data.get("tor_summary", {}),
        "top_events": events[:20],
        "circuits": data.get("tor_circuits", [])[:10],
        "hidden_services": data.get("hidden_service_indicators", [])[:10],
        "c2_indicators": data.get("c2_indicators", [])[:10],
        "internal_users": data.get("internal_users", [])[:15],
        "severity_breakdown": {
            sev: sum(1 for e in events if e.get("severity") == sev)
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        },
        "type_breakdown": {},
        "node_db": data.get("tor_node_db", {}),
    }
