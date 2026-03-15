"""
NetForensics — Advanced Intelligence API Routes v5
=====================================================
REST API endpoints for:
  • Threat Intelligence Feeds (AbuseIPDB, VirusTotal, OTX, Tor nodes)
  • Advanced Fingerprinting (JA3, JA3S, HASSH, HTTP/2)
  • Network Graph AI (infrastructure clusters, anomalies, C2 mapping)
  • Tor De-Anonymization Research (timing/volume correlations, fingerprints)
  • Autonomous Threat Hunting (anomalies, attack chains, hypotheses)
"""

import json
import logging
import uuid
from typing import Optional

from fastapi import APIRouter, HTTPException, Query

logger = logging.getLogger("netforensics.intel_routes")

router = APIRouter(prefix="/api/v5", tags=["Intelligence & Hunting"])

# ── Lazy singleton instances ───────────────────────────────────────────────────

_threat_intel = None
_fingerprint_engine = None
_graph_ai = None
_tor_deanon = None
_threat_hunter = None


def _get_threat_intel():
    global _threat_intel
    if _threat_intel is None:
        from backend.services.threat_intel_feeds import UnifiedThreatIntel
        _threat_intel = UnifiedThreatIntel()
    return _threat_intel


def _get_fingerprint_engine():
    global _fingerprint_engine
    if _fingerprint_engine is None:
        from backend.analysis.advanced_fingerprinting import AdvancedFingerprintEngine
        _fingerprint_engine = AdvancedFingerprintEngine()
    return _fingerprint_engine


def _get_graph_ai():
    global _graph_ai
    if _graph_ai is None:
        from backend.analysis.network_graph_ai import NetworkGraphAI
        _graph_ai = NetworkGraphAI()
    return _graph_ai


def _get_tor_deanon():
    global _tor_deanon
    if _tor_deanon is None:
        from backend.analysis.tor_deanon import TorDeanonEngine
        _tor_deanon = TorDeanonEngine()
    return _tor_deanon


def _get_threat_hunter():
    global _threat_hunter
    if _threat_hunter is None:
        from backend.analysis.autonomous_hunting import AutonomousThreatHunter
        _threat_hunter = AutonomousThreatHunter()
    return _threat_hunter


# ── Helper: load session data ──────────────────────────────────────────────────

async def _load_session_data(session_id: str) -> dict:
    """Load flows, packets, and analysis from DB for a session."""
    import aiosqlite
    import os
    DB_PATH = os.environ.get("NF_DB", "/tmp/netforensics.db")
    db = await aiosqlite.connect(DB_PATH)
    db.row_factory = aiosqlite.Row

    try:
        flow_rows = await db.execute_fetchall(
            "SELECT * FROM flows WHERE session_id=?", (session_id,))
        pkt_rows = await db.execute_fetchall(
            "SELECT * FROM packets WHERE session_id=? LIMIT 100000", (session_id,))

        flows = [dict(r) for r in flow_rows]
        packets = [dict(r) for r in pkt_rows]

        # Load latest analysis if available
        analysis_rows = await db.execute_fetchall(
            "SELECT result_data FROM analysis_results WHERE session_id=? "
            "ORDER BY created_at DESC LIMIT 1", (session_id,))
        analysis = {}
        if analysis_rows:
            try:
                analysis = json.loads(analysis_rows[0]["result_data"])
            except Exception:
                pass

        return {"flows": flows, "packets": packets, "analysis": analysis}
    finally:
        await db.close()


# ═══════════════════════════════════════════════════════════════════════════════
# THREAT INTELLIGENCE ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

@router.get("/intel/lookup/{ip}")
async def intel_lookup(ip: str):
    """Multi-source threat intel lookup (AbuseIPDB + VirusTotal + OTX + Tor)."""
    ti = _get_threat_intel()
    result = await ti.lookup_ip(ip)
    return result


@router.get("/intel/bulk/{session_id}")
async def intel_bulk_enrich(session_id: str,
                            max_ips: int = Query(30, le=100)):
    """Bulk enrich all external IPs from a session with threat intel."""
    ti = _get_threat_intel()
    data = await _load_session_data(session_id)
    if not data["flows"]:
        raise HTTPException(404, "Session has no flows")

    result = await ti.enrich_flows(data["flows"])
    return result


@router.get("/intel/tor-nodes")
async def get_tor_nodes():
    """Get Tor node list status and statistics."""
    ti = _get_threat_intel()
    return ti.tor_nodes.get_stats()


@router.post("/intel/tor-nodes/sync")
async def sync_tor_nodes():
    """Force sync Tor node list from Tor Project."""
    ti = _get_threat_intel()
    await ti.tor_nodes.sync(force=True)
    return {"status": "synced", **ti.tor_nodes.get_stats()}


@router.get("/intel/otx/pulses")
async def get_otx_pulses():
    """Fetch latest OTX threat intelligence pulses."""
    ti = _get_threat_intel()
    pulses = await ti.otx.fetch_pulses()
    return {
        "pulses": [
            {"id": p.pulse_id, "name": p.name, "author": p.author,
             "created": p.created, "tags": p.tags, "tlp": p.tlp,
             "adversary": p.adversary, "attack_ids": p.attack_ids,
             "indicator_count": len(p.indicators),
             "description": p.description[:200]}
            for p in pulses
        ],
        "total": len(pulses),
    }


@router.get("/intel/stats")
async def intel_stats():
    """Get threat intel service statistics."""
    ti = _get_threat_intel()
    return ti.get_stats()


# ═══════════════════════════════════════════════════════════════════════════════
# ADVANCED FINGERPRINTING ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

@router.get("/fingerprint/{session_id}")
async def fingerprint_analysis(session_id: str):
    """Run full JA3 + JA3S + HASSH + HTTP/2 fingerprint analysis."""
    engine = _get_fingerprint_engine()
    data = await _load_session_data(session_id)
    if not data["flows"]:
        raise HTTPException(404, "Session has no flows")

    result = engine.analyse(data["flows"], data["packets"])
    return result


@router.get("/fingerprint/{session_id}/ja3")
async def ja3_analysis(session_id: str):
    """Get JA3 (TLS client) fingerprint analysis only."""
    engine = _get_fingerprint_engine()
    data = await _load_session_data(session_id)
    results, clusters = engine.ja3.analyse(data["flows"])
    return {
        "fingerprints": [
            {"hash": r.hash_value, "app": r.matched_app, "type": r.matched_type,
             "severity": r.severity, "count": r.count, "ips": r.associated_ips[:5],
             "snis": r.associated_snis[:5]}
            for r in results
        ],
        "clusters": [
            {"hash": c.fingerprint_hash, "app": c.matched_app,
             "risk": c.risk_level, "flows": c.flow_count}
            for c in clusters
        ],
    }


@router.get("/fingerprint/{session_id}/hassh")
async def hassh_analysis(session_id: str):
    """Get HASSH (SSH) fingerprint analysis only."""
    engine = _get_fingerprint_engine()
    data = await _load_session_data(session_id)
    results = engine.hassh.analyse(data["flows"], data["packets"])
    return {
        "fingerprints": [
            {"hash": r.hash_value, "app": r.matched_app, "type": r.matched_type,
             "severity": r.severity, "src_ip": r.ip, "port": r.port}
            for r in results
        ],
    }


# ═══════════════════════════════════════════════════════════════════════════════
# NETWORK GRAPH AI ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

@router.get("/graph-ai/{session_id}")
async def graph_ai_analysis(session_id: str):
    """Run full Network Graph AI analysis (clusters, anomalies, C2 mapping)."""
    engine = _get_graph_ai()
    data = await _load_session_data(session_id)
    if not data["flows"]:
        raise HTTPException(404, "Session has no flows")

    # Extract suspicious IPs from existing analysis
    suspicious = set()
    for s in data["analysis"].get("suspicious_ips", []):
        suspicious.add(s.get("ip", ""))

    beacons = data["analysis"].get("beacons", [])
    result = engine.analyse(data["flows"], beacons, suspicious)
    return result


@router.get("/graph-ai/{session_id}/clusters")
async def graph_clusters(session_id: str):
    """Get infrastructure clusters only."""
    result = await graph_ai_analysis(session_id)
    return {
        "clusters": result.get("infrastructure_clusters", []),
        "summary": result.get("graph_summary", {}),
    }


@router.get("/graph-ai/{session_id}/c2-map")
async def c2_infrastructure_map(session_id: str):
    """Get C2 infrastructure map."""
    result = await graph_ai_analysis(session_id)
    return result.get("c2_infrastructure", {})


# ═══════════════════════════════════════════════════════════════════════════════
# TOR DE-ANONYMIZATION ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

@router.get("/tor-deanon/{session_id}")
async def tor_deanon_analysis(session_id: str):
    """Run full Tor de-anonymization research analysis."""
    engine = _get_tor_deanon()
    data = await _load_session_data(session_id)
    if not data["flows"]:
        raise HTTPException(404, "Session has no flows")

    result = engine.analyse(data["flows"], data["packets"])
    return result


@router.get("/tor-deanon/{session_id}/timing")
async def tor_timing_correlations(session_id: str):
    """Get Tor timing correlation analysis only."""
    result = await tor_deanon_analysis(session_id)
    return {
        "timing_correlations": result.get("timing_correlations", []),
        "volume_correlations": result.get("volume_correlations", []),
    }


@router.get("/tor-deanon/{session_id}/guard-profiles")
async def tor_guard_profiles(session_id: str):
    """Get Tor guard persistence profiles."""
    result = await tor_deanon_analysis(session_id)
    return {
        "guard_profiles": result.get("guard_profiles", []),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# AUTONOMOUS THREAT HUNTING ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

@router.get("/hunt/{session_id}")
async def autonomous_hunt(session_id: str):
    """Run full autonomous threat hunting analysis."""
    hunter = _get_threat_hunter()
    data = await _load_session_data(session_id)
    if not data["flows"]:
        raise HTTPException(404, "Session has no flows")

    result = hunter.hunt(data["flows"], data["analysis"])
    return result


@router.get("/hunt/{session_id}/findings")
async def hunt_findings(session_id: str):
    """Get hunting findings only."""
    result = await autonomous_hunt(session_id)
    return {
        "findings": result.get("findings", []),
        "summary": result.get("summary", {}),
    }


@router.get("/hunt/{session_id}/chains")
async def attack_chains(session_id: str):
    """Get detected attack chains."""
    result = await autonomous_hunt(session_id)
    return {
        "attack_chains": result.get("attack_chains", []),
    }


@router.get("/hunt/{session_id}/hypotheses")
async def threat_hypotheses(session_id: str):
    """Get AI-generated threat hypotheses."""
    result = await autonomous_hunt(session_id)
    return {
        "hypotheses": result.get("hypotheses", []),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# FULL ANALYSIS ENDPOINT (runs everything)
# ═══════════════════════════════════════════════════════════════════════════════

@router.post("/full-analysis/{session_id}")
async def full_advanced_analysis(session_id: str):
    """Run ALL advanced analysis engines on a session."""
    data = await _load_session_data(session_id)
    if not data["flows"]:
        raise HTTPException(404, "Session has no flows")

    flows, packets, analysis = data["flows"], data["packets"], data["analysis"]
    suspicious = {s.get("ip", "") for s in analysis.get("suspicious_ips", [])}

    results = {}

    # 1. Fingerprinting
    try:
        engine = _get_fingerprint_engine()
        results["fingerprinting"] = engine.analyse(flows, packets)
    except Exception as e:
        logger.error("Fingerprint error: %s", e)
        results["fingerprinting"] = {"error": str(e)}

    # 2. Graph AI
    try:
        gai = _get_graph_ai()
        results["graph_ai"] = gai.analyse(flows, analysis.get("beacons", []), suspicious)
    except Exception as e:
        logger.error("Graph AI error: %s", e)
        results["graph_ai"] = {"error": str(e)}

    # 3. Tor De-anonymization
    try:
        td = _get_tor_deanon()
        results["tor_deanon"] = td.analyse(flows, packets)
    except Exception as e:
        logger.error("Tor deanon error: %s", e)
        results["tor_deanon"] = {"error": str(e)}

    # 4. Autonomous Hunting
    try:
        hunter = _get_threat_hunter()
        results["threat_hunting"] = hunter.hunt(flows, analysis)
    except Exception as e:
        logger.error("Hunting error: %s", e)
        results["threat_hunting"] = {"error": str(e)}

    # 5. Threat Intel (async)
    try:
        ti = _get_threat_intel()
        results["threat_intel"] = await ti.enrich_flows(flows)
    except Exception as e:
        logger.error("Threat intel error: %s", e)
        results["threat_intel"] = {"error": str(e)}

    return results
