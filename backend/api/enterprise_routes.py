"""
NetForensics — Enterprise API Routes v3
=========================================
New API endpoints for enterprise features:
  • /api/v3/tor          — Tor traffic monitoring
  • /api/v3/lateral      — Lateral movement detection
  • /api/v3/dns-tunnel   — DNS tunneling alerts
  • /api/v3/encrypted    — Encrypted channel analysis
  • /api/v3/baseline     — Behavioral baseline UEBA
  • /api/v3/mitre        — MITRE ATT&CK mapping
  • /api/v3/threats      — Unified threat management
  • /api/v3/alerts       — SOC alert management
  • /api/v3/intel        — Threat intelligence
  • /api/v3/ml           — ML model results
  • /api/v3/investigate  — Investigation management
  • /api/v3/extension    — Browser extension gateway
"""

import json
import logging
import time
import uuid
from typing import List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

logger = logging.getLogger("netforensics.api.v3")

router = APIRouter(prefix="/api/v3", tags=["Enterprise v3"])

# ─── Lazy-init singletons ────────────────────────────────────────────────────
_engines = {}

def _get_engine(name):
    if name not in _engines:
        if name == "tor":
            from backend.analysis.tor_detector import TorDetector
            _engines[name] = TorDetector()
        elif name == "lateral":
            from backend.analysis.lateral_movement import LateralMovementDetector
            _engines[name] = LateralMovementDetector()
        elif name == "dns_tunnel":
            from backend.analysis.dns_tunneling import DNSTunnelingDetector
            _engines[name] = DNSTunnelingDetector()
        elif name == "encrypted":
            from backend.analysis.encrypted_channel import EncryptedChannelAnalyzer
            _engines[name] = EncryptedChannelAnalyzer()
        elif name == "baseline":
            from backend.analysis.behavioral_baseline import BehavioralBaselineEngine
            _engines[name] = BehavioralBaselineEngine()
        elif name == "mitre":
            from backend.analysis.mitre_mapper import MITREMapper
            _engines[name] = MITREMapper()
        elif name == "ml_dga":
            from backend.analysis.ml_models import DGAMLDetector
            _engines[name] = DGAMLDetector()
        elif name == "ml_anomaly":
            from backend.analysis.ml_models import FlowAnomalyDetector
            _engines[name] = FlowAnomalyDetector()
        elif name == "correlator":
            from backend.correlation.threat_correlator import ThreatCorrelator
            _engines[name] = ThreatCorrelator()
        elif name == "intel":
            from backend.services.threat_intel import ThreatIntelService
            _engines[name] = ThreatIntelService()
        elif name == "alerts":
            from backend.services.alert_manager import AlertManager
            _engines[name] = AlertManager()
    return _engines[name]


# ─── Helper: load session data ───────────────────────────────────────────────
async def _load_session_data(sid: str):
    """Load flows and packets for a session from the analysis cache."""
    import aiosqlite, os
    DB_PATH = os.environ.get("NF_DB", "/tmp/netforensics.db")
    db = await aiosqlite.connect(DB_PATH)
    db.row_factory = aiosqlite.Row
    try:
        flow_rows = await db.execute_fetchall(
            "SELECT * FROM flows WHERE session_id=?", (sid,))
        pkt_rows = await db.execute_fetchall(
            "SELECT * FROM packets WHERE session_id=? LIMIT 100000", (sid,))
        flows = [dict(r) for r in flow_rows]
        packets = [dict(r) for r in pkt_rows]
        return flows, packets
    finally:
        await db.close()


async def _load_analysis(sid: str):
    """Load cached full analysis results."""
    import aiosqlite, os
    DB_PATH = os.environ.get("NF_DB", "/tmp/netforensics.db")
    db = await aiosqlite.connect(DB_PATH)
    db.row_factory = aiosqlite.Row
    try:
        rows = await db.execute_fetchall(
            "SELECT result_data FROM analysis_results "
            "WHERE session_id=? AND analysis_type='full_analysis' "
            "ORDER BY created_at DESC LIMIT 1", (sid,))
        if rows:
            return json.loads(rows[0]["result_data"])
        return {}
    finally:
        await db.close()


# ═══════════════════════════════════════════════════════════════════════════════
# TOR TRAFFIC MONITORING
# ═══════════════════════════════════════════════════════════════════════════════

@router.get("/tor/{sid}")
async def get_tor_analysis(sid: str):
    """Run Tor traffic detection on a session."""
    flows, packets = await _load_session_data(sid)
    if not flows:
        raise HTTPException(404, "Session not found or no flows")
    detector = _get_engine("tor")
    return detector.analyse(flows, packets)


@router.get("/tor/{sid}/summary")
async def get_tor_summary(sid: str):
    """Get Tor detection summary only."""
    result = await get_tor_analysis(sid)
    return {
        "summary": result.get("tor_summary", {}),
        "alert_count": len(result.get("tor_alerts", [])),
        "circuit_count": len(result.get("tor_circuits", [])),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# LATERAL MOVEMENT DETECTION
# ═══════════════════════════════════════════════════════════════════════════════

@router.get("/lateral/{sid}")
async def get_lateral_analysis(sid: str):
    """Run lateral movement detection on a session."""
    flows, packets = await _load_session_data(sid)
    detector = _get_engine("lateral")
    return detector.analyse(flows, packets)


@router.get("/lateral/{sid}/pivots")
async def get_pivot_points(sid: str):
    """Get identified pivot points."""
    result = await get_lateral_analysis(sid)
    return {"pivot_points": result.get("pivot_points", [])}


# ═══════════════════════════════════════════════════════════════════════════════
# DNS TUNNELING DETECTION
# ═══════════════════════════════════════════════════════════════════════════════

@router.get("/dns-tunnel/{sid}")
async def get_dns_tunnel_analysis(sid: str):
    """Run DNS tunneling detection on a session."""
    flows, packets = await _load_session_data(sid)
    detector = _get_engine("dns_tunnel")
    return detector.analyse(packets, flows)


# ═══════════════════════════════════════════════════════════════════════════════
# ENCRYPTED CHANNEL ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════════

@router.get("/encrypted/{sid}")
async def get_encrypted_analysis(sid: str):
    """Run encrypted channel analysis on TLS flows."""
    flows, packets = await _load_session_data(sid)
    analyzer = _get_engine("encrypted")
    return analyzer.analyse(flows, packets)


# ═══════════════════════════════════════════════════════════════════════════════
# BEHAVIORAL BASELINE (UEBA)
# ═══════════════════════════════════════════════════════════════════════════════

@router.get("/baseline/{sid}")
async def get_behavioral_analysis(sid: str):
    """Build baseline and detect behavioral deviations."""
    flows, _ = await _load_session_data(sid)
    engine = _get_engine("baseline")
    baselines = engine.build_baseline(flows)
    # Use same flows for deviation detection (in production, compare against historical)
    deviations = engine.detect_deviations(flows, baselines)
    return {
        "baselines": {ip: {"ip": b.ip, "flow_count_mean": b.flow_count_mean,
                           "bytes_mean": b.bytes_mean, "tls_ratio_mean": b.tls_ratio_mean,
                           "active_hours": b.active_hours, "sample_count": b.sample_count}
                      for ip, b in list(baselines.items())[:30]},
        "deviations": deviations,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# MITRE ATT&CK MAPPING
# ═══════════════════════════════════════════════════════════════════════════════

@router.get("/mitre/{sid}")
async def get_mitre_mapping(sid: str):
    """Map all session detections to MITRE ATT&CK."""
    analysis = await _load_analysis(sid)
    if not analysis:
        raise HTTPException(404, "No analysis results found")
    mapper = _get_engine("mitre")
    return mapper.map_analysis(analysis)


@router.get("/mitre/{sid}/navigator")
async def get_navigator_layer(sid: str):
    """Export ATT&CK Navigator JSON layer."""
    result = await get_mitre_mapping(sid)
    return result.get("navigator_layer", {})


# ═══════════════════════════════════════════════════════════════════════════════
# UNIFIED THREATS (CORRELATED)
# ═══════════════════════════════════════════════════════════════════════════════

@router.get("/threats/{sid}")
async def get_correlated_threats(sid: str):
    """Get correlated threats from all engines."""
    analysis = await _load_analysis(sid)
    if not analysis:
        raise HTTPException(404, "No analysis results found")
    correlator = _get_engine("correlator")
    return correlator.correlate(analysis)


# ═══════════════════════════════════════════════════════════════════════════════
# SOC ALERT MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════════

@router.get("/alerts")
async def list_alerts(
    severity: Optional[str] = None,
    category: Optional[str] = None,
    limit: int = Query(50, le=200),
):
    """List active SOC alerts."""
    mgr = _get_engine("alerts")
    return {"alerts": mgr.get_active_alerts(severity, category, limit)}


@router.get("/alerts/stats")
async def alert_stats():
    """Get alert statistics."""
    mgr = _get_engine("alerts")
    return mgr.get_alert_stats()


class AlertUpdate(BaseModel):
    status: str
    assignee: Optional[str] = None
    comment: Optional[str] = None


@router.patch("/alerts/{alert_id}")
async def update_alert(alert_id: str, data: AlertUpdate):
    """Update alert status/assignment."""
    mgr = _get_engine("alerts")
    alert = mgr.update_status(alert_id, data.status, data.assignee, data.comment)
    if not alert:
        raise HTTPException(404, "Alert not found")
    return {"status": "updated", "alert_id": alert_id}


# ═══════════════════════════════════════════════════════════════════════════════
# THREAT INTELLIGENCE
# ═══════════════════════════════════════════════════════════════════════════════

@router.get("/intel/lookup/{ip}")
async def intel_lookup(ip: str):
    """Lookup IP in threat intelligence."""
    svc = _get_engine("intel")
    match = svc.lookup_ip(ip)
    if not match:
        return {"ip": ip, "found": False}
    return {"ip": ip, "found": True, "threat_type": match.threat_type,
            "severity": match.severity, "source": match.source,
            "reference": match.reference, "tags": match.tags}


@router.get("/intel/match/{sid}")
async def intel_match(sid: str):
    """Match session traffic against IOC database."""
    flows, packets = await _load_session_data(sid)
    svc = _get_engine("intel")
    return svc.match_iocs(flows, packets)


@router.get("/intel/stats")
async def intel_stats():
    """Get threat intelligence statistics."""
    svc = _get_engine("intel")
    return svc.get_stats()


# ═══════════════════════════════════════════════════════════════════════════════
# ML MODELS
# ═══════════════════════════════════════════════════════════════════════════════

class DGARequest(BaseModel):
    domains: List[str]


@router.post("/ml/dga")
async def ml_dga_check(req: DGARequest):
    """Check domains against ML DGA detector."""
    detector = _get_engine("ml_dga")
    results = detector.predict_batch(req.domains)
    return {"results": [
        {"domain": r.domain, "score": r.score, "is_dga": r.is_dga,
         "family": r.family, "confidence": r.confidence,
         "features": r.features}
        for r in results
    ]}


@router.get("/ml/anomalies/{sid}")
async def ml_anomalies(sid: str, threshold: float = Query(0.65, ge=0, le=1)):
    """Detect anomalous flows using Isolation Forest."""
    flows, _ = await _load_session_data(sid)
    detector = _get_engine("ml_anomaly")
    anomalies = detector.detect(flows, threshold)
    return {"anomalies": anomalies, "total_flows": len(flows),
            "anomaly_count": len(anomalies)}


# ═══════════════════════════════════════════════════════════════════════════════
# FULL ENTERPRISE ANALYSIS (ALL ENGINES)
# ═══════════════════════════════════════════════════════════════════════════════

@router.post("/analyze/{sid}")
async def run_enterprise_analysis(sid: str):
    """Run all enterprise detection engines on a session."""
    flows, packets = await _load_session_data(sid)
    if not flows:
        raise HTTPException(404, "No session data found")

    # Run base analysis first
    from backend.analysis.traffic_analyzer import TrafficAnalyzer
    base_analyzer = TrafficAnalyzer()
    base_results = base_analyzer.analyse(flows, packets)

    # Run enterprise engines
    tor = _get_engine("tor").analyse(flows, packets)
    lateral = _get_engine("lateral").analyse(flows, packets)
    dns_tunnel = _get_engine("dns_tunnel").analyse(packets, flows)
    encrypted = _get_engine("encrypted").analyse(flows, packets)
    ml_anomalies = _get_engine("ml_anomaly").detect(flows)

    # Merge into base results
    base_results["tor_alerts"] = tor.get("tor_alerts", [])
    base_results["tor_summary"] = tor.get("tor_summary", {})
    base_results["tor_circuits"] = tor.get("tor_circuits", [])
    base_results["lateral_alerts"] = lateral.get("lateral_alerts", [])
    base_results["lateral_summary"] = lateral.get("lateral_summary", {})
    base_results["pivot_points"] = lateral.get("pivot_points", [])
    base_results["dns_tunnel_alerts"] = dns_tunnel.get("dns_tunnel_alerts", [])
    base_results["dns_tunnel_summary"] = dns_tunnel.get("dns_tunnel_summary", {})
    base_results["encrypted_alerts"] = encrypted.get("encrypted_alerts", [])
    base_results["encrypted_summary"] = encrypted.get("encrypted_summary", {})
    base_results["ml_anomalies"] = ml_anomalies

    # Correlate threats
    correlator = _get_engine("correlator")
    threat_results = correlator.correlate(base_results)
    base_results["threats"] = threat_results.get("threats", [])
    base_results["campaigns"] = threat_results.get("campaigns", [])

    # MITRE mapping
    mapper = _get_engine("mitre")
    mitre_results = mapper.map_analysis(base_results)
    base_results["mitre_mappings"] = mitre_results.get("mitre_mappings", [])
    base_results["mitre_summary"] = mitre_results.get("mitre_summary", {})

    # Create SOC alerts
    alert_mgr = _get_engine("alerts")
    alert_mgr.ingest_threats(threat_results.get("threats", []))

    # Persist results
    import aiosqlite, os
    DB_PATH = os.environ.get("NF_DB", "/tmp/netforensics.db")
    db = await aiosqlite.connect(DB_PATH)
    try:
        await db.execute(
            "INSERT INTO analysis_results(id,session_id,analysis_type,result_data,created_at)"
            " VALUES(?,?,?,?,?)",
            (str(uuid.uuid4()), sid, "enterprise_analysis",
             json.dumps(base_results, default=str),
             time.strftime("%Y-%m-%dT%H:%M:%S")))
        await db.commit()
    finally:
        await db.close()

    return {
        "status": "complete",
        "session_id": sid,
        "summary": base_results.get("summary", {}),
        "threat_count": len(threat_results.get("threats", [])),
        "tor_alerts": len(tor.get("tor_alerts", [])),
        "lateral_alerts": len(lateral.get("lateral_alerts", [])),
        "dns_tunnel_alerts": len(dns_tunnel.get("dns_tunnel_alerts", [])),
        "encrypted_alerts": len(encrypted.get("encrypted_alerts", [])),
        "ml_anomalies": len(ml_anomalies),
        "mitre_techniques": mitre_results.get("mitre_summary", {}).get("total_techniques", 0),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# BROWSER EXTENSION GATEWAY
# ═══════════════════════════════════════════════════════════════════════════════

class ExtensionPayload(BaseModel):
    agent_id: str
    events: List[dict]


@router.post("/extension/ingest")
async def extension_ingest(data: ExtensionPayload):
    """Receive metadata from browser extension."""
    # In production, validate JWT token and rate-limit
    intel = _get_engine("intel")
    flagged = []
    for event in data.events[:100]:
        domain = event.get("domain", "")
        match = intel.lookup_domain(domain)
        if match:
            flagged.append({
                "domain": domain,
                "threat_type": match.threat_type,
                "severity": match.severity,
            })
    return {
        "received": len(data.events),
        "flagged": flagged,
        "agent_id": data.agent_id,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# HEALTH & VERSION
# ═══════════════════════════════════════════════════════════════════════════════

@router.get("/health")
async def v3_health():
    return {
        "status": "ok", "version": "3.0.0",
        "engines": [
            "beacon_detector", "burst_detector", "exfil_detector",
            "dga_detector", "ttl_analyzer", "tor_detector",
            "lateral_movement", "dns_tunneling", "encrypted_channel",
            "behavioral_baseline", "mitre_mapper", "ml_dga",
            "ml_anomaly", "threat_correlator", "threat_intel",
            "alert_manager",
        ],
        "enterprise": True,
    }
