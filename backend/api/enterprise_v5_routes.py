"""
NetForensics — Enterprise API Routes v5
=========================================
Comprehensive enterprise endpoints covering all 10 requested features:

  AUTH & RBAC:
    POST /api/v5/auth/login              — JWT login
    POST /api/v5/auth/refresh            — Refresh token
    POST /api/v5/auth/api-keys           — Create API key
    GET  /api/v5/auth/api-keys           — List API keys
    DELETE /api/v5/auth/api-keys/{id}    — Revoke API key

  TENANT MANAGEMENT:
    GET  /api/v5/tenants                 — List tenants
    POST /api/v5/tenants                 — Create tenant
    GET  /api/v5/users                   — List users
    POST /api/v5/users                   — Create user
    PUT  /api/v5/users/{id}/role         — Update role

  SOC OPERATIONS:
    GET  /api/v5/soc/alerts              — Query alerts
    POST /api/v5/soc/alerts              — Create alert
    PUT  /api/v5/soc/alerts/{id}/status  — Update alert status
    PUT  /api/v5/soc/alerts/{id}/assign  — Assign alert
    POST /api/v5/soc/alerts/{id}/comment — Add comment
    GET  /api/v5/soc/metrics             — SOC dashboard metrics
    GET  /api/v5/soc/correlations        — Alert correlations

  THREAT INTELLIGENCE:
    GET  /api/v5/geoip/{ip}              — GeoIP lookup
    POST /api/v5/geoip/batch             — Batch GeoIP
    GET  /api/v5/infra/map               — Infrastructure correlation map
    GET  /api/v5/infra/node/{ip}         — Node detail

  STIX/TAXII:
    GET  /api/v5/taxii/discovery         — TAXII discovery
    GET  /api/v5/taxii/collections       — List collections
    GET  /api/v5/taxii/collections/{id}  — Collection detail
    GET  /api/v5/taxii/collections/{id}/objects  — Get STIX objects
    POST /api/v5/taxii/collections/{id}/objects  — Add STIX objects
    POST /api/v5/stix/bundle             — Create STIX bundle from threats

  SIEM INTEGRATION:
    POST /api/v5/siem/export             — Export alerts (CEF/LEEF/Splunk/Elastic)
    GET  /api/v5/siem/webhook/test       — Test SIEM webhook

  REPORTS:
    POST /api/v5/reports/generate/{sid}  — Generate investigation report
    GET  /api/v5/reports/{report_id}     — Get report

  MITRE ATT&CK:
    GET  /api/v5/mitre/matrix            — Full ATT&CK coverage matrix
    GET  /api/v5/mitre/technique/{tid}   — Technique detail + detections

  AUDIT:
    GET  /api/v5/audit/log               — Query audit log

  COMPLIANCE:
    GET  /api/v5/compliance/status       — Compliance dashboard
"""

import json
import logging
import time
import uuid
from typing import Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query, Request
from pydantic import BaseModel

logger = logging.getLogger("netforensics.api.v5")

router = APIRouter(prefix="/api/v5", tags=["Enterprise v5"])


# ─── Lazy singletons ─────────────────────────────────────────────────────────

def _rbac():
    from backend.enterprise.multi_tenant_rbac import get_rbac_manager
    return get_rbac_manager()

def _soc():
    from backend.enterprise.soc_engine import get_soc_engine
    return get_soc_engine()

def _geoip():
    from backend.enterprise.threat_intel_platform import get_geoip
    return get_geoip()

def _taxii():
    from backend.enterprise.threat_intel_platform import get_taxii
    return get_taxii()

def _correlator():
    from backend.enterprise.threat_intel_platform import get_correlator
    return get_correlator()

def _reporter():
    from backend.enterprise.threat_intel_platform import get_reporter
    return get_reporter()

def _siem():
    from backend.enterprise.threat_intel_platform import SIEMExporter
    return SIEMExporter


# ─── Helpers ──────────────────────────────────────────────────────────────────

async def _get_context(request: Request):
    """Extract tenant context from Authorization header."""
    mgr = _rbac()
    auth = request.headers.get("Authorization", "")
    ip = request.client.host if request.client else "0.0.0.0"

    if auth.startswith("Bearer "):
        token = auth[7:]
        ctx = mgr.resolve_context(token=token, ip_address=ip)
        if ctx:
            return ctx

    if auth.startswith("ApiKey "):
        key = auth[7:]
        ctx = mgr.resolve_context(api_key=key, ip_address=ip)
        if ctx:
            return ctx

    # Dev mode: return default context
    tenants = list(mgr.tenants.values())
    users = list(mgr.users.values())
    if tenants and users:
        from backend.enterprise.multi_tenant_rbac import TenantContext
        return TenantContext(tenant=tenants[0], user=users[0], ip_address=ip)

    raise HTTPException(401, "Authentication required")


async def _load_session_data(sid: str):
    import aiosqlite, os
    DB_PATH = os.environ.get("NF_DB", "/tmp/netforensics.db")
    db = await aiosqlite.connect(DB_PATH)
    db.row_factory = aiosqlite.Row
    try:
        flow_rows = await db.execute_fetchall(
            "SELECT * FROM flows WHERE session_id=?", (sid,))
        pkt_rows = await db.execute_fetchall(
            "SELECT * FROM packets WHERE session_id=? LIMIT 100000", (sid,))
        return [dict(r) for r in flow_rows], [dict(r) for r in pkt_rows]
    finally:
        await db.close()


async def _load_analysis(sid: str):
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
# 1. AUTHENTICATION & RBAC
# ═══════════════════════════════════════════════════════════════════════════════

class LoginRequest(BaseModel):
    username: str
    password: str

class CreateAPIKeyRequest(BaseModel):
    name: str = ""
    permissions: List[str] = ["sessions:read", "alerts:read"]
    rate_limit: int = 1000
    ttl_days: int = 365


@router.post("/auth/login")
async def login(req: LoginRequest, request: Request):
    """Authenticate and receive JWT access + refresh tokens."""
    mgr = _rbac()
    result = mgr.authenticate(req.username, req.password)
    if not result:
        raise HTTPException(401, "Invalid credentials or account locked")

    ip = request.client.host if request.client else "0.0.0.0"
    from backend.enterprise.multi_tenant_rbac import TenantContext, Tenant, User
    ctx = TenantContext(ip_address=ip)
    mgr.audit.log(ctx, "login", "auth", result["user"]["id"],
                   {"username": req.username})
    return result


@router.post("/auth/refresh")
async def refresh_token(request: Request):
    """Refresh an expired access token using a valid refresh token."""
    mgr = _rbac()
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(401, "Refresh token required")

    payload = mgr.jwt.decode_token(auth[7:])
    if not payload or payload.get("type") != "refresh":
        raise HTTPException(401, "Invalid or expired refresh token")

    user = mgr.get_user(payload["sub"])
    tenant = mgr.get_tenant(payload["tid"])
    if not user or not tenant:
        raise HTTPException(401, "User or tenant not found")

    return {
        "access_token": mgr.jwt.create_access_token(user, tenant),
        "token_type": "bearer",
        "expires_in": mgr.jwt.access_ttl,
    }


@router.post("/auth/api-keys")
async def create_api_key(req: CreateAPIKeyRequest, request: Request):
    """Create a new API key for the authenticated user."""
    ctx = await _get_context(request)
    ctx.require_permission("config:write")
    mgr = _rbac()
    full_key, ak = mgr.create_api_key(
        ctx.user_id, name=req.name,
        permissions=req.permissions,
        rate_limit=req.rate_limit,
        ttl_days=req.ttl_days)
    mgr.audit.log(ctx, "create", "api_key", ak.id)
    return {
        "api_key": full_key,
        "key_id": ak.id,
        "prefix": ak.key_prefix,
        "name": ak.name,
        "permissions": ak.permissions,
        "expires_at": ak.expires_at,
        "warning": "Store this key securely. It will not be shown again.",
    }


@router.get("/auth/api-keys")
async def list_api_keys(request: Request):
    """List API keys for the authenticated user."""
    ctx = await _get_context(request)
    mgr = _rbac()
    return {"api_keys": mgr.list_api_keys(ctx.user_id)}


@router.delete("/auth/api-keys/{key_id}")
async def revoke_api_key(key_id: str, request: Request):
    """Revoke an API key."""
    ctx = await _get_context(request)
    ctx.require_permission("config:write")
    mgr = _rbac()
    if mgr.revoke_api_key(key_id):
        mgr.audit.log(ctx, "delete", "api_key", key_id)
        return {"status": "revoked", "key_id": key_id}
    raise HTTPException(404, "API key not found")


# ═══════════════════════════════════════════════════════════════════════════════
# 2. TENANT & USER MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════════

class CreateTenantRequest(BaseModel):
    name: str
    plan: str = "enterprise"
    max_users: int = 100

class CreateUserRequest(BaseModel):
    username: str
    password: str
    email: str = ""
    role: str = "soc_analyst"
    display_name: str = ""

class UpdateRoleRequest(BaseModel):
    role: str


@router.get("/tenants")
async def list_tenants(request: Request):
    """List all tenants (platform_admin only)."""
    ctx = await _get_context(request)
    ctx.require_permission("config:read")
    return {"tenants": _rbac().list_tenants()}


@router.post("/tenants")
async def create_tenant(req: CreateTenantRequest, request: Request):
    """Create a new tenant organization."""
    ctx = await _get_context(request)
    ctx.require_permission("config:write")
    mgr = _rbac()
    tenant = mgr.create_tenant(req.name, req.plan, req.max_users)
    mgr.audit.log(ctx, "create", "tenant", tenant.id,
                   {"name": req.name, "plan": req.plan})
    return {"tenant_id": tenant.id, "name": tenant.name, "slug": tenant.slug}


@router.get("/users")
async def list_users(request: Request, tenant_id: str = Query("")):
    """List users (filtered by tenant if specified)."""
    ctx = await _get_context(request)
    ctx.require_permission("users:read")
    tid = tenant_id or ctx.tenant_id
    return {"users": _rbac().list_users(tid)}


@router.post("/users")
async def create_user(req: CreateUserRequest, request: Request):
    """Create a new user in the current tenant."""
    ctx = await _get_context(request)
    ctx.require_permission("users:write")
    mgr = _rbac()
    try:
        user = mgr.create_user(
            ctx.tenant_id, req.username, req.password,
            req.email, req.role, req.display_name)
        mgr.audit.log(ctx, "create", "user", user.id,
                       {"username": req.username, "role": req.role})
        return {"user_id": user.id, "username": user.username, "role": user.role}
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.put("/users/{user_id}/role")
async def update_user_role(user_id: str, req: UpdateRoleRequest, request: Request):
    """Update a user's role."""
    ctx = await _get_context(request)
    ctx.require_permission("users:write")
    mgr = _rbac()
    try:
        user = mgr.update_user_role(user_id, req.role)
        mgr.audit.log(ctx, "update", "user", user_id,
                       {"new_role": req.role})
        return {"user_id": user_id, "new_role": req.role}
    except ValueError as e:
        raise HTTPException(400, str(e))


# ═══════════════════════════════════════════════════════════════════════════════
# 3. SOC ALERT MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════════

class CreateAlertRequest(BaseModel):
    title: str
    description: str = ""
    severity: str = "MEDIUM"
    category: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    threat_score: float = 0.5
    mitre_technique: str = ""
    session_id: str = ""
    evidence: List[Dict] = []

class UpdateStatusRequest(BaseModel):
    status: str
    comment: str = ""

class AssignAlertRequest(BaseModel):
    assignee: str
    assignee_id: str = ""

class CommentRequest(BaseModel):
    comment: str


@router.get("/soc/alerts")
async def soc_query_alerts(
    request: Request,
    status: str = Query(""),
    severity: str = Query(""),
    category: str = Query(""),
    assignee: str = Query(""),
    min_score: float = Query(0.0),
    session_id: str = Query(""),
    tag: str = Query(""),
    sort_by: str = Query("created_at"),
    limit: int = Query(100, le=500),
):
    """Query SOC alerts with filtering, sorting, and SLA checks."""
    ctx = await _get_context(request)
    ctx.require_permission("alerts:read")
    soc = _soc()
    results = soc.query_alerts(
        tenant_id=ctx.tenant_id, status=status, severity=severity,
        category=category, assignee=assignee, min_score=min_score,
        session_id=session_id, tag=tag, sort_by=sort_by, limit=limit)
    return {"alerts": results, "total": len(results)}


@router.post("/soc/alerts")
async def soc_create_alert(req: CreateAlertRequest, request: Request):
    """Manually create a SOC alert."""
    ctx = await _get_context(request)
    ctx.require_permission("alerts:write")
    soc = _soc()
    alert = soc.ingest_alert(req.dict(), ctx.tenant_id)
    _rbac().audit.log(ctx, "create", "alert", alert.id,
                       {"title": req.title, "severity": req.severity})
    return {"alert_id": alert.alert_id, "id": alert.id, "status": alert.status}


@router.put("/soc/alerts/{alert_id}/status")
async def soc_update_status(alert_id: str, req: UpdateStatusRequest,
                              request: Request):
    """Update alert lifecycle status."""
    ctx = await _get_context(request)
    ctx.require_permission("alerts:write")
    soc = _soc()
    alert = soc.update_status(alert_id, req.status,
                                user=ctx.user.username if ctx.user else "",
                                comment=req.comment)
    if not alert:
        raise HTTPException(404, "Alert not found or invalid transition")
    _rbac().audit.log(ctx, "update", "alert", alert_id,
                       {"new_status": req.status})
    return {"alert_id": alert.alert_id, "status": alert.status}


@router.put("/soc/alerts/{alert_id}/assign")
async def soc_assign_alert(alert_id: str, req: AssignAlertRequest,
                             request: Request):
    """Assign alert to an analyst."""
    ctx = await _get_context(request)
    ctx.require_permission("alerts:assign")
    soc = _soc()
    alert = soc.assign_alert(alert_id, req.assignee, req.assignee_id)
    if not alert:
        raise HTTPException(404, "Alert not found")
    return {"alert_id": alert.alert_id, "assignee": alert.assignee}


@router.post("/soc/alerts/{alert_id}/comment")
async def soc_add_comment(alert_id: str, req: CommentRequest,
                            request: Request):
    """Add analyst comment to an alert."""
    ctx = await _get_context(request)
    ctx.require_permission("alerts:write")
    soc = _soc()
    author = ctx.user.username if ctx.user else "api"
    alert = soc.add_comment(alert_id, author, req.comment)
    if not alert:
        raise HTTPException(404, "Alert not found")
    return {"alert_id": alert.alert_id, "comment_count": len(alert.comments)}


@router.get("/soc/metrics")
async def soc_metrics(request: Request):
    """SOC dashboard: MTTD, MTTR, SLA compliance, workload distribution."""
    ctx = await _get_context(request)
    ctx.require_permission("alerts:read")
    return _soc().get_metrics(ctx.tenant_id)


@router.get("/soc/correlations")
async def soc_correlations(request: Request):
    """Find correlated alert clusters."""
    ctx = await _get_context(request)
    ctx.require_permission("alerts:read")
    return {"correlations": _soc().correlate_alerts()}


# ═══════════════════════════════════════════════════════════════════════════════
# 4. GEOIP MAPPING
# ═══════════════════════════════════════════════════════════════════════════════

class GeoIPBatchRequest(BaseModel):
    ips: List[str]


@router.get("/geoip/{ip}")
async def geoip_lookup(ip: str, request: Request):
    """GeoIP lookup: country, ASN, org, risk score, threat tags."""
    await _get_context(request)
    return _geoip().lookup(ip)


@router.post("/geoip/batch")
async def geoip_batch(req: GeoIPBatchRequest, request: Request):
    """Batch GeoIP lookup (max 500 IPs)."""
    await _get_context(request)
    results = _geoip().lookup_batch(req.ips[:500])
    countries = {}
    for r in results:
        c = r["country"]
        countries[c] = countries.get(c, 0) + 1
    return {
        "results": results,
        "total": len(results),
        "country_distribution": countries,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# 5. ATTACKER INFRASTRUCTURE CORRELATION
# ═══════════════════════════════════════════════════════════════════════════════

@router.get("/infra/map")
async def infra_map(request: Request):
    """Get full attacker infrastructure correlation map."""
    ctx = await _get_context(request)
    ctx.require_permission("intel:read")
    return _correlator().get_infrastructure_map()


@router.get("/infra/node/{ip}")
async def infra_node(ip: str, request: Request):
    """Get detailed info for a specific infrastructure node."""
    ctx = await _get_context(request)
    ctx.require_permission("intel:read")
    result = _correlator().get_node_detail(ip)
    if not result:
        raise HTTPException(404, "Node not found in infrastructure map")
    return result


@router.post("/infra/ingest/{sid}")
async def infra_ingest(sid: str, request: Request):
    """Ingest threats from a session into the infrastructure correlator."""
    ctx = await _get_context(request)
    ctx.require_permission("intel:write")
    analysis = await _load_analysis(sid)
    if not analysis:
        raise HTTPException(404, "No analysis found for session")

    threats = analysis.get("threats", []) + analysis.get("ml_threats", [])
    corr = _correlator()
    corr.ingest_threats_batch(threats, sid)

    return {
        "ingested_threats": len(threats),
        "total_nodes": len(corr.nodes),
        "total_campaigns": len(corr.campaigns),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# 6. STIX/TAXII THREAT SHARING
# ═══════════════════════════════════════════════════════════════════════════════

@router.get("/taxii/discovery")
async def taxii_discovery():
    """TAXII 2.1 discovery endpoint."""
    return _taxii().get_discovery()


@router.get("/taxii/collections")
async def taxii_collections(request: Request):
    """List all TAXII collections."""
    await _get_context(request)
    return _taxii().list_collections()


@router.get("/taxii/collections/{collection_id}")
async def taxii_collection_detail(collection_id: str, request: Request):
    """Get TAXII collection details."""
    await _get_context(request)
    result = _taxii().get_collection(collection_id)
    if not result:
        raise HTTPException(404, "Collection not found")
    return result


@router.get("/taxii/collections/{collection_id}/objects")
async def taxii_get_objects(
    collection_id: str,
    request: Request,
    limit: int = Query(100, le=1000),
    added_after: str = Query(""),
    match_type: str = Query(""),
):
    """Get STIX objects from a TAXII collection."""
    await _get_context(request)
    return _taxii().get_objects(collection_id, limit, added_after, match_type)


@router.post("/taxii/collections/{collection_id}/objects")
async def taxii_add_objects(collection_id: str, request: Request):
    """Add STIX bundle to a TAXII collection."""
    ctx = await _get_context(request)
    ctx.require_permission("intel:write")
    body = await request.json()
    result = _taxii().add_objects(collection_id, body)
    _rbac().audit.log(ctx, "create", "stix_objects", collection_id)
    return result


@router.get("/taxii/collections/{collection_id}/manifest")
async def taxii_manifest(collection_id: str, request: Request):
    """Get TAXII collection manifest."""
    await _get_context(request)
    return _taxii().get_manifest(collection_id)


class STIXBundleRequest(BaseModel):
    session_id: str
    include_ml: bool = True


@router.post("/stix/bundle")
async def create_stix_bundle(req: STIXBundleRequest, request: Request):
    """Generate STIX 2.1 bundle from session analysis threats."""
    ctx = await _get_context(request)
    ctx.require_permission("intel:read")
    analysis = await _load_analysis(req.session_id)
    if not analysis:
        raise HTTPException(404, "No analysis found for session")

    from backend.enterprise.threat_intel_platform import STIXFactory
    stix_objects = []

    threats = analysis.get("threats", [])
    if req.include_ml:
        threats += analysis.get("ml_threats", [])

    taxii = _taxii()
    for threat in threats:
        taxii.publish_detection(threat)

    # Build bundle manually for response
    for t in threats[:100]:
        mitre = t.get("mitre_technique", "")
        if mitre:
            ap = STIXFactory.create_attack_pattern(
                mitre, t.get("threat_type", "unknown"),
                t.get("description", ""))
            stix_objects.append(ap)

        for ev in t.get("evidence", []):
            import re
            for ip in re.findall(r"\b\d+\.\d+\.\d+\.\d+\b", str(ev)):
                ind = STIXFactory.ip_indicator(
                    ip, t.get("threat_type", ""), int(t.get("score", 0.5) * 100))
                stix_objects.append(ind)

    bundle = STIXFactory.create_bundle(stix_objects)
    return {
        "bundle": bundle,
        "object_count": len(bundle["objects"]),
        "source_threats": len(threats),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# 7. SIEM INTEGRATION
# ═══════════════════════════════════════════════════════════════════════════════

class SIEMExportRequest(BaseModel):
    format: str = "cef"       # cef, leef, splunk, elastic, syslog
    session_id: str = ""
    severity_filter: str = ""
    limit: int = 500

class SIEMWebhookTest(BaseModel):
    url: str
    format: str = "json"


@router.post("/siem/export")
async def siem_export(req: SIEMExportRequest, request: Request):
    """Export alerts in SIEM-compatible format (CEF, LEEF, Splunk HEC, Elastic, Syslog)."""
    ctx = await _get_context(request)
    ctx.require_permission("siem:read")

    soc = _soc()
    alerts = soc.query_alerts(
        tenant_id=ctx.tenant_id,
        severity=req.severity_filter,
        session_id=req.session_id,
        limit=req.limit)

    Exporter = _siem()

    if req.format == "splunk":
        exported = [Exporter.to_splunk_hec(a) for a in alerts]
    elif req.format == "elastic":
        exported = [Exporter.to_elastic(a) for a in alerts]
    elif req.format in ("cef", "leef", "syslog"):
        exported = Exporter.export_batch(alerts, req.format)
    else:
        exported = [json.dumps(a) for a in alerts]

    _rbac().audit.log(ctx, "export", "siem", "",
                       {"format": req.format, "count": len(exported)})
    return {
        "format": req.format,
        "exported_count": len(exported),
        "data": exported[:200],
    }


@router.get("/siem/formats")
async def siem_formats():
    """List supported SIEM export formats."""
    return {
        "formats": [
            {"id": "cef", "name": "Common Event Format (CEF)",
             "targets": ["ArcSight", "QRadar", "LogRhythm"]},
            {"id": "leef", "name": "Log Event Extended Format (LEEF)",
             "targets": ["IBM QRadar"]},
            {"id": "splunk", "name": "Splunk HTTP Event Collector (HEC)",
             "targets": ["Splunk Enterprise", "Splunk Cloud"]},
            {"id": "elastic", "name": "Elasticsearch Document",
             "targets": ["Elastic SIEM", "OpenSearch"]},
            {"id": "syslog", "name": "RFC 5424 Syslog",
             "targets": ["Any Syslog receiver"]},
            {"id": "json", "name": "Generic JSON",
             "targets": ["Custom SIEM", "Data lakes"]},
        ],
    }


# ═══════════════════════════════════════════════════════════════════════════════
# 8. AUTOMATED INVESTIGATION REPORTS
# ═══════════════════════════════════════════════════════════════════════════════

_reports: Dict[str, Dict] = {}


@router.post("/reports/generate/{sid}")
async def generate_report(sid: str, request: Request):
    """Generate a comprehensive automated investigation report."""
    ctx = await _get_context(request)
    ctx.require_permission("reports:generate")

    analysis = await _load_analysis(sid)
    if not analysis:
        raise HTTPException(404, "No analysis found for session")

    ml_threats = analysis.get("ml_threats", [])
    infra_map = _correlator().get_infrastructure_map()
    tenant_name = ctx.tenant.name if ctx.tenant else "Default"

    reporter = _reporter()
    report = reporter.generate_report(
        session_id=sid,
        analysis=analysis,
        ml_threats=ml_threats,
        infra_map=infra_map,
        tenant_name=tenant_name)

    _reports[report["report_id"]] = report
    _rbac().audit.log(ctx, "create", "report", report["report_id"],
                       {"session_id": sid})
    return report


@router.get("/reports/{report_id}")
async def get_report(report_id: str, request: Request):
    """Retrieve a previously generated report."""
    ctx = await _get_context(request)
    ctx.require_permission("reports:read")
    report = _reports.get(report_id)
    if not report:
        raise HTTPException(404, "Report not found")
    return report


@router.get("/reports")
async def list_reports(request: Request):
    """List all generated reports."""
    ctx = await _get_context(request)
    ctx.require_permission("reports:read")
    return {
        "reports": [
            {
                "report_id": r["report_id"],
                "session_id": r["session_id"],
                "generated_at": r["generated_at"],
                "classification": r["classification"],
                "risk_level": r["threat_overview"]["risk_level"],
                "total_threats": r["threat_overview"]["total_threats"],
            }
            for r in _reports.values()
        ],
        "total": len(_reports),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# 9. MITRE ATT&CK MAPPING
# ═══════════════════════════════════════════════════════════════════════════════

# Comprehensive MITRE ATT&CK coverage matrix
_MITRE_COVERAGE = {
    "T1071": {"name": "Application Layer Protocol", "tactic": "Command and Control",
              "subtechniques": ["T1071.001", "T1071.004"],
              "detectors": ["BeaconMLDetector", "AbnormalFlowDetector"],
              "coverage": "high"},
    "T1071.001": {"name": "Web Protocols", "tactic": "Command and Control",
                   "detectors": ["BeaconMLDetector"], "coverage": "high"},
    "T1071.004": {"name": "DNS", "tactic": "Command and Control",
                   "detectors": ["DNSTunnelingDetector"], "coverage": "high"},
    "T1090": {"name": "Proxy", "tactic": "Command and Control",
              "subtechniques": ["T1090.003"],
              "detectors": ["TorC2Detector", "TorAnalyzer"], "coverage": "high"},
    "T1090.003": {"name": "Multi-hop Proxy", "tactic": "Command and Control",
                   "detectors": ["TorC2Detector", "TorAnalyzer"], "coverage": "high"},
    "T1573": {"name": "Encrypted Channel", "tactic": "Command and Control",
              "subtechniques": ["T1573.001", "T1573.002"],
              "detectors": ["EncryptedSessionDetector", "EncryptedChannelAnalyzer"],
              "coverage": "high"},
    "T1573.002": {"name": "Asymmetric Cryptography", "tactic": "Command and Control",
                   "detectors": ["EncryptedSessionDetector"], "coverage": "high"},
    "T1021": {"name": "Remote Services", "tactic": "Lateral Movement",
              "subtechniques": ["T1021.001", "T1021.002", "T1021.006"],
              "detectors": ["LateralMovementMLDetector", "LateralMovementDetector"],
              "coverage": "high"},
    "T1021.001": {"name": "Remote Desktop Protocol", "tactic": "Lateral Movement",
                   "detectors": ["LateralMovementMLDetector"], "coverage": "medium"},
    "T1021.002": {"name": "SMB/Windows Admin Shares", "tactic": "Lateral Movement",
                   "detectors": ["LateralMovementMLDetector"], "coverage": "high"},
    "T1021.006": {"name": "Windows Remote Management", "tactic": "Lateral Movement",
                   "detectors": ["LateralMovementMLDetector"], "coverage": "medium"},
    "T1568": {"name": "Dynamic Resolution", "tactic": "Command and Control",
              "subtechniques": ["T1568.002"],
              "detectors": ["DGAMLDetector"], "coverage": "high"},
    "T1568.002": {"name": "Domain Generation Algorithms", "tactic": "Command and Control",
                   "detectors": ["DGAMLDetector"], "coverage": "high"},
    "T1048": {"name": "Exfiltration Over Alternative Protocol",
              "tactic": "Exfiltration",
              "detectors": ["DNSTunnelingDetector", "AbnormalFlowDetector"],
              "coverage": "medium"},
    "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration",
              "detectors": ["BeaconMLDetector"], "coverage": "medium"},
    "T1040": {"name": "Network Sniffing", "tactic": "Credential Access",
              "detectors": ["BehavioralBaselineEngine"], "coverage": "low"},
    "T1046": {"name": "Network Service Discovery", "tactic": "Discovery",
              "detectors": ["LateralMovementDetector"], "coverage": "medium"},
    "T1018": {"name": "Remote System Discovery", "tactic": "Discovery",
              "detectors": ["LateralMovementMLDetector"], "coverage": "medium"},
    "T1082": {"name": "System Information Discovery", "tactic": "Discovery",
              "detectors": ["BehavioralBaselineEngine"], "coverage": "low"},
    "T1205": {"name": "Traffic Signaling", "tactic": "Defense Evasion",
              "detectors": ["BeaconMLDetector"], "coverage": "medium"},
}


@router.get("/mitre/matrix")
async def mitre_matrix(request: Request):
    """Full MITRE ATT&CK coverage matrix showing detected techniques."""
    await _get_context(request)

    # Group by tactic
    tactics = {}
    for tid, info in _MITRE_COVERAGE.items():
        tactic = info.get("tactic", "Unknown")
        if tactic not in tactics:
            tactics[tactic] = []
        tactics[tactic].append({
            "technique_id": tid,
            "name": info["name"],
            "coverage": info.get("coverage", "low"),
            "detectors": info.get("detectors", []),
        })

    coverage_stats = {
        "total_techniques": len(_MITRE_COVERAGE),
        "high_coverage": sum(1 for v in _MITRE_COVERAGE.values()
                              if v.get("coverage") == "high"),
        "medium_coverage": sum(1 for v in _MITRE_COVERAGE.values()
                                if v.get("coverage") == "medium"),
        "low_coverage": sum(1 for v in _MITRE_COVERAGE.values()
                             if v.get("coverage") == "low"),
    }

    return {
        "framework": "MITRE ATT&CK v14",
        "tactics": tactics,
        "coverage_stats": coverage_stats,
        "total_detectors": 12,
    }


@router.get("/mitre/technique/{technique_id}")
async def mitre_technique(technique_id: str, request: Request):
    """Get detailed MITRE technique info with NetForensics coverage."""
    await _get_context(request)
    info = _MITRE_COVERAGE.get(technique_id)
    if not info:
        raise HTTPException(404, f"Technique {technique_id} not mapped")
    return {
        "technique_id": technique_id,
        **info,
        "url": f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/",
    }


# ═══════════════════════════════════════════════════════════════════════════════
# 10. AUDIT LOG
# ═══════════════════════════════════════════════════════════════════════════════

@router.get("/audit/log")
async def audit_log(
    request: Request,
    user_id: str = Query(""),
    action: str = Query(""),
    resource_type: str = Query(""),
    since: str = Query(""),
    limit: int = Query(100, le=1000),
):
    """Query the audit log (tenant_admin+ required)."""
    ctx = await _get_context(request)
    ctx.require_permission("audit:read")
    mgr = _rbac()
    entries = mgr.audit.query(
        tenant_id=ctx.tenant_id, user_id=user_id,
        action=action, resource_type=resource_type,
        since=since, limit=limit)
    return {"entries": entries, "total": len(entries)}


# ═══════════════════════════════════════════════════════════════════════════════
# 11. COMPLIANCE DASHBOARD
# ═══════════════════════════════════════════════════════════════════════════════

@router.get("/compliance/status")
async def compliance_status(request: Request):
    """Compliance readiness dashboard across multiple frameworks."""
    ctx = await _get_context(request)
    ctx.require_permission("config:read")

    soc = _soc()
    metrics = soc.get_metrics(ctx.tenant_id)
    mgr = _rbac()

    users = mgr.list_users(ctx.tenant_id)
    mfa_enabled = sum(1 for u in users if u.get("mfa_enabled"))
    active_users = sum(1 for u in users if u.get("active"))

    return {
        "frameworks": {
            "NIST_CSF": {
                "status": "partial",
                "controls": {
                    "ID.AM": {"status": "implemented", "detail": "Asset identification via flow analysis"},
                    "DE.CM": {"status": "implemented", "detail": "Continuous monitoring via ML + heuristic engines"},
                    "DE.AE": {"status": "implemented", "detail": "Anomaly detection (5 ML engines + behavioral baseline)"},
                    "RS.MI": {"status": "implemented", "detail": "SOC alert management with SLA tracking"},
                    "RS.AN": {"status": "implemented", "detail": "Automated investigation reports"},
                    "PR.AC": {"status": "implemented", "detail": "RBAC with 6 roles, JWT + API key auth"},
                    "PR.DS": {"status": "partial", "detail": "TLS analysis; encryption at rest pending"},
                },
            },
            "ISO_27001": {
                "status": "partial",
                "controls": {
                    "A.8.15": {"status": "implemented", "detail": "Activity logging / audit trail"},
                    "A.8.16": {"status": "implemented", "detail": "Network traffic monitoring"},
                    "A.5.7": {"status": "implemented", "detail": "Threat intelligence integration (STIX/TAXII)"},
                    "A.8.8": {"status": "implemented", "detail": "Vulnerability detection / JA3 analysis"},
                    "A.5.23": {"status": "partial", "detail": "Multi-tenant isolation; network level pending"},
                },
            },
            "SOC2_TypeII": {
                "status": "partial",
                "controls": {
                    "CC6.1": {"status": "implemented", "detail": "Logical access controls (RBAC)"},
                    "CC6.8": {"status": "implemented", "detail": "Intrusion detection (ML + heuristic)"},
                    "CC7.2": {"status": "implemented", "detail": "Incident monitoring and response"},
                    "CC7.3": {"status": "implemented", "detail": "Evaluation of detected threats"},
                },
            },
            "PCI_DSS": {
                "status": "partial",
                "controls": {
                    "10.6": {"status": "implemented", "detail": "Review logs and security events"},
                    "11.4": {"status": "implemented", "detail": "IDS/IPS — network-based threat detection"},
                    "11.5": {"status": "partial", "detail": "Change detection capabilities"},
                },
            },
            "GDPR": {
                "status": "partial",
                "controls": {
                    "Art.32": {"status": "implemented", "detail": "Security of processing — monitoring"},
                    "Art.33": {"status": "implemented", "detail": "Breach notification support via alerts"},
                    "Art.35": {"status": "partial", "detail": "DPIA support via investigation reports"},
                },
            },
        },
        "security_posture": {
            "mfa_adoption": f"{mfa_enabled}/{active_users} users",
            "rbac_configured": True,
            "audit_logging": True,
            "threat_intel_feeds": len(_taxii().collections),
            "ml_models_active": 5,
            "sla_compliance_rate": metrics.get("sla_compliance", {}).get("rate", 0),
            "open_critical_alerts": metrics.get("severity_distribution", {}).get("CRITICAL", 0),
        },
    }


# ═══════════════════════════════════════════════════════════════════════════════
# ENTERPRISE HEALTH
# ═══════════════════════════════════════════════════════════════════════════════

@router.get("/health")
async def enterprise_health():
    """Enterprise platform health check."""
    mgr = _rbac()
    soc = _soc()

    return {
        "status": "operational",
        "version": "5.0.0",
        "platform": "NetForensics Enterprise",
        "modules": {
            "multi_tenant_rbac": "active",
            "soc_engine": f"active ({len(soc.alerts)} alerts)",
            "geoip": "active",
            "stix_taxii": f"active ({len(_taxii().collections)} collections)",
            "siem_export": "active (CEF/LEEF/Splunk/Elastic/Syslog)",
            "infra_correlator": f"active ({len(_correlator().nodes)} nodes)",
            "ml_pipeline": "active (5 engines)",
            "report_generator": "active",
            "mitre_attack": f"active ({len(_MITRE_COVERAGE)} techniques)",
            "compliance": "active (NIST/ISO/SOC2/PCI/GDPR)",
            "audit_log": f"active ({len(mgr.audit._entries)} entries)",
        },
        "tenants": len(mgr.tenants),
        "users": len(mgr.users),
        "api_keys": len(mgr.api_keys),
        "capabilities": [
            "Multi-Tenant Architecture",
            "Role-Based Access Control (6 roles)",
            "SOC Alert Management with SLA",
            "Threat Intelligence (STIX/TAXII 2.1)",
            "MITRE ATT&CK Mapping (20 techniques)",
            "Automated Investigation Reports",
            "SIEM Integration (5 formats)",
            "GeoIP Mapping",
            "Attacker Infrastructure Correlation",
            "ML Threat Detection (5 engines)",
            "Compliance Dashboard (5 frameworks)",
            "Comprehensive Audit Logging",
        ],
    }
