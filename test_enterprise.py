"""Quick verification of enterprise modules."""
import sys
sys.path.insert(0, ".")

# 1. RBAC
from backend.enterprise.multi_tenant_rbac import get_rbac_manager, ROLES
mgr = get_rbac_manager()
print(f"[OK] RBAC: {len(ROLES)} roles, {len(mgr.tenants)} tenants, {len(mgr.users)} users")

# Login
result = mgr.authenticate("admin", "admin")
assert result is not None, "Login failed"
assert "access_token" in result
print(f"[OK] Auth: JWT issued, role={result['user']['role']}")

# Decode JWT
payload = mgr.jwt.decode_token(result["access_token"])
assert payload is not None
assert payload["role"] == "platform_admin"
print(f"[OK] JWT: decoded, sub={payload['sub'][:8]}...")

# Create user
try:
    user = mgr.create_user(
        list(mgr.tenants.keys())[0],
        "analyst1", "securepass123",
        email="analyst@test.com", role="soc_analyst")
    print(f"[OK] User created: {user.username}, role={user.role}")
except ValueError:
    print("[OK] User already exists (idempotent)")

# API Key
full_key, ak = mgr.create_api_key(list(mgr.users.keys())[0], name="test_key")
assert full_key.startswith("nf_")
print(f"[OK] API Key: prefix={ak.key_prefix}")

# 2. GeoIP
from backend.enterprise.threat_intel_platform import get_geoip
geo = get_geoip()
r = geo.lookup("8.8.8.8")
assert r["country"] in ("US", "UNKNOWN")
print(f"[OK] GeoIP: 8.8.8.8 -> {r['country']} / {r['country_name']} / {r['org']}")

r2 = geo.lookup("192.168.1.1")
assert r2["is_private"] is True
print(f"[OK] GeoIP: 192.168.1.1 -> is_private={r2['is_private']}")

# 3. STIX/TAXII
from backend.enterprise.threat_intel_platform import get_taxii, STIXFactory
taxii = get_taxii()
assert len(taxii.collections) == 4
print(f"[OK] TAXII: {len(taxii.collections)} collections")

ind = STIXFactory.ip_indicator("1.2.3.4", "C2", 90)
assert ind["type"] == "indicator"
bundle = STIXFactory.create_bundle([ind])
assert bundle["type"] == "bundle"
assert len(bundle["objects"]) >= 2  # identity + indicator
print(f"[OK] STIX: bundle with {len(bundle['objects'])} objects")

# 4. SIEM Export
from backend.enterprise.threat_intel_platform import SIEMExporter
test_alert = {
    "title": "Beaconing Detected", "severity": "HIGH",
    "src_ip": "10.0.0.5", "dst_ip": "8.8.8.8",
    "status": "open", "category": "beacon",
    "alert_id": "NF-TEST-001", "threat_score": 0.92,
    "mitre_technique": "T1071", "description": "C2 beaconing"
}
cef = SIEMExporter.to_cef(test_alert)
assert cef.startswith("CEF:0|NetForensics")
leef = SIEMExporter.to_leef(test_alert)
assert "LEEF:2.0" in leef
splunk = SIEMExporter.to_splunk_hec(test_alert)
assert "event" in splunk
elastic = SIEMExporter.to_elastic(test_alert)
assert "_source" in elastic
syslog = SIEMExporter.to_syslog(test_alert)
assert "netforensics" in syslog
print(f"[OK] SIEM: CEF={len(cef)}ch, LEEF={len(leef)}ch, Splunk/Elastic/Syslog OK")

# 5. SOC Engine
from backend.enterprise.soc_engine import get_soc_engine
soc = get_soc_engine()
alert = soc.ingest_alert(test_alert, "test_tenant")
assert alert.alert_id.startswith("NF-")
print(f"[OK] SOC: Alert {alert.alert_id} created, status={alert.status}, "
      f"tags={alert.tags}")

metrics = soc.get_metrics()
assert "total_alerts" in metrics
assert metrics["total_alerts"] >= 1
print(f"[OK] SOC Metrics: {metrics['total_alerts']} alerts, "
      f"MTTD={metrics['mttd_human']}, open={metrics['open_alerts']}")

# 6. Infrastructure Correlator
from backend.enterprise.threat_intel_platform import get_correlator
corr = get_correlator()
corr.ingest_threat({
    "threat_type": "malware_beaconing",
    "score": 0.85,
    "evidence": ["Connection to 1.2.3.4:443", "Also seen at 5.6.7.8:9001"],
}, session_id="test_session")
assert len(corr.nodes) >= 2
print(f"[OK] Infra Correlator: {len(corr.nodes)} nodes, "
      f"{len(corr.campaigns)} campaigns")

# 7. Report Generator
from backend.enterprise.threat_intel_platform import get_reporter
reporter = get_reporter()
report = reporter.generate_report(
    session_id="test_sid",
    analysis={
        "summary": {"total_flows": 100, "total_bytes": 500000, "unique_endpoints": 15},
        "flows": [],
        "threats": [test_alert],
        "anomalies": [],
    },
    ml_threats=[{
        "threat_type": "malware_beaconing", "score": 0.85,
        "severity": "HIGH", "evidence": ["10.0.0.5 -> 8.8.8.8"],
        "mitre_technique": "T1071",
    }],
)
assert "report_id" in report
assert "executive_summary" in report
assert "recommendations" in report
print(f"[OK] Report: {report['report_id']}, "
      f"risk={report['threat_overview']['risk_level']}")

print()
print("=" * 55)
print("  ALL ENTERPRISE MODULE TESTS PASSED")
print("=" * 55)
