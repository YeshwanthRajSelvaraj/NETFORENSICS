"""
NetForensics — SOC Alert Manager v3
=====================================
Enterprise alert management:
  • Alert lifecycle (open → investigating → resolved)
  • Severity-based routing
  • De-duplication engine
  • Analyst annotations
  • SLA tracking
  • Alert export (STIX, CSV, JSON)
"""

import hashlib
import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional

logger = logging.getLogger("netforensics.alerts")

SEVERITY_PRIORITY = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
SLA_HOURS = {"CRITICAL": 1, "HIGH": 4, "MEDIUM": 24, "LOW": 72}


@dataclass
class SOCAlert:
    alert_id: str
    title: str
    severity: str
    category: str
    source_engine: str
    affected_ips: List[str]
    evidence: List[str]
    mitre_techniques: List[str] = field(default_factory=list)
    status: str = "open"
    assignee: Optional[str] = None
    created_at: float = 0.0
    updated_at: float = 0.0
    resolved_at: Optional[float] = None
    comments: List[dict] = field(default_factory=list)
    sla_deadline: float = 0.0
    sla_breached: bool = False
    threat_score: float = 0.0
    false_positive: bool = False
    related_alerts: List[str] = field(default_factory=list)


class AlertManager:
    """SOC-grade alert management with lifecycle tracking."""

    def __init__(self):
        self._alerts: Dict[str, SOCAlert] = {}
        self._dedup_cache: Dict[str, str] = {}  # dedup_key → alert_id

    def create_alert(self, title: str, severity: str, category: str,
                     source_engine: str, affected_ips: List[str],
                     evidence: List[str], mitre_techniques: List[str] = None,
                     threat_score: float = 0) -> SOCAlert:
        """Create a new alert with de-duplication."""
        # Generate dedup key
        dedup_key = hashlib.md5(
            f"{category}|{'|'.join(sorted(affected_ips))}|{source_engine}".encode()
        ).hexdigest()[:16]

        # Check for existing alert
        if dedup_key in self._dedup_cache:
            existing_id = self._dedup_cache[dedup_key]
            existing = self._alerts.get(existing_id)
            if existing and existing.status in ("open", "investigating"):
                existing.evidence.extend(evidence[:3])
                existing.updated_at = time.time()
                existing.threat_score = max(existing.threat_score, threat_score)
                logger.info("Alert deduplicated: %s", existing_id)
                return existing

        now = time.time()
        alert_id = hashlib.md5(f"{dedup_key}{now}".encode()).hexdigest()[:12]
        sla_hours = SLA_HOURS.get(severity, 72)

        alert = SOCAlert(
            alert_id=alert_id, title=title, severity=severity,
            category=category, source_engine=source_engine,
            affected_ips=affected_ips, evidence=evidence[:10],
            mitre_techniques=mitre_techniques or [],
            created_at=now, updated_at=now,
            sla_deadline=now + sla_hours * 3600,
            threat_score=threat_score,
        )

        self._alerts[alert_id] = alert
        self._dedup_cache[dedup_key] = alert_id
        logger.info("Alert created: %s [%s] %s", alert_id, severity, title)
        return alert

    def update_status(self, alert_id: str, status: str,
                      assignee: str = None, comment: str = None) -> Optional[SOCAlert]:
        alert = self._alerts.get(alert_id)
        if not alert:
            return None
        alert.status = status
        alert.updated_at = time.time()
        if assignee:
            alert.assignee = assignee
        if status == "resolved":
            alert.resolved_at = time.time()
        if comment:
            alert.comments.append({
                "text": comment, "author": assignee or "system",
                "timestamp": time.time(),
            })
        return alert

    def get_active_alerts(self, severity: str = None,
                          category: str = None, limit: int = 100) -> List[dict]:
        alerts = [a for a in self._alerts.values()
                  if a.status in ("open", "investigating")]
        if severity:
            alerts = [a for a in alerts if a.severity == severity]
        if category:
            alerts = [a for a in alerts if a.category == category]
        alerts.sort(key=lambda a: (SEVERITY_PRIORITY.get(a.severity, 0),
                                    a.threat_score), reverse=True)
        now = time.time()
        return [{
            "alert_id": a.alert_id, "title": a.title,
            "severity": a.severity, "category": a.category,
            "source_engine": a.source_engine,
            "affected_ips": a.affected_ips,
            "evidence": a.evidence[:5],
            "status": a.status, "assignee": a.assignee,
            "threat_score": a.threat_score,
            "mitre_techniques": a.mitre_techniques,
            "created_at": a.created_at,
            "sla_remaining_hours": max(0, (a.sla_deadline - now) / 3600),
            "sla_breached": now > a.sla_deadline,
            "comment_count": len(a.comments),
        } for a in alerts[:limit]]

    def get_alert_stats(self) -> dict:
        now = time.time()
        all_alerts = list(self._alerts.values())
        return {
            "total_alerts": len(all_alerts),
            "open": sum(1 for a in all_alerts if a.status == "open"),
            "investigating": sum(1 for a in all_alerts if a.status == "investigating"),
            "resolved": sum(1 for a in all_alerts if a.status == "resolved"),
            "sla_breached": sum(1 for a in all_alerts
                               if a.status in ("open","investigating") and now > a.sla_deadline),
            "by_severity": {
                sev: sum(1 for a in all_alerts if a.severity == sev and a.status != "resolved")
                for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
            },
            "by_category": dict(defaultdict(int, {
                a.category: sum(1 for x in all_alerts if x.category == a.category)
                for a in all_alerts
            })),
            "avg_resolution_hours": round(
                sum((a.resolved_at - a.created_at) / 3600
                    for a in all_alerts if a.resolved_at) /
                max(1, sum(1 for a in all_alerts if a.resolved_at)), 2
            ),
        }

    def ingest_threats(self, threats: List[dict]):
        """Create alerts from correlated threats."""
        for t in threats:
            self.create_alert(
                title=t.get("title", "Unknown threat"),
                severity=t.get("severity", "MEDIUM"),
                category=t.get("category", "unknown"),
                source_engine=", ".join(t.get("source_engines", [])),
                affected_ips=t.get("affected_ips", []),
                evidence=t.get("evidence", []),
                mitre_techniques=t.get("mitre_techniques", []),
                threat_score=t.get("threat_score", 0),
            )
