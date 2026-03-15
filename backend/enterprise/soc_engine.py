"""
NetForensics — SOC Operations Center Engine
==============================================
Advanced SOC alert management with:
  • Alert lifecycle (open → triage → investigate → resolve/escalate)
  • SLA tracking with configurable breach thresholds
  • Alert correlation and deduplication
  • Playbook automation (auto-triage based on rules)
  • SOC metrics dashboard (MTTD, MTTR, alert volume)
  • Shift management / analyst workload balancing
  • Escalation chains
"""

import json
import logging
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("netforensics.enterprise.soc")


# ═══════════════════════════════════════════════════════════════════════════════
# SOC ALERT MODEL
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class SOCAlert:
    id: str = ""
    alert_id: str = ""            # human-readable NF-YYYYMMDD-XXXX
    tenant_id: str = ""
    session_id: str = ""
    title: str = ""
    description: str = ""
    severity: str = "MEDIUM"      # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str = ""            # beaconing, lateral_movement, tor_c2, etc.
    source_engine: str = ""       # ML_beacon, heuristic_tor, etc.
    status: str = "open"          # open, triaged, investigating, resolved, false_positive, escalated
    assignee: str = ""
    assignee_id: str = ""
    priority: int = 0             # 1=highest, 5=lowest (auto-calculated)
    threat_score: float = 0.0
    confidence: float = 0.0

    # Evidence & context
    src_ip: str = ""
    dst_ip: str = ""
    affected_ips: List[str] = field(default_factory=list)
    evidence: List[Dict] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    kill_chain_phase: str = ""
    related_alerts: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)

    # SLA tracking
    sla_deadline: str = ""
    sla_breached: bool = False

    # Timeline
    created_at: str = ""
    triaged_at: str = ""
    assigned_at: str = ""
    resolved_at: str = ""
    updated_at: str = ""
    escalated_at: str = ""

    # Notes & comments
    comments: List[Dict] = field(default_factory=list)
    resolution: str = ""

    def __post_init__(self):
        if not self.id:
            self.id = str(uuid.uuid4())
        if not self.created_at:
            self.created_at = datetime.utcnow().isoformat()
        if not self.updated_at:
            self.updated_at = self.created_at
        if not self.alert_id:
            self.alert_id = f"NF-{datetime.utcnow().strftime('%Y%m%d')}-{str(uuid.uuid4())[:4].upper()}"
        if not self.priority:
            self.priority = self._auto_priority()
        if not self.sla_deadline:
            self.sla_deadline = self._compute_sla()

    def _auto_priority(self) -> int:
        _sev_map = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4, "INFO": 5}
        return _sev_map.get(self.severity, 3)

    def _compute_sla(self) -> str:
        _sla_hours = {"CRITICAL": 1, "HIGH": 4, "MEDIUM": 8, "LOW": 24, "INFO": 72}
        hours = _sla_hours.get(self.severity, 8)
        deadline = datetime.utcnow() + timedelta(hours=hours)
        return deadline.isoformat()

    def check_sla(self) -> bool:
        if self.status in ("resolved", "false_positive"):
            return False
        try:
            deadline = datetime.fromisoformat(self.sla_deadline)
            if datetime.utcnow() > deadline:
                self.sla_breached = True
                return True
        except Exception:
            pass
        return False

    def add_comment(self, author: str, comment: str):
        self.comments.append({
            "id": str(uuid.uuid4())[:8],
            "author": author,
            "comment": comment,
            "timestamp": datetime.utcnow().isoformat(),
        })
        self.updated_at = datetime.utcnow().isoformat()


# ═══════════════════════════════════════════════════════════════════════════════
# TRIAGE PLAYBOOK
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class TriageRule:
    name: str = ""
    condition_field: str = ""     # severity, category, threat_score, src_ip
    condition_op: str = ""        # eq, gt, lt, contains, in
    condition_value: Any = ""
    action: str = ""              # auto_assign, auto_close, escalate, tag
    action_value: str = ""        # assignee name, tag name, etc.
    enabled: bool = True


class TriagePlaybook:
    """Rule-based auto-triage engine for incoming alerts."""

    def __init__(self):
        self.rules: List[TriageRule] = [
            # Default rules
            TriageRule(
                name="Auto-escalate critical",
                condition_field="severity", condition_op="eq",
                condition_value="CRITICAL",
                action="escalate", action_value="soc_manager"),
            TriageRule(
                name="Auto-tag ML detections",
                condition_field="source_engine", condition_op="contains",
                condition_value="ML_",
                action="tag", action_value="ml_detection"),
            TriageRule(
                name="Auto-close low-confidence INFO",
                condition_field="severity", condition_op="eq",
                condition_value="INFO",
                action="auto_close", action_value="auto_triaged"),
            TriageRule(
                name="Flag Tor traffic",
                condition_field="category", condition_op="contains",
                condition_value="tor",
                action="tag", action_value="tor_related"),
            TriageRule(
                name="High-score auto-assign",
                condition_field="threat_score", condition_op="gt",
                condition_value=0.85,
                action="auto_assign", action_value="senior_analyst"),
        ]

    def apply(self, alert: SOCAlert) -> List[str]:
        """Apply triage rules and return list of actions taken."""
        actions_taken = []
        for rule in self.rules:
            if not rule.enabled:
                continue
            if self._evaluate(alert, rule):
                self._execute(alert, rule)
                actions_taken.append(f"{rule.name}: {rule.action}={rule.action_value}")
        return actions_taken

    def _evaluate(self, alert: SOCAlert, rule: TriageRule) -> bool:
        val = getattr(alert, rule.condition_field, None)
        if val is None:
            return False
        if rule.condition_op == "eq":
            return str(val) == str(rule.condition_value)
        if rule.condition_op == "gt":
            try:
                return float(val) > float(rule.condition_value)
            except Exception:
                return False
        if rule.condition_op == "lt":
            try:
                return float(val) < float(rule.condition_value)
            except Exception:
                return False
        if rule.condition_op == "contains":
            return str(rule.condition_value).lower() in str(val).lower()
        if rule.condition_op == "in":
            return str(val) in rule.condition_value
        return False

    def _execute(self, alert: SOCAlert, rule: TriageRule):
        if rule.action == "auto_assign":
            alert.assignee = rule.action_value
            alert.status = "triaged"
            alert.triaged_at = datetime.utcnow().isoformat()
        elif rule.action == "auto_close":
            alert.status = "resolved"
            alert.resolution = rule.action_value
            alert.resolved_at = datetime.utcnow().isoformat()
        elif rule.action == "escalate":
            alert.status = "escalated"
            alert.escalated_at = datetime.utcnow().isoformat()
            alert.add_comment("system", f"Auto-escalated to {rule.action_value}")
        elif rule.action == "tag":
            if rule.action_value not in alert.tags:
                alert.tags.append(rule.action_value)


# ═══════════════════════════════════════════════════════════════════════════════
# SOC ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

class SOCEngine:
    """
    Central SOC operations engine:
    - Alert ingestion, correlation, deduplication
    - Lifecycle management
    - Metrics & KPI tracking
    - Analyst workload distribution
    """

    def __init__(self):
        self.alerts: Dict[str, SOCAlert] = {}
        self.playbook = TriagePlaybook()
        self._alert_counter = 0
        self._dedup_window = 300        # 5 min dedup window
        self._recent_hashes: Dict[str, str] = {}  # hash -> alert_id

    # ── Alert Ingestion ───────────────────────────────────────────────────────

    def ingest_alert(self, alert_data: Dict, tenant_id: str = "") -> SOCAlert:
        """Create alert from detection data, auto-triage, and store."""
        # Dedup check
        dedup_hash = self._dedup_hash(alert_data)
        if dedup_hash in self._recent_hashes:
            existing_id = self._recent_hashes[dedup_hash]
            if existing_id in self.alerts:
                existing = self.alerts[existing_id]
                existing.add_comment("system", "Duplicate detection suppressed")
                return existing

        alert = SOCAlert(
            tenant_id=tenant_id,
            session_id=alert_data.get("session_id", ""),
            title=alert_data.get("title", alert_data.get("threat_type", "Alert")),
            description=alert_data.get("description", ""),
            severity=alert_data.get("severity", "MEDIUM"),
            category=alert_data.get("category", alert_data.get("threat_type", "")),
            source_engine=alert_data.get("source_engine",
                                          alert_data.get("detector", "")),
            threat_score=alert_data.get("threat_score",
                                         alert_data.get("score", 0.0)),
            confidence=alert_data.get("confidence", 0.5),
            src_ip=alert_data.get("src_ip", ""),
            dst_ip=alert_data.get("dst_ip", ""),
            affected_ips=alert_data.get("affected_ips", []),
            evidence=alert_data.get("evidence", []),
            mitre_techniques=alert_data.get("mitre_techniques",
                                              [alert_data.get("mitre_technique", "")]),
            kill_chain_phase=alert_data.get("kill_chain_phase", ""),
        )

        # Auto-triage
        actions = self.playbook.apply(alert)
        if actions:
            alert.add_comment("system",
                               f"Auto-triage: {'; '.join(actions)}")

        self.alerts[alert.id] = alert
        self._recent_hashes[dedup_hash] = alert.id
        self._alert_counter += 1

        logger.info("SOC Alert %s: %s [%s] score=%.2f",
                     alert.alert_id, alert.title, alert.severity,
                     alert.threat_score)
        return alert

    def ingest_ml_threats(self, ml_threats: List[Dict],
                           session_id: str = "",
                           tenant_id: str = "") -> List[SOCAlert]:
        """Batch-ingest ML threat detections as SOC alerts."""
        alerts = []
        for t in ml_threats:
            t["session_id"] = session_id
            t["source_engine"] = f"ML_{t.get('threat_type', 'unknown')}"
            t["title"] = (f"ML Detection: {t.get('threat_type', 'Unknown')}"
                           f" (score={t.get('score', 0):.2f})")
            alert = self.ingest_alert(t, tenant_id)
            alerts.append(alert)
        return alerts

    def _dedup_hash(self, data: Dict) -> str:
        import hashlib
        key = f"{data.get('src_ip', '')}-{data.get('dst_ip', '')}-" \
              f"{data.get('threat_type', data.get('category', ''))}-" \
              f"{data.get('session_id', '')}"
        return hashlib.md5(key.encode()).hexdigest()

    # ── Alert Lifecycle ───────────────────────────────────────────────────────

    def update_status(self, alert_id: str, new_status: str,
                       user: str = "", comment: str = "") -> Optional[SOCAlert]:
        alert = self.alerts.get(alert_id)
        if not alert:
            return None

        valid_transitions = {
            "open": ["triaged", "investigating", "resolved", "false_positive", "escalated"],
            "triaged": ["investigating", "resolved", "false_positive", "escalated"],
            "investigating": ["resolved", "false_positive", "escalated"],
            "escalated": ["investigating", "resolved"],
            "resolved": ["open"],     # reopen
            "false_positive": ["open"],
        }

        allowed = valid_transitions.get(alert.status, [])
        if new_status not in allowed:
            logger.warning("Invalid transition: %s -> %s", alert.status, new_status)
            return None

        alert.status = new_status
        alert.updated_at = datetime.utcnow().isoformat()

        if new_status == "triaged":
            alert.triaged_at = datetime.utcnow().isoformat()
        elif new_status == "investigating":
            if not alert.assigned_at:
                alert.assigned_at = datetime.utcnow().isoformat()
        elif new_status in ("resolved", "false_positive"):
            alert.resolved_at = datetime.utcnow().isoformat()
        elif new_status == "escalated":
            alert.escalated_at = datetime.utcnow().isoformat()

        if comment:
            alert.add_comment(user or "system",
                               f"Status → {new_status}: {comment}")

        return alert

    def assign_alert(self, alert_id: str, assignee: str,
                      assignee_id: str = "") -> Optional[SOCAlert]:
        alert = self.alerts.get(alert_id)
        if not alert:
            return None
        alert.assignee = assignee
        alert.assignee_id = assignee_id
        alert.assigned_at = datetime.utcnow().isoformat()
        if alert.status == "open":
            alert.status = "triaged"
            alert.triaged_at = datetime.utcnow().isoformat()
        alert.add_comment("system", f"Assigned to {assignee}")
        return alert

    def add_comment(self, alert_id: str, author: str,
                     comment: str) -> Optional[SOCAlert]:
        alert = self.alerts.get(alert_id)
        if alert:
            alert.add_comment(author, comment)
            return alert
        return None

    # ── Query & Filtering ─────────────────────────────────────────────────────

    def query_alerts(self, tenant_id: str = "", status: str = "",
                      severity: str = "", category: str = "",
                      assignee: str = "", min_score: float = 0.0,
                      session_id: str = "", tag: str = "",
                      sort_by: str = "created_at",
                      limit: int = 100) -> List[Dict]:
        results = list(self.alerts.values())

        if tenant_id:
            results = [a for a in results if a.tenant_id == tenant_id]
        if status:
            results = [a for a in results if a.status == status]
        if severity:
            results = [a for a in results if a.severity == severity]
        if category:
            results = [a for a in results if category.lower() in a.category.lower()]
        if assignee:
            results = [a for a in results if a.assignee == assignee]
        if min_score > 0:
            results = [a for a in results if a.threat_score >= min_score]
        if session_id:
            results = [a for a in results if a.session_id == session_id]
        if tag:
            results = [a for a in results if tag in a.tags]

        # Sort
        if sort_by == "threat_score":
            results.sort(key=lambda a: a.threat_score, reverse=True)
        elif sort_by == "severity":
            _ord = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
            results.sort(key=lambda a: _ord.get(a.severity, 5))
        else:
            results.sort(key=lambda a: a.created_at, reverse=True)

        # Check SLAs
        for a in results:
            a.check_sla()

        return [asdict(a) for a in results[:limit]]

    # ── SOC Metrics ───────────────────────────────────────────────────────────

    def get_metrics(self, tenant_id: str = "") -> Dict:
        alerts = list(self.alerts.values())
        if tenant_id:
            alerts = [a for a in alerts if a.tenant_id == tenant_id]

        if not alerts:
            return {"total_alerts": 0}

        now = datetime.utcnow()

        # MTTD: Mean Time To Detect (creation → triage)
        triage_times = []
        for a in alerts:
            if a.triaged_at:
                try:
                    created = datetime.fromisoformat(a.created_at)
                    triaged = datetime.fromisoformat(a.triaged_at)
                    triage_times.append((triaged - created).total_seconds())
                except Exception:
                    pass
        mttd = sum(triage_times) / len(triage_times) if triage_times else 0

        # MTTR: Mean Time To Resolve
        resolve_times = []
        for a in alerts:
            if a.resolved_at:
                try:
                    created = datetime.fromisoformat(a.created_at)
                    resolved = datetime.fromisoformat(a.resolved_at)
                    resolve_times.append((resolved - created).total_seconds())
                except Exception:
                    pass
        mttr = sum(resolve_times) / len(resolve_times) if resolve_times else 0

        # Status distribution
        status_dist = defaultdict(int)
        severity_dist = defaultdict(int)
        category_dist = defaultdict(int)
        for a in alerts:
            status_dist[a.status] += 1
            severity_dist[a.severity] += 1
            category_dist[a.category] += 1

        # SLA compliance
        sla_checked = [a for a in alerts if a.status not in ("resolved", "false_positive")]
        sla_breached = sum(1 for a in sla_checked if a.check_sla())

        # Analyst workload
        workload = defaultdict(int)
        for a in alerts:
            if a.assignee and a.status not in ("resolved", "false_positive"):
                workload[a.assignee] += 1

        # 24h trend
        h24_ago = (now - timedelta(hours=24)).isoformat()
        recent = [a for a in alerts if a.created_at >= h24_ago]

        return {
            "total_alerts": len(alerts),
            "open_alerts": status_dist.get("open", 0),
            "investigating": status_dist.get("investigating", 0),
            "resolved": status_dist.get("resolved", 0) + status_dist.get("false_positive", 0),
            "escalated": status_dist.get("escalated", 0),
            "status_distribution": dict(status_dist),
            "severity_distribution": dict(severity_dist),
            "category_distribution": dict(category_dist),
            "mttd_seconds": round(mttd, 1),
            "mttr_seconds": round(mttr, 1),
            "mttd_human": self._format_duration(mttd),
            "mttr_human": self._format_duration(mttr),
            "sla_compliance": {
                "total_active": len(sla_checked),
                "breached": sla_breached,
                "rate": round(1 - (sla_breached / max(len(sla_checked), 1)), 3),
            },
            "analyst_workload": dict(workload),
            "last_24h": {
                "new_alerts": len(recent),
                "critical": sum(1 for a in recent if a.severity == "CRITICAL"),
                "high": sum(1 for a in recent if a.severity == "HIGH"),
            },
            "avg_threat_score": round(
                sum(a.threat_score for a in alerts) / len(alerts), 3),
        }

    @staticmethod
    def _format_duration(seconds: float) -> str:
        if seconds < 60:
            return f"{seconds:.0f}s"
        if seconds < 3600:
            return f"{seconds / 60:.1f}m"
        return f"{seconds / 3600:.1f}h"

    # ── Alert Correlation ─────────────────────────────────────────────────────

    def correlate_alerts(self, window_seconds: int = 600) -> List[Dict]:
        """Find related alerts based on shared IPs, timeframe, and category."""
        correlations = []
        alert_list = sorted(self.alerts.values(),
                             key=lambda a: a.created_at, reverse=True)

        for i, a1 in enumerate(alert_list[:200]):
            related = []
            for a2 in alert_list[i + 1:i + 50]:
                score = 0
                # Same session
                if a1.session_id == a2.session_id and a1.session_id:
                    score += 0.3
                # Shared IPs
                shared_ips = set(a1.affected_ips) & set(a2.affected_ips)
                if a1.src_ip == a2.src_ip:
                    score += 0.2
                if shared_ips:
                    score += 0.1 * len(shared_ips)
                # Same category
                if a1.category == a2.category:
                    score += 0.2
                # Shared MITRE
                shared_mitre = set(a1.mitre_techniques) & set(a2.mitre_techniques)
                if shared_mitre:
                    score += 0.2

                if score >= 0.3:
                    related.append({
                        "alert_id": a2.alert_id,
                        "correlation_score": round(score, 3),
                        "shared_indicators": list(shared_ips)[:5],
                    })

            if related:
                correlations.append({
                    "primary_alert": a1.alert_id,
                    "related_alerts": related[:10],
                    "correlation_count": len(related),
                })

        return correlations[:50]


# ═══════════════════════════════════════════════════════════════════════════════
# SINGLETON
# ═══════════════════════════════════════════════════════════════════════════════

_soc: Optional[SOCEngine] = None


def get_soc_engine() -> SOCEngine:
    global _soc
    if _soc is None:
        _soc = SOCEngine()
    return _soc
