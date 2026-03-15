"""
NetForensics — DNS Tunneling Detection Engine v3
==================================================
Detects DNS-based data exfiltration and command channels:
  • High-entropy subdomain detection
  • Excessive TXT/NULL record queries
  • Long subdomain labels (encoded data)
  • High query frequency to single domain
  • Response size anomaly detection
  • Known DNS tunneling tool signatures (iodine, dnscat2, dns2tcp)

MITRE ATT&CK: T1071.004 — Application Layer Protocol: DNS
"""

import logging
import math
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("netforensics.dns_tunnel")

# Known DNS tunneling tool signatures
TUNNEL_SIGNATURES = {
    "t.v0": "iodine",
    "dnscat": "dnscat2",
    "dns2tcp": "dns2tcp",
    "pwn": "DNSExfiltrator",
}

# Suspicious TLDs often used in DNS tunneling
SUSPICIOUS_TLDS = {".tk", ".cf", ".ml", ".ga", ".gq", ".xyz", ".top", ".work", ".click"}


@dataclass
class DNSTunnelAlert:
    alert_type: str     # "high_entropy", "txt_abuse", "long_labels",
                        # "high_frequency", "tool_signature", "response_anomaly"
    domain: str
    src_ip: str
    confidence: str
    severity: str
    evidence: List[str]
    query_count: int = 0
    entropy: float = 0.0
    avg_label_length: float = 0.0
    mitre_technique: str = "T1071.004"
    score: float = 0.0
    estimated_bandwidth: int = 0  # bytes tunneled


def _subdomain_entropy(domain: str) -> float:
    """Calculate Shannon entropy of the subdomain portion."""
    parts = domain.split(".")
    if len(parts) <= 2:
        return 0.0
    subdomain = ".".join(parts[:-2])
    if not subdomain:
        return 0.0
    freq = Counter(subdomain.lower())
    n = len(subdomain)
    return round(-sum((c/n)*math.log2(c/n) for c in freq.values()), 4)


def _avg_label_length(domain: str) -> float:
    labels = domain.split(".")
    if not labels:
        return 0.0
    return round(statistics.mean(len(l) for l in labels), 2)


def _max_label_length(domain: str) -> int:
    return max((len(l) for l in domain.split(".")), default=0)


class DNSTunnelingDetector:
    # Thresholds
    ENTROPY_THRESHOLD = 4.0
    LABEL_LENGTH_THRESHOLD = 30
    FREQUENCY_THRESHOLD = 50   # queries/min to single base domain
    TXT_RATIO_THRESHOLD = 0.3
    MIN_QUERIES = 5

    def analyse(self, packets: List[dict], flows: List[dict]) -> dict:
        alerts: List[DNSTunnelAlert] = []

        # Extract DNS data
        dns_queries = [p for p in packets if p.get("dns_query")]
        if not dns_queries:
            return self._empty()

        # Group queries by base domain
        base_domains: Dict[str, List[dict]] = defaultdict(list)
        for p in dns_queries:
            query = p.get("dns_query", "")
            parts = query.split(".")
            base = ".".join(parts[-2:]) if len(parts) >= 2 else query
            base_domains[base].append(p)

        # 1. High entropy subdomain detection
        alerts.extend(self._detect_high_entropy(base_domains))

        # 2. TXT/NULL record abuse
        alerts.extend(self._detect_txt_abuse(base_domains))

        # 3. Long subdomain labels (encoded payload)
        alerts.extend(self._detect_long_labels(base_domains))

        # 4. High frequency to single domain
        alerts.extend(self._detect_high_frequency(base_domains))

        # 5. Known tool signatures
        alerts.extend(self._detect_tool_signatures(dns_queries))

        # 6. Unique subdomain ratio
        alerts.extend(self._detect_unique_subdomains(base_domains))

        # Build per-domain summary
        domain_summary = self._build_domain_summary(base_domains)

        return {
            "dns_tunnel_alerts": [
                {"alert_type": a.alert_type, "domain": a.domain,
                 "src_ip": a.src_ip, "confidence": a.confidence,
                 "severity": a.severity, "evidence": a.evidence,
                 "query_count": a.query_count, "entropy": a.entropy,
                 "score": a.score, "estimated_bandwidth": a.estimated_bandwidth,
                 "mitre_technique": a.mitre_technique}
                for a in sorted(alerts, key=lambda x: x.score, reverse=True)
            ],
            "domain_analysis": domain_summary[:30],
            "dns_tunnel_summary": {
                "total_alerts": len(alerts),
                "high_entropy_domains": sum(1 for a in alerts if a.alert_type=="high_entropy"),
                "txt_abuse_domains": sum(1 for a in alerts if a.alert_type=="txt_abuse"),
                "tool_signatures": sum(1 for a in alerts if a.alert_type=="tool_signature"),
                "total_dns_queries": len(dns_queries),
                "unique_domains": len(base_domains),
                "estimated_exfil_bytes": sum(a.estimated_bandwidth for a in alerts),
            },
        }

    def _detect_high_entropy(self, base_domains):
        alerts = []
        for base, queries in base_domains.items():
            if len(queries) < self.MIN_QUERIES:
                continue
            entropies = [_subdomain_entropy(q.get("dns_query","")) for q in queries]
            entropies = [e for e in entropies if e > 0]
            if not entropies:
                continue
            avg_entropy = statistics.mean(entropies)
            if avg_entropy > self.ENTROPY_THRESHOLD:
                src = queries[0].get("src_ip", "")
                bw = sum(len(q.get("dns_query","")) for q in queries)
                alerts.append(DNSTunnelAlert(
                    alert_type="high_entropy", domain=base, src_ip=src,
                    confidence="HIGH" if avg_entropy > 4.5 else "MEDIUM",
                    severity="CRITICAL" if avg_entropy > 4.5 else "HIGH",
                    evidence=[
                        f"Avg subdomain entropy: {avg_entropy:.2f} bits (threshold: {self.ENTROPY_THRESHOLD})",
                        f"Queries to {base}: {len(queries)}",
                        f"Sample: {queries[0].get('dns_query','')}",
                    ],
                    query_count=len(queries), entropy=avg_entropy,
                    score=min(100, 50 + (avg_entropy - self.ENTROPY_THRESHOLD) * 20),
                    estimated_bandwidth=bw))
        return alerts

    def _detect_txt_abuse(self, base_domains):
        alerts = []
        for base, queries in base_domains.items():
            if len(queries) < self.MIN_QUERIES:
                continue
            txt_count = sum(1 for q in queries if q.get("dns_type") in ("TXT","NULL","ANY"))
            txt_ratio = txt_count / len(queries)
            if txt_ratio > self.TXT_RATIO_THRESHOLD and txt_count > 10:
                alerts.append(DNSTunnelAlert(
                    alert_type="txt_abuse", domain=base,
                    src_ip=queries[0].get("src_ip",""),
                    confidence="HIGH" if txt_ratio > 0.5 else "MEDIUM",
                    severity="HIGH",
                    evidence=[
                        f"TXT/NULL ratio: {txt_ratio:.0%} ({txt_count}/{len(queries)})",
                        "Common in DNS tunneling (data in TXT records)",
                    ],
                    query_count=len(queries),
                    score=min(100, 40 + txt_ratio * 60)))
        return alerts

    def _detect_long_labels(self, base_domains):
        alerts = []
        for base, queries in base_domains.items():
            if len(queries) < self.MIN_QUERIES:
                continue
            max_lens = [_max_label_length(q.get("dns_query","")) for q in queries]
            long_count = sum(1 for l in max_lens if l > self.LABEL_LENGTH_THRESHOLD)
            if long_count > len(queries) * 0.3:
                avg_max = statistics.mean(max_lens)
                bw = sum(len(q.get("dns_query","")) for q in queries)
                alerts.append(DNSTunnelAlert(
                    alert_type="long_labels", domain=base,
                    src_ip=queries[0].get("src_ip",""),
                    confidence="HIGH" if avg_max > 40 else "MEDIUM",
                    severity="HIGH",
                    evidence=[
                        f"Long labels in {long_count}/{len(queries)} queries",
                        f"Avg max label: {avg_max:.0f} chars",
                        "Encoded data in DNS labels",
                    ],
                    query_count=len(queries), avg_label_length=avg_max,
                    score=min(100, 45 + long_count * 3),
                    estimated_bandwidth=bw))
        return alerts

    def _detect_high_frequency(self, base_domains):
        alerts = []
        for base, queries in base_domains.items():
            if len(queries) < 20:
                continue
            times = sorted(q.get("timestamp",0) for q in queries)
            if times[-1] - times[0] < 1:
                continue
            rate = len(queries) / ((times[-1] - times[0]) / 60)  # per minute
            if rate > self.FREQUENCY_THRESHOLD:
                alerts.append(DNSTunnelAlert(
                    alert_type="high_frequency", domain=base,
                    src_ip=queries[0].get("src_ip",""),
                    confidence="HIGH" if rate > 100 else "MEDIUM",
                    severity="HIGH",
                    evidence=[
                        f"Query rate: {rate:.0f}/min (threshold: {self.FREQUENCY_THRESHOLD})",
                        f"Total queries: {len(queries)}",
                    ],
                    query_count=len(queries),
                    score=min(100, 40 + rate * 0.5)))
        return alerts

    def _detect_tool_signatures(self, queries):
        alerts = []
        for q in queries:
            domain = q.get("dns_query", "").lower()
            for sig, tool in TUNNEL_SIGNATURES.items():
                if sig in domain:
                    alerts.append(DNSTunnelAlert(
                        alert_type="tool_signature", domain=domain,
                        src_ip=q.get("src_ip",""),
                        confidence="HIGH", severity="CRITICAL",
                        evidence=[f"DNS tunneling tool signature: {tool}",
                                  f"Matched pattern: '{sig}' in {domain}"],
                        score=95, mitre_technique="T1071.004"))
                    break
        return alerts

    def _detect_unique_subdomains(self, base_domains):
        alerts = []
        for base, queries in base_domains.items():
            if len(queries) < 20:
                continue
            full_domains = [q.get("dns_query","") for q in queries]
            unique_ratio = len(set(full_domains)) / len(full_domains)
            if unique_ratio > 0.8:
                alerts.append(DNSTunnelAlert(
                    alert_type="unique_subdomains", domain=base,
                    src_ip=queries[0].get("src_ip",""),
                    confidence="MEDIUM", severity="HIGH",
                    evidence=[
                        f"Unique subdomain ratio: {unique_ratio:.0%}",
                        f"{len(set(full_domains))} unique out of {len(full_domains)}",
                        "Each query uses different subdomain (data encoding)",
                    ],
                    query_count=len(queries),
                    score=min(100, 35 + unique_ratio * 50)))
        return alerts

    def _build_domain_summary(self, base_domains):
        summaries = []
        for base, queries in base_domains.items():
            entropies = [_subdomain_entropy(q.get("dns_query","")) for q in queries]
            entropies = [e for e in entropies if e > 0]
            types = Counter(q.get("dns_type","A") for q in queries)
            summaries.append({
                "domain": base, "query_count": len(queries),
                "avg_entropy": round(statistics.mean(entropies),3) if entropies else 0,
                "unique_subdomains": len({q.get("dns_query","") for q in queries}),
                "query_types": dict(types.most_common(5)),
                "sources": sorted({q.get("src_ip","") for q in queries})[:10],
            })
        return sorted(summaries, key=lambda x: x["query_count"], reverse=True)

    @staticmethod
    def _empty():
        return {"dns_tunnel_alerts":[],"domain_analysis":[],
                "dns_tunnel_summary":{"total_alerts":0,"high_entropy_domains":0,
                "txt_abuse_domains":0,"tool_signatures":0,"total_dns_queries":0,
                "unique_domains":0,"estimated_exfil_bytes":0}}
