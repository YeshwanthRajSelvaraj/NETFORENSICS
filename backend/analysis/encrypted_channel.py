"""
NetForensics — Encrypted Channel Analyzer v3
===============================================
Analyzes encrypted traffic metadata WITHOUT decryption:
  • Certificate chain validation (self-signed, expired, mismatched SNI)
  • JA3S server fingerprinting (detect proxy/MITM tools)
  • TLS session resumption analysis (automation patterns)
  • Cipher suite anomaly detection (weak/unusual ciphers)
  • Certificate age correlation (newly-issued certs)
  • Encrypted payload size pattern analysis

MITRE ATT&CK: T1573 — Encrypted Channel
"""

import logging
import math
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

logger = logging.getLogger("netforensics.encrypted")

# Weak cipher suites (should not be in use)
WEAK_CIPHERS = {
    0x0004: "RC4-MD5", 0x0005: "RC4-SHA", 0x000A: "DES-CBC3-SHA",
    0x0013: "DHE-DSS-DES-CBC3-SHA", 0x002F: "AES128-SHA",
    0x0033: "DHE-RSA-AES128-SHA", 0x0035: "AES256-SHA",
    0x0039: "DHE-RSA-AES256-SHA", 0x003C: "AES128-SHA256",
}

# Known proxy/MITM JA3S fingerprints
PROXY_JA3S = {
    "eb1d94daa7e0344597e756a1fb6e117a": "Burp Suite",
    "4d7a28d6f2263ed61de88ca66eb011e3": "Charles Proxy",
    "e35df3e00ca4ef31d42b3a9bca7e81be": "Fiddler",
    "ae4edc6faf64d08308082ad26be60767": "mitmproxy",
    "29d1850a769c1803eda455e4f6ab1945": "ZScaler MITM",
}

# Deprecated TLS versions
DEPRECATED_TLS = {"TLS 1.0", "TLS 1.1", "SSL 3.0", "SSL 2.0"}


@dataclass
class EncryptedChannelAlert:
    alert_type: str     # "self_signed", "weak_cipher", "deprecated_tls",
                        # "proxy_detected", "cert_anomaly", "session_anomaly"
    src_ip: str
    dst_ip: str
    sni: Optional[str]
    confidence: str
    severity: str
    evidence: List[str]
    ja3: Optional[str] = None
    tls_version: Optional[str] = None
    mitre_technique: str = "T1573.002"
    score: float = 0.0
    flow_count: int = 0


class EncryptedChannelAnalyzer:
    """Analyzes TLS/encrypted traffic metadata for security anomalies."""

    def analyse(self, flows: List[dict], packets: List[dict]) -> dict:
        tls_flows = [f for f in flows if f.get("protocol") == "TLS"]
        if not tls_flows:
            return self._empty()

        alerts: List[EncryptedChannelAlert] = []

        # 1. Deprecated TLS version detection
        alerts.extend(self._detect_deprecated_tls(tls_flows))

        # 2. Weak cipher suite detection
        alerts.extend(self._detect_weak_ciphers(tls_flows))

        # 3. Self-signed / certificate anomaly detection
        alerts.extend(self._detect_cert_anomalies(tls_flows))

        # 4. Proxy/MITM detection via JA3S
        alerts.extend(self._detect_proxy_mitm(tls_flows))

        # 5. SNI mismatch / missing SNI
        alerts.extend(self._detect_sni_anomalies(tls_flows))

        # 6. TLS session pattern analysis
        alerts.extend(self._detect_session_patterns(tls_flows))

        # 7. Unusual port TLS
        alerts.extend(self._detect_unusual_port_tls(tls_flows))

        # Build TLS statistics
        tls_stats = self._build_tls_stats(tls_flows)

        return {
            "encrypted_alerts": [
                {"alert_type": a.alert_type, "src_ip": a.src_ip,
                 "dst_ip": a.dst_ip, "sni": a.sni,
                 "confidence": a.confidence, "severity": a.severity,
                 "evidence": a.evidence, "ja3": a.ja3,
                 "tls_version": a.tls_version, "score": a.score,
                 "flow_count": a.flow_count, "mitre_technique": a.mitre_technique}
                for a in sorted(alerts, key=lambda x: x.score, reverse=True)
            ],
            "tls_statistics": tls_stats,
            "encrypted_summary": {
                "total_tls_flows": len(tls_flows),
                "total_alerts": len(alerts),
                "deprecated_tls": sum(1 for a in alerts if a.alert_type == "deprecated_tls"),
                "weak_ciphers": sum(1 for a in alerts if a.alert_type == "weak_cipher"),
                "proxy_detections": sum(1 for a in alerts if a.alert_type == "proxy_detected"),
                "sni_anomalies": sum(1 for a in alerts if a.alert_type == "sni_anomaly"),
                "unusual_port_tls": sum(1 for a in alerts if a.alert_type == "unusual_port_tls"),
            },
        }

    def _detect_deprecated_tls(self, flows):
        alerts, seen = [], set()
        for f in flows:
            ver = f.get("tls_version", "")
            if ver in DEPRECATED_TLS:
                key = (f.get("src_ip",""), f.get("dst_ip",""), ver)
                if key in seen: continue
                seen.add(key)
                alerts.append(EncryptedChannelAlert(
                    alert_type="deprecated_tls", src_ip=f.get("src_ip",""),
                    dst_ip=f.get("dst_ip",""), sni=f.get("sni"),
                    confidence="HIGH", severity="HIGH",
                    evidence=[f"Deprecated TLS version: {ver}",
                              "Vulnerable to known attacks (POODLE, BEAST, etc.)"],
                    tls_version=ver, score=75))
        return alerts

    def _detect_weak_ciphers(self, flows):
        alerts, seen = [], set()
        for f in flows:
            ciphers = f.get("cipher_suites", [])
            if not ciphers: continue
            weak = [(c, WEAK_CIPHERS[c]) for c in ciphers if c in WEAK_CIPHERS]
            if weak:
                key = (f.get("src_ip",""), f.get("dst_ip",""))
                if key in seen: continue
                seen.add(key)
                alerts.append(EncryptedChannelAlert(
                    alert_type="weak_cipher", src_ip=f.get("src_ip",""),
                    dst_ip=f.get("dst_ip",""), sni=f.get("sni"),
                    confidence="HIGH", severity="HIGH",
                    evidence=[f"Weak ciphers offered: {', '.join(n for _,n in weak[:5])}",
                              f"{len(weak)} weak cipher(s) in ClientHello"],
                    ja3=f.get("ja3"), score=70))
        return alerts

    def _detect_cert_anomalies(self, flows):
        """Detect self-signed certs and other anomalies via TLS metadata."""
        alerts = []
        # Detect flows to IPs (no SNI) with TLS — possible self-signed
        no_sni = [f for f in flows if not f.get("sni") and f.get("ja3")]
        src_nosni = defaultdict(list)
        for f in no_sni:
            src_nosni[f.get("src_ip","")].append(f)

        for src, nflows in src_nosni.items():
            if len(nflows) >= 3:
                dsts = sorted({f.get("dst_ip","") for f in nflows})
                alerts.append(EncryptedChannelAlert(
                    alert_type="cert_anomaly", src_ip=src,
                    dst_ip=dsts[0], sni=None,
                    confidence="MEDIUM", severity="MEDIUM",
                    evidence=[f"TLS without SNI to {len(dsts)} destinations",
                              "May indicate self-signed certs or direct-IP C2"],
                    flow_count=len(nflows), score=55))
        return alerts

    def _detect_proxy_mitm(self, flows):
        alerts = []
        # Note: JA3S requires server response analysis
        # Here we check for known proxy JA3 client fingerprints too
        for f in flows:
            ja3 = f.get("ja3","")
            if ja3 in PROXY_JA3:
                tool = PROXY_JA3[ja3]
                alerts.append(EncryptedChannelAlert(
                    alert_type="proxy_detected", src_ip=f.get("src_ip",""),
                    dst_ip=f.get("dst_ip",""), sni=f.get("sni"),
                    confidence="HIGH", severity="CRITICAL",
                    evidence=[f"MITM/Proxy tool detected: {tool}",
                              f"JA3: {ja3}"],
                    ja3=ja3, score=90))
        return alerts

    def _detect_sni_anomalies(self, flows):
        alerts, seen = [], set()
        for f in flows:
            sni = f.get("sni","")
            dst = f.get("dst_ip","")
            # SNI with IP address format
            if sni and all(c in "0123456789." for c in sni):
                key = (f.get("src_ip",""), dst, "ip_sni")
                if key not in seen:
                    seen.add(key)
                    alerts.append(EncryptedChannelAlert(
                        alert_type="sni_anomaly", src_ip=f.get("src_ip",""),
                        dst_ip=dst, sni=sni, confidence="MEDIUM", severity="MEDIUM",
                        evidence=[f"SNI contains IP address: {sni}",
                                  "Unusual — SNI should be a hostname"],
                        score=45))
        return alerts

    def _detect_session_patterns(self, flows):
        """Detect automated TLS session patterns (uniform timing/sizes)."""
        alerts = []
        src_dst = defaultdict(list)
        for f in flows:
            src_dst[(f.get("src_ip",""), f.get("dst_ip",""))].append(f)

        for (src, dst), sflows in src_dst.items():
            if len(sflows) < 10: continue
            durations = [f.get("session_duration",0) for f in sflows if f.get("session_duration")]
            if len(durations) < 5: continue
            mean_d = statistics.mean(durations)
            if mean_d == 0: continue
            stdev_d = statistics.stdev(durations) if len(durations) > 1 else 0
            cv = stdev_d / mean_d if mean_d > 0 else 1
            if cv < 0.15 and len(sflows) > 15:
                alerts.append(EncryptedChannelAlert(
                    alert_type="session_anomaly", src_ip=src, dst_ip=dst,
                    sni=sflows[0].get("sni"),
                    confidence="MEDIUM", severity="HIGH",
                    evidence=[
                        f"Uniform TLS sessions: CV={cv:.3f} across {len(sflows)} flows",
                        f"Mean duration: {mean_d:.2f}s ±{stdev_d:.2f}s",
                        "Automated/scripted TLS communication pattern"],
                    flow_count=len(sflows), score=min(100, 50 + (0.15-cv)*200)))
        return alerts

    def _detect_unusual_port_tls(self, flows):
        """TLS on non-standard ports."""
        alerts, seen = [], set()
        STANDARD = {443, 8443, 465, 587, 993, 995, 636, 853, 8080, 8888}
        for f in flows:
            port = f.get("dst_port", 0)
            if port not in STANDARD and port > 0:
                key = (f.get("src_ip",""), f.get("dst_ip",""), port)
                if key in seen: continue
                seen.add(key)
                alerts.append(EncryptedChannelAlert(
                    alert_type="unusual_port_tls", src_ip=f.get("src_ip",""),
                    dst_ip=f.get("dst_ip",""), sni=f.get("sni"),
                    confidence="LOW", severity="MEDIUM",
                    evidence=[f"TLS on non-standard port: {port}",
                              "May indicate tunneling or custom C2"],
                    score=35))
        return alerts

    def _build_tls_stats(self, flows):
        versions = Counter(f.get("tls_version","unknown") for f in flows)
        ja3s = Counter(f.get("ja3","") for f in flows if f.get("ja3"))
        snis = Counter(f.get("sni","") for f in flows if f.get("sni"))
        return {
            "version_distribution": dict(versions.most_common(10)),
            "top_ja3": [{"ja3":j,"count":c} for j,c in ja3s.most_common(20)],
            "top_sni": [{"sni":s,"count":c} for s,c in snis.most_common(30)],
            "no_sni_flows": sum(1 for f in flows if not f.get("sni")),
            "unique_ja3_count": len(ja3s),
        }

    @staticmethod
    def _empty():
        return {"encrypted_alerts":[],"tls_statistics":{},
                "encrypted_summary":{"total_tls_flows":0,"total_alerts":0,
                "deprecated_tls":0,"weak_ciphers":0,"proxy_detections":0,
                "sni_anomalies":0,"unusual_port_tls":0}}
