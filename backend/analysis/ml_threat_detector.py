"""
NetForensics — ML Threat Detector v4
======================================
Five specialized ML detection engines, each targeting a specific
threat class using different ML techniques:

  1. BeaconMLDetector         — Isolation Forest + LSTM-proxy timing
  2. AbnormalFlowDetector     — Isolation Forest on volumetric features
  3. TorC2Detector            — Multi-feature scoring + graph analysis
  4. EncryptedSessionDetector — Statistical clustering on TLS features
  5. LateralMovementMLDetector— Graph Neural Network proxy + port analysis

Techniques (pure Python, no sklearn/torch):
  • Isolation Forest          — anomaly scoring (O(n log n))
  • EWMA Periodicity          — exponential weighted autocorrelation
  • K-Means Clustering        — unsupervised flow grouping
  • Weighted Feature Scoring  — trained weight vectors per threat class
  • Graph Centrality Proxy    — betweenness + fan-out for pivot detection

All detection outputs include:
  • threat_type, score (0-1), confidence, evidence, mitre_technique
"""

import logging
import math
import random
import statistics
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("netforensics.ml.detector")

# ─── MITRE ATT&CK Mappings ────────────────────────────────────────────────────
MITRE_MAP = {
    "beacon":             "T1071.001",   # Web Protocols C2
    "abnormal_flow":      "T1071",       # Application Layer Protocol
    "tor_c2":             "T1090.003",   # Multi-hop Proxy (Tor)
    "suspicious_tls":     "T1573.002",   # Asymmetric Cryptography
    "lateral_movement":   "T1021",       # Remote Services
}

SEVERITY_MAP = {
    (0.90, 1.01): "CRITICAL",
    (0.75, 0.90): "HIGH",
    (0.55, 0.75): "MEDIUM",
    (0.00, 0.55): "LOW",
}

def _severity(score: float) -> str:
    for (lo, hi), sev in SEVERITY_MAP.items():
        if lo <= score < hi:
            return sev
    return "LOW"


# ═══════════════════════════════════════════════════════════════════════════════
# Pure-Python Isolation Forest (reusable core)
# ═══════════════════════════════════════════════════════════════════════════════

class _IsoTree:
    __slots__ = ("feat", "thresh", "left", "right", "size")

    def __init__(self):
        self.feat = self.thresh = None
        self.left = self.right = None
        self.size = 0

    @classmethod
    def build(cls, data: List[List[float]], depth: int, max_depth: int,
               rng: random.Random) -> "_IsoTree":
        node = cls()
        node.size = len(data)
        if depth >= max_depth or len(data) <= 1:
            return node
        n_feat = len(data[0])
        feat = rng.randint(0, n_feat - 1)
        vals = [row[feat] for row in data]
        lo, hi = min(vals), max(vals)
        if lo == hi:
            return node
        thresh = rng.uniform(lo, hi)
        node.feat = feat
        node.thresh = thresh
        left_data = [r for r in data if r[feat] < thresh]
        right_data = [r for r in data if r[feat] >= thresh]
        node.left = cls.build(left_data, depth + 1, max_depth, rng)
        node.right = cls.build(right_data, depth + 1, max_depth, rng)
        return node

    def path_length(self, point: List[float], depth: int = 0) -> float:
        if self.feat is None:
            n = self.size
            return depth + (_c(n) if n > 1 else 0)
        if point[self.feat] < self.thresh:
            return self.left.path_length(point, depth + 1)
        return self.right.path_length(point, depth + 1)


def _c(n: int) -> float:
    if n <= 1:
        return 0.0
    return 2.0 * (math.log(n - 1) + 0.5772156649) - 2.0 * (n - 1) / n


class PureIsolationForest:
    """
    Pure-Python Isolation Forest.
    Trains in O(n·t·log(ψ)) time where t=n_trees, ψ=max_samples.
    Scores in O(t·log(ψ)) per point.
    """

    def __init__(self, n_trees: int = 100, max_samples: int = 256,
                 seed: int = 42):
        self.n_trees = n_trees
        self.max_samples = max_samples
        self.rng = random.Random(seed)
        self._trees: List[_IsoTree] = []
        self._n = 0
        self._fitted = False

    def fit(self, data: List[List[float]]):
        if len(data) < 4:
            return
        self._n = len(data)
        max_depth = math.ceil(math.log2(min(self.max_samples, self._n)))
        self._trees = []
        for _ in range(self.n_trees):
            sample = self.rng.sample(
                data, min(self.max_samples, len(data)))
            tree = _IsoTree.build(sample, 0, max_depth, self.rng)
            self._trees.append(tree)
        self._fitted = True

    def anomaly_score(self, point: List[float]) -> float:
        """Return anomaly score in [0, 1]. Higher → more anomalous."""
        if not self._fitted or not self._trees:
            return 0.5
        avg_path = statistics.mean(t.path_length(point) for t in self._trees)
        c = _c(self._n)
        if c <= 0:
            return 0.5
        return round(2.0 ** (-avg_path / c), 4)

    def score_batch(self, points: List[List[float]]) -> List[float]:
        return [self.anomaly_score(p) for p in points]

    def get_state(self) -> dict:
        """Serialize to dict (lightweight — just retrain marker)."""
        return {"fitted": self._fitted, "n": self._n,
                "n_trees": self.n_trees, "max_samples": self.max_samples}


# ═══════════════════════════════════════════════════════════════════════════════
# Pure-Python K-Means (for flow clustering)
# ═══════════════════════════════════════════════════════════════════════════════

class PureKMeans:
    """Lloyd's K-Means in pure Python."""

    def __init__(self, k: int = 6, max_iter: int = 100, seed: int = 0):
        self.k = k
        self.max_iter = max_iter
        self.rng = random.Random(seed)
        self.centroids: List[List[float]] = []
        self._fitted = False

    def fit(self, data: List[List[float]]):
        if len(data) < self.k:
            return
        # KMeans++ init
        self.centroids = [self.rng.choice(data)]
        while len(self.centroids) < self.k:
            dists = [min(self._dist(x, c) for c in self.centroids)
                     for x in data]
            total = sum(dists)
            if total == 0:
                break
            r = self.rng.random() * total
            cumul = 0.0
            for i, d in enumerate(dists):
                cumul += d
                if cumul >= r:
                    self.centroids.append(data[i])
                    break

        for _ in range(self.max_iter):
            clusters: Dict[int, List[List[float]]] = defaultdict(list)
            for x in data:
                nearest = min(range(self.k),
                              key=lambda i: self._dist(x, self.centroids[i]))
                clusters[nearest].append(x)

            new_centroids = []
            changed = False
            for i in range(self.k):
                pts = clusters.get(i, [])
                if pts:
                    new_c = [statistics.mean(p[j] for p in pts)
                             for j in range(len(pts[0]))]
                else:
                    new_c = self.centroids[i]
                if new_c != self.centroids[i]:
                    changed = True
                new_centroids.append(new_c)
            self.centroids = new_centroids
            if not changed:
                break

        self._fitted = True

    def predict(self, point: List[float]) -> int:
        if not self._fitted:
            return 0
        return min(range(len(self.centroids)),
                   key=lambda i: self._dist(point, self.centroids[i]))

    def distance_to_nearest(self, point: List[float]) -> float:
        if not self._fitted:
            return 0.0
        return min(self._dist(point, c) for c in self.centroids)

    @staticmethod
    def _dist(a: List[float], b: List[float]) -> float:
        return math.sqrt(sum((x - y) ** 2 for x, y in zip(a, b)))


# ═══════════════════════════════════════════════════════════════════════════════
# Weighted Scoring Classifier (trained weight vector)
# ═══════════════════════════════════════════════════════════════════════════════

class WeightedScoringClassifier:
    """
    Simple but effective linear classifier trained via
    gradient-free weight search on labeled data.

    Learns a 26-dim weight vector w such that
        score(x) = sigmoid(w · x + b)
    approximates P(positive | x).

    Training: Coordinate descent / hill-climbing (no autograd needed).
    """

    def __init__(self, n_features: int = 26, positive_label: str = "beacon"):
        self.n_features = n_features
        self.positive_label = positive_label
        self.weights: List[float] = [0.0] * n_features
        self.bias: float = -2.0   # Start biased toward benign
        self._fitted = False
        self.rng = random.Random(42)

    def _sigmoid(self, x: float) -> float:
        return 1.0 / (1.0 + math.exp(-max(-500, min(500, x))))

    def _score(self, x: List[float]) -> float:
        dot = sum(w * xi for w, xi in zip(self.weights, x)) + self.bias
        return self._sigmoid(dot)

    def train(self, vectors: List[List[float]], labels: List[str]):
        """Train via mini-batch hill-climbing."""
        if not vectors:
            return

        # Convert to binary
        y = [1 if l == self.positive_label else 0 for l in labels]
        n = len(vectors)

        # Initialize weights with feature importance heuristic
        # (positive correlation with label)
        for j in range(self.n_features):
            pos_mean = statistics.mean(
                vectors[i][j] for i in range(n) if y[i] == 1) if any(y) else 0
            neg_mean = statistics.mean(
                vectors[i][j] for i in range(n) if y[i] == 0) if not all(y) else 0
            self.weights[j] = (pos_mean - neg_mean) * 2.0

        # Refine with coordinate descent (50 iterations)
        lr = 0.1
        for epoch in range(50):
            batch = self.rng.sample(
                list(range(n)), min(128, n))
            g_w = [0.0] * self.n_features
            g_b = 0.0
            for i in batch:
                pred = self._score(vectors[i])
                err = pred - y[i]
                for j in range(self.n_features):
                    g_w[j] += err * vectors[i][j]
                g_b += err
            inv_batch = 1.0 / len(batch)
            self.weights = [w - lr * inv_batch * g
                            for w, g in zip(self.weights, g_w)]
            self.bias -= lr * inv_batch * g_b
            if epoch % 10 == 9:
                lr *= 0.7   # lr decay

        self._fitted = True

    def score(self, x: List[float]) -> float:
        return round(self._score(x), 4)

    def predict_label(self, x: List[float],
                       threshold: float = 0.5) -> str:
        return self.positive_label if self.score(x) >= threshold else "benign"

    def get_state(self) -> dict:
        return {"weights": self.weights, "bias": self.bias,
                "positive_label": self.positive_label}

    def load_state(self, state: dict):
        self.weights = state.get("weights", self.weights)
        self.bias = state.get("bias", self.bias)
        self.positive_label = state.get("positive_label", self.positive_label)
        self._fitted = True


# ═══════════════════════════════════════════════════════════════════════════════
# 1. BEACON ML DETECTOR — Isolation Forest + LSTM-proxy timing
# ═══════════════════════════════════════════════════════════════════════════════

class BeaconMLDetector:
    """
    Detects malware C2 beaconing via:
      • Isolation Forest on 26-dim flow feature vector
      • EWMA-based periodicity scoring on packet timing sequences
      • Weighted classifier trained on beacon vs benign patterns

    Technique: Hybrid (IF + trained weights + timing EWMA)
    Feature subset: timing (6) + volume (5) → 11 features
    """

    FEATURE_IDX = list(range(11))   # timing + volume features

    def __init__(self):
        self.iso_forest = PureIsolationForest(n_trees=80, max_samples=256)
        self.classifier = WeightedScoringClassifier(
            n_features=26, positive_label="beacon")
        self.kmeans = PureKMeans(k=4, seed=1)
        self._trained = False

    def train(self, vectors: List[List[float]], labels: List[str]):
        beacon_vecs = [v for v, l in zip(vectors, labels) if l == "beacon"]
        all_vecs = vectors if vectors else []

        if len(all_vecs) >= 20:
            self.iso_forest.fit(all_vecs)
        if len(beacon_vecs) >= 5:
            self.kmeans.fit(beacon_vecs)

        self.classifier.train(vectors, labels)
        self._trained = True

    def predict_label(self, x: List[float]) -> str:
        return self.classifier.predict_label(x, threshold=0.45)

    def detect(self, flow_features: List["FeatureVector"],
               timing_sequences: Dict[str, List[List[float]]],
               normalizer: "FeatureNormalizer") -> List[dict]:
        """Run full beacon detection on extracted features."""
        threats = []

        for fv in flow_features:
            vec = normalizer.transform(fv.to_vector())

            # Score 1: Isolation Forest (general anomaly)
            iso_score = self.iso_forest.anomaly_score(vec)

            # Score 2: Classifier (beacon-specific)
            clf_score = self.classifier.score(vec)

            # Score 3: Timing periodicity from feature vector
            periodicity = fv.periodicity_score
            cv = fv.interval_cv

            # Combined score — beacon = low CV + high periodicity + clf
            # Low CV means highly regular timing
            regularity = max(0.0, 1.0 - min(cv, 3.0) / 3.0)
            beacon_score = round(
                0.35 * clf_score
                + 0.25 * regularity
                + 0.20 * periodicity
                + 0.20 * iso_score,
                4)

            # Score 4: LSTM-proxy — check timing sequence if available
            seq = timing_sequences.get(fv.entity_id)
            if seq:
                seq_score = self._ewma_periodicity(
                    [s[0] for s in seq if s[0] > 0])
                beacon_score = round(0.7 * beacon_score + 0.3 * seq_score, 4)

            if beacon_score < 0.40:
                continue

            # Build evidence
            evidence = []
            if regularity > 0.6:
                evidence.append(
                    f"Regular timing: CV={cv:.3f}, "
                    f"mean_interval={fv.interval_mean:.2f}s")
            if periodicity > 0.5:
                evidence.append(
                    f"High autocorrelation: {periodicity:.3f}")
            if clf_score > 0.5:
                evidence.append(
                    f"Beacon classifier score: {clf_score:.3f}")
            if fv.ja3_rarity > 0.7:
                evidence.append(
                    f"Rare JA3 fingerprint (rarity={fv.ja3_rarity:.2f})")
            if fv.unique_dst_ratio < 0.05:
                evidence.append("Single-destination persistent connection")

            threats.append({
                "threat_type":       "malware_beaconing",
                "entity_id":         fv.entity_id,
                "entity_type":       fv.entity_type,
                "score":             beacon_score,
                "severity":          _severity(beacon_score),
                "confidence":        "HIGH" if beacon_score > 0.75 else "MEDIUM",
                "mitre_technique":   MITRE_MAP["beacon"],
                "evidence":          evidence or ["Periodic C2 pattern detected"],
                "features": {
                    "interval_mean":    fv.interval_mean,
                    "interval_cv":      fv.interval_cv,
                    "periodicity":      fv.periodicity_score,
                    "ja3_rarity":       fv.ja3_rarity,
                    "flow_duration":    fv.flow_duration,
                    "classifier_score": clf_score,
                    "iso_score":        iso_score,
                },
            })

        return sorted(threats, key=lambda x: x["score"], reverse=True)

    @staticmethod
    def _ewma_periodicity(intervals: List[float],
                           alpha: float = 0.3) -> float:
        """
        LSTM-proxy: Exponential Weighted Moving Average residual.
        Low residual → high periodicity.
        """
        if len(intervals) < 4:
            return 0.0
        ewma = intervals[0]
        residuals = []
        for iv in intervals[1:]:
            residuals.append(abs(iv - ewma))
            ewma = alpha * iv + (1 - alpha) * ewma
        mean_iv = statistics.mean(intervals)
        if mean_iv == 0:
            return 0.0
        mean_resid = statistics.mean(residuals)
        score = max(0.0, 1.0 - mean_resid / max(mean_iv, 0.001))
        return round(min(1.0, score), 4)

    def get_state(self) -> dict:
        return {
            "classifier": self.classifier.get_state(),
            "iso_forest": self.iso_forest.get_state(),
            "trained": self._trained,
        }


# ═══════════════════════════════════════════════════════════════════════════════
# 2. ABNORMAL FLOW DETECTOR — Isolation Forest on volumetric features
# ═══════════════════════════════════════════════════════════════════════════════

class AbnormalFlowDetector:
    """
    Detects abnormal traffic flows via Isolation Forest on:
      • Packet counts, byte volumes, rates, size distributions
      • Flow duration, protocol, port patterns

    Technique: Isolation Forest (unsupervised, no labels needed at inference)
    Feature subset: volume (5) + flow (5) = 10 features
    """

    FEATURE_IDX = list(range(6, 16))  # volume + flow features

    def __init__(self):
        self.iso_forest = PureIsolationForest(n_trees=100, max_samples=256)
        self.classifier = WeightedScoringClassifier(
            n_features=26, positive_label="abnormal_flow")
        # Per-protocol baselines {protocol → (mean_bytes, stdev_bytes)}
        self._baselines: Dict[str, Tuple[float, float]] = {}
        self._trained = False

    def train(self, vectors: List[List[float]], labels: List[str]):
        if len(vectors) >= 20:
            self.iso_forest.fit(vectors)
        self.classifier.train(vectors, labels)
        self._trained = True

    def predict_label(self, x: List[float]) -> str:
        return self.classifier.predict_label(x, threshold=0.4)

    def detect(self, flow_features: List["FeatureVector"],
               flows: List[dict],
               normalizer: "FeatureNormalizer") -> List[dict]:
        """Detect volumetric anomalies."""
        # Build per-protocol byte distribution for Z-score baseline
        proto_bytes: Dict[str, List[float]] = defaultdict(list)
        for f in flows:
            proto = f.get("protocol", "")
            b = f.get("total_bytes", 0)
            if proto and b > 0:
                proto_bytes[proto].append(math.log1p(b))
        for proto, vals in proto_bytes.items():
            if len(vals) > 2:
                self._baselines[proto] = (
                    statistics.mean(vals),
                    statistics.stdev(vals) if len(vals) > 1 else 1.0)

        threats = []
        flow_by_id = {f.get("flow_id", ""): f for f in flows}

        for fv in flow_features:
            vec = normalizer.transform(fv.to_vector())

            # Isolation Forest score
            iso_score = self.iso_forest.anomaly_score(vec)
            clf_score = self.classifier.score(vec)

            # Protocol Z-score
            flow = flow_by_id.get(fv.entity_id, {})
            proto = flow.get("protocol", "")
            z_score = 0.0
            if proto in self._baselines:
                mean_b, std_b = self._baselines[proto]
                if std_b > 0:
                    z_score = abs(fv.total_bytes - mean_b) / std_b

            # Combined score
            z_norm = min(1.0, z_score / 5.0)  # Z>5 → max
            combined = round(
                0.40 * iso_score
                + 0.35 * clf_score
                + 0.25 * z_norm,
                4)

            if combined < 0.42:
                continue

            evidence = []
            if iso_score > 0.65:
                evidence.append(
                    f"Isolation Forest anomaly score: {iso_score:.3f}")
            if z_score > 3.0:
                evidence.append(
                    f"Volume Z-score {z_score:.1f}σ above {proto} baseline")
            if fv.bytes_per_second > 100_000:
                evidence.append(
                    f"High data rate: {fv.bytes_per_second:,.0f} B/s")
            if fv.burst_ratio > 0.6:
                evidence.append(
                    f"High burst ratio: {fv.burst_ratio:.2f}")

            threats.append({
                "threat_type":      "abnormal_traffic_flow",
                "entity_id":        fv.entity_id,
                "entity_type":      fv.entity_type,
                "score":            combined,
                "severity":         _severity(combined),
                "confidence":       "HIGH" if combined > 0.75 else "MEDIUM",
                "mitre_technique":  MITRE_MAP["abnormal_flow"],
                "evidence":         evidence or ["Volumetric anomaly detected"],
                "features": {
                    "total_bytes":      math.expm1(fv.total_bytes),
                    "total_packets":    math.expm1(fv.total_packets),
                    "bytes_per_second": fv.bytes_per_second,
                    "burst_ratio":      fv.burst_ratio,
                    "z_score":          round(z_score, 2),
                    "iso_score":        iso_score,
                },
            })

        return sorted(threats, key=lambda x: x["score"], reverse=True)

    def get_state(self) -> dict:
        return {"classifier": self.classifier.get_state(),
                "iso_forest": self.iso_forest.get_state(),
                "trained": self._trained}


# ═══════════════════════════════════════════════════════════════════════════════
# 3. TOR C2 DETECTOR — Graph + feature scoring
# ═══════════════════════════════════════════════════════════════════════════════

class TorC2Detector:
    """
    Detects Tor-based command & control using:
      • Graph features: low fan-out (single relay) + low betweenness
      • JA3 rarity (Tor uses unique fingerprints)
      • SNI entropy (Tor hidden service patterns)
      • Port pattern (9001, 9030, non-standard)
      • Weighted classifier trained on Tor vs benign

    Technique: Graph Neural Network proxy + weighted classification
    MITRE: T1090.003 — Multi-hop Proxy (Tor)
    """

    # Known Tor-associated ports
    TOR_PORTS = {9001, 9030, 9050, 9051, 9150, 9151}
    # Non-standard HTTPS ports often used by Tor bridges
    BRIDGE_PORTS = {443, 80, 8080, 8443}

    def __init__(self):
        self.classifier = WeightedScoringClassifier(
            n_features=26, positive_label="tor_c2")
        self.iso_forest = PureIsolationForest(n_trees=80, max_samples=200)
        self._trained = False

    def train(self, vectors: List[List[float]], labels: List[str]):
        self.iso_forest.fit(vectors)
        self.classifier.train(vectors, labels)
        self._trained = True

    def predict_label(self, x: List[float]) -> str:
        return self.classifier.predict_label(x, threshold=0.4)

    def detect(self, flow_features: List["FeatureVector"],
               flows: List[dict],
               normalizer: "FeatureNormalizer") -> List[dict]:
        """Detect Tor-based C2 connections."""
        flow_by_id = {f.get("flow_id", ""): f for f in flows}
        threats = []

        for fv in flow_features:
            vec = normalizer.transform(fv.to_vector())
            clf_score = self.classifier.score(vec)
            iso_score = self.iso_forest.anomaly_score(vec)

            flow = flow_by_id.get(fv.entity_id, {})
            dst_port = flow.get("dst_port", 0)

            # Tor-specific heuristic signals
            port_score = 0.0
            if dst_port in self.TOR_PORTS:
                port_score = 0.9
            elif dst_port in self.BRIDGE_PORTS and fv.ja3_rarity > 0.7:
                port_score = 0.6   # Bridge over standard ports

            # Graph signal: Tor relays are single-destination
            graph_score = 0.0
            if fv.fan_out < math.log1p(2) and fv.betweenness_proxy < 0.02:
                graph_score = 0.6  # Low fan-out typical of Tor clients

            # SNI entropy: Tor .onion domains have high entropy labels
            sni_score = min(1.0, fv.sni_entropy / 5.0) if fv.sni_entropy > 3.5 else 0.0

            # JA3 rarity: Tor Browser has distinctive fingerprint
            ja3_score = fv.ja3_rarity

            combined = round(
                0.30 * clf_score
                + 0.20 * port_score
                + 0.20 * graph_score
                + 0.15 * sni_score
                + 0.15 * ja3_score,
                4)

            if combined < 0.38:
                continue

            evidence = []
            if port_score > 0.5:
                evidence.append(
                    f"Tor-associated port: {dst_port}")
            if graph_score > 0.4:
                evidence.append(
                    f"Single-relay graph pattern (fan_out≈{math.expm1(fv.fan_out):.0f})")
            if sni_score > 0.3:
                evidence.append(
                    f"High SNI entropy: {fv.sni_entropy:.3f} (onion pattern)")
            if ja3_score > 0.65:
                evidence.append(
                    f"Rare TLS fingerprint (rarity={ja3_score:.2f})")
            if fv.tls_version_score > 0:
                evidence.append("Deprecated TLS version (Tor bridge evasion)")

            threats.append({
                "threat_type":      "tor_c2",
                "entity_id":        fv.entity_id,
                "entity_type":      fv.entity_type,
                "score":            combined,
                "severity":         _severity(combined),
                "confidence":       "HIGH" if port_score > 0.7 else "MEDIUM",
                "mitre_technique":  MITRE_MAP["tor_c2"],
                "evidence":         evidence or ["Tor C2 pattern detected"],
                "features": {
                    "dst_port":         dst_port,
                    "ja3_rarity":       fv.ja3_rarity,
                    "sni_entropy":      fv.sni_entropy,
                    "fan_out":          round(math.expm1(fv.fan_out)),
                    "betweenness":      fv.betweenness_proxy,
                    "clf_score":        clf_score,
                },
            })

        return sorted(threats, key=lambda x: x["score"], reverse=True)

    def get_state(self) -> dict:
        return {"classifier": self.classifier.get_state(),
                "iso_forest": self.iso_forest.get_state()}


# ═══════════════════════════════════════════════════════════════════════════════
# 4. ENCRYPTED SESSION DETECTOR — K-Means clustering on TLS features
# ═══════════════════════════════════════════════════════════════════════════════

class EncryptedSessionDetector:
    """
    Detects suspicious encrypted sessions using:
      • K-Means clustering on TLS feature quadrant
        (JA3 rarity, SNI entropy, version, port)
      • Isolation Forest on packet size uniformity (C2 padding)
      • Classifier trained on suspicious TLS patterns

    Technique: Unsupervised clustering + IF
    MITRE: T1573.002 — Encrypted Channel: Asymmetric Cryptography
    """

    TLS_FEATURE_IDX = [16, 17, 18, 19]  # ja3_rarity, sni_entropy,
                                          # sni_length, tls_version

    def __init__(self):
        self.kmeans = PureKMeans(k=5, seed=7)
        self.classifier = WeightedScoringClassifier(
            n_features=26, positive_label="suspicious_tls")
        self.iso_forest = PureIsolationForest(n_trees=60, max_samples=200)
        self._cluster_threat_map: Dict[int, float] = {}
        self._trained = False

    def train(self, vectors: List[List[float]], labels: List[str]):
        # Extract TLS sub-features for clustering
        tls_vecs = [[v[i] for i in self.TLS_FEATURE_IDX] for v in vectors]
        if len(tls_vecs) >= self.kmeans.k:
            self.kmeans.fit(tls_vecs)
            # Label each cluster by majority vote
            cluster_labels: Dict[int, List[str]] = defaultdict(list)
            for v, src_vec, lbl in zip(tls_vecs, vectors, labels):
                c = self.kmeans.predict(v)
                cluster_labels[c].append(lbl)
            for c, lbls in cluster_labels.items():
                threat_count = sum(1 for l in lbls if l != "benign")
                self._cluster_threat_map[c] = threat_count / max(len(lbls), 1)

        self.iso_forest.fit(vectors)
        self.classifier.train(vectors, labels)
        self._trained = True

    def predict_label(self, x: List[float]) -> str:
        return self.classifier.predict_label(x, threshold=0.42)

    def detect(self, flow_features: List["FeatureVector"],
               flows: List[dict],
               normalizer: "FeatureNormalizer") -> List[dict]:
        """Detect suspicious encrypted sessions."""
        flow_by_id = {f.get("flow_id", ""): f for f in flows}
        threats = []

        for fv in flow_features:
            # Only analyze TLS flows
            if fv.protocol_code < 0.45:  # Not TLS-like
                continue

            vec = normalizer.transform(fv.to_vector())
            clf_score = self.classifier.score(vec)
            iso_score = self.iso_forest.anomaly_score(vec)

            # Cluster-based threat score
            tls_sub = [vec[i] for i in self.TLS_FEATURE_IDX]
            cluster = self.kmeans.predict(tls_sub)
            cluster_score = self._cluster_threat_map.get(cluster, 0.0)

            # Packet size uniformity (C2 padding pattern)
            size_uniformity = 1.0 - min(1.0, fv.pkt_size_stdev / 500.0)

            combined = round(
                0.30 * clf_score
                + 0.25 * cluster_score
                + 0.25 * iso_score
                + 0.20 * (0.5 * fv.ja3_rarity + 0.5 * size_uniformity),
                4)

            if combined < 0.40:
                continue

            flow = flow_by_id.get(fv.entity_id, {})
            evidence = []
            if fv.ja3_rarity > 0.7:
                evidence.append(
                    f"Rare JA3 fingerprint (rarity={fv.ja3_rarity:.2f})")
            if fv.tls_version_score > 0:
                evidence.append("Deprecated TLS version in use")
            if fv.sni_entropy < 1.5 and fv.sni_length_norm > 0:
                evidence.append(
                    f"Low-entropy SNI (IP-as-hostname pattern)")
            if size_uniformity > 0.8:
                evidence.append(
                    f"Highly uniform packet sizes (stdev={fv.pkt_size_stdev:.1f}B) — C2 padding")
            if cluster_score > 0.5:
                evidence.append(
                    f"TLS cluster {cluster} has {cluster_score:.0%} threat rate")
            if not flow.get("sni") and flow.get("ja3"):
                evidence.append("TLS with no SNI — direct-IP connection")

            threats.append({
                "threat_type":      "suspicious_encrypted_session",
                "entity_id":        fv.entity_id,
                "entity_type":      fv.entity_type,
                "score":            combined,
                "severity":         _severity(combined),
                "confidence":       "HIGH" if combined > 0.72 else "MEDIUM",
                "mitre_technique":  MITRE_MAP["suspicious_tls"],
                "evidence":         evidence or ["Anomalous TLS session pattern"],
                "features": {
                    "ja3_rarity":       fv.ja3_rarity,
                    "sni_entropy":      fv.sni_entropy,
                    "tls_version":      fv.tls_version_score,
                    "pkt_size_stdev":   fv.pkt_size_stdev,
                    "cluster_id":       cluster,
                    "cluster_threat":   cluster_score,
                    "clf_score":        clf_score,
                },
            })

        return sorted(threats, key=lambda x: x["score"], reverse=True)

    def get_state(self) -> dict:
        return {"classifier": self.classifier.get_state(),
                "cluster_threat_map": self._cluster_threat_map,
                "trained": self._trained}


# ═══════════════════════════════════════════════════════════════════════════════
# 5. LATERAL MOVEMENT ML DETECTOR — Graph centrality + port clustering
# ═══════════════════════════════════════════════════════════════════════════════

class LateralMovementMLDetector:
    """
    Detects internal lateral movement using:
      • Graph Neural Network proxy: betweenness + fan-out centrality
      • K-Means clustering on admin-port feature space
      • Classifier on lateral movement feature signature
      • Temporal sequence: rapid multi-hop connection patterns

    Technique: GNN proxy + K-Means + weighted classifier
    MITRE: T1021 — Remote Services
    """

    ADMIN_PORTS = {22, 135, 139, 445, 3389, 5985, 5986, 88, 389, 5900}
    INTERNAL_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                          "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                          "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                          "172.30.", "172.31.", "192.168.")

    def __init__(self):
        self.classifier = WeightedScoringClassifier(
            n_features=26, positive_label="lateral_movement")
        self.iso_forest = PureIsolationForest(n_trees=80, max_samples=200)
        self.kmeans = PureKMeans(k=4, seed=3)
        self._trained = False

    def _is_internal(self, ip: str) -> bool:
        return bool(ip) and ip.startswith(self.INTERNAL_PREFIXES)

    def train(self, vectors: List[List[float]], labels: List[str]):
        self.iso_forest.fit(vectors)
        self.classifier.train(vectors, labels)
        # Cluster on graph + port features [14, 23, 24, 25] = port_entropy, fan_out, fan_in, betweenness
        sub = [[v[14], v[23], v[24], v[25]] for v in vectors]
        if len(sub) >= self.kmeans.k:
            self.kmeans.fit(sub)
        self._trained = True

    def predict_label(self, x: List[float]) -> str:
        return self.classifier.predict_label(x, threshold=0.42)

    def detect(self, flow_features: List["FeatureVector"],
               flows: List[dict],
               normalizer: "FeatureNormalizer") -> List[dict]:
        """Detect lateral movement inside the network."""
        # Only consider internal-to-internal flows
        internal_fids = {
            f.get("flow_id", "")
            for f in flows
            if self._is_internal(f.get("src_ip", ""))
            and self._is_internal(f.get("dst_ip", ""))
        }
        flow_by_id = {f.get("flow_id", ""): f for f in flows}

        # Build IP-level movement graph
        ip_graph = self._build_movement_graph(flows)

        threats = []

        for fv in flow_features:
            # Filter to internal flows only
            if fv.entity_id not in internal_fids and fv.entity_type == "flow":
                # For endpoints, include all
                if fv.entity_type != "endpoint":
                    continue

            vec = normalizer.transform(fv.to_vector())
            clf_score = self.classifier.score(vec)
            iso_score = self.iso_forest.anomaly_score(vec)

            # GNN proxy: centrality in movement graph
            entity = fv.entity_id
            if fv.entity_type == "flow":
                flow = flow_by_id.get(entity, {})
                entity = flow.get("src_ip", "")

            graph_node = ip_graph.get(entity, {})
            gnn_score = graph_node.get("threat_score", 0.0)

            # Port entropy score (high = scanning)
            port_score = min(1.0, fv.port_entropy / 4.5)

            # Rapid multi-destination check
            fan_out_score = min(1.0, math.expm1(fv.fan_out) / 50)

            combined = round(
                0.30 * clf_score
                + 0.25 * gnn_score
                + 0.20 * port_score
                + 0.15 * fan_out_score
                + 0.10 * iso_score,
                4)

            if combined < 0.38:
                continue

            flow = flow_by_id.get(fv.entity_id, {})
            dst_port = flow.get("dst_port", 0)

            evidence = []
            if port_score > 0.5:
                evidence.append(
                    f"High port entropy: {fv.port_entropy:.2f} — scanning pattern")
            if fan_out_score > 0.4:
                evidence.append(
                    f"Connections to {math.expm1(fv.fan_out):.0f} unique internal hosts")
            if dst_port in self.ADMIN_PORTS:
                evidence.append(
                    f"Admin protocol port: {dst_port} "
                    f"({self._port_name(dst_port)})")
            if gnn_score > 0.5:
                evidence.append(
                    f"Graph centrality score: {gnn_score:.2f} — pivot point")
            if fv.interval_mean < 1.0 and fv.burst_ratio > 0.5:
                evidence.append("Rapid sequential internal connections")

            threats.append({
                "threat_type":      "lateral_movement",
                "entity_id":        fv.entity_id,
                "entity_type":      fv.entity_type,
                "score":            combined,
                "severity":         _severity(combined),
                "confidence":       "HIGH" if gnn_score > 0.6 else "MEDIUM",
                "mitre_technique":  MITRE_MAP["lateral_movement"],
                "evidence":         evidence or ["Internal lateral movement pattern"],
                "features": {
                    "fan_out":          round(math.expm1(fv.fan_out)),
                    "port_entropy":     fv.port_entropy,
                    "betweenness":      fv.betweenness_proxy,
                    "dst_port":         dst_port,
                    "gnn_score":        gnn_score,
                    "clf_score":        clf_score,
                    "interval_mean":    fv.interval_mean,
                },
            })

        return sorted(threats, key=lambda x: x["score"], reverse=True)

    def _build_movement_graph(self, flows: List[dict]) -> Dict[str, dict]:
        """
        GNN-proxy: compute per-IP threat score from graph topology.
        Score = f(fan_out, admin_port_ratio, pivot_score)
        """
        out_map: Dict[str, set] = defaultdict(set)
        in_map: Dict[str, set] = defaultdict(set)
        admin_counts: Dict[str, int] = defaultdict(int)
        total_flow_count: Dict[str, int] = defaultdict(int)
        ext_inbound: Dict[str, int] = defaultdict(int)

        for f in flows:
            src = f.get("src_ip", "")
            dst = f.get("dst_ip", "")
            port = f.get("dst_port", 0)
            if not src or not dst:
                continue

            src_int = self._is_internal(src)
            dst_int = self._is_internal(dst)

            if src_int:
                out_map[src].add(dst)
                total_flow_count[src] += 1
                if port in self.ADMIN_PORTS:
                    admin_counts[src] += 1
            if dst_int:
                in_map[dst].add(src)
                if not src_int:
                    ext_inbound[dst] += 1  # External → internal

        result: Dict[str, dict] = {}
        all_ips = set(out_map) | set(in_map)

        for ip in all_ips:
            if not self._is_internal(ip):
                continue
            fan_out = len(out_map.get(ip, set()))
            fan_in = len(in_map.get(ip, set()))
            total = total_flow_count.get(ip, 1)
            admin_ratio = admin_counts.get(ip, 0) / max(total, 1)
            pivot = 1 if (ext_inbound.get(ip, 0) > 0 and fan_out > 2) else 0

            # GNN-proxy threat score
            threat = min(1.0,
                          0.3 * min(1.0, fan_out / 30)
                          + 0.3 * admin_ratio
                          + 0.3 * pivot
                          + 0.1 * min(1.0, fan_in / 10))

            result[ip] = {
                "fan_out": fan_out, "fan_in": fan_in,
                "admin_ratio": round(admin_ratio, 3),
                "is_pivot": bool(pivot),
                "threat_score": round(threat, 4),
            }
        return result

    @staticmethod
    def _port_name(port: int) -> str:
        return {22: "SSH", 135: "DCOM", 139: "NetBIOS", 445: "SMB",
                3389: "RDP", 5985: "WinRM", 5986: "WinRM-HTTPS",
                88: "Kerberos", 389: "LDAP", 5900: "VNC"}.get(port, "Unknown")

    def get_state(self) -> dict:
        return {"classifier": self.classifier.get_state(),
                "trained": self._trained}


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN ORCHESTRATOR — MLThreatDetector
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class MLDetectionResult:
    """Aggregate result from all ML detectors."""
    threats: List[dict] = field(default_factory=list)
    scores_by_flow: Dict[str, dict] = field(default_factory=dict)
    cluster_assignments: Dict[str, int] = field(default_factory=dict)
    summary: dict = field(default_factory=dict)
    model_versions: List[dict] = field(default_factory=list)


class MLThreatDetector:
    """
    Orchestrates all 5 ML detection engines:
      1. BeaconMLDetector
      2. AbnormalFlowDetector
      3. TorC2Detector
      4. EncryptedSessionDetector
      5. LateralMovementMLDetector

    Also runs K-Means flow clustering for behavioral grouping.
    """

    def __init__(self):
        self.beacon_detector = BeaconMLDetector()
        self.abnormal_detector = AbnormalFlowDetector()
        self.tor_detector = TorC2Detector()
        self.encrypted_detector = EncryptedSessionDetector()
        self.lateral_detector = LateralMovementMLDetector()
        self.flow_clusterer = PureKMeans(k=6, seed=42)
        self._initialized = False

    def initialize(self, registry: "ModelRegistry",
                    normalizer: "FeatureNormalizer"):
        """Load trained models from registry into detectors."""
        from backend.analysis.ml_pipeline import ModelRegistry  # avoid circular

        model_types = {
            "beacon":           self.beacon_detector,
            "abnormal_flow":    self.abnormal_detector,
            "tor_c2":           self.tor_detector,
            "suspicious_tls":   self.encrypted_detector,
            "lateral_movement": self.lateral_detector,
        }

        for model_type, detector in model_types.items():
            mv = registry.get_active(model_type)
            if mv and mv.model_state:
                state = mv.model_state
                if hasattr(detector, "classifier") and "classifier" in state:
                    detector.classifier.load_state(state["classifier"])
                detector._trained = True
                logger.info("Loaded model: %s v%d (F1=%.3f)",
                             model_type, mv.version, mv.f1_score)

        self._initialized = True

    def detect_all(self,
                    flows: List[dict],
                    packets: List[dict],
                    extractor: "MLFeatureExtractor",
                    normalizer: "FeatureNormalizer") -> dict:
        """
        Run all 5 detection engines and return merged results.

        Pipeline
        --------
          1. Extract flow features         (26-dim vectors)
          2. Extract timing sequences      (LSTM-proxy input)
          3. Normalize features
          4. Run Isolation Forest (general anomaly baseline)
          5. Run each specialized detector
          6. Cluster flows (K-Means, k=6)
          7. Deduplicate & rank threats
          8. Return merged result dict
        """
        t0 = time.time()

        if not flows:
            return self._empty_result()

        # ── Step 1 & 2: Feature extraction ────────────────────────────────────
        flow_features = extractor.extract_flow_features(flows, packets)
        endpoint_features = extractor.extract_endpoint_features(flows, packets)

        # Build flow_meta for timing sequence extraction
        flow_meta = {f.get("flow_id", ""): f for f in flows}
        timing_seqs = extractor.extract_timing_sequences(
            packets, flow_meta, seq_len=32)

        # ── Step 3: Normalize ─────────────────────────────────────────────────
        all_vecs = [fv.to_vector() for fv in flow_features]
        if not normalizer._fitted and all_vecs:
            normalizer.fit(all_vecs)

        # ── Step 4: General IF anomaly scoring ────────────────────────────────
        general_if = PureIsolationForest(n_trees=60, max_samples=min(256, len(all_vecs)))
        if len(all_vecs) >= 10:
            general_if.fit(all_vecs)
        raw_scores = {
            fv.entity_id: general_if.anomaly_score(fv.to_vector())
            for fv in flow_features
        }

        # ── Step 5: Run specialized detectors ─────────────────────────────────
        beacon_threats = self.beacon_detector.detect(
            flow_features, timing_seqs, normalizer)
        abnormal_threats = self.abnormal_detector.detect(
            flow_features, flows, normalizer)
        tor_threats = self.tor_detector.detect(
            flow_features, flows, normalizer)
        encrypted_threats = self.encrypted_detector.detect(
            flow_features, flows, normalizer)
        lateral_threats = self.lateral_detector.detect(
            endpoint_features, flows, normalizer)

        # ── Step 6: K-Means flow clustering ───────────────────────────────────
        cluster_map: Dict[str, int] = {}
        cluster_profiles: List[dict] = []
        if len(all_vecs) >= self.flow_clusterer.k:
            norm_vecs = normalizer.transform_batch(all_vecs)
            self.flow_clusterer.fit(norm_vecs)
            for fv, nv in zip(flow_features, norm_vecs):
                c = self.flow_clusterer.predict(nv)
                cluster_map[fv.entity_id] = c

            # Profile each cluster
            cluster_groups: Dict[int, List["FeatureVector"]] = defaultdict(list)
            for fv in flow_features:
                c = cluster_map.get(fv.entity_id, 0)
                cluster_groups[c].append(fv)

            for cid, members in sorted(cluster_groups.items()):
                profile = self._profile_cluster(cid, members)
                cluster_profiles.append(profile)

        # ── Step 7: Merge and de-duplicate ────────────────────────────────────
        all_threats = (beacon_threats + abnormal_threats + tor_threats
                        + encrypted_threats + lateral_threats)

        # De-duplicate by entity_id: keep highest score per entity
        dedup: Dict[str, dict] = {}
        for t in all_threats:
            eid = t["entity_id"]
            if eid not in dedup or t["score"] > dedup[eid]["score"]:
                dedup[eid] = t

        ranked = sorted(dedup.values(), key=lambda x: x["score"], reverse=True)

        # Per-flow score map
        scores_by_flow = {}
        for fv in flow_features:
            eid = fv.entity_id
            scores_by_flow[eid] = {
                "anomaly_score": raw_scores.get(eid, 0.0),
                "cluster":       cluster_map.get(eid, -1),
                "threat_score":  dedup[eid]["score"] if eid in dedup else 0.0,
            }

        elapsed = round(time.time() - t0, 3)

        # ── Step 8: Summary ───────────────────────────────────────────────────
        summary = {
            "total_flows_analyzed":   len(flow_features),
            "total_endpoints":        len(endpoint_features),
            "total_threats_detected": len(ranked),
            "beacon_threats":         len(beacon_threats),
            "abnormal_flow_threats":  len(abnormal_threats),
            "tor_c2_threats":         len(tor_threats),
            "encrypted_threats":      len(encrypted_threats),
            "lateral_threats":        len(lateral_threats),
            "clusters_found":         len(cluster_profiles),
            "critical_threats":       sum(1 for t in ranked if t["severity"] == "CRITICAL"),
            "high_threats":           sum(1 for t in ranked if t["severity"] == "HIGH"),
            "elapsed_seconds":        elapsed,
        }

        return {
            "ml_threats":        ranked[:100],
            "ml_scores":         scores_by_flow,
            "ml_clusters":       cluster_profiles,
            "ml_summary":        summary,
            "detection_modules": {
                "beacon":    {"count": len(beacon_threats),    "technique": "Isolation Forest + EWMA Periodicity"},
                "abnormal":  {"count": len(abnormal_threats),  "technique": "Isolation Forest + Z-Score"},
                "tor_c2":    {"count": len(tor_threats),       "technique": "Graph GNN-Proxy + JA3 Rarity"},
                "encrypted": {"count": len(encrypted_threats), "technique": "K-Means TLS Clustering"},
                "lateral":   {"count": len(lateral_threats),   "technique": "Graph Centrality + Port Entropy"},
            },
        }

    @staticmethod
    def _profile_cluster(cid: int,
                          members: List["FeatureVector"]) -> dict:
        """Characterize a K-Means cluster with aggregate statistics."""
        if not members:
            return {"cluster_id": cid, "count": 0}

        avg = lambda attr: round(
            statistics.mean(getattr(m, attr) for m in members), 4)

        # Infer dominant behavior
        dominant_proto = Counter(
            round(m.protocol_code, 1) for m in members).most_common(1)[0][0]
        proto_name = {0.2: "TCP", 0.3: "UDP", 0.4: "HTTP", 0.5: "TLS",
                       0.6: "DNS", 0.7: "SSH", 0.8: "SMB", 0.9: "RDP"
                       }.get(dominant_proto, "Mixed")

        mean_cv = avg("interval_cv")
        mean_fan = avg("fan_out")
        mean_port_ent = avg("port_entropy")

        # Cluster behavior label
        if mean_cv < 0.3:
            behavior = "periodic_c2"
        elif mean_fan > 2.0:
            behavior = "scanning_lateral"
        elif avg("total_bytes") > 8.0:
            behavior = "bulk_transfer"
        elif avg("dns_query_entropy") > 3.5:
            behavior = "dga_dns"
        elif proto_name == "TLS" and avg("ja3_rarity") > 0.6:
            behavior = "suspicious_tls"
        else:
            behavior = "normal_traffic"

        return {
            "cluster_id":       cid,
            "count":            len(members),
            "behavior_label":   behavior,
            "dominant_protocol": proto_name,
            "avg_interval_cv":  mean_cv,
            "avg_fan_out":      mean_fan,
            "avg_port_entropy": mean_port_ent,
            "avg_bytes":        avg("total_bytes"),
            "avg_ja3_rarity":   avg("ja3_rarity"),
            "avg_periodicity":  avg("periodicity_score"),
        }

    @staticmethod
    def _empty_result() -> dict:
        return {
            "ml_threats":        [],
            "ml_scores":         {},
            "ml_clusters":       [],
            "ml_summary": {
                "total_flows_analyzed": 0, "total_threats_detected": 0,
                "beacon_threats": 0, "abnormal_flow_threats": 0,
                "tor_c2_threats": 0, "encrypted_threats": 0,
                "lateral_threats": 0, "elapsed_seconds": 0,
            },
            "detection_modules": {},
        }
