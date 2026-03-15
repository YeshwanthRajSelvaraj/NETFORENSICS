"""
NetForensics — ML-Based Detection Models v3
==============================================
Machine learning detection without heavy dependencies:
  • DGA Detection — Character-level statistical model
  • Anomaly Detection — Isolation Forest (pure Python)
  • Traffic Classification — Decision tree ensemble
  • Encrypted Traffic Fingerprinting

All models run in pure Python (no sklearn/torch required).
"""

import logging
import math
import random
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("netforensics.ml")


# ═══════════════════════════════════════════════════════════════════════════════
# DGA Detection Model (Statistical + N-gram)
# ═══════════════════════════════════════════════════════════════════════════════

# English bigram frequencies (top 50)
ENGLISH_BIGRAMS = {
    "th": 3.56, "he": 3.07, "in": 2.43, "er": 2.05, "an": 1.99,
    "re": 1.85, "on": 1.76, "at": 1.49, "en": 1.45, "nd": 1.35,
    "ti": 1.34, "es": 1.34, "or": 1.28, "te": 1.27, "of": 1.17,
    "ed": 1.17, "is": 1.13, "it": 1.12, "al": 1.09, "ar": 1.07,
    "st": 1.05, "to": 1.04, "nt": 1.04, "ng": 0.95, "se": 0.93,
    "ha": 0.93, "as": 0.87, "ou": 0.87, "io": 0.83, "le": 0.83,
    "ve": 0.83, "co": 0.79, "me": 0.79, "de": 0.76, "hi": 0.76,
    "ri": 0.73, "ro": 0.73, "ic": 0.70, "ne": 0.69, "ea": 0.69,
}

VOWELS = set("aeiou")
CONSONANTS = set("bcdfghjklmnpqrstvwxyz")


@dataclass
class DGAPrediction:
    domain: str
    score: float         # 0.0 - 1.0
    is_dga: bool
    features: Dict[str, float]
    family: str          # predicted DGA family or "unknown"
    confidence: str


class DGAMLDetector:
    """
    Multi-feature DGA detector using statistical analysis:
    1. Character entropy
    2. Bigram deviation from English
    3. Consonant/vowel ratio
    4. Digit ratio
    5. Label length
    6. N-gram pronounceability score
    7. Sequential character patterns
    """

    THRESHOLD = 0.55

    def predict(self, domain: str) -> DGAPrediction:
        label = domain.split(".")[0].lower() if domain else ""
        if not label or len(label) < 3:
            return DGAPrediction(domain=domain, score=0, is_dga=False,
                                features={}, family="benign", confidence="LOW")

        features = self._extract_features(label)
        score = self._compute_score(features)
        family = self._classify_family(features, score)

        return DGAPrediction(
            domain=domain, score=round(score, 4),
            is_dga=score >= self.THRESHOLD,
            features=features,
            family=family,
            confidence="HIGH" if score > 0.8 else "MEDIUM" if score > 0.6 else "LOW")

    def predict_batch(self, domains: List[str]) -> List[DGAPrediction]:
        return [self.predict(d) for d in domains]

    def _extract_features(self, label: str) -> Dict[str, float]:
        n = len(label)

        # 1. Character entropy
        freq = Counter(label)
        entropy = -sum((c/n)*math.log2(c/n) for c in freq.values())

        # 2. Bigram score (deviation from English)
        bigram_score = 0.0
        if n >= 2:
            bigrams = [label[i:i+2] for i in range(n-1)]
            known = sum(1 for bg in bigrams if bg in ENGLISH_BIGRAMS)
            bigram_score = 1.0 - (known / len(bigrams))

        # 3. Consonant ratio
        consonants = sum(1 for c in label if c in CONSONANTS)
        consonant_ratio = consonants / n

        # 4. Vowel ratio
        vowels = sum(1 for c in label if c in VOWELS)
        vowel_ratio = vowels / n

        # 5. Digit ratio
        digits = sum(1 for c in label if c.isdigit())
        digit_ratio = digits / n

        # 6. Length score (long labels are suspicious)
        length_score = min(1.0, max(0, (n - 8) / 20))

        # 7. Max consecutive consonants
        max_consec = 0
        cur = 0
        for c in label:
            if c in CONSONANTS:
                cur += 1
                max_consec = max(max_consec, cur)
            else:
                cur = 0
        consec_score = min(1.0, max_consec / 5)

        # 8. Unique character ratio
        unique_ratio = len(set(label)) / n

        # 9. Has meaningful pattern (repeated trigrams = likely hex/base encoding)
        trigrams = [label[i:i+3] for i in range(n-2)]
        trigram_unique = len(set(trigrams)) / max(len(trigrams), 1)

        return {
            "entropy": round(entropy, 4),
            "bigram_deviation": round(bigram_score, 4),
            "consonant_ratio": round(consonant_ratio, 4),
            "vowel_ratio": round(vowel_ratio, 4),
            "digit_ratio": round(digit_ratio, 4),
            "length_score": round(length_score, 4),
            "consec_consonants": round(consec_score, 4),
            "unique_ratio": round(unique_ratio, 4),
            "trigram_diversity": round(trigram_unique, 4),
            "label_length": n,
        }

    def _compute_score(self, features: Dict[str, float]) -> float:
        """Weighted ensemble of features."""
        weights = {
            "entropy": 0.20,
            "bigram_deviation": 0.20,
            "consonant_ratio": 0.10,
            "digit_ratio": 0.15,
            "length_score": 0.10,
            "consec_consonants": 0.10,
            "unique_ratio": -0.05,  # High unique = more random
            "trigram_diversity": 0.10,
        }

        score = 0.0
        for feat, weight in weights.items():
            val = features.get(feat, 0)
            if weight < 0:
                score += abs(weight) * (1.0 - val)
            else:
                score += weight * val

        # Bonus for high entropy + high consonant ratio
        if features.get("entropy", 0) > 3.5 and features.get("consonant_ratio", 0) > 0.65:
            score += 0.15

        # Bonus for digits in domain
        if features.get("digit_ratio", 0) > 0.3:
            score += 0.10

        return min(1.0, max(0.0, score))

    def _classify_family(self, features: Dict[str, float], score: float) -> str:
        if score < self.THRESHOLD:
            return "benign"
        if features.get("digit_ratio", 0) > 0.5:
            return "conficker"  # Heavy digit usage
        if features.get("label_length", 0) > 20 and features.get("entropy", 0) > 4.0:
            return "necurs"     # Very long, high entropy
        if features.get("consonant_ratio", 0) > 0.75:
            return "cryptolocker"  # Mostly consonants
        if features.get("bigram_deviation", 0) > 0.8:
            return "suppobox"   # Poor English bigrams
        return "unknown_dga"


# ═══════════════════════════════════════════════════════════════════════════════
# Isolation Forest (Pure Python) for Anomaly Detection
# ═══════════════════════════════════════════════════════════════════════════════

class IsolationTree:
    """Single isolation tree for anomaly detection."""

    def __init__(self, max_depth: int = 10):
        self.max_depth = max_depth
        self.tree = None

    def fit(self, data: List[List[float]]):
        self.tree = self._build(data, 0)

    def _build(self, data, depth):
        if depth >= self.max_depth or len(data) <= 1:
            return {"type": "leaf", "size": len(data)}
        n_features = len(data[0])
        feat = random.randint(0, n_features - 1)
        vals = [row[feat] for row in data]
        lo, hi = min(vals), max(vals)
        if lo == hi:
            return {"type": "leaf", "size": len(data)}
        split = random.uniform(lo, hi)
        left = [row for row in data if row[feat] < split]
        right = [row for row in data if row[feat] >= split]
        return {
            "type": "split", "feature": feat, "threshold": split,
            "left": self._build(left, depth + 1),
            "right": self._build(right, depth + 1),
        }

    def path_length(self, point: List[float], node=None, depth=0) -> float:
        if node is None:
            node = self.tree
        if node is None or node["type"] == "leaf":
            n = node["size"] if node else 1
            return depth + self._c(n)
        if point[node["feature"]] < node["threshold"]:
            return self.path_length(point, node["left"], depth + 1)
        return self.path_length(point, node["right"], depth + 1)

    @staticmethod
    def _c(n):
        if n <= 1: return 0
        return 2 * (math.log(n - 1) + 0.5772156649) - 2 * (n - 1) / n


class IsolationForest:
    """Pure Python Isolation Forest for network anomaly detection."""

    def __init__(self, n_trees: int = 50, max_samples: int = 256):
        self.n_trees = n_trees
        self.max_samples = max_samples
        self.trees: List[IsolationTree] = []
        self._n = 0

    def fit(self, data: List[List[float]]):
        self._n = len(data)
        self.trees = []
        for _ in range(self.n_trees):
            sample = random.sample(data, min(self.max_samples, len(data)))
            tree = IsolationTree()
            tree.fit(sample)
            self.trees.append(tree)
        logger.info("IsolationForest trained: %d trees, %d samples", self.n_trees, self._n)

    def score(self, point: List[float]) -> float:
        """Anomaly score: closer to 1.0 = more anomalous."""
        if not self.trees:
            return 0.5
        avg_path = statistics.mean(t.path_length(point) for t in self.trees)
        c = IsolationTree._c(self._n) if self._n > 1 else 1
        return round(2 ** (-avg_path / c) if c > 0 else 0.5, 4)

    def predict(self, point: List[float], threshold: float = 0.6) -> bool:
        """True if anomalous."""
        return self.score(point) > threshold


# ═══════════════════════════════════════════════════════════════════════════════
# Flow Anomaly Detector (using Isolation Forest)
# ═══════════════════════════════════════════════════════════════════════════════

class FlowAnomalyDetector:
    """Detects anomalous network flows using Isolation Forest."""

    FEATURES = [
        "packet_count", "total_bytes", "session_duration",
        "avg_packet_size", "dst_port_normalized",
    ]

    def __init__(self):
        self.forest = IsolationForest(n_trees=30, max_samples=200)
        self._trained = False

    def _flow_to_vector(self, flow: dict) -> List[float]:
        pkt = flow.get("packet_count", 0)
        byt = flow.get("total_bytes", 0)
        dur = flow.get("session_duration", 0)
        avg_pkt = byt / max(pkt, 1)
        port = flow.get("dst_port", 0) / 65535
        return [
            math.log1p(pkt), math.log1p(byt),
            math.log1p(dur), math.log1p(avg_pkt), port,
        ]

    def fit(self, flows: List[dict]):
        vectors = [self._flow_to_vector(f) for f in flows if f.get("packet_count", 0) > 0]
        if len(vectors) < 20:
            logger.warning("Not enough flows for anomaly training: %d", len(vectors))
            return
        self.forest.fit(vectors)
        self._trained = True
        logger.info("Flow anomaly detector trained on %d flows", len(vectors))

    def detect(self, flows: List[dict], threshold: float = 0.65) -> List[dict]:
        if not self._trained:
            self.fit(flows)
        if not self._trained:
            return []

        anomalies = []
        for f in flows:
            vec = self._flow_to_vector(f)
            score = self.forest.score(vec)
            if score > threshold:
                anomalies.append({
                    "flow_id": f.get("flow_id", ""),
                    "src_ip": f.get("src_ip", ""),
                    "dst_ip": f.get("dst_ip", ""),
                    "dst_port": f.get("dst_port", 0),
                    "protocol": f.get("protocol", ""),
                    "anomaly_score": score,
                    "packet_count": f.get("packet_count", 0),
                    "total_bytes": f.get("total_bytes", 0),
                    "session_duration": f.get("session_duration", 0),
                    "reason": "Statistical outlier per Isolation Forest",
                })

        return sorted(anomalies, key=lambda x: x["anomaly_score"], reverse=True)[:50]
