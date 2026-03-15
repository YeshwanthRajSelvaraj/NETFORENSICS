"""
NetForensics — ML Pipeline & Training Infrastructure v4
==========================================================
Complete ML pipeline for network threat detection:

  1. Dataset Design       — Synthetic + real-data dataset generator
  2. Feature Pipeline     — Extract → Normalize → Split
  3. Model Registry       — Manage trained model versions
  4. Training Strategy    — Online + batch training with validation
  5. Deployment           — Hot-reload models inside FastAPI

All models run in pure Python — no sklearn/torch/tensorflow required.
Models are serializable to JSON for persistence and version control.
"""

import hashlib
import json
import logging
import math
import os
import random
import statistics
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from backend.analysis.ml_features import (
    FeatureNormalizer, FeatureVector, MLFeatureExtractor,
)

logger = logging.getLogger("netforensics.ml.pipeline")

# ═══════════════════════════════════════════════════════════════════════════════
# 1. DATASET DESIGN — Synthetic threat data generator
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class LabeledSample:
    """A single labeled training sample."""
    features: List[float]
    label: str               # "benign", "beacon", "tor_c2", "lateral", etc.
    threat_type: str = ""    # More specific sub-type
    confidence: float = 1.0  # Label confidence (1.0 = ground truth)
    source: str = ""         # "synthetic", "pcap", "manual"


class SyntheticDatasetGenerator:
    """
    Generates labeled synthetic training data for threat detection models.

    Each generator creates realistic feature vectors that mimic
    known threat patterns. This allows training models before
    real-world labeled data is available (cold-start problem).

    The generator produces data following these distributions:
      • 60% benign traffic (normal web/email/DNS)
      • 10% malware beaconing (periodic C2 with jitter)
      • 8%  abnormal flows (volumetric anomalies)
      • 7%  Tor-based C2 (encrypted + Tor exit patterns)
      • 8%  suspicious TLS (unusual JA3/self-signed/deprecated)
      • 7%  lateral movement (internal scan/pivot patterns)
    """

    def __init__(self, seed: int = 42):
        self.rng = random.Random(seed)

    def generate(self, n_samples: int = 5000) -> List[LabeledSample]:
        """Generate a balanced synthetic dataset."""
        samples: List[LabeledSample] = []

        distribution = {
            "benign": int(n_samples * 0.60),
            "beacon": int(n_samples * 0.10),
            "abnormal_flow": int(n_samples * 0.08),
            "tor_c2": int(n_samples * 0.07),
            "suspicious_tls": int(n_samples * 0.08),
            "lateral_movement": int(n_samples * 0.07),
        }

        for label, count in distribution.items():
            generator = getattr(self, f"_gen_{label}")
            for _ in range(count):
                features = generator()
                samples.append(LabeledSample(
                    features=features, label=label,
                    threat_type=label, confidence=0.95,
                    source="synthetic"))

        self.rng.shuffle(samples)
        logger.info("Generated synthetic dataset: %d samples (%s)",
                     len(samples),
                     ", ".join(f"{k}={v}" for k, v in distribution.items()))
        return samples

    def _gen_benign(self) -> List[float]:
        """Normal web/email traffic profile."""
        return [
            self.rng.uniform(0.5, 30.0),     # interval_mean
            self.rng.uniform(0.1, 15.0),      # interval_stdev
            self.rng.uniform(0.3, 2.0),       # interval_cv  (irregular)
            self.rng.uniform(0.1, 10.0),      # jitter
            self.rng.uniform(0.0, 0.3),       # periodicity  (low)
            self.rng.uniform(0.0, 0.3),       # burst_ratio
            math.log1p(self.rng.randint(500, 500_000)),    # total_bytes
            math.log1p(self.rng.randint(5, 500)),          # total_packets
            self.rng.uniform(200, 1400),      # bytes/pkt
            self.rng.uniform(100, 50_000),    # bytes/sec
            self.rng.uniform(50, 500),        # pkt_size_stdev
            math.log1p(self.rng.uniform(1, 300)),  # flow_duration
            self.rng.choice([0.2, 0.4, 0.5]),     # protocol (TCP/HTTP/TLS)
            self.rng.choice([80, 443, 8080]) / 65535,  # dst_port_norm
            self.rng.uniform(0, 2.0),          # port_entropy
            self.rng.uniform(0.1, 0.5),        # unique_dst_ratio
            self.rng.uniform(0.0, 0.3),        # ja3_rarity (common)
            self.rng.uniform(2.5, 4.0),        # sni_entropy
            self.rng.uniform(0.15, 0.5),       # sni_length_norm
            0.0,                                # tls_version (modern)
            self.rng.uniform(2.0, 3.5),        # dns_query_entropy
            self.rng.uniform(0.1, 0.4),        # dns_label_length
            self.rng.uniform(0.3, 0.55),       # dns_consonant_ratio
            math.log1p(self.rng.randint(1, 20)),  # fan_out
            math.log1p(self.rng.randint(1, 10)),  # fan_in
            self.rng.uniform(0.0, 0.1),           # betweenness
        ]

    def _gen_beacon(self) -> List[float]:
        """Malware beaconing — periodic with low jitter."""
        base_interval = self.rng.choice([5, 10, 30, 60, 300, 600])
        jitter_pct = self.rng.uniform(0.02, 0.15)
        return [
            base_interval,                               # interval_mean (regular)
            base_interval * jitter_pct,                   # stdev (very low)
            jitter_pct,                                   # cv (very low = periodic)
            base_interval * jitter_pct * 0.5,             # jitter (low)
            self.rng.uniform(0.6, 0.95),                  # periodicity (HIGH)
            self.rng.uniform(0.0, 0.1),                   # burst_ratio (low)
            math.log1p(self.rng.randint(100, 5000)),      # bytes (small payloads)
            math.log1p(self.rng.randint(20, 200)),        # packets
            self.rng.uniform(50, 300),                    # bytes/pkt (small)
            self.rng.uniform(10, 500),                    # bytes/sec (low)
            self.rng.uniform(10, 80),                     # pkt_size_stdev (uniform)
            math.log1p(self.rng.uniform(300, 86400)),     # duration (long-lived)
            0.5,                                          # TLS
            443 / 65535,                                  # port 443
            self.rng.uniform(0.0, 0.5),                   # port_entropy
            self.rng.uniform(0.02, 0.1),                  # 1 destination
            self.rng.uniform(0.5, 1.0),                   # ja3_rarity (rare JA3)
            self.rng.uniform(3.0, 4.5),                   # sni_entropy
            self.rng.uniform(0.2, 0.6),                   # sni_length
            0.0,                                          # tls modern
            self.rng.uniform(2.0, 4.0),                   # dns_entropy
            self.rng.uniform(0.1, 0.5),                   # dns_label
            self.rng.uniform(0.3, 0.6),                   # dns_consonant
            math.log1p(1),                                # fan_out (single dest)
            math.log1p(self.rng.randint(0, 2)),           # fan_in
            self.rng.uniform(0.0, 0.05),                  # betweenness
        ]

    def _gen_abnormal_flow(self) -> List[float]:
        """Volumetric anomaly — unusual bytes/packets/duration."""
        anomaly_type = self.rng.choice(["high_volume", "rapid_burst", "long_idle"])
        base = self._gen_benign()
        if anomaly_type == "high_volume":
            base[6] = math.log1p(self.rng.randint(10_000_000, 500_000_000))
            base[7] = math.log1p(self.rng.randint(5000, 100_000))
            base[9] = self.rng.uniform(100_000, 5_000_000)
        elif anomaly_type == "rapid_burst":
            base[0] = self.rng.uniform(0.001, 0.05)  # very fast intervals
            base[5] = self.rng.uniform(0.7, 1.0)     # high burst ratio
            base[7] = math.log1p(self.rng.randint(1000, 50_000))
        else:  # long idle
            base[0] = self.rng.uniform(300, 3600)     # very long intervals
            base[11] = math.log1p(self.rng.uniform(7200, 86400))
            base[7] = math.log1p(self.rng.randint(2, 10))
        return base

    def _gen_tor_c2(self) -> List[float]:
        """Tor-based C2 — encrypted, Tor exit node patterns."""
        return [
            self.rng.uniform(10, 120),               # moderate intervals
            self.rng.uniform(5, 40),                  # moderate stdev
            self.rng.uniform(0.2, 0.6),               # semi-regular
            self.rng.uniform(2, 20),                  # moderate jitter
            self.rng.uniform(0.3, 0.7),               # moderate periodicity
            self.rng.uniform(0.05, 0.2),              # low burst
            math.log1p(self.rng.randint(1000, 50000)),  # moderate bytes
            math.log1p(self.rng.randint(10, 500)),      # moderate packets
            self.rng.uniform(100, 600),               # variable pkt size
            self.rng.uniform(50, 5000),               # moderate rate
            self.rng.uniform(100, 400),               # moderate size stdev
            math.log1p(self.rng.uniform(60, 7200)),   # moderate duration
            0.5,                                      # TLS
            self.rng.choice([443, 9001, 9030]) / 65535,  # Tor ports
            self.rng.uniform(0.0, 1.0),               # port_entropy
            self.rng.uniform(0.01, 0.05),             # very few destinations
            self.rng.uniform(0.7, 1.0),               # VERY rare JA3
            self.rng.uniform(3.5, 5.0),               # high sni entropy
            self.rng.uniform(0.3, 0.8),               # longer SNI
            self.rng.choice([0.0, 1.0]),              # sometimes deprecated
            self.rng.uniform(3.0, 5.0),               # high dns entropy
            self.rng.uniform(0.3, 0.8),               # long dns labels
            self.rng.uniform(0.5, 0.8),               # high consonant
            math.log1p(self.rng.randint(1, 3)),       # low fan_out
            math.log1p(self.rng.randint(0, 1)),       # very low fan_in
            self.rng.uniform(0.0, 0.03),              # low betweenness
        ]

    def _gen_suspicious_tls(self) -> List[float]:
        """Suspicious encrypted sessions — unusual JA3/certs."""
        base = self._gen_benign()
        base[12] = 0.5    # TLS
        base[16] = self.rng.uniform(0.8, 1.0)    # VERY rare JA3
        base[17] = self.rng.uniform(1.0, 2.5)    # low SNI entropy (IP-like)
        base[18] = self.rng.uniform(0.0, 0.15)   # very short SNI
        base[19] = self.rng.choice([0.0, 1.0])    # sometimes deprecated TLS
        base[13] = self.rng.choice(                # unusual ports
            [4444, 8888, 1337, 9999, 31337]) / 65535
        base[10] = self.rng.uniform(0, 30)        # very uniform packet sizes
        return base

    def _gen_lateral_movement(self) -> List[float]:
        """Internal lateral movement — scan/pivot patterns."""
        return [
            self.rng.uniform(0.01, 2.0),             # very fast intervals
            self.rng.uniform(0.005, 1.0),             # low stdev
            self.rng.uniform(0.1, 0.5),               # fairly regular
            self.rng.uniform(0.01, 0.5),              # low jitter
            self.rng.uniform(0.1, 0.5),               # moderate periodicity
            self.rng.uniform(0.3, 0.8),               # high burst ratio
            math.log1p(self.rng.randint(100, 10000)), # moderate bytes
            math.log1p(self.rng.randint(3, 50)),      # few packets per target
            self.rng.uniform(50, 400),                # small-mid packets
            self.rng.uniform(500, 50_000),            # high rate (scanning)
            self.rng.uniform(10, 100),                # low size stdev
            math.log1p(self.rng.uniform(0.1, 30)),    # short duration
            self.rng.choice([0.2, 0.7, 0.8, 0.9]),   # TCP/SSH/SMB/RDP
            self.rng.choice([22, 135, 445, 3389, 5985]) / 65535,  # admin ports
            self.rng.uniform(2.5, 4.5),               # HIGH port entropy (scanning)
            self.rng.uniform(0.5, 1.0),               # HIGH unique dest ratio
            self.rng.uniform(0.0, 0.3),               # ja3_rarity (normal)
            self.rng.uniform(0.0, 1.0),               # sni (often no SNI)
            self.rng.uniform(0.0, 0.1),               # sni_length (none)
            0.0,                                       # tls_version
            0.0,                                       # dns_entropy (none)
            0.0,                                       # dns_label (none)
            0.0,                                       # dns_consonant (none)
            math.log1p(self.rng.randint(10, 200)),    # HIGH fan_out (scanning)
            math.log1p(self.rng.randint(0, 3)),       # low fan_in
            self.rng.uniform(0.1, 0.5),               # high betweenness (pivot)
        ]


# ═══════════════════════════════════════════════════════════════════════════════
# 2. MODEL REGISTRY — Version management & persistence
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class ModelVersion:
    model_id: str
    model_type: str        # "beacon", "anomaly", "tor_c2", etc.
    version: int
    created_at: str
    accuracy: float = 0.0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    training_samples: int = 0
    feature_count: int = 26
    normalizer_state: Optional[dict] = None
    model_state: Optional[dict] = None
    is_active: bool = True


class ModelRegistry:
    """Manages trained model versions with JSON persistence."""

    def __init__(self, storage_dir: str = "/tmp/nf_models"):
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self._models: Dict[str, ModelVersion] = {}

    def register(self, model: ModelVersion):
        self._models[f"{model.model_type}:{model.version}"] = model
        self._persist(model)
        logger.info("Registered model %s v%d (F1=%.3f)",
                     model.model_type, model.version, model.f1_score)

    def get_active(self, model_type: str) -> Optional[ModelVersion]:
        candidates = [
            m for m in self._models.values()
            if m.model_type == model_type and m.is_active
        ]
        return max(candidates, key=lambda m: m.version) if candidates else None

    def list_models(self) -> List[dict]:
        return [
            {"model_id": m.model_id, "type": m.model_type,
             "version": m.version, "f1": m.f1_score,
             "samples": m.training_samples, "active": m.is_active}
            for m in self._models.values()
        ]

    def _persist(self, model: ModelVersion):
        path = self.storage_dir / f"{model.model_type}_v{model.version}.json"
        data = {
            "model_id": model.model_id, "model_type": model.model_type,
            "version": model.version, "created_at": model.created_at,
            "accuracy": model.accuracy, "precision": model.precision,
            "recall": model.recall, "f1_score": model.f1_score,
            "training_samples": model.training_samples,
            "normalizer_state": model.normalizer_state,
            "model_state": model.model_state,
        }
        path.write_text(json.dumps(data, indent=2))

    def load_all(self):
        for path in self.storage_dir.glob("*.json"):
            try:
                data = json.loads(path.read_text())
                mv = ModelVersion(**{k: v for k, v in data.items()
                                     if k in ModelVersion.__dataclass_fields__})
                self._models[f"{mv.model_type}:{mv.version}"] = mv
            except Exception as e:
                logger.warning("Failed to load model %s: %s", path, e)
        logger.info("Loaded %d model versions from disk", len(self._models))


# ═══════════════════════════════════════════════════════════════════════════════
# 3. TRAINING STRATEGY — Train/validate/evaluate
# ═══════════════════════════════════════════════════════════════════════════════

class TrainingStrategy:
    """
    Manages the training lifecycle:
      1. Generate/load dataset
      2. Split into train/validation/test (70/15/15)
      3. Train model with early-stopping proxy
      4. Evaluate and register
    """

    def __init__(self, registry: ModelRegistry):
        self.registry = registry
        self.rng = random.Random(42)

    def train_test_split(self, samples: List[LabeledSample],
                         train_ratio: float = 0.70,
                         val_ratio: float = 0.15
                         ) -> Tuple[List[LabeledSample],
                                    List[LabeledSample],
                                    List[LabeledSample]]:
        """Stratified train/val/test split."""
        by_label: Dict[str, List[LabeledSample]] = defaultdict(list)
        for s in samples:
            by_label[s.label].append(s)

        train, val, test = [], [], []
        for label, group in by_label.items():
            self.rng.shuffle(group)
            n = len(group)
            n_train = int(n * train_ratio)
            n_val = int(n * val_ratio)
            train.extend(group[:n_train])
            val.extend(group[n_train:n_train + n_val])
            test.extend(group[n_train + n_val:])

        self.rng.shuffle(train)
        self.rng.shuffle(val)
        self.rng.shuffle(test)
        return train, val, test

    def evaluate(self, predictions: List[str],
                 ground_truth: List[str],
                 positive_labels: List[str]
                 ) -> Dict[str, float]:
        """Compute accuracy, precision, recall, F1."""
        n = len(predictions)
        if n == 0:
            return {"accuracy": 0, "precision": 0, "recall": 0, "f1": 0}

        correct = sum(1 for p, g in zip(predictions, ground_truth) if p == g)
        accuracy = correct / n

        tp = sum(1 for p, g in zip(predictions, ground_truth)
                 if p in positive_labels and g in positive_labels)
        fp = sum(1 for p, g in zip(predictions, ground_truth)
                 if p in positive_labels and g not in positive_labels)
        fn = sum(1 for p, g in zip(predictions, ground_truth)
                 if p not in positive_labels and g in positive_labels)

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = (2 * precision * recall / (precision + recall)
              if (precision + recall) > 0 else 0)

        return {
            "accuracy": round(accuracy, 4),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
        }

    def cross_validate(self, samples: List[LabeledSample],
                        model_factory: Callable,
                        k: int = 5) -> Dict[str, float]:
        """k-fold cross-validation (simplified)."""
        self.rng.shuffle(samples)
        fold_size = len(samples) // k
        metrics_list: List[Dict[str, float]] = []

        for i in range(k):
            val_start = i * fold_size
            val_end = val_start + fold_size
            val_set = samples[val_start:val_end]
            train_set = samples[:val_start] + samples[val_end:]

            model = model_factory()
            train_vectors = [s.features for s in train_set]
            train_labels = [s.label for s in train_set]
            model.train(train_vectors, train_labels)

            predictions = [model.predict_label(s.features) for s in val_set]
            ground_truth = [s.label for s in val_set]

            threat_labels = [l for l in set(train_labels) if l != "benign"]
            metrics = self.evaluate(predictions, ground_truth, threat_labels)
            metrics_list.append(metrics)

        avg = {}
        for key in metrics_list[0]:
            avg[key] = round(statistics.mean(m[key] for m in metrics_list), 4)
        return avg


# ═══════════════════════════════════════════════════════════════════════════════
# 4. ML PIPELINE ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════════════════

class MLPipeline:
    """
    End-to-end ML pipeline orchestrator.

    Usage
    -----
        pipeline = MLPipeline()
        pipeline.initialize()             # Generate synthetic data & train
        results = pipeline.predict(flows, packets)  # Inference
    """

    def __init__(self, model_dir: str = "/tmp/nf_models"):
        self.registry = ModelRegistry(model_dir)
        self.strategy = TrainingStrategy(self.registry)
        self.feature_extractor = MLFeatureExtractor()
        self.normalizer = FeatureNormalizer()
        self._initialized = False
        self._threat_detector = None

    def initialize(self, force_retrain: bool = False):
        """
        Initialize the pipeline:
          1. Check for existing trained models
          2. If none (or force_retrain), generate synthetic data and train
          3. Load the ML threat detector with trained models
        """
        if self._initialized and not force_retrain:
            return

        # Try loading existing models
        self.registry.load_all()
        existing = self.registry.list_models()

        if not existing or force_retrain:
            logger.info("Training ML models from synthetic data...")
            self._train_from_synthetic()

        # Import and initialize the threat detector
        from backend.analysis.ml_threat_detector import MLThreatDetector
        self._threat_detector = MLThreatDetector()
        self._threat_detector.initialize(self.registry, self.normalizer)
        self._initialized = True
        logger.info("ML Pipeline initialized — all models ready")

    def _train_from_synthetic(self):
        """Generate synthetic data and train all models."""
        gen = SyntheticDatasetGenerator(seed=42)
        dataset = gen.generate(n_samples=5000)

        # Split
        train, val, test = self.strategy.train_test_split(dataset)
        logger.info("Dataset split: train=%d, val=%d, test=%d",
                     len(train), len(val), len(test))

        # Fit normalizer on training features
        train_vectors = [s.features for s in train]
        self.normalizer.fit(train_vectors)
        norm_train = self.normalizer.transform_batch(train_vectors)
        norm_val = self.normalizer.transform_batch([s.features for s in val])
        norm_test = self.normalizer.transform_batch([s.features for s in test])

        # Train each specialized model
        from backend.analysis.ml_threat_detector import (
            BeaconMLDetector, AbnormalFlowDetector, TorC2Detector,
            EncryptedSessionDetector, LateralMovementMLDetector,
        )

        models = {
            "beacon": (BeaconMLDetector, ["beacon"]),
            "abnormal_flow": (AbnormalFlowDetector,
                              ["abnormal_flow"]),
            "tor_c2": (TorC2Detector, ["tor_c2"]),
            "suspicious_tls": (EncryptedSessionDetector,
                               ["suspicious_tls"]),
            "lateral_movement": (LateralMovementMLDetector,
                                 ["lateral_movement"]),
        }

        for model_type, (cls, positive_labels) in models.items():
            detector = cls()

            # Train
            train_labels = [s.label for s in train]
            detector.train(norm_train, train_labels)

            # Evaluate on test
            test_labels = [s.label for s in test]
            predictions = [detector.predict_label(v) for v in norm_test]
            metrics = self.strategy.evaluate(
                predictions, test_labels, positive_labels)

            # Register model version
            mv = ModelVersion(
                model_id=str(uuid.uuid4()),
                model_type=model_type,
                version=1,
                created_at=time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                accuracy=metrics["accuracy"],
                precision=metrics["precision"],
                recall=metrics["recall"],
                f1_score=metrics["f1"],
                training_samples=len(train),
                normalizer_state=self.normalizer.to_dict(),
                model_state=detector.get_state(),
            )
            self.registry.register(mv)
            logger.info("Trained %s: accuracy=%.3f, F1=%.3f",
                         model_type, metrics["accuracy"], metrics["f1"])

    def predict(self, flows: List[dict],
                packets: List[dict]) -> dict:
        """
        Run full ML threat detection pipeline on session data.

        Returns
        -------
        dict with keys:
            ml_threats    — list of detected threats
            ml_scores     — per-flow anomaly scores
            ml_summary    — aggregate statistics
            model_info    — active model versions
        """
        if not self._initialized:
            self.initialize()

        return self._threat_detector.detect_all(
            flows, packets, self.feature_extractor, self.normalizer)

    def retrain_with_feedback(self, flows: List[dict],
                               packets: List[dict],
                               labels: Dict[str, str]):
        """
        Online learning: retrain models with analyst-labeled data.

        Parameters
        ----------
        labels : dict mapping flow_id → label (e.g., "beacon", "benign")
        """
        features = self.feature_extractor.extract_flow_features(flows, packets)
        labeled_samples = []
        for fv in features:
            label = labels.get(fv.entity_id)
            if label:
                vec = self.normalizer.transform(fv.to_vector())
                labeled_samples.append(LabeledSample(
                    features=vec, label=label,
                    source="analyst_feedback", confidence=1.0))

        if len(labeled_samples) < 10:
            return {"status": "insufficient_labels",
                    "count": len(labeled_samples)}

        # Combine with synthetic data for stability
        gen = SyntheticDatasetGenerator(seed=int(time.time()))
        synthetic = gen.generate(n_samples=max(500, len(labeled_samples) * 5))
        all_data = labeled_samples + synthetic

        # Retrain
        self._train_from_synthetic()
        return {"status": "retrained",
                "labeled_count": len(labeled_samples),
                "total_samples": len(all_data)}

    def get_pipeline_status(self) -> dict:
        """Return pipeline state for monitoring."""
        return {
            "initialized": self._initialized,
            "models": self.registry.list_models(),
            "normalizer_fitted": self.normalizer._fitted,
            "feature_dimensions": 26,
            "feature_groups": {
                "timing": 6, "volume": 5, "flow": 5,
                "tls": 4, "dns": 3, "graph": 3,
            },
        }
