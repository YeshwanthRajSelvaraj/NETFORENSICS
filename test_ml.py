"""End-to-end ML pipeline self-test."""
import sys
sys.path.insert(0, ".")

# 1. Feature vector
from backend.analysis.ml_features import MLFeatureExtractor, FeatureVector, FeatureNormalizer
fv = FeatureVector(entity_id="test_flow")
vec = fv.to_vector()
assert len(vec) == 26, f"Expected 26 features, got {len(vec)}"
assert len(FeatureVector.feature_names()) == 26
print(f"[OK] FeatureVector: 26 dims confirmed")

# 2. Synthetic dataset
from backend.analysis.ml_pipeline import SyntheticDatasetGenerator, TrainingStrategy, ModelRegistry
gen = SyntheticDatasetGenerator(seed=42)
ds = gen.generate(n_samples=500)
label_dist = {}
for s in ds:
    label_dist[s.label] = label_dist.get(s.label, 0) + 1
assert len(ds) >= 400, f"Expected >= 400 samples, got {len(ds)}"
assert "beacon" in label_dist, "Missing beacon class"
assert "lateral_movement" in label_dist, "Missing lateral_movement class"
print(f"[OK] Dataset: {len(ds)} samples -> {label_dist}")

# 3. Train/val/test split
reg = ModelRegistry("/tmp/nf_models_test")
strat = TrainingStrategy(reg)
train, val, test = strat.train_test_split(ds)
total = len(train) + len(val) + len(test)
assert total == len(ds), f"Split sizes don't add up: {total} != {len(ds)}"
print(f"[OK] Split: train={len(train)}, val={len(val)}, test={len(test)}")

# 4. Normalizer
norm = FeatureNormalizer()
vecs = [s.features for s in train]
norm.fit(vecs)
transformed = norm.transform_batch(vecs[:5])
assert all(0.0 <= x <= 1.0 for x in transformed[0]), "Normalization out of [0,1]"
print(f"[OK] Normalizer: fitted, first 5 dims={[round(x, 3) for x in transformed[0][:5]]}")

# 5. Isolation Forest
from backend.analysis.ml_threat_detector import PureIsolationForest
ifo = PureIsolationForest(n_trees=20, max_samples=64)
ifo.fit(vecs)
scores = ifo.score_batch([s.features for s in test[:5]])
assert all(0.0 <= s <= 1.0 for s in scores), f"IF scores out of range: {scores}"
print(f"[OK] Isolation Forest: 5 anomaly scores = {[round(s, 3) for s in scores]}")

# 6. WeightedScoringClassifier
from backend.analysis.ml_threat_detector import WeightedScoringClassifier
clf = WeightedScoringClassifier(n_features=26, positive_label="beacon")
norm_vecs = norm.transform_batch(vecs)
train_labels = [s.label for s in train]
clf.train(norm_vecs, train_labels)
beacon_samples = [s for s in test if s.label == "beacon"]
assert beacon_samples, "No beacon samples in test set"
beacon_vec = norm.transform(beacon_samples[0].features)
score = clf.score(beacon_vec)
print(f"[OK] WeightedClassifier: beacon sample score = {score:.3f}")

# 7. K-Means
from backend.analysis.ml_threat_detector import PureKMeans
km = PureKMeans(k=4)
km.fit(norm_vecs[:200])
cluster = km.predict(norm_vecs[0])
assert 0 <= cluster < 4, f"Cluster out of range: {cluster}"
print(f"[OK] K-Means: sample assigned to cluster {cluster}")

# 8. Evaluation metrics
predictions = [clf.predict_label(norm.transform(s.features)) for s in test]
labels = [s.label for s in test]
metrics = strat.evaluate(predictions, labels, ["beacon"])
print(f"[OK] Evaluation: accuracy={metrics['accuracy']:.3f}, "
      f"precision={metrics['precision']:.3f}, recall={metrics['recall']:.3f}, "
      f"F1={metrics['f1']:.3f}")

# 9. Feature extraction from mock flows
ext = MLFeatureExtractor()
flows = [
    {"flow_id": "f1", "src_ip": "192.168.1.10", "dst_ip": "8.8.8.8",
     "dst_port": 443, "protocol": "TLS", "total_bytes": 5000,
     "packet_count": 80, "session_duration": 600.0,
     "ja3": "abc123", "sni": "google.com", "tls_version": "TLS 1.3"},
    {"flow_id": "f2", "src_ip": "192.168.1.10", "dst_ip": "1.2.3.4",
     "dst_port": 9001, "protocol": "TLS", "total_bytes": 3000,
     "packet_count": 40, "session_duration": 1800.0, "ja3": "rare_xyz", "sni": ""},
    {"flow_id": "f3", "src_ip": "192.168.1.20", "dst_ip": "192.168.1.30",
     "dst_port": 445, "protocol": "SMB", "total_bytes": 500,
     "packet_count": 10, "session_duration": 2.0},
]
packets = [
    {"flow_id": "f1", "src_ip": "192.168.1.10", "dst_ip": "8.8.8.8",
     "timestamp": float(t), "size": 120}
    for t in range(0, 600, 10)
] + [
    {"flow_id": "f2", "src_ip": "192.168.1.10", "dst_ip": "1.2.3.4",
     "timestamp": float(t), "size": 250}
    for t in range(0, 1800, 60)
]
flow_feats = ext.extract_flow_features(flows, packets)
endpoint_feats = ext.extract_endpoint_features(flows, packets)
assert len(flow_feats) == 3, f"Expected 3 flow vectors, got {len(flow_feats)}"
assert len(endpoint_feats) == 2, f"Expected 2 endpoint vectors, got {len(endpoint_feats)}"
print(f"[OK] Feature extraction: {len(flow_feats)} flow vecs, {len(endpoint_feats)} endpoint vecs")

# 10. Full pipeline end-to-end
from backend.analysis.ml_pipeline import MLPipeline
pipeline = MLPipeline("/tmp/nf_models_test")
pipeline.initialize(force_retrain=True)
result = pipeline.predict(flows, packets)
assert "ml_threats" in result
assert "ml_clusters" in result
assert "ml_summary" in result
n_threats = len(result["ml_threats"])
n_clusters = len(result["ml_clusters"])
elapsed = result["ml_summary"].get("elapsed_seconds", -1)
print(f"[OK] Pipeline predict: {n_threats} threats, {n_clusters} clusters, {elapsed}s elapsed")
print(f"     ml_summary: {result['ml_summary']}")

# 11. Model registry
models = pipeline.registry.list_models()
assert len(models) >= 5, f"Expected >= 5 registered models, got {len(models)}"
print(f"[OK] Model registry: {len(models)} models registered")
for m in models:
    print(f"     {m['type']:20s}  v{m['version']}  F1={m['f1']:.3f}  samples={m['samples']}")

print()
print("=" * 50)
print("  ALL ML PIPELINE TESTS PASSED ")
print("=" * 50)
