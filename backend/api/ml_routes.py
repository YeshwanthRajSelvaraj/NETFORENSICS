"""
NetForensics — ML API Routes v4
=================================
FastAPI endpoints for the ML threat detection pipeline:

  POST /api/v4/ml/initialize            — Initialize / train models
  GET  /api/v4/ml/status                — Pipeline state & model registry
  POST /api/v4/ml/train/synthetic       — Retrain on fresh synthetic data
  POST /api/v4/ml/train/feedback        — Online retrain with analyst labels
  GET  /api/v4/ml/analyze/{sid}         — Full ML analysis on a session
  GET  /api/v4/ml/threats/{sid}         — ML-detected threats only
  GET  /api/v4/ml/clusters/{sid}        — Flow cluster profiles
  GET  /api/v4/ml/scores/{sid}          — Per-flow anomaly scores
  POST /api/v4/ml/dga/batch             — Batch DGA domain scoring
  GET  /api/v4/ml/beacon/{sid}          — Beacon detection results
  GET  /api/v4/ml/lateral/{sid}         — Lateral movement ML results
  GET  /api/v4/ml/tor/{sid}             — Tor C2 ML results
  GET  /api/v4/ml/encrypted/{sid}       — Suspicious TLS ML results
  GET  /api/v4/ml/models                — Registered model versions
  POST /api/v4/ml/models/retrain        — Force full retrain
  GET  /api/v4/ml/features/{sid}        — Feature vectors (for debugging)
  GET  /api/v4/ml/pipeline/dataset      — Synthetic dataset sample
"""

import json
import logging
import time
import uuid
from typing import Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query
from pydantic import BaseModel

logger = logging.getLogger("netforensics.api.ml")

router = APIRouter(prefix="/api/v4/ml", tags=["ML Threat Detection v4"])

# ─── Lazy-init ML Pipeline singleton ─────────────────────────────────────────

_pipeline = None


def _get_pipeline():
    global _pipeline
    if _pipeline is None:
        from backend.analysis.ml_pipeline import MLPipeline
        _pipeline = MLPipeline(model_dir="/tmp/nf_models")
    return _pipeline


async def _load_session(sid: str):
    """Helper: load flows + packets for a session from SQLite."""
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


async def _persist_ml_results(sid: str, results: dict):
    """Persist ML analysis results to SQLite."""
    import aiosqlite, os
    DB_PATH = os.environ.get("NF_DB", "/tmp/netforensics.db")
    db = await aiosqlite.connect(DB_PATH)
    try:
        await db.execute(
            "INSERT INTO analysis_results(id,session_id,analysis_type,"
            "result_data,created_at) VALUES(?,?,?,?,?)",
            (str(uuid.uuid4()), sid, "ml_analysis",
             json.dumps(results, default=str),
             time.strftime("%Y-%m-%dT%H:%M:%SZ")))
        await db.commit()
    finally:
        await db.close()


# ═══════════════════════════════════════════════════════════════════════════════
# PIPELINE LIFECYCLE
# ═══════════════════════════════════════════════════════════════════════════════

@router.post("/initialize")
async def initialize_pipeline(force: bool = Query(False)):
    """
    Initialize the ML pipeline.
    On first call: generates 5000-sample synthetic dataset and trains all models.
    Subsequent calls: loads cached model weights from disk.

    Set `force=true` to retrain from scratch.
    """
    pipeline = _get_pipeline()
    t0 = time.time()
    pipeline.initialize(force_retrain=force)
    elapsed = round(time.time() - t0, 2)
    return {
        "status": "initialized",
        "elapsed_seconds": elapsed,
        "force_retrain": force,
        **pipeline.get_pipeline_status(),
    }


@router.get("/status")
async def pipeline_status():
    """Return current pipeline state, model registry, and feature schema."""
    pipeline = _get_pipeline()
    status = pipeline.get_pipeline_status()
    from backend.analysis.ml_features import FeatureVector
    status["feature_names"] = FeatureVector.feature_names()
    status["detection_engines"] = [
        {"name": "BeaconMLDetector",
         "technique": "Isolation Forest + EWMA Periodicity (LSTM-proxy)",
         "features": "timing (6) + volume (5)",
         "mitre": "T1071.001"},
        {"name": "AbnormalFlowDetector",
         "technique": "Isolation Forest + per-protocol Z-score",
         "features": "volume (5) + flow (5)",
         "mitre": "T1071"},
        {"name": "TorC2Detector",
         "technique": "Graph GNN-proxy + JA3 rarity + port analysis",
         "features": "graph (3) + TLS (4) + flow (5)",
         "mitre": "T1090.003"},
        {"name": "EncryptedSessionDetector",
         "technique": "K-Means clustering on TLS feature quadrant + IF",
         "features": "TLS (4) + timing (6)",
         "mitre": "T1573.002"},
        {"name": "LateralMovementMLDetector",
         "technique": "Graph centrality (GNN-proxy) + K-Means + port entropy",
         "features": "graph (3) + flow (5) + timing (6)",
         "mitre": "T1021"},
    ]
    return status


@router.get("/models")
async def list_models():
    """List all registered ML model versions with performance metrics."""
    pipeline = _get_pipeline()
    if not pipeline._initialized:
        pipeline.initialize()
    return {
        "models": pipeline.registry.list_models(),
        "total": len(pipeline.registry.list_models()),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# TRAINING ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

@router.post("/train/synthetic")
async def train_synthetic(
    bg: BackgroundTasks,
    n_samples: int = Query(5000, ge=500, le=50000),
):
    """
    Retrain all ML models on a freshly generated synthetic dataset.
    Runs in background — use /status to monitor progress.
    """
    def _do_train():
        from backend.analysis.ml_pipeline import SyntheticDatasetGenerator
        pipeline = _get_pipeline()
        gen = SyntheticDatasetGenerator(seed=int(time.time()))
        dataset = gen.generate(n_samples=n_samples)
        train, val, test = pipeline.strategy.train_test_split(dataset)
        pipeline._train_from_synthetic()
        logger.info("Synthetic retrain complete: %d samples", n_samples)

    bg.add_task(_do_train)
    return {
        "status": "training_queued",
        "n_samples": n_samples,
        "message": "Training in background. Check /api/v4/ml/status for completion.",
    }


class FeedbackRequest(BaseModel):
    session_id: str
    labels: Dict[str, str]   # flow_id → label


@router.post("/train/feedback")
async def train_with_feedback(req: FeedbackRequest, bg: BackgroundTasks):
    """
    Online learning: retrain models using analyst-labeled flows.

    Labels should be one of:
      'benign', 'beacon', 'abnormal_flow', 'tor_c2',
      'suspicious_tls', 'lateral_movement'
    """
    flows, packets = await _load_session(req.session_id)
    if not flows:
        raise HTTPException(404, "Session not found or empty")

    valid_labels = {"benign", "beacon", "abnormal_flow",
                    "tor_c2", "suspicious_tls", "lateral_movement"}
    invalid = {v for v in req.labels.values() if v not in valid_labels}
    if invalid:
        raise HTTPException(400, f"Invalid labels: {invalid}. "
                                  f"Valid: {valid_labels}")

    pipeline = _get_pipeline()
    if not pipeline._initialized:
        pipeline.initialize()

    def _do_retrain():
        result = pipeline.retrain_with_feedback(flows, packets, req.labels)
        logger.info("Feedback retrain: %s", result)

    bg.add_task(_do_retrain)
    return {
        "status": "feedback_accepted",
        "session_id": req.session_id,
        "label_count": len(req.labels),
        "message": "Retraining with feedback in background.",
    }


@router.post("/models/retrain")
async def force_retrain(bg: BackgroundTasks):
    """Force a complete model retrain from synthetic data."""
    def _retrain():
        pipeline = _get_pipeline()
        pipeline.initialize(force_retrain=True)

    bg.add_task(_retrain)
    return {"status": "retrain_queued",
            "message": "Full retrain started in background."}


# ═══════════════════════════════════════════════════════════════════════════════
# ANALYSIS ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

@router.get("/analyze/{sid}")
async def full_ml_analysis(sid: str):
    """
    Run the complete ML threat detection pipeline on a session.
    This runs all 5 detection engines + K-Means clustering.

    Returns:
      - ml_threats:   Ranked list of all detected threats
      - ml_clusters:  Flow behavioral cluster profiles (K-Means, k=6)
      - ml_scores:    Per-flow anomaly scores (Isolation Forest)
      - ml_summary:   Aggregate counts by threat type
      - detection_modules: Per-engine technique descriptions
    """
    flows, packets = await _load_session(sid)
    if not flows:
        raise HTTPException(404, "Session not found or has no flows")

    pipeline = _get_pipeline()
    if not pipeline._initialized:
        pipeline.initialize()

    results = pipeline.predict(flows, packets)

    # Persist ML results alongside other analyses
    await _persist_ml_results(sid, results)

    return results


@router.get("/threats/{sid}")
async def ml_threats(
    sid: str,
    min_score: float = Query(0.0, ge=0.0, le=1.0),
    threat_type: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = Query(50, le=200),
):
    """
    Return ML-detected threats filtered by score / type / severity.

    threat_type options:
      malware_beaconing, abnormal_traffic_flow, tor_c2,
      suspicious_encrypted_session, lateral_movement
    """
    flows, packets = await _load_session(sid)
    if not flows:
        raise HTTPException(404, "Session not found or has no flows")

    pipeline = _get_pipeline()
    if not pipeline._initialized:
        pipeline.initialize()

    results = pipeline.predict(flows, packets)
    threats = results.get("ml_threats", [])

    # Apply filters
    if min_score > 0:
        threats = [t for t in threats if t["score"] >= min_score]
    if threat_type:
        threats = [t for t in threats if t["threat_type"] == threat_type]
    if severity:
        threats = [t for t in threats if t["severity"] == severity.upper()]

    return {
        "threats": threats[:limit],
        "total": len(threats),
        "session_id": sid,
        "filters_applied": {
            "min_score": min_score,
            "threat_type": threat_type,
            "severity": severity,
        },
    }


@router.get("/clusters/{sid}")
async def ml_clusters(sid: str):
    """
    Return K-Means flow clusters with behavioral labels.
    Clusters represent discovered traffic archetypes:
      periodic_c2, scanning_lateral, bulk_transfer,
      dga_dns, suspicious_tls, normal_traffic
    """
    flows, packets = await _load_session(sid)
    if not flows:
        raise HTTPException(404, "Session not found")

    pipeline = _get_pipeline()
    if not pipeline._initialized:
        pipeline.initialize()

    results = pipeline.predict(flows, packets)
    return {
        "clusters": results.get("ml_clusters", []),
        "session_id": sid,
        "k": 6,
        "algorithm": "K-Means (Lloyd's, KMeans++ init, k=6)",
    }


@router.get("/scores/{sid}")
async def ml_scores(
    sid: str,
    min_anomaly: float = Query(0.6, ge=0.0, le=1.0),
):
    """
    Return per-flow Isolation Forest anomaly scores.
    Score > 0.6 generally indicates an anomalous flow.
    """
    flows, packets = await _load_session(sid)
    if not flows:
        raise HTTPException(404, "Session not found")

    pipeline = _get_pipeline()
    if not pipeline._initialized:
        pipeline.initialize()

    results = pipeline.predict(flows, packets)
    scores = results.get("ml_scores", {})

    # Filter and sort by anomaly score
    filtered = {
        fid: s for fid, s in scores.items()
        if s.get("anomaly_score", 0) >= min_anomaly
    }
    sorted_scores = sorted(
        [{"flow_id": k, **v} for k, v in filtered.items()],
        key=lambda x: x["anomaly_score"], reverse=True)

    return {
        "scores": sorted_scores[:200],
        "total_flows": len(scores),
        "anomalous_count": len(filtered),
        "session_id": sid,
        "threshold": min_anomaly,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# PER-DETECTOR ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

@router.get("/beacon/{sid}")
async def ml_beacon(
    sid: str,
    min_score: float = Query(0.40, ge=0.0, le=1.0),
):
    """Malware beaconing detection (Isolation Forest + EWMA Periodicity)."""
    flows, packets = await _load_session(sid)
    if not flows:
        raise HTTPException(404, "Session not found")

    pipeline = _get_pipeline()
    if not pipeline._initialized:
        pipeline.initialize()

    results = pipeline.predict(flows, packets)
    threats = [t for t in results.get("ml_threats", [])
               if t["threat_type"] == "malware_beaconing"
               and t["score"] >= min_score]

    return {
        "beacon_threats": threats,
        "count": len(threats),
        "technique": "Isolation Forest + EWMA Periodicity (LSTM-proxy)",
        "features_used": ["interval_mean", "interval_cv", "periodicity_score",
                           "interval_jitter", "burst_ratio", "ja3_rarity"],
        "mitre": "T1071.001",
    }


@router.get("/lateral/{sid}")
async def ml_lateral(
    sid: str,
    min_score: float = Query(0.38, ge=0.0, le=1.0),
):
    """Lateral movement ML detection (Graph GNN-proxy + K-Means)."""
    flows, packets = await _load_session(sid)
    if not flows:
        raise HTTPException(404, "Session not found")

    pipeline = _get_pipeline()
    if not pipeline._initialized:
        pipeline.initialize()

    results = pipeline.predict(flows, packets)
    threats = [t for t in results.get("ml_threats", [])
               if t["threat_type"] == "lateral_movement"
               and t["score"] >= min_score]

    return {
        "lateral_threats": threats,
        "count": len(threats),
        "technique": "Graph GNN-proxy (betweenness + fan-out centrality) + Weighted Classifier",
        "features_used": ["fan_out", "port_entropy", "betweenness_proxy",
                           "interval_mean", "burst_ratio", "unique_dst_ratio"],
        "mitre": "T1021",
    }


@router.get("/tor/{sid}")
async def ml_tor(
    sid: str,
    min_score: float = Query(0.38, ge=0.0, le=1.0),
):
    """Tor-based C2 ML detection (JA3 rarity + graph + port analysis)."""
    flows, packets = await _load_session(sid)
    if not flows:
        raise HTTPException(404, "Session not found")

    pipeline = _get_pipeline()
    if not pipeline._initialized:
        pipeline.initialize()

    results = pipeline.predict(flows, packets)
    threats = [t for t in results.get("ml_threats", [])
               if t["threat_type"] == "tor_c2"
               and t["score"] >= min_score]

    return {
        "tor_c2_threats": threats,
        "count": len(threats),
        "technique": "Graph GNN-proxy + JA3 rarity + SNI entropy + Port scoring",
        "features_used": ["ja3_rarity", "sni_entropy", "fan_out",
                           "betweenness_proxy", "dst_port_norm",
                           "tls_version_score"],
        "mitre": "T1090.003",
    }


@router.get("/encrypted/{sid}")
async def ml_encrypted(
    sid: str,
    min_score: float = Query(0.40, ge=0.0, le=1.0),
):
    """Suspicious TLS detection (K-Means clustering + IF on TLS features)."""
    flows, packets = await _load_session(sid)
    if not flows:
        raise HTTPException(404, "Session not found")

    pipeline = _get_pipeline()
    if not pipeline._initialized:
        pipeline.initialize()

    results = pipeline.predict(flows, packets)
    threats = [t for t in results.get("ml_threats", [])
               if t["threat_type"] == "suspicious_encrypted_session"
               and t["score"] >= min_score]

    return {
        "encrypted_threats": threats,
        "count": len(threats),
        "technique": "K-Means clustering (k=5) on TLS feature quadrant + Isolation Forest",
        "features_used": ["ja3_rarity", "sni_entropy", "sni_length_norm",
                           "tls_version_score", "pkt_size_stdev"],
        "mitre": "T1573.002",
    }


# ═══════════════════════════════════════════════════════════════════════════════
# DGA BATCH SCORING
# ═══════════════════════════════════════════════════════════════════════════════

class DGABatchRequest(BaseModel):
    domains: List[str]
    threshold: float = 0.55


@router.post("/dga/batch")
async def dga_batch(req: DGABatchRequest):
    """
    Score multiple domains for DGA likelihood using the ML model.
    Returns scores and predicted DGA family for each domain.
    """
    from backend.analysis.ml_models import DGAMLDetector
    detector = DGAMLDetector()
    results = detector.predict_batch(req.domains[:1000])  # cap at 1000
    return {
        "results": [
            {
                "domain":     r.domain,
                "score":      r.score,
                "is_dga":     r.is_dga,
                "family":     r.family,
                "confidence": r.confidence,
                "features":   r.features,
            }
            for r in results
        ],
        "total": len(results),
        "dga_count": sum(1 for r in results if r.is_dga),
        "threshold": req.threshold,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# FEATURE INSPECTION (Debug / Explainability)
# ═══════════════════════════════════════════════════════════════════════════════

@router.get("/features/{sid}")
async def get_features(
    sid: str,
    entity_type: str = Query("flow", pattern="^(flow|endpoint)$"),
    limit: int = Query(50, le=500),
):
    """
    Return extracted feature vectors for a session.
    Useful for debugging, model validation, and explainability.

    entity_type: 'flow' or 'endpoint'
    """
    flows, packets = await _load_session(sid)
    if not flows:
        raise HTTPException(404, "Session not found")

    from backend.analysis.ml_features import MLFeatureExtractor, FeatureVector

    extractor = MLFeatureExtractor()

    if entity_type == "flow":
        features = extractor.extract_flow_features(flows, packets)
    else:
        features = extractor.extract_endpoint_features(flows, packets)

    feature_names = FeatureVector.feature_names()

    return {
        "entity_type": entity_type,
        "feature_count": 26,
        "feature_names": feature_names,
        "vectors": [
            {
                "entity_id": fv.entity_id,
                "features": dict(zip(feature_names, fv.to_vector())),
                "raw_vector": fv.to_vector(),
            }
            for fv in features[:limit]
        ],
        "total": len(features),
        "session_id": sid,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# SYNTHETIC DATASET PREVIEW
# ═══════════════════════════════════════════════════════════════════════════════

@router.get("/pipeline/dataset")
async def dataset_preview(
    n_samples: int = Query(100, ge=10, le=1000),
    label_filter: Optional[str] = None,
):
    """
    Generate and preview a sample of the synthetic training dataset.
    Useful for understanding what the models are trained on.
    """
    from backend.analysis.ml_pipeline import SyntheticDatasetGenerator
    from backend.analysis.ml_features import FeatureVector

    gen = SyntheticDatasetGenerator(seed=42)
    dataset = gen.generate(n_samples=n_samples)

    if label_filter:
        dataset = [s for s in dataset if s.label == label_filter]

    feature_names = FeatureVector.feature_names()
    label_dist = {}
    for s in dataset:
        label_dist[s.label] = label_dist.get(s.label, 0) + 1

    return {
        "total_samples": len(dataset),
        "label_distribution": label_dist,
        "feature_names": feature_names,
        "samples": [
            {
                "label": s.label,
                "confidence": s.confidence,
                "source": s.source,
                "features": dict(zip(feature_names, s.features)),
            }
            for s in dataset[:50]
        ],
        "dataset_design": {
            "benign": "60% — normal web/email/DNS traffic",
            "beacon": "10% — periodic C2, low interval CV, high periodicity",
            "abnormal_flow": "8% — volumetric anomalies, burst patterns",
            "tor_c2": "7% — Tor exit, rare JA3, low fan-out",
            "suspicious_tls": "8% — rare JA3, no-SNI, deprecated TLS",
            "lateral_movement": "7% — high fan-out, admin ports, high port entropy",
        },
    }


# ═══════════════════════════════════════════════════════════════════════════════
# HEALTH
# ═══════════════════════════════════════════════════════════════════════════════

@router.get("/health")
async def ml_health():
    """ML subsystem health check."""
    pipeline = _get_pipeline()
    return {
        "status": "ok",
        "ml_version": "4.0.0",
        "initialized": pipeline._initialized,
        "engines": [
            "BeaconMLDetector",
            "AbnormalFlowDetector",
            "TorC2Detector",
            "EncryptedSessionDetector",
            "LateralMovementMLDetector",
            "K-MeansFlowClusterer",
        ],
        "features": 26,
        "feature_groups": {
            "timing": 6, "volume": 5, "flow": 5,
            "tls": 4, "dns": 3, "graph": 3,
        },
        "techniques": [
            "Isolation Forest",
            "LSTM-proxy (EWMA periodicity)",
            "K-Means Clustering",
            "Graph Neural Network proxy",
            "Weighted Gradient-Free Classifier",
        ],
    }
