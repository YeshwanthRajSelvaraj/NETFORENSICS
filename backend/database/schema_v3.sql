-- NetForensics v3 — Enterprise PostgreSQL Schema
-- ================================================
-- Extends base schema with enterprise features:
--   • Unified alerts table with MITRE mapping
--   • Investigation/case management
--   • Threat intelligence indicators
--   • Tor node registry
--   • Behavioral baselines
--   • DNS tunneling data
--   • Lateral movement tracking
--   • Browser extension data
--   • Audit logging
--   • ML model registry
--   • RBAC tables
-- Apply: psql -d netforensics -f schema_v3.sql

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- ── Include base schema (idempotent) ──────────────────────────────────────────
-- (capture_sessions, flows, packets, analysis_results, endpoint_profiles,
--  ja3_registry already exist from schema.sql)

-- ═══════════════════════════════════════════════════════════════════════════════
-- ENTERPRISE TABLES
-- ═══════════════════════════════════════════════════════════════════════════════

-- ── Unified Alerts ───────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS alerts (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id      UUID REFERENCES capture_sessions(id) ON DELETE CASCADE,
    alert_id        VARCHAR(20) NOT NULL UNIQUE,
    title           TEXT NOT NULL,
    severity        VARCHAR(20) NOT NULL CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO')),
    category        VARCHAR(50) NOT NULL,
    source_engine   VARCHAR(100) NOT NULL,
    affected_ips    JSONB DEFAULT '[]',
    evidence        JSONB DEFAULT '[]',
    mitre_techniques JSONB DEFAULT '[]',
    threat_score    DOUBLE PRECISION DEFAULT 0,
    status          VARCHAR(20) DEFAULT 'open'
                    CHECK (status IN ('open','investigating','resolved','false_positive','escalated')),
    assignee        VARCHAR(100),
    sla_deadline    TIMESTAMPTZ,
    sla_breached    BOOLEAN DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW(),
    resolved_at     TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_alerts_session   ON alerts(session_id);
CREATE INDEX IF NOT EXISTS idx_alerts_severity  ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_status    ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_category  ON alerts(category);
CREATE INDEX IF NOT EXISTS idx_alerts_created   ON alerts(created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_score     ON alerts(threat_score DESC);

-- ── Alert Comments ───────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS alert_comments (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    alert_id    UUID NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    author      VARCHAR(100) NOT NULL,
    comment     TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_comments_alert ON alert_comments(alert_id);

-- ── Investigations (Case Management) ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS investigations (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    case_number     VARCHAR(20) NOT NULL UNIQUE,
    title           TEXT NOT NULL,
    description     TEXT,
    status          VARCHAR(20) DEFAULT 'open'
                    CHECK (status IN ('open','in_progress','closed','archived')),
    priority        VARCHAR(20) DEFAULT 'medium'
                    CHECK (priority IN ('critical','high','medium','low')),
    lead_analyst    VARCHAR(100),
    classification  VARCHAR(20) DEFAULT 'TLP:AMBER'
                    CHECK (classification IN ('TLP:RED','TLP:AMBER','TLP:GREEN','TLP:CLEAR')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW(),
    closed_at       TIMESTAMPTZ,
    findings        TEXT,
    recommendations TEXT
);

-- ── Investigation Evidence ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS investigation_evidence (
    id                UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    investigation_id  UUID NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    evidence_type     VARCHAR(50) NOT NULL,  -- 'alert', 'flow', 'packet', 'screenshot', 'note'
    reference_id      UUID,                  -- FK to alerts/flows/etc
    description       TEXT,
    metadata          JSONB DEFAULT '{}',
    added_by          VARCHAR(100),
    added_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_evidence_inv ON investigation_evidence(investigation_id);

-- ── Threat Intelligence Indicators ───────────────────────────────────────────
CREATE TABLE IF NOT EXISTS threat_indicators (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    ioc_type        VARCHAR(20) NOT NULL CHECK (ioc_type IN ('ip','domain','ja3','url','hash')),
    value           TEXT NOT NULL,
    source          VARCHAR(100) NOT NULL,
    threat_type     VARCHAR(50),
    confidence      INTEGER CHECK (confidence BETWEEN 0 AND 100),
    severity        VARCHAR(20),
    tags            JSONB DEFAULT '[]',
    reference       TEXT,
    first_seen      TIMESTAMPTZ DEFAULT NOW(),
    last_seen       TIMESTAMPTZ DEFAULT NOW(),
    active          BOOLEAN DEFAULT TRUE,
    UNIQUE (ioc_type, value, source)
);

CREATE INDEX IF NOT EXISTS idx_ti_type   ON threat_indicators(ioc_type);
CREATE INDEX IF NOT EXISTS idx_ti_value  ON threat_indicators USING gin (value gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_ti_active ON threat_indicators(active) WHERE active = TRUE;

-- ── Threat Intel Feed Metadata ───────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS threat_intel_feeds (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name            VARCHAR(100) NOT NULL UNIQUE,
    feed_type       VARCHAR(20) CHECK (feed_type IN ('stix','csv','json','api')),
    url             TEXT,
    api_key_name    VARCHAR(50),  -- reference to secrets manager
    update_interval INTEGER DEFAULT 3600,  -- seconds
    last_update     TIMESTAMPTZ,
    indicator_count INTEGER DEFAULT 0,
    status          VARCHAR(20) DEFAULT 'active',
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- ── Tor Node Registry ────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS tor_nodes (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    ip              INET NOT NULL,
    port            INTEGER,
    node_type       VARCHAR(20) CHECK (node_type IN ('guard','relay','exit','bridge','authority')),
    fingerprint     VARCHAR(64),
    country         CHAR(2),
    bandwidth       BIGINT DEFAULT 0,
    flags           JSONB DEFAULT '[]',
    first_seen      TIMESTAMPTZ DEFAULT NOW(),
    last_seen       TIMESTAMPTZ DEFAULT NOW(),
    active          BOOLEAN DEFAULT TRUE,
    UNIQUE (ip, port)
);

CREATE INDEX IF NOT EXISTS idx_tor_ip    ON tor_nodes(ip);
CREATE INDEX IF NOT EXISTS idx_tor_type  ON tor_nodes(node_type);
CREATE INDEX IF NOT EXISTS idx_tor_active ON tor_nodes(active) WHERE active = TRUE;

-- ── Behavioral Baselines ─────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS behavioral_baselines (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    ip                  INET NOT NULL,
    baseline_period     VARCHAR(10) CHECK (baseline_period IN ('7d','30d','90d')),
    flow_count_mean     DOUBLE PRECISION,
    flow_count_mad      DOUBLE PRECISION,
    bytes_mean          DOUBLE PRECISION,
    bytes_mad           DOUBLE PRECISION,
    unique_dst_mean     DOUBLE PRECISION,
    session_dur_mean    DOUBLE PRECISION,
    tls_ratio_mean      DOUBLE PRECISION,
    active_hours        JSONB DEFAULT '[]',
    common_ports        JSONB DEFAULT '[]',
    common_destinations JSONB DEFAULT '[]',
    sample_count        INTEGER DEFAULT 0,
    computed_at         TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE (ip, baseline_period)
);

CREATE INDEX IF NOT EXISTS idx_baseline_ip ON behavioral_baselines(ip);

-- ── DNS Tunneling Alerts ─────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS dns_tunneling_alerts (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id      UUID REFERENCES capture_sessions(id) ON DELETE CASCADE,
    domain          VARCHAR(512) NOT NULL,
    src_ip          INET,
    alert_type      VARCHAR(50),
    entropy         DOUBLE PRECISION,
    query_count     INTEGER,
    confidence      VARCHAR(20),
    severity        VARCHAR(20),
    evidence        JSONB DEFAULT '[]',
    estimated_bytes INTEGER DEFAULT 0,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- ── Lateral Movement Alerts ──────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS lateral_movement_alerts (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id      UUID REFERENCES capture_sessions(id) ON DELETE CASCADE,
    alert_type      VARCHAR(50),
    src_ip          INET,
    dst_ip          INET,
    dst_port        INTEGER,
    confidence      VARCHAR(20),
    severity        VARCHAR(20),
    targets         JSONB DEFAULT '[]',
    evidence        JSONB DEFAULT '[]',
    mitre_technique VARCHAR(20),
    score           DOUBLE PRECISION DEFAULT 0,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- ── Browser Extension Data ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS browser_extension_data (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    agent_id        VARCHAR(64) NOT NULL,  -- hashed browser instance ID
    domain          VARCHAR(512),
    dns_time_ms     DOUBLE PRECISION,
    tcp_time_ms     DOUBLE PRECISION,
    tls_time_ms     DOUBLE PRECISION,
    request_size    INTEGER,
    response_size   INTEGER,
    http_version    VARCHAR(10),
    cert_issuer     VARCHAR(255),
    cert_expiry     TIMESTAMPTZ,
    tls_version     VARCHAR(20),
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ext_agent ON browser_extension_data(agent_id);
CREATE INDEX IF NOT EXISTS idx_ext_domain ON browser_extension_data(domain);
CREATE INDEX IF NOT EXISTS idx_ext_ts ON browser_extension_data(timestamp);

-- ── Audit Log ────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS audit_log (
    id          BIGSERIAL PRIMARY KEY,
    user_id     VARCHAR(100) NOT NULL,
    action      VARCHAR(50) NOT NULL,
    resource    VARCHAR(100),
    resource_id UUID,
    details     JSONB DEFAULT '{}',
    ip_address  INET,
    timestamp   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_ts   ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);

-- ── ML Model Registry ────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ml_model_registry (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    model_name      VARCHAR(100) NOT NULL,
    model_version   VARCHAR(20) NOT NULL,
    model_type      VARCHAR(50),  -- 'dga_detector', 'anomaly_detector', 'traffic_classifier'
    accuracy        DOUBLE PRECISION,
    f1_score        DOUBLE PRECISION,
    training_samples INTEGER,
    parameters      JSONB DEFAULT '{}',
    status          VARCHAR(20) DEFAULT 'active'
                    CHECK (status IN ('active','deprecated','training')),
    trained_at      TIMESTAMPTZ DEFAULT NOW(),
    deployed_at     TIMESTAMPTZ,
    UNIQUE (model_name, model_version)
);

-- ── RBAC: Users ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username    VARCHAR(100) NOT NULL UNIQUE,
    email       VARCHAR(255) UNIQUE,
    role        VARCHAR(20) NOT NULL DEFAULT 'analyst'
                CHECK (role IN ('admin','analyst','investigator','readonly')),
    active      BOOLEAN DEFAULT TRUE,
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    last_login  TIMESTAMPTZ
);

-- ── RBAC: API Keys ───────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS api_keys (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key_hash    VARCHAR(128) NOT NULL UNIQUE,
    name        VARCHAR(100),
    permissions JSONB DEFAULT '["read"]',
    expires_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    last_used   TIMESTAMPTZ
);

-- ═══════════════════════════════════════════════════════════════════════════════
-- VIEWS FOR COMMON QUERIES
-- ═══════════════════════════════════════════════════════════════════════════════

CREATE OR REPLACE VIEW v_active_threats AS
SELECT a.*, array_length(a.affected_ips::jsonb, 1) as ip_count
FROM alerts a
WHERE a.status IN ('open', 'investigating')
ORDER BY
    CASE a.severity WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3
                     WHEN 'MEDIUM' THEN 2 ELSE 1 END DESC,
    a.threat_score DESC;

CREATE OR REPLACE VIEW v_alert_metrics AS
SELECT
    date_trunc('hour', created_at) AS hour,
    severity,
    COUNT(*) AS alert_count,
    AVG(threat_score) AS avg_score,
    COUNT(*) FILTER (WHERE sla_breached) AS sla_breached_count
FROM alerts
GROUP BY date_trunc('hour', created_at), severity;

CREATE OR REPLACE VIEW v_tor_activity AS
SELECT
    t.ip, t.node_type, t.country,
    COUNT(DISTINCT f.src_ip) AS internal_connections,
    SUM(f.total_bytes) AS total_bytes,
    MAX(f.start_time) AS last_activity
FROM tor_nodes t
JOIN flows f ON (f.dst_ip = t.ip::text OR f.src_ip = t.ip::text)
WHERE t.active = TRUE
GROUP BY t.ip, t.node_type, t.country;
