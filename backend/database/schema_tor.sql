-- NetForensics — Tor Analysis Schema Extension
-- ================================================
-- Extended tables for comprehensive Tor traffic analysis
-- Apply after schema_v3.sql

-- ── Tor Detection Events ─────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS tor_events (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id      UUID REFERENCES capture_sessions(id) ON DELETE CASCADE,
    event_type      VARCHAR(50) NOT NULL,
    sub_type        VARCHAR(50),
    src_ip          INET NOT NULL,
    dst_ip          INET,
    dst_port        INTEGER,
    confidence      DOUBLE PRECISION CHECK (confidence BETWEEN 0 AND 1),
    severity        VARCHAR(20) CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW')),
    score           DOUBLE PRECISION DEFAULT 0,
    evidence        JSONB DEFAULT '[]',
    tor_node_type   VARCHAR(20),
    mitre_technique VARCHAR(20) DEFAULT 'T1090.003',
    circuit_id      VARCHAR(16),
    metadata        JSONB DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_tor_evt_session  ON tor_events(session_id);
CREATE INDEX IF NOT EXISTS idx_tor_evt_type     ON tor_events(event_type);
CREATE INDEX IF NOT EXISTS idx_tor_evt_src      ON tor_events(src_ip);
CREATE INDEX IF NOT EXISTS idx_tor_evt_severity ON tor_events(severity);
CREATE INDEX IF NOT EXISTS idx_tor_evt_score    ON tor_events(score DESC);
CREATE INDEX IF NOT EXISTS idx_tor_evt_ts       ON tor_events(created_at);

-- ── Tor Circuits ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS tor_circuits (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id      UUID REFERENCES capture_sessions(id) ON DELETE CASCADE,
    circuit_id      VARCHAR(16) NOT NULL,
    src_ip          INET NOT NULL,
    hops            JSONB NOT NULL DEFAULT '[]',
    hop_count       INTEGER NOT NULL DEFAULT 0,
    guard_ip        INET,
    exit_ip         INET,
    build_time_ms   DOUBLE PRECISION,
    duration        DOUBLE PRECISION DEFAULT 0,
    packet_count    INTEGER DEFAULT 0,
    total_bytes     BIGINT DEFAULT 0,
    cell_ratio      DOUBLE PRECISION DEFAULT 0,
    is_hidden_service BOOLEAN DEFAULT FALSE,
    rendezvous_ip   INET,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_tor_circ_session ON tor_circuits(session_id);
CREATE INDEX IF NOT EXISTS idx_tor_circ_src     ON tor_circuits(src_ip);
CREATE INDEX IF NOT EXISTS idx_tor_circ_guard   ON tor_circuits(guard_ip);
CREATE INDEX IF NOT EXISTS idx_tor_circ_hs      ON tor_circuits(is_hidden_service) WHERE is_hidden_service;

-- ── Hidden Service Indicators ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS tor_hidden_service_indicators (
    id                    UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id            UUID REFERENCES capture_sessions(id) ON DELETE CASCADE,
    src_ip                INET NOT NULL,
    rendezvous_candidates JSONB DEFAULT '[]',
    confidence            DOUBLE PRECISION,
    duration              DOUBLE PRECISION,
    evidence              JSONB DEFAULT '[]',
    estimated_circuits    INTEGER DEFAULT 0,
    data_volume_bytes     BIGINT DEFAULT 0,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_tor_hs_session ON tor_hidden_service_indicators(session_id);
CREATE INDEX IF NOT EXISTS idx_tor_hs_src     ON tor_hidden_service_indicators(src_ip);

-- ── Tor C2 Indicators ───────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS tor_c2_indicators (
    id                    UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id            UUID REFERENCES capture_sessions(id) ON DELETE CASCADE,
    src_ip                INET NOT NULL,
    guard_ip              INET,
    beacon_interval_mean  DOUBLE PRECISION,
    beacon_interval_cv    DOUBLE PRECISION,
    session_count         INTEGER DEFAULT 0,
    total_duration        DOUBLE PRECISION DEFAULT 0,
    confidence            DOUBLE PRECISION,
    evidence              JSONB DEFAULT '[]',
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_tor_c2_session ON tor_c2_indicators(session_id);
CREATE INDEX IF NOT EXISTS idx_tor_c2_src     ON tor_c2_indicators(src_ip);

-- ── Tor Node Consensus Log ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS tor_consensus_log (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    consensus_date  DATE NOT NULL,
    total_relays    INTEGER DEFAULT 0,
    total_exits     INTEGER DEFAULT 0,
    total_guards    INTEGER DEFAULT 0,
    total_bridges   INTEGER DEFAULT 0,
    total_bandwidth BIGINT DEFAULT 0,
    fetched_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (consensus_date)
);

-- ── Tor Flow Entropy Profiles ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS tor_entropy_profiles (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id      UUID REFERENCES capture_sessions(id) ON DELETE CASCADE,
    src_ip          INET NOT NULL,
    dst_ip          INET NOT NULL,
    size_entropy    DOUBLE PRECISION,
    time_entropy    DOUBLE PRECISION,
    packet_count    INTEGER DEFAULT 0,
    mean_size       DOUBLE PRECISION,
    cell_ratio      DOUBLE PRECISION DEFAULT 0,
    is_tor_like     BOOLEAN DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_tor_ent_session ON tor_entropy_profiles(session_id);

-- ═══════════════════════════════════════════════════════════════════════════════
-- VIEWS
-- ═══════════════════════════════════════════════════════════════════════════════

CREATE OR REPLACE VIEW v_tor_dashboard AS
SELECT
    te.session_id,
    te.event_type,
    te.sub_type,
    te.severity,
    COUNT(*) AS event_count,
    AVG(te.score) AS avg_score,
    MAX(te.score) AS max_score,
    COUNT(DISTINCT te.src_ip) AS unique_sources,
    COUNT(DISTINCT te.dst_ip) AS unique_destinations
FROM tor_events te
GROUP BY te.session_id, te.event_type, te.sub_type, te.severity;

CREATE OR REPLACE VIEW v_tor_internal_users AS
SELECT
    te.src_ip,
    COUNT(*) AS total_events,
    MAX(te.score) AS max_score,
    array_agg(DISTINCT te.event_type) AS event_types,
    COUNT(DISTINCT te.dst_ip) AS tor_nodes_contacted,
    MAX(te.created_at) AS last_activity,
    bool_or(EXISTS(
        SELECT 1 FROM tor_hidden_service_indicators h WHERE h.src_ip = te.src_ip
    )) AS has_hs_indicators,
    bool_or(EXISTS(
        SELECT 1 FROM tor_c2_indicators c WHERE c.src_ip = te.src_ip
    )) AS has_c2_indicators
FROM tor_events te
WHERE te.src_ip << '10.0.0.0/8'
   OR te.src_ip << '172.16.0.0/12'
   OR te.src_ip << '192.168.0.0/16'
GROUP BY te.src_ip
ORDER BY max_score DESC;

CREATE OR REPLACE VIEW v_tor_timeline AS
SELECT
    date_trunc('minute', te.created_at) AS minute,
    te.event_type,
    te.severity,
    COUNT(*) AS event_count,
    AVG(te.score) AS avg_score
FROM tor_events te
GROUP BY date_trunc('minute', te.created_at), te.event_type, te.severity
ORDER BY minute;
