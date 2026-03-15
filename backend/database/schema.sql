-- NetForensics — PostgreSQL Production Schema
-- Apply with: psql -d netforensics -f schema.sql

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- ── Capture Sessions ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS capture_sessions (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name          VARCHAR(255) NOT NULL,
    source_type   VARCHAR(20)  NOT NULL CHECK (source_type IN ('live','pcap','demo')),
    source_path   VARCHAR(512),
    interface     VARCHAR(100),
    status        VARCHAR(20)  NOT NULL DEFAULT 'running'
                               CHECK (status IN ('running','processing','completed','error')),
    started_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    ended_at      TIMESTAMPTZ,
    total_packets BIGINT       NOT NULL DEFAULT 0,
    total_flows   BIGINT       NOT NULL DEFAULT 0,
    metadata      JSONB        NOT NULL DEFAULT '{}'
);

-- ── Flows ─────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS flows (
    id               UUID      PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id       UUID      NOT NULL REFERENCES capture_sessions(id) ON DELETE CASCADE,
    flow_id          CHAR(16)  NOT NULL,
    src_ip           INET      NOT NULL,
    dst_ip           INET      NOT NULL,
    src_port         INTEGER,
    dst_port         INTEGER,
    protocol         VARCHAR(20) NOT NULL,
    start_time       TIMESTAMPTZ NOT NULL,
    end_time         TIMESTAMPTZ NOT NULL,
    session_duration DOUBLE PRECISION DEFAULT 0,
    packet_count     INTEGER   NOT NULL DEFAULT 0,
    total_bytes      BIGINT    NOT NULL DEFAULT 0,
    avg_packet_size  DOUBLE PRECISION,
    tls_version      VARCHAR(20),
    sni              VARCHAR(512),
    ja3              CHAR(32),
    ja3_string       TEXT,
    cipher_suites    JSONB,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_flows_session    ON flows(session_id);
CREATE INDEX IF NOT EXISTS idx_flows_src_ip     ON flows(src_ip);
CREATE INDEX IF NOT EXISTS idx_flows_dst_ip     ON flows(dst_ip);
CREATE INDEX IF NOT EXISTS idx_flows_protocol   ON flows(protocol);
CREATE INDEX IF NOT EXISTS idx_flows_start      ON flows(start_time);
CREATE INDEX IF NOT EXISTS idx_flows_ja3        ON flows(ja3) WHERE ja3 IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_flows_sni        ON flows(sni) WHERE sni IS NOT NULL;

-- ── Packets (metadata only — no payload) ─────────────────────────────────────
CREATE TABLE IF NOT EXISTS packets (
    id               BIGSERIAL   PRIMARY KEY,
    session_id       UUID        NOT NULL REFERENCES capture_sessions(id) ON DELETE CASCADE,
    flow_id          CHAR(16),
    timestamp        DOUBLE PRECISION NOT NULL,
    src_ip           INET,
    dst_ip           INET,
    src_port         INTEGER,
    dst_port         INTEGER,
    protocol         VARCHAR(20),
    size             INTEGER,
    ttl              SMALLINT,
    flags            VARCHAR(10),
    payload_entropy  DOUBLE PRECISION,
    dns_query        VARCHAR(512),
    dns_type         VARCHAR(10)
) PARTITION BY RANGE (timestamp);

-- Create initial partition (adjust ranges for production)
CREATE TABLE IF NOT EXISTS packets_default PARTITION OF packets DEFAULT;

CREATE INDEX IF NOT EXISTS idx_packets_session   ON packets(session_id);
CREATE INDEX IF NOT EXISTS idx_packets_flow      ON packets(flow_id) WHERE flow_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_packets_timestamp ON packets(timestamp);
CREATE INDEX IF NOT EXISTS idx_packets_src_ip    ON packets(src_ip);

-- ── Analysis Results ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS analysis_results (
    id            UUID      PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id    UUID      NOT NULL REFERENCES capture_sessions(id) ON DELETE CASCADE,
    analysis_type VARCHAR(50) NOT NULL,
    result_data   JSONB     NOT NULL,
    severity      VARCHAR(20),
    target_ip     INET,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_analysis_session  ON analysis_results(session_id);
CREATE INDEX IF NOT EXISTS idx_analysis_type     ON analysis_results(analysis_type);
CREATE INDEX IF NOT EXISTS idx_analysis_target   ON analysis_results(target_ip) WHERE target_ip IS NOT NULL;

-- ── Endpoint Profiles ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS endpoint_profiles (
    id                   UUID  PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id           UUID  NOT NULL REFERENCES capture_sessions(id) ON DELETE CASCADE,
    ip                   INET  NOT NULL,
    total_flows          INTEGER DEFAULT 0,
    total_bytes          BIGINT  DEFAULT 0,
    unique_destinations  INTEGER DEFAULT 0,
    unique_sources       INTEGER DEFAULT 0,
    protocols            JSONB,
    suspicion_score      DOUBLE PRECISION DEFAULT 0,
    suspicion_reasons    JSONB,
    tls_ratio            DOUBLE PRECISION,
    ja3_hashes           JSONB,
    sni_domains          JSONB,
    malware_ja3_matches  JSONB,
    first_seen           TIMESTAMPTZ,
    last_seen            TIMESTAMPTZ,
    geoip_country        CHAR(2),
    geoip_city           VARCHAR(100),
    geoip_org            VARCHAR(255),
    asn                  VARCHAR(50),
    reverse_dns          VARCHAR(255),
    updated_at           TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE (ip, session_id)
);

-- ── JA3 Fingerprint Registry ──────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ja3_registry (
    hash         CHAR(32)     PRIMARY KEY,
    ja3_string   TEXT,
    application  VARCHAR(255),
    known_malware VARCHAR(255),
    threat_level VARCHAR(20),
    first_seen   TIMESTAMPTZ  DEFAULT NOW(),
    hit_count    INTEGER      DEFAULT 1
);

-- Seed known malware hashes
INSERT INTO ja3_registry (hash, application, known_malware, threat_level) VALUES
('e7d705a3286e19ea42f587b344ee6865', 'Cobalt Strike beacon',   'Cobalt Strike',        'critical'),
('6734f37431670b3ab4292b8f60f29984', 'Metasploit Meterpreter', 'Metasploit',           'critical'),
('a0e9f5d64349fb13191bc781f81f42e1', 'Metasploit stager',      'Metasploit',           'critical'),
('de9f2c7fd25e1b3afad3e85a0226823f', 'TrickBot banking trojan','TrickBot / Emotet',    'critical'),
('e7eca2baf4458d095b7f45da28c16c34', 'Dridex banking trojan',  'Dridex',               'critical'),
('b386946a5a44d1ddcc843bc75336dfce', 'Trickbot HTTPS comms',   'TrickBot',             'critical'),
('192a954d99b56e72cc6fcd974b862bb9', 'AgentTesla stealer',     'AgentTesla',           'high')
ON CONFLICT (hash) DO NOTHING;
