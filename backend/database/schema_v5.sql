-- NetForensics v5 — Enterprise Schema Extension
-- =================================================
-- Adds tables for the 10 new enterprise features.
-- Apply after schema_v3.sql:
--   psql -d netforensics -f schema_v5.sql
-- For SQLite dev mode, these are created via Python on startup.

-- ═══════════════════════════════════════════════════════════════════════════════
-- 1. MULTI-TENANT ARCHITECTURE
-- ═══════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS tenants (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name            VARCHAR(255) NOT NULL,
    slug            VARCHAR(64) NOT NULL UNIQUE,
    plan            VARCHAR(20) DEFAULT 'enterprise'
                    CHECK (plan IN ('community','professional','enterprise')),
    max_users       INTEGER DEFAULT 100,
    max_sessions    INTEGER DEFAULT 10000,
    features        JSONB DEFAULT '[]',
    active          BOOLEAN DEFAULT TRUE,
    settings        JSONB DEFAULT '{}',
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- Extend existing tables with tenant_id
ALTER TABLE capture_sessions ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id);
ALTER TABLE alerts           ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id);
ALTER TABLE investigations   ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id);
ALTER TABLE threat_indicators ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id);

CREATE INDEX IF NOT EXISTS idx_sessions_tenant ON capture_sessions(tenant_id);
CREATE INDEX IF NOT EXISTS idx_alerts_tenant   ON alerts(tenant_id);
CREATE INDEX IF NOT EXISTS idx_inv_tenant      ON investigations(tenant_id);

-- ═══════════════════════════════════════════════════════════════════════════════
-- 2. ENHANCED RBAC
-- ═══════════════════════════════════════════════════════════════════════════════

-- Extend users table
ALTER TABLE users ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id);
ALTER TABLE users ADD COLUMN IF NOT EXISTS display_name VARCHAR(255);
ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash VARCHAR(512);
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_enabled BOOLEAN DEFAULT FALSE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_secret VARCHAR(64);
ALTER TABLE users ADD COLUMN IF NOT EXISTS failed_logins INTEGER DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS locked_until TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN IF NOT EXISTS preferences JSONB DEFAULT '{}';

-- Drop old role constraint and add new one
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_role_check;
ALTER TABLE users ADD CONSTRAINT users_role_check
    CHECK (role IN ('platform_admin','tenant_admin','soc_manager',
                    'soc_analyst','investigator','readonly'));

-- Sessions/tokens
CREATE TABLE IF NOT EXISTS user_sessions (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash      VARCHAR(128) NOT NULL,
    ip_address      INET,
    user_agent      TEXT,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    expires_at      TIMESTAMPTZ NOT NULL,
    revoked         BOOLEAN DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_sessions_user  ON user_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_token ON user_sessions(token_hash);

-- ═══════════════════════════════════════════════════════════════════════════════
-- 3. ENHANCED SOC ALERTS
-- ═══════════════════════════════════════════════════════════════════════════════

ALTER TABLE alerts ADD COLUMN IF NOT EXISTS confidence DOUBLE PRECISION DEFAULT 0;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS priority INTEGER DEFAULT 3;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS kill_chain_phase VARCHAR(50);
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS related_alerts JSONB DEFAULT '[]';
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS tags JSONB DEFAULT '[]';
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS triaged_at TIMESTAMPTZ;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS escalated_at TIMESTAMPTZ;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS resolution TEXT;

-- Triage playbook rules
CREATE TABLE IF NOT EXISTS triage_rules (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id       UUID REFERENCES tenants(id),
    name            VARCHAR(255) NOT NULL,
    condition_field VARCHAR(50) NOT NULL,
    condition_op    VARCHAR(20) NOT NULL,
    condition_value TEXT NOT NULL,
    action          VARCHAR(50) NOT NULL,
    action_value    TEXT,
    priority        INTEGER DEFAULT 100,
    enabled         BOOLEAN DEFAULT TRUE,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- ═══════════════════════════════════════════════════════════════════════════════
-- 4. STIX/TAXII COLLECTIONS
-- ═══════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS taxii_collections (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id       UUID REFERENCES tenants(id),
    title           VARCHAR(255) NOT NULL,
    description     TEXT,
    can_read        BOOLEAN DEFAULT TRUE,
    can_write       BOOLEAN DEFAULT TRUE,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS stix_objects (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    collection_id   UUID NOT NULL REFERENCES taxii_collections(id) ON DELETE CASCADE,
    stix_id         VARCHAR(255) NOT NULL,
    stix_type       VARCHAR(50) NOT NULL,
    spec_version    VARCHAR(10) DEFAULT '2.1',
    object_data     JSONB NOT NULL,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    modified_at     TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_stix_collection ON stix_objects(collection_id);
CREATE INDEX IF NOT EXISTS idx_stix_type       ON stix_objects(stix_type);
CREATE INDEX IF NOT EXISTS idx_stix_id         ON stix_objects(stix_id);

-- ═══════════════════════════════════════════════════════════════════════════════
-- 5. GEOIP CACHE
-- ═══════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS geoip_cache (
    ip              INET PRIMARY KEY,
    country         CHAR(2),
    country_name    VARCHAR(100),
    region          VARCHAR(50),
    city            VARCHAR(100),
    latitude        DOUBLE PRECISION,
    longitude       DOUBLE PRECISION,
    asn             VARCHAR(20),
    org             VARCHAR(255),
    is_tor_exit     BOOLEAN DEFAULT FALSE,
    is_vpn          BOOLEAN DEFAULT FALSE,
    is_proxy        BOOLEAN DEFAULT FALSE,
    is_hosting      BOOLEAN DEFAULT FALSE,
    risk_score      DOUBLE PRECISION DEFAULT 0,
    threat_tags     JSONB DEFAULT '[]',
    cached_at       TIMESTAMPTZ DEFAULT NOW()
);

-- ═══════════════════════════════════════════════════════════════════════════════
-- 6. ATTACKER INFRASTRUCTURE
-- ═══════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS infra_nodes (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id       UUID REFERENCES tenants(id),
    ip              INET NOT NULL,
    domain          VARCHAR(512),
    node_type       VARCHAR(20),   -- c2, proxy, exfil, scanning, relay
    country         CHAR(2),
    org             VARCHAR(255),
    confidence      DOUBLE PRECISION DEFAULT 0,
    threat_types    JSONB DEFAULT '[]',
    connections     JSONB DEFAULT '[]',
    tags            JSONB DEFAULT '[]',
    first_seen      TIMESTAMPTZ DEFAULT NOW(),
    last_seen       TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE (tenant_id, ip)
);

CREATE TABLE IF NOT EXISTS infra_campaigns (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id       UUID REFERENCES tenants(id),
    campaign_name   VARCHAR(255),
    node_count      INTEGER DEFAULT 0,
    ips             JSONB DEFAULT '[]',
    countries       JSONB DEFAULT '[]',
    threat_types    JSONB DEFAULT '[]',
    confidence      DOUBLE PRECISION DEFAULT 0,
    first_seen      TIMESTAMPTZ DEFAULT NOW(),
    last_seen       TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_infra_ip     ON infra_nodes(ip);
CREATE INDEX IF NOT EXISTS idx_infra_type   ON infra_nodes(node_type);
CREATE INDEX IF NOT EXISTS idx_infra_tenant ON infra_nodes(tenant_id);

-- ═══════════════════════════════════════════════════════════════════════════════
-- 7. INVESTIGATION REPORTS
-- ═══════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS investigation_reports (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id       UUID REFERENCES tenants(id),
    report_id       VARCHAR(50) NOT NULL UNIQUE,
    session_id      UUID,
    classification  VARCHAR(20) DEFAULT 'TLP:AMBER',
    risk_level      VARCHAR(20),
    total_threats   INTEGER DEFAULT 0,
    report_data     JSONB NOT NULL,
    generated_by    VARCHAR(100),
    generated_at    TIMESTAMPTZ DEFAULT NOW()
);

-- ═══════════════════════════════════════════════════════════════════════════════
-- 8. SIEM EXPORT LOG
-- ═══════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS siem_exports (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id       UUID REFERENCES tenants(id),
    format          VARCHAR(20) NOT NULL,
    alert_count     INTEGER DEFAULT 0,
    destination     VARCHAR(255),
    exported_by     VARCHAR(100),
    exported_at     TIMESTAMPTZ DEFAULT NOW()
);

-- ═══════════════════════════════════════════════════════════════════════════════
-- 9. ENHANCED MITRE MAPPING
-- ═══════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS mitre_detections (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id      UUID,
    technique_id    VARCHAR(20) NOT NULL,
    technique_name  VARCHAR(255),
    tactic          VARCHAR(100),
    detector        VARCHAR(100),
    confidence      DOUBLE PRECISION DEFAULT 0,
    evidence        JSONB DEFAULT '[]',
    detected_at     TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_mitre_tech    ON mitre_detections(technique_id);
CREATE INDEX IF NOT EXISTS idx_mitre_session ON mitre_detections(session_id);

-- ═══════════════════════════════════════════════════════════════════════════════
-- 10. ENHANCED AUDIT LOG
-- ═══════════════════════════════════════════════════════════════════════════════

ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id);
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS user_agent TEXT;
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS session_id UUID;
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS success BOOLEAN DEFAULT TRUE;

-- ═══════════════════════════════════════════════════════════════════════════════
-- VIEWS
-- ═══════════════════════════════════════════════════════════════════════════════

CREATE OR REPLACE VIEW v_soc_dashboard AS
SELECT
    a.tenant_id,
    a.severity,
    a.status,
    COUNT(*) AS alert_count,
    AVG(a.threat_score) AS avg_score,
    COUNT(*) FILTER (WHERE a.sla_breached) AS sla_breached,
    MIN(a.created_at) AS earliest,
    MAX(a.created_at) AS latest
FROM alerts a
GROUP BY a.tenant_id, a.severity, a.status;

CREATE OR REPLACE VIEW v_infra_overview AS
SELECT
    i.tenant_id,
    i.node_type,
    i.country,
    COUNT(*) AS node_count,
    AVG(i.confidence) AS avg_confidence,
    MAX(i.last_seen) AS last_activity
FROM infra_nodes i
GROUP BY i.tenant_id, i.node_type, i.country;

CREATE OR REPLACE VIEW v_compliance_summary AS
SELECT
    t.id AS tenant_id,
    t.name AS tenant_name,
    COUNT(DISTINCT u.id) AS user_count,
    COUNT(DISTINCT u.id) FILTER (WHERE u.mfa_enabled) AS mfa_users,
    COUNT(DISTINCT a.id) AS total_alerts,
    COUNT(DISTINCT a.id) FILTER (WHERE a.status = 'open') AS open_alerts,
    COUNT(DISTINCT a.id) FILTER (WHERE a.sla_breached) AS sla_breaches,
    COUNT(DISTINCT ir.id) AS reports_generated
FROM tenants t
LEFT JOIN users u ON u.tenant_id = t.id
LEFT JOIN alerts a ON a.tenant_id = t.id
LEFT JOIN investigation_reports ir ON ir.tenant_id = t.id
GROUP BY t.id, t.name;
