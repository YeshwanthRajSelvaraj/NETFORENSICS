import React, { useState, useEffect, useCallback, useMemo } from 'react';

const API = 'http://localhost:8000';

/* ─── Severity color mapping ──────────────────────────────────────────────── */
const SEV_COLORS = {
  CRITICAL: '#ef4444', HIGH: '#f59e0b', MEDIUM: '#3b82f6', LOW: '#6b7280',
};
const SEV_BG = {
  CRITICAL: 'rgba(239,68,68,0.12)', HIGH: 'rgba(245,158,11,0.12)',
  MEDIUM: 'rgba(59,130,246,0.12)', LOW: 'rgba(107,114,128,0.12)',
};

/* ─── Reusable components ─────────────────────────────────────────────────── */
const Card = ({ title, children, icon, accent }) => (
  <div style={{
    background: 'rgba(15,23,42,0.85)', borderRadius: 14,
    border: `1px solid ${accent || 'rgba(99,179,237,0.12)'}`,
    padding: '18px 20px', backdropFilter: 'blur(12px)',
  }}>
    {title && (
      <h3 style={{ fontSize: 13, fontWeight: 600, color: '#94a3b8', letterSpacing: 0.6,
        textTransform: 'uppercase', marginBottom: 14, display: 'flex', alignItems: 'center', gap: 8 }}>
        {icon && <span style={{ fontSize: 16 }}>{icon}</span>}{title}
      </h3>
    )}
    {children}
  </div>
);

const Stat = ({ label, value, color, small }) => (
  <div style={{ textAlign: 'center' }}>
    <div style={{ fontSize: small ? 22 : 28, fontWeight: 800, color: color || '#63b3ed',
      fontFamily: "'JetBrains Mono', monospace" }}>{value}</div>
    <div style={{ fontSize: 10, color: '#64748b', marginTop: 2, textTransform: 'uppercase',
      letterSpacing: 0.5 }}>{label}</div>
  </div>
);

const Badge = ({ sev }) => (
  <span style={{
    fontSize: 10, fontWeight: 700, padding: '2px 8px', borderRadius: 6,
    background: SEV_BG[sev] || SEV_BG.LOW, color: SEV_COLORS[sev] || '#888',
    textTransform: 'uppercase', letterSpacing: 0.5,
  }}>{sev}</span>
);

const ScoreBar = ({ score, max = 100 }) => (
  <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
    <div style={{ flex: 1, height: 6, borderRadius: 3, background: 'rgba(255,255,255,0.06)' }}>
      <div style={{
        width: `${Math.min(100, (score / max) * 100)}%`, height: '100%', borderRadius: 3,
        background: score > 80 ? '#ef4444' : score > 60 ? '#f59e0b' : score > 40 ? '#3b82f6' : '#6b7280',
        transition: 'width 0.6s ease',
      }} />
    </div>
    <span style={{ fontSize: 11, fontWeight: 700, color: '#cbd5e1', fontFamily: 'monospace',
      minWidth: 28, textAlign: 'right' }}>{Math.round(score)}</span>
  </div>
);


/* ─── Main Dashboard ──────────────────────────────────────────────────────── */
export default function TorDashboard({ sessionId }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [tab, setTab] = useState('overview');
  const [evFilter, setEvFilter] = useState({ severity: '', type: '' });

  const runAnalysis = useCallback(async () => {
    if (!sessionId) return;
    setLoading(true);
    setError(null);
    try {
      await fetch(`${API}/api/v3/tor/analyze/${sessionId}`, { method: 'POST' });
      const res = await fetch(`${API}/api/v3/tor/dashboard/${sessionId}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setData(await res.json());
    } catch (e) { setError(e.message); }
    finally { setLoading(false); }
  }, [sessionId]);

  useEffect(() => { if (sessionId) runAnalysis(); }, [sessionId]);

  if (!sessionId) return <EmptyState />;
  if (loading) return <LoadingState />;
  if (error) return <ErrorState msg={error} retry={runAnalysis} />;
  if (!data) return <EmptyState />;

  const s = data.summary || {};
  const tabs = [
    { id: 'overview', label: 'Overview', icon: '📊' },
    { id: 'events', label: 'Events', icon: '⚡' },
    { id: 'circuits', label: 'Circuits', icon: '🔗' },
    { id: 'hidden', label: 'Hidden Services', icon: '🧅' },
    { id: 'c2', label: 'C2 Detection', icon: '🎯' },
    { id: 'users', label: 'Internal Users', icon: '👤' },
  ];

  return (
    <div style={{ fontFamily: "'Inter', 'Segoe UI', system-ui, sans-serif", color: '#e2e8f0',
      minHeight: '100vh', background: 'linear-gradient(135deg, #0a0e1a 0%, #0f172a 50%, #0a0e1a 100%)' }}>

      {/* Header */}
      <div style={{ padding: '24px 28px', borderBottom: '1px solid rgba(99,179,237,0.1)',
        background: 'rgba(15,23,42,0.6)', backdropFilter: 'blur(20px)' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
            <div style={{ width: 44, height: 44, borderRadius: 12,
              background: 'linear-gradient(135deg, #7c3aed, #6d28d9)',
              display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 22 }}>🧅</div>
            <div>
              <h1 style={{ fontSize: 20, fontWeight: 700, margin: 0,
                background: 'linear-gradient(90deg, #a78bfa, #818cf8)', WebkitBackgroundClip: 'text',
                WebkitTextFillColor: 'transparent' }}>Tor Traffic Analyzer</h1>
              <p style={{ fontSize: 12, color: '#64748b', margin: 0 }}>
                9-module metadata-only analysis engine • Session {sessionId?.slice(0, 8)}…
              </p>
            </div>
          </div>
          <button onClick={runAnalysis} style={{
            padding: '8px 18px', borderRadius: 8, border: '1px solid rgba(124,58,237,0.4)',
            background: 'rgba(124,58,237,0.15)', color: '#a78bfa', fontSize: 12,
            fontWeight: 600, cursor: 'pointer',
          }}>↻ Re-analyze</button>
        </div>

        {/* Tab bar */}
        <div style={{ display: 'flex', gap: 4, marginTop: 16 }}>
          {tabs.map(t => (
            <button key={t.id} onClick={() => setTab(t.id)} style={{
              padding: '7px 14px', borderRadius: 8, border: 'none', fontSize: 12, fontWeight: 600,
              cursor: 'pointer', transition: 'all 0.2s',
              background: tab === t.id ? 'rgba(124,58,237,0.25)' : 'transparent',
              color: tab === t.id ? '#a78bfa' : '#64748b',
            }}>{t.icon} {t.label}</button>
          ))}
        </div>
      </div>

      {/* Body */}
      <div style={{ padding: '20px 28px' }}>
        {tab === 'overview' && <OverviewTab s={s} data={data} />}
        {tab === 'events' && <EventsTab events={data.top_events || []} filter={evFilter} setFilter={setEvFilter} />}
        {tab === 'circuits' && <CircuitsTab circuits={data.circuits || []} />}
        {tab === 'hidden' && <HiddenTab hs={data.hidden_services || []} />}
        {tab === 'c2' && <C2Tab c2={data.c2_indicators || []} />}
        {tab === 'users' && <UsersTab users={data.internal_users || []} />}
      </div>
    </div>
  );
}


/* ═══════ Tab: Overview ═══════════════════════════════════════════════════ */
function OverviewTab({ s, data }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      {/* KPI row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))', gap: 10 }}>
        <Card><Stat label="Total Events" value={s.total_events || 0} /></Card>
        <Card accent="rgba(239,68,68,0.3)">
          <Stat label="Critical" value={s.critical_events || 0} color="#ef4444" /></Card>
        <Card accent="rgba(245,158,11,0.3)">
          <Stat label="High" value={s.high_events || 0} color="#f59e0b" /></Card>
        <Card><Stat label="Circuits" value={s.circuits_detected || 0} color="#a78bfa" /></Card>
        <Card accent="rgba(139,92,246,0.3)">
          <Stat label="Hidden Svc" value={s.hidden_service_indicators || 0} color="#8b5cf6" /></Card>
        <Card accent="rgba(234,88,12,0.3)">
          <Stat label="C2 Alerts" value={s.c2_indicators || 0} color="#ea580c" /></Card>
        <Card><Stat label="Bridges" value={s.bridge_detections || 0} color="#14b8a6" /></Card>
        <Card><Stat label="Internal IPs" value={s.unique_internal_ips || 0} color="#6366f1" /></Card>
      </div>

      {/* Detection breakdown */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
        <Card title="Detection Breakdown" icon="📊">
          {[
            { k: 'node_matches', l: 'Node IP Matches', c: '#3b82f6' },
            { k: 'fingerprint_matches', l: 'TLS Fingerprints', c: '#8b5cf6' },
            { k: 'cell_detections', l: 'Cell Patterns', c: '#14b8a6' },
            { k: 'circuits_detected', l: 'Circuit Builds', c: '#f59e0b' },
            { k: 'timing_correlations', l: 'Timing Correlations', c: '#ef4444' },
            { k: 'entropy_matches', l: 'Entropy Matches', c: '#6366f1' },
          ].map(({ k, l, c }) => (
            <div key={k} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center',
              padding: '6px 0', borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
              <span style={{ fontSize: 12, color: '#94a3b8' }}>{l}</span>
              <span style={{ fontSize: 14, fontWeight: 700, color: c, fontFamily: 'monospace' }}>
                {s[k] || 0}
              </span>
            </div>
          ))}
        </Card>

        <Card title="Severity Distribution" icon="🎯">
          {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(sev => {
            const count = data.severity_breakdown?.[sev] || 0;
            const total = s.total_events || 1;
            return (
              <div key={sev} style={{ marginBottom: 10 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                  <Badge sev={sev} />
                  <span style={{ fontSize: 12, color: '#94a3b8' }}>{count} events</span>
                </div>
                <div style={{ height: 6, borderRadius: 3, background: 'rgba(255,255,255,0.06)' }}>
                  <div style={{ width: `${(count / total) * 100}%`, height: '100%', borderRadius: 3,
                    background: SEV_COLORS[sev], transition: 'width 0.6s ease' }} />
                </div>
              </div>
            );
          })}
        </Card>
      </div>

      {/* Top events preview */}
      <Card title="Top Threats" icon="⚡">
        <div style={{ maxHeight: 260, overflowY: 'auto' }}>
          {(data.top_events || []).slice(0, 8).map((e, i) => (
            <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 10,
              padding: '8px 0', borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
              <Badge sev={e.severity} />
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: 12, fontWeight: 600, color: '#e2e8f0' }}>
                  {e.event_type?.replace(/_/g, ' ')} → {e.sub_type?.replace(/_/g, ' ')}
                </div>
                <div style={{ fontSize: 11, color: '#64748b' }}>{e.src_ip} → {e.dst_ip}</div>
              </div>
              <ScoreBar score={e.score || 0} />
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}


/* ═══════ Tab: Events ════════════════════════════════════════════════════ */
function EventsTab({ events, filter, setFilter }) {
  const filtered = useMemo(() => {
    let evts = events;
    if (filter.severity) evts = evts.filter(e => e.severity === filter.severity);
    if (filter.type) evts = evts.filter(e => e.event_type === filter.type);
    return evts;
  }, [events, filter]);

  const types = [...new Set(events.map(e => e.event_type))];

  return (
    <div>
      <div style={{ display: 'flex', gap: 8, marginBottom: 14 }}>
        <select value={filter.severity} onChange={e => setFilter(p => ({ ...p, severity: e.target.value }))}
          style={{ padding: '6px 12px', borderRadius: 6, background: 'rgba(15,23,42,0.9)',
            border: '1px solid rgba(255,255,255,0.1)', color: '#e2e8f0', fontSize: 12 }}>
          <option value="">All Severities</option>
          {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(s =>
            <option key={s} value={s}>{s}</option>)}
        </select>
        <select value={filter.type} onChange={e => setFilter(p => ({ ...p, type: e.target.value }))}
          style={{ padding: '6px 12px', borderRadius: 6, background: 'rgba(15,23,42,0.9)',
            border: '1px solid rgba(255,255,255,0.1)', color: '#e2e8f0', fontSize: 12 }}>
          <option value="">All Types</option>
          {types.map(t => <option key={t} value={t}>{t.replace(/_/g, ' ')}</option>)}
        </select>
        <span style={{ fontSize: 12, color: '#64748b', alignSelf: 'center', marginLeft: 'auto' }}>
          {filtered.length} events
        </span>
      </div>
      <div style={{ maxHeight: 500, overflowY: 'auto' }}>
        {filtered.map((e, i) => (
          <Card key={i}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
              <Badge sev={e.severity} />
              <span style={{ fontSize: 13, fontWeight: 600 }}>
                {e.event_type?.replace(/_/g, ' ')} — {e.sub_type?.replace(/_/g, ' ')}
              </span>
              <span style={{ marginLeft: 'auto' }}><ScoreBar score={e.score || 0} /></span>
            </div>
            <div style={{ fontSize: 12, color: '#94a3b8', marginBottom: 6 }}>
              {e.src_ip} → {e.dst_ip}:{e.dst_port}
              {e.tor_node_type && <span style={{ marginLeft: 8, color: '#a78bfa' }}>({e.tor_node_type})</span>}
            </div>
            <ul style={{ fontSize: 11, color: '#64748b', margin: 0, paddingLeft: 16, listStyle: 'disc' }}>
              {(e.evidence || []).slice(0, 4).map((ev, j) => <li key={j}>{ev}</li>)}
            </ul>
            {e.mitre_technique && (
              <div style={{ marginTop: 6, fontSize: 10, color: '#6366f1' }}>
                MITRE: {e.mitre_technique}
              </div>
            )}
          </Card>
        ))}
      </div>
    </div>
  );
}


/* ═══════ Tab: Circuits ══════════════════════════════════════════════════ */
function CircuitsTab({ circuits }) {
  return (
    <div>
      <div style={{ marginBottom: 12, fontSize: 13, color: '#94a3b8' }}>
        {circuits.length} circuit(s) detected
      </div>
      {circuits.map((c, i) => (
        <Card key={i} accent={c.is_hidden_service ? 'rgba(139,92,246,0.3)' : undefined}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10 }}>
            <span style={{ fontSize: 16 }}>{c.is_hidden_service ? '🧅' : '🔗'}</span>
            <span style={{ fontSize: 13, fontWeight: 700, color: '#e2e8f0' }}>
              Circuit {c.circuit_id}
            </span>
            {c.is_hidden_service && (
              <span style={{ fontSize: 10, padding: '2px 8px', borderRadius: 6,
                background: 'rgba(139,92,246,0.2)', color: '#a78bfa' }}>Hidden Service</span>
            )}
          </div>
          {/* Circuit path visualization */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 4, flexWrap: 'wrap',
            padding: '10px 12px', background: 'rgba(0,0,0,0.2)', borderRadius: 8, marginBottom: 10 }}>
            <span style={{ fontSize: 12, fontWeight: 600, color: '#6366f1', fontFamily: 'monospace' }}>
              {c.src_ip}
            </span>
            {(c.hops || []).map((hop, j) => (
              <React.Fragment key={j}>
                <span style={{ color: '#4a5568' }}>→</span>
                <span style={{ fontSize: 12, fontFamily: 'monospace',
                  color: j === 0 ? '#f59e0b' : j === (c.hops || []).length - 1 ? '#ef4444' : '#94a3b8',
                  fontWeight: j === 0 || j === (c.hops || []).length - 1 ? 700 : 400 }}>
                  {hop}
                  {j === 0 && <span style={{ fontSize: 9, color: '#f59e0b' }}> (guard)</span>}
                  {j === (c.hops || []).length - 1 && <span style={{ fontSize: 9, color: '#ef4444' }}> (exit)</span>}
                </span>
              </React.Fragment>
            ))}
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 8 }}>
            <Stat label="Hops" value={(c.hops || []).length} small />
            <Stat label="Build Time" value={`${c.build_time_ms?.toFixed(0)}ms`} small color="#f59e0b" />
            <Stat label="Packets" value={c.packet_count || 0} small />
            <Stat label="Cell Ratio" value={`${((c.cell_ratio || 0) * 100).toFixed(0)}%`} small color="#14b8a6" />
          </div>
        </Card>
      ))}
    </div>
  );
}


/* ═══════ Tab: Hidden Services ═══════════════════════════════════════════ */
function HiddenTab({ hs }) {
  return (
    <div>
      {hs.length === 0 ? (
        <Card><p style={{ color: '#64748b', textAlign: 'center', padding: 20 }}>
          No hidden service indicators detected</p></Card>
      ) : hs.map((h, i) => (
        <Card key={i} accent="rgba(139,92,246,0.3)">
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
            <span style={{ fontSize: 18 }}>🧅</span>
            <span style={{ fontSize: 14, fontWeight: 700, color: '#a78bfa' }}>{h.src_ip}</span>
            <span style={{ marginLeft: 'auto', fontSize: 11, color: '#64748b' }}>
              Confidence: {(h.confidence * 100).toFixed(0)}%
            </span>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 8, marginBottom: 10 }}>
            <Stat label="Duration" value={`${(h.duration / 60).toFixed(0)}min`} small color="#a78bfa" />
            <Stat label="Circuits" value={h.circuit_count || 0} small />
            <Stat label="Data" value={`${((h.data_volume_bytes || 0) / 1024).toFixed(0)}KB`} small color="#14b8a6" />
          </div>
          <ul style={{ fontSize: 11, color: '#94a3b8', margin: 0, paddingLeft: 16 }}>
            {(h.evidence || []).map((e, j) => <li key={j}>{e}</li>)}
          </ul>
        </Card>
      ))}
    </div>
  );
}


/* ═══════ Tab: C2 Detection ═════════════════════════════════════════════ */
function C2Tab({ c2 }) {
  return (
    <div>
      {c2.length === 0 ? (
        <Card><p style={{ color: '#64748b', textAlign: 'center', padding: 20 }}>
          No C2-over-Tor indicators detected</p></Card>
      ) : c2.map((c, i) => (
        <Card key={i} accent="rgba(234,88,12,0.3)">
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
            <span style={{ fontSize: 18 }}>🎯</span>
            <span style={{ fontSize: 14, fontWeight: 700, color: '#ea580c' }}>{c.src_ip}</span>
            <span style={{ color: '#64748b', fontSize: 11 }}>→ guard {c.guard_ip}</span>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 8, marginBottom: 10 }}>
            <Stat label="Interval" value={`${c.interval_mean?.toFixed(1)}s`} small color="#ea580c" />
            <Stat label="Jitter (CV)" value={c.interval_cv?.toFixed(3)} small />
            <Stat label="Sessions" value={c.session_count || 0} small />
            <Stat label="Duration" value={`${((c.duration || 0) / 60).toFixed(0)}m`} small color="#f59e0b" />
          </div>
          <ScoreBar score={(c.confidence || 0) * 100} />
          <ul style={{ fontSize: 11, color: '#94a3b8', margin: '8px 0 0', paddingLeft: 16 }}>
            {(c.evidence || []).map((e, j) => <li key={j}>{e}</li>)}
          </ul>
        </Card>
      ))}
    </div>
  );
}


/* ═══════ Tab: Internal Users ═══════════════════════════════════════════ */
function UsersTab({ users }) {
  return (
    <div>
      <div style={{ marginBottom: 12, fontSize: 13, color: '#94a3b8' }}>
        {users.length} internal endpoint(s) with Tor activity
      </div>
      <div style={{ display: 'grid', gap: 8 }}>
        {users.map((u, i) => (
          <Card key={i}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <span style={{ fontSize: 18 }}>👤</span>
              <span style={{ fontSize: 14, fontWeight: 700, color: '#e2e8f0', fontFamily: 'monospace' }}>
                {u.ip}
              </span>
              <div style={{ flex: 1 }}><ScoreBar score={u.max_score || 0} /></div>
              <span style={{ fontSize: 12, color: '#64748b' }}>{u.event_count} events</span>
            </div>
            <div style={{ display: 'flex', gap: 4, marginTop: 8, flexWrap: 'wrap' }}>
              {(u.event_types || []).map((t, j) => (
                <span key={j} style={{ fontSize: 10, padding: '2px 6px', borderRadius: 4,
                  background: 'rgba(99,179,237,0.1)', color: '#63b3ed' }}>
                  {t.replace(/_/g, ' ')}
                </span>
              ))}
            </div>
          </Card>
        ))}
      </div>
    </div>
  );
}


/* ═══════ Status screens ════════════════════════════════════════════════ */
function EmptyState() {
  return <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: 400,
    color: '#64748b', fontSize: 14 }}>Select a session to run Tor analysis</div>;
}
function LoadingState() {
  return <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: 400,
    color: '#a78bfa', fontSize: 14 }}>
    <span style={{ animation: 'spin 1s linear infinite', display: 'inline-block', marginRight: 8 }}>🔄</span>
    Running 9-module Tor analysis…</div>;
}
function ErrorState({ msg, retry }) {
  return <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
    minHeight: 400, color: '#ef4444', fontSize: 14, gap: 10 }}>
    ⚠ Error: {msg}
    <button onClick={retry} style={{ padding: '6px 14px', borderRadius: 6, border: '1px solid rgba(239,68,68,0.3)',
      background: 'rgba(239,68,68,0.1)', color: '#ef4444', cursor: 'pointer' }}>Retry</button>
  </div>;
}
