import { useState, useEffect, useRef, useCallback, useMemo } from "react";
import {
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, RadarChart, Radar, PolarGrid,
  PolarAngleAxis, ScatterChart, Scatter, ZAxis
} from "recharts";
import AdvancedVisualizationsPanel from "./components/AdvancedVisualizationsPanel";

// ─── Config ───────────────────────────────────────────────────────────────────
const API    = window.NF_API    || "http://localhost:8000/api";
const WS_URL = window.NF_WS_URL || "ws://localhost:8000/ws";

// ─── Design tokens ────────────────────────────────────────────────────────────
const C = {
  bg0: "#04070d",      // deepest background
  bg1: "#080e18",      // surface
  bg2: "#0c1424",      // card
  bg3: "#111c30",      // elevated card
  border: "#172236",
  borderBright: "#1f3050",
  // Accent hierarchy
  cyan:   "#00e5ff",
  blue:   "#2979ff",
  purple: "#7c4dff",
  green:  "#00e676",
  amber:  "#ffab40",
  red:    "#ff1744",
  pink:   "#f50057",
  // Text
  text:   "#d0dae8",
  textSub:"#5a7499",
  textDim:"#2e4a6a",
  // Protocol
  TLS:   "#7c4dff",
  TCP:   "#2979ff",
  UDP:   "#00e676",
  DNS:   "#ffab40",
  ICMP:  "#ff1744",
  OTHER: "#37474f",
};

const RISK_COLOR = s => s >= 70 ? C.red : s >= 45 ? C.amber : s >= 20 ? "#ffee58" : C.green;
const RISK_LABEL = s => s >= 70 ? "CRITICAL" : s >= 45 ? "HIGH" : s >= 20 ? "MEDIUM" : "LOW";
const CONF_COLOR = c => ({ HIGH: C.red, MEDIUM: C.amber, LOW: C.textSub }[c] || C.textSub);
const PROTO_COL  = p => C[p] || C.OTHER;
const PIE_COLS   = [C.cyan, C.purple, C.green, C.amber, C.red, C.blue, C.pink];

const fmtBytes = b => {
  if (!b) return "0 B";
  const u = ["B","KB","MB","GB"]; let i=0, v=+b;
  while (v>=1024 && i<3) { v/=1024; i++; }
  return `${v.toFixed(1)} ${u[i]}`;
};
const fmtTs   = ts => ts ? new Date(ts * 1000).toLocaleTimeString() : "—";
const fmtDate = ts => ts ? new Date(ts * 1000).toLocaleString() : "—";
const mono    = v  => <span style={{ fontFamily:"'IBM Plex Mono',monospace", fontSize:11 }}>{v}</span>;

// ─── Micro components ─────────────────────────────────────────────────────────

const Tag = ({ label, color = C.cyan, dot }) => (
  <span style={{
    display:"inline-flex", alignItems:"center", gap:4,
    background:`${color}14`, color, border:`1px solid ${color}30`,
    borderRadius:3, padding:"1px 7px",
    fontSize:10, fontWeight:700, letterSpacing:1.2,
    whiteSpace:"nowrap", textTransform:"uppercase",
  }}>
    {dot && <span style={{ width:5, height:5, borderRadius:"50%",
                            background:color, display:"inline-block" }}/>}
    {label}
  </span>
);

const Pill = ({ value, color = C.cyan }) => (
  <span style={{
    background:`${color}20`, color, border:`1px solid ${color}35`,
    borderRadius:12, padding:"2px 10px", fontSize:11, fontWeight:700,
  }}>{value}</span>
);

const Stat = ({ label, value, color = C.cyan, sub, pulse }) => (
  <div style={{
    background:`linear-gradient(135deg, ${C.bg2}, ${C.bg3})`,
    border:`1px solid ${C.border}`, borderTop:`1px solid ${color}30`,
    borderRadius:8, padding:"16px 20px", flex:1, minWidth:130,
    position:"relative", overflow:"hidden",
  }}>
    <div style={{
      position:"absolute", top:0, right:0, width:60, height:60,
      background:`radial-gradient(circle at top right, ${color}0a, transparent 70%)`,
    }}/>
    <div style={{ color:C.textSub, fontSize:10, letterSpacing:2,
                   textTransform:"uppercase", marginBottom:10 }}>{label}</div>
    <div style={{
      color, fontSize:28, fontWeight:800,
      fontFamily:"'IBM Plex Mono',monospace", lineHeight:1,
      display:"flex", alignItems:"center", gap:8,
    }}>
      {value ?? <span style={{color:C.textDim}}>—</span>}
      {pulse && value > 0 && (
        <span style={{ width:8, height:8, borderRadius:"50%", background:color,
                        animation:"pulse 1.5s infinite", display:"inline-block" }}/>
      )}
    </div>
    {sub && <div style={{ color:C.textSub, fontSize:11, marginTop:6 }}>{sub}</div>}
  </div>
);

const Card = ({ title, children, toolbar, style = {}, noPad, glow }) => (
  <div style={{
    background:C.bg2, border:`1px solid ${glow ? `${glow}40` : C.border}`,
    boxShadow: glow ? `0 0 20px ${glow}10` : "none",
    borderRadius:10, overflow:"hidden", ...style,
  }}>
    {title && (
      <div style={{
        display:"flex", justifyContent:"space-between", alignItems:"center",
        padding:"12px 18px", borderBottom:`1px solid ${C.border}`,
        background:`linear-gradient(90deg, ${C.bg3}, ${C.bg2})`,
      }}>
        <span style={{ color:C.text, fontWeight:700, fontSize:13, letterSpacing:0.3 }}>{title}</span>
        {toolbar}
      </div>
    )}
    <div style={noPad ? {} : { padding:18 }}>{children}</div>
  </div>
);

// ─── Data table ───────────────────────────────────────────────────────────────
const Table = ({ cols, rows, onRow, empty = "No data" }) => (
  <div style={{ overflowX:"auto" }}>
    <table style={{ width:"100%", borderCollapse:"collapse", fontSize:12 }}>
      <thead>
        <tr style={{ background:C.bg3 }}>
          {cols.map(c => (
            <th key={c.key} style={{
              padding:"9px 14px", textAlign:"left",
              color:C.textSub, fontSize:10, letterSpacing:1.8,
              textTransform:"uppercase",
              borderBottom:`1px solid ${C.border}`, whiteSpace:"nowrap",
            }}>{c.label}</th>
          ))}
        </tr>
      </thead>
      <tbody>
        {rows.map((row, i) => (
          <tr key={i}
              onClick={() => onRow && onRow(row)}
              style={{ cursor:onRow?"pointer":"default", borderBottom:`1px solid ${C.border}18`,
                        transition:"background 0.1s" }}
              onMouseEnter={e => e.currentTarget.style.background = C.bg3}
              onMouseLeave={e => e.currentTarget.style.background = "transparent"}>
            {cols.map(c => (
              <td key={c.key} style={{ padding:"9px 14px", color:c.color || C.text, whiteSpace:"nowrap" }}>
                {c.render ? c.render(row[c.key], row)
                          : (row[c.key] ?? <span style={{color:C.textDim}}>—</span>)}
              </td>
            ))}
          </tr>
        ))}
      </tbody>
    </table>
    {!rows.length && (
      <div style={{ textAlign:"center", padding:"48px 20px", color:C.textDim, fontSize:13 }}>
        {empty}
      </div>
    )}
  </div>
);

// ─── Risk bar ─────────────────────────────────────────────────────────────────
const RiskBar = ({ score }) => {
  const col = RISK_COLOR(score);
  return (
    <div style={{ display:"flex", alignItems:"center", gap:10 }}>
      <div style={{ width:80, background:C.bg3, borderRadius:3, height:5, overflow:"hidden" }}>
        <div style={{ width:`${score}%`, background:col, height:"100%",
                       borderRadius:3, transition:"width 0.5s",
                       boxShadow:`0 0 6px ${col}88` }}/>
      </div>
      <Tag label={RISK_LABEL(score)} color={col}/>
    </div>
  );
};

// ─── Network graph (SVG force) ────────────────────────────────────────────────
const NetworkGraph = ({ nodes = [], edges = [] }) => {
  const [pos, setPos]   = useState({});
  const [drag, setDrag] = useState(null);
  const svgRef = useRef(null);

  useEffect(() => {
    if (!nodes.length) return;
    const cx = 500, cy = 300, r = 230;
    const p = {};
    nodes.forEach((n, i) => {
      const a = (i / nodes.length) * 2 * Math.PI - Math.PI/2;
      p[n.id] = {
        x: cx + r * Math.cos(a) + (Math.random()-0.5)*40,
        y: cy + r * Math.sin(a) + (Math.random()-0.5)*40,
      };
    });
    setPos(p);
  }, [nodes.length]);

  const maxBytes = useMemo(() => Math.max(...edges.map(e => e.bytes||0), 1), [edges]);

  const onMD = (id, e) => { e.preventDefault(); setDrag(id); };
  const onMM = e => {
    if (!drag || !svgRef.current) return;
    const r2 = svgRef.current.getBoundingClientRect();
    setPos(p => ({ ...p, [drag]: {
      x: (e.clientX - r2.left) * (1000/r2.width),
      y: (e.clientY - r2.top)  * (600/r2.height),
    }}));
  };
  const onMU = () => setDrag(null);

  return (
    <svg ref={svgRef} viewBox="0 0 1000 600"
         style={{ width:"100%", background:C.bg0, borderRadius:8, cursor:drag?"grabbing":"default" }}
         onMouseMove={onMM} onMouseUp={onMU} onMouseLeave={onMU}>
      <defs>
        <radialGradient id="gInt"><stop offset="0%" stopColor={C.blue} stopOpacity={0.9}/><stop offset="100%" stopColor={C.blue} stopOpacity={0}/></radialGradient>
        <radialGradient id="gExt"><stop offset="0%" stopColor={C.cyan} stopOpacity={0.9}/><stop offset="100%" stopColor={C.cyan} stopOpacity={0}/></radialGradient>
        <radialGradient id="gDng"><stop offset="0%" stopColor={C.red}  stopOpacity={0.9}/><stop offset="100%" stopColor={C.red}  stopOpacity={0}/></radialGradient>
        <filter id="gl"><feGaussianBlur stdDeviation="4" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
        <marker id="arr" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto">
          <path d="M0,0 L6,3 L0,6 Z" fill={C.textDim} opacity={0.6}/>
        </marker>
      </defs>
      {/* Edges */}
      {edges.map((e, i) => {
        const sp = pos[e.source], tp = pos[e.target];
        if (!sp || !tp) return null;
        const w = Math.max(0.5, (e.bytes/maxBytes)*4);
        return <line key={i} x1={sp.x} y1={sp.y} x2={tp.x} y2={tp.y}
                     stroke={PROTO_COL(e.protocol)} strokeWidth={w}
                     strokeOpacity={0.5} markerEnd="url(#arr)"/>;
      })}
      {/* Nodes */}
      {nodes.map(n => {
        const p = pos[n.id]; if (!p) return null;
        const isDng = n.suspicious;
        const grad  = isDng ? "url(#gDng)" : n.type === "internal" ? "url(#gInt)" : "url(#gExt)";
        const stroke= isDng ? C.red : n.type === "internal" ? C.blue : C.cyan;
        return (
          <g key={n.id} filter="url(#gl)" style={{ cursor:"grab" }} onMouseDown={ev=>onMD(n.id,ev)}>
            <circle cx={p.x} cy={p.y} r={n.type==="internal"?22:18}
                    fill={grad} stroke={stroke} strokeWidth={isDng?2:1.5} strokeOpacity={0.8}/>
            {isDng && <circle cx={p.x} cy={p.y} r={26} fill="none" stroke={C.red}
                               strokeWidth={0.8} strokeOpacity={0.4} strokeDasharray="4 3"/>}
            <text x={p.x} y={p.y+4} textAnchor="middle" fontSize={8}
                  fill={C.text} fontFamily="'IBM Plex Mono',monospace" pointerEvents="none">
              {n.id.split(".").slice(-2).join(".")}
            </text>
            <title>{n.id} ({n.type})</title>
          </g>
        );
      })}
      {!nodes.length && (
        <text x={500} y={300} textAnchor="middle" fill={C.textDim} fontSize={14} fontFamily="monospace">
          Select a session to view network graph
        </text>
      )}
      {/* Legend */}
      {nodes.length > 0 && (
        <g transform="translate(20,550)">
          {[["Internal node",C.blue], ["External node",C.cyan], ["Suspicious",C.red]].map(([l,c],i) => (
            <g key={i} transform={`translate(${i*140},0)`}>
              <circle cx={6} cy={0} r={5} fill={c} opacity={0.8}/>
              <text x={14} y={4} fontSize={9} fill={C.textSub} fontFamily="monospace">{l}</text>
            </g>
          ))}
        </g>
      )}
    </svg>
  );
};

// ─── Live packet feed ─────────────────────────────────────────────────────────
const LiveFeed = ({ packets, paused, onToggle }) => {
  const listRef = useRef(null);
  useEffect(() => {
    if (!paused && listRef.current) listRef.current.scrollTop = 0;
  }, [packets.length, paused]);

  return (
    <div>
      <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center",
                     padding:"10px 16px", borderBottom:`1px solid ${C.border}` }}>
        <div style={{ display:"flex", alignItems:"center", gap:10 }}>
          <div style={{ width:7, height:7, borderRadius:"50%",
                         background: paused ? C.amber : C.green,
                         boxShadow:`0 0 8px ${paused ? C.amber : C.green}` }}/>
          <span style={{ color:C.textSub, fontSize:11 }}>
            {paused ? "PAUSED" : "LIVE"} — {packets.length.toLocaleString()} packets
          </span>
        </div>
        <button onClick={onToggle} style={{
          background:"transparent", border:`1px solid ${C.borderBright}`,
          color:C.textSub, borderRadius:4, padding:"4px 12px",
          cursor:"pointer", fontSize:11, fontFamily:"'IBM Plex Mono',monospace",
        }}>
          {paused ? "▶ Resume" : "⏸ Pause"}
        </button>
      </div>
      <div ref={listRef} style={{ maxHeight:340, overflowY:"auto" }}>
        {[...packets].slice(0,80).map((p, i) => (
          <div key={i} style={{
            display:"grid",
            gridTemplateColumns:"86px 125px 16px 125px 60px 72px auto",
            gap:6, padding:"5px 14px", alignItems:"center",
            background: i===0 && !paused ? `${C.cyan}07` : "transparent",
            borderBottom:`1px solid ${C.border}10`,
            fontSize:11, fontFamily:"'IBM Plex Mono',monospace",
          }}>
            <span style={{ color:C.textDim }}>{fmtTs(p.timestamp)}</span>
            <span style={{ color:C.text, overflow:"hidden", textOverflow:"ellipsis" }}>{p.src_ip}</span>
            <span style={{ color:C.textDim }}>→</span>
            <span style={{ color:C.text, overflow:"hidden", textOverflow:"ellipsis" }}>{p.dst_ip}</span>
            <Tag label={p.protocol} color={PROTO_COL(p.protocol)}/>
            <span style={{ color:C.textSub, textAlign:"right" }}>{fmtBytes(p.size)}</span>
            <span style={{ color:C.textDim, overflow:"hidden", textOverflow:"ellipsis" }}>
              {p.sni || ""}
              {p.ja3?.startsWith("e7d7") &&
                <span style={{ color:C.red, fontWeight:700, marginLeft:6 }}>⚠ Cobalt Strike</span>}
            </span>
          </div>
        ))}
        {!packets.length && (
          <div style={{ textAlign:"center", padding:"60px 20px", color:C.textDim }}>
            Awaiting packet capture…
          </div>
        )}
      </div>
    </div>
  );
};

// ─── Beacon card ──────────────────────────────────────────────────────────────
const BeaconCard = ({ b }) => {
  const col = CONF_COLOR(b.confidence);
  const pct = Math.round(b.regularity * 100);
  return (
    <div style={{
      background:`linear-gradient(135deg, ${C.bg2}, ${col}08)`,
      border:`1px solid ${col}35`, borderLeft:`3px solid ${col}`,
      borderRadius:8, padding:"14px 18px", marginBottom:12,
    }}>
      <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start", marginBottom:10 }}>
        <div>
          <div style={{ fontFamily:"'IBM Plex Mono',monospace", fontSize:13, color:C.text, marginBottom:4 }}>
            {b.src_ip} <span style={{color:C.textDim}}>→</span> {b.dst_ip}
            <span style={{color:C.textSub}}>:{b.dst_port}</span>
          </div>
          {b.sni && (
            <div style={{ color:C.purple, fontSize:11, fontFamily:"monospace" }}>
              SNI: {b.sni}
              {b.dga_score > 0.6 && (
                <span style={{ color:C.red, marginLeft:8 }}>
                  ⚠ DGA score: {(b.dga_score*100).toFixed(0)}%
                </span>
              )}
            </div>
          )}
        </div>
        <div style={{ display:"flex", gap:6, flexShrink:0 }}>
          <Tag label={b.confidence} color={col} dot/>
          <Tag label={b.beacon_type?.replace(/_/g," ")} color={C.cyan}/>
        </div>
      </div>

      {/* Interval visualisation */}
      <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr 1fr 1fr", gap:14, marginBottom:12 }}>
        {[
          { label:"Interval", value:`${b.interval_mean}s`, sub:`±${b.interval_stdev}s` },
          { label:"Regularity", value:`${pct}%`, sub:"CoV analysis" },
          { label:"Connections", value:b.packet_count, sub:"observed" },
          { label:"Type", value:b.beacon_type?.replace(/_/g," ").split(" ")[0], sub:"beacon class" },
        ].map((kv, i) => (
          <div key={i} style={{ background:`${col}08`, borderRadius:6, padding:"8px 12px" }}>
            <div style={{ color:C.textSub, fontSize:9, letterSpacing:1.5, textTransform:"uppercase" }}>
              {kv.label}
            </div>
            <div style={{ color:col, fontSize:17, fontWeight:800,
                           fontFamily:"'IBM Plex Mono',monospace", marginTop:2 }}>
              {kv.value}
            </div>
            <div style={{ color:C.textDim, fontSize:10, marginTop:1 }}>{kv.sub}</div>
          </div>
        ))}
      </div>

      {/* Regularity bar */}
      <div style={{ background:C.bg0, borderRadius:4, height:6, overflow:"hidden" }}>
        <div style={{ width:`${pct}%`, height:"100%", background:`linear-gradient(90deg, ${col}80, ${col})`,
                       borderRadius:4, boxShadow:`0 0 8px ${col}88` }}/>
      </div>

      {b.malware_match && (
        <div style={{
          marginTop:10, padding:"7px 14px",
          background:`${C.red}12`, border:`1px solid ${C.red}40`,
          borderRadius:6, color:C.red, fontSize:12, fontWeight:700,
          display:"flex", alignItems:"center", gap:8,
        }}>
          ⚠&nbsp; Malware JA3 Match: <span style={{fontFamily:"monospace"}}>{b.malware_match}</span>
          {b.ja3 && <span style={{color:C.textSub, fontWeight:400}}> ({b.ja3.slice(0,16)}…)</span>}
        </div>
      )}
    </div>
  );
};

// ─── Alert banner ─────────────────────────────────────────────────────────────
const AlertBanner = ({ alerts = [] }) => {
  if (!alerts.length) return null;
  return (
    <div style={{ marginBottom:20 }}>
      {alerts.map((a, i) => (
        <div key={i} style={{
          display:"flex", alignItems:"center", gap:12, padding:"10px 16px",
          background:`${a.color}0e`, border:`1px solid ${a.color}30`,
          borderLeft:`3px solid ${a.color}`, borderRadius:7, marginBottom:8,
          fontSize:12,
        }}>
          <span style={{ color:a.color, fontSize:16 }}>{a.icon}</span>
          <span style={{ color:C.text }}>{a.message}</span>
          {a.badge && <Tag label={a.badge} color={a.color}/>}
        </div>
      ))}
    </div>
  );
};

// ─── Tooltip style ────────────────────────────────────────────────────────────
const TT = { background:C.bg3, border:`1px solid ${C.borderBright}`,
              color:C.text, fontSize:11, borderRadius:6 };

// ─── useApi hook ──────────────────────────────────────────────────────────────
function useApi(url, deps = []) {
  const [data, setData]       = useState(null);
  const [loading, setLoading] = useState(!!url);
  useEffect(() => {
    if (!url) { setData(null); return; }
    setLoading(true);
    fetch(url).then(r => r.json()).then(d => { setData(d); setLoading(false); })
              .catch(() => setLoading(false));
  }, [url, ...deps]);
  return { data, loading };
}

// ─── Main App ─────────────────────────────────────────────────────────────────
export default function App() {
  const [tab,       setTab]       = useState("overview");
  const [sessions,  setSessions]  = useState([]);
  const [activeSid, setActiveSid] = useState(null);
  const [livePackets,setLive]     = useState([]);
  const [paused,    setPaused]    = useState(false);
  const [wsOk,      setWsOk]      = useState(false);
  const [capturing, setCapturing] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [notif,     setNotif]     = useState(null);
  const [sideOpen,  setSideOpen]  = useState(true);
  const fileRef = useRef(null);
  const wsRef   = useRef(null);

  // ── Data fetching ──────────────────────────────────────────────────────────
  const { data:flows }      = useApi(activeSid ? `${API}/sessions/${activeSid}/flows?limit=300` : null, [activeSid]);
  const { data:stats }      = useApi(activeSid ? `${API}/sessions/${activeSid}/stats` : null, [activeSid]);
  const { data:graph }      = useApi(activeSid ? `${API}/sessions/${activeSid}/graph` : null, [activeSid]);
  const { data:analysisArr} = useApi(activeSid ? `${API}/sessions/${activeSid}/analysis` : null, [activeSid]);
  const analysis = analysisArr?.[0]?.result_data;

  const loadSessions = useCallback(() => {
    fetch(`${API}/sessions`).then(r => r.json()).then(setSessions).catch(() => {});
  }, []);

  useEffect(() => { loadSessions(); const t = setInterval(loadSessions, 8000); return () => clearInterval(t); }, []);

  // ── WebSocket ──────────────────────────────────────────────────────────────
  useEffect(() => {
    let reconnect = true;
    const connect = () => {
      const ws = new WebSocket(WS_URL);
      ws.onopen  = () => setWsOk(true);
      ws.onclose = () => { setWsOk(false); if (reconnect) setTimeout(connect, 3000); };
      ws.onmessage = e => {
        const msg = JSON.parse(e.data);
        if (msg.event === "packet" && !paused)
          setLive(p => [msg.data, ...p.slice(0, 399)]);
        if (msg.event === "pcap_complete" || msg.event === "analysis_complete")
          loadSessions();
        if (msg.event === "analysis_complete")
          toast("✓ Analysis complete", C.green);
        if (msg.event === "pcap_complete")
          toast(`✓ PCAP processed — ${msg.packets} packets`, C.cyan);
      };
      wsRef.current = ws;
    };
    connect();
    return () => { reconnect = false; wsRef.current?.close(); };
  }, [paused]);

  const toast = (msg, color = C.cyan) => {
    setNotif({ msg, color });
    setTimeout(() => setNotif(null), 4000);
  };

  // ── Capture ────────────────────────────────────────────────────────────────
  const startCapture = async () => {
    const r = await fetch(`${API}/capture/start`, {
      method:"POST", headers:{"Content-Type":"application/json"},
      body: JSON.stringify({ interface:"eth0" }),
    });
    const d = await r.json();
    setCapturing(true); setActiveSid(d.session_id);
    loadSessions(); toast("● Capture started", C.green);
  };

  const stopCapture = async () => {
    const r = await fetch(`${API}/capture/stop`, { method:"POST" });
    const d = await r.json();
    setCapturing(false);
    if (d.session_id) setActiveSid(d.session_id);
    loadSessions(); toast("■ Capture stopped", C.amber);
  };

  const uploadPcap = async e => {
    const file = e.target.files[0]; if (!file) return;
    setUploading(true); toast("⬆ Uploading PCAP…");
    const fd = new FormData(); fd.append("file", file);
    const r = await fetch(`${API}/upload/pcap`, { method:"POST", body:fd });
    const d = await r.json();
    setUploading(false); setActiveSid(d.session_id);
    loadSessions(); e.target.value = "";
  };

  // ── Computed ───────────────────────────────────────────────────────────────
  const timelineData = useMemo(() =>
    (stats?.timeline || []).map(t => ({
      time: new Date(t.bucket * 1000).toLocaleTimeString(),
      packets: t.cnt, kbytes: Math.round((t.bytes||0)/1024),
    })), [stats]);

  const protoData = useMemo(() =>
    (stats?.protocol_distribution || []).map(p => ({ name:p.protocol, value:p.cnt })), [stats]);

  const clusterData = useMemo(() =>
    (analysis?.clusters || []).map(c => ({ name:c.label.replace(/_/g," "), value:c.flow_count })), [analysis]);

  // ── Alerts for banner ──────────────────────────────────────────────────────
  const activeAlerts = useMemo(() => {
    const a = [];
    if ((analysis?.summary?.beacon_count || 0) > 0)
      a.push({ color:C.red, icon:"⚡", message:`${analysis.summary.beacon_count} beacon alert(s) detected — possible C2 activity`, badge:"C2" });
    if ((analysis?.summary?.exfil_alerts || 0) > 0)
      a.push({ color:C.amber, icon:"⬆", message:`${analysis.summary.exfil_alerts} possible data exfiltration event(s) detected`, badge:"EXFIL" });
    if ((analysis?.summary?.dga_domains || 0) > 0)
      a.push({ color:C.purple, icon:"◈", message:`${analysis.summary.dga_domains} DGA-generated domain(s) detected`, badge:"DGA" });
    if ((analysis?.summary?.ttl_anomalies || 0) > 0)
      a.push({ color:C.amber, icon:"⚠", message:`${analysis.summary.ttl_anomalies} TTL anomaly/anomalies — possible spoofing or tunneling` });
    return a;
  }, [analysis]);

  // ── Nav ────────────────────────────────────────────────────────────────────
  const NAV = [
    { id:"overview",   label:"Overview",      icon:"◈",  badge: activeAlerts.length },
    { id:"live",       label:"Live Monitor",  icon:"◉",  badge: capturing ? "LIVE" : null },
    { id:"flows",      label:"Flow Table",    icon:"≡"  },
    { id:"graph",      label:"Network Map",   icon:"⬡"  },
    { id:"beacons",    label:"Beacons",       icon:"⚡", badge: analysis?.summary?.beacon_count || null, badgeColor: C.red },
    { id:"exfil",      label:"Exfiltration",  icon:"⬆", badge: analysis?.summary?.exfil_alerts || null, badgeColor: C.amber },
    { id:"endpoints",  label:"Endpoints",     icon:"◎"  },
    { id:"tls",        label:"TLS / JA3",     icon:"🔐" },
    { id:"dga",        label:"DGA / DNS",     icon:"◻", badge: analysis?.summary?.dga_domains || null, badgeColor: C.purple },
    { id:"ttl",        label:"TTL Profiles",  icon:"⊕",  badge: analysis?.summary?.ttl_anomalies || null, badgeColor: C.amber },
    { id:"clusters",   label:"Flow Clusters", icon:"⬟"  },
    { id:"visualize",  label:"Advanced Visuals", icon:"◆"  },
  ];

  const session = sessions.find(s => s.id === activeSid);
  const graphNodes = useMemo(() => {
    const suspIps = new Set((analysis?.suspicious_ips || []).filter(x => x.suspicion_score > 40).map(x => x.ip));
    return (graph?.nodes || []).map(n => ({ ...n, suspicious: suspIps.has(n.id) }));
  }, [graph, analysis]);

  // ─── CSS animation ────────────────────────────────────────────────────────
  const style = document.createElement("style");
  style.innerHTML = `@keyframes pulse { 0%,100%{opacity:1}50%{opacity:0.3} }`;
  document.head.appendChild(style);

  return (
    <div style={{ display:"flex", minHeight:"100vh", background:C.bg0, color:C.text,
                   fontFamily:"-apple-system,'Segoe UI',sans-serif" }}>
      {/* Global CSS */}
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;700&display=swap');
        *::-webkit-scrollbar{width:4px;height:4px}
        *::-webkit-scrollbar-track{background:${C.bg0}}
        *::-webkit-scrollbar-thumb{background:${C.border};border-radius:2px}
        @keyframes pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.4;transform:scale(0.9)}}
        @keyframes fadein{from{opacity:0;transform:translateY(-6px)}to{opacity:1;transform:none}}
      `}</style>

      {/* ── Sidebar ─────────────────────────────────────────────────────── */}
      <div style={{
        width: sideOpen ? 230 : 56, flexShrink:0,
        background:C.bg1, borderRight:`1px solid ${C.border}`,
        display:"flex", flexDirection:"column",
        position:"sticky", top:0, height:"100vh",
        overflow:"hidden", transition:"width 0.2s",
      }}>
        {/* Logo */}
        <div style={{ padding:"20px 14px 14px", display:"flex", alignItems:"center", gap:10, overflow:"hidden" }}>
          <div style={{
            width:28, height:28, background:`linear-gradient(135deg, ${C.cyan}, ${C.blue})`,
            borderRadius:6, display:"flex", alignItems:"center", justifyContent:"center",
            fontSize:14, flexShrink:0,
          }}>⬡</div>
          {sideOpen && (
            <div>
              <div style={{ fontFamily:"'IBM Plex Mono',monospace", letterSpacing:3,
                             fontSize:11, fontWeight:700 }}>
                <span style={{ color:C.cyan }}>NET</span>
                <span style={{ color:C.text }}>FORENSICS</span>
              </div>
              <div style={{ color:C.textDim, fontSize:8, letterSpacing:2.5, marginTop:1 }}>
                METADATA ANALYSIS v2
              </div>
            </div>
          )}
          <button onClick={() => setSideOpen(v => !v)} style={{
            marginLeft:"auto", background:"transparent", border:"none",
            color:C.textDim, cursor:"pointer", fontSize:14, flexShrink:0,
          }}>{sideOpen ? "‹" : "›"}</button>
        </div>

        {/* Status row */}
        {sideOpen && (
          <div style={{ padding:"6px 14px 12px", display:"flex", alignItems:"center", gap:8 }}>
            <div style={{
              width:7, height:7, borderRadius:"50%",
              background:wsOk ? C.green : C.red,
              boxShadow:`0 0 8px ${wsOk?C.green:C.red}`,
              animation: wsOk ? "pulse 2s infinite" : "none",
            }}/>
            <span style={{ fontSize:10, color:C.textSub, letterSpacing:1.5 }}>
              {wsOk ? "CONNECTED" : "OFFLINE"}
            </span>
          </div>
        )}

        {/* Nav items */}
        <div style={{ padding:"0 6px", flex:1, overflowY:"auto" }}>
          {NAV.map(n => {
            const active = tab === n.id;
            const badgeColor = n.badgeColor || C.red;
            return (
              <button key={n.id} onClick={() => setTab(n.id)} style={{
                display:"flex", alignItems:"center", gap:10, width:"100%",
                padding:"8px 10px", marginBottom:2,
                background: active ? `${C.cyan}12` : "transparent",
                border:`1px solid ${active ? C.cyan+"35" : "transparent"}`,
                borderRadius:6, color: active ? C.cyan : C.textSub,
                fontSize:12, cursor:"pointer", textAlign:"left",
                transition:"all 0.1s", overflow:"hidden",
              }}>
                <span style={{ fontSize:15, minWidth:20, textAlign:"center" }}>{n.icon}</span>
                {sideOpen && (
                  <>
                    <span style={{ flex:1, whiteSpace:"nowrap" }}>{n.label}</span>
                    {n.badge ? (
                      <span style={{
                        background: typeof n.badge === "string" ? `${C.green}20` : `${badgeColor}20`,
                        color: typeof n.badge === "string" ? C.green : badgeColor,
                        border:`1px solid ${typeof n.badge === "string" ? C.green : badgeColor}40`,
                        borderRadius:10, padding:"0 6px", fontSize:9, fontWeight:700,
                        letterSpacing:1, lineHeight:"16px",
                      }}>
                        {n.badge}
                      </span>
                    ) : null}
                  </>
                )}
              </button>
            );
          })}
        </div>

        {/* Sessions panel */}
        {sideOpen && (
          <div style={{ borderTop:`1px solid ${C.border}`, padding:"10px 10px" }}>
            <div style={{ fontSize:9, color:C.textDim, letterSpacing:2.5,
                           textTransform:"uppercase", marginBottom:8, paddingLeft:4 }}>
              Sessions
            </div>
            <div style={{ maxHeight:200, overflowY:"auto" }}>
              {sessions.map(s => (
                <button key={s.id} onClick={() => setActiveSid(s.id)} style={{
                  display:"block", width:"100%", textAlign:"left",
                  padding:"7px 10px", marginBottom:3,
                  background: activeSid===s.id ? `${C.cyan}10` : "transparent",
                  border:`1px solid ${activeSid===s.id ? C.cyan+"30" : "transparent"}`,
                  borderRadius:6, cursor:"pointer",
                }}>
                  <div style={{
                    color: activeSid===s.id ? C.cyan : C.text,
                    fontSize:11, fontWeight:600,
                    overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap",
                  }}>{s.name}</div>
                  <div style={{ color:C.textDim, fontSize:10, marginTop:2 }}>
                    {(s.total_packets||0).toLocaleString()} pkts &nbsp;
                    <Tag label={s.status} small
                      color={s.status==="completed"?C.green:s.status==="running"?C.amber:s.status==="error"?C.red:C.textDim}/>
                  </div>
                </button>
              ))}
              {!sessions.length && (
                <div style={{ color:C.textDim, fontSize:11, padding:"8px 4px" }}>No sessions yet</div>
              )}
            </div>
          </div>
        )}
      </div>

      {/* ── Main content ────────────────────────────────────────────────── */}
      <div style={{ flex:1, overflow:"auto", maxHeight:"100vh" }}>

        {/* Topbar */}
        <div style={{
          position:"sticky", top:0, zIndex:20,
          background:`${C.bg1}f0`, backdropFilter:"blur(12px)",
          borderBottom:`1px solid ${C.border}`,
          display:"flex", alignItems:"center", justifyContent:"space-between",
          padding:"12px 24px",
        }}>
          <div>
            <h1 style={{ margin:0, fontSize:17, fontWeight:700, color:C.text }}>
              {NAV.find(n => n.id === tab)?.label}
            </h1>
            {session && (
              <div style={{ fontSize:10, color:C.textSub, fontFamily:"monospace", marginTop:2 }}>
                {session.name} &nbsp;·&nbsp; {activeSid?.slice(0,8)}…
              </div>
            )}
          </div>
          <div style={{ display:"flex", gap:8, alignItems:"center" }}>
            {notif && (
              <div style={{
                padding:"6px 14px", background:`${notif.color}15`,
                border:`1px solid ${notif.color}40`, borderRadius:6,
                fontSize:11, color:notif.color, animation:"fadein 0.2s ease",
              }}>{notif.msg}</div>
            )}
            <input ref={fileRef} type="file" accept=".pcap" onChange={uploadPcap} style={{display:"none"}}/>
            <button onClick={() => fileRef.current?.click()} style={{
              background:`${C.blue}18`, border:`1px solid ${C.blue}50`,
              color:C.blue, borderRadius:6, padding:"7px 14px",
              cursor:"pointer", fontSize:11, fontWeight:700,
            }}>
              {uploading ? "⟳ Processing…" : "⬆ Import PCAP"}
            </button>
            {capturing
              ? <button onClick={stopCapture} style={{
                  background:`${C.red}18`, border:`1px solid ${C.red}60`,
                  color:C.red, borderRadius:6, padding:"7px 14px",
                  cursor:"pointer", fontSize:11, fontWeight:700,
                }}>■ Stop Capture</button>
              : <button onClick={startCapture} style={{
                  background:`linear-gradient(135deg, ${C.cyan}cc, ${C.blue}cc)`,
                  border:"none", color:"#000", borderRadius:6, padding:"7px 16px",
                  cursor:"pointer", fontSize:11, fontWeight:800,
                }}>▶ Live Capture</button>
            }
          </div>
        </div>

        <div style={{ padding:20 }}>
          <AlertBanner alerts={activeAlerts}/>

          {/* ══ OVERVIEW ══ */}
          {tab === "overview" && (
            <div>
              <div style={{ display:"flex", gap:12, flexWrap:"wrap", marginBottom:20 }}>
                <Stat label="Total Flows"     value={analysis?.summary?.total_flows?.toLocaleString()} icon="⟁"/>
                <Stat label="Total Packets"   value={analysis?.summary?.total_packets?.toLocaleString()} color={C.text}/>
                <Stat label="Unique IPs"      value={analysis?.summary?.unique_ips} color={C.purple}/>
                <Stat label="Beacon Alerts"   value={analysis?.summary?.beacon_count ?? 0} color={C.red} pulse/>
                <Stat label="Suspicious IPs"  value={analysis?.summary?.suspicious_ip_count ?? 0} color={C.amber}/>
                <Stat label="DGA Domains"     value={analysis?.summary?.dga_domains ?? 0} color={C.purple}/>
                <Stat label="Exfil Alerts"    value={analysis?.summary?.exfil_alerts ?? 0} color={C.amber}/>
                <Stat label="TTL Anomalies"   value={analysis?.summary?.ttl_anomalies ?? 0} color={C.amber}/>
              </div>

              <div style={{ display:"grid", gridTemplateColumns:"2fr 1fr", gap:16, marginBottom:16 }}>
                <Card title="Traffic Volume Timeline">
                  <ResponsiveContainer width="100%" height={220}>
                    <AreaChart data={timelineData}>
                      <defs>
                        <linearGradient id="ag1" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%"  stopColor={C.cyan} stopOpacity={0.25}/>
                          <stop offset="95%" stopColor={C.cyan} stopOpacity={0}/>
                        </linearGradient>
                        <linearGradient id="ag2" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%"  stopColor={C.blue} stopOpacity={0.2}/>
                          <stop offset="95%" stopColor={C.blue} stopOpacity={0}/>
                        </linearGradient>
                      </defs>
                      <CartesianGrid stroke={C.border} strokeDasharray="4 4"/>
                      <XAxis dataKey="time" stroke={C.textDim} fontSize={9} interval="preserveStartEnd"/>
                      <YAxis yAxisId="l" stroke={C.textDim} fontSize={9}/>
                      <YAxis yAxisId="r" orientation="right" stroke={C.textDim} fontSize={9}/>
                      <Tooltip contentStyle={TT}/>
                      <Area yAxisId="l" type="monotone" dataKey="packets" stroke={C.cyan}
                            fill="url(#ag1)" strokeWidth={1.5} dot={false} name="Packets"/>
                      <Area yAxisId="r" type="monotone" dataKey="kbytes" stroke={C.blue}
                            fill="url(#ag2)" strokeWidth={1.5} dot={false} name="KB"/>
                    </AreaChart>
                  </ResponsiveContainer>
                </Card>
                <Card title="Protocol Mix">
                  <ResponsiveContainer width="100%" height={220}>
                    <PieChart>
                      <Pie data={protoData} dataKey="value" nameKey="name"
                           cx="50%" cy="50%" outerRadius={80} innerRadius={44}
                           label={({ name, percent }) => percent > 0.05 ? `${name} ${(percent*100).toFixed(0)}%` : ""}
                           labelLine={false}>
                        {protoData.map((e, i) => (
                          <Cell key={i} fill={PROTO_COL(e.name)} opacity={0.85}/>
                        ))}
                      </Pie>
                      <Tooltip contentStyle={TT}/>
                    </PieChart>
                  </ResponsiveContainer>
                </Card>
              </div>

              <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:16 }}>
                <Card title="Top Source IPs" noPad>
                  <Table cols={[
                    { key:"ip",    label:"IP",    render:v => mono(v) },
                    { key:"flows", label:"Flows", color:C.cyan },
                    { key:"bytes", label:"Bytes", render:v => fmtBytes(v) },
                  ]} rows={stats?.top_sources || []}/>
                </Card>
                <Card title="Top Destination IPs" noPad>
                  <Table cols={[
                    { key:"ip",    label:"IP",    render:v => mono(v) },
                    { key:"flows", label:"Flows", color:C.cyan },
                    { key:"bytes", label:"Bytes", render:v => fmtBytes(v) },
                  ]} rows={stats?.top_destinations || []}/>
                </Card>
              </div>
            </div>
          )}

          {/* ══ LIVE MONITOR ══ */}
          {tab === "live" && (
            <div>
              <div style={{ display:"flex", gap:12, flexWrap:"wrap", marginBottom:20 }}>
                <Stat label="Captured"    value={livePackets.length.toLocaleString()} color={capturing?C.green:C.textSub} pulse={capturing}/>
                <Stat label="Unique Src"  value={new Set(livePackets.map(p=>p.src_ip)).size} color={C.purple}/>
                <Stat label="TLS"         value={livePackets.filter(p=>p.protocol==="TLS").length} color={C.TLS}/>
                <Stat label="DNS"         value={livePackets.filter(p=>p.protocol==="DNS").length} color={C.DNS}/>
                <Stat label="With SNI"    value={livePackets.filter(p=>p.sni).length}  color={C.amber}/>
                <Stat label="⚠ Malware JA3" value={livePackets.filter(p=>p.ja3?.startsWith("e7d7")).length} color={C.red} pulse/>
              </div>

              <div style={{ display:"grid", gridTemplateColumns:"2fr 1fr", gap:16, marginBottom:16 }}>
                <Card title="Realtime Packet Rate">
                  <ResponsiveContainer width="100%" height={180}>
                    <BarChart data={(() => {
                      const bkts = {};
                      livePackets.forEach(p => {
                        const b = Math.floor(p.timestamp/5)*5;
                        bkts[b] = (bkts[b]||0) + 1;
                      });
                      return Object.entries(bkts).slice(-30).map(([t,c]) => ({
                        time: new Date(+t*1000).toLocaleTimeString(), count:c,
                      }));
                    })()}>
                      <CartesianGrid stroke={C.border} strokeDasharray="4 4"/>
                      <XAxis dataKey="time" stroke={C.textDim} fontSize={9}/>
                      <YAxis stroke={C.textDim} fontSize={9}/>
                      <Tooltip contentStyle={TT}/>
                      <Bar dataKey="count" fill={C.cyan} radius={[3,3,0,0]} opacity={0.8}/>
                    </BarChart>
                  </ResponsiveContainer>
                </Card>
                <Card title="Protocol Split">
                  <div style={{ display:"flex", flexDirection:"column", gap:12, paddingTop:4 }}>
                    {Object.entries({ TLS:C.TLS, TCP:C.TCP, UDP:C.UDP, DNS:C.DNS, ICMP:C.ICMP }).map(([proto,color]) => {
                      const cnt = livePackets.filter(p=>p.protocol===proto).length;
                      const pct = livePackets.length ? cnt/livePackets.length*100 : 0;
                      return (
                        <div key={proto}>
                          <div style={{ display:"flex", justifyContent:"space-between", marginBottom:5 }}>
                            <Tag label={proto} color={color}/>
                            <span style={{ fontSize:11, color:C.textSub, fontFamily:"monospace" }}>{cnt}</span>
                          </div>
                          <div style={{ background:C.bg0, borderRadius:3, height:4 }}>
                            <div style={{ width:`${pct}%`, background:color, height:"100%",
                                           borderRadius:3, transition:"width 0.4s",
                                           boxShadow:pct>0?`0 0 6px ${color}80`:"none" }}/>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </Card>
              </div>
              <Card noPad glow={capturing ? C.green : undefined}>
                <LiveFeed packets={livePackets} paused={paused} onToggle={() => setPaused(v=>!v)}/>
              </Card>
            </div>
          )}

          {/* ══ FLOWS ══ */}
          {tab === "flows" && (
            <Card title={`Flow Records — ${flows?.total?.toLocaleString()||0} total`} noPad>
              <Table cols={[
                { key:"src_ip",   label:"Source",     render:v => mono(v) },
                { key:"src_port", label:"SPort",       color:C.textSub },
                { key:"dst_ip",   label:"Destination", render:v => mono(v) },
                { key:"dst_port", label:"DPort",       color:C.textSub },
                { key:"protocol", label:"Proto",       render:v => <Tag label={v} color={PROTO_COL(v)}/> },
                { key:"packet_count", label:"Pkts",   color:C.cyan },
                { key:"total_bytes",  label:"Bytes",  render:v => fmtBytes(v) },
                { key:"session_duration", label:"Duration", render:v => v ? `${(+v).toFixed(1)}s` : "—" },
                { key:"sni",  label:"SNI",  render:v => v ? <span style={{color:C.purple,fontSize:11}}>{v}</span> : "—" },
                { key:"ja3",  label:"JA3",  render:(v,row) => v ? (
                  <span style={{ color: row.ja3_malware ? C.red : C.cyan,
                                   fontFamily:"monospace", fontSize:10 }}>
                    {v.slice(0,14)}…
                    {row.ja3_malware && <span style={{marginLeft:4}}>⚠</span>}
                  </span>
                ) : "—" },
              ]} rows={flows?.flows || []}/>
            </Card>
          )}

          {/* ══ NETWORK GRAPH ══ */}
          {tab === "graph" && (
            <div>
              <div style={{ display:"flex", gap:12, marginBottom:14, flexWrap:"wrap", alignItems:"center" }}>
                <div style={{ color:C.textSub, fontSize:12 }}>
                  {graphNodes.length} nodes · {graph?.edges?.length||0} edges
                </div>
                <div style={{ display:"flex", gap:10 }}>
                  {Object.entries({ TLS:C.TLS, TCP:C.TCP, UDP:C.UDP, DNS:C.DNS }).map(([p,c]) => (
                    <div key={p} style={{ display:"flex", alignItems:"center", gap:5 }}>
                      <div style={{ width:18, height:2.5, background:c, borderRadius:2 }}/>
                      <span style={{ fontSize:10, color:C.textSub, fontFamily:"monospace" }}>{p}</span>
                    </div>
                  ))}
                </div>
                <div style={{ color:C.textDim, fontSize:10, marginLeft:"auto" }}>
                  Drag nodes to rearrange · Red ring = suspicious
                </div>
              </div>
              <Card noPad>
                <NetworkGraph nodes={graphNodes} edges={graph?.edges||[]}/>
              </Card>
            </div>
          )}

          {/* ══ BEACONS ══ */}
          {tab === "beacons" && (
            <div>
              <Card style={{ marginBottom:16, background:`${C.red}08`, borderColor:`${C.red}25` }}>
                <div style={{ fontSize:12, color:C.textSub, lineHeight:1.7 }}>
                  <span style={{ color:C.red, fontWeight:700 }}>⚡ Beacon Detection Algorithm</span>&nbsp;—
                  Analyses inter-connection timing intervals between each (src, dst, port) pair.
                  Uses <b style={{color:C.text}}>Coefficient of Variation</b> (CV = σ/μ) on intervals.
                  &nbsp;CV &lt; 10% → <b style={{color:C.red}}>HIGH</b>,
                  CV &lt; 25% → <b style={{color:C.amber}}>MEDIUM</b>,
                  CV &lt; 40% → <b style={{color:C.textSub}}>LOW</b>.
                  Low CV means highly periodic traffic — a hallmark of malware command-and-control.
                </div>
              </Card>
              {!(analysis?.beacons?.length) && (
                <div style={{ textAlign:"center", padding:"60px 20px", color:C.textDim }}>
                  ✓ No beacon activity detected in this session
                </div>
              )}
              {(analysis?.beacons || []).map((b, i) => <BeaconCard key={i} b={b}/>)}
            </div>
          )}

          {/* ══ EXFILTRATION ══ */}
          {tab === "exfil" && (
            <div>
              <Card style={{ marginBottom:16, background:`${C.amber}08`, borderColor:`${C.amber}25` }}>
                <div style={{ fontSize:12, color:C.textSub, lineHeight:1.7 }}>
                  <span style={{ color:C.amber, fontWeight:700 }}>⬆ Data Exfiltration Detection</span>&nbsp;—
                  Flags IP pairs where outbound bytes significantly exceed inbound bytes.
                  Threshold: <b style={{color:C.text}}>ratio &gt; 10× and sent &gt; 10 MB</b>.
                  High asymmetry can indicate data theft, command output exfiltration, or bulk file upload to untrusted destinations.
                </div>
              </Card>
              {!(analysis?.exfil_alerts?.length) && (
                <div style={{ textAlign:"center", padding:"60px 20px", color:C.textDim }}>
                  ✓ No high-ratio exfiltration detected
                </div>
              )}
              <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:14 }}>
                {(analysis?.exfil_alerts || []).map((e, i) => (
                  <div key={i} style={{
                    background:`${C.amber}08`, border:`1px solid ${C.amber}30`,
                    borderLeft:`3px solid ${C.amber}`, borderRadius:8, padding:"14px 18px",
                  }}>
                    <div style={{ fontFamily:"monospace", fontSize:13, color:C.text, marginBottom:10 }}>
                      {e.src_ip} <span style={{color:C.textDim}}>→</span> {e.dst_ip}
                    </div>
                    <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:10 }}>
                      {[
                        { l:"Sent",    v:fmtBytes(e.total_sent) },
                        { l:"Received",v:fmtBytes(e.total_recv) },
                        { l:"Ratio",   v:`${e.ratio}×`, bold:true },
                        { l:"Sessions",v:e.session_count },
                      ].map(x => (
                        <div key={x.l} style={{ background:C.bg3, borderRadius:5, padding:"7px 10px" }}>
                          <div style={{ color:C.textDim, fontSize:9, letterSpacing:1.5, textTransform:"uppercase" }}>{x.l}</div>
                          <div style={{ color:x.bold?C.amber:C.text, fontSize:16, fontWeight:700,
                                         fontFamily:"monospace", marginTop:2 }}>{x.v}</div>
                        </div>
                      ))}
                    </div>
                    {e.sni && <div style={{ marginTop:8, color:C.purple, fontSize:11, fontFamily:"monospace" }}>SNI: {e.sni}</div>}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* ══ ENDPOINTS ══ */}
          {tab === "endpoints" && (
            <Card title="Endpoint Threat Profiles" noPad>
              <Table cols={[
                { key:"ip",              label:"IP Address",    render:v => mono(v) },
                { key:"suspicion_score", label:"Risk",          render:v => <RiskBar score={v}/> },
                { key:"total_flows",     label:"Flows",         color:C.cyan },
                { key:"total_bytes",     label:"Bytes",         render:v => fmtBytes(v) },
                { key:"fan_out",         label:"Fan-out",       color:C.textSub },
                { key:"port_entropy",    label:"Port Entropy",  render:v => v ? (
                  <span style={{color: v>3.5?C.red:v>2.5?C.amber:C.textSub}}>{v?.toFixed(2)}</span>
                ) : "—" },
                { key:"os_guess",        label:"OS Guess",      render:v => v ? <Tag label={v} color={C.cyan}/> : "—" },
                { key:"dga_domains",     label:"DGA",           render:v => v?.length ? <Tag label={`${v.length}×`} color={C.purple}/> : "—" },
                { key:"malware_ja3_matches", label:"Malware JA3", render:v => v?.length ? <Tag label={`⚠ ${v[0]}`} color={C.red}/> : "—" },
                { key:"beacon_count",    label:"Beacons",       render:v => v ? <Tag label={v} color={C.red}/> : "—" },
                { key:"reasons",         label:"Reasons",       render:v => (
                  <div style={{display:"flex",gap:4,flexWrap:"wrap"}}>
                    {(v||[]).slice(0,2).map((r,i) => (
                      <span key={i} style={{ background:`${C.amber}12`, color:C.amber,
                                              border:`1px solid ${C.amber}25`, borderRadius:3,
                                              padding:"1px 7px", fontSize:9 }}>{r}</span>
                    ))}
                  </div>
                )},
              ]} rows={analysis?.suspicious_ips || []}
                 empty="No suspicious endpoints — run analysis first"/>
            </Card>
          )}

          {/* ══ TLS / JA3 ══ */}
          {tab === "tls" && (
            <div>
              <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:16, marginBottom:16 }}>
                <Card title="TLS Version Distribution">
                  <ResponsiveContainer width="100%" height={220}>
                    <PieChart>
                      <Pie data={(() => {
                        const m = {};
                        (stats?.tls_fingerprints||[]).forEach(f => {
                          const v = f.tls_version || "Unknown";
                          m[v] = (m[v]||0) + f.cnt;
                        });
                        return Object.entries(m).map(([name,value])=>({name,value}));
                      })()} dataKey="value" nameKey="name"
                           cx="50%" cy="50%" outerRadius={82} innerRadius={44}
                           label={({name,percent})=>`${name} ${(percent*100).toFixed(0)}%`} labelLine={false}>
                        {PIE_COLS.map((_,i) => <Cell key={i} fill={PIE_COLS[i]}/>)}
                      </Pie>
                      <Tooltip contentStyle={TT}/>
                    </PieChart>
                  </ResponsiveContainer>
                </Card>

                <Card title="Malware JA3 Cross-Reference">
                  {[
                    { hash:"e7d705a3286e19ea42f587b344ee6865", label:"Cobalt Strike default", col:C.red },
                    { hash:"6734f37431670b3ab4292b8f60f29984", label:"Metasploit Meterpreter",col:C.red },
                    { hash:"de9f2c7fd25e1b3afad3e85a0226823f", label:"TrickBot / Emotet",     col:C.amber },
                    { hash:"a0e9f5d64349fb13191bc781f81f42e1", label:"Metasploit stager",      col:C.amber },
                    { hash:"e7eca2baf4458d095b7f45da28c16c34", label:"Dridex banking trojan",  col:C.amber },
                  ].map((kh, i) => {
                    const hit = (stats?.tls_fingerprints||[]).find(f => f.ja3 === kh.hash);
                    return (
                      <div key={i} style={{ display:"flex", justifyContent:"space-between",
                                             alignItems:"center", padding:"9px 0",
                                             borderBottom: i<4 ? `1px solid ${C.border}18` : "none" }}>
                        <div>
                          <div style={{ fontFamily:"monospace", fontSize:10, color:hit?kh.col:C.textDim }}>
                            {kh.hash.slice(0,26)}…
                          </div>
                          <div style={{ color:hit?kh.col:C.textSub, fontSize:12, fontWeight:hit?700:400, marginTop:1 }}>
                            {kh.label}
                          </div>
                        </div>
                        {hit
                          ? <Tag label={`⚠ ${hit.cnt}×`} color={kh.col}/>
                          : <span style={{ color:C.green, fontSize:12 }}>✓ Clean</span>
                        }
                      </div>
                    );
                  })}
                </Card>
              </div>
              <Card title="JA3 Fingerprint Registry" noPad>
                <Table cols={[
                  { key:"ja3",         label:"JA3 Hash",     render:v => mono(v) },
                  { key:"tls_version", label:"TLS Version" },
                  { key:"sni",         label:"SNI",          render:v => v ? <span style={{color:C.purple}}>{v}</span> : "—" },
                  { key:"cnt",         label:"Flows",        color:C.cyan },
                  { key:"malware",     label:"Malware",      render:v => v ? <Tag label={`⚠ ${v}`} color={C.red}/> : "—" },
                ]} rows={stats?.tls_fingerprints || []}/>
              </Card>
            </div>
          )}

          {/* ══ DGA / DNS ══ */}
          {tab === "dga" && (
            <div>
              <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:16, marginBottom:16 }}>
                <Card title="DGA Domain Alerts" glow={analysis?.dga_alerts?.length ? C.purple : undefined}>
                  <div style={{ fontSize:11, color:C.textSub, marginBottom:14, lineHeight:1.6 }}>
                    <b style={{color:C.purple}}>DGA detection</b> uses three metrics:
                    label entropy (&gt;3.5 bits), consonant ratio (&gt;65%), and label length (&gt;12 chars).
                    Score ≥ 60% is flagged.
                  </div>
                  {(analysis?.dga_alerts || []).map((d, i) => (
                    <div key={i} style={{
                      background:`${C.purple}08`, border:`1px solid ${C.purple}30`,
                      borderLeft:`3px solid ${C.purple}`, borderRadius:6, padding:"10px 14px", marginBottom:8,
                    }}>
                      <div style={{ fontFamily:"monospace", color:C.text, fontSize:12, marginBottom:6 }}>
                        {d.domain}
                        <Pill value={`DGA ${(d.dga_score*100).toFixed(0)}%`} color={C.purple}/>
                      </div>
                      <div style={{ display:"flex", gap:16, fontSize:11, color:C.textSub }}>
                        <span>Entropy: <b style={{color:C.text}}>{d.entropy}</b></span>
                        <span>Consonant: <b style={{color:C.text}}>{(d.consonant_ratio*100).toFixed(0)}%</b></span>
                        <span>Length: <b style={{color:C.text}}>{d.label_length}</b></span>
                        <span>Src: <b style={{color:C.text,fontFamily:"monospace"}}>{d.src_ip}</b></span>
                      </div>
                    </div>
                  ))}
                  {!analysis?.dga_alerts?.length && (
                    <div style={{color:C.textDim, textAlign:"center", padding:"30px 0"}}>
                      ✓ No DGA-like domains detected
                    </div>
                  )}
                </Card>

                <Card title="DNS Query Type Distribution">
                  <ResponsiveContainer width="100%" height={250}>
                    <BarChart layout="vertical" data={(() => {
                      const m = {};
                      (stats?.dns_queries||[]).forEach(q => { m[q.dns_type||"?"]=(m[q.dns_type||"?"]||0)+q.cnt; });
                      return Object.entries(m).map(([name,value])=>({name,value}));
                    })()}>
                      <CartesianGrid stroke={C.border} strokeDasharray="4 4"/>
                      <XAxis type="number" stroke={C.textDim} fontSize={9}/>
                      <YAxis type="category" dataKey="name" stroke={C.textDim} fontSize={10} width={44}/>
                      <Tooltip contentStyle={TT}/>
                      <Bar dataKey="value" fill={C.DNS} radius={[0,4,4,0]} opacity={0.85}/>
                    </BarChart>
                  </ResponsiveContainer>
                </Card>
              </div>

              <Card title="Top DNS Queries" noPad>
                <Table cols={[
                  { key:"query",     label:"Domain",    render:v => mono(v) },
                  { key:"type",      label:"Type",      render:v => <Tag label={v||"?"} color={C.DNS}/> },
                  { key:"cnt",       label:"Count",     color:C.cyan },
                  { key:"dga_score", label:"DGA Score", render:v => v > 0.4 ? (
                    <span style={{ color:C.purple, fontWeight:700 }}>{(v*100).toFixed(0)}%</span>
                  ) : <span style={{color:C.textDim}}>—</span> },
                ]} rows={stats?.dns_queries || []}/>
              </Card>
            </div>
          )}

          {/* ══ TTL PROFILES ══ */}
          {tab === "ttl" && (
            <div>
              <Card style={{ marginBottom:16, background:`${C.amber}08`, borderColor:`${C.amber}25` }}>
                <div style={{ fontSize:12, color:C.textSub, lineHeight:1.7 }}>
                  <span style={{color:C.amber,fontWeight:700}}>⊕ TTL Fingerprinting</span>&nbsp;—
                  OS inference from initial TTL: Linux≈64, Windows≈128, Cisco≈255.
                  Multiple distinct TTL values from one IP may indicate
                  <b style={{color:C.text}}> IP spoofing</b>, <b style={{color:C.text}}>tunneling</b>, or
                  <b style={{color:C.text}}> multi-hop routing</b> anomalies.
                  Flagged: &gt;3 unique TTL values or variance &gt; 100.
                </div>
              </Card>
              {(analysis?.ttl_profiles||[]).length === 0 && (
                <div style={{ textAlign:"center", padding:"60px 20px", color:C.textDim }}>
                  ✓ No TTL anomalies detected
                </div>
              )}
              <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr 1fr", gap:14 }}>
                {(analysis?.ttl_profiles||[]).map((t, i) => (
                  <div key={i} style={{
                    background:`${C.amber}08`, border:`1px solid ${C.amber}30`,
                    borderTop:`2px solid ${C.amber}`, borderRadius:8, padding:"14px 16px",
                  }}>
                    <div style={{ fontFamily:"monospace", fontSize:13, color:C.text, marginBottom:8 }}>
                      {mono(t.ip)}
                    </div>
                    {[
                      { l:"Dominant TTL",  v:t.dominant_ttl },
                      { l:"OS Guess",      v:t.os_guess },
                      { l:"Unique TTLs",   v:t.unique_ttls },
                      { l:"TTL Variance",  v:t.ttl_variance },
                    ].map(x => (
                      <div key={x.l} style={{ display:"flex", justifyContent:"space-between",
                                               borderBottom:`1px solid ${C.border}20`, padding:"4px 0", fontSize:12 }}>
                        <span style={{color:C.textSub}}>{x.l}</span>
                        <span style={{color:C.text, fontFamily:"monospace"}}>{x.v}</span>
                      </div>
                    ))}
                    {t.anomaly_reason && (
                      <div style={{ marginTop:8, color:C.amber, fontSize:11, fontWeight:600 }}>
                        ⚠ {t.anomaly_reason}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* ══ CLUSTERS ══ */}
          {tab === "clusters" && (
            <div>
              <div style={{ display:"grid", gridTemplateColumns:"2fr 1fr", gap:16 }}>
                <Card title="Flow Cluster Distribution">
                  <ResponsiveContainer width="100%" height={300}>
                    <BarChart data={clusterData} layout="vertical">
                      <CartesianGrid stroke={C.border} strokeDasharray="4 4"/>
                      <XAxis type="number" stroke={C.textDim} fontSize={9}/>
                      <YAxis type="category" dataKey="name" stroke={C.textDim} fontSize={10} width={130}/>
                      <Tooltip contentStyle={TT}/>
                      <Bar dataKey="value" fill={C.cyan} radius={[0,4,4,0]} opacity={0.8}/>
                    </BarChart>
                  </ResponsiveContainer>
                </Card>
                <Card title="Cluster Details">
                  {(analysis?.clusters||[]).map((c,i) => {
                    const colors = [C.cyan,C.purple,C.green,C.amber,C.red,C.blue,C.pink];
                    const col = colors[i % colors.length];
                    return (
                      <div key={i} style={{
                        display:"flex", justifyContent:"space-between", alignItems:"center",
                        padding:"10px 0", borderBottom:`1px solid ${C.border}18`,
                      }}>
                        <div>
                          <div style={{ color:col, fontWeight:700, fontSize:12 }}>
                            {c.label.replace(/_/g," ").toUpperCase()}
                          </div>
                          <div style={{ color:C.textSub, fontSize:11, marginTop:2 }}>
                            port {c.dominant_port} · avg {fmtBytes(c.avg_bytes)}
                          </div>
                        </div>
                        <Pill value={c.flow_count.toLocaleString()} color={col}/>
                      </div>
                    );
                  })}
                </Card>
              </div>
            </div>
          )}

          {/* ══ ADVANCED VISUALIZATIONS ══ */}
          {tab === "visualize" && (
            <AdvancedVisualizationsPanel
              analysis={analysis}
              stats={stats}
              graph={graph}
              graphNodes={graphNodes}
              torData={null}
              livePackets={livePackets}
              activeSid={activeSid}
            />
          )}

          {/* ══ Empty state ══ */}
          {!activeSid && tab !== "live" && (
            <div style={{ textAlign:"center", padding:"80px 20px" }}>
              <div style={{ fontSize:64, marginBottom:20, opacity:0.15 }}>⬡</div>
              <div style={{ fontSize:24, fontWeight:700, color:C.text, marginBottom:10 }}>
                No session selected
              </div>
              <div style={{ fontSize:14, color:C.textSub, marginBottom:32, maxWidth:420, margin:"0 auto 32px" }}>
                Import a PCAP file for offline forensic analysis, or start a live capture session
                to monitor network traffic in real time.
              </div>
              <div style={{ display:"flex", gap:12, justifyContent:"center" }}>
                <button onClick={() => fileRef.current?.click()} style={{
                  background:`${C.blue}20`, border:`1px solid ${C.blue}50`,
                  color:C.blue, borderRadius:8, padding:"11px 24px",
                  cursor:"pointer", fontSize:13, fontWeight:700,
                }}>⬆ Import PCAP</button>
                <button onClick={startCapture} style={{
                  background:`linear-gradient(135deg, ${C.cyan}, ${C.blue})`,
                  border:"none", color:"#000", borderRadius:8, padding:"11px 24px",
                  cursor:"pointer", fontSize:13, fontWeight:800,
                }}>▶ Start Live Capture</button>
              </div>
            </div>
          )}

        </div>
      </div>
    </div>
  );
}
