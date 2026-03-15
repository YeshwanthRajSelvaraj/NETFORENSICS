/**
 * TorCircuitVisualization — Animated Tor circuit path renderer.
 *
 * Features:
 *  • SVG-based multi-hop circuit path with animated data flow
 *  • Guard → Relay → Exit node differentiation with distinct icons
 *  • Onion-layer depth indicators
 *  • Hidden service circuit rendering (6 hops)
 *  • Circuit timing analysis display
 *  • Click-to-expand circuit details
 */
import { useState, useMemo, useRef, useEffect } from "react";
import { C } from "./tokens";

const NODE_COLORS = {
  client:  C.blue,
  guard:   "#f59e0b",
  relay:   "#a78bfa",
  exit:    C.red,
  onion:   "#8b5cf6",
  rp:      C.pink,      // rendezvous point
};

const NODE_ICONS = {
  client: "◉",
  guard:  "⛊",
  relay:  "◈",
  exit:   "↗",
  onion:  "🧅",
  rp:     "⊛",
};

export default function TorCircuitVisualization({ circuits = [], sessionId }) {
  const [selected, setSelected] = useState(null);
  const [animPhase, setAnimPhase] = useState(0);

  // Animate data flow
  useEffect(() => {
    const iv = setInterval(() => setAnimPhase(p => (p + 1) % 100), 50);
    return () => clearInterval(iv);
  }, []);

  if (!circuits.length) {
    return (
      <div style={{
        textAlign: "center", padding: "60px 20px", color: C.textDim,
        fontSize: 13, fontFamily: "monospace",
      }}>
        No Tor circuits detected in this session
      </div>
    );
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      {/* Summary strip */}
      <div style={{
        display: "flex", gap: 12, padding: "12px 16px",
        background: `linear-gradient(90deg, ${C.bg3}, ${C.bg2})`,
        borderRadius: 8, border: `1px solid ${C.purple}25`,
      }}>
        {[
          { label: "Total Circuits",     value: circuits.length,                                   color: C.purple },
          { label: "Hidden Service",     value: circuits.filter(c => c.is_hidden_service).length,  color: "#8b5cf6" },
          { label: "Standard",           value: circuits.filter(c => !c.is_hidden_service).length, color: C.cyan },
          { label: "Avg Build Time",     value: `${(circuits.reduce((s,c) => s + (c.build_time_ms||0), 0) / circuits.length).toFixed(0)}ms`, color: C.amber },
        ].map(s => (
          <div key={s.label} style={{ flex: 1, textAlign: "center" }}>
            <div style={{
              fontSize: 22, fontWeight: 800, color: s.color,
              fontFamily: "'IBM Plex Mono', monospace",
            }}>{s.value}</div>
            <div style={{ fontSize: 9, color: C.textSub, letterSpacing: 1.5, textTransform: "uppercase", marginTop: 2 }}>
              {s.label}
            </div>
          </div>
        ))}
      </div>

      {/* Circuit cards */}
      {circuits.map((circuit, idx) => (
        <CircuitPath
          key={idx}
          circuit={circuit}
          index={idx}
          expanded={selected === idx}
          onToggle={() => setSelected(selected === idx ? null : idx)}
          animPhase={animPhase}
        />
      ))}
    </div>
  );
}

/* ── Single circuit SVG rendering ─────────────────────────────────────────── */
function CircuitPath({ circuit, index, expanded, onToggle, animPhase }) {
  const isHS   = circuit.is_hidden_service;
  const hops   = circuit.hops || [];
  const allNodes = buildNodeList(circuit);

  // SVG dimensions
  const svgW   = 900;
  const svgH   = expanded ? 200 : 120;
  const nodeY  = svgH / 2;
  const spacing = svgW / (allNodes.length + 1);

  return (
    <div
      style={{
        background: `linear-gradient(135deg, ${C.bg2}, ${isHS ? '#8b5cf610' : C.bg3})`,
        border: `1px solid ${isHS ? '#8b5cf635' : C.border}`,
        borderLeft: `3px solid ${isHS ? '#8b5cf6' : C.purple}`,
        borderRadius: 10, overflow: "hidden",
        transition: "all 0.3s",
      }}
    >
      {/* Header */}
      <div
        onClick={onToggle}
        style={{
          display: "flex", alignItems: "center", gap: 10,
          padding: "12px 18px", cursor: "pointer",
          borderBottom: expanded ? `1px solid ${C.border}` : "none",
        }}
      >
        <span style={{ fontSize: 18 }}>{isHS ? "🧅" : "🔗"}</span>
        <span style={{ fontSize: 13, fontWeight: 700, color: C.text }}>
          Circuit {circuit.circuit_id || index + 1}
        </span>
        {isHS && (
          <span style={{
            fontSize: 10, padding: "2px 8px", borderRadius: 6,
            background: "rgba(139,92,246,0.2)", color: "#a78bfa",
          }}>Hidden Service</span>
        )}
        <span style={{
          fontSize: 10, padding: "2px 8px", borderRadius: 6,
          background: `${C.amber}18`, color: C.amber,
        }}>{hops.length} hops</span>
        <div style={{ flex: 1 }} />
        <span style={{ color: C.textDim, fontSize: 12 }}>{expanded ? "▾" : "▸"}</span>
      </div>

      {/* Circuit SVG */}
      <div style={{ padding: "4px 10px 10px" }}>
        <svg viewBox={`0 0 ${svgW} ${svgH}`} style={{ width: "100%", height: svgH }}>
          <defs>
            {/* Animated dash pattern */}
            <linearGradient id={`circGrad${index}`} x1="0" y1="0" x2="1" y2="0">
              <stop offset="0%"  stopColor={C.purple} stopOpacity={0.8} />
              <stop offset="50%" stopColor={isHS ? "#8b5cf6" : C.cyan} stopOpacity={0.6} />
              <stop offset="100%" stopColor={C.purple} stopOpacity={0.8} />
            </linearGradient>
            <filter id={`glow${index}`}>
              <feGaussianBlur stdDeviation="3" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
          </defs>

          {/* Encryption layer indicators (onion layers) */}
          {allNodes.map((_, i) => {
            if (i >= allNodes.length - 1) return null;
            const x1 = spacing * (i + 1);
            const x2 = spacing * (i + 2);
            const layerDepth = allNodes.length - 1 - i;
            const opacity = Math.min(0.12, 0.03 * layerDepth);
            return (
              <rect
                key={`layer-${i}`}
                x={x1 - 10} y={nodeY - 30 - layerDepth * 3}
                width={x2 - x1 + 20} height={60 + layerDepth * 6}
                rx={8} fill={C.purple} opacity={opacity}
              />
            );
          })}

          {/* Connection lines */}
          {allNodes.map((_, i) => {
            if (i >= allNodes.length - 1) return null;
            const x1 = spacing * (i + 1);
            const x2 = spacing * (i + 2);
            return (
              <g key={`link-${i}`}>
                <line
                  x1={x1 + 18} y1={nodeY} x2={x2 - 18} y2={nodeY}
                  stroke={`url(#circGrad${index})`}
                  strokeWidth={2} opacity={0.6}
                />
                {/* Animated data packet */}
                <circle
                  cx={x1 + 18 + ((x2 - x1 - 36) * ((animPhase + i * 15) % 100) / 100)}
                  cy={nodeY}
                  r={2.5}
                  fill={C.cyan}
                  opacity={0.9}
                  filter={`url(#glow${index})`}
                />
              </g>
            );
          })}

          {/* Nodes */}
          {allNodes.map((node, i) => {
            const cx = spacing * (i + 1);
            const color = NODE_COLORS[node.role] || C.textSub;
            return (
              <g key={`node-${i}`} filter={`url(#glow${index})`}>
                <circle cx={cx} cy={nodeY} r={16} fill={`${color}22`}
                        stroke={color} strokeWidth={1.5} />
                <circle cx={cx} cy={nodeY} r={10} fill={`${color}44`} />
                <text x={cx} y={nodeY + 4} textAnchor="middle"
                      fontSize={11} fill={color} fontWeight="bold">
                  {NODE_ICONS[node.role] || "●"}
                </text>
                {/* Label below */}
                <text x={cx} y={nodeY + 32} textAnchor="middle"
                      fontSize={8} fill={C.textSub} fontFamily="monospace">
                  {node.label}
                </text>
                {/* Role label above */}
                <text x={cx} y={nodeY - 24} textAnchor="middle"
                      fontSize={7} fill={color}
                      style={{ textTransform: "uppercase", letterSpacing: 1 }}>
                  {node.role}
                </text>
              </g>
            );
          })}
        </svg>
      </div>

      {/* Expanded details */}
      {expanded && (
        <div style={{
          display: "grid", gridTemplateColumns: "repeat(4, 1fr)",
          gap: 10, padding: "12px 18px",
          borderTop: `1px solid ${C.border}`,
        }}>
          {[
            { label: "Build Time",   value: `${circuit.build_time_ms?.toFixed(0)}ms`, color: C.amber },
            { label: "Packet Count", value: circuit.packet_count || 0,                 color: C.cyan },
            { label: "Cell Ratio",   value: `${((circuit.cell_ratio || 0) * 100).toFixed(0)}%`, color: C.teal },
            { label: "Duration",     value: `${((circuit.duration || 0) / 60).toFixed(1)}min`, color: C.purple },
          ].map(s => (
            <div key={s.label} style={{
              background: `${s.color}0a`, borderRadius: 6, padding: "8px 12px",
              textAlign: "center",
            }}>
              <div style={{
                fontSize: 18, fontWeight: 800, color: s.color,
                fontFamily: "'IBM Plex Mono', monospace",
              }}>{s.value}</div>
              <div style={{
                fontSize: 8, color: C.textSub, letterSpacing: 1.2,
                textTransform: "uppercase", marginTop: 2,
              }}>{s.label}</div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

/* ── Build ordered node list from circuit hops ────────────────────────────── */
function buildNodeList(circuit) {
  const nodes = [];
  const ip = ip => ip?.split(".").slice(-2).join(".") || "?.?";

  // Client
  nodes.push({ role: "client", label: ip(circuit.src_ip) });

  const hops = circuit.hops || [];
  hops.forEach((h, i) => {
    if (i === 0) {
      nodes.push({ role: "guard", label: ip(h) });
    } else if (i === hops.length - 1 && !circuit.is_hidden_service) {
      nodes.push({ role: "exit", label: ip(h) });
    } else if (circuit.is_hidden_service && i === hops.length - 1) {
      nodes.push({ role: "rp", label: ip(h) });
    } else {
      nodes.push({ role: "relay", label: ip(h) });
    }
  });

  // Append the onion icon for hidden service destination
  if (circuit.is_hidden_service) {
    nodes.push({ role: "onion", label: ".onion" });
  }

  return nodes;
}
