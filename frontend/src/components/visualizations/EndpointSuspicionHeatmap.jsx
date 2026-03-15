/**
 * EndpointSuspicionHeatmap — Canvas-rendered heatmap of endpoint risk profiles.
 *
 * Features:
 *  • Grid cells coloured by risk score (green → amber → red gradient)
 *  • Axes labelled by IP and metric category
 *  • Hover reveal with detailed scores
 *  • Sortable by risk, flows, fan-out
 *  • Click to drill into endpoint detail
 */
import { useState, useMemo, useRef, useEffect, useCallback } from "react";
import { C, RISK_COLOR, fmtBytes } from "./tokens";

const METRICS = [
  { key: "suspicion_score",  label: "Risk Score",    max: 100 },
  { key: "total_flows",      label: "Total Flows",   max: null },  // auto
  { key: "fan_out",          label: "Fan-out",        max: null },
  { key: "port_entropy",     label: "Port Entropy",   max: 5 },
  { key: "beacon_count",     label: "Beacons",        max: 10 },
  { key: "dga_count",        label: "DGA Domains",    max: 10 },
];

const GRAD = [
  [0.0, [14, 184, 166]],   // teal
  [0.3, [0, 230, 118]],    // green
  [0.5, [255, 238, 88]],   // yellow
  [0.7, [255, 171, 64]],   // amber
  [1.0, [255, 23, 68]],    // red
];

function lerpColor(t) {
  t = Math.max(0, Math.min(1, t));
  for (let i = 0; i < GRAD.length - 1; i++) {
    if (t >= GRAD[i][0] && t <= GRAD[i + 1][0]) {
      const f = (t - GRAD[i][0]) / (GRAD[i + 1][0] - GRAD[i][0]);
      const a = GRAD[i][1], b = GRAD[i + 1][1];
      const r = Math.round(a[0] + (b[0] - a[0]) * f);
      const g = Math.round(a[1] + (b[1] - a[1]) * f);
      const bv = Math.round(a[2] + (b[2] - a[2]) * f);
      return `rgb(${r},${g},${bv})`;
    }
  }
  return `rgb(${GRAD[GRAD.length - 1][1].join(",")})`;
}

export default function EndpointSuspicionHeatmap({
  endpoints = [],
  onEndpointClick,
}) {
  const [hover, setHover] = useState(null);
  const [sortKey, setSortKey] = useState("suspicion_score");
  const canvasRef = useRef(null);

  // Sorted + limited
  const sorted = useMemo(() =>
    [...endpoints]
      .sort((a, b) => (b[sortKey] || 0) - (a[sortKey] || 0))
      .slice(0, 30),
    [endpoints, sortKey]
  );

  // Auto-compute max for each metric
  const maxVals = useMemo(() => {
    const m = {};
    METRICS.forEach(metric => {
      if (metric.max !== null) {
        m[metric.key] = metric.max;
      } else {
        m[metric.key] = Math.max(...sorted.map(e => e[metric.key] || 0), 1);
      }
    });
    return m;
  }, [sorted]);

  // Canvas rendering
  const cellW  = 80;
  const cellH  = 26;
  const labelW = 140;
  const headerH = 60;
  const canW   = labelW + METRICS.length * cellW + 20;
  const canH   = headerH + sorted.length * cellH + 20;

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    const dpr = window.devicePixelRatio || 1;
    canvas.width  = canW * dpr;
    canvas.height = canH * dpr;
    ctx.scale(dpr, dpr);

    // Clear
    ctx.fillStyle = C.bg0;
    ctx.fillRect(0, 0, canW, canH);

    // Column headers
    ctx.save();
    METRICS.forEach((metric, mi) => {
      const x = labelW + mi * cellW + cellW / 2;
      ctx.save();
      ctx.translate(x, headerH - 6);
      ctx.rotate(-Math.PI / 4);
      ctx.fillStyle = C.textSub;
      ctx.font = "10px 'IBM Plex Mono', monospace";
      ctx.textAlign = "left";
      ctx.fillText(metric.label, 0, 0);
      ctx.restore();
    });
    ctx.restore();

    // Rows
    sorted.forEach((ep, ri) => {
      const y = headerH + ri * cellH;

      // Row label
      ctx.fillStyle = C.text;
      ctx.font = "10px 'IBM Plex Mono', monospace";
      ctx.textAlign = "right";
      ctx.textBaseline = "middle";
      ctx.fillText(ep.ip, labelW - 10, y + cellH / 2);

      // Cells
      METRICS.forEach((metric, mi) => {
        const x = labelW + mi * cellW;
        const val = ep[metric.key] || 0;
        const norm = Math.min(1, val / maxVals[metric.key]);
        const color = lerpColor(norm);

        // Cell background
        ctx.fillStyle = color;
        ctx.globalAlpha = Math.max(0.12, norm * 0.85);
        ctx.beginPath();
        ctx.roundRect(x + 2, y + 2, cellW - 4, cellH - 4, 3);
        ctx.fill();
        ctx.globalAlpha = 1;

        // Cell border
        ctx.strokeStyle = `${color}40`;
        ctx.lineWidth = 0.5;
        ctx.beginPath();
        ctx.roundRect(x + 2, y + 2, cellW - 4, cellH - 4, 3);
        ctx.stroke();

        // Value text
        ctx.fillStyle = norm > 0.5 ? "#fff" : C.textSub;
        ctx.font = `${norm > 0.6 ? 'bold ' : ''}10px 'IBM Plex Mono', monospace`;
        ctx.textAlign = "center";
        ctx.textBaseline = "middle";
        const displayVal = metric.key === "port_entropy"
          ? val?.toFixed(2) : val?.toLocaleString?.() ?? val;
        ctx.fillText(displayVal, x + cellW / 2, y + cellH / 2);
      });

      // Row separator
      ctx.strokeStyle = `${C.border}30`;
      ctx.lineWidth = 0.5;
      ctx.beginPath();
      ctx.moveTo(0, y + cellH);
      ctx.lineTo(canW, y + cellH);
      ctx.stroke();
    });
  }, [sorted, maxVals, canW, canH]);

  // Mouse handler for hover
  const handleMouse = useCallback((e) => {
    const rect = canvasRef.current?.getBoundingClientRect();
    if (!rect) return;
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;
    const scaleX = canW / rect.width;
    const scaleY = canH / rect.height;
    const sx = x * scaleX;
    const sy = y * scaleY;

    if (sx < labelW || sy < headerH) { setHover(null); return; }
    const row = Math.floor((sy - headerH) / cellH);
    const col = Math.floor((sx - labelW) / cellW);
    if (row >= 0 && row < sorted.length && col >= 0 && col < METRICS.length) {
      setHover({
        ep: sorted[row],
        metric: METRICS[col],
        value: sorted[row][METRICS[col].key],
        x: e.clientX - rect.left,
        y: e.clientY - rect.top,
      });
    } else {
      setHover(null);
    }
  }, [sorted, canW, canH]);

  const handleClick = useCallback((e) => {
    const rect = canvasRef.current?.getBoundingClientRect();
    if (!rect) return;
    const y = (e.clientY - rect.top) * (canH / rect.height);
    if (y < headerH) return;
    const row = Math.floor((y - headerH) / cellH);
    if (row >= 0 && row < sorted.length) {
      onEndpointClick?.(sorted[row]);
    }
  }, [sorted, canH, onEndpointClick]);

  if (!sorted.length) {
    return (
      <div style={{ textAlign: "center", padding: "60px 20px", color: C.textDim, fontSize: 13 }}>
        No endpoint data available — run analysis first
      </div>
    );
  }

  return (
    <div style={{ position: "relative" }}>
      {/* Sort controls */}
      <div style={{
        display: "flex", gap: 6, marginBottom: 10, alignItems: "center",
      }}>
        <span style={{ fontSize: 10, color: C.textSub, letterSpacing: 1, textTransform: "uppercase" }}>
          Sort by:
        </span>
        {METRICS.map(m => (
          <button key={m.key} onClick={() => setSortKey(m.key)} style={{
            padding: "4px 10px", borderRadius: 4, border: "none",
            fontSize: 10, cursor: "pointer",
            background: sortKey === m.key ? `${C.cyan}20` : "transparent",
            color: sortKey === m.key ? C.cyan : C.textSub,
            fontFamily: "'IBM Plex Mono', monospace",
          }}>{m.label}</button>
        ))}
      </div>

      {/* Canvas heatmap */}
      <canvas
        ref={canvasRef}
        style={{
          width: "100%", height: canH,
          borderRadius: 8, cursor: "pointer",
          background: C.bg0,
        }}
        onMouseMove={handleMouse}
        onMouseLeave={() => setHover(null)}
        onClick={handleClick}
      />

      {/* Hover tooltip */}
      {hover && (
        <div style={{
          position: "absolute",
          left: hover.x + 12, top: hover.y - 10,
          background: `${C.bg3}f0`, border: `1px solid ${C.borderBright}`,
          borderRadius: 8, padding: "8px 12px", fontSize: 11,
          pointerEvents: "none", zIndex: 20,
          backdropFilter: "blur(8px)",
          boxShadow: "0 4px 20px rgba(0,0,0,0.5)",
        }}>
          <div style={{ fontFamily: "monospace", color: C.cyan, fontWeight: 700 }}>
            {hover.ep.ip}
          </div>
          <div style={{ color: C.textSub, marginTop: 2 }}>
            {hover.metric.label}: <b style={{ color: C.text }}>{hover.value}</b>
          </div>
          <div style={{ color: C.textDim, fontSize: 9, marginTop: 2 }}>
            Risk: {hover.ep.suspicion_score}
          </div>
        </div>
      )}

      {/* Color legend */}
      <div style={{
        display: "flex", alignItems: "center", gap: 8, marginTop: 10,
        justifyContent: "center",
      }}>
        <span style={{ fontSize: 9, color: C.textSub }}>LOW</span>
        <div style={{
          width: 200, height: 8, borderRadius: 4,
          background: `linear-gradient(90deg, ${lerpColor(0)}, ${lerpColor(0.3)}, ${lerpColor(0.5)}, ${lerpColor(0.7)}, ${lerpColor(1)})`,
        }} />
        <span style={{ fontSize: 9, color: C.textSub }}>CRITICAL</span>
      </div>
    </div>
  );
}
