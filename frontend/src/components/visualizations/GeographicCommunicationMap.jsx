/**
 * GeographicCommunicationMap — SVG world map with connection arcs.
 *
 * Features:
 *  • Equirectangular world map rendered via D3 geo
 *  • Animated arc connections between source and destination
 *  • GeoIP-based endpoint positioning
 *  • Risk-coloured arcs (red for suspicious, cyan for normal)
 *  • City-level markers with volume indicators
 *  • Hover tooltips with IP, country, volume
 *  • Zoom and pan support
 */
import { useRef, useEffect, useState, useMemo, useCallback } from "react";
import * as d3 from "d3";
import { C, fmtBytes } from "./tokens";

// Simplified country centroids for demo (lat, lon)
const COUNTRY_GEO = {
  US: [-98, 38], CN: [104, 35], RU: [105, 62], DE: [10, 51],
  GB: [-1, 52], FR: [2, 47], JP: [138, 36], BR: [-55, -10],
  IN: [78, 21], AU: [134, -25], KR: [127, 37], NL: [5, 52],
  SE: [15, 62], CA: [-106, 56], SG: [104, 1], ZA: [25, -29],
  IL: [35, 31], IR: [53, 32], KP: [127, 40], UA: [32, 49],
  TW: [121, 24], HK: [114, 22], CH: [8, 47], NO: [8, 62],
  FI: [26, 64], PL: [20, 52], IT: [12, 42], ES: [-4, 40],
  MX: [-102, 24], AR: [-64, -34], EG: [30, 27], SA: [45, 24],
  AE: [54, 24], TH: [100, 15], VN: [108, 14], ID: [120, -5],
  MY: [102, 4], PH: [122, 12], NG: [8, 10], KE: [38, 1],
};

// Demo function to assign geo coords to IPs (in production, use a GeoIP lookup)
function ipToGeo(ip) {
  if (!ip) return null;
  const parts = ip.split(".").map(Number);
  // Simple hash to pick a country
  const hash = (parts[0] * 7 + parts[1] * 13 + parts[2] * 17 + parts[3] * 23) % Object.keys(COUNTRY_GEO).length;
  const country = Object.keys(COUNTRY_GEO)[hash];
  const [lon, lat] = COUNTRY_GEO[country];
  // Slight jitter for multiple IPs in same country
  return {
    lat: lat + (parts[3] % 10 - 5) * 0.5,
    lon: lon + (parts[2] % 10 - 5) * 0.5,
    country,
    ip,
  };
}

export default function GeographicCommunicationMap({
  edges = [],
  suspiciousIps = new Set(),
  nodes = [],
}) {
  const svgRef = useRef(null);
  const [hover, setHover] = useState(null);

  // Build connection data
  const connections = useMemo(() =>
    edges.map(e => ({
      source: ipToGeo(e.source),
      target: ipToGeo(e.target),
      bytes: e.bytes || 0,
      protocol: e.protocol,
      suspicious: suspiciousIps.has(e.source) || suspiciousIps.has(e.target),
    })).filter(c => c.source && c.target),
    [edges, suspiciousIps]
  );

  // Unique endpoints
  const endpoints = useMemo(() => {
    const map = {};
    connections.forEach(c => {
      [c.source, c.target].forEach(ep => {
        if (!map[ep.ip]) {
          map[ep.ip] = { ...ep, bytes: 0, connections: 0, suspicious: false };
        }
        map[ep.ip].bytes += c.bytes;
        map[ep.ip].connections += 1;
        if (c.suspicious) map[ep.ip].suspicious = true;
      });
    });
    return Object.values(map);
  }, [connections]);

  // D3 map rendering
  useEffect(() => {
    if (!svgRef.current) return;
    const svg = d3.select(svgRef.current);
    svg.selectAll("*").remove();

    const width = 960, height = 500;
    svg.attr("viewBox", `0 0 ${width} ${height}`);

    const projection = d3.geoNaturalEarth1()
      .scale(160)
      .translate([width / 2, height / 2]);

    const path = d3.geoPath().projection(projection);

    // Background
    svg.append("rect")
      .attr("width", width).attr("height", height)
      .attr("fill", C.bg0);

    const g = svg.append("g");

    // Graticule
    g.append("path")
      .datum(d3.geoGraticule10())
      .attr("d", path)
      .attr("fill", "none")
      .attr("stroke", `${C.border}30`)
      .attr("stroke-width", 0.3);

    // Land (simplified path from d3 built-in sphere)
    g.append("path")
      .datum({ type: "Sphere" })
      .attr("d", path)
      .attr("fill", "none")
      .attr("stroke", `${C.border}60`)
      .attr("stroke-width", 0.5);

    // Draw simple country outlines using world bbox rectangles
    // In production you'd use a proper GeoJSON world file
    Object.entries(COUNTRY_GEO).forEach(([code, [lon, lat]]) => {
      const [px, py] = projection([lon, lat]);
      if (!px) return;
      g.append("circle")
        .attr("cx", px).attr("cy", py)
        .attr("r", 1.5)
        .attr("fill", `${C.textDim}40`);
    });

    // Defs for glow
    const defs = svg.append("defs");
    const glow = defs.append("filter").attr("id", "mapGlow");
    glow.append("feGaussianBlur").attr("stdDeviation", 3);

    // Connection arcs
    const maxBytes = Math.max(...connections.map(c => c.bytes), 1);

    connections.forEach((conn, i) => {
      const [sx, sy] = projection([conn.source.lon, conn.source.lat]);
      const [tx, ty] = projection([conn.target.lon, conn.target.lat]);
      if (!sx || !tx) return;

      const mid = [(sx + tx) / 2, (sy + ty) / 2];
      const dx = tx - sx, dy = ty - sy;
      const dist = Math.sqrt(dx * dx + dy * dy);
      const ctrl = [mid[0] - dy * 0.3, mid[1] + dx * 0.3 - dist * 0.15];

      const arcColor = conn.suspicious ? C.red : C.cyan;
      const opacity = Math.max(0.2, Math.min(0.8, conn.bytes / maxBytes));
      const strokeW = Math.max(0.5, Math.min(3, (conn.bytes / maxBytes) * 3));

      // Glow arc
      g.append("path")
        .attr("d", `M ${sx},${sy} Q ${ctrl[0]},${ctrl[1]} ${tx},${ty}`)
        .attr("fill", "none")
        .attr("stroke", arcColor)
        .attr("stroke-width", strokeW + 2)
        .attr("opacity", opacity * 0.15)
        .attr("filter", "url(#mapGlow)");

      // Main arc
      g.append("path")
        .attr("d", `M ${sx},${sy} Q ${ctrl[0]},${ctrl[1]} ${tx},${ty}`)
        .attr("fill", "none")
        .attr("stroke", arcColor)
        .attr("stroke-width", strokeW)
        .attr("opacity", opacity)
        .attr("stroke-linecap", "round");

      // Animated particle along arc
      const particle = g.append("circle")
        .attr("r", 2)
        .attr("fill", arcColor)
        .attr("opacity", 0.9);

      // Animate
      (function animateParticle() {
        particle
          .attr("cx", sx).attr("cy", sy)
          .transition()
          .duration(2000 + Math.random() * 3000)
          .delay(i * 200)
          .attrTween("cx", () => {
            return t => {
              const u = 1 - t;
              return u * u * sx + 2 * u * t * ctrl[0] + t * t * tx;
            };
          })
          .attrTween("cy", () => {
            return t => {
              const u = 1 - t;
              return u * u * sy + 2 * u * t * ctrl[1] + t * t * ty;
            };
          })
          .on("end", animateParticle);
      })();
    });

    // Endpoint markers
    endpoints.forEach(ep => {
      const [px, py] = projection([ep.lon, ep.lat]);
      if (!px) return;

      const r = Math.max(3, Math.min(10, Math.sqrt(ep.connections) * 2));
      const color = ep.suspicious ? C.red : C.cyan;

      // Glow
      g.append("circle")
        .attr("cx", px).attr("cy", py).attr("r", r + 4)
        .attr("fill", color).attr("opacity", 0.12)
        .attr("filter", "url(#mapGlow)");

      // Marker
      g.append("circle")
        .attr("cx", px).attr("cy", py).attr("r", r)
        .attr("fill", `${color}44`)
        .attr("stroke", color)
        .attr("stroke-width", 1)
        .style("cursor", "pointer")
        .append("title")
        .text(`${ep.ip} (${ep.country})\n${ep.connections} connections\n${fmtBytes(ep.bytes)}`);

      // Country label
      if (ep.connections >= 2) {
        g.append("text")
          .attr("x", px).attr("y", py + r + 10)
          .attr("text-anchor", "middle")
          .attr("font-size", 7)
          .attr("fill", C.textSub)
          .attr("font-family", "monospace")
          .text(ep.country);
      }
    });

    // Zoom
    const zoom = d3.zoom()
      .scaleExtent([1, 8])
      .on("zoom", (event) => {
        g.attr("transform", event.transform);
      });

    svg.call(zoom);

  }, [connections, endpoints]);

  if (!connections.length) {
    return (
      <div style={{ textAlign: "center", padding: "60px 20px", color: C.textDim, fontSize: 13 }}>
        No geographic data available — select a session to view the map
      </div>
    );
  }

  return (
    <div>
      {/* Stats bar */}
      <div style={{
        display: "flex", gap: 14, marginBottom: 12, alignItems: "center",
        flexWrap: "wrap",
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
          <span style={{ width: 8, height: 8, borderRadius: "50%", background: C.cyan, boxShadow: `0 0 6px ${C.cyan}` }} />
          <span style={{ fontSize: 11, color: C.textSub }}>
            {endpoints.filter(e => !e.suspicious).length} normal endpoints
          </span>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
          <span style={{ width: 8, height: 8, borderRadius: "50%", background: C.red, boxShadow: `0 0 6px ${C.red}` }} />
          <span style={{ fontSize: 11, color: C.textSub }}>
            {endpoints.filter(e => e.suspicious).length} suspicious
          </span>
        </div>
        <span style={{ width: 1, height: 14, background: C.border }} />
        <span style={{ fontSize: 11, color: C.textSub }}>
          {connections.length} connections · {new Set(endpoints.map(e => e.country)).size} countries
        </span>
        <span style={{ marginLeft: "auto", fontSize: 10, color: C.textDim }}>
          Scroll to zoom · Drag to pan
        </span>
      </div>

      {/* Map */}
      <div style={{
        background: C.bg0, borderRadius: 10,
        border: `1px solid ${C.border}`, overflow: "hidden",
      }}>
        <svg ref={svgRef} style={{ width: "100%", height: "auto" }} />
      </div>

      {/* Country summary */}
      <div style={{
        display: "flex", gap: 6, marginTop: 10, flexWrap: "wrap",
        justifyContent: "center",
      }}>
        {Array.from(new Set(endpoints.map(e => e.country))).sort().map(country => {
          const eps = endpoints.filter(e => e.country === country);
          const totalConns = eps.reduce((s, e) => s + e.connections, 0);
          const hasSusp = eps.some(e => e.suspicious);
          return (
            <span key={country} style={{
              fontSize: 10, padding: "2px 8px", borderRadius: 4,
              background: hasSusp ? `${C.red}15` : `${C.cyan}10`,
              color: hasSusp ? C.red : C.cyan,
              border: `1px solid ${hasSusp ? C.red : C.cyan}25`,
              fontFamily: "monospace",
            }}>
              {country} ({totalConns})
            </span>
          );
        })}
      </div>
    </div>
  );
}
