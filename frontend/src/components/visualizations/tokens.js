// ─── Shared Design Tokens ─────────────────────────────────────────────────────
// Single source of truth for the investigation dashboard color system.

export const C = {
  bg0:          "#04070d",
  bg1:          "#080e18",
  bg2:          "#0c1424",
  bg3:          "#111c30",
  border:       "#172236",
  borderBright: "#1f3050",
  // Accent hierarchy
  cyan:   "#00e5ff",
  blue:   "#2979ff",
  purple: "#7c4dff",
  green:  "#00e676",
  amber:  "#ffab40",
  red:    "#ff1744",
  pink:   "#f50057",
  teal:   "#14b8a6",
  indigo: "#6366f1",
  orange: "#ea580c",
  // Text
  text:    "#d0dae8",
  textSub: "#5a7499",
  textDim: "#2e4a6a",
  // Protocol
  TLS:   "#7c4dff",
  TCP:   "#2979ff",
  UDP:   "#00e676",
  DNS:   "#ffab40",
  ICMP:  "#ff1744",
  OTHER: "#37474f",
};

export const RISK_COLOR = s =>
  s >= 70 ? C.red : s >= 45 ? C.amber : s >= 20 ? "#ffee58" : C.green;

export const fmtBytes = b => {
  if (!b) return "0 B";
  const u = ["B", "KB", "MB", "GB"];
  let i = 0, v = +b;
  while (v >= 1024 && i < 3) { v /= 1024; i++; }
  return `${v.toFixed(1)} ${u[i]}`;
};

export const fmtTs   = ts => ts ? new Date(ts * 1000).toLocaleTimeString() : "—";
export const fmtDate = ts => ts ? new Date(ts * 1000).toLocaleString() : "—";
