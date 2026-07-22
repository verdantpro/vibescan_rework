import { useMemo, useState } from "react";
import "./TimeSeries.css";

const W = 640;
const H = 200;
const PAD = { t: 14, r: 14, b: 24, l: 34 };

export default function TimeSeries({ data }: { data: Record<string, number> }) {
  const points = useMemo(
    () => Object.entries(data).sort((a, b) => a[0].localeCompare(b[0])).map(([label, value]) => ({ label, value })),
    [data]
  );
  const [hover, setHover] = useState<number | null>(null);

  if (points.length === 0) return <div className="bar-empty mono dim">no submissions in range</div>;

  const max = Math.max(...points.map((p) => p.value), 1);
  const iw = W - PAD.l - PAD.r;
  const ih = H - PAD.t - PAD.b;
  const x = (i: number) => PAD.l + (points.length === 1 ? iw / 2 : (i / (points.length - 1)) * iw);
  const y = (v: number) => PAD.t + ih - (v / max) * ih;

  const line = points.map((p, i) => `${i === 0 ? "M" : "L"}${x(i)},${y(p.value)}`).join(" ");
  const area = `${line} L${x(points.length - 1)},${PAD.t + ih} L${x(0)},${PAD.t + ih} Z`;

  const onMove = (e: React.MouseEvent<SVGSVGElement>) => {
    const rect = e.currentTarget.getBoundingClientRect();
    const px = ((e.clientX - rect.left) / rect.width) * W;
    const i = Math.round(((px - PAD.l) / iw) * (points.length - 1));
    setHover(Math.max(0, Math.min(points.length - 1, i)));
  };

  const hp = hover != null ? points[hover] : null;

  return (
    <div className="ts">
      <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" onMouseMove={onMove} onMouseLeave={() => setHover(null)}>
        <defs>
          <linearGradient id="tsfill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="rgba(56,225,255,0.35)" />
            <stop offset="100%" stopColor="rgba(56,225,255,0)" />
          </linearGradient>
        </defs>
        {[0, 0.5, 1].map((f) => (
          <line key={f} className="ts-grid" x1={PAD.l} x2={W - PAD.r} y1={PAD.t + ih * f} y2={PAD.t + ih * f} />
        ))}
        <text className="ts-axis" x={PAD.l - 6} y={PAD.t + 4} textAnchor="end">{max}</text>
        <text className="ts-axis" x={PAD.l - 6} y={PAD.t + ih} textAnchor="end">0</text>
        <path className="ts-area" d={area} fill="url(#tsfill)" />
        <path className="ts-line" d={line} />
        {hp && hover != null && (
          <g>
            <line className="ts-cross" x1={x(hover)} x2={x(hover)} y1={PAD.t} y2={PAD.t + ih} />
            <circle className="ts-dot" cx={x(hover)} cy={y(hp.value)} r="4" />
          </g>
        )}
      </svg>
      <div className="ts-foot mono dim">
        {hp ? (
          <span className="ts-tip">
            <b>{hp.value.toLocaleString()}</b> submissions · {hp.label} UTC
          </span>
        ) : (
          <span>{points[0].label} → {points[points.length - 1].label}</span>
        )}
      </div>
    </div>
  );
}
