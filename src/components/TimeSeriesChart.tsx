import { useEffect, useMemo, useRef, useState } from "react";
import { clockTime } from "../format";

export interface Series {
  key: string;
  label: string;
  color: string;
  values: number[];
}

interface Props {
  /** Unix seconds, one per sample, ascending. */
  times: number[];
  series: Series[];
  height?: number;
  format: (v: number) => string;
  /** Fill under the line (single-series magnitude charts). */
  area?: boolean;
  compact?: boolean;
  /** Smallest y-axis top, so an idle chart doesn't show repeated tiny ticks. */
  minMax?: number;
}

function niceMax(v: number): number {
  if (v <= 0) return 1;
  const exp = Math.pow(10, Math.floor(Math.log10(v)));
  const f = v / exp;
  const nice = f <= 1 ? 1 : f <= 2 ? 2 : f <= 2.5 ? 2.5 : f <= 5 ? 5 : 10;
  return nice * exp;
}

/** Line/area time series with recessive grid, crosshair + tooltip on hover. */
export function TimeSeriesChart({ times, series, height = 220, format, area = false, compact = false, minMax = 4 }: Props) {
  const wrap = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(600);
  const [hover, setHover] = useState<number | null>(null);
  const gradId = useMemo(() => `g${Math.random().toString(36).slice(2, 8)}`, []);

  useEffect(() => {
    const el = wrap.current;
    if (!el) return;
    const ro = new ResizeObserver((e) => setWidth(Math.max(120, e[0].contentRect.width)));
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const pad = compact ? { l: 0, r: 0, t: 6, b: 0 } : { l: 60, r: 12, t: 10, b: 24 };
  const w = width - pad.l - pad.r;
  const h = height - pad.t - pad.b;
  const n = times.length;
  const max = niceMax(Math.max(minMax, ...series.flatMap((s) => s.values)));
  const x = (i: number) => pad.l + (n <= 1 ? w : (i / (n - 1)) * w);
  const y = (v: number) => pad.t + h - (v / max) * h;

  const paths = series.map((s) => {
    let d = "";
    s.values.forEach((v, i) => {
      d += `${i === 0 ? "M" : "L"}${x(i).toFixed(1)},${y(v).toFixed(1)}`;
    });
    return d;
  });

  const yTicks = compact ? [] : [0, 0.25, 0.5, 0.75, 1].map((f) => f * max);
  const xTickIdx = compact || n < 2 ? [] : [0, Math.floor((n - 1) / 3), Math.floor((2 * (n - 1)) / 3), n - 1];

  function onMove(e: React.MouseEvent<SVGRectElement>) {
    if (n === 0) return;
    const r = e.currentTarget.getBoundingClientRect();
    const px = e.clientX - r.left;
    const i = Math.round((px / r.width) * (n - 1));
    setHover(Math.max(0, Math.min(n - 1, i)));
  }

  const tipLeft = hover == null ? 0 : x(hover);
  const flip = tipLeft > width - 190;

  return (
    <div className="chart" ref={wrap}>
      {series.length > 1 && !compact && (
        <div className="legend" style={{ marginBottom: 8 }}>
          {series.map((s) => (
            <span key={s.key}>
              <i className="swatch" style={{ background: s.color }} />
              {s.label}
            </span>
          ))}
        </div>
      )}
      <svg width={width} height={height} role="img" aria-label={series.map((s) => s.label).join(", ")}>
        {area && series[0] && (
          <defs>
            <linearGradient id={gradId} x1="0" x2="0" y1="0" y2="1">
              <stop offset="0%" style={{ stopColor: series[0].color, stopOpacity: 0.28 }} />
              <stop offset="100%" style={{ stopColor: series[0].color, stopOpacity: 0.02 }} />
            </linearGradient>
          </defs>
        )}
        {yTicks.map((v, i) => (
          <g key={i}>
            <line className={i === 0 ? "baseline" : "gridline"} x1={pad.l} x2={pad.l + w} y1={y(v)} y2={y(v)} />
            <text className="tick" x={pad.l - 8} y={y(v) + 4} textAnchor="end">
              {format(v)}
            </text>
          </g>
        ))}
        {xTickIdx.map((i, k) => (
          <text
            key={k}
            className="tick"
            x={x(i)}
            y={height - 6}
            textAnchor={k === 0 ? "start" : k === xTickIdx.length - 1 ? "end" : "middle"}
          >
            {clockTime(times[i] * 1000)}
          </text>
        ))}
        {area && series[0] && n > 1 && (
          <path d={`${paths[0]}L${x(n - 1)},${pad.t + h}L${x(0)},${pad.t + h}Z`} fill={`url(#${gradId})`} />
        )}
        {series.map((s, i) => (
          <path key={s.key} d={paths[i]} fill="none" style={{ stroke: s.color }} strokeWidth={2} strokeLinejoin="round" strokeLinecap="round" />
        ))}
        {hover != null && (
          <g>
            <line className="crosshair" x1={x(hover)} x2={x(hover)} y1={pad.t} y2={pad.t + h} />
            {series.map((s) => (
              <circle
                key={s.key}
                cx={x(hover)}
                cy={y(s.values[hover] ?? 0)}
                r={4}
                style={{ fill: s.color, stroke: "var(--surface)" }}
                strokeWidth={2}
              />
            ))}
          </g>
        )}
        <rect
          x={pad.l}
          y={0}
          width={w}
          height={height}
          fill="transparent"
          onMouseMove={onMove}
          onMouseLeave={() => setHover(null)}
        />
      </svg>
      {hover != null && times[hover] != null && (
        <div
          className="tooltip"
          style={{
            top: series.length > 1 && !compact ? 30 : 0,
            left: flip ? undefined : tipLeft + 12,
            right: flip ? width - tipLeft + 12 : undefined,
          }}
        >
          <div className="tt-time">{clockTime(times[hover] * 1000)}</div>
          {series.map((s) => (
            <div className="tt-row" key={s.key}>
              <i className="swatch" style={{ background: s.color }} />
              <span className="dim">{s.label}</span>
              <span className="v">{format(s.values[hover] ?? 0)}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
