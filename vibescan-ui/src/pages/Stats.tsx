import { useEffect, useState } from "react";
import { api, type Stats } from "../api";
import TimeSeries from "../components/TimeSeries";
import ErrorState from "../components/ErrorState";
import { useMeta } from "../lib/meta";
import "./grid.css";
import "./Stats.css";

const RANGES: [string, number][] = [
  ["1H", 1],
  ["24H", 24],
  ["7D", 168],
  ["ALL", 8760],
];

// Status codes carry reserved state colors (never reused as categorical hues).
const STATUS_COLOR: Record<string, string> = {
  "200": "var(--lime)",
  "3xx": "var(--amber)",
  "4xx": "var(--red)",
  "5xx": "var(--red)",
};

const VERDICT_COLOR: Record<string, string> = {
  malicious: "var(--red)",
  suspicious: "var(--amber)",
  clean: "var(--accent)",
};

function BarRow({ label, value, max, color }: { label: string; value: number; max: number; color: string }) {
  const pct = max > 0 ? Math.max(2, (value / max) * 100) : 0;
  return (
    <div className="bar-row" title={`${label}: ${value.toLocaleString()}`}>
      <span className="bar-label mono">{label}</span>
      <span className="bar-track">
        <span className="bar-fill" style={{ width: `${pct}%`, background: color }} />
      </span>
      <span className="bar-val mono">{value.toLocaleString()}</span>
    </div>
  );
}

function BarList({ data, color = "var(--cyan)", limit = 10 }: { data: Record<string, number>; color?: string; limit?: number }) {
  const rows = Object.entries(data).sort((a, b) => b[1] - a[1]).slice(0, limit);
  const max = rows.length ? rows[0][1] : 0;
  if (!rows.length) return <div className="bar-empty mono dim">no data</div>;
  return (
    <div className="bar-list">
      {rows.map(([k, v]) => (
        <BarRow key={k} label={k} value={v} max={max} color={color} />
      ))}
    </div>
  );
}

export default function StatsPage() {
  useMeta({
    title: "Internet Exposure Statistics — VibeScan",
    description: "Aggregate statistics on discovered web services: ports, status codes, cleartext exposure, CVEs, and reputation.",
    path: "/stats",
  });
  const [hours, setHours] = useState(24);
  const [s, setS] = useState<Stats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    let alive = true;
    setLoading(true);
    setError(false);
    api
      .stats(hours)
      .then((d) => alive && setS(d))
      .catch(() => alive && setError(true))
      .finally(() => alive && setLoading(false));
    return () => {
      alive = false;
    };
  }, [hours, reloadKey]);

  const secure = s?.secure_capture_counts.secured ?? 0;
  const insecure = s?.secure_capture_counts.insecure ?? 0;
  const total = secure + insecure;
  const insecurePct = total ? Math.round((insecure / total) * 100) : 0;

  const statusData: Record<string, number> = s
    ? { "200": s.status_code_counts["200"] || 0, "3xx": s.status_code_counts["3xx"] || 0, "4xx": s.status_code_counts["4xx"] || 0, "5xx": s.status_code_counts["5xx"] || 0 }
    : {};

  return (
    <div className="page wrap">
      <div className="page-head row spread stats-head">
        <div>
          <div className="eyebrow">◊ Telemetry</div>
          <h1 className="page-title display">Broadcast stats</h1>
        </div>
        <div className="chips stats-range">
          {RANGES.map(([label, h]) => (
            <button key={label} className={`chip mono${hours === h ? " on" : ""}`} onClick={() => setHours(h)}>
              {label}
            </button>
          ))}
        </div>
      </div>

      {loading && !s ? (
        <div className="empty">◌ AGGREGATING…</div>
      ) : error && !s ? (
        <ErrorState onRetry={() => setReloadKey((k) => k + 1)} />
      ) : !s ? (
        <div className="empty">TELEMETRY OFFLINE</div>
      ) : (
        <>
          <div className="stat-tiles">
            <div className="tile panel hud">
              <div className="tile-label eyebrow">Hosts</div>
              <div className="tile-num display">{s.totals.hosts.toLocaleString()}</div>
            </div>
            <div className="tile panel hud">
              <div className="tile-label eyebrow">Services</div>
              <div className="tile-num display">{s.totals.services.toLocaleString()}</div>
            </div>
            <div className="tile panel hud tile-insecure">
              <div className="tile-label eyebrow">Cleartext HTTP</div>
              <div className="tile-num display insecure">{insecurePct}%</div>
              <div className="tile-bar">
                <span className="tile-bar-fill" style={{ width: `${insecurePct}%` }} />
              </div>
              <div className="tile-sub mono dim">
                {insecure.toLocaleString()} insecure · {secure.toLocaleString()} https
              </div>
            </div>
            <div className="tile panel hud">
              <div className="tile-label eyebrow">Exposed</div>
              <div className="tile-num display insecure">{s.exposed_services.toLocaleString()}</div>
              <div className="tile-sub mono dim">services with ≥1 known CVE · via Shodan</div>
            </div>
          </div>

          <div className="stats-grid">
            <section className="panel panel-pad">
              <div className="eyebrow chart-head">◊ Services by port</div>
              <BarList data={s.services_by_port} />
            </section>

            <section className="panel panel-pad">
              <div className="eyebrow chart-head">◊ Response status</div>
              <div className="bar-list">
                {Object.entries(statusData).map(([k, v]) => (
                  <BarRow
                    key={k}
                    label={k}
                    value={v}
                    max={Math.max(...Object.values(statusData), 1)}
                    color={STATUS_COLOR[k]}
                  />
                ))}
              </div>
            </section>

            <section className="panel panel-pad">
              <div className="eyebrow chart-head">◊ Top servers</div>
              <BarList data={s.top_banners} color="var(--violet)" limit={8} />
            </section>

            <section className="panel panel-pad">
              <div className="eyebrow chart-head">◊ Shodan tags</div>
              <BarList data={s.top_tags} color="var(--accent-soft)" limit={8} />
            </section>

            <section className="panel panel-pad">
              <div className="eyebrow chart-head">◊ Reputation</div>
              {Object.keys(s.verdicts || {}).length ? (
                <div className="bar-list">
                  {(["malicious", "suspicious", "clean"] as const).map((k) => (
                    <BarRow
                      key={k}
                      label={k}
                      value={s.verdicts[k] || 0}
                      max={Math.max(...Object.values(s.verdicts), 1)}
                      color={VERDICT_COLOR[k]}
                    />
                  ))}
                </div>
              ) : (
                <div className="bar-empty mono dim">no reputation data yet</div>
              )}
            </section>

            <section className="panel panel-pad stats-time">
              <div className="eyebrow chart-head">◊ Submissions over time</div>
              <TimeSeries data={s.submissions_over_time} />
            </section>
          </div>
        </>
      )}
    </div>
  );
}
