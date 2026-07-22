import { useEffect, useMemo, useState } from "react";
import { api, type Tile } from "../api";
import SignalCard from "../components/SignalCard";
import "./grid.css";
import "./Search.css";

type SecFilter = "any" | "https" | "http";

export default function Search() {
  const [q, setQ] = useState("");
  const [debounced, setDebounced] = useState("");
  const [port, setPort] = useState("");
  const [sec, setSec] = useState<SecFilter>("any");
  const [status, setStatus] = useState<number | null>(null);
  const [tiles, setTiles] = useState<Tile[]>([]);
  const [loading, setLoading] = useState(false);
  const [touched, setTouched] = useState(false);

  useEffect(() => {
    const id = setTimeout(() => setDebounced(q.trim()), 250);
    return () => clearTimeout(id);
  }, [q]);

  const active = useMemo(
    () => debounced !== "" || port !== "" || sec !== "any" || status !== null,
    [debounced, port, sec, status]
  );

  useEffect(() => {
    if (!active) {
      setTiles([]);
      return;
    }
    let alive = true;
    setLoading(true);
    setTouched(true);
    api
      .search({
        q: debounced || undefined,
        port: port ? Number(port) : undefined,
        status: status ?? undefined,
        secured: sec === "any" ? undefined : sec === "https",
        limit: 90,
      })
      .then((r) => alive && setTiles(r.entries))
      .catch(() => alive && setTiles([]))
      .finally(() => alive && setLoading(false));
    return () => {
      alive = false;
    };
  }, [debounced, port, sec, status, active]);

  const statuses: [string, number | null][] = [
    ["any", null],
    ["200", 200],
    ["301", 301],
    ["403", 403],
    ["404", 404],
    ["500", 500],
  ];

  return (
    <div className="page wrap">
      <div className="page-head">
        <div className="eyebrow">◊ Search</div>
        <h1 className="page-title display">Query the census</h1>
      </div>

      <div className="search-bar hud">
        <span className="search-prompt mono">▸</span>
        <input
          className="search-input mono"
          autoFocus
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="banner, product, whois, IP, or page text…"
        />
      </div>

      <div className="filters">
        <input
          className="filter-port mono"
          value={port}
          onChange={(e) => setPort(e.target.value.replace(/\D/g, ""))}
          placeholder="port"
          inputMode="numeric"
        />
        <div className="chips">
          {(["any", "http", "https"] as SecFilter[]).map((s) => (
            <button key={s} className={`chip mono${sec === s ? " on" : ""}`} onClick={() => setSec(s)}>
              {s}
            </button>
          ))}
        </div>
        <div className="chips">
          {statuses.map(([label, val]) => (
            <button
              key={label}
              className={`chip mono${status === val ? " on" : ""}`}
              onClick={() => setStatus(val)}
            >
              {label}
            </button>
          ))}
        </div>
      </div>

      {!active ? (
        <div className="empty">ENTER A QUERY OR PICK A FILTER</div>
      ) : loading ? (
        <div className="empty">◌ SCANNING…</div>
      ) : tiles.length === 0 && touched ? (
        <div className="empty">NO MATCHING SIGNALS</div>
      ) : (
        <>
          <div className="page-sub mono search-count">{tiles.length} matches</div>
          <div className="signal-grid">
            {tiles.map((t) => (
              <SignalCard key={`${t.ip}:${t.port}`} t={t} />
            ))}
          </div>
        </>
      )}
    </div>
  );
}
