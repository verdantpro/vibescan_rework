import { useEffect, useState } from "react";
import { api, type Tile } from "../api";
import SignalCard from "../components/SignalCard";
import "./grid.css";

const PAGE = 60;

export default function Feed() {
  const [tiles, setTiles] = useState<Tile[]>([]);
  const [offset, setOffset] = useState(0);
  const [hasMore, setHasMore] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let alive = true;
    setLoading(true);
    api
      .gallery(PAGE, offset)
      .then((r) => {
        if (!alive) return;
        setTiles((prev) => (offset === 0 ? r.entries : [...prev, ...r.entries]));
        setHasMore(r.has_more);
      })
      .finally(() => alive && setLoading(false));
    return () => {
      alive = false;
    };
  }, [offset]);

  return (
    <div className="page wrap">
      <div className="page-head">
        <div className="eyebrow">◊ Feed</div>
        <h1 className="page-title display">Signal feed</h1>
        <div className="page-sub mono">Most recent captured services across the census.</div>
      </div>

      {tiles.length === 0 && !loading ? (
        <div className="empty">NO SIGNALS ON RECORD</div>
      ) : (
        <div className="signal-grid">
          {tiles.map((t) => (
            <SignalCard key={`${t.ip}:${t.port}`} t={t} />
          ))}
        </div>
      )}

      <div className="page-more">
        {loading ? (
          <span className="mono dim">◌ scanning…</span>
        ) : hasMore ? (
          <button className="btn" onClick={() => setOffset((o) => o + PAGE)}>
            load more ↓
          </button>
        ) : (
          tiles.length > 0 && <span className="mono dim">— end of feed —</span>
        )}
      </div>
    </div>
  );
}
