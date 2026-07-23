import { useCallback, useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { api, type SignalDetail, type Stats, type Tile } from "../api";
import Viewport from "../components/Viewport";
import WorldMap, { type MapPoint } from "../components/WorldMap";
import SignalCard from "../components/SignalCard";
import "./Console.css";

export default function Console() {
  const [detail, setDetail] = useState<SignalDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [auto, setAuto] = useState(false);
  const [recent, setRecent] = useState<Tile[]>([]);
  const [stats, setStats] = useState<Stats | null>(null);
  const timer = useRef<number | null>(null);

  const acquire = useCallback(async () => {
    setLoading(true);
    try {
      // Prefer the random-capture pool; if empty/unavailable, fall back to the
      // latest gallery tile so the viewport is never stuck on a dead API.
      let ip: string;
      let port: number;
      try {
        const cap = await api.randomCapture();
        ip = cap.ip;
        port = cap.port;
      } catch {
        const gal = await api.gallery(12);
        const pick = gal.entries[Math.floor(Math.random() * gal.entries.length)];
        if (!pick) throw new Error("no captures");
        ip = pick.ip;
        port = pick.port;
      }
      const d = await api.signal(ip, port);
      setDetail(d);
    } catch {
      // No captures yet, or one vanished — leave prior signal on screen.
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    acquire();
    api.gallery(48).then((r) => setRecent(r.entries)).catch(() => {});
    api.stats(8760).then(setStats).catch(() => {});
  }, [acquire]);

  useEffect(() => {
    if (!auto) return;
    timer.current = window.setInterval(acquire, 6000);
    return () => {
      if (timer.current) window.clearInterval(timer.current);
    };
  }, [auto, acquire]);

  const points: MapPoint[] = recent
    .filter((t) => t.geo)
    .map((t) => ({ ip: t.ip, port: t.port, lat: t.geo!.lat, lon: t.geo!.lon, insecure: !t.secured }));

  const insecure = stats?.secure_capture_counts.insecure ?? null;
  const hosts = stats?.totals.hosts ?? null;

  return (
    <div className="console wrap">
      <div className="console-head">
        <div className="eyebrow">◊ vibescan · live acquisition</div>
        <h1 className="console-h1 display">
          {insecure != null ? insecure.toLocaleString() : "—"}{" "}
          <span className="console-h1-sub">cleartext HTTP services on record</span>
        </h1>
        <p className="console-lede dim">
          Random IPv4 discovery on common web ports — banners, screenshots, and geo.
          Acquire a signal, or browse the {hosts != null ? hosts.toLocaleString() : ""} hosts indexed so far.
        </p>
      </div>

      <Viewport
        detail={detail}
        loading={loading}
        auto={auto}
        onAcquire={acquire}
        onToggleAuto={() => setAuto((a) => !a)}
      />

      <section className="panel panel-pad console-map">
        <div className="row spread console-section-head">
          <span className="eyebrow">◊ Signal origins</span>
          <span className="mono dim">geolocated · last {recent.length} captures</span>
        </div>
        <WorldMap points={points} />
      </section>

      <section className="console-recent">
        <div className="row spread console-section-head">
          <span className="eyebrow">◊ Recent acquisitions</span>
          <Link className="mono console-more" to="/feed">
            full feed →
          </Link>
        </div>
        <div className="console-strip">
          {recent.slice(0, 6).map((t) => (
            <SignalCard key={`${t.ip}:${t.port}`} t={t} />
          ))}
        </div>
      </section>
    </div>
  );
}
