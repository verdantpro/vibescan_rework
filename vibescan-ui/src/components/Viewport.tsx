import { Link } from "react-router-dom";
import { imageURL, type SignalDetail } from "../api";
import StatusBadge from "./StatusBadge";
import "./Viewport.css";

interface Props {
  detail: SignalDetail | null;
  loading: boolean;
  auto: boolean;
  onAcquire: () => void;
  onToggleAuto: () => void;
}

function Line({ label, value, accent }: { label: string; value?: string | number | null; accent?: boolean }) {
  return (
    <div className="tl-line">
      <span className="tl-label mono">{label}</span>
      <span className={`tl-value mono${accent ? " tl-accent" : ""}`}>{value ?? "—"}</span>
    </div>
  );
}

export default function Viewport({ detail, loading, auto, onAcquire, onToggleAuto }: Props) {
  const s = detail?.service;
  const geo = s?.geo;
  const coords = geo ? `${geo.lat.toFixed(3)}, ${geo.lon.toFixed(3)}` : null;
  const place = geo ? [geo.city, geo.country_iso].filter(Boolean).join(" · ") : null;
  const key = s ? `${s.ip}:${s.port}` : "empty";

  return (
    <section className="vp panel hud">
      <div className="vp-screen">
        {s?.image_url ? (
          <img key={key} className="vp-img" src={imageURL(s.image_url)} alt="" />
        ) : (
          <div className="vp-empty mono">{loading ? "SCANNING…" : "NO SIGNAL"}</div>
        )}
        <div className="vp-scan" />
        <div className="vp-vignette" />

        {/* OSD overlay */}
        <div className="vp-osd-top mono">
          <span className={`vp-rec${loading ? " scanning" : ""}`}>
            <span className="live-dot" /> {loading ? "ACQUIRING" : "LIVE"}
          </span>
          <span className="vp-callsign">{s ? `${s.ip}:${s.port}` : "— — —"}</span>
        </div>
        <div className="vp-osd-bottom mono">
          <span>{s ? s.product || "unknown service" : ""}</span>
          {s && <StatusBadge status={s.http_status} />}
        </div>

        <span className="vp-corner tl" />
        <span className="vp-corner tr" />
        <span className="vp-corner bl" />
        <span className="vp-corner br" />
      </div>

      <aside className="vp-telemetry">
        <div className="eyebrow">◊ Telemetry</div>
        <Line label="CALL SIGN" value={s ? `${s.ip}:${s.port}` : null} accent />
        <Line label="PROTOCOL" value={s ? (s.secured ? "HTTPS" : "HTTP") : null} />
        <Line label="STATUS" value={s?.http_status} />
        <Line label="SERVER" value={s?.product} />
        <Line label="OPERATOR" value={s?.whois} />
        <Line label="ORIGIN" value={place} />
        <Line label="COORD" value={coords} />
        <Line label="pHASH" value={s?.screenshot_phash} />
        <Line label="DOM" value={s?.dom_hash} />

        <div className="vp-controls">
          <button className="btn btn-primary" onClick={onAcquire} disabled={loading}>
            {loading ? "◌ acquiring" : "▸ acquire next"}
          </button>
          <button className={`btn${auto ? " btn-primary" : " btn-ghost"}`} onClick={onToggleAuto}>
            {auto ? "❚❚ auto" : "▶ auto"}
          </button>
          {s && (
            <Link className="btn btn-ghost" to={`/signal/${s.ip}/${s.port}`}>
              inspect →
            </Link>
          )}
        </div>
      </aside>
    </section>
  );
}
