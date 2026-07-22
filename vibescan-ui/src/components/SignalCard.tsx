import { Link } from "react-router-dom";
import { imageURL, type Tile } from "../api";
import StatusBadge from "./StatusBadge";
import "./SignalCard.css";

export default function SignalCard({ t }: { t: Tile }) {
  return (
    <Link className="card hud" to={`/signal/${t.ip}/${t.port}`}>
      <div className="card-shot">
        {t.image_url ? (
          <img src={imageURL(t.image_url)} alt="" loading="lazy" />
        ) : (
          <div className="card-noshot mono">NO SIGNAL</div>
        )}
        <div className="card-scan" />
        <span className="card-callsign mono">
          {t.ip}:{t.port}
        </span>
      </div>
      <div className="card-meta">
        <div className="row spread">
          <span className="mono card-product">{t.product || "unknown"}</span>
          <span className="row" style={{ gap: 6 }}>
            {t.secured ? <span className="lock">HTTPS</span> : <span className="insecure">HTTP</span>}
            <StatusBadge status={t.http_status} />
          </span>
        </div>
        <div className="row spread card-sub">
          <span className="mono dim">{t.whois}</span>
          {t.geo?.country_iso && <span className="mono dim">{t.geo.country_iso}</span>}
        </div>
      </div>
    </Link>
  );
}
