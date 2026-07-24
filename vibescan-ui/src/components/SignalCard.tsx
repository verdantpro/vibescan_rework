import { Link } from "react-router-dom";
import { imageURL, type Tile } from "../api";
import { timeAgo } from "../lib/time";
import StatusBadge from "./StatusBadge";
import "./SignalCard.css";

export default function SignalCard({ t }: { t: Tile }) {
  const flagged = t.verdict === "malicious" || t.verdict === "suspicious";
  const provenance = flagged || (t.vuln_count ?? 0) > 0;
  const srcLabel = t.sources && t.sources.length ? t.sources.join(", ") : "third-party feeds";
  const enriched = timeAgo(t.enriched_at);
  return (
    <Link className="card hud" to={`/signal/${t.ip}/${t.port}`}>
      <div className="card-shot">
        {t.image_url ? (
          <img
            src={imageURL(t.thumb_url || t.image_url)}
            alt=""
            loading="lazy"
            decoding="async"
            width={1147}
            height={720}
          />
        ) : (
          <div className="card-noshot mono">NO SIGNAL</div>
        )}
        <span className="card-callsign mono">
          {t.ip}:{t.port}
        </span>
        {t.vuln_count ? (
          <span
            className="card-vuln mono"
            title={`${t.vuln_count} CVE${t.vuln_count > 1 ? "s" : ""} associated with this host by ${srcLabel} — provider-reported, not independently verified`}
          >
            ⚠ {t.vuln_count} CVE{t.vuln_count > 1 ? "s" : ""}
          </span>
        ) : null}
        {flagged ? (
          <span
            className={`card-verdict mono ${t.verdict}`}
            title={`Reputation match from ${srcLabel}${enriched ? ` (${enriched})` : ""} — not independently verified, may be inaccurate`}
          >
            {t.verdict === "malicious" ? "⚑ poss. malicious" : "⚑ suspect"}
          </span>
        ) : null}
      </div>
      <div className="card-meta">
        <div className="row spread">
          <span className="mono card-product">{t.product || "unknown"}</span>
          <span className="row" style={{ gap: 6 }}>
            {t.secured ? (
              <span className="lock" title="Captured over TLS (after any redirects)">HTTPS</span>
            ) : (
              <span className="insecure" title="Captured over cleartext HTTP (after any redirects)">HTTP</span>
            )}
            <StatusBadge status={t.http_status} />
          </span>
        </div>
        <div className="row spread card-sub">
          {t.whois && t.whois !== "unknown" ? (
            <span className="mono dim">{t.whois}</span>
          ) : (
            <span className="mono dim">{t.geo?.city || t.geo?.country || "—"}</span>
          )}
          {t.geo?.country_iso && <span className="mono dim">{t.geo.country_iso}</span>}
        </div>
        {provenance && (
          <div className="card-provenance mono" title="Reputation and CVE data come from third-party feeds and are not independently verified.">
            {srcLabel}
            {enriched ? ` · ${enriched}` : ""} · unverified
          </div>
        )}
      </div>
    </Link>
  );
}
