import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api, imageURL, type SignalDetail } from "../api";
import StatusBadge from "../components/StatusBadge";
import "./Signal.css";

function Field({
  label,
  value,
  hideEmpty,
}: {
  label: string;
  value?: string | number | null;
  hideEmpty?: boolean;
}) {
  if (hideEmpty && (value == null || value === "" || value === "unknown")) return null;
  return (
    <div className="sig-field">
      <span className="sig-flabel mono">{label}</span>
      <span className="sig-fvalue mono">{value ?? "—"}</span>
    </div>
  );
}

export default function Signal() {
  const { ip = "", port = "" } = useParams();
  const [d, setD] = useState<SignalDetail | null>(null);
  const [state, setState] = useState<"loading" | "ok" | "error">("loading");

  useEffect(() => {
    let alive = true;
    setState("loading");
    api
      .signal(ip, port)
      .then((r) => {
        if (!alive) return;
        setD(r);
        setState("ok");
      })
      .catch(() => alive && setState("error"));
    return () => {
      alive = false;
    };
  }, [ip, port]);

  if (state === "loading") return <div className="page wrap empty">◌ TUNING…</div>;
  if (state === "error" || !d) return <div className="page wrap empty">SIGNAL NOT FOUND</div>;

  const s = d.service;
  const geo = s.geo;

  return (
    <div className="page wrap sig">
      <div className="sig-top">
        <Link to="/feed" className="mono sig-back">
          ← feed
        </Link>
        <h1 className="sig-callsign display">
          {s.ip}:{s.port}
        </h1>
        <div className="row sig-tags">
          {s.secured ? (
            <span className="lock mono" title="Captured over TLS (after any redirects)">HTTPS</span>
          ) : (
            <span className="insecure mono" title="Captured over cleartext HTTP (after any redirects)">HTTP</span>
          )}
          <StatusBadge status={s.http_status} />
          {s.product && <span className="badge badge-mute">{s.product}</span>}
        </div>
      </div>

      <div className="sig-main">
        <div className="sig-shot panel hud">
          {s.image_url ? (
            <img src={imageURL(s.image_url)} alt={`${s.ip}:${s.port}`} />
          ) : (
            <div className="empty">NO CAPTURE</div>
          )}
        </div>

        <aside className="sig-info panel panel-pad">
          <div className="eyebrow" style={{ marginBottom: 12 }}>◊ Record</div>
          <Field label="OPERATOR" value={s.whois} hideEmpty />
          <Field
            label="ORIGIN"
            value={geo ? [geo.city, geo.region, geo.country].filter(Boolean).join(", ") : null}
            hideEmpty
          />
          <Field label="COORD" value={geo ? `${geo.lat.toFixed(4)}, ${geo.lon.toFixed(4)}` : null} hideEmpty />
          <Field label="COUNTRY" value={geo?.country_iso} hideEmpty />
          <Field label="CERT CN" value={s.cert_cn} hideEmpty />
          <Field label="pHASH" value={s.screenshot_phash} hideEmpty />
          <Field label="DOM HASH" value={s.dom_hash} hideEmpty />
          <Field label="CAPTURE" value={s.capture_hash ? `${s.capture_hash}.${s.capture_ext}` : null} hideEmpty />
          <Field
            label="SUBMITTER"
            value={d.anon || d.submitted_by === "0.0.0.0" ? "anonymous" : d.submitted_by}
          />
          <Field label="SEEN" value={s.updated_at?.replace("T", " ").replace("Z", " UTC")} />
        </aside>
      </div>

      <section className="panel panel-pad sig-banner">
        <div className="eyebrow" style={{ marginBottom: 10 }}>◊ Service banner</div>
        <pre className="mono sig-pre">{s.banner || "— no banner —"}</pre>
      </section>

      {d.fulltext && (
        <section className="panel panel-pad sig-source">
          <div className="eyebrow" style={{ marginBottom: 10 }}>◊ Page source ({d.fulltext.length.toLocaleString()} chars)</div>
          <pre className="mono sig-pre sig-fulltext">{d.fulltext}</pre>
        </section>
      )}
    </div>
  );
}
