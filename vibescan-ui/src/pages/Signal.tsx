import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api, imageURL, type SignalDetail } from "../api";
import CrossReference from "../components/CrossReference";
import { useMeta } from "../lib/meta";
import "./Signal.css";

function Note({
  label,
  value,
  mono,
  tone,
  hideEmpty,
}: {
  label: string;
  value?: string | number | null;
  mono?: boolean;
  tone?: "alert";
  hideEmpty?: boolean;
}) {
  if (hideEmpty && (value == null || value === "" || value === "unknown")) return null;
  return (
    <div className="fr-note">
      <dt>{label}</dt>
      <dd className={`${mono ? "hash" : ""}${tone === "alert" ? " alert" : ""}`}>{value ?? "—"}</dd>
    </div>
  );
}

export default function Signal() {
  const { ip = "", port = "" } = useParams();
  const [d, setD] = useState<SignalDetail | null>(null);
  const [state, setState] = useState<"loading" | "ok" | "error">("loading");

  useMeta({
    title: ip && port ? `${ip}:${port} — VibeScan record` : "Record — VibeScan",
    description: "A point-in-time capture and telemetry record for a discovered web service.",
  });

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

  if (state === "loading") return <div className="record"><div className="page wrap empty">◌ Tuning…</div></div>;
  if (state === "error" || !d) return <div className="record"><div className="page wrap empty">Signal not found</div></div>;

  const s = d.service;
  const geo = s.geo;
  const seen = s.updated_at?.replace("T", " ").replace("Z", " UTC");
  const origin = geo ? [geo.city, geo.region, geo.country].filter(Boolean).join(" · ") : null;
  const submitter = d.anon || d.submitted_by === "0.0.0.0" ? "anonymous" : d.submitted_by;

  return (
    <div className="record">
      <div className="page wrap sig-record">
        <Link to="/feed" className="fr-back">← feed</Link>

        <header className="fr-casehead">
          <div>
            <span className="fr-eyebrow">Case</span>
            <h1 className="fr-callsign">
              {s.ip}<span className="port">:{s.port}</span>
            </h1>
          </div>
          <div className="fr-caseright">
            <span className={`fr-class ${s.secured ? "ok" : "alert"}`}>
              <b></b> {s.secured ? "Secured · TLS" : "Cleartext · No TLS"}
            </span>
            {seen && (
              <div className="fr-filed">
                <span>Seen</span>
                {seen}
              </div>
            )}
          </div>
        </header>

        <div className="fr-body">
          <figure className="fr-exhibit">
            <span className="fr-tick tl"></span><span className="fr-tick tr"></span>
            <span className="fr-tick bl"></span><span className="fr-tick br"></span>
            <div className="fr-exhibit-frame">
              {s.image_url ? (
                <img
                  src={imageURL(s.image_url)}
                  alt={`Captured screenshot of ${s.ip}:${s.port}`}
                  width={1147}
                  height={720}
                  loading="lazy"
                  decoding="async"
                />
              ) : (
                <div className="fr-noshot">No capture on record</div>
              )}
            </div>
            <figcaption className="fr-cap">
              <span>Exhibit A{s.capture_hash ? ` · capture ${s.capture_hash.slice(0, 8)}` : ""}</span>
              <span>{s.capture_ext ? s.capture_ext.toUpperCase() : ""}</span>
            </figcaption>
          </figure>

          <aside className="fr-notes">
            <div className="fr-notes-h">Field notes</div>
            <dl>
              <Note label="Operator" value={s.whois} hideEmpty />
              <Note label="Origin" value={origin} hideEmpty />
              <Note label="Coord" value={geo ? `${geo.lat.toFixed(4)}, ${geo.lon.toFixed(4)}` : null} hideEmpty />
              <Note label="Country" value={geo?.country_iso} hideEmpty />
              <Note label="Server" value={s.product} hideEmpty />
              <Note
                label="Protocol"
                value={s.secured ? "HTTPS · TLS" : "HTTP — no transport encryption"}
                tone={s.secured ? undefined : "alert"}
              />
              <Note label="Status" value={s.http_status} />
              <Note label="Cert CN" value={s.cert_cn} hideEmpty />
              <Note label="pHash" value={s.screenshot_phash} mono hideEmpty />
              <Note label="DOM" value={s.dom_hash} mono hideEmpty />
              <Note label="Submitter" value={submitter} mono />
            </dl>
          </aside>
        </div>

        <CrossReference ip={s.ip} />

        <section className="fr-sec">
          <div className="fr-sec-h">Service banner</div>
          <pre className="fr-pre">{s.banner || "— no banner —"}</pre>
        </section>

        {d.fulltext && (
          <section className="fr-sec">
            <div className="fr-sec-h">Page source · {d.fulltext.length.toLocaleString()} chars</div>
            <pre className="fr-pre fr-scroll">{d.fulltext}</pre>
          </section>
        )}
      </div>
    </div>
  );
}
