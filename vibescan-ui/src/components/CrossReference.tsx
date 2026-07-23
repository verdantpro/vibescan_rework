import { useEffect, useState, type ReactNode } from "react";
import { api, type Enrichment } from "../api";

// Common ports get a service label so "3306" reads as "3306/mysql".
const PORT_NAME: Record<number, string> = {
  21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 110: "pop3",
  143: "imap", 161: "snmp", 389: "ldap", 443: "https", 445: "smb", 465: "smtps",
  587: "smtp", 993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle", 2049: "nfs",
  3306: "mysql", 3389: "rdp", 5432: "postgres", 5900: "vnc", 6379: "redis", 8080: "http",
  8443: "https", 9200: "elastic", 11211: "memcached", 27017: "mongodb",
};

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="fr-note">
      <dt>{label}</dt>
      <dd>{children}</dd>
    </div>
  );
}

export default function CrossReference({ ip }: { ip: string }) {
  const [enr, setEnr] = useState<Enrichment | null>(null);
  const [state, setState] = useState<"loading" | "ok" | "error">("loading");

  useEffect(() => {
    let alive = true;
    setState("loading");
    api
      .enrich(ip)
      .then((e) => {
        if (!alive) return;
        setEnr(e);
        setState("ok");
      })
      .catch(() => alive && setState("error"));
    return () => {
      alive = false;
    };
  }, [ip]);

  const hasData =
    !!enr &&
    ((enr.ports?.length ?? 0) > 0 ||
      (enr.vulns?.length ?? 0) > 0 ||
      (enr.tags?.length ?? 0) > 0 ||
      !!enr.org ||
      (enr.hostnames?.length ?? 0) > 0);

  const lastSeen =
    enr?.last_seen && !enr.last_seen.startsWith("0001")
      ? enr.last_seen.replace("T", " ").slice(0, 19) + " UTC"
      : null;

  return (
    <section className="fr-sec fr-xref">
      <div className="fr-sec-h">Cross-reference · via Shodan / InternetDB</div>

      {state === "loading" ? (
        <div className="fr-xref-msg mono">◌ cross-referencing…</div>
      ) : state === "error" ? (
        <div className="fr-xref-msg mono">Couldn't reach the enrichment service.</div>
      ) : !hasData ? (
        <div className="fr-xref-msg mono">No external records on file for this host.</div>
      ) : (
        <>
          <dl className="fr-xref-grid">
            {enr!.ports?.length ? (
              <Row label="Also open">
                <span className="fr-chips">
                  {enr!.ports.map((p) => (
                    <span key={p} className="fr-chip">
                      {p}
                      {PORT_NAME[p] ? `/${PORT_NAME[p]}` : ""}
                    </span>
                  ))}
                </span>
              </Row>
            ) : null}

            {enr!.vulns?.length ? (
              <Row label={`Exposure · ${enr!.vulns.length} CVE${enr!.vulns.length > 1 ? "s" : ""}`}>
                <span className="fr-chips">
                  {enr!.vulns.map((v) => (
                    <a
                      key={v}
                      className="fr-chip vuln"
                      href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(v)}`}
                      target="_blank"
                      rel="noopener noreferrer"
                    >
                      {v}
                    </a>
                  ))}
                </span>
              </Row>
            ) : null}

            {enr!.tags?.length ? (
              <Row label="Tags">
                <span className="fr-chips">
                  {enr!.tags.map((t) => (
                    <span key={t} className="fr-chip">
                      {t}
                    </span>
                  ))}
                </span>
              </Row>
            ) : null}

            {enr!.org ? <Row label="Operator">{[enr!.org, enr!.asn].filter(Boolean).join(" · ")}</Row> : null}
            {enr!.isp && enr!.isp !== enr!.org ? <Row label="ISP">{enr!.isp}</Row> : null}
            {enr!.city || enr!.country ? (
              <Row label="Origin">{[enr!.city, enr!.country].filter(Boolean).join(", ")}</Row>
            ) : null}
            {enr!.hostnames?.length ? <Row label="Hostnames">{enr!.hostnames.join(", ")}</Row> : null}
            {lastSeen ? <Row label="Last seen">{lastSeen}</Row> : null}
          </dl>

          <div className="fr-xref-attr mono">
            data via Shodan ·{" "}
            <a href={`https://www.shodan.io/host/${ip}`} target="_blank" rel="noopener noreferrer">
              shodan.io/host/{ip}
            </a>
          </div>
        </>
      )}
    </section>
  );
}
