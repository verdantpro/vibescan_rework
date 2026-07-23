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

function Chips({ items, kind }: { items: string[]; kind?: "vuln" | "flag" }) {
  return (
    <span className="fr-chips">
      {items.map((t) => (
        <span key={t} className={`fr-chip${kind ? ` ${kind}` : ""}`}>
          {t}
        </span>
      ))}
    </span>
  );
}

function Verdict({ v }: { v: string }) {
  const cls = v === "malicious" ? "mal" : v === "suspicious" ? "sus" : "clean";
  // The feeds carry false positives, so the label hedges rather than accuses.
  const label = v === "malicious" ? "Potentially malicious" : v === "suspicious" ? "Suspicious" : "Clean";
  return (
    <div className={`fr-verdict ${cls}`}>
      <b></b>
      <span className="fr-verdict-label">{label.toUpperCase()}</span>
      <span className="fr-verdict-note mono">per third-party feeds — may be inaccurate</span>
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

  const t = enr?.threat;
  const hasData =
    !!enr &&
    ((enr.ports?.length ?? 0) > 0 ||
      (enr.vulns?.length ?? 0) > 0 ||
      (enr.tags?.length ?? 0) > 0 ||
      !!enr.org ||
      (enr.hostnames?.length ?? 0) > 0 ||
      !!enr.verdict ||
      !!t);

  const lastSeen =
    enr?.last_seen && !enr.last_seen.startsWith("0001")
      ? enr.last_seen.replace("T", " ").slice(0, 19) + " UTC"
      : null;

  // Network flags aggregated from IPQS + IPinfo.
  const flags: string[] = [];
  if (t?.ipqs?.tor || t?.ipinfo?.is_tor) flags.push("tor");
  if (t?.ipqs?.vpn || t?.ipinfo?.is_vpn) flags.push("vpn");
  if (t?.ipqs?.proxy || t?.ipinfo?.is_proxy) flags.push("proxy");
  if (t?.ipqs?.bot_status) flags.push("bot");
  if (t?.ipinfo?.is_hosting) flags.push("hosting");
  if (t?.ipqs?.recent_abuse) flags.push("recent-abuse");

  return (
    <section className="fr-sec fr-xref">
      <div className="fr-sec-h">Cross-reference · via Shodan / InternetDB / threat feeds</div>

      {state === "loading" ? (
        <div className="fr-xref-msg mono">◌ cross-referencing…</div>
      ) : state === "error" ? (
        <div className="fr-xref-msg mono">Couldn't reach the enrichment service.</div>
      ) : !hasData ? (
        <div className="fr-xref-msg mono">No external records on file for this host.</div>
      ) : (
        <>
          {enr!.verdict ? <Verdict v={enr!.verdict} /> : null}

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
                <Chips items={enr!.tags} />
              </Row>
            ) : null}

            {flags.length ? (
              <Row label="Flags">
                <Chips items={flags} kind="flag" />
              </Row>
            ) : null}

            {/* --- reputation --- */}
            {t?.virustotal ? (
              <Row label="VirusTotal">
                <span className={t.virustotal.malicious > 0 ? "fr-bad" : undefined}>
                  {t.virustotal.malicious} malicious · {t.virustotal.suspicious} suspicious ·{" "}
                  {t.virustotal.harmless} harmless
                </span>
              </Row>
            ) : null}
            {t?.abuseipdb ? (
              <Row label="AbuseIPDB">
                <span className={t.abuseipdb.abuse_confidence >= 25 ? "fr-bad" : undefined}>
                  {t.abuseipdb.abuse_confidence}% confidence · {t.abuseipdb.total_reports} reports
                  {t.abuseipdb.is_whitelisted ? " · whitelisted" : ""}
                </span>
              </Row>
            ) : null}
            {t?.greynoise ? (
              <Row label="GreyNoise">
                {t.greynoise.classification || "unknown"}
                {t.greynoise.riot ? " · benign infra" : ""}
                {t.greynoise.name ? ` · ${t.greynoise.name}` : ""}
              </Row>
            ) : null}
            {t?.ipqs ? (
              <Row label="Fraud score">
                <span className={t.ipqs.fraud_score >= 75 ? "fr-bad" : undefined}>
                  {t.ipqs.fraud_score}/100
                  {t.ipqs.abuse_velocity && t.ipqs.abuse_velocity !== "none"
                    ? ` · abuse velocity ${t.ipqs.abuse_velocity}`
                    : ""}
                </span>
              </Row>
            ) : null}

            {/* --- threat feeds --- */}
            {t?.otx && t.otx.pulse_count > 0 ? (
              <Row label={`OTX · ${t.otx.pulse_count} pulse${t.otx.pulse_count > 1 ? "s" : ""}`}>
                {(t.otx.pulse_names ?? []).slice(0, 8).join(" · ") || "—"}
              </Row>
            ) : null}
            {t?.threatfox && t.threatfox.ioc_count > 0 ? (
              <Row label={`ThreatFox · ${t.threatfox.ioc_count} IOC${t.threatfox.ioc_count > 1 ? "s" : ""}`}>
                <span className="fr-bad">
                  {(t.threatfox.iocs ?? [])
                    .map((i) => i.malware || i.threat_type)
                    .filter(Boolean)
                    .slice(0, 6)
                    .join(" · ") || "flagged"}
                </span>
              </Row>
            ) : null}
            {t?.pulsedive && t.pulsedive.risk && t.pulsedive.risk !== "unknown" ? (
              <Row label="Pulsedive">
                {t.pulsedive.risk}
                {t.pulsedive.threats?.length ? ` · ${t.pulsedive.threats.slice(0, 5).join(", ")}` : ""}
              </Row>
            ) : null}

            {/* --- ownership / origin --- */}
            {enr!.org ? <Row label="Operator">{[enr!.org, enr!.asn].filter(Boolean).join(" · ")}</Row> : null}
            {t?.bgp?.asn ? (
              <Row label="ASN">
                {["AS" + t.bgp.asn, t.bgp.asn_name, t.bgp.rir].filter(Boolean).join(" · ")}
                {t.bgp.prefixes?.length ? ` · ${t.bgp.prefixes.slice(0, 4).join(", ")}` : ""}
              </Row>
            ) : null}
            {!enr!.org && t?.ipapi?.isp ? <Row label="Operator">{t.ipapi.isp}</Row> : null}
            {t?.ipapi && (t.ipapi.city || t.ipapi.country) ? (
              <Row label="Origin">{[t.ipapi.city, t.ipapi.region, t.ipapi.country].filter(Boolean).join(", ")}</Row>
            ) : enr!.city || enr!.country ? (
              <Row label="Origin">{[enr!.city, enr!.country].filter(Boolean).join(", ")}</Row>
            ) : null}
            {enr!.hostnames?.length ? <Row label="Hostnames">{enr!.hostnames.join(", ")}</Row> : null}
            {lastSeen ? <Row label="Last seen">{lastSeen}</Row> : null}
          </dl>

          <div className="fr-xref-attr mono">
            data via Shodan · InternetDB · ip-api · RIPEstat · VirusTotal · AbuseIPDB · GreyNoise ·
            AlienVault OTX · ThreatFox · IPQualityScore · Pulsedive · IPinfo.{" "}
            Reputation is third-party and may be wrong —{" "}
            <a href="mailto:abuse@verdantprotocol.com?subject=Reputation%20dispute">dispute it</a>.
          </div>
        </>
      )}
    </section>
  );
}
