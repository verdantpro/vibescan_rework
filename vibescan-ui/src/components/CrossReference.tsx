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

function Chips({ items, kind, href }: { items: string[]; kind?: "vuln" | "flag"; href?: (s: string) => string }) {
  return (
    <span className="fr-chips">
      {items.map((s) =>
        href ? (
          <a key={s} className={`fr-chip${kind ? ` ${kind}` : ""}`} href={href(s)} target="_blank" rel="noopener noreferrer">
            {s}
          </a>
        ) : (
          <span key={s} className={`fr-chip${kind ? ` ${kind}` : ""}`}>
            {s}
          </span>
        )
      )}
    </span>
  );
}

function SubHead({ children }: { children: ReactNode }) {
  return <div className="fr-xref-sub mono">{children}</div>;
}

function Verdict({ v }: { v: string }) {
  const cls = v === "malicious" ? "mal" : v === "suspicious" ? "sus" : "clean";
  const label = v === "malicious" ? "Potentially malicious" : v === "suspicious" ? "Suspicious" : "Clean";
  return (
    <div className={`fr-verdict ${cls}`}>
      <b></b>
      <span className="fr-verdict-label">{label.toUpperCase()}</span>
      <span className="fr-verdict-note mono">per third-party feeds — may be inaccurate</span>
    </div>
  );
}

const d10 = (s?: string) => (s ? s.slice(0, 10) : "");
const joind = (...parts: (string | undefined | false)[]) => parts.filter(Boolean).join(" · ");

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

  const flags: string[] = [];
  if (t?.ipqs?.tor || t?.ipinfo?.is_tor) flags.push("tor");
  if (t?.ipqs?.vpn || t?.ipinfo?.is_vpn) flags.push("vpn");
  if (t?.ipqs?.proxy || t?.ipinfo?.is_proxy) flags.push("proxy");
  if (t?.ipqs?.bot_status) flags.push("bot");
  if (t?.ipinfo?.is_hosting) flags.push("hosting");
  if (t?.ipqs?.recent_abuse) flags.push("recent-abuse");

  const shodanLastSeen =
    enr?.last_seen && !enr.last_seen.startsWith("0001")
      ? enr.last_seen.replace("T", " ").slice(0, 19) + " UTC"
      : null;

  const hasExposure =
    (enr?.ports?.length ?? 0) > 0 ||
    (enr?.vulns?.length ?? 0) > 0 ||
    (enr?.cpes?.length ?? 0) > 0 ||
    (enr?.products?.length ?? 0) > 0 ||
    (enr?.tags?.length ?? 0) > 0;
  const hasRep = !!(t?.virustotal || t?.abuseipdb || t?.greynoise || t?.ipqs || t?.pulsedive || flags.length);
  const hasFeeds = !!((t?.otx && t.otx.pulse_count > 0) || (t?.threatfox && t.threatfox.ioc_count > 0));
  const hasNet = !!(enr?.org || t?.bgp?.asn || t?.ipapi || t?.ipinfo || (enr?.hostnames?.length ?? 0) > 0);
  const hasData = hasExposure || hasRep || hasFeeds || hasNet || !!enr?.verdict;

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

          {/* ---------------- Exposure ---------------- */}
          {hasExposure ? (
            <>
              <SubHead>◇ Exposure</SubHead>
              <dl className="fr-xref-grid">
                {enr!.ports?.length ? (
                  <Row label="Open ports">
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
                  <Row label={`CVEs · ${enr!.vulns.length}`}>
                    <Chips items={enr!.vulns} kind="vuln" href={(v) => `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(v)}`} />
                  </Row>
                ) : null}
                {enr!.products?.length ? <Row label="Products">{enr!.products.join(" · ")}</Row> : null}
                {enr!.cpes?.length ? (
                  <Row label="CPEs">
                    <Chips items={enr!.cpes} />
                  </Row>
                ) : null}
                {enr!.tags?.length ? (
                  <Row label="Tags">
                    <Chips items={enr!.tags} />
                  </Row>
                ) : null}
              </dl>
            </>
          ) : null}

          {/* ---------------- Reputation ---------------- */}
          {hasRep ? (
            <>
              <SubHead>◇ Reputation</SubHead>
              <dl className="fr-xref-grid">
                {flags.length ? (
                  <Row label="Network flags">
                    <Chips items={flags} kind="flag" />
                  </Row>
                ) : null}
                {t?.virustotal ? (
                  <Row label="VirusTotal">
                    <span className={t.virustotal.malicious > 0 ? "fr-bad" : undefined}>
                      {t.virustotal.malicious} malicious · {t.virustotal.suspicious} suspicious ·{" "}
                      {t.virustotal.harmless} harmless · {t.virustotal.undetected} undetected
                    </span>
                    {t.virustotal.last_analysis_date ? (
                      <span className="fr-sub"> — last scan {t.virustotal.last_analysis_date}</span>
                    ) : null}
                  </Row>
                ) : null}
                {t?.abuseipdb ? (
                  <Row label="AbuseIPDB">
                    <span className={t.abuseipdb.abuse_confidence >= 25 ? "fr-bad" : undefined}>
                      {t.abuseipdb.abuse_confidence}% confidence · {t.abuseipdb.total_reports} reports
                    </span>
                    {(t.abuseipdb.usage_type || t.abuseipdb.domain || t.abuseipdb.last_reported_at || t.abuseipdb.is_tor || t.abuseipdb.is_whitelisted) ? (
                      <span className="fr-sub">
                        {" — "}
                        {joind(
                          t.abuseipdb.usage_type,
                          t.abuseipdb.domain,
                          t.abuseipdb.last_reported_at && `last reported ${d10(t.abuseipdb.last_reported_at)}`,
                          t.abuseipdb.is_tor && "Tor",
                          t.abuseipdb.is_whitelisted && "whitelisted"
                        )}
                      </span>
                    ) : null}
                  </Row>
                ) : null}
                {t?.greynoise ? (
                  <Row label="GreyNoise">
                    {joind(
                      t.greynoise.classification || "unknown",
                      t.greynoise.noise && "internet noise",
                      t.greynoise.riot && "benign infra",
                      t.greynoise.name,
                      t.greynoise.last_seen && `last seen ${d10(t.greynoise.last_seen)}`
                    )}
                  </Row>
                ) : null}
                {t?.ipqs ? (
                  <Row label="IPQualityScore">
                    <span className={t.ipqs.fraud_score >= 75 ? "fr-bad" : undefined}>{t.ipqs.fraud_score}/100 fraud</span>
                    {(t.ipqs.abuse_velocity && t.ipqs.abuse_velocity !== "none") || t.ipqs.country_code ? (
                      <span className="fr-sub">
                        {" — "}
                        {joind(
                          t.ipqs.abuse_velocity && t.ipqs.abuse_velocity !== "none" && `abuse velocity ${t.ipqs.abuse_velocity}`,
                          t.ipqs.country_code
                        )}
                      </span>
                    ) : null}
                  </Row>
                ) : null}
                {t?.pulsedive && t.pulsedive.risk && t.pulsedive.risk !== "unknown" ? (
                  <Row label="Pulsedive">
                    {t.pulsedive.risk}
                    {t.pulsedive.threats?.length ? ` · threats: ${t.pulsedive.threats.join(", ")}` : ""}
                    {t.pulsedive.feeds?.length ? (
                      <span className="fr-sub"> — feeds: {t.pulsedive.feeds.join(", ")}</span>
                    ) : null}
                    {t.pulsedive.last_seen ? <span className="fr-sub"> — last seen {t.pulsedive.last_seen}</span> : null}
                  </Row>
                ) : null}
              </dl>
            </>
          ) : null}

          {/* ---------------- Threat feeds ---------------- */}
          {hasFeeds ? (
            <>
              <SubHead>◇ Threat feeds</SubHead>
              <dl className="fr-xref-grid">
                {t?.otx && t.otx.pulse_count > 0 ? (
                  <Row label={`AlienVault OTX · ${t.otx.pulse_count}`}>{(t.otx.pulse_names ?? []).join(" · ") || "—"}</Row>
                ) : null}
                {t?.threatfox && t.threatfox.ioc_count > 0 ? (
                  <Row label={`ThreatFox · ${t.threatfox.ioc_count}`}>
                    <div className="fr-iocs">
                      {(t.threatfox.iocs ?? []).map((i, n) => (
                        <div key={i.ioc + n} className="fr-ioc">
                          <span className="fr-bad">{i.malware || i.threat_type || "IOC"}</span>
                          {joind(
                            i.threat_type && i.malware ? i.threat_type : undefined,
                            i.confidence_level ? `${i.confidence_level}% conf` : undefined,
                            i.first_seen && `seen ${d10(i.first_seen)}`
                          )
                            ? " · " +
                              joind(
                                i.threat_type && i.malware ? i.threat_type : undefined,
                                i.confidence_level ? `${i.confidence_level}% conf` : undefined,
                                i.first_seen && `seen ${d10(i.first_seen)}`
                              )
                            : ""}
                          <span className="fr-ioc-val mono"> {i.ioc}</span>
                        </div>
                      ))}
                    </div>
                  </Row>
                ) : null}
              </dl>
            </>
          ) : null}

          {/* ---------------- Network & ownership ---------------- */}
          {hasNet ? (
            <>
              <SubHead>◇ Network &amp; ownership</SubHead>
              <dl className="fr-xref-grid">
                {enr!.org ? <Row label="Operator">{joind(enr!.org, enr!.asn)}</Row> : null}
                {t?.bgp?.asn ? (
                  <Row label="ASN (BGP)">
                    {joind("AS" + t.bgp.asn, t.bgp.asn_name, t.bgp.asn_description, t.bgp.rir && `RIR ${t.bgp.rir}`)}
                    {t.bgp.prefixes?.length ? <span className="fr-sub"> — {t.bgp.prefixes.join(", ")}</span> : null}
                  </Row>
                ) : null}
                {t?.ipapi ? (
                  <Row label="ip-api">{joind(t.ipapi.isp, [t.ipapi.city, t.ipapi.region, t.ipapi.country].filter(Boolean).join(", "))}</Row>
                ) : enr!.city || enr!.country ? (
                  <Row label="Origin">{[enr!.city, enr!.country].filter(Boolean).join(", ")}</Row>
                ) : null}
                {t?.ipinfo ? (
                  <Row label="IPinfo">
                    {joind(
                      t.ipinfo.hostname,
                      t.ipinfo.org,
                      [t.ipinfo.city, t.ipinfo.region, t.ipinfo.country].filter(Boolean).join(", ") || undefined,
                      t.ipinfo.timezone
                    ) || "—"}
                  </Row>
                ) : null}
                {enr!.hostnames?.length ? <Row label="Hostnames">{enr!.hostnames.join(", ")}</Row> : null}
                {shodanLastSeen ? <Row label="Last seen">{shodanLastSeen}</Row> : null}
              </dl>
            </>
          ) : null}

          <div className="fr-xref-attr mono">
            {enr!.sources?.length ? <span>sources: {enr!.sources.join(", ")} · </span> : null}
            data via Shodan · InternetDB · ip-api · RIPEstat · VirusTotal · AbuseIPDB · GreyNoise ·
            AlienVault OTX · ThreatFox · IPQualityScore · Pulsedive · IPinfo. Reputation is
            third-party and may be wrong —{" "}
            <a href="mailto:abuse@verdantprotocol.com?subject=Reputation%20dispute">dispute it</a>.
          </div>
        </>
      )}
    </section>
  );
}
