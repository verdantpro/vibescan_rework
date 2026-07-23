import "./About.css";

const ABUSE = "abuse@verdantprotocol.com";

export default function About() {
  return (
    <div className="record">
      <div className="page wrap about">
        <div className="eyebrow">◊ About the record</div>
        <h1 className="about-title display">What VibeScan is</h1>
        <p className="about-lede">
          A public census of the reachable web — a screenshot and a few facts about services found,
          at random, across the public internet.
        </p>

        <section className="about-sec">
          <h2 className="about-h">How it works</h2>
          <p>
            VibeScan generates random public IPv4 addresses, checks a handful of common web ports
            (<span className="mono">80, 443, 8000, 8080, 8443</span>) with nmap, and — for anything
            answering HTTP or HTTPS — takes a screenshot in a headless browser and files it as a{" "}
            <em>record</em>: the capture, the service banner, HTTP status, the TLS certificate name,
            coarse geolocation derived from the IP, and a snapshot of the page's HTML.
          </p>
          <p>
            Scanning runs continuously in the background at a deliberately slow rate, and every agent
            honors an exclusion list (below) before it touches an address.
          </p>
        </section>

        <section className="about-sec">
          <h2 className="about-h">What “live” means</h2>
          <p>
            The console updates live, but it is a live view of <em>captured records</em> — not a
            real-time scan of the host you happen to be looking at. Each record shows when it was
            captured (its <span className="mono">Seen</span> time). A page may have changed, moved,
            or gone away since; the record is a point-in-time snapshot, not the current state of that
            server.
          </p>
        </section>

        <section className="about-sec">
          <h2 className="about-h">Scope &amp; limits</h2>
          <p>We only look at what an anonymous visitor could already see. Specifically, VibeScan does not:</p>
          <ul className="about-list">
            <li>sign in, submit credentials, or use any authentication;</li>
            <li>exploit, fuzz, or attempt to bypass anything — it loads the page a browser would;</li>
            <li>probe non-web services or scan ports exhaustively;</li>
            <li>capture addresses on its exclusion list.</li>
          </ul>
          <p>
            The scanning agent's own source IP is anonymized in the record. Read APIs are rate-limited.
          </p>
        </section>

        <section className="about-sec">
          <h2 className="about-h">A note on content</h2>
          <p>
            Records are screenshots of third-party sites. They may contain material we did not create
            and cannot vouch for, and — because discovery is random — occasionally something personal
            or sensitive. If a record includes information about you or someone else that shouldn't be
            on public display, tell us and we'll take it down.
          </p>
        </section>

        <section className="about-sec about-contact">
          <h2 className="about-h">Opt out &amp; takedowns</h2>
          <p>
            One address handles all of this: <a className="about-mail" href={`mailto:${ABUSE}`}>{ABUSE}</a>.
            It's monitored by a person.
          </p>

          <div className="about-actions">
            <div className="about-action">
              <div className="about-action-h mono">Stop future scans</div>
              <p>
                Send the IP or CIDR range you control. We add it to the scan blacklist; agents stop
                capturing it within about an hour, permanently.
              </p>
              <a
                className="btn"
                href={`mailto:${ABUSE}?subject=${encodeURIComponent("Opt-out request (IP / CIDR)")}`}
              >
                ✉ request exclusion
              </a>
            </div>

            <div className="about-action">
              <div className="about-action-h mono">Remove existing records</div>
              <p>
                Send the host(s) or range you want removed and we'll delete those records. There is no
                automatic expiry — captures stay until removal is requested.
              </p>
              <a
                className="btn"
                href={`mailto:${ABUSE}?subject=${encodeURIComponent("Takedown request (host / range)")}`}
              >
                ✉ request removal
              </a>
            </div>

            <div className="about-action">
              <div className="about-action-h mono">Report abuse or illegal content</div>
              <p>Flag a record that shouldn't be hosted anywhere and we'll act on it promptly.</p>
              <a
                className="btn"
                href={`mailto:${ABUSE}?subject=${encodeURIComponent("Abuse report")}`}
              >
                ✉ report a record
              </a>
            </div>
          </div>
        </section>
      </div>
    </div>
  );
}
