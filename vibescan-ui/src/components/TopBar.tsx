import { useEffect, useState } from "react";
import { NavLink } from "react-router-dom";
import { api } from "../api";
import "./TopBar.css";

const NAV = [
  { to: "/", label: "LIVE", end: true },
  { to: "/feed", label: "FEED" },
  { to: "/search", label: "SEARCH" },
  { to: "/stats", label: "STATS" },
];

function useClock() {
  const [t, setT] = useState(() => new Date());
  useEffect(() => {
    const id = setInterval(() => setT(new Date()), 1000);
    return () => clearInterval(id);
  }, []);
  return t.toISOString().slice(11, 19);
}

export default function TopBar() {
  const clock = useClock();
  const [insecure, setInsecure] = useState<number | null>(null);

  useEffect(() => {
    api
      .stats(8760)
      .then((s) => setInsecure(s.secure_capture_counts.insecure ?? 0))
      .catch(() => setInsecure(null));
  }, []);

  return (
    <header className="topbar">
      <div className="wrap topbar-inner">
        <NavLink to="/" className="brand">
          <span className="brand-word">
            <span className="brand-mark display">Vibe</span><span className="brand-accent display">scan</span>
          </span>
          <span className="brand-sub mono">Live Cleartext HTTP Acquisition</span>
        </NavLink>

        <nav className="nav">
          {NAV.map((n) => (
            <NavLink key={n.to} to={n.to} end={n.end} className="nav-link mono">
              {n.label}
            </NavLink>
          ))}
        </nav>

        <div className="topbar-meta mono">
          {insecure != null && (
            <span className="insecure-count">
              <span className="insecure">▲</span> {insecure.toLocaleString()} cleartext
            </span>
          )}
          <span className="clock">
            <span className="live-dot" /> {clock} UTC
          </span>
        </div>
      </div>
    </header>
  );
}
