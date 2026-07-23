import { Link } from "react-router-dom";
import "./Footer.css";

export default function Footer() {
  return (
    <footer className="footer">
      <div className="wrap footer-inner mono">
        <span className="footer-note">VibeScan · a random IPv4 census of the reachable web</span>
        <nav className="footer-links">
          <Link to="/about">About &amp; ethics</Link>
          <a href="mailto:abuse@verdantprotocol.com?subject=Opt-out%20request%20(IP%20%2F%20CIDR)">
            Opt out / report
          </a>
        </nav>
      </div>
    </footer>
  );
}
