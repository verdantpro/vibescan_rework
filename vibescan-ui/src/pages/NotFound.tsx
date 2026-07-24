import { Link } from "react-router-dom";
import { useMeta } from "../lib/meta";
import "./NotFound.css";

export default function NotFound() {
  useMeta({
    title: "Signal Lost (404) — VibeScan",
    description: "The requested page could not be found.",
  });
  return (
    <div className="notfound">
      <div className="page wrap notfound-inner">
        <div className="nf-code mono">404</div>
        <h1 className="nf-title display">Signal lost</h1>
        <p className="nf-lede">
          No record answers at this address. It may have been removed, or the link is wrong.
        </p>
        <div className="nf-actions">
          <Link className="btn" to="/">
            ← back to the console
          </Link>
          <Link className="btn" to="/search">
            search the census
          </Link>
        </div>
      </div>
    </div>
  );
}
