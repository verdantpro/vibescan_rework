// Typed client for the VibeScan v2 read API.

// In production the UI is served same-origin by the Go binary, so an unset base
// means relative /api URLs. Only local dev falls back to the collector's port —
// this way a prod build without .env.production can never point at localhost.
export const API_BASE =
  (import.meta.env.VITE_API_BASE as string | undefined) ??
  (import.meta.env.DEV ? "http://127.0.0.1:8000" : "");

export interface Geo {
  ip: string;
  lat: number;
  lon: number;
  city: string;
  region: string;
  country: string;
  country_iso: string;
  accuracy_radius_km: number | null;
}

export interface Tile {
  ip: string;
  port: number;
  banner: string;
  product: string;
  http_status: number | null;
  secured: boolean;
  whois: string;
  image_url: string;
  capture_hash: string;
  capture_ext: string;
  has_fulltext: boolean;
  screenshot_phash?: string;
  dom_hash?: string;
  cert_cn?: string;
  updated_at: string;
  geo?: Geo | null;
}

export interface ListResponse {
  entries: Tile[];
  has_more: boolean;
  query?: string;
}

export interface RandomCapture {
  image_url: string;
  ip: string;
  port: number;
  product_name: string;
  whois: string;
}

export interface SignalDetail {
  service: Tile;
  fulltext: string;
  favicon_hash: string;
  submitted_by: string;
  anon: boolean;
  timestamp: string | null;
  received_at: string | null;
}

export interface Stats {
  time_range_hours: number;
  totals: { hosts: number; services: number };
  services_by_port: Record<string, number>;
  status_code_counts: Record<string, number>;
  secure_capture_counts: Record<string, number>;
  top_banners: Record<string, number>;
  submissions_by_client: Record<string, number>;
  submissions_over_time: Record<string, number>;
}

export interface SearchParams {
  q?: string;
  port?: number;
  status?: number;
  secured?: boolean;
  product?: string;
  limit?: number;
  offset?: number;
}

/** Resolve a possibly-relative image_url against the API host. */
export function imageURL(url: string): string {
  if (!url) return "";
  if (url.startsWith("http")) return url;
  return API_BASE + url;
}

/** A failed API call. `offline` means the collector was unreachable or reported
 *  itself offline (503 / {offline:true}) — distinct from a request that
 *  succeeded and simply returned no results. */
export class ApiError extends Error {
  offline: boolean;
  status?: number;
  constructor(message: string, opts: { offline: boolean; status?: number }) {
    super(message);
    this.name = "ApiError";
    this.offline = opts.offline;
    this.status = opts.status;
  }
}

export function isOffline(e: unknown): boolean {
  return e instanceof ApiError && e.offline;
}

async function get<T>(path: string): Promise<T> {
  let res: Response;
  try {
    res = await fetch(API_BASE + path);
  } catch {
    // Network-level failure: the collector is unreachable.
    throw new ApiError(`${path} → unreachable`, { offline: true });
  }
  if (!res.ok) {
    // The read APIs return 503 {offline:true} when the datastore is down; treat
    // that (and any 5xx) as offline so the UI can distinguish it from "no data".
    let offline = res.status >= 500;
    try {
      const body = await res.clone().json();
      if (body && body.offline === true) offline = true;
    } catch {
      /* non-JSON body; keep the status-based guess */
    }
    throw new ApiError(`${path} → ${res.status}`, { offline, status: res.status });
  }
  return res.json() as Promise<T>;
}

// Short-lived cache for stats: the all-time snapshot is requested by both the
// TopBar and the Console on first paint — this collapses those (and any rapid
// range toggling) into a single in-flight request per range. The server also
// caches for 60s; 30s here just avoids duplicate client round-trips.
const STATS_TTL_MS = 30_000;
const statsCache = new Map<number, { at: number; p: Promise<Stats> }>();

export const api = {
  gallery: (limit = 60, offset = 0) =>
    get<ListResponse>(`/api/v2/gallery?limit=${limit}&offset=${offset}`),

  // Pure-recency feed ("Latest signals"): newest captures first, any status.
  recent: (limit = 60, offset = 0) =>
    get<ListResponse>(`/api/v2/gallery?sort=recent&limit=${limit}&offset=${offset}`),

  search: (p: SearchParams) => {
    const q = new URLSearchParams();
    if (p.q) q.set("q", p.q);
    if (p.port != null) q.set("port", String(p.port));
    if (p.status != null) q.set("status", String(p.status));
    if (p.secured != null) q.set("secured", String(p.secured));
    if (p.product) q.set("product", p.product);
    q.set("limit", String(p.limit ?? 60));
    q.set("offset", String(p.offset ?? 0));
    return get<ListResponse>(`/api/v2/search?${q.toString()}`);
  },

  stats: (timeRange = 24): Promise<Stats> => {
    const hit = statsCache.get(timeRange);
    if (hit && Date.now() - hit.at < STATS_TTL_MS) return hit.p;
    const p = get<Stats>(`/api/v2/stats?time_range=${timeRange}`).catch((e) => {
      statsCache.delete(timeRange); // let a failed fetch be retried immediately
      throw e;
    });
    statsCache.set(timeRange, { at: Date.now(), p });
    return p;
  },

  randomCapture: () => get<RandomCapture>(`/api/v2/random-capture`),

  // brief omits the heavy page-source fulltext (the live console never shows it).
  signal: (ip: string, port: number | string, opts?: { brief?: boolean }) =>
    get<SignalDetail>(`/api/v2/services/${ip}/${port}${opts?.brief ? "?brief=1" : ""}`),
};
