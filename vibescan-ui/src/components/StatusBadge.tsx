export function statusClass(s: number | null | undefined): string {
  if (s == null) return "badge-mute";
  if (s === 200) return "badge-ok";
  if (s >= 300 && s < 400) return "badge-redir";
  if (s >= 400) return "badge-err";
  return "badge-mute";
}

export default function StatusBadge({ status }: { status: number | null | undefined }) {
  return <span className={`badge ${statusClass(status)}`}>{status ?? "—"}</span>;
}
