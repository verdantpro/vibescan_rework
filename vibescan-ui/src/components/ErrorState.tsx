interface Props {
  /** Headline explaining what failed. Defaults to a collector-unreachable message. */
  message?: string;
  onRetry: () => void;
}

/** Explicit, retryable failure state — kept visually distinct from a legitimate
 *  empty result so an outage never reads as "the scanner found nothing". */
export default function ErrorState({ message = "Couldn't reach the collector", onRetry }: Props) {
  return (
    <div className="error-state">
      <span className="error-msg mono">{message}</span>
      <button className="btn" onClick={onRetry}>
        ↻ retry
      </button>
    </div>
  );
}
