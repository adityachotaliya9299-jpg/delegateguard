/**
 * The DelegateGuard mark: a delegation arrow stopped dead by the guard bar,
 * inside a shield. Drawn by hand so it stays crisp at 14px in a PR comment
 * and at 96px on the landing page.
 */
export function Mark({ size = 34 }: { size?: number }) {
  return (
    <svg
      width={size}
      height={size * (40 / 36)}
      viewBox="0 0 36 40"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      aria-hidden="true"
    >
      <path
        d="M18 2.2 L33 8.1 V19.2 C33 27.9 27.1 34.4 18 37.8 C8.9 34.4 3 27.9 3 19.2 V8.1 Z"
        stroke="currentColor"
        strokeWidth="2.6"
        strokeLinejoin="round"
      />
      {/* incoming delegation */}
      <line x1="7.5" y1="20" x2="14.5" y2="20" stroke="var(--brand, #bf3a17)" strokeWidth="3.1" />
      <path d="M14 14.8 L21.4 20 L14 25.2 Z" fill="var(--brand, #bf3a17)" />
      {/* the guard */}
      <rect x="22.6" y="11.5" width="3.4" height="17" fill="currentColor" />
    </svg>
  );
}

export function Wordmark({ compact = false }: { compact?: boolean }) {
  return (
    <span className="inline-flex items-baseline gap-0.5">
      <span
        className="display"
        style={{ fontSize: compact ? 19 : 22, fontWeight: 640, letterSpacing: "-0.01em" }}
      >
        Delegate
      </span>
      <span
        className="display"
        style={{
          fontSize: compact ? 19 : 22,
          fontWeight: 640,
          letterSpacing: "-0.01em",
          color: "var(--brand)",
        }}
      >
        Guard
      </span>
    </span>
  );
}

export default function Logo({ compact = false }: { compact?: boolean }) {
  return (
    <span className="inline-flex items-center gap-2.5" style={{ color: "var(--ink)" }}>
      <Mark size={compact ? 26 : 30} />
      <Wordmark compact={compact} />
    </span>
  );
}
