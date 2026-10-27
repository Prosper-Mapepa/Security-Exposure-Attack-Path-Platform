export function SeapMark({ className = 'h-11 w-11' }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
      <defs>
        <linearGradient id="seap-mark-field" x1="4" y1="2" x2="36" y2="38" gradientUnits="userSpaceOnUse">
          <stop stopColor="#0b3d38" />
          <stop offset="0.55" stopColor="#0f6b63" />
          <stop offset="1" stopColor="#1aa896" />
        </linearGradient>
        <linearGradient id="seap-mark-path" x1="8" y1="28" x2="32" y2="10" gradientUnits="userSpaceOnUse">
          <stop stopColor="#d7f5ef" stopOpacity="0.95" />
          <stop offset="1" stopColor="#7ee0d0" />
        </linearGradient>
      </defs>
      <rect x="1.5" y="1.5" width="37" height="37" rx="9" fill="url(#seap-mark-field)" stroke="rgba(255,255,255,0.18)" strokeWidth="1" />
      <path
        d="M9 27.5C12.5 27.5 14.2 22.8 17.8 20.2C21.2 17.8 23.4 19.6 26.2 16.4C28.4 13.9 29.2 11 32 10"
        stroke="url(#seap-mark-path)"
        strokeWidth="1.7"
        strokeLinecap="round"
        className="seap-logo-route"
      />
      <circle cx="9" cy="27.5" r="2.35" fill="#ecfdf8" />
      <circle cx="18.2" cy="19.8" r="2.1" fill="#f0fdfa" stroke="#0b3d38" strokeWidth="0.8" />
      <circle cx="32" cy="10" r="2.6" fill="#f8fafc" />
      <circle cx="32" cy="10" r="4.4" stroke="#ecfdf8" strokeOpacity="0.35" strokeWidth="1" className="seap-logo-ring" />
    </svg>
  );
}

/** Teal SEAP lockup — matches the brand wordmark treatment */
export function SeapWordmark({ compact = false }: { compact?: boolean }) {
  return (
    <span className="min-w-0">
      <span className="seap-wordmark-teal block truncate text-[1.65rem] font-bold leading-none tracking-[0.28em] sm:text-[1.85rem]">
        SEAP
      </span>
      {compact ? null : (
        <span className="mt-1 hidden truncate text-[10px] font-medium uppercase tracking-[0.22em] text-mute sm:block">
          Exposure & attack paths
        </span>
      )}
    </span>
  );
}
