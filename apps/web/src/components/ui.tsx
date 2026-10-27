import { CircleHelp, Loader2 } from 'lucide-react';
import { useEffect, useId, useRef, useState, type ButtonHTMLAttributes, type CSSProperties, type ReactNode } from 'react';
import { createPortal } from 'react-dom';

const SEVERITY: Record<string, string> = {
  CRITICAL: 'bg-rose-600 text-white',
  HIGH: 'bg-orange-500 text-white',
  MEDIUM: 'bg-amber-400 text-slate-950',
  LOW: 'bg-sky-500 text-white',
  INFO: 'bg-slate-500 text-white',
};

const SEVERITY_TIP: Record<string, string> = {
  CRITICAL: 'Immediate risk. Prioritize containment and remediation.',
  HIGH: 'Serious exposure. Schedule remediation soon.',
  MEDIUM: 'Meaningful risk. Plan a fix with the asset owner.',
  LOW: 'Limited impact. Track and remediate when practical.',
  INFO: 'Informational finding. Useful context, usually not urgent.',
};

export type TooltipPlacement = 'top' | 'bottom' | 'left' | 'right';

export function Tooltip({
  content,
  children,
  placement = 'top',
  delay = 280,
  className = '',
}: {
  content: ReactNode;
  children: ReactNode;
  placement?: TooltipPlacement;
  delay?: number;
  className?: string;
}) {
  const tipId = useId();
  const triggerRef = useRef<HTMLSpanElement>(null);
  const [open, setOpen] = useState(false);
  const [coords, setCoords] = useState<CSSProperties>({});
  const timer = useRef<number | null>(null);

  function clearTimer() {
    if (timer.current != null) {
      window.clearTimeout(timer.current);
      timer.current = null;
    }
  }

  function show() {
    clearTimer();
    timer.current = window.setTimeout(() => setOpen(true), delay);
  }

  function hide() {
    clearTimer();
    setOpen(false);
  }

  useEffect(() => () => clearTimer(), []);

  useEffect(() => {
    if (!open || !triggerRef.current) return;
    function place() {
      const rect = triggerRef.current?.getBoundingClientRect();
      if (!rect) return;
      const gap = 8;
      if (placement === 'bottom') {
        setCoords({ top: rect.bottom + gap, left: rect.left + rect.width / 2, transform: 'translateX(-50%)' });
      } else if (placement === 'left') {
        setCoords({ top: rect.top + rect.height / 2, left: rect.left - gap, transform: 'translate(-100%, -50%)' });
      } else if (placement === 'right') {
        setCoords({ top: rect.top + rect.height / 2, left: rect.right + gap, transform: 'translateY(-50%)' });
      } else {
        setCoords({ top: rect.top - gap, left: rect.left + rect.width / 2, transform: 'translate(-50%, -100%)' });
      }
    }
    place();
    window.addEventListener('scroll', place, true);
    window.addEventListener('resize', place);
    return () => {
      window.removeEventListener('scroll', place, true);
      window.removeEventListener('resize', place);
    };
  }, [open, placement]);

  return (
    <span
      ref={triggerRef}
      className={`max-w-full ${className || 'inline-flex'}`}
      onMouseEnter={show}
      onMouseLeave={hide}
      onFocus={show}
      onBlur={hide}
      aria-describedby={open ? tipId : undefined}
    >
      {children}
      {open && content
        ? createPortal(
            <span
              id={tipId}
              role="tooltip"
              className="pointer-events-none fixed z-[90] max-w-xs rounded-md border border-line bg-panel px-2.5 py-1.5 text-xs leading-relaxed text-slate-900 shadow-lg dark:text-slate-100"
              style={coords}
            >
              {content}
            </span>,
            document.body,
          )
        : null}
    </span>
  );
}

export function Hint({ label, tip, placement = 'top' }: { label: ReactNode; tip: string; placement?: TooltipPlacement }) {
  return (
    <span className="inline-flex items-center gap-1.5">
      <span>{label}</span>
      <Tooltip content={tip} placement={placement}>
        <button
          type="button"
          className="inline-flex h-4 w-4 items-center justify-center rounded-full text-mute hover:text-accent focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent"
          aria-label={typeof label === 'string' ? `About ${label}` : 'More information'}
        >
          <CircleHelp size={14} aria-hidden="true" />
        </button>
      </Tooltip>
    </span>
  );
}

export function Severity({ value }: { value: string }) {
  return (
    <Tooltip content={SEVERITY_TIP[value] ?? 'Finding severity from the scanner and risk model.'}>
      <span className={`rounded px-2 py-0.5 text-xs font-semibold tracking-wide ${SEVERITY[value] ?? SEVERITY.INFO}`}>{value}</span>
    </Tooltip>
  );
}

export function Spinner({ className = 'h-4 w-4' }: { className?: string }) {
  return <Loader2 className={`animate-spin ${className}`} aria-hidden="true" />;
}

export function PageHeader({ title, description, actions }: { title: string; description?: string; actions?: ReactNode }) {
  return (
    <div className="flex flex-wrap items-end justify-between gap-4 border-b border-line pb-4">
      <div className="min-w-0">
        <h1 className="text-xl font-semibold tracking-tight">{title}</h1>
        {description ? <p className="mt-1 max-w-2xl text-sm text-mute">{description}</p> : null}
      </div>
      {actions ? <div className="ml-auto flex flex-wrap items-center gap-2">{actions}</div> : null}
    </div>
  );
}

export function PageLoading({ label }: { label: string }) {
  return (
    <div className="flex items-center gap-2 py-8 text-sm text-mute" role="status">
      <Spinner />
      <span>{label}</span>
    </div>
  );
}

export function Panel({ title, tip, children, action }: { title?: string; tip?: string; children: ReactNode; action?: ReactNode }) {
  return (
    <section className="rounded-lg border border-line bg-panel p-4">
      {(title || action) && (
        <div className="mb-4 flex items-center justify-between gap-3">
          {title ? (
            <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
              {tip ? <Hint label={title} tip={tip} /> : title}
            </h2>
          ) : <span />}
          {action}
        </div>
      )}
      {children}
    </section>
  );
}

export function Empty({ title, body }: { title: string; body: string }) {
  return (
    <div className="rounded-md border border-dashed border-line px-4 py-10 text-center">
      <p className="font-medium">{title}</p>
      <p className="mt-1 text-sm text-mute">{body}</p>
    </div>
  );
}

export function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="block text-sm">
      <span className="mb-1 block text-mute">{label}</span>
      {children}
    </label>
  );
}

export const inputClass = 'w-full rounded-md border border-line bg-ink px-3 py-2 text-sm outline-none focus:border-accent';

const buttonVariants = {
  primary: 'bg-accent text-white hover:bg-accent/90',
  secondary: 'border border-line bg-panel hover:bg-ink',
  danger: 'bg-rose-600 text-white hover:bg-rose-500',
} as const;

type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  loading?: boolean;
  variant?: keyof typeof buttonVariants;
};

export function Button({ children, loading = false, disabled, className = '', variant = 'primary', type = 'button', ...props }: ButtonProps) {
  const busy = loading || disabled;
  return (
    <button
      {...props}
      type={type}
      disabled={busy}
      aria-busy={loading || undefined}
      className={`inline-flex min-h-9 items-center justify-center gap-2 rounded-md px-3 py-2 text-sm font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-60 ${buttonVariants[variant]} ${className}`}
    >
      {loading ? <Spinner /> : null}
      {children}
    </button>
  );
}

export function IconButton({ children, loading = false, disabled, className = '', ...props }: ButtonHTMLAttributes<HTMLButtonElement> & { loading?: boolean }) {
  return (
    <button
      {...props}
      type="button"
      disabled={loading || disabled}
      aria-busy={loading || undefined}
      className={`inline-flex h-9 w-9 items-center justify-center rounded-md border border-line bg-panel hover:bg-ink disabled:cursor-not-allowed disabled:opacity-60 ${className}`}
    >
      {loading ? <Spinner /> : children}
    </button>
  );
}

export function Table({ headers, children }: { headers: string[]; children: ReactNode }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-sm">
        <thead className="border-b border-line text-xs uppercase tracking-wide text-mute">
          <tr>{headers.map((header) => <th key={header} className="px-3 py-2 font-medium">{header}</th>)}</tr>
        </thead>
        <tbody>{children}</tbody>
      </table>
    </div>
  );
}
