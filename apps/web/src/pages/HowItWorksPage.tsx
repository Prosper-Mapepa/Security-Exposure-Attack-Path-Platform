import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';

const signals = [
  { scanner: 'GITLEAKS', title: 'Live cloud token in the billing repository', severity: 'CRITICAL', score: 94, phase: 'Secret masked before it is stored' },
  { scanner: 'SEMGREP', title: 'SQL query built from request input', severity: 'HIGH', score: 81, phase: 'Finding normalized and deduplicated' },
  { scanner: 'TRIVY', title: 'Vulnerable base image on the public API', severity: 'HIGH', score: 76, phase: 'Scored with exposure and data sensitivity' },
  { scanner: 'ZAP', title: 'Billing endpoint accepts unauthenticated calls', severity: 'MEDIUM', score: 64, phase: 'Path traced to the customer database' },
];

const severityClass: Record<string, string> = {
  CRITICAL: 'bg-rose-600 text-white',
  HIGH: 'bg-orange-500 text-white',
  MEDIUM: 'bg-amber-400 text-slate-950',
};

const steps = [
  {
    number: '01',
    title: 'Open one organization',
    body: 'Registration creates a tenant and makes you its security admin. Assets, findings, paths, and audit events stay inside that organization.',
  },
  {
    number: '02',
    title: 'Inventory what the entry can reach',
    body: 'Add applications, APIs, repositories, cloud resources, containers, identities, and Kubernetes objects. Mark what is public, privileged, or holding restricted data.',
  },
  {
    number: '03',
    title: 'Queue the scan',
    body: 'The browser accepts the job and returns. The worker runs the scanner. A missing tool fails the job instead of inventing a finding.',
  },
  {
    number: '04',
    title: 'Keep one finding and show the score',
    body: 'Duplicates collapse into one vulnerability. The 0–100 score weighs the factors below, and the finding page lists why each one counted.',
  },
  {
    number: '05',
    title: 'Walk only stored relationships',
    body: 'The graph starts at the internet or a public asset, crosses an open vulnerability, and follows access, role, authentication, connection, or dependency edges that were stored.',
  },
  {
    number: '06',
    title: 'Close it only after a second scan',
    body: 'Assign remediation and queue a validation scan. Resolved is set when that later scan no longer reports the finding. The audit record is append-only.',
  },
];

const scanners = [
  { name: 'SEMGREP', target: 'Repository or path' },
  { name: 'TRIVY', target: 'Image or filesystem' },
  { name: 'GITLEAKS', target: 'Secret type, value discarded' },
  { name: 'ZAP', target: 'URL, through the ZAP API' },
];

const factors = ['Technical severity', 'Exposure', 'Authentication', 'Privilege', 'Data sensitivity', 'Attack path'];

export function HowItWorksPage() {
  const [index, setIndex] = useState(0);
  const [reduced, setReduced] = useState(false);
  const signal = signals[index];

  useEffect(() => {
    const media = window.matchMedia('(prefers-reduced-motion: reduce)');
    const apply = () => setReduced(media.matches);
    apply();
    media.addEventListener('change', apply);
    return () => media.removeEventListener('change', apply);
  }, []);

  useEffect(() => {
    if (reduced) return;
    const timer = window.setInterval(() => setIndex((current) => (current + 1) % signals.length), 3800);
    return () => window.clearInterval(timer);
  }, [reduced]);

  return (
    <div className="min-h-screen bg-ink text-slate-900 dark:text-slate-100">
      <header className="sticky top-0 z-20 border-b border-line bg-panel/95 backdrop-blur-sm">
        <div className="mx-auto flex h-14 max-w-[1400px] items-center justify-between px-4 md:px-8">
          <Link to="/" className="font-mono text-xs tracking-[0.22em] text-accent">SEAP</Link>
          <nav className="flex items-center gap-2">
            <Link to="/how-it-works" aria-current="page" className="inline-flex min-h-9 items-center rounded-md px-3 text-sm font-medium text-accent">How it works</Link>
            <Link to="/login" className="inline-flex min-h-9 items-center rounded-md px-3 text-sm text-mute hover:text-slate-900 dark:hover:text-slate-100">Sign in</Link>
            <Link to="/register" className="inline-flex min-h-9 items-center rounded-md bg-accent px-3 text-sm font-medium text-white hover:bg-accent/90">Create organization</Link>
          </nav>
        </div>
      </header>

      <main className="mx-auto grid max-w-[1400px] gap-8 px-4 py-8 md:grid-cols-[minmax(0,0.86fr)_minmax(0,1.14fr)] md:items-start md:px-8 md:py-10">
        <div className="order-1 md:col-start-1 md:row-start-1">
          <p className="font-mono text-xs uppercase tracking-[0.22em] text-accent">How it works</p>
          <h1 className="mt-3 max-w-xl text-3xl font-semibold leading-tight tracking-tight md:text-4xl">From a public entry to a fix you can prove.</h1>
          <p className="mt-3 max-w-xl text-sm leading-relaxed text-mute md:text-base">
            Inventory the asset, run the scanner off the request, score the finding with the business context you stored, and follow the relationships an attacker would walk.
          </p>
        </div>

        <section className="seap-stage order-2 flex min-h-[420px] flex-col overflow-hidden rounded-lg border border-line bg-panel md:sticky md:top-20 md:order-none md:col-start-2 md:row-span-2 md:row-start-1 md:h-[calc(100dvh-6.5rem)] md:min-h-0" aria-label="Animated attack path">
          <div className="flex shrink-0 items-center justify-between gap-3 border-b border-line px-4 py-3">
            <p className="shrink-0 text-sm font-medium">Exposure graph</p>
            <p key={signal.phase} className="seap-rise min-w-0 truncate text-right font-mono text-[11px] uppercase tracking-wide text-accent">{signal.phase}</p>
          </div>
          <svg viewBox="0 0 640 360" preserveAspectRatio="xMidYMid meet" className="h-full min-h-[280px] w-full flex-1 text-slate-900 dark:text-slate-100" role="img" aria-label="Internet connects to a public API, then a service account, then a customer database.">
            <path id="how-route" d="M128 180 C 180 180, 190 94, 236 94 S 340 94, 372 180 S 470 266, 508 266" className="seap-route" fill="none" />
            {!reduced && (
              <circle r="5" className="fill-accent">
                <animateMotion dur="4.8s" repeatCount="indefinite">
                  <mpath href="#how-route" />
                </animateMotion>
              </circle>
            )}
            <GraphNode x={88} y={180} label="Internet" detail="PUBLIC" live />
            <GraphNode x={236} y={94} label="Billing API" detail="EXPOSED" />
            <GraphNode x={372} y={180} label="Service account" detail="PRIVILEGED" />
            <GraphNode x={508} y={266} label="Customer DB" detail="RESTRICTED" sink />
          </svg>
          <div className="flex shrink-0 items-center gap-3 border-t border-line px-4 py-3">
            <p className="text-xs uppercase tracking-wide text-mute">Signal</p>
            <p key={signal.scanner} className="seap-rise min-w-0 flex-1 truncate text-sm">
              <span className="font-mono text-xs text-accent">{signal.scanner}</span>
              <span className="mx-2 text-mute">·</span>
              {signal.title}
            </p>
            <span className={`shrink-0 rounded px-2 py-0.5 text-xs font-semibold tracking-wide ${severityClass[signal.severity]}`}>{signal.severity}</span>
            <span className="shrink-0 font-mono text-sm">Risk {signal.score}</span>
          </div>
        </section>

        <div className="order-3 md:col-start-1 md:row-start-2">
          <ol className="space-y-0">
            {steps.map((step) => (
              <li key={step.number} className="relative border-l border-line py-4 pl-5">
                <span className="absolute -left-[5px] top-6 h-2.5 w-2.5 rounded-full bg-accent" aria-hidden="true" />
                <p className="font-mono text-xs text-accent">{step.number}</p>
                <h2 className="mt-1 text-base font-semibold tracking-tight">{step.title}</h2>
                <p className="mt-1.5 max-w-xl text-sm leading-relaxed text-mute">{step.body}</p>
                {step.number === '03' && (
                  <ul className="mt-3 space-y-2">
                    {scanners.map((scanner) => (
                      <li key={scanner.name} className="flex items-center justify-between gap-3 rounded-md border border-line bg-panel px-3 py-2">
                        <span className="font-mono text-xs text-accent">{scanner.name}</span>
                        <span className="text-xs text-mute">{scanner.target}</span>
                      </li>
                    ))}
                  </ul>
                )}
                {step.number === '04' && (
                  <ul className="mt-3 flex flex-wrap gap-2">
                    {factors.map((factor) => (
                      <li key={factor} className="rounded-md border border-line bg-panel px-2.5 py-1 text-xs text-mute">{factor}</li>
                    ))}
                  </ul>
                )}
              </li>
            ))}
          </ol>

          <section className="mt-6 rounded-lg border border-line bg-panel p-5">
            <h2 className="text-base font-semibold tracking-tight">Start with an empty organization</h2>
            <p className="mt-2 text-sm text-mute">The dashboard stays empty until you add an asset and queue a scan. Seed data does not insert findings.</p>
            <div className="mt-4 flex flex-wrap gap-3">
              <Link to="/register" className="inline-flex min-h-10 items-center rounded-md bg-accent px-4 text-sm font-medium text-white hover:bg-accent/90">Create organization</Link>
              <Link to="/login" className="inline-flex min-h-10 items-center rounded-md border border-line px-4 text-sm font-medium hover:bg-ink">Sign in</Link>
            </div>
          </section>
        </div>
      </main>
    </div>
  );
}

function GraphNode({ x, y, label, detail, live, sink }: { x: number; y: number; label: string; detail: string; live?: boolean; sink?: boolean }) {
  return (
    <g transform={`translate(${x} ${y})`}>
      <circle r={live || sink ? 16 : 13} className={sink ? 'seap-sink fill-panel stroke-accent' : 'fill-panel stroke-line'} strokeWidth="1.5" />
      {live && <circle r="16" className="seap-entry fill-none stroke-accent" strokeWidth="1.5" />}
      <text y="-28" textAnchor="middle" className="fill-current text-[14px] font-medium">{label}</text>
      <text y="4" textAnchor="middle" className="fill-accent font-mono text-[9px] tracking-wider">{detail}</text>
    </g>
  );
}
