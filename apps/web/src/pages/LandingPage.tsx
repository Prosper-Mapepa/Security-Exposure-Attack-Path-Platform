import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';

const signals = [
  { scanner: 'GITLEAKS', title: 'Live cloud token in the billing repository', severity: 'CRITICAL', score: 94, phase: 'Secret masked before it is stored' },
  { scanner: 'SEMGREP', title: 'SQL query built from request input', severity: 'HIGH', score: 81, phase: 'Finding normalized and deduplicated' },
  { scanner: 'TRIVY', title: 'Vulnerable base image on the public API', severity: 'HIGH', score: 76, phase: 'Scored with exposure and data sensitivity' },
  { scanner: 'ZAP', title: 'Billing endpoint accepts unauthenticated calls', severity: 'MEDIUM', score: 64, phase: 'Path traced to the customer database' },
];

const steps = [
  { title: 'Inventory', body: 'Applications, APIs, repositories, cloud resources, and identities sit in one tenant.' },
  { title: 'Scan off the request', body: 'Semgrep, Trivy, Gitleaks, and ZAP run in a worker queue, not inside the browser call.' },
  { title: 'Trace the path', body: 'Stored relationships show how a public entry reaches a sensitive system.' },
  { title: 'Prove the fix', body: 'A finding is resolved only after a second scan confirms it is gone.' },
];

const severityClass: Record<string, string> = {
  CRITICAL: 'bg-rose-600 text-white',
  HIGH: 'bg-orange-500 text-white',
  MEDIUM: 'bg-amber-400 text-slate-950',
};

export function LandingPage() {
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
            <Link to="/how-it-works" className="inline-flex min-h-9 items-center rounded-md px-3 text-sm text-mute hover:text-slate-900 dark:hover:text-slate-100">How it works</Link>
            <Link to="/login" className="inline-flex min-h-9 items-center rounded-md px-3 text-sm text-mute hover:text-slate-900 dark:hover:text-slate-100">Sign in</Link>
            <Link to="/register" className="inline-flex min-h-9 items-center rounded-md bg-accent px-3 text-sm font-medium text-white hover:bg-accent/90">Create organization</Link>
          </nav>
        </div>
      </header>

      <main className="mx-auto max-w-[1400px] px-4 py-12 md:px-8 md:py-16">
        <div className="grid items-center gap-10 lg:grid-cols-[minmax(0,0.92fr)_minmax(0,1.08fr)]">
          <div>
            <p className="font-mono text-xs uppercase tracking-[0.22em] text-accent">Security exposure platform</p>
            <h1 className="mt-3 max-w-xl text-4xl font-semibold leading-tight tracking-tight md:text-5xl">See the path from a public entry to the data it can reach.</h1>
            <p className="mt-4 max-w-xl text-base text-mute">
              Inventory the asset, run the scanner, score the finding with business context, and follow the relationships an attacker would walk.
            </p>
            <div className="mt-6 flex flex-wrap gap-3">
              <Link to="/register" className="inline-flex min-h-10 items-center rounded-md bg-accent px-4 text-sm font-medium text-white hover:bg-accent/90">Create organization</Link>
              <Link to="/login" className="inline-flex min-h-10 items-center rounded-md border border-line bg-panel px-4 text-sm font-medium hover:bg-ink">Sign in</Link>
              <Link to="/how-it-works" className="inline-flex min-h-10 items-center rounded-md px-4 text-sm font-medium text-mute hover:text-slate-900 dark:hover:text-slate-100">How it works</Link>
            </div>
          </div>

          <section className="seap-stage relative overflow-hidden rounded-lg border border-line bg-panel" aria-label="Animated attack path">
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-line px-4 py-3">
              <p className="text-sm font-medium">Exposure graph</p>
              <p key={signal.phase} className="seap-rise font-mono text-[11px] uppercase tracking-wide text-accent">{signal.phase}</p>
            </div>
            <div className="grid gap-0 lg:grid-cols-[minmax(0,1fr)_220px]">
              <svg viewBox="0 0 560 300" className="h-auto w-full text-slate-900 dark:text-slate-100" role="img" aria-label="Internet connects to a public API, then a service account, then a customer database.">
                <path id="seap-route" d="M88 150 C 140 150, 150 64, 196 64 S 300 64, 332 150 S 430 236, 468 236" className="seap-route" fill="none" />
                {!reduced && (
                  <circle r="5" className="fill-accent">
                    <animateMotion dur="4.8s" repeatCount="indefinite">
                      <mpath href="#seap-route" />
                    </animateMotion>
                  </circle>
                )}
                <GraphNode x={48} y={150} label="Internet" detail="PUBLIC" live />
                <GraphNode x={196} y={64} label="Billing API" detail="EXPOSED" />
                <GraphNode x={332} y={150} label="Service account" detail="PRIVILEGED" />
                <GraphNode x={468} y={236} label="Customer DB" detail="RESTRICTED" sink />
              </svg>
              <div className="border-t border-line p-4 lg:border-l lg:border-t-0">
                <p className="text-xs uppercase tracking-wide text-mute">Latest signal</p>
                <div key={signal.scanner} className="seap-rise mt-3">
                  <p className="font-mono text-xs text-accent">{signal.scanner}</p>
                  <p className="mt-2 text-sm font-medium leading-snug">{signal.title}</p>
                  <div className="mt-3 flex items-center justify-between gap-2">
                    <span className={`rounded px-2 py-0.5 text-xs font-semibold tracking-wide ${severityClass[signal.severity]}`}>{signal.severity}</span>
                    <span className="font-mono text-sm">Risk {signal.score}</span>
                  </div>
                </div>
                <div className="mt-4 flex gap-1" aria-hidden="true">
                  {signals.map((item, itemIndex) => (
                    <span key={item.scanner} className={`h-1 flex-1 rounded-full ${itemIndex === index ? 'bg-accent' : 'bg-line'}`} />
                  ))}
                </div>
              </div>
            </div>
          </section>
        </div>

        <ol className="mt-14 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {steps.map((step, stepIndex) => (
            <li key={step.title} className="rounded-lg border border-line bg-panel p-4">
              <p className="font-mono text-xs text-accent">0{stepIndex + 1}</p>
              <h2 className="mt-2 text-base font-semibold">{step.title}</h2>
              <p className="mt-2 text-sm text-mute">{step.body}</p>
            </li>
          ))}
        </ol>
      </main>
    </div>
  );
}

function GraphNode({ x, y, label, detail, live, sink }: { x: number; y: number; label: string; detail: string; live?: boolean; sink?: boolean }) {
  return (
    <g transform={`translate(${x} ${y})`}>
      <circle r={live || sink ? 16 : 13} className={sink ? 'seap-sink fill-panel stroke-accent' : 'fill-panel stroke-line'} strokeWidth="1.5" />
      {live && <circle r="16" className="seap-entry fill-none stroke-accent" strokeWidth="1.5" />}
      <text y="-28" textAnchor="middle" className="fill-current text-[13px] font-medium">{label}</text>
      <text y="4" textAnchor="middle" className="fill-accent font-mono text-[9px] tracking-wider">{detail}</text>
    </g>
  );
}
