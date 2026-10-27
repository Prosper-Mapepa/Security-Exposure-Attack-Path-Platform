import { Bell, Compass, Moon, Sun } from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';
import { Link, NavLink, Outlet, useNavigate } from 'react-router-dom';
import { api, clearCsrf } from '../lib/api';
import { useAuth } from '../lib/auth';
import { clearTourCompleted } from '../lib/tour';
import { SeapMark, SeapWordmark } from './SeapLogo';
import { TourGuide, useAutoStartTour } from './TourGuide';
import { Button, IconButton, Spinner, Tooltip } from './ui';

type NavLinkItem = [to: string, label: string, tourId: string, tip: string];

const groups: Array<{ label: string; links: NavLinkItem[] }> = [
  {
    label: 'Overview',
    links: [['/dashboard', 'Dashboard', 'nav-dashboard', 'Open risk, exposure, and remediation pace for the organization.']],
  },
  {
    label: 'Inventory',
    links: [
      ['/assets', 'Assets', 'nav-assets', 'Applications, APIs, repos, cloud resources, and other things you can scan.'],
      ['/scans', 'Scans', 'nav-scans', 'Queue Semgrep, Trivy, Gitleaks, or ZAP. The worker runs jobs outside the request.'],
    ],
  },
  {
    label: 'Exposure',
    links: [
      ['/findings', 'Findings', 'nav-findings', 'Normalized vulnerabilities grouped by scan, with risk and evidence.'],
      ['/attack-paths', 'Attack paths', 'nav-attack-paths', 'Routes from the internet through a vulnerability to a sensitive sink.'],
      ['/developer', 'My findings', 'nav-developer', 'Findings you own or remediations assigned to you.'],
    ],
  },
  {
    label: 'Response',
    links: [
      ['/incidents', 'Incidents', 'nav-incidents', 'Track an active security event and the assets tied to it.'],
      ['/remediations', 'Remediation', 'nav-remediations', 'Assigned fix work. Validate with a follow-up scan.'],
      ['/events', 'Events', 'nav-events', 'Normalized analyst or SIEM events you can link into incidents.'],
    ],
  },
  {
    label: 'Governance',
    links: [
      ['/reports', 'Reports', 'nav-reports', 'Export posture as JSON, CSV, or PDF. Secrets stay masked.'],
      ['/audit', 'Audit', 'nav-audit', 'Append-only history of who changed authentication, scans, and workflow.'],
      ['/settings', 'Settings', 'nav-settings', 'Roles, members, and asset relationships for the attack-path graph.'],
    ],
  },
];

const links = groups.flatMap((group) => group.links);

function navClass(isActive: boolean) {
  return `block whitespace-nowrap rounded-md px-3 py-2 text-sm ${isActive ? 'bg-accent/15 font-medium text-accent' : 'text-mute hover:bg-ink hover:text-slate-900 dark:hover:text-slate-100'}`;
}

export function Shell() {
  const { user, setUser } = useAuth();
  const navigate = useNavigate();
  const [dark, setDark] = useState(localStorage.getItem('theme') !== 'light');
  const [notes, setNotes] = useState<Array<{ id: string; title: string; readAt: string | null }>>([]);
  const [open, setOpen] = useState(false);
  const [signingOut, setSigningOut] = useState(false);
  const [readingId, setReadingId] = useState<string | null>(null);
  const [tourOpen, setTourOpen] = useState(false);
  const startTour = useCallback(() => {
    clearTourCompleted();
    setTourOpen(true);
  }, []);
  useAutoStartTour(useCallback(() => setTourOpen(true), []));

  useEffect(() => {
    function onRestart() {
      startTour();
    }
    window.addEventListener('seap:start-tour', onRestart);
    return () => window.removeEventListener('seap:start-tour', onRestart);
  }, [startTour]);

  useEffect(() => {
    document.documentElement.classList.toggle('dark', dark);
    localStorage.setItem('theme', dark ? 'dark' : 'light');
  }, [dark]);

  useEffect(() => {
    void api.get<Array<{ id: string; title: string; readAt: string | null }>>('/api/notifications').then(setNotes).catch(() => setNotes([]));
  }, []);

  async function logout() {
    setSigningOut(true);
    try {
      await api.post('/api/auth/logout');
    } catch {
      // Clear the local session even if the revoke call fails (e.g. expired CSRF).
    } finally {
      clearCsrf();
      setUser(null);
      setSigningOut(false);
      navigate('/login');
    }
  }

  async function markRead(id: string) {
    setReadingId(id);
    try {
      await api.post(`/api/notifications/${id}/read`);
      setNotes((items) => items.map((item) => (item.id === id ? { ...item, readAt: new Date().toISOString() } : item)));
    } finally {
      setReadingId(null);
    }
  }

  const unread = notes.filter((note) => !note.readAt).length;

  return (
    <div className="min-h-screen bg-ink text-slate-900 dark:text-slate-100">
      <header className="sticky top-0 z-20 border-b border-line bg-panel/95 backdrop-blur supports-[backdrop-filter]:bg-panel/80">
        <div className="flex h-[4.5rem] items-center justify-between gap-4 px-4 md:px-5">
          <Link
            to="/dashboard"
            className="group flex min-w-0 items-center gap-3 no-underline transition-opacity hover:opacity-95"
            data-tour="brand"
            aria-label="SEAP home"
          >
            <span className="relative shrink-0 transition-transform duration-300 group-hover:-translate-y-px">
              <SeapMark className="h-11 w-11 drop-shadow-[0_8px_18px_rgba(15,107,99,0.35)]" />
            </span>
            <SeapWordmark />
          </Link>

          <div className="flex shrink-0 items-center gap-2 sm:gap-3">
            <Tooltip content={user ? `${user.email} · ${user.role}` : 'Signed-in account'} placement="bottom">
              <div className="hidden max-w-[11rem] truncate rounded-md border border-line bg-ink/60 px-3 py-1.5 text-left md:block">
                <p className="truncate text-sm font-medium leading-tight">{user?.name}</p>
                <p className="truncate font-mono text-[10px] uppercase tracking-[0.12em] text-mute">{user?.role}</p>
              </div>
            </Tooltip>

            <div className="hidden h-8 w-px bg-line sm:block" aria-hidden="true" />

            <div className="flex items-center gap-1.5">
              <Tooltip content="Walk through inventory, exposure, response, and governance" placement="bottom">
                <Button data-tour="tour-start" variant="secondary" className="px-2.5 sm:px-3" aria-label="Start platform tour" onClick={startTour}>
                  <Compass size={16} aria-hidden="true" />
                  <span className="hidden sm:inline">Tour</span>
                </Button>
              </Tooltip>
              <div className="relative">
                <Tooltip content={unread > 0 ? `${unread} unread notification${unread === 1 ? '' : 's'}` : 'Notifications'} placement="bottom">
                  <IconButton className="relative" aria-label="Notifications" onClick={() => setOpen((value) => !value)}>
                    <Bell size={16} />
                    {unread > 0 && <span className="absolute right-1.5 top-1.5 h-2 w-2 rounded-full bg-rose-500" />}
                  </IconButton>
                </Tooltip>
                {open && (
                  <div className="absolute right-0 z-30 mt-2 w-80 rounded-lg border border-line bg-panel p-2 shadow-lg">
                    <p className="px-2 py-1 text-xs font-medium uppercase tracking-wide text-mute">Notifications</p>
                    {notes.length === 0 ? <p className="px-2 py-3 text-sm text-mute">No notifications</p> : notes.slice(0, 6).map((note) => (
                      <button
                        key={note.id}
                        type="button"
                        className="flex w-full items-center gap-2 rounded-md px-2 py-2 text-left text-sm hover:bg-ink disabled:opacity-60"
                        disabled={readingId === note.id}
                        aria-busy={readingId === note.id || undefined}
                        onClick={() => void markRead(note.id)}
                      >
                        {readingId === note.id ? <Spinner /> : <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${note.readAt ? 'bg-line' : 'bg-accent'}`} />}
                        <span className={note.readAt ? 'text-mute' : ''}>{note.title}</span>
                      </button>
                    ))}
                  </div>
                )}
              </div>
              <Tooltip content={dark ? 'Switch to light theme' : 'Switch to dark theme'} placement="bottom">
                <IconButton aria-label="Toggle color theme" onClick={() => setDark((value) => !value)}>
                  {dark ? <Sun size={16} /> : <Moon size={16} />}
                </IconButton>
              </Tooltip>
              <Tooltip content="End this session and return to sign in" placement="bottom">
                <Button variant="secondary" className="px-2.5 sm:px-3" loading={signingOut} onClick={() => void logout()}>
                  <span className="hidden sm:inline">Sign out</span>
                  <span className="sm:hidden">Out</span>
                </Button>
              </Tooltip>
            </div>
          </div>
        </div>
      </header>
      <div className="md:grid md:grid-cols-[232px_minmax(0,1fr)]">
        <aside className="border-b border-line bg-panel md:sticky md:top-[4.5rem] md:h-[calc(100vh-4.5rem)] md:overflow-y-auto md:border-b-0 md:border-r">
          <nav className="flex gap-1 overflow-x-auto px-3 py-2 md:hidden" aria-label="Sections">
            {links.map(([to, label, tourId, tip]) => (
              <Tooltip key={to} content={tip} placement="bottom">
                <NavLink to={to} data-tour={tourId} className={({ isActive }) => navClass(isActive)}>
                  {label}
                </NavLink>
              </Tooltip>
            ))}
          </nav>
          <nav className="hidden px-3 py-4 md:block" aria-label="Sections">
            {groups.map((group) => (
              <div key={group.label} className="mb-5 last:mb-0">
                <p className="mb-1 px-3 text-[10px] font-semibold uppercase tracking-[0.16em] text-mute">{group.label}</p>
                {group.links.map(([to, label, tourId, tip]) => (
                  <Tooltip key={to} content={tip} placement="right" className="block w-full">
                    <NavLink to={to} data-tour={tourId} className={({ isActive }) => navClass(isActive)}>
                      {label}
                    </NavLink>
                  </Tooltip>
                ))}
              </div>
            ))}
          </nav>
        </aside>
        <main className="mx-auto w-full max-w-6xl px-4 py-6 md:px-8">
          <Outlet />
        </main>
      </div>
      <TourGuide open={tourOpen} onClose={() => setTourOpen(false)} />
    </div>
  );
}
