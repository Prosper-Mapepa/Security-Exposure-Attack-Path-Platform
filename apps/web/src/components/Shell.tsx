import { Bell, Moon, Sun } from 'lucide-react';
import { useEffect, useState } from 'react';
import { NavLink, Outlet, useNavigate } from 'react-router-dom';
import { api } from '../lib/api';
import { useAuth } from '../lib/auth';
import { Button, IconButton, Spinner } from './ui';

const groups = [
  { label: 'Overview', links: [['/dashboard', 'Dashboard']] },
  { label: 'Inventory', links: [['/assets', 'Assets'], ['/scans', 'Scans']] },
  { label: 'Exposure', links: [['/findings', 'Findings'], ['/attack-paths', 'Attack paths'], ['/developer', 'My findings']] },
  { label: 'Response', links: [['/incidents', 'Incidents'], ['/remediations', 'Remediation'], ['/events', 'Events']] },
  { label: 'Governance', links: [['/reports', 'Reports'], ['/audit', 'Audit'], ['/settings', 'Settings']] },
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
      setUser(null);
      navigate('/login');
    } finally {
      setSigningOut(false);
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
      <header className="sticky top-0 z-20 flex h-14 items-center justify-between border-b border-line bg-panel px-4">
        <div className="flex min-w-0 items-center gap-3">
          <span className="font-mono text-xs tracking-[0.22em] text-accent">SEAP</span>
          <span className="hidden truncate text-sm font-medium sm:inline">Exposure & attack paths</span>
        </div>
        <div className="flex items-center gap-3">
          <div className="hidden text-right sm:block">
            <p className="text-sm font-medium leading-tight">{user?.name}</p>
            <p className="font-mono text-[11px] uppercase tracking-wide text-mute">{user?.role}</p>
          </div>
          <div className="relative">
            <IconButton className="relative" aria-label="Notifications" onClick={() => setOpen((value) => !value)}>
              <Bell size={16} />
              {unread > 0 && <span className="absolute right-1.5 top-1.5 h-2 w-2 rounded-full bg-rose-500" />}
            </IconButton>
            {open && (
              <div className="absolute right-0 z-30 mt-2 w-80 rounded-lg border border-line bg-panel p-2">
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
          <IconButton aria-label="Toggle color theme" onClick={() => setDark((value) => !value)}>
            {dark ? <Sun size={16} /> : <Moon size={16} />}
          </IconButton>
          <Button variant="secondary" loading={signingOut} onClick={() => void logout()}>Sign out</Button>
        </div>
      </header>
      <div className="md:grid md:grid-cols-[232px_minmax(0,1fr)]">
        <aside className="border-b border-line bg-panel md:sticky md:top-14 md:h-[calc(100vh-3.5rem)] md:overflow-y-auto md:border-b-0 md:border-r">
          <nav className="flex gap-1 overflow-x-auto px-3 py-2 md:hidden" aria-label="Sections">
            {links.map(([to, label]) => (
              <NavLink key={to} to={to} className={({ isActive }) => navClass(isActive)}>
                {label}
              </NavLink>
            ))}
          </nav>
          <nav className="hidden px-3 py-4 md:block" aria-label="Sections">
            {groups.map((group) => (
              <div key={group.label} className="mb-5 last:mb-0">
                <p className="mb-1 px-3 text-[10px] font-semibold uppercase tracking-[0.16em] text-mute">{group.label}</p>
                {group.links.map(([to, label]) => (
                  <NavLink key={to} to={to} className={({ isActive }) => navClass(isActive)}>
                    {label}
                  </NavLink>
                ))}
              </div>
            ))}
          </nav>
        </aside>
        <main className="mx-auto w-full max-w-6xl px-4 py-6 md:px-8">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
