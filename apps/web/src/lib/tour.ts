export type TourPlacement = 'right' | 'left' | 'bottom' | 'top' | 'center';

export interface TourStep {
  id: string;
  title: string;
  body: string;
  route: string;
  target?: string;
  placement?: TourPlacement;
}

export const TOUR_STORAGE_KEY = 'seap_tour_completed';

export const tourSteps: TourStep[] = [
  {
    id: 'welcome',
    title: 'Welcome to SEAP',
    body: 'This short tour walks the full loop: inventory what you have, scan it, see exposure and attack paths, then assign remediation and prove the fix.',
    route: '/dashboard',
    target: '[data-tour="brand"]',
    placement: 'bottom',
  },
  {
    id: 'dashboard',
    title: 'Security posture',
    body: 'The dashboard summarizes open risk, internet-facing assets, attack paths, overdue remediation, and mean time to remediate from findings you close.',
    route: '/dashboard',
    target: '[data-tour="nav-dashboard"]',
    placement: 'right',
  },
  {
    id: 'assets',
    title: 'Inventory assets',
    body: 'Add applications, APIs, repositories, cloud resources, containers, identities, and databases. Mark exposure, criticality, and owners so risk and paths stay accurate.',
    route: '/assets',
    target: '[data-tour="nav-assets"]',
    placement: 'right',
  },
  {
    id: 'scans',
    title: 'Run scanners',
    body: 'Queue Semgrep, Trivy, Gitleaks, or ZAP against an asset. The worker runs the job; a missing tool fails the scan instead of inventing findings.',
    route: '/scans',
    target: '[data-tour="nav-scans"]',
    placement: 'right',
  },
  {
    id: 'findings',
    title: 'Triage findings',
    body: 'Open vulnerabilities are grouped by scan. Open a finding for evidence, risk factors, attack paths, assignment, validation history, and audit.',
    route: '/findings',
    target: '[data-tour="nav-findings"]',
    placement: 'right',
  },
  {
    id: 'attack-paths',
    title: 'Attack paths',
    body: 'Paths start at the internet or a public asset, cross an open vulnerability, and follow stored relationships to a sensitive sink such as a database or privileged role.',
    route: '/attack-paths',
    target: '[data-tour="nav-attack-paths"]',
    placement: 'right',
  },
  {
    id: 'developer',
    title: 'My findings',
    body: 'Engineers see findings they own or remediations assigned to them, grouped by project, with guidance to fix and validate.',
    route: '/developer',
    target: '[data-tour="nav-developer"]',
    placement: 'right',
  },
  {
    id: 'incidents',
    title: 'Incidents',
    body: 'Open an incident to track an active event. Create can link the top attack path, related findings, and recent security events.',
    route: '/incidents',
    target: '[data-tour="nav-incidents"]',
    placement: 'right',
  },
  {
    id: 'remediations',
    title: 'Remediation',
    body: 'Assigned work lives here. Validate fix re-runs the original scanner; the finding resolves only when that scan no longer reports it.',
    route: '/remediations',
    target: '[data-tour="nav-remediations"]',
    placement: 'right',
  },
  {
    id: 'events',
    title: 'Security events',
    body: 'Ingest analyst or SIEM events, attach them to assets, and link them into incidents for response context.',
    route: '/events',
    target: '[data-tour="nav-events"]',
    placement: 'right',
  },
  {
    id: 'reports',
    title: 'Reports',
    body: 'Export posture as JSON, CSV, or PDF generated from live database data. Secret values stay masked.',
    route: '/reports',
    target: '[data-tour="nav-reports"]',
    placement: 'right',
  },
  {
    id: 'audit',
    title: 'Audit log',
    body: 'Authentication, scans, assignments, and role changes are append-only. Each row shows who performed the action.',
    route: '/audit',
    target: '[data-tour="nav-audit"]',
    placement: 'right',
  },
  {
    id: 'settings',
    title: 'Organization settings',
    body: 'Manage roles and permissions, provision members, and connect asset relationships the attack-path graph walks.',
    route: '/settings',
    target: '[data-tour="nav-settings"]',
    placement: 'right',
  },
  {
    id: 'finish',
    title: 'You are ready',
    body: 'Start with Assets and a scan, then review Findings and Attack paths. Restart this tour anytime from the header.',
    route: '/dashboard',
    target: '[data-tour="tour-start"]',
    placement: 'bottom',
  },
];

export function isTourCompleted() {
  try {
    return localStorage.getItem(TOUR_STORAGE_KEY) === '1';
  } catch {
    return false;
  }
}

export function markTourCompleted() {
  try {
    localStorage.setItem(TOUR_STORAGE_KEY, '1');
  } catch {
    /* ignore quota / private mode */
  }
}

export function clearTourCompleted() {
  try {
    localStorage.removeItem(TOUR_STORAGE_KEY);
  } catch {
    /* ignore */
  }
}
