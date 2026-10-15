export const ROLES = [
  'PLATFORM_ADMIN',
  'SECURITY_ADMIN',
  'SECURITY_ANALYST',
  'ENGINEER',
  'VIEWER',
] as const;

export type RoleName = (typeof ROLES)[number];

export const PERMISSIONS = [
  'org:read',
  'org:manage',
  'user:read',
  'user:manage',
  'asset:read',
  'asset:write',
  'finding:read',
  'finding:triage',
  'scan:read',
  'scan:run',
  'attackpath:read',
  'attackpath:write',
  'incident:read',
  'incident:write',
  'remediation:read',
  'remediation:write',
  'report:read',
  'report:export',
  'audit:read',
  'event:read',
  'event:write',
  'policy:read',
  'policy:write',
  'notification:read',
  'dashboard:read',
] as const;

export type Permission = (typeof PERMISSIONS)[number];

const ALL = [...PERMISSIONS];

const ANALYST: Permission[] = ALL.filter(
  (permission) => !['user:manage', 'policy:write', 'org:manage'].includes(permission),
);

const ENGINEER: Permission[] = [
  'org:read',
  'asset:read',
  'finding:read',
  'scan:read',
  'attackpath:read',
  'incident:read',
  'remediation:read',
  'remediation:write',
  'report:read',
  'notification:read',
  'dashboard:read',
  'event:read',
];

const VIEWER: Permission[] = [
  'org:read',
  'asset:read',
  'finding:read',
  'scan:read',
  'attackpath:read',
  'incident:read',
  'remediation:read',
  'report:read',
  'notification:read',
  'dashboard:read',
  'event:read',
  'policy:read',
  'user:read',
];

export const ROLE_PERMISSIONS: Record<RoleName, readonly Permission[]> = {
  PLATFORM_ADMIN: ALL,
  SECURITY_ADMIN: ALL,
  SECURITY_ANALYST: ANALYST,
  ENGINEER: ENGINEER,
  VIEWER: VIEWER,
};

export function hasPermission(role: RoleName, permission: Permission): boolean {
  return ROLE_PERMISSIONS[role].includes(permission);
}
