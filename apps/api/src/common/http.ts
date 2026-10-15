import { createHash, randomBytes } from 'node:crypto';
import type { Response } from 'express';

export function pageWindow(page: number, pageSize: number): { skip: number; take: number } {
  return { skip: (page - 1) * pageSize, take: pageSize };
}

export function cookieBase() {
  return {
    secure: process.env.COOKIE_SECURE === 'true',
    sameSite: 'lax' as const,
    domain: process.env.COOKIE_DOMAIN || undefined,
  };
}

export function setAuthCookies(response: Response, accessToken: string, refreshToken: string, csrfToken: string) {
  const base = cookieBase();
  response.cookie('seap_access', accessToken, {
    ...base,
    httpOnly: true,
    path: '/',
    maxAge: 15 * 60 * 1000,
  });
  response.cookie('seap_refresh', refreshToken, {
    ...base,
    httpOnly: true,
    path: '/api/auth',
    maxAge: Number(process.env.REFRESH_TOKEN_TTL_DAYS ?? 14) * 24 * 60 * 60 * 1000,
  });
  response.cookie('seap_csrf', csrfToken, {
    ...base,
    httpOnly: false,
    path: '/',
    maxAge: Number(process.env.REFRESH_TOKEN_TTL_DAYS ?? 14) * 24 * 60 * 60 * 1000,
  });
}

export function clearAuthCookies(response: Response) {
  const base = cookieBase();
  response.clearCookie('seap_access', { ...base, path: '/' });
  response.clearCookie('seap_refresh', { ...base, path: '/api/auth' });
  response.clearCookie('seap_csrf', { ...base, path: '/' });
}

export function newCsrfToken(): string {
  return randomBytes(32).toString('base64url');
}

export function clientIp(forwarded: string | undefined, socket: string | undefined): string | undefined {
  const candidate = forwarded?.split(',')[0]?.trim() || socket;
  if (!candidate) return undefined;
  return candidate.slice(0, 64);
}

export function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}
