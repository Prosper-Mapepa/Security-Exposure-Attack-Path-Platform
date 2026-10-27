export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
  }
}

function csrfFromCookie(): string {
  if (typeof document === 'undefined') return '';
  const row = document.cookie.split('; ').find((part) => part.startsWith('seap_csrf='));
  if (!row) return '';
  return decodeURIComponent(row.slice('seap_csrf='.length));
}

let csrfToken = sessionStorage.getItem('seap_csrf') ?? csrfFromCookie();

export function setCsrf(token: string) {
  csrfToken = token;
  sessionStorage.setItem('seap_csrf', token);
}

/** Double-submit: header must match the cookie the browser will send. */
function activeCsrf(): string {
  const fromCookie = csrfFromCookie();
  if (fromCookie) {
    if (fromCookie !== csrfToken) setCsrf(fromCookie);
    return fromCookie;
  }
  return csrfToken;
}

function gatewayMessage(status: number) {
  if (status === 502 || status === 503 || status === 504) {
    return 'API is unreachable. Confirm the api service is running and web API_UPSTREAM points at it.';
  }
  return `Request failed (${status})`;
}

function parsePayload(text: string) {
  if (!text) return {};
  try {
    return JSON.parse(text) as {
      error?: {
        message?: string | string[];
        details?: { formErrors?: string[]; fieldErrors?: Record<string, string[] | undefined> };
      };
      csrfToken?: string;
    };
  } catch {
    return {
      error: {
        message: text.trimStart().startsWith('<')
          ? 'API returned an HTML error page instead of JSON. The web proxy cannot reach the api service.'
          : 'API returned a non-JSON response.',
      },
    };
  }
}

async function request<T>(path: string, init: RequestInit = {}, retry = true): Promise<T> {
  const headers = new Headers(init.headers);
  if (init.body && !(init.body instanceof FormData) && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }
  const csrf = activeCsrf();
  if (csrf) headers.set('x-csrf-token', csrf);
  const response = await fetch(path, { ...init, headers, credentials: 'include' });
  if (response.status === 401 && retry && !path.startsWith('/api/auth/')) {
    const refreshed = await fetch('/api/auth/refresh', {
      method: 'POST',
      credentials: 'include',
      headers: csrf ? { 'x-csrf-token': csrf } : {},
      signal: init.signal,
    });
    if (refreshed.ok) {
      const body = parsePayload(await refreshed.text());
      if (body.csrfToken) setCsrf(body.csrfToken);
      return request(path, init, false);
    }
  }
  if (response.status === 403 && retry && path !== '/api/auth/csrf') {
    const message = (await response.clone().text()) || '';
    if (message.includes('CSRF')) {
      await ensureCsrf();
      return request(path, init, false);
    }
  }
  const text = await response.text();
  const payload = parsePayload(text);
  if (!response.ok) {
    const base = Array.isArray(payload.error?.message) ? payload.error?.message.join(', ') : payload.error?.message;
    const fieldErrors = Object.values(payload.error?.details?.fieldErrors ?? {}).flatMap((messages) => messages ?? []);
    const formErrors = payload.error?.details?.formErrors ?? [];
    const details = [...new Set([...formErrors, ...fieldErrors])].filter(Boolean);
    const message = details.length && (!base || base === 'Validation failed') ? details.join(' ') : base;
    throw new ApiError(message || gatewayMessage(response.status), response.status);
  }
  if (payload.csrfToken) setCsrf(payload.csrfToken);
  return payload as T;
}

export const api = {
  get: <T>(path: string, init?: RequestInit) => request<T>(path, init),
  post: <T>(path: string, body?: unknown) =>
    request<T>(path, { method: 'POST', body: body instanceof FormData ? body : JSON.stringify(body ?? {}) }),
  patch: <T>(path: string, body?: unknown) => request<T>(path, { method: 'PATCH', body: JSON.stringify(body ?? {}) }),
  put: <T>(path: string, body?: unknown) => request<T>(path, { method: 'PUT', body: JSON.stringify(body ?? {}) }),
  delete: <T>(path: string) => request<T>(path, { method: 'DELETE' }),
};

export async function ensureCsrf() {
  const result = await api.get<{ csrfToken: string }>('/api/auth/csrf');
  setCsrf(result.csrfToken);
}

export function clearCsrf() {
  csrfToken = '';
  sessionStorage.removeItem('seap_csrf');
}
