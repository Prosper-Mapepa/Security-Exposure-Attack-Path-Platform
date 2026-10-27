export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
  }
}

let csrfToken = sessionStorage.getItem('seap_csrf') ?? '';

export function setCsrf(token: string) {
  csrfToken = token;
  sessionStorage.setItem('seap_csrf', token);
}

async function request<T>(path: string, init: RequestInit = {}, retry = true): Promise<T> {
  const headers = new Headers(init.headers);
  if (init.body && !(init.body instanceof FormData) && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }
  if (csrfToken) headers.set('x-csrf-token', csrfToken);
  const response = await fetch(path, { ...init, headers, credentials: 'include' });
  if (response.status === 401 && retry && !path.startsWith('/api/auth/')) {
    const refreshed = await fetch('/api/auth/refresh', {
      method: 'POST',
      credentials: 'include',
      headers: csrfToken ? { 'x-csrf-token': csrfToken } : {},
      signal: init.signal,
    });
    if (refreshed.ok) {
      const body = (await refreshed.json()) as { csrfToken?: string };
      if (body.csrfToken) setCsrf(body.csrfToken);
      return request(path, init, false);
    }
  }
  const text = await response.text();
  const payload = text
    ? (JSON.parse(text) as {
        error?: {
          message?: string | string[];
          details?: { formErrors?: string[]; fieldErrors?: Record<string, string[] | undefined> };
        };
        csrfToken?: string;
      })
    : {};
  if (!response.ok) {
    const base = Array.isArray(payload.error?.message) ? payload.error?.message.join(', ') : payload.error?.message;
    const fieldErrors = Object.values(payload.error?.details?.fieldErrors ?? {}).flatMap((messages) => messages ?? []);
    const formErrors = payload.error?.details?.formErrors ?? [];
    const details = [...new Set([...formErrors, ...fieldErrors])].filter(Boolean);
    const message = details.length && (!base || base === 'Validation failed') ? details.join(' ') : base;
    throw new ApiError(message || `Request failed (${response.status})`, response.status);
  }
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
