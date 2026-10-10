// API client. Same-origin requests with the HttpOnly session cookie; the CSRF
// token (readable cookie set by the server) is echoed in X-CSRF-Token on every
// state-changing request. No tokens are ever stored in localStorage.

export class ApiError extends Error {
  constructor(status, code, message, details) {
    super(message);
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

function csrfToken() {
  const m = document.cookie.match(/(?:^|;\s*)(?:__Host-)?fx_csrf=([^;]+)/);
  return m ? decodeURIComponent(m[1]) : null;
}

let onUnauthenticated = () => {};
export const setUnauthenticatedHandler = (fn) => {
  onUnauthenticated = fn;
};

export async function request(method, path, body, { signal } = {}) {
  const headers = { accept: 'application/json' };
  if (body !== undefined) headers['content-type'] = 'application/json';
  if (method !== 'GET') {
    const t = csrfToken();
    if (t) headers['x-csrf-token'] = t;
  }
  let res;
  try {
    res = await fetch(`/api${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), credentials: 'same-origin', signal });
  } catch (err) {
    if (err.name === 'AbortError') throw err;
    throw new ApiError(0, 'NETWORK', 'Can’t reach FootprintX. Check your connection and try again.');
  }
  if (res.status === 204) return null;
  let data = null;
  try {
    data = await res.json();
  } catch {
    if (!res.ok) throw new ApiError(res.status, 'BAD_RESPONSE', 'FootprintX returned an unexpected response. Try again.');
  }
  if (!res.ok) {
    const e = data?.error || {};
    if (res.status === 401 && path !== '/auth/login') onUnauthenticated();
    throw new ApiError(res.status, e.code || 'ERROR', e.message || 'The request failed.', e.details);
  }
  return data;
}

export const api = {
  get: (p, o) => request('GET', p, undefined, o),
  post: (p, b = {}) => request('POST', p, b),
  patch: (p, b = {}) => request('PATCH', p, b),
  put: (p, b = {}) => request('PUT', p, b),
  del: (p, b) => request('DELETE', p, b),
};

/** Downloads a GET endpoint as a file (export, CSV). */
export async function download(path, fallbackName) {
  const res = await fetch(`/api${path}`, { credentials: 'same-origin' });
  if (!res.ok) {
    // Surface the server's own explanation when it sent one, so a failed
    // extension build or a missing package says why rather than "try again".
    const body = await res.json().catch(() => null);
    const err = body?.error;
    throw new ApiError(res.status, err?.code || 'DOWNLOAD_FAILED', err?.message || 'The download could not be prepared.');
  }
  const blob = await res.blob();
  const name = res.headers.get('content-disposition')?.match(/filename="([^"]+)"/)?.[1] || fallbackName;
  const url = URL.createObjectURL(blob);
  const a = Object.assign(document.createElement('a'), { href: url, download: name });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
