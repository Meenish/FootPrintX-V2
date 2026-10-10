// FootprintX API client for the extension. Every failure is classified so
// callers can show an honest state: an error is never treated as "clean".

export const API_ERRORS = Object.freeze({
  OFFLINE: 'OFFLINE',
  TIMEOUT: 'TIMEOUT',
  UNAUTHENTICATED: 'UNAUTHENTICATED',
  PREMIUM_REQUIRED: 'PREMIUM_REQUIRED',
  PREMIUM_EXPIRED: 'PREMIUM_EXPIRED',
  RATE_LIMITED: 'RATE_LIMITED',
  SERVER_ERROR: 'SERVER_ERROR',
  BAD_REQUEST: 'BAD_REQUEST',
  BAD_RESPONSE: 'BAD_RESPONSE',
});

export function createApi({ baseUrl, getToken, fetchImpl = (...a) => globalThis.fetch(...a), timeoutMs = 6000 }) {
  async function request(method, path, body, { auth = true } = {}) {
    const headers = { accept: 'application/json' };
    if (body !== undefined) headers['content-type'] = 'application/json';
    if (auth) {
      const token = await getToken();
      if (!token) return { ok: false, status: 0, errorCode: API_ERRORS.UNAUTHENTICATED };
      headers.authorization = `Bearer ${token}`;
    }
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeoutMs);
    let res;
    try {
      // credentials: 'omit' — the extension never sends or receives cookies.
      res = await fetchImpl(`${baseUrl}${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), signal: ctrl.signal, credentials: 'omit', redirect: 'error', cache: 'no-store' });
    } catch (err) {
      clearTimeout(timer);
      return { ok: false, status: 0, errorCode: err?.name === 'AbortError' ? API_ERRORS.TIMEOUT : API_ERRORS.OFFLINE };
    }
    clearTimeout(timer);
    let data = null;
    if (res.status !== 204) {
      try {
        data = await res.json();
      } catch {
        if (res.ok) return { ok: false, status: res.status, errorCode: API_ERRORS.BAD_RESPONSE };
      }
    }
    if (res.ok) return { ok: true, status: res.status, data };
    const code = data?.error?.code;
    let errorCode = API_ERRORS.SERVER_ERROR;
    if (res.status === 401) errorCode = API_ERRORS.UNAUTHENTICATED;
    else if (res.status === 402) errorCode = code === 'PREMIUM_EXPIRED' ? API_ERRORS.PREMIUM_EXPIRED : API_ERRORS.PREMIUM_REQUIRED;
    else if (res.status === 429) errorCode = API_ERRORS.RATE_LIMITED;
    else if (res.status >= 400 && res.status < 500) errorCode = API_ERRORS.BAD_REQUEST;
    return { ok: false, status: res.status, errorCode, serverCode: code || null, message: data?.error?.message || null };
  }

  return {
    awareness: (domain) => request('POST', '/api/extension/account-awareness', { domain }),
    status: () => request('GET', '/api/extension/status'),
    link: (code, label) => request('POST', '/api/extension/link', { code, label }, { auth: false }),
    unlink: () => request('POST', '/api/extension/unlink', {}),
    lookup: (prefixes) => request('POST', '/api/extension/lookup', { prefixes }),
    manualCheck: (domain) => request('POST', '/api/reputation/check', { domain }),
    setSync: (syncEnabled) => request('PUT', '/api/extension/settings', { syncEnabled }),
    sendEvents: (events) => request('POST', '/api/extension/events', { events }),
    reportFalsePositive: (domain, reportedStatus, note) => request('POST', '/api/reputation/false-positive', { domain, reportedStatus, note }),
  };
}
