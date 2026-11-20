export const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || '').replace(/\/$/, '');

export async function apiFetch(endpoint, options = {}) {
  const { auth = true, ...fetchOptions } = options;
  const token = auth ? localStorage.getItem('token') : null;
  const headers = new Headers(fetchOptions.headers);
  if (fetchOptions.body && !(fetchOptions.body instanceof FormData)) headers.set('Content-Type', 'application/json');
  if (token) headers.set('Authorization', `Bearer ${token}`);
  const response = await fetch(`${API_BASE_URL}${endpoint}`, {
    ...fetchOptions, headers,
    signal: fetchOptions.signal || AbortSignal.timeout(15000),
  });
  if (!response.ok) {
    if (response.status === 401 && token && localStorage.getItem('token') === token) {
      window.dispatchEvent(new Event('netshield:unauthorized'));
    }
    const body = await response.json().catch(() => ({}));
    const detail = Array.isArray(body.detail) ? body.detail.map(item => item.msg).join('; ') : body.detail;
    const error = new Error(detail || `Request failed (${response.status})`);
    error.status = response.status;
    throw error;
  }
  return response;
}

export const socketURL = dataset => {
  const url = new URL('/ws/traffic/stream', API_BASE_URL || window.location.origin);
  url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:';
  url.searchParams.set('dataset', dataset);
  return url.toString();
};

export const authAPI = {
  register: async payload => (await apiFetch('/api/auth/register', { method: 'POST', body: JSON.stringify(payload), auth: false })).json(),
  login: async payload => (await apiFetch('/api/auth/login', { method: 'POST', body: JSON.stringify(payload), auth: false })).json(),
};
