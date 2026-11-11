// One transport for both shells: the Tauri app calls into Rust directly, the web UI posts to the
// server. Everything above this file is identical in both.

const internals = (window as any).__TAURI_INTERNALS__;
export const isApp: boolean = !!internals;

const TOKEN_KEY = 'vulnwatch-token';

export class AuthError extends Error {}

export function getToken(): string {
  try {
    return localStorage.getItem(TOKEN_KEY) ?? '';
  } catch {
    return '';
  }
}

export function setToken(token: string) {
  try {
    if (token) localStorage.setItem(TOKEN_KEY, token);
    else localStorage.removeItem(TOKEN_KEY);
  } catch {
    /* private mode: stays signed in for this page load only */
  }
  memoryToken = token;
}

let memoryToken = getToken();

export async function rpc<T = any>(method: string, params: Record<string, unknown> = {}): Promise<T> {
  if (isApp) {
    try {
      return await internals.invoke('rpc', { method, params });
    } catch (e) {
      throw new Error(typeof e === 'string' ? e : ((e as any)?.message ?? String(e)));
    }
  }
  let res: Response;
  try {
    res = await fetch('/api/rpc', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${memoryToken}` },
      body: JSON.stringify({ method, params }),
    });
  } catch {
    throw new Error('Cannot reach the vulnwatch server.');
  }
  if (res.status === 401) throw new AuthError('unauthorized');
  const body = await res.json().catch(() => null);
  if (!body) throw new Error(`Server error (${res.status}).`);
  if (body.error) throw new Error(body.error);
  return body.result;
}

/** Does this server need a token at all? */
export async function health(): Promise<{ auth: boolean; version: string }> {
  if (isApp) return { auth: false, version: '' };
  const res = await fetch('/api/health');
  return res.json();
}

/** Open a link outside the app (the system browser on Android). */
export function openExternal(url: string) {
  if (isApp) internals.invoke('plugin:opener|open_url', { url }).catch(() => window.open(url, '_blank'));
  else window.open(url, '_blank', 'noopener,noreferrer');
}
