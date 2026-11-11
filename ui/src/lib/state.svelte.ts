// App-wide reactive state: route, session, status, toasts.
import { AuthError, getToken, health, isApp, rpc, setToken } from './api';
import type { Settings, Status, Subscription } from './types';

function parseRoute(): string[] {
  const h = location.hash.replace(/^#\/?/, '');
  return h ? h.split('/').map(decodeURIComponent) : [];
}

export const app = $state({
  route: parseRoute(),
  /** 'loading' | 'login' | 'ready' */
  session: 'loading' as 'loading' | 'login' | 'ready',
  status: null as Status | null,
  settings: null as Settings | null,
  subs: [] as Subscription[],
  toasts: [] as { id: number; text: string; kind: 'info' | 'error' }[],
});

window.addEventListener('hashchange', () => {
  app.route = parseRoute();
  window.scrollTo(0, 0);
});

export function go(path: string) {
  location.hash = '#' + path;
}

let toastId = 0;
export function toast(text: string, kind: 'info' | 'error' = 'info') {
  const id = ++toastId;
  app.toasts.push({ id, text, kind });
  setTimeout(() => (app.toasts = app.toasts.filter((t) => t.id !== id)), kind === 'error' ? 7000 : 3500);
}

/** Run an API call; on failure show a toast (or the sign-in screen) and return undefined. */
export async function call<T = any>(method: string, params: Record<string, unknown> = {}): Promise<T | undefined> {
  try {
    return await rpc<T>(method, params);
  } catch (e) {
    if (e instanceof AuthError) app.session = 'login';
    else toast((e as Error).message, 'error');
    return undefined;
  }
}

export function applyTheme(theme: string | undefined) {
  if (theme === 'light' || theme === 'dark') document.documentElement.dataset.theme = theme;
  else delete document.documentElement.dataset.theme;
}

export async function refreshStatus() {
  try {
    const before = app.status?.unread ?? null;
    app.status = await rpc<Status>('status');
    if (before !== null && app.status.unread > before) browserNotify(app.status.unread - before);
  } catch (e) {
    if (e instanceof AuthError) app.session = 'login';
  }
}

export async function refreshSubs() {
  const r = await call<{ subscriptions: Subscription[] }>('subs.list');
  if (r) app.subs = r.subscriptions;
}

export async function loadSettings() {
  const r = await call<{ settings: Settings }>('settings.get');
  if (r) {
    app.settings = r.settings;
    applyTheme(r.settings.theme);
  }
}

/** Web UI only: a desktop notification while the tab is open. (The Android app notifies natively.) */
function browserNotify(count: number) {
  if (isApp || !('Notification' in window) || Notification.permission !== 'granted') return;
  try {
    new Notification('vulnwatch', { body: `${count} new vulnerability alert${count === 1 ? '' : 's'}`, icon: '/icon.svg' });
  } catch {
    /* some mobile browsers only allow this from a service worker */
  }
}

export async function start() {
  // A link printed by the server carries the token: `/#token=...`.
  const m = location.hash.match(/^#token=(.+)$/);
  if (m) {
    setToken(decodeURIComponent(m[1]));
    history.replaceState(null, '', location.pathname);
    app.route = [];
  }
  try {
    if (!isApp && !getToken()) {
      const h = await health();
      if (h.auth) {
        app.session = 'login';
        return;
      }
    }
    await rpc('status');
  } catch (e) {
    if (e instanceof AuthError) {
      app.session = 'login';
      return;
    }
  }
  app.session = 'ready';
  followNotification();
  await Promise.all([refreshStatus(), refreshSubs(), loadSettings()]);
}

export async function signIn(token: string): Promise<boolean> {
  setToken(token.trim());
  try {
    await rpc('status');
  } catch (e) {
    if (e instanceof AuthError) {
      setToken('');
      return false;
    }
    throw e;
  }
  await start();
  return true;
}

export function signOut() {
  setToken('');
  app.session = 'login';
}

setInterval(() => {
  if (app.session === 'ready' && !document.hidden) refreshStatus();
}, 60_000);
document.addEventListener('visibilitychange', () => {
  if (app.session === 'ready' && !document.hidden) refreshStatus();
  followNotification();
});
window.addEventListener('focus', followNotification);

/** App only: a tapped notification names the page to open. */
async function followNotification() {
  if (!isApp || document.hidden) return;
  try {
    const r = await rpc<{ route?: string } | null>('android.take_route');
    if (r?.route) {
      go(r.route);
      refreshStatus();
    }
  } catch {
    /* not running on Android */
  }
}
