// App-wide reactive state: route, session, status, toasts.
import { AuthError, getToken, health, isApp, rpc, setToken } from './api';
import type { CheckStep, Settings, Status, Subscription } from './types';

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

// Scroll position per history entry, so Back (in-app or Android's) returns to where you were.
// Each entry is tagged with a key in history.state; a fresh entry (a link was followed) has none.
if ('scrollRestoration' in history) history.scrollRestoration = 'manual';
const scrolls = new Map<string, number>();
function entryKey(): { key: string; fresh: boolean } {
  const key = history.state?.vwKey;
  if (key) return { key, fresh: false };
  const made = Math.random().toString(36).slice(2);
  history.replaceState({ ...(history.state ?? {}), vwKey: made }, '');
  return { key: made, fresh: true };
}
let entry = entryKey().key;
let stopRestore = () => {};

window.addEventListener('hashchange', () => {
  scrolls.set(entry, window.scrollY);
  const next = entryKey();
  entry = next.key;
  app.route = parseRoute();
  stopRestore();
  const y = next.fresh ? 0 : (scrolls.get(entry) ?? 0);
  window.scrollTo(0, y);
  if (y > 0) stopRestore = restoreScroll(y);
});

/** Pages load their content after showing: keep scrolling to `y` as the page grows, until it
 *  gets there, the user scrolls themselves, or a few seconds pass. */
function restoreScroll(y: number): () => void {
  const reached = () => Math.abs(window.scrollY - y) < 2;
  const ro = new ResizeObserver(() => {
    window.scrollTo(0, y);
    if (reached()) stop();
  });
  const stop = () => {
    ro.disconnect();
    clearTimeout(timer);
    for (const ev of ['touchstart', 'wheel', 'keydown'] as const) window.removeEventListener(ev, stop);
  };
  const timer = setTimeout(stop, 4000);
  for (const ev of ['touchstart', 'wheel', 'keydown'] as const) window.addEventListener(ev, stop, { passive: true });
  ro.observe(document.body);
  return stop;
}

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
    if (app.status.checking) watchCheck();
  } catch (e) {
    if (e instanceof AuthError) app.session = 'login';
  }
}

export async function refreshSubs() {
  const r = await call<{ subscriptions: Subscription[] }>('subs.list');
  if (r) app.subs = r.subscriptions;
}

/** The check that is running, or the last one. Lives here so it survives moving between pages. */
export const check = $state({
  running: false,
  steps: [] as CheckStep[],
  /** How long the check has been going, or took. */
  ms: null as number | null,
  /** Alerts it has raised so far. */
  found: 0,
  /** Goes up whenever the alert list is worth reloading. */
  changes: 0,
  /** Whether the list of steps is shown. */
  open: false,
});

interface CheckProgress {
  running: boolean;
  ms: number | null;
  new: number;
  steps: CheckStep[];
}

let asking = false;
let watching = false;

/** Follow a check until it ends: its steps, and alerts as they are raised. Safe to call any time. */
export async function watchCheck() {
  if (watching) return;
  watching = true;
  try {
    for (;;) {
      let p: CheckProgress;
      try {
        p = await rpc<CheckProgress>('poll.progress');
      } catch {
        break;
      }
      // Just after asking for a check the answer may still describe the one before it.
      if (p.running || !asking) {
        const more = p.new > check.found;
        const ended = check.running && !p.running;
        check.steps = p.steps;
        check.ms = p.ms;
        check.found = p.new;
        if (more || ended) {
          check.changes++;
          refreshStatus();
          refreshSubs();
        }
      }
      check.running = p.running || asking;
      if (!check.running) break;
      await new Promise((r) => setTimeout(r, 500));
    }
  } finally {
    watching = false;
    check.running = asking;
  }
}

export async function checkNow() {
  if (check.running) return;
  asking = true;
  check.running = true;
  check.steps = [];
  check.ms = 0;
  check.found = 0;
  watchCheck();
  const r = await call('poll');
  asking = false;
  watchCheck();
  if (!r) {
    check.running = watching;
    return;
  }
  if (r.errors.length) toast(r.errors[0], 'error');
  else toast(r.skipped ? 'A check is already running' : r.new ? `${r.new} new alert${r.new === 1 ? '' : 's'}` : 'Nothing new');
  check.changes++;
  await Promise.all([refreshStatus(), refreshSubs()]);
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
