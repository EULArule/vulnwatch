<script lang="ts">
  import type { Target } from './lib/types';
  import { app, start } from './lib/state.svelte';
  import Icon from './components/Icon.svelte';
  import Login from './pages/Login.svelte';
  import Home from './pages/Home.svelte';
  import Browse from './pages/Browse.svelte';
  import VulnPage from './pages/VulnPage.svelte';
  import Alerts from './pages/Alerts.svelte';
  import Subs from './pages/Subs.svelte';
  import SettingsPage from './pages/SettingsPage.svelte';

  start();

  const page = $derived(app.route[0] ?? '');
  const target = $derived.by((): Target | null => {
    const r = app.route;
    switch (r[0]) {
      case 'p':
        return r[2] ? { kind: 'product', vendor: r[1], product: r[2], keywords: [] } : null;
      case 'vendor':
        return r[1] ? { kind: 'vendor', vendor: r[1] } : null;
      case 'pkg':
        // Package names may contain slashes (Go modules, scoped npm packages).
        return r[2] ? { kind: 'package', ecosystem: r[1], name: r.slice(2).join('/') } : null;
      case 'k':
        return r[1] ? { kind: 'keyword', keywords: r[1].split(',').map((k) => k.trim()).filter(Boolean) } : null;
      case 'latest':
        return { kind: 'everything' };
    }
    return null;
  });
  const tab = $derived(page === 'alerts' ? 'alerts' : page === 'subs' ? 'subs' : page === 'settings' ? 'settings' : 'search');
  const unread = $derived(app.status?.unread ?? 0);
  const tabs = [
    { id: 'search', href: '#/', icon: 'search', label: 'Search' },
    { id: 'alerts', href: '#/alerts', icon: 'bell', label: 'Alerts' },
    { id: 'subs', href: '#/subs', icon: 'eye', label: 'Watching' },
    { id: 'settings', href: '#/settings', icon: 'gear', label: 'Settings' },
  ];
</script>

{#if app.session === 'loading'}
  <div class="loading boot"><span class="spinner"></span></div>
{:else if app.session === 'login'}
  <Login />
{:else}
  <nav aria-label="Main">
    <a class="brand" href="#/"><img src="/icon.svg" alt="" width="30" height="30" /><span>vulnwatch</span></a>
    {#each tabs as t}
      <a href={t.href} class="tab" class:on={tab === t.id} aria-current={tab === t.id ? 'page' : undefined}>
        <span class="ico">
          <Icon name={t.icon} size={22} />
          {#if t.id === 'alerts' && unread}<span class="dot">{unread > 99 ? '99+' : unread}</span>{/if}
        </span>
        <span>{t.label}</span>
      </a>
    {/each}
  </nav>

  <main>
    {#if target}
      {#key JSON.stringify(target)}
        <Browse {target} />
      {/key}
    {:else if page === 'cve' && app.route[1]}
      <VulnPage id={app.route.slice(1).join('/')} />
    {:else if page === 'alerts'}
      <Alerts subId={app.route[1] ? Number(app.route[1]) : null} />
    {:else if page === 'subs'}
      <Subs />
    {:else if page === 'settings'}
      <SettingsPage />
    {:else}
      <Home />
    {/if}
  </main>
{/if}

<div class="toasts" aria-live="polite">
  {#each app.toasts as t (t.id)}
    <div class="toast" class:error={t.kind === 'error'}>{t.text}</div>
  {/each}
</div>

<style>
  .boot {
    min-height: 100vh;
  }
  main {
    max-width: 860px;
    margin: 0 auto;
    padding: 1.2rem 1rem calc(var(--nav-h) + 2rem + env(safe-area-inset-bottom));
    padding-top: calc(1.2rem + env(safe-area-inset-top));
  }
  nav {
    position: fixed;
    z-index: 30;
    left: 0;
    right: 0;
    bottom: 0;
    height: calc(var(--nav-h) + env(safe-area-inset-bottom));
    padding-bottom: env(safe-area-inset-bottom);
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    background: var(--surface);
    border-top: 1px solid var(--border);
  }
  .brand {
    display: none;
  }
  .tab {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 2px;
    font-size: 0.72rem;
    font-weight: 600;
    color: var(--muted);
    text-decoration: none;
  }
  .tab.on {
    color: var(--accent);
  }
  .ico {
    position: relative;
    display: grid;
    place-items: center;
    width: 56px;
    height: 28px;
    border-radius: 999px;
  }
  .tab.on .ico {
    background: var(--accent-soft);
  }
  .dot {
    position: absolute;
    top: -4px;
    left: 30px;
    min-width: 18px;
    height: 18px;
    padding: 0 5px;
    border-radius: 999px;
    background: var(--crit);
    color: var(--surface);
    font-size: 0.68rem;
    font-weight: 700;
    display: grid;
    place-items: center;
  }
  .toasts {
    position: fixed;
    z-index: 60;
    left: 0;
    right: 0;
    bottom: calc(var(--nav-h) + 0.8rem + env(safe-area-inset-bottom));
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 0.4rem;
    pointer-events: none;
    padding: 0 1rem;
  }
  .toast {
    background: var(--text);
    color: var(--bg);
    padding: 0.65rem 1rem;
    border-radius: 12px;
    box-shadow: var(--shadow);
    font-size: 0.92rem;
    font-weight: 550;
    max-width: 520px;
  }
  .toast.error {
    background: var(--danger);
    color: var(--surface);
  }

  @media (min-width: 760px) {
    nav {
      top: 0;
      bottom: auto;
      height: var(--nav-h);
      padding: 0 max(1rem, calc((100vw - 860px) / 2));
      display: flex;
      gap: 0.3rem;
      align-items: center;
      border-top: 0;
      border-bottom: 1px solid var(--border);
    }
    .brand {
      display: flex;
      align-items: center;
      gap: 0.55rem;
      font-weight: 800;
      font-size: 1.1rem;
      color: var(--text);
      text-decoration: none;
      margin-right: auto;
    }
    .tab {
      flex-direction: row;
      gap: 0.4rem;
      font-size: 0.93rem;
      padding: 0 0.9rem 0 0.5rem;
      height: 40px;
      border-radius: 999px;
    }
    .tab.on {
      background: var(--accent-soft);
    }
    .ico {
      width: 30px;
    }
    .tab.on .ico {
      background: transparent;
    }
    .dot {
      left: 16px;
    }
    main {
      padding-top: calc(var(--nav-h) + 1.6rem);
      padding-bottom: 3rem;
    }
    .toasts {
      bottom: 1.5rem;
    }
  }
</style>
