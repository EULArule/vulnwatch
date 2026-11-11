<script lang="ts">
  import type { Subscription } from '../lib/types';
  import { defaultFilter } from '../lib/types';
  import { app, call, refreshSubs } from '../lib/state.svelte';
  import { filterLabel, targetLabel, targetPath } from '../lib/format';
  import Icon from '../components/Icon.svelte';
  import SubscribeDialog from '../components/SubscribeDialog.svelte';

  let editing: Subscription | null = $state(null);

  const VIEW_KEY = 'vulnwatch.subs.compact';
  function stored() {
    try {
      return localStorage.getItem(VIEW_KEY) === '1';
    } catch {
      return false;
    }
  }
  let compact = $state(stored());
  function setCompact(on: boolean) {
    compact = on;
    try {
      localStorage.setItem(VIEW_KEY, on ? '1' : '0');
    } catch {
      /* the choice just won't be remembered */
    }
  }

  let query = $state('');
  const shown = $derived.by(() => {
    const words = query.toLowerCase().split(/\s+/).filter(Boolean);
    if (!words.length) return app.subs;
    return app.subs.filter((s) => {
      const text = `${s.name} ${targetLabel(s.target)} ${filterLabel(s.filter)}`.toLowerCase();
      return words.every((w) => text.includes(w));
    });
  });

  $effect(() => {
    refreshSubs();
  });

  async function toggle(s: Subscription, enabled: boolean) {
    const { alerts, unread, ...rest } = s;
    if (await call('subs.save', { subscription: { ...rest, enabled } })) await refreshSubs();
  }

  const hasKev = $derived(app.subs.some((s) => s.target.kind === 'everything' && s.filter.exploited_only));
  function addKev() {
    editing = {
      id: 0,
      name: 'Actively exploited (any product)',
      target: { kind: 'everything' },
      filter: { ...defaultFilter(), exploited_only: true },
      enabled: true,
      notify: true,
    };
  }
</script>

<header class="row head">
  <div class="grow">
    <h1>Watching</h1>
    <div class="muted small">What you get alerts for, and the filter on each</div>
  </div>
  <a class="btn primary sm" href="#/"><Icon name="plus" size={18} /> Add</a>
</header>

{#if !app.subs.length}
  <div class="card empty">
    <h2>You are not watching anything yet</h2>
    <p>Search for a product, vendor or package, then tap <b>Get alerts</b>.</p>
    <p style="margin-top:1rem"><a class="btn primary" href="#/"><Icon name="search" /> Find a product</a></p>
  </div>
{/if}

{#if app.subs.length}
  <div class="row tools">
    <input class="input grow" type="search" bind:value={query} placeholder="Search what you watch" aria-label="Search what you watch" />
    <div class="seg view">
      <button class:on={!compact} onclick={() => setCompact(false)}>Detailed</button>
      <button class:on={compact} onclick={() => setCompact(true)}>Compact</button>
    </div>
  </div>
  {#if query.trim()}
    <div class="muted small count">{shown.length} of {app.subs.length}{shown.length ? '' : ' — nothing matches'}</div>
  {/if}
{/if}

{#if compact}
  {#if shown.length}
    <div class="card list">
      {#each shown as s (s.id)}
        <div class="line" class:off={!s.enabled}>
          <a class="name" href={'#' + targetPath(s.target)} title={targetLabel(s.target)}>{s.name}</a>
          <a class="hits" href={'#/alerts/' + s.id} aria-label="{s.alerts ?? 0} alerts{s.unread ? `, ${s.unread} new` : ''}">
            {s.alerts ?? 0}
            {#if s.unread}<span class="badge accent">{s.unread} new</span>{/if}
          </a>
          <label class="switch" title={s.enabled ? 'Active' : 'Paused'}>
            <input type="checkbox" checked={s.enabled} onchange={(e) => toggle(s, e.currentTarget.checked)} aria-label="Active" />
          </label>
        </div>
      {/each}
    </div>
  {/if}
{:else}
<div class="stack">
  {#each shown as s (s.id)}
    <div class="card sub" class:off={!s.enabled}>
      <a class="main" href={'#' + targetPath(s.target)}>
        <b>{s.name}</b>
        <span class="muted small">{targetLabel(s.target)}</span>
        <span class="small filter"><Icon name="bell" size={15} /> {filterLabel(s.filter)}{s.notify ? '' : ' · no notifications'}</span>
      </a>
      <div class="side">
        <label class="switch" title={s.enabled ? 'Active' : 'Paused'}>
          <input type="checkbox" checked={s.enabled} onchange={(e) => toggle(s, e.currentTarget.checked)} aria-label="Active" />
        </label>
      </div>
      <div class="foot row">
        <a class="btn ghost sm" href={'#/alerts/' + s.id}>
          {s.alerts ?? 0} alert{s.alerts === 1 ? '' : 's'}
          {#if s.unread}<span class="badge accent">{s.unread} new</span>{/if}
        </a>
        <span class="grow"></span>
        <button class="btn ghost sm" onclick={() => (editing = s)}><Icon name="edit" size={18} /> Edit filter</button>
      </div>
    </div>
  {/each}
</div>
{/if}

{#if !hasKev}
  <button class="card pad suggest" onclick={addKev}>
    <span class="ico"><Icon name="flame" /></span>
    <span class="grow">
      <b>Watch everything that is being exploited</b>
      <span class="muted small">An alert whenever any vulnerability is added to CISA's exploited list — a few per week.</span>
    </span>
    <Icon name="plus" />
  </button>
{/if}

{#if editing}
  <SubscribeDialog sub={editing} onclose={() => (editing = null)} />
{/if}

<style>
  .head {
    margin-bottom: 1rem;
  }
  .tools {
    gap: 0.6rem;
    margin-bottom: 0.8rem;
    flex-wrap: wrap;
  }
  .tools .input {
    min-width: 12rem;
  }
  .view {
    flex: none;
  }
  .count {
    margin: -0.3rem 0 0.7rem 0.2rem;
  }
  .list {
    overflow: hidden;
  }
  .line {
    display: flex;
    align-items: center;
    gap: 0.6rem;
    padding: 0.35rem 0.8rem 0.35rem 1rem;
    min-height: 48px;
  }
  .line + .line {
    border-top: 1px solid var(--border);
  }
  .line.off .name,
  .line.off .hits {
    opacity: 0.55;
  }
  .name {
    flex: 1;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    color: inherit;
    text-decoration: none;
    font-weight: 600;
  }
  .hits {
    flex: none;
    display: flex;
    align-items: center;
    gap: 0.4rem;
    padding: 0.4rem 0.3rem;
    color: var(--muted);
    text-decoration: none;
    font-variant-numeric: tabular-nums;
  }
  .sub {
    display: grid;
    grid-template-columns: 1fr auto;
    overflow: hidden;
  }
  .sub.off .main {
    opacity: 0.55;
  }
  .main {
    display: flex;
    flex-direction: column;
    gap: 0.15rem;
    padding: 0.9rem 1rem 0.6rem;
    color: inherit;
    text-decoration: none;
    min-width: 0;
  }
  .main b {
    font-size: 1.05rem;
  }
  .filter {
    display: flex;
    align-items: center;
    gap: 0.35rem;
    margin-top: 0.25rem;
    color: var(--accent);
    font-weight: 600;
  }
  .side {
    padding: 0.5rem 0.8rem 0 0;
  }
  .foot {
    grid-column: 1 / -1;
    border-top: 1px solid var(--border);
    padding: 0.3rem 0.5rem;
  }
  .suggest {
    display: flex;
    align-items: center;
    gap: 0.8rem;
    width: 100%;
    margin-top: 1.2rem;
    text-align: left;
    cursor: pointer;
    border-style: dashed;
    box-shadow: none;
    color: inherit;
  }
  .suggest .grow {
    display: flex;
    flex-direction: column;
  }
  .suggest:hover {
    border-color: var(--accent);
  }
  .ico {
    flex: none;
    width: 38px;
    height: 38px;
    border-radius: 11px;
    display: grid;
    place-items: center;
    background: var(--crit-bg);
    color: var(--crit);
  }
</style>
