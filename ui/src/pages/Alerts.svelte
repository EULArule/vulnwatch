<script lang="ts" module>
  /** How many alerts each list showed last time ("Load older" included), so coming back to it
   *  shows the same rows and the scroll position can be restored. */
  const shown = new Map<string, number>();
</script>

<script lang="ts">
  import { untrack } from 'svelte';
  import type { Alert } from '../lib/types';
  import { app, call, check, checkNow, refreshSubs, watchCheck } from '../lib/state.svelte';
  import { ago, dayLabel } from '../lib/format';
  import Icon from '../components/Icon.svelte';
  import VulnRow from '../components/VulnRow.svelte';

  let { subId = null }: { subId?: number | null } = $props();

  let alerts: Alert[] = $state([]);
  let more = $state(false);
  let loading = $state(true);
  /** The server could not be reached: the list is what this device kept. */
  let kept = $state(false);
  const FILTER_KEY = 'vulnwatch.alerts.unreadOnly';
  function stored() {
    try {
      return localStorage.getItem(FILTER_KEY) === '1';
    } catch {
      return false;
    }
  }
  let unreadOnly = $state(stored());
  function setUnreadOnly(on: boolean) {
    unreadOnly = on;
    try {
      localStorage.setItem(FILTER_KEY, on ? '1' : '0');
    } catch {
      /* the choice just won't be remembered */
    }
  }

  const sub = $derived(subId ? app.subs.find((s) => s.id === subId) : null);

  async function load(append = false, quiet = false) {
    if (!append && !quiet) loading = true;
    const key = `${subId}|${unreadOnly}`;
    const r = await call('alerts.list', {
      sub_id: subId,
      unread_only: unreadOnly,
      before_id: append ? alerts[alerts.length - 1]?.id : null,
      limit: append ? 50 : Math.min(500, Math.max(50, shown.get(key) ?? 0, untrack(() => alerts.length))),
    });
    loading = false;
    if (!r) return;
    alerts = append ? [...alerts, ...r.alerts] : r.alerts;
    shown.set(key, alerts.length);
    more = r.more;
    if (!append) kept = !!r.kept;
    if (app.status) app.status.unread = r.unread;
  }

  $effect(() => {
    subId;
    unreadOnly;
    load();
  });

  // Pick up alerts that arrive while this page is open.
  let lastUnread = app.status?.unread ?? 0;
  $effect(() => {
    const n = app.status?.unread ?? 0;
    if (n > lastUnread) load(false, true);
    lastUnread = n;
  });

  // A check may be running already: one started here before leaving the page, or the timed one.
  watchCheck();
  // Show what a check finds as it finds it, not only once every source has answered.
  let lastChange = check.changes;
  $effect(() => {
    if (check.changes !== lastChange) load(false, true);
    lastChange = check.changes;
  });

  function secs(ms: number, whole = false) {
    return whole || ms >= 10_000 ? `${Math.floor(ms / 1000)}s` : `${(ms / 1000).toFixed(1)}s`;
  }

  const groups = $derived.by(() => {
    const out: { day: string; items: Alert[] }[] = [];
    for (const a of alerts) {
      const day = dayLabel(a.created_at);
      if (out[out.length - 1]?.day !== day) out.push({ day, items: [] });
      out[out.length - 1].items.push(a);
    }
    return out;
  });

  async function open(a: Alert) {
    if (a.read) return;
    a.read = true;
    const r = await call('alerts.mark', { ids: [a.id], read: true });
    if (r && app.status) app.status.unread = r.unread;
  }

  async function markAll() {
    const r = await call('alerts.mark', { sub_id: subId, read: true });
    if (!r) return;
    alerts.forEach((a) => (a.read = true));
    if (app.status) app.status.unread = r.unread;
    refreshSubs();
  }

  async function clearAll() {
    if (!confirm('Delete all alerts from this list? Your subscriptions stay.')) return;
    const r = await call('alerts.delete', { sub_id: subId });
    if (!r) return;
    await load();
    refreshSubs();
  }

  async function remove(a: Alert) {
    const r = await call('alerts.delete', { ids: [a.id] });
    if (!r) return;
    alerts = alerts.filter((x) => x.id !== a.id);
    if (app.status) app.status.unread = r.unread;
    refreshSubs();
  }

  const hasUnread = $derived(alerts.some((a) => !a.read));
</script>

<header class="row wrap head">
  <div class="grow">
    <h1>{sub ? sub.name : 'Alerts'}</h1>
    <div class="muted small">
      {#if !app.subs.length}
        Subscribe to something to start receiving alerts
      {:else}
        Last checked {ago(app.status?.last_check)}
        {#if app.status?.last_errors?.length}<span class="err"> · {app.status.last_errors[0]}</span>{/if}
      {/if}
    </div>
  </div>
  {#if check.running}
    <button class="btn sm" onclick={() => (check.open = !check.open)} aria-expanded={check.open} title="Show what is being checked">
      <span class="spinner"></span> Checking… {secs(check.ms ?? 0, true)}
    </button>
  {:else}
    <button class="btn sm" onclick={checkNow}><Icon name="refresh" size={18} /> Check now</button>
  {/if}
</header>

{#if check.open && (check.running || check.steps.length)}
  <div class="card steps">
    <div class="row top">
      <b class="grow small">
        {#if check.running}
          Checking{check.found ? ` · ${check.found} new so far` : ''}
        {:else}
          Last check took {secs(check.ms ?? 0)}{check.found ? ` · ${check.found} new` : ''}
        {/if}
      </b>
      <button class="del" onclick={() => (check.open = false)} aria-label="Hide" title="Hide"><Icon name="x" size={16} /></button>
    </div>
    {#each check.steps as s, i (i)}
      <div class="step {s.state}">
        <span class="mark">
          {#if s.state === 'running'}<span class="spinner"></span>{:else}<Icon name={s.state === 'done' ? 'check' : 'x'} size={17} />{/if}
        </span>
        <span class="grow what">
          {s.name}
          {#if s.error}<span class="small why">{s.error}</span>{/if}
        </span>
        <span class="took small">{secs(s.ms, s.state === 'running')}</span>
      </div>
    {:else}
      <div class="step muted small">Starting…</div>
    {/each}
  </div>
{:else if !check.running && check.steps.length}
  <p class="lastrun"><button class="link small" onclick={() => (check.open = true)}>What the last check did</button></p>
{/if}

<div class="row wrap bar">
  <div class="chips grow">
    <button class="chip" class:on={!unreadOnly} onclick={() => setUnreadOnly(false)}>All</button>
    <button class="chip" class:on={unreadOnly} onclick={() => setUnreadOnly(true)}>Unread{app.status?.unread ? ` (${app.status.unread})` : ''}</button>
    {#if subId}<a class="chip" href="#/alerts"><Icon name="x" size={16} /> {sub?.name ?? 'Filter'}</a>{/if}
  </div>
  {#if hasUnread}<button class="btn ghost sm" onclick={markAll}><Icon name="check" size={18} /> Mark all read</button>{/if}
  {#if alerts.length}<button class="btn ghost sm" onclick={clearAll} aria-label="Delete all" title="Delete all"><Icon name="trash" size={18} /></button>{/if}
</div>

{#if kept && !loading}
  <div class="card pad offline small">No connection to your server. These are the alerts saved on this device.</div>
{/if}
{#if loading}
  <div class="loading"><span class="spinner"></span></div>
{:else if !alerts.length}
  <div class="card empty">
    {#if !app.subs.length}
      <h2>No alerts yet</h2>
      <p>Search for a product you use and tap <b>Get alerts</b>.</p>
      <p style="margin-top:1rem"><a class="btn primary" href="#/"><Icon name="search" /> Find a product</a></p>
    {:else}
      <h2>{unreadOnly ? 'All caught up' : 'Nothing new so far'}</h2>
      <p>You will be told when a new vulnerability matches what you watch. Past vulnerabilities are on each product's page.</p>
    {/if}
  </div>
{:else}
  {#each groups as g (g.day)}
    <h2 class="day">{g.day}</h2>
    <div class="card list">
      {#each g.items as a (a.id)}
        <div class="item" onclickcapture={(e) => !(e.target as Element).closest('.del') && open(a)} role="presentation">
          <div class="meta small">
            <a class="badge accent" href={'#/alerts/' + a.sub_id}>{a.sub_name}</a>
            {#if a.kind === 'exploited'}<span class="badge exploited">Now being exploited</span>{/if}
            <span class="muted when">{ago(a.created_at)}</span>
            <button class="del" onclick={(e) => { e.stopPropagation(); remove(a); }} aria-label="Delete this alert" title="Delete this alert"><Icon name="x" size={16} /></button>
          </div>
          <VulnRow vuln={a.vuln} unread={!a.read} />
        </div>
      {/each}
    </div>
  {/each}
  {#if more}
    <p class="morebtn"><button class="btn" onclick={() => load(true)}>Load older</button></p>
  {/if}
{/if}

<style>
  .head {
    margin-bottom: 0.9rem;
  }
  .bar {
    margin-bottom: 0.4rem;
  }
  .err {
    color: var(--danger);
  }
  .steps {
    margin-bottom: 0.8rem;
    padding: 0.5rem 1rem 0.6rem;
  }
  .steps .top {
    min-height: 2rem;
  }
  .step {
    display: flex;
    align-items: flex-start;
    gap: 0.6rem;
    padding: 0.3rem 0;
  }
  .mark {
    flex: none;
    display: grid;
    place-items: center;
    width: 1.2rem;
    height: 1.3rem;
  }
  .mark .spinner {
    width: 15px;
    height: 15px;
    border-width: 2px;
  }
  .step.done .mark {
    color: var(--ok);
  }
  .step.failed .mark,
  .why {
    color: var(--danger);
  }
  .what {
    min-width: 0;
    overflow-wrap: anywhere;
  }
  .why {
    display: block;
  }
  .took {
    flex: none;
    color: var(--muted);
    font-variant-numeric: tabular-nums;
  }
  .step.running .took {
    color: var(--text);
    font-weight: 600;
  }
  .lastrun {
    margin: -0.5rem 0 0.5rem;
    text-align: right;
  }
  .link {
    border: 0;
    padding: 0.2rem 0;
    background: none;
    color: var(--muted);
    text-decoration: underline;
    cursor: pointer;
  }
  .offline {
    margin: 0.6rem 0;
    color: var(--muted);
  }
  .day {
    margin: 1.1rem 0 0.5rem;
    font-size: 0.85rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--muted);
  }
  .list {
    overflow: hidden;
  }
  .item {
    border-bottom: 1px solid var(--border);
  }
  .item:last-child {
    border-bottom: 0;
  }
  .meta {
    display: flex;
    flex-wrap: wrap;
    gap: 0.4rem;
    align-items: center;
    padding: 0.7rem 1rem 0;
  }
  .when {
    margin-left: auto;
  }
  .del {
    display: grid;
    place-items: center;
    width: 2rem;
    height: 2rem;
    margin: -0.35rem -0.5rem -0.35rem 0;
    border: 0;
    border-radius: 50%;
    background: none;
    color: var(--muted);
    cursor: pointer;
  }
  .del:hover {
    background: var(--border);
    color: var(--text);
  }
  .item :global(.vuln) {
    border-bottom: 0;
    padding-top: 0.5rem;
  }
  .morebtn {
    text-align: center;
    margin-top: 1rem;
  }
</style>
