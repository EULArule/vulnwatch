<script lang="ts">
  import type { Alert } from '../lib/types';
  import { app, call, refreshStatus, refreshSubs, toast } from '../lib/state.svelte';
  import { ago, dayLabel } from '../lib/format';
  import Icon from '../components/Icon.svelte';
  import VulnRow from '../components/VulnRow.svelte';

  let { subId = null }: { subId?: number | null } = $props();

  let alerts: Alert[] = $state([]);
  let more = $state(false);
  let loading = $state(true);
  let unreadOnly = $state(false);
  let checking = $state(false);

  const sub = $derived(subId ? app.subs.find((s) => s.id === subId) : null);

  async function load(append = false) {
    if (!append) loading = true;
    const r = await call('alerts.list', {
      sub_id: subId,
      unread_only: unreadOnly,
      before_id: append ? alerts[alerts.length - 1]?.id : null,
      limit: 50,
    });
    loading = false;
    if (!r) return;
    alerts = append ? [...alerts, ...r.alerts] : r.alerts;
    more = r.more;
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
    if (n > lastUnread) load();
    lastUnread = n;
  });

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
    const r = await call('alerts.delete', subId ? { ids: alerts.map((a) => a.id) } : {});
    if (!r) return;
    await load();
    refreshSubs();
  }

  async function checkNow() {
    checking = true;
    const r = await call('poll');
    checking = false;
    if (!r) return;
    if (r.errors.length) toast(r.errors[0], 'error');
    else toast(r.skipped ? 'A check is already running' : r.new ? `${r.new} new alert${r.new === 1 ? '' : 's'}` : 'Nothing new');
    await Promise.all([load(), refreshStatus(), refreshSubs()]);
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
  <button class="btn sm" onclick={checkNow} disabled={checking}>
    {#if checking}<span class="spinner"></span>{:else}<Icon name="refresh" size={18} />{/if} Check now
  </button>
</header>

<div class="row wrap bar">
  <div class="chips grow">
    <button class="chip" class:on={!unreadOnly} onclick={() => (unreadOnly = false)}>All</button>
    <button class="chip" class:on={unreadOnly} onclick={() => (unreadOnly = true)}>Unread{app.status?.unread ? ` (${app.status.unread})` : ''}</button>
    {#if subId}<a class="chip" href="#/alerts"><Icon name="x" size={16} /> {sub?.name ?? 'Filter'}</a>{/if}
  </div>
  {#if hasUnread}<button class="btn ghost sm" onclick={markAll}><Icon name="check" size={18} /> Mark all read</button>{/if}
  {#if alerts.length}<button class="btn ghost sm" onclick={clearAll} aria-label="Delete all" title="Delete all"><Icon name="trash" size={18} /></button>{/if}
</div>

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
        <div class="item" onclickcapture={() => open(a)} role="presentation">
          <div class="meta small">
            <a class="badge accent" href={'#/alerts/' + a.sub_id}>{a.sub_name}</a>
            {#if a.kind === 'exploited'}<span class="badge exploited">Now being exploited</span>{/if}
            <span class="muted when">{ago(a.created_at)}</span>
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
  .item :global(.vuln) {
    border-bottom: 0;
    padding-top: 0.5rem;
  }
  .morebtn {
    text-align: center;
    margin-top: 1rem;
  }
</style>
