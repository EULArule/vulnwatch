<script lang="ts">
  import type { AttackVector, Severity, Subscription, Target, Vuln } from '../lib/types';
  import { defaultFilter } from '../lib/types';
  import { rpc } from '../lib/api';
  import { app, call } from '../lib/state.svelte';
  import { cap, pretty, sevRank } from '../lib/format';
  import Icon from '../components/Icon.svelte';
  import VulnRow from '../components/VulnRow.svelte';
  import SubscribeDialog from '../components/SubscribeDialog.svelte';

  let { target }: { target: Target } = $props();

  let items: Vuln[] = $state([]);
  let total = $state(0);
  let approx = $state(false);
  let nextEnd: number | null = $state(null);
  let notes: string[] = $state([]);
  let loading = $state(true);
  let loadingMore = $state(false);
  /** Showing a first batch while the complete list is still loading. */
  let partial = $state(false);
  let error = $state('');
  let title = $state('');
  let subtitle = $state('');
  let suggested: string[] = $state([]);
  let editing: Subscription | null = $state(null);

  let sort: 'newest' | 'severity' | 'epss' = $state('newest');
  let minSev: Severity | null = $state(null);
  let exploitedOnly = $state(false);
  let vectors: AttackVector[] = $state([]);
  const vectorNames: [AttackVector, string][] = [
    ['network', 'Over the network'],
    ['adjacent', 'Same network'],
    ['local', 'Local access'],
    ['physical', 'Physical access'],
  ];
  function toggleVector(v: AttackVector) {
    vectors = vectors.includes(v) ? vectors.filter((x) => x !== v) : [...vectors, v];
  }
  let text = $state('');

  const same = (a: Target, b: Target) => {
    if (a.kind !== b.kind) return false;
    const strip = (t: Target) => (t.kind === 'product' ? { ...t, keywords: [] } : t);
    return JSON.stringify(strip(a)) === JSON.stringify(strip(b));
  };
  const existing = $derived(app.subs.filter((s) => same(s.target, target)));

  async function load(refresh = false) {
    const t = target;
    const current = () => t === target;
    loading = true;
    partial = false;
    error = '';
    let done = false;
    if (!refresh && t.kind === 'product') {
      // Something to read within a second or so, while the complete list is fetched.
      rpc('vulns.list', { target: t, quick: true })
        .then((r) => {
          if (done || !current() || !r.items.length) return;
          items = r.items;
          total = r.total;
          nextEnd = r.next_end;
          partial = r.partial;
          loading = false;
        })
        .catch(() => {});
    }
    try {
      const r = await rpc('vulns.list', { target: t, refresh });
      if (!current()) return;
      items = r.items;
      total = r.total;
      approx = !!r.approx;
      nextEnd = r.next_end;
      notes = r.notes;
    } catch (e) {
      if (!current()) return;
      if (!partial) error = (e as Error).message;
      else notes = ['Could not load the full list: ' + (e as Error).message];
    }
    done = true;
    partial = false;
    loading = false;
  }

  async function loadMore() {
    loadingMore = true;
    const r = await call('vulns.list', { target, end: nextEnd });
    loadingMore = false;
    if (!r) return;
    const seen = new Set(items.map((i) => i.id));
    items = [...items, ...r.items.filter((i: Vuln) => !seen.has(i.id))];
    nextEnd = r.next_end;
  }

  $effect(() => {
    const t = target;
    items = [];
    minSev = null;
    exploitedOnly = false;
    vectors = [];
    text = '';
    suggested = [];
    switch (t.kind) {
      case 'product':
        title = pretty(t.product);
        subtitle = pretty(t.vendor);
        rpc('product.info', { vendor: t.vendor, product: t.product })
          .then((r) => {
            if (r.product) title = r.product.title;
            suggested = r.keywords;
          })
          .catch(() => {});
        break;
      case 'vendor':
        title = pretty(t.vendor);
        subtitle = 'All products from this vendor';
        break;
      case 'package':
        title = t.name;
        subtitle = `${t.ecosystem} package`;
        break;
      case 'keyword':
        title = `"${t.keywords.join('", "')}"`;
        subtitle = 'Vulnerabilities mentioning this';
        break;
      case 'everything':
        title = 'Latest vulnerabilities';
        subtitle = 'Everything, newest first';
    }
    load();
  });

  const shown = $derived.by(() => {
    const needle = text.trim().toLowerCase();
    let list = items.filter(
      (v) =>
        (!minSev || sevRank(v.severity) >= sevRank(minSev)) &&
        (!exploitedOnly || v.exploited) &&
        (!vectors.length || (!!v.attack_vector && vectors.includes(v.attack_vector))) &&
        (!needle || (v.id + ' ' + (v.title ?? '') + ' ' + v.summary).toLowerCase().includes(needle)),
    );
    if (sort === 'severity') list = [...list].sort((a, b) => (b.cvss ?? -1) - (a.cvss ?? -1));
    if (sort === 'epss') list = [...list].sort((a, b) => (b.epss ?? -1) - (a.epss ?? -1));
    return list;
  });
  const exploitedCount = $derived(items.filter((v) => v.exploited).length);

  function subscribe() {
    const t: Target = target.kind === 'product' ? { ...target, keywords: suggested } : target;
    editing = { id: 0, name: target.kind === 'keyword' ? target.keywords.join(', ') : target.kind === 'everything' ? '' : title, target: t, filter: defaultFilter(), enabled: true, notify: true };
  }
</script>

<header class="head">
  <button class="btn ghost sm back" onclick={() => history.back()} aria-label="Back"><Icon name="back" /></button>
  <div class="grow">
    <h1>{title}</h1>
    <div class="muted">
      {#if target.kind === 'product'}
        <a href={'#/vendor/' + encodeURIComponent(target.vendor)}>{subtitle}</a>
      {:else}{subtitle}{/if}
      {#if !loading && !error && !partial}· {approx ? 'about ' : ''}{total.toLocaleString()} {total === 1 ? 'vulnerability' : 'vulnerabilities'}{/if}
    </div>
  </div>
</header>

<div class="actions row wrap">
  {#each existing as s (s.id)}
    <button class="btn" onclick={() => (editing = s)}>
      <Icon name="check" /> Watching{existing.length > 1 ? `: ${s.name}` : ''}
    </button>
  {/each}
  {#if !existing.length}
    <button class="btn primary" onclick={subscribe}><Icon name="bell" /> Get alerts</button>
  {:else}
    <button class="btn ghost sm" onclick={subscribe}><Icon name="plus" size={18} /> Another alert rule</button>
  {/if}
</div>

{#if loading}
  <div class="loading"><span class="spinner"></span> Loading from vulnerability databases…</div>
{:else if error}
  <div class="card empty">
    <h2>Could not load this list</h2>
    <p>{error}</p>
    <p style="margin-top:1rem"><button class="btn" onclick={() => load(true)}><Icon name="refresh" /> Try again</button></p>
  </div>
{:else}
  <div class="tools stack">
    <div class="row wrap">
      <div class="seg sortseg" role="group" aria-label="Sort">
        <button class:on={sort === 'newest'} onclick={() => (sort = 'newest')}>Newest</button>
        <button class:on={sort === 'severity'} onclick={() => (sort = 'severity')}>Most severe</button>
        <button class:on={sort === 'epss'} onclick={() => (sort = 'epss')}>Most likely</button>
      </div>
      <input class="input grow find" bind:value={text} placeholder="Filter this list" aria-label="Filter this list" />
      <button class="btn ghost sm" onclick={() => load(true)} aria-label="Refresh" title="Refresh"><Icon name="refresh" /></button>
    </div>
    <div class="chips">
      {#each ['low', 'medium', 'high', 'critical'] as const as s}
        <button class="chip" class:on={minSev === s} onclick={() => (minSev = minSev === s ? null : s)}>
          {s === 'critical' ? 'Critical' : cap(s) + '+'}
        </button>
      {/each}
      <button class="chip" class:on={exploitedOnly} onclick={() => (exploitedOnly = !exploitedOnly)}>
        <Icon name="flame" size={16} /> Exploited{exploitedCount ? ` (${exploitedCount})` : ''}
      </button>
    </div>
    <div class="chips" role="group" aria-label="How it can be attacked">
      {#each vectorNames as [v, label]}
        <button class="chip" class:on={vectors.includes(v)} onclick={() => toggleVector(v)}>{label}</button>
      {/each}
    </div>
  </div>

  {#each notes as n}<p class="muted small note">{n}</p>{/each}

  {#if shown.length}
    <div class="card list">
      {#each shown as v (v.id)}
        <VulnRow vuln={v} />
      {/each}
    </div>
  {:else}
    <div class="card empty">
      <h2>{items.length ? 'Nothing matches these filters' : 'No known vulnerabilities'}</h2>
      <p>{items.length ? 'Loosen the filters above.' : 'None are recorded for this yet. Subscribe to hear about the first one.'}</p>
    </div>
  {/if}

  {#if nextEnd}
    <p class="morebtn">
      <button class="btn" onclick={loadMore} disabled={loadingMore}>
        {#if loadingMore}<span class="spinner"></span>{/if}
        Load older ({(total - items.length > 0 ? total - items.length : nextEnd).toLocaleString()} more)
      </button>
    </p>
  {/if}
{/if}

{#if editing}
  <SubscribeDialog sub={editing} onclose={() => (editing = null)} />
{/if}

<style>
  .head {
    display: flex;
    gap: 0.4rem;
    align-items: flex-start;
  }
  .back {
    margin-left: -0.5rem;
  }
  .actions {
    margin: 0.9rem 0 1.1rem;
  }
  .tools {
    margin-bottom: 0.8rem;
  }
  .sortseg {
    flex: 1 1 300px;
  }
  .find {
    flex: 1 1 180px;
  }
  .list {
    overflow: hidden;
  }
  .note {
    margin-bottom: 0.5rem;
  }
  .morebtn {
    text-align: center;
    margin-top: 1rem;
  }
</style>
