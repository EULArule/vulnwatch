<script lang="ts">
  import type { AttackVector, CheckStep, Severity, Subscription, Target, Vuln } from '../lib/types';
  import { defaultFilter } from '../lib/types';
  import { rpc } from '../lib/api';
  import { app, call, refreshStatus, refreshSubs, toast } from '../lib/state.svelte';
  import { pretty, secs, sevRank } from '../lib/format';
  import Icon from '../components/Icon.svelte';
  import VulnRow from '../components/VulnRow.svelte';
  import SubscribeDialog from '../components/SubscribeDialog.svelte';
  import Steps from '../components/Steps.svelte';

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
  /** What the current (or last) load waited for, source by source, as in a check. */
  let steps: CheckStep[] = $state([]);
  let elapsed = $state(0);
  let showSteps = $state(false);
  let loads = 0;

  let sort: 'newest' | 'severity' | 'epss' = $state('newest');
  let minSev: Severity | null = $state(null);
  let exploitedOnly = $state(false);
  let vectors: AttackVector[] = $state([]);
  const vectorNames: [AttackVector, string][] = [
    ['network', 'Remote'],
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
    const n = ++loads;
    const current = () => n === loads && t === target;
    loading = true;
    partial = false;
    error = '';
    steps = [];
    elapsed = 0;
    let done = false;
    const job = Math.random().toString(36).slice(2) + Date.now().toString(36);
    const started = Date.now();
    (async () => {
      while (!done && current()) {
        await new Promise((r) => setTimeout(r, 400));
        if (done || !current()) break;
        elapsed = Date.now() - started;
        const p = await rpc<{ steps: CheckStep[] }>('vulns.progress', { job }).catch(() => null);
        if (p && !done && current()) steps = p.steps;
      }
    })();
    if (!refresh && t.kind === 'product') {
      // Something to read within a second or so, while the complete list is fetched.
      rpc('vulns.list', { target: t, quick: true, job })
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
      const r = await rpc('vulns.list', { target: t, refresh, job });
      if (!current()) return;
      steps = r.steps ?? [];
      items = r.items;
      total = r.total;
      approx = !!r.approx;
      nextEnd = r.next_end;
      notes = r.notes;
      if (r.new_alerts) {
        toast(`${r.new_alerts} new alert${r.new_alerts === 1 ? '' : 's'} from this list`);
        refreshStatus();
        refreshSubs();
      }
    } catch (e) {
      if (!current()) return;
      // Which source failed, for the error card.
      const p = await rpc<{ steps: CheckStep[] }>('vulns.progress', { job }).catch(() => null);
      if (p && current()) steps = p.steps;
      if (!partial) error = (e as Error).message;
      else notes = ['Could not load the full list: ' + (e as Error).message];
    }
    done = true;
    elapsed = Date.now() - started;
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
    <div class="muted small meta">
      {#if target.kind === 'product'}
        <a href={'#/vendor/' + encodeURIComponent(target.vendor)}>{subtitle}</a>
      {:else}{subtitle}{/if}
      {#if !loading && !error && !partial}· {approx ? 'about ' : ''}{total.toLocaleString()} {total === 1 ? 'vulnerability' : 'vulnerabilities'}{/if}
      {#if !loading && !partial && steps.length}
        · <button class="link" onclick={() => (showSteps = !showSteps)} aria-expanded={showSteps} title="What loading this list did">{secs(elapsed)}</button>
      {/if}
    </div>
  </div>
  <div class="watch">
    {#each existing as s (s.id)}
      <button class="btn sm" onclick={() => (editing = s)} title={s.name}>
        <Icon name="check" size={18} /> Watching{existing.length > 1 ? `: ${s.name}` : ''}
      </button>
    {/each}
    {#if !existing.length}
      <button class="btn primary sm" onclick={subscribe}><Icon name="bell" size={18} /> Get alerts</button>
    {:else}
      <button class="btn ghost sm" onclick={subscribe} aria-label="Another alert rule" title="Another alert rule"><Icon name="plus" size={18} /></button>
    {/if}
  </div>
</header>

{#if loading || partial || (showSteps && steps.length) || (error && steps.length)}
  <Steps {steps} onclose={loading || partial ? undefined : () => (showSteps = false)}>
    {#snippet title()}
      {#if loading || partial}
        Loading{partial ? ' the full list' : ''}… {secs(elapsed, true)}
      {:else}
        Loading took {secs(elapsed)}
      {/if}
    {/snippet}
  </Steps>
{/if}

{#if loading}
  <!-- The steps above say what it is waiting for. -->
{:else if error}
  <div class="card empty">
    <h2>Could not load this list</h2>
    <p>{error}</p>
    <p style="margin-top:1rem"><button class="btn" onclick={() => load(true)}><Icon name="refresh" /> Try again</button></p>
  </div>
{:else}
  <div class="tools">
    <div class="row">
      <input class="input grow" bind:value={text} placeholder="Filter this list" aria-label="Filter this list" />
      <select class="input sort" bind:value={sort} aria-label="Sort">
        <option value="newest">Newest</option>
        <option value="severity">Most severe</option>
        <option value="epss">Most likely</option>
      </select>
      <button class="btn ghost sm" onclick={() => load(true)} aria-label="Refresh" title="Refresh"><Icon name="refresh" /></button>
    </div>
    <div class="chips line" role="group" aria-label="Filters">
      <select class="chip" class:on={minSev} bind:value={minSev} aria-label="Severity">
        <option value={null}>Any severity</option>
        <option value="low">Low+</option>
        <option value="medium">Medium+</option>
        <option value="high">High+</option>
        <option value="critical">Critical</option>
      </select>
      <button class="chip" class:on={exploitedOnly} onclick={() => (exploitedOnly = !exploitedOnly)}>
        <Icon name="flame" size={16} /> Exploited{exploitedCount ? ` (${exploitedCount})` : ''}
      </button>
      {#each vectorNames as [v, label]}
        <button class="chip" class:on={vectors.includes(v)} onclick={() => toggleVector(v)} title="How it can be attacked">{label}</button>
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
    margin-bottom: 0.9rem;
  }
  .back {
    margin-left: -0.5rem;
  }
  .meta {
    margin-top: 0.1rem;
  }
  .watch {
    display: flex;
    flex-wrap: wrap;
    justify-content: flex-end;
    gap: 0.3rem;
    max-width: 50%;
  }
  .watch .btn {
    max-width: 100%;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .link {
    border: 0;
    padding: 0;
    background: none;
    color: inherit;
    font: inherit;
    text-decoration: underline;
    cursor: pointer;
  }
  .tools {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
    margin-bottom: 0.8rem;
  }
  .sort {
    width: auto;
    flex: none;
    padding-right: 0.4rem;
  }
  /* One line of filters that scrolls sideways on a narrow screen, instead of three rows. */
  .line {
    flex-wrap: nowrap;
    overflow-x: auto;
    scrollbar-width: none;
    margin: 0 -1rem;
    padding: 0 1rem;
  }
  .line::-webkit-scrollbar {
    display: none;
  }
  .line .chip {
    flex: none;
    white-space: nowrap;
  }
  select.chip {
    appearance: auto;
    padding-right: 0.4rem;
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
