<script lang="ts">
  import type { Product } from '../lib/types';
  import { rpc } from '../lib/api';
  import { app, call, go } from '../lib/state.svelte';
  import { partLabel, pretty, targetPath } from '../lib/format';
  import Icon from '../components/Icon.svelte';

  let q = $state(sessionStorage.getItem('vw-q') ?? '');
  let products: Product[] = $state([]);
  let vulnId: string | null = $state(null);
  let online: Product[] | null = $state(null);
  let packages: { ecosystem: string; name: string; count: number }[] | null = $state(null);
  let busy = $state('');
  const term = $derived(q.trim());

  let seq = 0;
  $effect(() => {
    const text = term;
    sessionStorage.setItem('vw-q', text);
    online = null;
    packages = null;
    const mine = ++seq;
    if (text.length < 2) {
      products = [];
      vulnId = null;
      return;
    }
    // The catalog is bundled, so this is instant: search on every keystroke.
    rpc('search', { q: text })
      .then((r) => {
        if (mine !== seq) return;
        products = r.products;
        vulnId = r.vuln_id;
      })
      .catch(() => {});
  });

  async function searchOnline() {
    busy = 'online';
    const r = await call('search.online', { q: term });
    busy = '';
    if (r) online = r.products;
  }

  async function searchPackages() {
    busy = 'packages';
    const r = await call('search.packages', { q: term });
    busy = '';
    if (r) packages = r.packages;
  }

  function submit(e: Event) {
    e.preventDefault();
    if (vulnId) go('/cve/' + encodeURIComponent(vulnId));
    else if (products.length) go(targetPath({ kind: 'product', vendor: products[0].vendor, product: products[0].product, keywords: [] }));
  }

  const examples = ['OpenSSH', 'Chrome', 'Windows 11', 'nginx', 'FortiOS', 'WordPress', 'Linux kernel', 'log4j'];
</script>

{#snippet productRow(p: Product)}
  <a class="hit" href={'#' + targetPath({ kind: 'product', vendor: p.vendor, product: p.product, keywords: [] })}>
    <span class="ico"><Icon name={p.part === 'o' ? 'shield' : p.part === 'h' ? 'box' : 'tag'} /></span>
    <span class="grow">
      <b>{p.title}</b>
      <span class="muted small">{partLabel(p.part)} · {pretty(p.vendor)}</span>
    </span>
    <Icon name="chevron" />
  </a>
{/snippet}

<section class="hero" class:compact={term.length >= 2}>
  {#if term.length < 2}
    <h1>What do you want to watch?</h1>
    <p class="muted">Find a product, see every known vulnerability, and get alerted about new ones.</p>
  {/if}
  <form class="search" onsubmit={submit} role="search">
    <Icon name="search" size={22} />
    <!-- svelte-ignore a11y_autofocus -->
    <input bind:value={q} placeholder="Product, vendor, package or CVE id" aria-label="Search" autocomplete="off" autocapitalize="off" spellcheck="false" autofocus={!app.status?.mobile} />
    {#if q}<button type="button" class="btn ghost sm" onclick={() => (q = '')} aria-label="Clear"><Icon name="x" /></button>{/if}
  </form>
</section>

{#if term.length < 2}
  <div class="chips center">
    {#each examples as e}
      <button class="chip" onclick={() => (q = e)}>{e}</button>
    {/each}
  </div>

  <div class="quick">
    <a class="card pad tile" href="#/latest">
      <Icon name="globe" size={26} />
      <b>Latest vulnerabilities</b>
      <span class="muted small">Everything published recently, newest first</span>
    </a>
    <a class="card pad tile" href="#/subs">
      <Icon name="eye" size={26} />
      <b>{app.subs.length ? `Watching ${app.subs.length}` : 'Nothing watched yet'}</b>
      <span class="muted small">{app.subs.length ? app.subs.slice(0, 3).map((s) => s.name).join(', ') : 'Search for a product to start'}</span>
    </a>
  </div>
{:else}
  <div class="card results">
    {#if vulnId}
      <a class="hit" href={'#/cve/' + encodeURIComponent(vulnId)}>
        <span class="ico"><Icon name="shield" /></span>
        <span class="grow"><b class="mono">{vulnId}</b><span class="muted small">Open this vulnerability</span></span>
        <Icon name="chevron" />
      </a>
    {/if}
    {#each products as p (p.vendor + ':' + p.product)}
      {@render productRow(p)}
    {/each}
    {#if !products.length && !vulnId}
      <div class="empty">
        <h2>No product named "{term}" in the catalog</h2>
        <p>Try the options below — new products and software packages are found there.</p>
      </div>
    {/if}
  </div>

  <h2 class="section">More ways to watch "{term}"</h2>
  <div class="card results">
    <a class="hit" href={'#' + targetPath({ kind: 'keyword', keywords: [term] })}>
      <span class="ico"><Icon name="search" /></span>
      <span class="grow"><b>Any vulnerability mentioning "{term}"</b><span class="muted small">Keyword watch — good for things that are not in the product catalog</span></span>
      <Icon name="chevron" />
    </a>
    <button class="hit" onclick={searchPackages} disabled={busy === 'packages'}>
      <span class="ico"><Icon name="box" /></span>
      <span class="grow"><b>Find a package named "{term}"</b><span class="muted small">npm, PyPI, Go, crates.io, Maven, Debian and more (exact name)</span></span>
      {#if busy === 'packages'}<span class="spinner"></span>{/if}
    </button>
    {#if packages}
      {#each packages as p}
        <a class="hit sub" href={'#' + targetPath({ kind: 'package', ecosystem: p.ecosystem, name: p.name })}>
          <span class="grow"><b>{p.name}</b> <span class="badge accent">{p.ecosystem}</span><span class="muted small">{p.count} known {p.count === 1 ? 'advisory' : 'advisories'}</span></span>
          <Icon name="chevron" />
        </a>
      {:else}
        <div class="hit sub muted">No package with exactly that name has advisories.</div>
      {/each}
    {/if}
    <button class="hit" onclick={searchOnline} disabled={busy === 'online'}>
      <span class="ico"><Icon name="globe" /></span>
      <span class="grow"><b>Search NVD's live product dictionary</b><span class="muted small">For products added since this app's catalog was built</span></span>
      {#if busy === 'online'}<span class="spinner"></span>{/if}
    </button>
    {#if online}
      {#each online as p (p.vendor + ':' + p.product)}
        {@render productRow(p)}
      {:else}
        <div class="hit sub muted">NVD has no matching product either.</div>
      {/each}
    {/if}
  </div>
{/if}

<style>
  .hero {
    text-align: center;
    padding: 9vh 0 1.2rem;
    display: flex;
    flex-direction: column;
    gap: 0.6rem;
  }
  .hero.compact {
    padding-top: 0.3rem;
  }
  .hero h1 {
    font-size: clamp(1.6rem, 5vw, 2.2rem);
  }
  .search {
    margin-top: 0.8rem;
    display: flex;
    align-items: center;
    gap: 0.6rem;
    padding: 0 0.6rem 0 1rem;
    min-height: 56px;
    border-radius: 18px;
    border: 1.5px solid var(--border);
    background: var(--surface);
    box-shadow: var(--shadow);
    color: var(--muted);
  }
  .search:focus-within {
    border-color: var(--accent);
  }
  .search input {
    flex: 1;
    min-width: 0;
    border: 0;
    outline: 0;
    background: transparent;
    font-size: 1.08rem;
    color: var(--text);
    min-height: 52px;
  }
  .center {
    justify-content: center;
  }
  .quick {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
    gap: 0.8rem;
    margin-top: 2rem;
  }
  .tile {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
    color: inherit;
    text-decoration: none;
  }
  .tile :global(svg) {
    color: var(--accent);
  }
  .tile:hover {
    border-color: var(--accent);
  }
  .results {
    overflow: hidden;
  }
  .section {
    margin: 1.4rem 0 0.6rem;
  }
  .hit {
    display: flex;
    align-items: center;
    gap: 0.8rem;
    width: 100%;
    padding: 0.75rem 1rem;
    min-height: 60px;
    border: 0;
    border-bottom: 1px solid var(--border);
    background: transparent;
    text-align: left;
    color: inherit;
    text-decoration: none;
    cursor: pointer;
  }
  .hit:last-child {
    border-bottom: 0;
  }
  a.hit:hover,
  button.hit:hover {
    background: var(--surface-2);
  }
  .hit .grow {
    display: flex;
    flex-direction: column;
  }
  .hit.sub {
    padding-left: 3.6rem;
    background: var(--surface-2);
  }
  .hit.sub .grow {
    display: block;
  }
  .hit.sub .muted.small {
    display: block;
  }
  .ico {
    flex: none;
    width: 38px;
    height: 38px;
    border-radius: 11px;
    display: grid;
    place-items: center;
    background: var(--accent-soft);
    color: var(--accent);
  }
  .hit > :global(svg) {
    color: var(--muted);
    flex: none;
  }
</style>
