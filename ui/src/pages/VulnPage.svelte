<script lang="ts">
  import type { Vuln } from '../lib/types';
  import { openExternal, rpc } from '../lib/api';
  import { cap, date, pct, score } from '../lib/format';
  import Icon from '../components/Icon.svelte';

  let { id }: { id: string } = $props();

  let v: Vuln | null = $state(null);
  let error = $state('');
  let loading = $state(true);

  async function load(refresh = false) {
    loading = true;
    error = '';
    try {
      v = await rpc('vulns.get', { id, refresh });
    } catch (e) {
      error = (e as Error).message;
    }
    loading = false;
  }
  $effect(() => {
    id;
    v = null;
    load();
  });

  const vectorWords: Record<string, string> = {
    network: 'Remotely, over the network',
    adjacent: 'From the same local network',
    local: 'Needs local access',
    physical: 'Needs physical access',
  };
  const originWords: Record<string, string> = { nvd: 'NVD', vendor: 'the vendor', adp: 'CISA' };
  const host = (u: string) => {
    try {
      return new URL(u).hostname.replace(/^www\./, '');
    } catch {
      return u;
    }
  };
  /** Where this record can be read at the databases it came from (and the other big ones). */
  const sourceLinks = $derived.by(() => {
    if (!v) return [];
    const out: { name: string; note: string; url: string }[] = [];
    const ids = [v.id, ...(v.aliases ?? [])];
    const cve = ids.find((i) => i.startsWith('CVE-'));
    const has = (s: string) => v!.sources.includes(s);
    const used = (s: string) => (has(s) ? 'used for this page' : 'look it up');
    if (cve) {
      out.push({ name: 'NVD', note: used('nvd'), url: `https://nvd.nist.gov/vuln/detail/${cve}` });
      out.push({ name: 'CVE.org', note: used('cve.org'), url: `https://www.cve.org/CVERecord?id=${cve}` });
    }
    for (const id of ids.filter((i) => i.startsWith('GHSA-')).slice(0, 2)) {
      out.push({ name: 'GitHub Advisory', note: id, url: `https://github.com/advisories/${id}` });
    }
    out.push({ name: 'OSV', note: used('osv'), url: `https://osv.dev/vulnerability/${has('osv') && !cve ? v.id : (ids.find((i) => !i.startsWith('CVE-')) ?? v.id)}` });
    if (cve) {
      out.push({ name: 'CIRCL Vulnerability-Lookup', note: used('circl'), url: `https://vulnerability.circl.lu/vuln/${cve}` });
      const euvd = ids.find((i) => i.startsWith('EUVD-'));
      if (euvd) out.push({ name: 'ENISA EUVD', note: used('euvd'), url: `https://euvd.enisa.europa.eu/vulnerability/${euvd}` });
      if (has('cvedetails')) out.push({ name: 'CVEdetails', note: used('cvedetails'), url: `https://www.cvedetails.com/cve/${cve}/` });
      if (v.exploited) out.push({ name: 'CISA Known Exploited', note: 'listed as exploited', url: `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${cve}` });
      out.push({ name: 'EPSS', note: 'exploit likelihood', url: `https://api.first.org/data/v1/epss?cve=${cve}` });
    }
    return out;
  });
  function ext(e: MouseEvent, url: string) {
    e.preventDefault();
    openExternal(url);
  }
</script>

<header class="head">
  <button class="btn ghost sm back" onclick={() => history.back()} aria-label="Back"><Icon name="back" /></button>
  <div class="grow">
    <h1 class="mono">{v?.id ?? id}</h1>
    {#if v?.aliases?.length}<div class="muted small">Also known as {v.aliases.join(', ')}</div>{/if}
  </div>
  <button class="btn ghost sm" onclick={() => load(true)} aria-label="Refresh" title="Refresh"><Icon name="refresh" /></button>
</header>

{#if loading}
  <div class="loading"><span class="spinner"></span> Loading…</div>
{:else if error || !v}
  <div class="card empty">
    <h2>Could not load {id}</h2>
    <p>{error}</p>
    <p style="margin-top:1rem"><button class="btn" onclick={() => load(true)}><Icon name="refresh" /> Try again</button></p>
  </div>
{:else}
  {#if v.exploited}
    <div class="alert">
      <Icon name="flame" size={22} />
      <div><b>Being exploited in the wild</b><br /><span class="small">Listed in CISA's Known Exploited Vulnerabilities catalog{v.kev_added ? ` since ${date(v.kev_added)}` : ''}. Patch first.</span></div>
    </div>
  {/if}

  <div class="facts">
    <div class="card fact sev-{v.severity ?? 'none'}">
      <span class="k">Severity</span>
      <b class="big">{score(v)}</b>
      <span>{v.severity ? cap(v.severity) : 'Not scored yet'}</span>
    </div>
    <div class="card fact">
      <span class="k">Attack</span>
      <b>{v.attack_vector ? vectorWords[v.attack_vector] : 'Unknown'}</b>
    </div>
    <div class="card fact">
      <span class="k">Chance of exploitation</span>
      <b class="big">{v.epss != null ? pct(v.epss) : '–'}</b>
      <span class="small">{v.epss != null ? `in 30 days (EPSS), higher than ${pct(v.epss_percentile)} of CVEs` : 'No EPSS estimate yet'}</span>
    </div>
    <div class="card fact">
      <span class="k">Fix</span>
      <b>{v.fixed_in.length ? v.fixed_in.slice(0, 4).join(', ') : 'Not stated'}</b>
      {#if v.fixed_in.length}<span class="small">Update to this version or later</span>{/if}
    </div>
  </div>

  <section class="card pad stack">
    {#if v.title}<h2>{v.title}</h2>{/if}
    <p class="desc">{v.description || v.summary}</p>
    <div class="muted small">
      Published {date(v.published) || 'unknown'}{v.modified ? ` · updated ${date(v.modified)}` : ''}
      {#if v.status} · {v.status}{/if}
      · sources: {v.sources.join(', ')}
    </div>
  </section>

  {#if v.products?.length}
    <section class="card pad stack">
      <h2>Affected</h2>
      <div class="chips">
        {#each v.products as p}<span class="badge prod">{p}</span>{/each}
      </div>
    </section>
  {/if}

  {#if v.scores?.length || v.cwes?.length}
    <section class="card pad stack">
      <h2>Scoring details</h2>
      {#each v.scores ?? [] as s}
        <div class="small">
          <b>CVSS {s.version}: {s.base.toFixed(1)}</b> <span class="muted">by {originWords[s.origin] ?? s.origin}</span>
          {#if s.vector}<div class="mono muted">{s.vector}</div>{/if}
        </div>
      {/each}
      {#if v.cwes?.length}
        <div class="small"><b>Weakness:</b> {v.cwes.join(', ')}</div>
      {/if}
    </section>
  {/if}

  <section class="card pad stack">
    <h2>Sources</h2>
    <p class="hint">Open this vulnerability at the databases it comes from.</p>
    {#each sourceLinks as l}
      <a class="link" href={l.url} onclick={(e) => ext(e, l.url)} rel="noreferrer"><Icon name="external" size={18} /> <span><b>{l.name}</b> <span class="muted small">{l.note}</span></span></a>
    {/each}
  </section>

  {#if v.references?.length}
    <section class="card pad stack">
      <h2>References</h2>
      <p class="hint">Advisories, patches and write-ups linked from the record.</p>
      {#each v.references as r}
        <a class="link" href={r} onclick={(e) => ext(e, r)} rel="noreferrer"><Icon name="external" size={18} /> <span>{host(r)}<span class="muted small path"> {r.replace(/^https?:\/\/[^/]+/, '').slice(0, 70)}</span></span></a>
      {/each}
    </section>
  {/if}
{/if}

<style>
  .head {
    display: flex;
    gap: 0.4rem;
    align-items: flex-start;
    margin-bottom: 1rem;
  }
  .back {
    margin-left: -0.5rem;
  }
  .alert {
    display: flex;
    gap: 0.7rem;
    align-items: flex-start;
    padding: 0.9rem 1rem;
    border-radius: var(--radius);
    background: var(--crit-bg);
    color: var(--crit);
    margin-bottom: 0.8rem;
  }
  .facts {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 0.7rem;
    margin-bottom: 0.8rem;
  }
  .fact {
    padding: 0.8rem 0.9rem;
    display: flex;
    flex-direction: column;
    gap: 0.1rem;
  }
  .fact .k {
    font-size: 0.74rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    opacity: 0.8;
  }
  .fact .big {
    font-size: 1.7rem;
    line-height: 1.1;
  }
  section {
    margin-bottom: 0.8rem;
  }
  .desc {
    white-space: pre-line;
  }
  .prod {
    font-weight: 550;
    font-size: 0.82rem;
    white-space: normal;
  }
  .link {
    display: flex;
    gap: 0.5rem;
    align-items: flex-start;
    min-height: 32px;
  }
  .link :global(svg) {
    flex: none;
    margin-top: 2px;
  }
  .path {
    word-break: break-all;
  }
</style>
