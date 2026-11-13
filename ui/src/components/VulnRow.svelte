<script lang="ts">
  import type { Vuln } from '../lib/types';
  import { cap, date, pct, score } from '../lib/format';

  import { remember } from '../lib/seen';

  let { vuln, unread = false }: { vuln: Vuln; unread?: boolean } = $props();
  $effect(() => remember(vuln));
</script>

<a class="vuln" class:unread href={'#/cve/' + encodeURIComponent(vuln.id)}>
  <span class="score sev-{vuln.severity ?? 'none'}" title={vuln.severity ? cap(vuln.severity) : 'Not scored yet'}>
    <b>{score(vuln)}</b>
    <small>{vuln.severity ? cap(vuln.severity) : 'No score'}</small>
  </span>
  <span class="body">
    <span class="top">
      <span class="id mono">{vuln.id}</span>
      {#if vuln.exploited}<span class="badge exploited">Exploited</span>{/if}
      {#if vuln.epss != null && vuln.epss >= 0.1}<span class="badge" title="Chance of exploitation in the next 30 days (EPSS)">EPSS {pct(vuln.epss)}</span>{/if}
      <span class="when muted small">{date(vuln.published)}</span>
    </span>
    <span class="text">{vuln.title || vuln.summary}</span>
    {#if vuln.fixed_in?.length}
      <span class="muted small">Fixed in {vuln.fixed_in.slice(0, 3).join(', ')}</span>
    {/if}
  </span>
</a>

<style>
  .vuln {
    display: flex;
    gap: 0.8rem;
    padding: 0.8rem 1rem;
    color: inherit;
    text-decoration: none;
    border-bottom: 1px solid var(--border);
    align-items: flex-start;
  }
  .vuln:last-child {
    border-bottom: 0;
  }
  .vuln:hover {
    background: var(--surface-2);
  }
  .score {
    flex: none;
    width: 62px;
    border-radius: 12px;
    padding: 0.35rem 0;
    display: flex;
    flex-direction: column;
    align-items: center;
    line-height: 1.15;
  }
  .score b {
    font-size: 1.15rem;
  }
  .score small {
    font-size: 0.68rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.02em;
  }
  .body {
    display: flex;
    flex-direction: column;
    gap: 0.15rem;
    min-width: 0;
    flex: 1;
  }
  .top {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 0.4rem;
  }
  .id {
    font-weight: 700;
  }
  .when {
    margin-left: auto;
  }
  .text {
    display: -webkit-box;
    -webkit-line-clamp: 2;
    line-clamp: 2;
    -webkit-box-orient: vertical;
    overflow: hidden;
    font-size: 0.93rem;
  }
  .unread .id::before {
    content: '';
    display: inline-block;
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--accent);
    margin-right: 0.4rem;
    vertical-align: middle;
  }
</style>
