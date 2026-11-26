<script lang="ts">
  import type { Snippet } from 'svelte';
  import type { CheckStep } from '../lib/types';
  import { secs } from '../lib/format';
  import Icon from './Icon.svelte';

  // What a check, or the loading of a list, waits for: one line per source, with its time.
  let { steps, title, onclose }: { steps: CheckStep[]; title: Snippet; onclose?: () => void } = $props();
</script>

<div class="card steps">
  <div class="row top">
    <b class="grow small">{@render title()}</b>
    {#if onclose}
      <button class="del" onclick={onclose} aria-label="Hide" title="Hide"><Icon name="x" size={16} /></button>
    {/if}
  </div>
  {#each steps as s, i (i)}
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

<style>
  .steps {
    margin-bottom: 0.8rem;
    padding: 0.5rem 1rem 0.6rem;
  }
  .top {
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
  .del {
    display: grid;
    place-items: center;
    width: 2rem;
    height: 2rem;
    margin-right: -0.5rem;
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
</style>
