<script lang="ts">
  import { untrack } from 'svelte';

  // A row of preset values plus "Custom", which opens a field for any number. `max` is only
  // what the setting can physically hold; it is not shown.
  let {
    value = $bindable(),
    options,
    label,
    min = 1,
    max,
    unit,
  }: { value: number; options: number[]; label: (n: number) => string; min?: number; max: number; unit: string } = $props();

  let custom = $state(untrack(() => !options.includes(value)));
  let text = $state('');
  $effect(() => {
    text = String(value);
  });

  // Applied when the field is left or Enter is pressed, so half-typed numbers are never saved.
  function commit() {
    const n = Math.round(Number(text));
    if (text.trim() !== '' && Number.isFinite(n)) value = Math.min(max, Math.max(min, n));
    text = String(value);
  }
</script>

<div class="seg" style="grid-auto-flow: row; grid-template-columns: repeat({options.length}, 1fr) auto">
  {#each options as o}
    <button class:on={!custom && value === o} onclick={() => ((custom = false), (value = o))}>{label(o)}</button>
  {/each}
  <button class="more" class:on={custom} onclick={() => (custom = true)}>Custom</button>
</div>
{#if custom}
  <label class="custom">
    <input type="text" inputmode="numeric" bind:value={text} onchange={commit} onkeydown={(e) => e.key === 'Enter' && commit()} aria-label="Custom value in {unit}" />
    <span>{unit}{#if min > 1} <span class="range">({min} or more)</span>{/if}</span>
  </label>
{/if}

<style>
  .seg button {
    white-space: nowrap;
    padding: 0 0.1rem;
  }
  .seg .more {
    padding: 0 0.6rem;
  }
  .custom {
    display: flex;
    align-items: center;
    gap: 0.6rem;
    font-weight: 500;
  }
  .custom input {
    width: 6.5rem;
    min-height: 40px;
    padding: 0 0.7rem;
    border: 1px solid var(--border);
    border-radius: 10px;
    background: var(--surface);
    color: var(--text);
    font: inherit;
  }
  .range {
    color: var(--muted);
  }
</style>
