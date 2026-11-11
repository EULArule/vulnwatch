<script lang="ts">
  import { untrack } from 'svelte';
  import type { AttackVector, Severity, Subscription } from '../lib/types';
  import { cap, filterLabel, pct, targetLabel } from '../lib/format';
  import { rpc } from '../lib/api';
  import { call, refreshSubs, toast } from '../lib/state.svelte';
  import Icon from './Icon.svelte';

  let { sub, onclose }: { sub: Subscription; onclose: (saved: boolean) => void } = $props();

  // Work on a copy so Cancel really cancels.
  let draft: Subscription = $state(untrack(() => JSON.parse(JSON.stringify(sub))));
  const isNew = untrack(() => sub.id === 0);
  const f = $derived(draft.filter);

  let keywords = $state(untrack(() => ('keywords' in sub.target ? sub.target.keywords.join(', ') : '')));
  let include = $state(untrack(() => sub.filter.include_keywords.join(', ')));
  let exclude = $state(untrack(() => sub.filter.exclude_keywords.join(', ')));
  let more = $state(
    untrack(() => {
      const x = sub.filter;
      return !!(x.attack_vectors.length || x.min_epss || x.include_keywords.length || x.exclude_keywords.length || !x.include_unscored || !x.always_if_exploited);
    }),
  );
  let saving = $state(false);
  let preview: { checked: number; passing: number } | null = $state(null);

  const list = (s: string) => s.split(',').map((x) => x.trim()).filter(Boolean);
  const sevs: (Severity | null)[] = [null, 'low', 'medium', 'high', 'critical'];
  const vectors: AttackVector[] = ['network', 'adjacent', 'local', 'physical'];
  const epssSteps: (number | null)[] = [null, 0.01, 0.1, 0.5];
  const hasConditions = $derived(!!(f.min_severity || f.min_cvss || f.attack_vectors.length || f.min_epss));

  function built(): Subscription {
    const s: Subscription = JSON.parse(JSON.stringify(draft));
    if (s.target.kind === 'product' || s.target.kind === 'keyword') s.target.keywords = list(keywords);
    s.filter.include_keywords = list(include);
    s.filter.exclude_keywords = list(exclude);
    return s;
  }

  function toggleVector(v: AttackVector) {
    const set = new Set(f.attack_vectors);
    set.has(v) ? set.delete(v) : set.add(v);
    draft.filter.attack_vectors = vectors.filter((x) => set.has(x));
  }

  // Show how the filter would have treated recent history; makes the choices tangible.
  let timer: ReturnType<typeof setTimeout>;
  $effect(() => {
    const s = built();
    clearTimeout(timer);
    if (s.target.kind === 'keyword' && !s.target.keywords.length) return;
    timer = setTimeout(async () => {
      try {
        preview = await rpc('subs.preview', { target: s.target, filter: s.filter });
      } catch {
        preview = null;
      }
    }, 400);
    return () => clearTimeout(timer);
  });

  async function save() {
    saving = true;
    const r = await call('subs.save', { subscription: built() });
    saving = false;
    if (!r) return;
    await refreshSubs();
    toast(isNew ? `Watching ${r.subscription.name}` : 'Saved');
    onclose(true);
  }

  async function remove() {
    if (!confirm(`Stop watching "${draft.name}"? Its alerts are removed too.`)) return;
    if ((await call('subs.delete', { id: draft.id })) === undefined) return;
    await refreshSubs();
    toast('Removed');
    onclose(true);
  }

  function key(e: KeyboardEvent) {
    if (e.key === 'Escape') onclose(false);
  }
</script>

<svelte:window onkeydown={key} />

<div class="backdrop" onclick={() => onclose(false)} role="presentation"></div>
<div class="sheet card" role="dialog" aria-modal="true" aria-label={isNew ? 'Subscribe' : 'Edit subscription'}>
  <header class="row">
    <div class="grow">
      <h2>{isNew ? 'Get alerts' : 'Edit alerts'}</h2>
      <div class="muted small">{targetLabel(draft.target)}</div>
    </div>
    <button class="btn ghost sm" onclick={() => onclose(false)} aria-label="Close"><Icon name="x" /></button>
  </header>

  <div class="content stack">
    <label class="field">
      Name
      <input class="input" bind:value={draft.name} placeholder="Shown on alerts" />
    </label>

    {#if draft.target.kind === 'product' || draft.target.kind === 'keyword'}
      <label class="field">
        {draft.target.kind === 'product' ? 'Also match these words' : 'Words or phrases to watch for'}
        <input class="input" bind:value={keywords} placeholder="comma separated" autocapitalize="off" />
        <span class="hint">
          {#if draft.target.kind === 'product'}
            Brand-new CVEs often have no product data yet. A vulnerability whose description mentions one of these phrases also counts. Leave empty for exact product matches only.
          {:else}
            Matches whole words, anywhere in a vulnerability's title or description.
          {/if}
        </span>
      </label>
    {/if}

    <div class="field">
      Alert me about
      <div class="seg" role="group" aria-label="Minimum severity">
        {#each sevs as s}
          <button class:on={f.min_severity === s} onclick={() => (draft.filter.min_severity = s)}>
            {s === null ? 'Any' : s === 'critical' ? 'Critical' : cap(s) + '+'}
          </button>
        {/each}
      </div>
      <span class="hint">Minimum severity. "High+" means high and critical.</span>
    </div>

    <label class="field">
      Minimum CVSS score
      <div class="row cvss">
        <input
          class="input"
          type="number"
          min="0"
          max="10"
          step="0.1"
          inputmode="decimal"
          placeholder="Any"
          value={f.min_cvss ?? ''}
          oninput={(e) => {
            const n = parseFloat(e.currentTarget.value);
            draft.filter.min_cvss = Number.isFinite(n) && n > 0 ? Math.min(10, Math.round(n * 10) / 10) : null;
          }}
        />
        <div class="chips">
          {#each [4, 7, 9] as c}
            <button class="chip" class:on={f.min_cvss === c} onclick={() => (draft.filter.min_cvss = f.min_cvss === c ? null : c)}>{c.toFixed(1)}+</button>
          {/each}
        </div>
      </div>
      <span class="hint">Exact cut-off from 0.1 to 10, e.g. 7.5. Leave empty for any score.</span>
    </label>

    <label class="switch">
      <span class="label">Only if exploited in the wild<small>Listed in CISA's Known Exploited Vulnerabilities catalog</small></span>
      <input type="checkbox" bind:checked={draft.filter.exploited_only} />
    </label>

    <button class="btn ghost sm more" onclick={() => (more = !more)} aria-expanded={more}>
      <span class="rot" class:open={more}><Icon name="chevron" size={18} /></span>
      More filters
    </button>

    {#if more}
      <div class="stack more-box">
        <div class="field">
          How it can be attacked
          <div class="chips">
            {#each vectors as v}
              <button class="chip" class:on={f.attack_vectors.includes(v)} onclick={() => toggleVector(v)}>
                {v === 'network' ? 'Over the network' : v === 'adjacent' ? 'Same network' : v === 'local' ? 'Local access' : 'Physical access'}
              </button>
            {/each}
          </div>
          <span class="hint">{f.attack_vectors.length ? 'Only the selected kinds.' : 'Nothing selected = any.'}</span>
        </div>

        <div class="field">
          Likelihood of exploitation (EPSS)
          <div class="seg" role="group" aria-label="Minimum EPSS">
            {#each epssSteps as p}
              <button class:on={(f.min_epss ?? null) === p} onclick={() => (draft.filter.min_epss = p)}>
                {p === null ? 'Any' : '≥ ' + pct(p)}
              </button>
            {/each}
          </div>
          <span class="hint">Estimated chance it is exploited within 30 days. Most CVEs are below 1%.</span>
        </div>

        {#if hasConditions}
          <label class="switch">
            <span class="label">Include ones without a score yet<small>New CVEs usually start unscored. Turn off to wait for a score (you may hear later).</small></span>
            <input type="checkbox" bind:checked={draft.filter.include_unscored} />
          </label>
        {/if}

        {#if hasConditions && !f.exploited_only}
          <label class="switch">
            <span class="label">Always alert when exploited<small>Even if it is below the levels chosen above</small></span>
            <input type="checkbox" bind:checked={draft.filter.always_if_exploited} />
          </label>
        {/if}

        <label class="field">
          Must mention
          <input class="input" bind:value={include} placeholder="e.g. remote code execution, authentication" autocapitalize="off" />
        </label>
        <label class="field">
          Ignore if it mentions
          <input class="input" bind:value={exclude} placeholder="e.g. windows, plugin" autocapitalize="off" />
        </label>
      </div>
    {/if}

    <label class="switch">
      <span class="label">Send notifications<small>Off = alerts are only listed in the app</small></span>
      <input type="checkbox" bind:checked={draft.notify} />
    </label>
    {#if !isNew}
      <label class="switch">
        <span class="label">Active</span>
        <input type="checkbox" bind:checked={draft.enabled} />
      </label>
    {/if}

    <div class="preview small">
      <b>{filterLabel(built().filter)}</b>
      {#if preview && preview.checked > 0}
        <div class="muted">
          {preview.passing} of the {preview.checked} most recent {preview.passing === 1 ? 'vulnerability' : 'vulnerabilities'} would have alerted you.
        </div>
      {/if}
    </div>
  </div>

  <footer class="row">
    {#if !isNew}
      <button class="btn danger" onclick={remove} aria-label="Delete"><Icon name="trash" /></button>
    {/if}
    <button class="btn grow" onclick={() => onclose(false)}>Cancel</button>
    <button class="btn primary grow" onclick={save} disabled={saving}>
      {isNew ? 'Subscribe' : 'Save'}
    </button>
  </footer>
</div>

<style>
  .cvss {
    gap: 10px;
    flex-wrap: wrap;
  }
  .cvss .input {
    width: 110px;
    flex: none;
  }
  .backdrop {
    position: fixed;
    inset: 0;
    background: rgb(0 0 0 / 45%);
    z-index: 40;
  }
  .sheet {
    position: fixed;
    z-index: 41;
    left: 50%;
    top: 50%;
    transform: translate(-50%, -50%);
    width: min(540px, calc(100vw - 2rem));
    max-height: min(88vh, 860px);
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }
  header,
  footer {
    padding: 0.9rem 1rem;
    flex: none;
  }
  header {
    border-bottom: 1px solid var(--border);
  }
  footer {
    border-top: 1px solid var(--border);
    padding-bottom: calc(0.9rem + env(safe-area-inset-bottom));
  }
  .content {
    padding: 1rem;
    overflow-y: auto;
    gap: 1rem;
  }
  .field {
    display: flex;
    flex-direction: column;
    gap: 0.35rem;
    font-weight: 600;
    font-size: 0.92rem;
  }
  .more {
    align-self: flex-start;
    padding-left: 0.3rem;
  }
  .rot {
    display: inline-flex;
    transition: transform 0.15s;
  }
  .rot.open {
    transform: rotate(90deg);
  }
  .more-box {
    gap: 1rem;
    padding: 1rem;
    border-radius: 12px;
    background: var(--surface-2);
  }
  .preview {
    padding: 0.7rem 0.9rem;
    border-radius: 12px;
    background: var(--accent-soft);
  }
  @media (max-width: 640px) {
    .sheet {
      left: 0;
      right: 0;
      bottom: 0;
      top: auto;
      transform: none;
      width: 100%;
      max-height: 92vh;
      border-radius: 20px 20px 0 0;
      border-bottom: 0;
    }
  }
</style>
