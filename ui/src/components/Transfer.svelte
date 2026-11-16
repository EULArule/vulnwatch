<script lang="ts">
  // Export and import: the settings, what is watched and the alerts received, as one file.
  import { isApp } from '../lib/api';
  import { app, call, check, refreshStatus, refreshSubs, toast } from '../lib/state.svelte';

  let { onimported }: { onimported: () => void } = $props();

  // The phone has no downloads; there the file goes through Android's "save as" or share sheet.
  const phone = $derived(isApp && !!app.status?.mobile);
  let busy = $state(false);

  let out = $state({ settings: true, secrets: false, subscriptions: true, alerts: false });
  const nothing = $derived(!out.settings && !out.subscriptions);

  async function make(how: 'save' | 'share') {
    busy = true;
    const r = await call<{ export: unknown; name: string }>('data.export', {
      settings: out.settings,
      secrets: out.settings && out.secrets,
      subscriptions: out.subscriptions,
      alerts: out.subscriptions && out.alerts,
    });
    busy = false;
    if (!r) return;
    const text = JSON.stringify(r.export, null, 2);
    if (phone) {
      await call(how === 'share' ? 'android.share_file' : 'android.save_file', { name: r.name, text });
      return;
    }
    const url = URL.createObjectURL(new Blob([text], { type: 'application/json' }));
    const a = document.createElement('a');
    a.href = url;
    a.download = r.name;
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 10_000);
  }

  interface Doc {
    vulnwatch_export?: number;
    version?: string;
    exported_at?: string;
    settings?: Record<string, unknown>;
    subscriptions?: unknown[];
    alerts?: unknown[];
  }
  let picker: HTMLInputElement;
  let found = $state<{ name: string; data: Doc } | null>(null);
  let take = $state({ settings: true, subscriptions: true, alerts: true });
  const PRIVATE = ['nvd_api_key', 'cvedetails_token', 'ntfy', 'webhook', 'remote'];
  const hasSecrets = $derived(!!found?.data.settings && PRIVATE.some((k) => k in found!.data.settings!));
  const count = (n: number, one: string, many = one + 's') => `${n} ${n === 1 ? one : many}`;

  async function picked() {
    const file = picker.files?.[0];
    picker.value = '';
    if (!file) return;
    let data: Doc | null = null;
    try {
      data = JSON.parse(await file.text());
    } catch {
      /* said below */
    }
    if (!data || typeof data.vulnwatch_export !== 'number') return toast('That file is not a vulnwatch export', 'error');
    take = { settings: !!data.settings, subscriptions: !!data.subscriptions, alerts: !!data.alerts };
    if (!take.settings && !take.subscriptions) return toast('There is nothing to import in that file', 'error');
    found = { name: file.name, data };
  }

  type Counts = { added: number; existing: number };
  async function bring() {
    if (!found) return;
    busy = true;
    const r = await call<{ settings: boolean; subscriptions?: Counts; alerts?: Counts }>('data.import', {
      data: found.data,
      settings: take.settings,
      subscriptions: take.subscriptions,
      alerts: take.subscriptions && take.alerts,
    });
    busy = false;
    if (!r) return;
    const parts: string[] = [];
    if (r.settings) parts.push('settings');
    if (r.subscriptions) {
      const { added, existing } = r.subscriptions;
      parts.push(`${added} watched${existing ? ` (${existing} already there)` : ''}`);
    }
    if (r.alerts) parts.push(count(r.alerts.added, 'alert'));
    toast(`Imported: ${parts.join(', ')}`);
    found = null;
    refreshSubs();
    refreshStatus();
    check.changes++;
    if (r.settings) onimported();
  }
</script>

<section class="card pad stack">
  <h2>Export and import</h2>
  <p class="hint">Put your setup in a file: to move it to another device, to keep a copy, or to share what you watch with someone.</p>

  <label class="switch">
    <span class="label">Settings<small>Everything on this page</small></span>
    <input type="checkbox" bind:checked={out.settings} />
  </label>
  {#if out.settings}
    <label class="switch sub">
      <span class="label">With keys and channels<small>API keys, ntfy, webhook and server connection. Leave off when the file is for someone else.</small></span>
      <input type="checkbox" bind:checked={out.secrets} />
    </label>
  {/if}
  <label class="switch">
    <span class="label">What you watch<small>{count(app.subs.length || (app.status?.subscriptions ?? 0), 'subscription')}, each with its filter</small></span>
    <input type="checkbox" bind:checked={out.subscriptions} />
  </label>
  {#if out.subscriptions}
    <label class="switch sub">
      <span class="label">With the alerts received<small>The whole alert list, including what you have read</small></span>
      <input type="checkbox" bind:checked={out.alerts} />
    </label>
  {/if}

  <div class="row buttons">
    {#if phone}
      <button class="btn primary" onclick={() => make('save')} disabled={busy || nothing}>Save to a file</button>
      <button class="btn" onclick={() => make('share')} disabled={busy || nothing}>Share</button>
    {:else}
      <button class="btn primary" onclick={() => make('save')} disabled={busy || nothing}>Export to a file</button>
    {/if}
    <button class="btn" onclick={() => picker.click()} disabled={busy}>Import from a file</button>
    <input bind:this={picker} type="file" accept={phone ? undefined : '.json,application/json'} onchange={picked} hidden />
  </div>

  {#if found}
    <div class="nest stack">
      <div>
        <b>{found.name}</b>
        <div class="muted small">
          {found.data.exported_at ? `Exported ${new Date(found.data.exported_at).toLocaleString()}` : 'A vulnwatch export'}{found.data.version ? ` by vulnwatch ${found.data.version}` : ''}
        </div>
      </div>
      {#if found.data.settings}
        <label class="switch">
          <span class="label">Settings<small>Replace yours{hasSecrets ? ', including keys, notification channels and server connection' : '. Your keys and notification channels stay as they are'}</small></span>
          <input type="checkbox" bind:checked={take.settings} />
        </label>
      {/if}
      {#if found.data.subscriptions}
        <label class="switch">
          <span class="label">{count(found.data.subscriptions.length, 'subscription')}<small>Added to what you watch. What you already watch stays as it is.</small></span>
          <input type="checkbox" bind:checked={take.subscriptions} />
        </label>
      {/if}
      {#if found.data.alerts && take.subscriptions}
        <label class="switch sub">
          <span class="label">{count(found.data.alerts.length, 'alert')}<small>Added to your alert list, without notifications</small></span>
          <input type="checkbox" bind:checked={take.alerts} />
        </label>
      {/if}
      <div class="row buttons">
        <button class="btn primary" onclick={bring} disabled={busy || (!take.settings && !take.subscriptions)}>
          {#if busy}<span class="spinner"></span>{/if} Import
        </button>
        <button class="btn" onclick={() => (found = null)} disabled={busy}>Cancel</button>
      </div>
    </div>
  {/if}
</section>

<style>
  section {
    margin-bottom: 0.9rem;
    gap: 0.9rem;
  }
  .sub {
    margin-left: 1.1rem;
  }
  .buttons {
    flex-wrap: wrap;
    gap: 0.5rem;
  }
  .nest {
    padding: 0.9rem;
    border-radius: 12px;
    background: var(--surface-2);
    gap: 0.9rem;
  }
</style>
