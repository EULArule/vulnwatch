<script lang="ts">
  import type { Settings } from '../lib/types';
  import { isApp, rpc } from '../lib/api';
  import { app, applyTheme, call, refreshStatus, refreshSubs, signOut, toast } from '../lib/state.svelte';
  import { ago } from '../lib/format';
  import Icon from '../components/Icon.svelte';

  let s = $state<Settings | null>(null);
  let saved = '';
  let android: { notifications: boolean; battery_exempt: boolean } | null = $state(null);
  let testing = $state(false);
  let pairing = $state(false);
  let browserPerm = $state('Notification' in window ? Notification.permission : 'unsupported');

  async function load() {
    const r = await call<{ settings: Settings }>('settings.get');
    if (!r) return;
    saved = JSON.stringify(r.settings);
    s = r.settings;
    if (isApp) android = (await call('android.state')) ?? null;
  }
  load();

  // Every change saves itself shortly after; there is no Save button to forget.
  let timer: ReturnType<typeof setTimeout>;
  $effect(() => {
    if (!s) return;
    const now = JSON.stringify(s);
    if (now === saved) return;
    applyTheme(s.theme);
    clearTimeout(timer);
    timer = setTimeout(async () => {
      const r = await call<{ settings: Settings }>('settings.set', { settings: JSON.parse(now) });
      if (!r) return;
      saved = now;
      app.settings = r.settings;
      refreshStatus();
    }, 500);
  });

  const intervals = $derived(
    app.status?.mobile && s?.background !== 'realtime'
      ? [15, 30, 60, 180, 360]
      : [5, 15, 30, 60, 180],
  );
  $effect(() => {
    // Android's periodic scheduler cannot run more often than every 15 minutes.
    if (s && app.status?.mobile && s.background === 'periodic' && s.interval_minutes < 15) s.interval_minutes = 15;
  });
  const every = (m: number) => (m < 60 ? `${m} min` : `${m / 60} h`);

  async function test() {
    testing = true;
    await new Promise((r) => setTimeout(r, 600)); // let a pending save land first
    const r = await call('notify.test');
    testing = false;
    if (!r) return;
    if (r.errors.length) toast(r.errors[0], 'error');
    else if (isApp || r.channels.ntfy || r.channels.webhook) toast('Test notification sent');
    else toast('Turn on ntfy or a webhook first', 'error');
  }

  async function pair() {
    if (!s) return;
    pairing = true;
    try {
      const r = await rpc('remote.test', { url: s.remote.url, token: s.remote.token });
      s.remote.enabled = true;
      toast(`Connected to vulnwatch ${r.version}`);
      setTimeout(() => {
        refreshSubs();
        refreshStatus();
      }, 900);
    } catch (e) {
      toast((e as Error).message, 'error');
    }
    pairing = false;
  }

  async function unpair() {
    if (!s) return;
    s.remote.enabled = false;
    setTimeout(() => {
      refreshSubs();
      refreshStatus();
    }, 900);
  }

  async function androidAsk(what: 'notifications' | 'battery') {
    await call('android.request_' + what);
    // The system dialog is asynchronous; re-read once the user is back.
    setTimeout(async () => (android = (await call('android.state')) ?? android), 1500);
  }
  document.addEventListener('visibilitychange', async () => {
    if (isApp && !document.hidden) android = (await call('android.state')) ?? android;
  });

  async function askBrowser() {
    browserPerm = await Notification.requestPermission();
  }
</script>

<h1 class="title">Settings</h1>

{#if !s}
  <div class="loading"><span class="spinner"></span></div>
{:else}
  {#if app.status?.mobile}
    <section class="card pad stack">
      <h2>Background alerts</h2>
      <div class="options">
        <label class="opt" class:on={s.background === 'periodic'}>
          <input type="radio" bind:group={s.background} value="periodic" />
          <span><b>Battery friendly</b><small>Checks on a schedule, even when the app is closed. Android may delay a check while the phone is idle.</small></span>
        </label>
        <label class="opt" class:on={s.background === 'realtime'}>
          <input type="radio" bind:group={s.background} value="realtime" />
          <span><b>Always on</b><small>Keeps a small service running with a permanent notification, so checks happen on time. Uses more battery.</small></span>
        </label>
        <label class="opt" class:on={s.background === 'off'}>
          <input type="radio" bind:group={s.background} value="off" />
          <span><b>Off</b><small>Only checks while the app is open.</small></span>
        </label>
      </div>
      <p class="hint">Works without Google Play services: the phone checks by itself{s.remote.enabled ? ' against your server' : ''}.</p>

      {#if android && !android.notifications}
        <div class="warn row">
          <span class="grow"><b>Notifications are blocked</b><br /><span class="small">Android needs your permission to show alerts.</span></span>
          <button class="btn sm primary" onclick={() => androidAsk('notifications')}>Allow</button>
        </div>
      {/if}
      {#if android && !android.battery_exempt && s.background !== 'off'}
        <div class="warn row">
          <span class="grow"><b>Battery optimisation is on</b><br /><span class="small">Some phones stop background checks to save power. Exempting vulnwatch makes alerts reliable.</span></span>
          <button class="btn sm" onclick={() => androidAsk('battery')}>Exempt</button>
        </div>
      {/if}
    </section>
  {/if}

  <section class="card pad stack">
    <h2>Checking</h2>
    <div class="field">
      Check for new vulnerabilities every
      <div class="seg">
        {#each intervals as m}
          <button class:on={s.interval_minutes === m} onclick={() => (s!.interval_minutes = m)}>{every(m)}</button>
        {/each}
      </div>
      {#if app.status?.remote}<span class="hint">How often this phone asks your server. The server has its own interval.</span>{/if}
    </div>
    <div class="field">
      Keep alerted vulnerabilities for reading offline
      <div class="seg">
        {#each [0, 1, 3, 7, 14, 30, 90] as d}
          <button class:on={s.offline_days === d} onclick={() => (s!.offline_days = d)}>{d === 0 ? 'Off' : `${d} d`}</button>
        {/each}
      </div>
      <span class="hint">Each alert is saved with its full details for this long, so it still opens when there is no connection.</span>
    </div>
    <div class="muted small">
      Last check {ago(app.status?.last_check)}
      {#if app.status?.last_errors?.length}
        <div class="err">{#each app.status.last_errors as e}<div>{e}</div>{/each}</div>
      {/if}
    </div>
  </section>

  <section class="card pad stack">
    <h2>Notifications</h2>
    {#if isApp}
      <p class="hint">This phone shows a notification for every new alert. The options below are extra channels.</p>
    {:else}
      <p class="hint">The server checks around the clock. To be told when you are away from this page, use the Android app, ntfy, or a webhook.</p>
      {#if browserPerm === 'default'}
        <button class="btn sm start" onclick={askBrowser}><Icon name="bell" size={18} /> Also notify in this browser while it is open</button>
      {:else if browserPerm === 'granted'}
        <p class="small ok"><Icon name="check" size={16} /> Browser notifications are on while this page is open.</p>
      {/if}
    {/if}

    <label class="switch">
      <span class="label">ntfy<small>Free push to any phone or desktop via the ntfy app. No Google services needed.</small></span>
      <input type="checkbox" bind:checked={s.ntfy.enabled} />
    </label>
    {#if s.ntfy.enabled}
      <div class="nest stack">
        <label class="field">Topic<input class="input" bind:value={s.ntfy.topic} placeholder="a hard-to-guess name, e.g. vulns-k3x9p2" autocapitalize="off" /><span class="hint">Subscribe to the same topic in the ntfy app. Anyone who knows the topic can read it, so pick something random.</span></label>
        <label class="field">Server<input class="input" bind:value={s.ntfy.server} placeholder="https://ntfy.sh" autocapitalize="off" inputmode="url" /></label>
        <label class="field">Access token <span class="hint">only for protected topics</span><input class="input" type="password" bind:value={s.ntfy.token} autocomplete="off" /></label>
      </div>
    {/if}

    <label class="switch">
      <span class="label">Webhook<small>POST each alert as JSON (works with Slack, Discord, Mattermost, Home Assistant…)</small></span>
      <input type="checkbox" bind:checked={s.webhook.enabled} />
    </label>
    {#if s.webhook.enabled}
      <div class="nest">
        <label class="field">URL<input class="input" bind:value={s.webhook.url} placeholder="https://…" autocapitalize="off" inputmode="url" /></label>
      </div>
    {/if}

    <button class="btn start" onclick={test} disabled={testing}>
      {#if testing}<span class="spinner"></span>{:else}<Icon name="bell" size={18} />{/if} Send a test notification
    </button>
  </section>

  {#if app.status?.mobile}
    <section class="card pad stack">
      <h2>Use my vulnwatch server</h2>
      <p class="hint">Optional. If you run the vulnwatch server, the app can use its subscriptions and alerts instead of checking by itself. You get the same list on every device.</p>
      {#if s.remote.enabled}
        <p class="small ok"><Icon name="check" size={16} /> Connected to {s.remote.url}</p>
        <button class="btn start" onclick={unpair}>Disconnect and check on this phone</button>
      {:else}
        <label class="field">Server address<input class="input" bind:value={s.remote.url} placeholder="https://vulnwatch.example.org" autocapitalize="off" inputmode="url" /></label>
        <label class="field">Access token<input class="input" type="password" bind:value={s.remote.token} autocomplete="off" /></label>
        <button class="btn primary start" onclick={pair} disabled={pairing || !s.remote.url}>
          {#if pairing}<span class="spinner"></span>{/if} Connect
        </button>
      {/if}
    </section>
  {/if}

  {#if !app.status?.remote}
    <section class="card pad stack">
      <h2>Sources</h2>
      <p class="hint">Always on: NVD (CVE database), CISA KEV (known exploited) and OSV (open-source packages).</p>
      <label class="switch">
        <span class="label">CIRCL Vulnerability-Lookup<small>Adds CVEs that NVD has not analysed yet to product pages</small></span>
        <input type="checkbox" bind:checked={s.use_circl} />
      </label>
      <label class="switch">
        <span class="label">ENISA EUVD<small>Supplies those CVEs when CIRCL is switched off or not answering</small></span>
        <input type="checkbox" bind:checked={s.use_euvd} />
      </label>
      <label class="switch">
        <span class="label">EPSS scores<small>Exploit likelihood from FIRST.org, shown on lists and usable in filters</small></span>
        <input type="checkbox" bind:checked={s.use_epss} />
      </label>
      <label class="switch">
        <span class="label">CVE.org live feed<small>Sees brand-new CVEs a little before NVD. More data per check.</small></span>
        <input type="checkbox" bind:checked={s.use_cvelist} />
      </label>
      <label class="field">
        NVD API key <span class="hint">optional — lists load faster and are rate-limited less. Free from nvd.nist.gov.</span>
        <input class="input mono" type="password" bind:value={s.nvd_api_key} autocomplete="off" />
      </label>
      <label class="field">
        CVEdetails API token <span class="hint">optional — adds cvedetails.com's listing to product pages. From your cvedetails.com account.</span>
        <input class="input mono" type="password" bind:value={s.cvedetails_token} autocomplete="off" />
      </label>
      <div class="field">
        A new subscription also alerts for what was published in the
        <div class="seg">
          {#each [0, 1, 3, 7, 14, 30] as d}
            <button class:on={s.lookback_days === d} onclick={() => (s!.lookback_days = d)}>{d === 0 ? 'Nothing earlier' : d === 1 ? 'Day before' : `${d} days before`}</button>
          {/each}
        </div>
        <span class="hint">How far back a subscription reaches from the day you create it. Opening or refreshing a product you watch adds what its page lists from that time to your alerts.</span>
      </div>
      <div class="field">
        Ignore vulnerabilities published more than
        <div class="seg">
          {#each [7, 30, 90, 365] as d}
            <button class:on={s.max_age_days === d} onclick={() => (s!.max_age_days = d)}>{d} days ago</button>
          {/each}
        </div>
        <span class="hint">Databases keep editing old entries; this stops those edits from alerting you. Newly exploited ones always alert.</span>
      </div>
    </section>
  {/if}

  <section class="card pad stack">
    <h2>Appearance</h2>
    <div class="seg">
      {#each ['system', 'light', 'dark'] as const as t}
        <button class:on={s.theme === t} onclick={() => (s!.theme = t)}>{t === 'system' ? 'Match device' : t === 'light' ? 'Light' : 'Dark'}</button>
      {/each}
    </div>
  </section>

  <p class="muted small about">
    vulnwatch {app.status?.version}{app.status?.server_version ? ` · server ${app.status.server_version}` : ''}
    {#if !isApp} · <button class="linkbtn" onclick={signOut}>Sign out</button>{/if}
  </p>
{/if}

<style>
  .title {
    margin-bottom: 1rem;
  }
  section {
    margin-bottom: 0.9rem;
    gap: 0.9rem;
  }
  .field {
    display: flex;
    flex-direction: column;
    gap: 0.35rem;
    font-weight: 600;
    font-size: 0.92rem;
  }
  .options {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }
  .opt {
    display: flex;
    gap: 0.7rem;
    align-items: flex-start;
    padding: 0.75rem 0.9rem;
    border: 1.5px solid var(--border);
    border-radius: 12px;
    cursor: pointer;
  }
  .opt.on {
    border-color: var(--accent);
    background: var(--accent-soft);
  }
  .opt input {
    margin-top: 0.25rem;
    accent-color: var(--accent);
    width: 18px;
    height: 18px;
    flex: none;
  }
  .opt small {
    display: block;
    color: var(--muted);
    font-size: 0.85rem;
  }
  .warn {
    padding: 0.75rem 0.9rem;
    border-radius: 12px;
    background: var(--med-bg);
    color: var(--med);
  }
  .nest {
    padding: 0.9rem;
    border-radius: 12px;
    background: var(--surface-2);
  }
  .start {
    align-self: flex-start;
  }
  .err {
    color: var(--danger);
    margin-top: 0.3rem;
  }
  .ok {
    color: var(--ok);
    display: flex;
    align-items: center;
    gap: 0.35rem;
  }
  .about {
    text-align: center;
    margin: 1.5rem 0;
  }
  .linkbtn {
    border: 0;
    background: none;
    padding: 0;
    color: var(--accent);
    cursor: pointer;
  }
</style>
