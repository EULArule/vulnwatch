<script lang="ts">
  import { signIn } from '../lib/state.svelte';

  let token = $state('');
  let error = $state('');
  let busy = $state(false);

  async function submit(e: Event) {
    e.preventDefault();
    busy = true;
    error = '';
    try {
      if (!(await signIn(token))) error = 'That token was not accepted.';
    } catch (err) {
      error = (err as Error).message;
    }
    busy = false;
  }
</script>

<main>
  <form class="card pad stack" onsubmit={submit}>
    <img src="/icon.svg" alt="" width="56" height="56" />
    <h1>vulnwatch</h1>
    <p class="muted">Enter the access token the server printed when it started.</p>
    <!-- svelte-ignore a11y_autofocus -->
    <input class="input mono" type="password" bind:value={token} placeholder="Access token" autocomplete="current-password" autofocus />
    {#if error}<p class="err small">{error}</p>{/if}
    <button class="btn primary" disabled={busy || !token.trim()}>Sign in</button>
  </form>
</main>

<style>
  main {
    min-height: 100vh;
    display: grid;
    place-items: center;
    padding: 1rem;
  }
  form {
    width: min(400px, 100%);
    padding: 1.5rem;
  }
  .err {
    color: var(--danger);
  }
</style>
