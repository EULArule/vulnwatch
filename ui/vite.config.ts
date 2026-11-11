import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';

// `npm run dev` proxies the API to a locally running `vulnwatch` server.
export default defineConfig({
  plugins: [svelte()],
  clearScreen: false,
  server: {
    port: 5173,
    strictPort: true,
    host: process.env.TAURI_DEV_HOST || false,
    proxy: { '/api': 'http://127.0.0.1:8088' },
  },
  build: { target: 'es2021', chunkSizeWarningLimit: 800 },
});
