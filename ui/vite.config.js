import { defineConfig } from 'vite'
import { svelte } from '@sveltejs/vite-plugin-svelte'
import tailwindcss from '@tailwindcss/vite'
import { visualizer } from 'rollup-plugin-visualizer'
import path from 'path'

// PANEL_URL=https://panel.example.com npm run dev -- --port 5174 --host 127.0.0.1
// runs the UI locally against a live panel: every /api request and the WebSocket go to that
// panel. Origin is rewritten to the panel's so its CSRF check sees a same-origin request. Open the
// UI as http://localhost (an SSH tunnel is fine) — browsers only keep the panel's Secure session
// cookie on https or localhost.
const PANEL_URL = process.env.PANEL_URL
const livePanelProxy = PANEL_URL && {
  '/api': {
    target: PANEL_URL,
    changeOrigin: true,
    secure: true,
    ws: true,
    configure: (proxy) => {
      const origin = new URL(PANEL_URL).origin
      proxy.on('proxyReq', (req) => req.getHeader('origin') && req.setHeader('origin', origin))
      proxy.on('proxyReqWs', (req) => req.setHeader('origin', origin))
    }
  }
}

export default defineConfig({
  resolve: {
    alias: {
      $lib: path.resolve('./src/lib')
    }
  },
  plugins: [
    svelte(),
    tailwindcss(),
    visualizer({ open: false, filename: 'dist/stats.html' })
  ],
  base: '/',
  server: {
    host: '0.0.0.0',
    port: 80,
    allowedHosts: true,
    // Allow importing the repo-root README.md (../README.md) so the About page can render
    // its Architecture section as the single source of truth for the diagrams.
    fs: { allow: ['..'] },
    proxy: livePanelProxy || {
      // Headscale API
      '/api/v1': {
        target: 'http://traefik',
        changeOrigin: true
      },
      // WireGuard API
      '/api/wg': {
        target: 'http://traefik',
        changeOrigin: true
      },
      // Traefik API
      '/api/traefik': {
        target: 'http://traefik',
        changeOrigin: true
      },
      // AdGuard API
      '/api/adguard': {
        target: 'http://traefik',
        changeOrigin: true
      },
      // Firewall API
      '/api/fw': {
        target: 'http://traefik',
        changeOrigin: true
      }
    }
  }
})
