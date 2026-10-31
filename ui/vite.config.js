import { defineConfig } from 'vite'
import { svelte } from '@sveltejs/vite-plugin-svelte'
import tailwindcss from '@tailwindcss/vite'
import { visualizer } from 'rollup-plugin-visualizer'
import path from 'path'
import fs from 'fs'

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

// The step-up lives in src/stores/app.js only: no other file may put a password or 2FA code into a
// request, or handle the step-up answer (428) itself — they send the proof stepUpConfirm /
// withStepUp / passwordProof give them, so every screen offers the same checks and the passkey.
// The sign-in page is the one exception: its password and code are the login, not a step-up.
function stepUpOnePlace() {
  const own = /currentPassword|totpCode|[!=]==\s*428/
  const allowed = new Set(['src/stores/app.js', 'src/views/Login.svelte'])
  return {
    name: 'step-up-one-place',
    buildStart() {
      const bad = []
      const walk = (dir) => {
        for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
          const p = path.join(dir, e.name)
          if (e.isDirectory()) walk(p)
          else if (/\.(js|svelte)$/.test(e.name) && !allowed.has(p.split(path.sep).join('/'))) {
            fs.readFileSync(p, 'utf8').split('\n').forEach((line, i) => { if (own.test(line)) bad.push(`${p}:${i + 1}`) })
          }
        }
      }
      walk('src')
      if (bad.length) this.error('a step-up of its own (use the helpers in src/stores/app.js):\n  ' + bad.join('\n  '))
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
    stepUpOnePlace(),
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
