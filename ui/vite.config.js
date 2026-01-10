import { defineConfig } from 'vite'
import { svelte } from '@sveltejs/vite-plugin-svelte'
import tailwindcss from '@tailwindcss/vite'
import { visualizer } from 'rollup-plugin-visualizer'
import path from 'path'

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
    proxy: {
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
