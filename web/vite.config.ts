import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// Node.js is build-time only. The output below is embedded into the Go
// controller binary via go:embed; no Node process exists at runtime.
export default defineConfig({
  base: '/',
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    proxy: {
      // The Go controller is expected on its default development port.
      '/api': {
        target: 'http://127.0.0.1:8080',
        changeOrigin: false,
      },
    },
  },
  build: {
    outDir: '../internal/webui/public',
    emptyOutDir: true,
    target: 'es2022',
    sourcemap: false,
    // Keep every asset as a self-hosted file: the controller CSP only allows
    // same-origin scripts/styles, and no inline module-preload shim is needed
    // for the supported browsers.
    assetsInlineLimit: 0,
    modulePreload: { polyfill: false },
    chunkSizeWarningLimit: 800,
  },
})
