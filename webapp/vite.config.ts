import { defineConfig } from 'vite'

// Served by the gateway at the origin root beside the generated routes
// (/{package}/{Service}/{Rpc}); same origin, so no proxy and no base path.
export default defineConfig({
  base: '/',
  define: { global: 'globalThis' },
  build: { outDir: 'dist' },
})
