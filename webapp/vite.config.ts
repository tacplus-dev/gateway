import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  base: '/',
  build: {
    outDir: 'dist',
  },
  server: {
    proxy: {
      '/fleetwood': 'https://localhost:9000',
      '/ironmaiden': 'https://localhost:9000',
    },
  },
})
