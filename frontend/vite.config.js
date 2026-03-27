import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

export default defineConfig({
  base: './',
  plugins: [react(), tailwindcss()],
  server: {
    proxy: {
      '/ws': {
        target: 'ws://127.0.0.1:8006',
        ws: true,
      },
      '/api': {
        target: 'http://127.0.0.1:8006',
      }
    }
  }
})
