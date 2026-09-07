import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// dev 期把 /api/* 代理到后端 FastAPI（127.0.0.1:8765），免跨域。
// preview（本地验证 dist 构建产物）走同一份代理。
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8765',
        changeOrigin: true,
        ws: true,
      },
    },
  },
  preview: {
    port: 4173,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8765',
        changeOrigin: true,
        ws: true,
      },
    },
  },
})
