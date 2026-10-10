import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// The dev server proxies /api to the backend so the browser sees a single
// origin: session cookies stay first-party and CORS is not needed.
const apiTarget = process.env.FX_API_PROXY || 'http://localhost:5000';

export default defineConfig({
  plugins: [react()],
  server: { port: 5173, strictPort: true, proxy: { '/api': { target: apiTarget, changeOrigin: false } } },
  preview: { port: 4173, proxy: { '/api': { target: apiTarget, changeOrigin: false } } },
  build: { outDir: 'dist', sourcemap: false },
});
