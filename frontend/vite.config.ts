import { fileURLToPath, URL } from 'node:url';
import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

// En desarrollo, las llamadas a /api se reenvían al backend para evitar CORS.
// API_PROXY_TARGET permite apuntar al contenedor de la API (ver docker-compose.dev.yml).
const apiTarget = process.env.API_PROXY_TARGET ?? 'http://localhost:3000';

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) },
  },
  build: {
    rollupOptions: {
      output: {
        // Vite 8 (rolldown): las librerías pesadas se sirven en trozos aparte.
        advancedChunks: {
          groups: [
            { name: 'charts', test: /node_modules[\\/]recharts/ },
            { name: 'react', test: /node_modules[\\/](react|react-dom|react-router|@tanstack)/ },
          ],
        },
      },
    },
  },
  server: {
    port: 5173,
    proxy: {
      '/api': { target: apiTarget, changeOrigin: true },
    },
    watch: { usePolling: process.env.CHOKIDAR_USEPOLLING === 'true' },
  },
});
