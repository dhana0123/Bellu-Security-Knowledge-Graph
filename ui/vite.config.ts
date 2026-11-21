import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

const target = process.env.BSKG_API_URL ?? 'http://127.0.0.1:8080';

export default defineConfig({
  base: '/ui/',
  plugins: [react(), tailwindcss()],
  build: {
    outDir: 'dist',
    // dist/.gitkeep and embed.go are owned by the API side; never wipe them.
    emptyOutDir: false,
    sourcemap: false,
    assetsInlineLimit: 0,
  },
  server: {
    proxy: {
      '/v1': target,
      '/healthz': target,
    },
  },
  test: {
    environment: 'jsdom',
    include: ['src/**/*.test.ts', 'src/**/*.test.tsx'],
  },
});
