import { fileURLToPath } from 'node:url'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vitest/config'

// https://vite.dev/config/
export default defineConfig({
  base: process.env.VITE_BASE || '/',
  build: {
    target: 'es2020',
    sourcemap: false,
  },
  worker: {
    format: 'es',
  },
  plugins: [
    react(),
    {
      name: 'production-content-security-policy',
      apply: 'build',
      transformIndexHtml(html) {
        return {
          html,
          tags: [{
            tag: 'meta',
            attrs: {
              'http-equiv': 'Content-Security-Policy',
              content: "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self'; connect-src 'self'; worker-src 'self' blob:; object-src 'none'; base-uri 'none'; form-action 'none'",
            },
            injectTo: 'head',
          }],
        };
      },
    },
  ],
  resolve: {
    dedupe: ['react', 'react-dom'],
  },
  server: {
    fs: {
      allow: [fileURLToPath(new URL('..', import.meta.url))],
    },
  },
  test: {
    environment: 'jsdom',
    setupFiles: './tests/setup.ts',
  },
})
