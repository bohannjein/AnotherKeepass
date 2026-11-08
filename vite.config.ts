import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'
import pkg from './package.json' with { type: 'json' }

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  // shown under the logo; package.json, tauri.conf.json and Cargo.toml carry the same version
  define: { __APP_VERSION__: JSON.stringify(pkg.version) },
  // the Rust build output is huge and locked while building; watching it breaks HMR
  server: { watch: { ignored: ['**/src-tauri/**'] } },
})
