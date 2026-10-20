import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  // the Rust build output is huge and locked while building; watching it breaks HMR
  server: { watch: { ignored: ['**/src-tauri/**'] } },
})
