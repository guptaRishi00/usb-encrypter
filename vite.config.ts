import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Tauri drives this dev server; the fixed port matches `devUrl` in
// tauri.conf.json, and `strictPort` makes a clash fail loudly instead of
// silently serving on a port the app window will never load.
export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  server: {
    port: 5273,
    strictPort: true,
    host: '127.0.0.1',
    watch: { ignored: ['**/src-tauri/**'] },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    target: 'chrome110',
    sourcemap: false,
  },
});
