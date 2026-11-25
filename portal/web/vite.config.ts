import path from "node:path"
import react from "@vitejs/plugin-react"
import tailwindcss from "@tailwindcss/vite"
import { defineConfig } from "vite"

// Output goes into the Python package; the portal serves it under /app/.
export default defineConfig({
  base: "/app/",
  plugins: [react(), tailwindcss()],
  resolve: { alias: { "@": path.resolve(import.meta.dirname, "./src") } },
  build: {
    outDir: "../src/portal/web_dist",
    emptyOutDir: true,
    // CSP script-src 'self': no inline modulepreload polyfill.
    modulePreload: { polyfill: false },
    assetsInlineLimit: 0,
    sourcemap: false,
  },
  server: { proxy: { "/api": "http://127.0.0.1:8443" } },
})
