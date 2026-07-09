import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { resolve } from "node:path";

// Gateway serves this SPA at /dashboard/* (src/src/routes/dashboard.rs).
// base must stay /dashboard/ so asset URLs hydrate under that prefix.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  base: "/dashboard/",
  build: {
    outDir: "dist",
    emptyOutDir: true,
    sourcemap: true,
  },
  resolve: {
    alias: {
      "@": resolve(__dirname, "src"),
    },
  },
  server: {
    port: 3000,
    // Dev: proxy API to local gateway (same-origin simulation for CSRF optional)
    proxy: {
      "/v1": "http://127.0.0.1:8080",
      "/livez": "http://127.0.0.1:8080",
      "/readyz": "http://127.0.0.1:8080",
    },
  },
});
