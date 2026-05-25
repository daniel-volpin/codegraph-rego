import tailwindcss from "@tailwindcss/vite";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const devProxyTarget = process.env.CODEGRAPH_DEV_PROXY_TARGET || "http://127.0.0.1:8000";

export default defineConfig({
  plugins: [tailwindcss(), react()],
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: "./src/test/setup.ts",
    css: true,
    include: ["src/**/*.test.ts", "src/**/*.test.tsx"],
    exclude: ["tests/e2e/**"],
  },
  server: {
    port: 5173,
    strictPort: true,
    proxy: {
      "/api": {
        target: devProxyTarget,
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api/, ""),
      },
    },
  },
  preview: {
    port: 4173
  },
  build: {
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (!id.includes("node_modules")) {
            return undefined;
          }

          // Syntax highlighting drags in Prism + refractor; isolate so the
          // React vendor chunk stays cacheable across releases.
          if (
            id.includes("react-syntax-highlighter") ||
            id.includes("refractor") ||
            id.includes("prismjs")
          ) {
            return "syntax-vendor";
          }

          if (id.includes("react-markdown")) {
            return "markdown-vendor";
          }

          if (id.includes("@tanstack/react-table")) {
            return "table-vendor";
          }

          if (id.includes("lucide-react")) {
            return "icons-vendor";
          }

          if (id.includes("react-router-dom") || id.includes("@tanstack/react-query")) {
            return "app-vendor";
          }

          if (id.includes("react") || id.includes("react-dom")) {
            return "react-vendor";
          }

          return undefined;
        }
      }
    }
  }
});
