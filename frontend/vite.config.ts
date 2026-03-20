import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173
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

          if (id.includes("react-markdown")) {
            return "markdown-vendor";
          }

          if (id.includes("@tanstack/react-table")) {
            return "table-vendor";
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
