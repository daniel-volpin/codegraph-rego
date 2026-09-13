import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import tailwindcss from "@tailwindcss/vite";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const devProxyTarget = process.env.CODEGRAPH_DEV_PROXY_TARGET || "http://127.0.0.1:8000";

// Pin the runtime `service.version` to package.json so OTel reports a real
// version instead of drifting from a hand-maintained constant. Read is
// guarded so unit tests that import this config under jsdom (where
// `import.meta.url` isn't a file URL) don't crash on a missing package.json.
function readPackageVersion(): string {
  try {
    const raw = readFileSync(resolve(process.cwd(), "package.json"), "utf-8");
    return (JSON.parse(raw) as { version?: string }).version ?? "0.0.0-dev";
  } catch {
    return "0.0.0-dev";
  }
}

const APP_VERSION = readPackageVersion();
const forkedDomTests = ["src/lib/runtimeConfig.test.ts"];
const nodeTests = [
  "src/lib/api.test.ts",
  "src/lib/dependencies.test.ts",
  "src/components/features/policy/policyUtils.test.ts",
  "src/viteConfig.test.ts",
];

export default defineConfig({
  define: {
    __APP_VERSION__: JSON.stringify(APP_VERSION),
  },
  plugins: [tailwindcss(), react()],
  test: {
    globals: true,
    css: true,
    exclude: ["tests/e2e/**"],
    projects: [
      {
        test: {
          name: "dom-vm",
          pool: "vmForks",
          vmMemoryLimit: "512MB",
          environment: "jsdom",
          setupFiles: "./src/test/setup.ts",
          include: ["src/**/*.test.ts", "src/**/*.test.tsx"],
          exclude: [...forkedDomTests, ...nodeTests],
        },
      },
      {
        test: {
          name: "dom-forks",
          pool: "forks",
          environment: "jsdom",
          setupFiles: "./src/test/setup.ts",
          include: forkedDomTests,
        },
      },
      {
        test: {
          name: "node-forks",
          pool: "forks",
          environment: "node",
          include: nodeTests,
        },
      },
    ],
  },
  server: {
    // Bind IPv4 loopback explicitly. Vite's default host is "localhost", which
    // resolves to ::1 first on macOS and modern Linux, so the 127.0.0.1 URL in
    // README.md refused connections while localhost worked.
    host: "127.0.0.1",
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
