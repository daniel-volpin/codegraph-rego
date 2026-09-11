/** @type {import('tailwindcss').Config} */
export default {
  darkMode: ["class"],
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      fontFamily: {
        sans: [
          "Inter",
          "-apple-system",
          "BlinkMacSystemFont",
          "Segoe UI",
          "Roboto",
          "Helvetica Neue",
          "Arial",
          "sans-serif",
        ],
        mono: [
          "ui-monospace",
          "SFMono-Regular",
          "Menlo",
          "Monaco",
          "Consolas",
          '"Liberation Mono"',
          '"Courier New"',
          "monospace",
        ],
      },
      colors: {
        background: "#f8fafc",
        foreground: "#0f172a",
        card: "#ffffff",
        border: "#e2e8f0",
        sidebar: {
          DEFAULT: "#090d16",
          foreground: "#f1f5f9",
          border: "#1e293b",
          accent: "#4338ca",
          muted: "#94a3b8",
        },
        primary: {
          DEFAULT: "#4f46e5",
          foreground: "#ffffff",
          hover: "#4338ca",
        },
        muted: {
          DEFAULT: "#f1f5f9",
          foreground: "#64748b",
        },
      },
      boxShadow: {
        subtle: "0 1px 2px 0 rgb(0 0 0 / 0.05)",
        soft: "0 1px 3px 0 rgb(15 23 42 / 0.08), 0 1px 2px -1px rgb(15 23 42 / 0.08)",
        card: "0 0 0 1px rgba(226, 232, 240, 0.8), 0 1px 2px 0 rgba(15, 23, 42, 0.05)",
      },
      borderRadius: {
        xl: "0.75rem",
        "2xl": "1rem",
      },
    },
  },
  plugins: [],
};

