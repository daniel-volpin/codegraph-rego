import tailwindcssAnimate from "tailwindcss-animate";

/** @type {import('tailwindcss').Config} */
export default {
  darkMode: ["class"],
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        background: "#f8fafc",
        foreground: "#0f172a",
        card: "#ffffff",
        border: "#e2e8f0",
        sidebar: {
          DEFAULT: "#020617",
          foreground: "#e2e8f0",
          border: "#1e293b",
          accent: "#4f46e5",
          muted: "#94a3b8",
        },
        primary: {
          DEFAULT: "#4f46e5",
          foreground: "#ffffff",
        },
        muted: {
          DEFAULT: "#f1f5f9",
          foreground: "#64748b",
        },
      },
      boxShadow: {
        soft: "0 4px 12px rgba(15, 23, 42, 0.08)",
      },
    },
  },
  plugins: [tailwindcssAnimate],
};
