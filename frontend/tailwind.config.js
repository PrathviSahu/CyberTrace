/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        bg: {
          base: "#080c14",
          surface1: "#0e1626",
          surface2: "#162035",
          hover: "#1e2c47",
          active: "#253759",
        },
        border: {
          subtle: "rgba(255, 255, 255, 0.08)",
          accent: "rgba(99, 102, 241, 0.35)",
          cyan: "rgba(6, 182, 212, 0.4)",
        },
        cyan: {
          glow: "#06b6d4",
          DEFAULT: "#06b6d4",
          dark: "#0891b2",
        },
        indigo: {
          glow: "#6366f1",
          DEFAULT: "#6366f1",
          dark: "#4f46e5",
        },
        severity: {
          critical: "#ef4444",
          "critical-bg": "#2b1218",
          high: "#f59e0b",
          "high-bg": "#281d0d",
          medium: "#eab308",
          "medium-bg": "#24210b",
          low: "#38bdf8",
          "low-bg": "#0d2338",
          healthy: "#10b981",
          "healthy-bg": "#0c281e",
        },
      },
      fontFamily: {
        sans: ["Inter", "Geist", "system-ui", "-apple-system", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "SFMono-Regular", "monospace"],
      },
      boxShadow: {
        card: "0 2px 8px 0 rgba(0, 0, 0, 0.45)",
        modal: "0 8px 32px 0 rgba(0, 0, 0, 0.75)",
        drawer: "-4px 0 24px 0 rgba(0, 0, 0, 0.65)",
        glowCyan: "0 0 15px rgba(6, 182, 212, 0.25)",
        glowIndigo: "0 0 15px rgba(99, 102, 241, 0.25)",
      },
    },
  },
  plugins: [],
};

