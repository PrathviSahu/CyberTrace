/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        canvas: "#111315",
        bg: {
          base: "#111315",
          sidebar: "#191C1F",
          surface: "#1D2125",
          surface1: "#1D2125",
          surface2: "#24282C",
          elevated: "#24282C",
          hover: "#2A2F35",
          active: "#2B2722",
        },
        border: {
          subtle: "#30363C",
          default: "#30363C",
          accent: "#B58A61",
          slate: "#30363C",
        },
        text: {
          primary: "#E9ECEF",
          secondary: "#A0A7AE",
          muted: "#737D87",
          disabled: "#555E67",
        },
        bronze: {
          DEFAULT: "#B58A61",
          hover: "#C69A70",
          active: "#9E7752",
          subtle: "rgba(181, 138, 97, 0.12)",
          ring: "#B58A61",
        },
        steel: {
          DEFAULT: "#B58A61", // backward compatibility alias
          hover: "#C69A70",
          active: "#2B2722",
          ring: "#B58A61",
        },
        severity: {
          critical: "#E06C68",
          "critical-bg": "rgba(224, 108, 104, 0.12)",
          high: "#D99A54",
          "high-bg": "rgba(217, 154, 84, 0.12)",
          medium: "#C9B86B",
          "medium-bg": "rgba(201, 184, 107, 0.12)",
          low: "#76A58B",
          "low-bg": "rgba(118, 165, 139, 0.12)",
          info: "#8A94A0",
          "info-bg": "rgba(138, 148, 160, 0.12)",
          healthy: "#76A58B",
          "healthy-bg": "rgba(118, 165, 139, 0.12)",
        },
        provenance: {
          observed: "#B58A61",
          "observed-bg": "rgba(181, 138, 97, 0.12)",
          benchmark: "#9B8FA8",
          "benchmark-bg": "rgba(155, 143, 168, 0.12)",
          calculated: "#6EA59A",
          "calculated-bg": "rgba(110, 165, 154, 0.12)",
        },
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "-apple-system", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "SFMono-Regular", "monospace"],
      },
      boxShadow: {
        card: "0 1px 2px 0 rgba(0, 0, 0, 0.35)",
        modal: "0 12px 36px 0 rgba(0, 0, 0, 0.65)",
        drawer: "-4px 0 24px 0 rgba(0, 0, 0, 0.55)",
      },
    },
  },
  plugins: [],
};
