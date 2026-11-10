import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  darkMode: "class",
  theme: {
    extend: {
      fontFamily: {
        display: ["var(--font-display)", "Georgia", "serif"],
        sans: ["var(--font-sans)", "system-ui", "sans-serif"],
        mono: ["var(--font-mono)", "Consolas", "monospace"],
      },
      colors: {
        background: "var(--background)",
        foreground: "var(--foreground)",
        border: "var(--border)",
        "studio-void": "var(--surface-void)",
        "studio-panel": "var(--surface-panel)",
        "studio-elevated": "var(--surface-elevated)",
        "studio-hairline": "var(--border-hairline)",
        "ink-primary": "var(--ink-primary)",
        "ink-muted": "var(--ink-muted)",
        "sig-crimson": "var(--sig-crimson)",
        "sig-gold": "var(--sig-gold)",
        "sig-emerald": "var(--sig-emerald)",
        "sig-cyan": "var(--sig-cyan)",
        zinc: {
          50: "rgb(var(--z-50) / <alpha-value>)",
          100: "rgb(var(--z-100) / <alpha-value>)",
          200: "rgb(var(--z-200) / <alpha-value>)",
          300: "rgb(var(--z-300) / <alpha-value>)",
          400: "rgb(var(--z-400) / <alpha-value>)",
          500: "rgb(var(--z-500) / <alpha-value>)",
          600: "rgb(var(--z-600) / <alpha-value>)",
          700: "rgb(var(--z-700) / <alpha-value>)",
          800: "rgb(var(--z-800) / <alpha-value>)",
          900: "rgb(var(--z-900) / <alpha-value>)",
          950: "rgb(var(--z-950) / <alpha-value>)",
        },
      },
    },
  },
  plugins: [],
};
export default config;
