/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'ui-monospace', 'SFMono-Regular', 'monospace'],
      },
      colors: {
        base: { 950: '#0a0e14', 900: '#0f141c', 850: '#141b25', 800: '#1a2230', 700: '#263142', 600: '#36445a' },
        ink: { DEFAULT: '#e4e9f0', dim: '#9aa7ba', faint: '#64748b' },
        accent: { DEFAULT: '#3ea6c4', deep: '#2b7f99' },
        sev: { low: '#5a8dd6', medium: '#e0a93b', high: '#e2743a', critical: '#d9455f' },
        ok: '#49b391', warn: '#e0a93b', bad: '#d9455f',
      },
      boxShadow: { panel: '0 1px 0 0 rgba(255,255,255,0.03) inset, 0 8px 24px -12px rgba(0,0,0,0.6)' },
    },
  },
  plugins: [],
};
