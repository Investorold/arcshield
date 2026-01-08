/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        'arc-purple': '#7C3AED',
        'arc-blue': '#3B82F6',
        'severity-critical': '#DC2626',
        'severity-high': '#F97316',
        'severity-medium': '#EAB308',
        'severity-low': '#22C55E',
        'severity-info': '#6B7280',
      },
    },
  },
  plugins: [],
}
