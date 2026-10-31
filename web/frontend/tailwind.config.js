/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        background: '#030303',
        surface: '#0d0d0d',
        surfaceHover: '#161616',
        divider: '#222222',
        dividerHover: '#444444',
        primary: '#ffffff',
        primaryHover: '#e0e0e0',
        text: '#f5f5f5',
        muted: '#888888',
        danger: '#ff4444',
        success: '#ffffff',
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'monospace'],
        display: ['"JetBrains Mono"', 'monospace'],
      }
    },
  },
  plugins: [],
}
