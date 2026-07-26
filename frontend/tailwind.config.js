/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        void: '#000000',
        surface: '#050505',
        raised: '#0D0D0F',
        edge: '#18181C',
        dim: '#5B6672',
        ink: '#E6EAEE',
        sev: {
          critical: '#DC2626',
          high: '#EA580C',
          medium: '#D97706',
          low: '#2563EB',
          info: '#6B7280',
        },
        ok: '#16A34A',
        degraded: '#D97706',
        down: '#DC2626',
      },
      fontFamily: {
        mono: ['"JetBrains Mono"', '"IBM Plex Mono"', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'monospace'],
        sans: ['Inter', 'Geist', 'ui-sans-serif', 'system-ui', 'sans-serif'],
      },
      animation: {
        'flash-crit': 'flashBar 600ms ease-out',
        'flash-high': 'flashBar 600ms ease-out',
        'flash-med': 'flashBar 600ms ease-out',
        'flash-low': 'flashBar 600ms ease-out',
        'flash-info': 'flashBar 600ms ease-out',
        'pulse-dot': 'pulseDot 1.4s ease-in-out infinite',
        'pulse-soft': 'pulseSoft 1.6s ease-in-out infinite',
        'pulse-glow': 'pulseGlow 2.5s ease-in-out infinite',
        'fade-in': 'fadeIn 240ms ease-out',
        'slide-in-right': 'slideInRight 300ms cubic-bezier(0.16, 1, 0.3, 1)',
        'beam-scan': 'beamScan 12s linear infinite',
        'counter-pop': 'counterPop 400ms cubic-bezier(0.175, 0.885, 0.32, 1.275)',
        'shimmer': 'shimmer 2s linear infinite',
        'row-enter': 'rowEnter 300ms cubic-bezier(0.16, 1, 0.3, 1) forwards',
      },
      keyframes: {
        flashBar: {
          '0%': { opacity: '0.55' },
          '100%': { opacity: '0' },
        },
        pulseDot: {
          '0%, 100%': { opacity: '0.4', transform: 'scale(1)' },
          '50%': { opacity: '1', transform: 'scale(1.5)' },
        },
        pulseSoft: {
          '0%, 100%': { opacity: '0.85' },
          '50%': { opacity: '1' },
        },
        pulseGlow: {
          '0%, 100%': { opacity: '0.4', filter: 'blur(8px)' },
          '50%': { opacity: '0.8', filter: 'blur(12px)' },
        },
        fadeIn: {
          from: { opacity: '0' },
          to: { opacity: '1' },
        },
        slideInRight: {
          from: { transform: 'translateX(100%)' },
          to: { transform: 'translateX(0)' },
        },
        beamScan: {
          '0%': { strokeDashoffset: '100' },
          '100%': { strokeDashoffset: '0' },
        },
        counterPop: {
          '0%': { transform: 'scale(1)' },
          '50%': { transform: 'scale(1.18)' },
          '100%': { transform: 'scale(1)' },
        },
        shimmer: {
          '0%': { backgroundPosition: '-200% 0' },
          '100%': { backgroundPosition: '200% 0' },
        },
        rowEnter: {
          from: { opacity: '0', transform: 'translateY(-6px)' },
          to: { opacity: '1', transform: 'translateY(0)' },
        },
      },
    },
  },
  plugins: [],
};
