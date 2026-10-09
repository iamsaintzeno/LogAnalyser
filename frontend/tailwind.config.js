/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        risk: {
          critical: '#ef4444', // red-500
          high: '#f97316', // orange-500
          medium: '#facc15', // yellow-400
          low: '#22c55e', // green-500
        },
      },
    },
  },
  plugins: [],
};
