/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        accent: "#4a90e2",
        bodybg: "#f4f7f6",
        text: "#333333",
        card: "#ffffff",
      },
      boxShadow: {
        card: "0 4px 6px rgba(0,0,0,0.1)",
        cardHover: "0 8px 15px rgba(0,0,0,0.15)",
      },
    },
  },
  plugins: [],
}

