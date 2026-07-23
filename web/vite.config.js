import { defineConfig } from "vite";
import vue from "@vitejs/plugin-vue";

export default defineConfig({
  // Relative base so the built site works from any GitHub Pages subpath
  // (e.g. https://<user>.github.io/spotlib-rs/).
  base: "./",
  plugins: [vue()],
});
