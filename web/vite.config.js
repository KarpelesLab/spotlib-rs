import { fileURLToPath, URL } from "node:url";
import { defineConfig } from "vite";
import vue from "@vitejs/plugin-vue";

export default defineConfig({
  // Relative base so the built site works from any GitHub Pages subpath
  // (e.g. https://<user>.github.io/spotlib-rs/).
  base: "./",
  plugins: [vue()],
  resolve: {
    alias: {
      // wasm-bindgen emits `import … from "purecrypto"` for purecrypto's
      // `random_get` host import; resolve it to our shim.
      purecrypto: fileURLToPath(new URL("./src/purecrypto-shim.js", import.meta.url)),
    },
  },
});
