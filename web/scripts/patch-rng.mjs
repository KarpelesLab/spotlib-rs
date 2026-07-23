// Injects purecrypto's `random_get` host import into the wasm-bindgen glue.
//
// purecrypto's OsRng (wasm32-unknown-unknown) imports `purecrypto.random_get`,
// which wasm-bindgen does not provide — so the module would fail to instantiate.
// wasm-bindgen's `--target web` glue assembles its import object in
// `__wbg_get_imports()` and ends it with `return imports;`. We add our
// `imports.purecrypto` entry just before that return, wired to
// `crypto.getRandomValues`. The closure reads the live linear memory
// (`wasm.memory`, assigned after instantiation) at call time, so growth/detach
// is not a concern.
//
// Usage: node web/scripts/patch-rng.mjs <path-to-generated-js>

import { readFileSync, writeFileSync } from "node:fs";

const file = process.argv[2];
if (!file) {
  console.error("usage: node patch-rng.mjs <glue.js>");
  process.exit(1);
}

let src = readFileSync(file, "utf8");

if (src.includes("imports.purecrypto")) {
  console.log(`patch-rng: ${file} already patched, skipping`);
  process.exit(0);
}

// `return imports;` closes __wbg_get_imports() in every wasm-bindgen `--target
// web` version — a far more stable anchor than the internal `imports.wbg` line.
const anchor = "return imports;";
if (!src.includes(anchor)) {
  console.error(
    `patch-rng: anchor ${JSON.stringify(anchor)} not found in ${file}; ` +
      "the wasm-bindgen output format may have changed. First 60 lines:",
  );
  console.error(src.split("\n").slice(0, 60).join("\n"));
  process.exit(1);
}

const injection = `imports.purecrypto = {
        random_get(ptr, len) {
            const view = new Uint8Array(wasm.memory.buffer, ptr >>> 0, len >>> 0);
            // crypto.getRandomValues caps at 65536 bytes per call — chunk it.
            for (let off = 0; off < view.length; off += 65536) {
                crypto.getRandomValues(view.subarray(off, Math.min(off + 65536, view.length)));
            }
        },
    };
    ${anchor}`;

// Replace only the first occurrence (the one inside __wbg_get_imports).
src = src.replace(anchor, injection);
writeFileSync(file, src);
console.log(`patch-rng: injected purecrypto.random_get into ${file}`);
