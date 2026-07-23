// Satisfies purecrypto's `random_get` wasm import.
//
// purecrypto's OsRng (wasm32-unknown-unknown) imports `purecrypto.random_get`.
// Modern wasm-bindgen (`--target web`) emits `import * as … from "purecrypto"`
// for that module, so we provide it as a real ES module (wired via a Vite alias
// on the bare specifier `purecrypto`) instead of patching the generated glue.
//
// `random_get` needs to write into the wasm instance's linear memory, which is
// only known after instantiation — so the app calls `setMemory(wasm.memory)`
// once `init()` resolves, before creating any client (key generation is the
// first thing that draws entropy).

let memory = null;

/// Provide the wasm instance's `WebAssembly.Memory` (call once after init()).
export function setMemory(m) {
  memory = m;
}

/// Fill `len` bytes at `ptr` in wasm memory with CSPRNG output.
export function random_get(ptr, len) {
  if (!memory) {
    throw new Error("purecrypto.random_get called before setMemory()");
  }
  const view = new Uint8Array(memory.buffer, ptr >>> 0, len >>> 0);
  // crypto.getRandomValues caps at 65536 bytes per call — chunk it.
  for (let off = 0; off < view.length; off += 65536) {
    crypto.getRandomValues(view.subarray(off, Math.min(off + 65536, view.length)));
  }
}
