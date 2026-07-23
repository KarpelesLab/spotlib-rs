<script setup>
import { onMounted, onUnmounted, ref, computed } from "vue";
import init, { SpotClient } from "./pkg/spot_web.js";
import wasmUrl from "./pkg/spot_web_bg.wasm?url";
import { setMemory } from "./purecrypto-shim.js";

const QUERY_MS = 15000;
// After this long with no online connection, show a diagnostic hint.
const DIAGNOSE_AFTER_MS = 12000;

// "loading" | "connecting" | "online" | "error"
const phase = ref("loading");
const targetId = ref("");
const connOnline = ref(0);
const connTotal = ref(0);
const busy = ref(false);
const log = ref([]);
const hint = ref("");

let client = null;
let pollTimer = null;
let diagnoseTimer = null;

const statusLabel = computed(
  () =>
    ({
      loading: "Loading wasm…",
      connecting: "Connecting…",
      online: "Online",
      error: "Error",
    })[phase.value],
);

const canAct = computed(() => phase.value === "online" && !busy.value);

function append(msg) {
  const ts = new Date().toLocaleTimeString();
  log.value.push(`[${ts}] ${msg}`);
}

// Status is derived by polling the client's live connection counts, so the page
// self-heals: if connections come up later (e.g. after a server-side change)
// it flips to "online" without a reload.
function poll() {
  if (!client) return;
  connOnline.value = client.connOnline();
  connTotal.value = client.connTotal();

  if (connOnline.value > 0 && phase.value !== "online") {
    phase.value = "online";
    hint.value = "";
    append(`online — ${connOnline.value}/${connTotal.value} connection(s)`);
  } else if (connOnline.value === 0 && phase.value === "online") {
    phase.value = "connecting";
    append("lost all connections — reconnecting…");
  }
}

function diagnose() {
  if (phase.value === "online") return;
  const origin = window.location.origin;
  if (connTotal.value > 0) {
    hint.value =
      `Connection attempts are being made but none complete the Spot handshake. ` +
      `The server is most likely rejecting this page's WebSocket Origin (${origin}) ` +
      `on /_websocket. It will connect automatically once the server allows this Origin.`;
  } else {
    hint.value =
      `No server connections yet — the host list (Spot:connect) may be unreachable ` +
      `from this origin (${origin}).`;
  }
  append(`diagnostic: ${hint.value}`);
}

onMounted(async () => {
  try {
    const wasm = await init(wasmUrl);
    // purecrypto's random_get writes into this memory; wire it before any
    // client is created (key generation is the first entropy draw).
    setMemory(wasm.memory);
    client = new SpotClient();
    targetId.value = client.targetId;
    append(`client created — id ${targetId.value}`);

    phase.value = "connecting";
    append("connecting to the Spot network…");
    poll();
    pollTimer = setInterval(poll, 1000);
    diagnoseTimer = setTimeout(diagnose, DIAGNOSE_AFTER_MS);
  } catch (e) {
    phase.value = "error";
    append(`init error: ${e}`);
  }
});

onUnmounted(() => {
  if (pollTimer) clearInterval(pollTimer);
  if (diagnoseTimer) clearTimeout(diagnoseTimer);
  if (client) client.close();
});

async function getTime() {
  if (!canAct.value) return;
  busy.value = true;
  append("query @/time …");
  try {
    const ms = await client.getTime(QUERY_MS);
    append(`server time: ${new Date(ms).toISOString()}`);
  } catch (e) {
    append(`@/time failed: ${e}`);
  } finally {
    busy.value = false;
  }
}

async function pingSelf() {
  if (!canAct.value) return;
  busy.value = true;
  const target = `${targetId.value}/ping`;
  const payload = "hello from the browser";
  append(`ping self → ${target} ("${payload}")`);
  try {
    const res = await client.queryText(target, payload, QUERY_MS);
    append(`ping response: "${res}"`);
  } catch (e) {
    append(`ping failed: ${e}`);
  } finally {
    busy.value = false;
  }
}
</script>

<template>
  <main>
    <header>
      <h1>spotlib <span class="tag">wasm</span></h1>
      <p class="sub">
        A browser client built from the Rust <code>spotlib</code> crate,
        connected to the live Spot network over WebSocket.
      </p>
    </header>

    <section class="status">
      <span class="dot" :class="phase"></span>
      <span class="label">{{ statusLabel }}</span>
      <span class="conns" v-if="phase !== 'loading'">
        {{ connOnline }}/{{ connTotal }} online
      </span>
    </section>

    <section class="id" v-if="targetId">
      <div class="k">this client</div>
      <code class="v">{{ targetId }}</code>
    </section>

    <section class="hint" v-if="hint">{{ hint }}</section>

    <section class="actions">
      <button :disabled="!canAct" @click="getTime">Get server time</button>
      <button :disabled="!canAct" @click="pingSelf">Ping self (e2e round-trip)</button>
    </section>

    <section class="log">
      <div v-for="(line, i) in log" :key="i" class="line">{{ line }}</div>
    </section>

    <footer>
      Self-ping sends an end-to-end encrypted message addressed to this client's
      own <code>/ping</code> endpoint; it leaves the browser, routes through the
      Spot network, and comes back — proving a real round-trip.
    </footer>
  </main>
</template>

<style>
:root {
  color-scheme: dark;
  --bg: #0d1117;
  --panel: #161b22;
  --border: #30363d;
  --fg: #e6edf3;
  --muted: #8b949e;
  --accent: #58a6ff;
  --ok: #3fb950;
  --warn: #d29922;
  --err: #f85149;
}
* {
  box-sizing: border-box;
}
body {
  margin: 0;
  background: var(--bg);
  color: var(--fg);
  font: 15px/1.55 ui-sans-serif, system-ui, -apple-system, sans-serif;
}
main {
  max-width: 720px;
  margin: 0 auto;
  padding: 2.5rem 1.25rem 4rem;
}
h1 {
  margin: 0;
  font-size: 1.9rem;
  letter-spacing: -0.02em;
}
.tag {
  font-size: 0.7rem;
  vertical-align: super;
  color: var(--accent);
  border: 1px solid var(--accent);
  border-radius: 999px;
  padding: 0.1rem 0.5rem;
  letter-spacing: 0.04em;
}
.sub {
  color: var(--muted);
  margin: 0.5rem 0 2rem;
}
code {
  font-family: ui-monospace, "SF Mono", Menlo, monospace;
}
.status {
  display: flex;
  align-items: center;
  gap: 0.6rem;
  margin-bottom: 1.25rem;
}
.dot {
  width: 0.7rem;
  height: 0.7rem;
  border-radius: 50%;
  background: var(--muted);
  box-shadow: 0 0 0 3px rgba(255, 255, 255, 0.04);
}
.dot.connecting {
  background: var(--warn);
  animation: pulse 1.2s infinite;
}
.dot.online {
  background: var(--ok);
}
.dot.error {
  background: var(--err);
}
@keyframes pulse {
  0%,
  100% {
    opacity: 1;
  }
  50% {
    opacity: 0.35;
  }
}
.label {
  font-weight: 600;
}
.conns {
  color: var(--muted);
  font-size: 0.85rem;
  margin-left: auto;
}
.id {
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 0.85rem 1rem;
  margin-bottom: 1.5rem;
}
.id .k {
  color: var(--muted);
  font-size: 0.72rem;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  margin-bottom: 0.3rem;
}
.id .v {
  word-break: break-all;
  color: var(--accent);
}
.hint {
  background: rgba(210, 153, 34, 0.1);
  border: 1px solid var(--warn);
  color: #e3b341;
  border-radius: 10px;
  padding: 0.75rem 1rem;
  font-size: 0.85rem;
  line-height: 1.5;
  margin-bottom: 1.5rem;
}
.actions {
  display: flex;
  flex-wrap: wrap;
  gap: 0.75rem;
  margin-bottom: 1.75rem;
}
button {
  background: var(--accent);
  color: #0d1117;
  border: 0;
  border-radius: 8px;
  padding: 0.6rem 1.1rem;
  font-size: 0.9rem;
  font-weight: 600;
  cursor: pointer;
  transition: opacity 0.15s;
}
button:hover:not(:disabled) {
  opacity: 0.88;
}
button:disabled {
  opacity: 0.4;
  cursor: not-allowed;
}
.log {
  background: #010409;
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 1rem;
  min-height: 9rem;
  max-height: 24rem;
  overflow-y: auto;
  font-family: ui-monospace, "SF Mono", Menlo, monospace;
  font-size: 0.82rem;
}
.line {
  white-space: pre-wrap;
  word-break: break-all;
  padding: 0.1rem 0;
  color: #c9d1d9;
}
footer {
  margin-top: 2rem;
  color: var(--muted);
  font-size: 0.8rem;
  line-height: 1.6;
}
</style>
