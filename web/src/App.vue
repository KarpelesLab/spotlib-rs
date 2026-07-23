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
const idCard = ref(null);

let client = null;
let pollTimer = null;
let diagnoseTimer = null;
let lastOnline = -1;

function fmtTime(unixSecs) {
  if (!unixSecs) return "—";
  return new Date(unixSecs * 1000).toISOString().replace("T", " ").replace(".000Z", "Z");
}

function refreshIdCard() {
  if (!client) return;
  try {
    idCard.value = JSON.parse(client.idCardJson());
  } catch (e) {
    append(`id card read failed: ${e}`);
  }
}

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

  // Re-read the ID card when the online count changes — group memberships are
  // filled in by the server during the handshake.
  if (connOnline.value !== lastOnline) {
    lastOnline = connOnline.value;
    refreshIdCard();
  }

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
    refreshIdCard();
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

// --- sending commands to a manually specified peer --------------------------

const peerId = ref("");
// A peer command is only sendable once online, when idle, and with a plausible
// key-based address.
const peerValid = computed(() => peerId.value.trim().startsWith("k."));
const canSendPeer = computed(() => canAct.value && peerValid.value);

function hexPreview(bytes, n = 16) {
  const head = Array.from(bytes.slice(0, n))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return head + (bytes.length > n ? "…" : "");
}

// `version` replies with a UTF-8 string; `finger` replies with the peer's
// signed ID card (binary), so it is shown as a byte count + hex preview.
async function sendPeerCommand(endpoint) {
  if (!canSendPeer.value) return;
  busy.value = true;
  const peer = peerId.value.trim();
  const target = `${peer}/${endpoint}`;
  append(`→ ${target}`);
  try {
    if (endpoint === "finger") {
      const res = await client.query(target, new Uint8Array(), QUERY_MS);
      append(`finger response: ${res.length} bytes — signed ID card [${hexPreview(res)}]`);
    } else {
      const res = await client.queryText(target, "", QUERY_MS);
      append(`${endpoint} response: "${res}"`);
    }
  } catch (e) {
    append(`${endpoint} failed: ${e}`);
  } finally {
    busy.value = false;
  }
}

function useSelfAsPeer() {
  peerId.value = targetId.value;
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

    <section class="card" v-if="idCard">
      <div class="k">identity card</div>
      <dl>
        <dt>issued</dt>
        <dd>{{ fmtTime(idCard.issued) }}</dd>

        <dt>subkeys</dt>
        <dd>
          <div v-for="s in idCard.subkeys" :key="s.id" class="row">
            <span class="purposes">{{ s.purposes.join(", ") || "—" }}</span>
            <code class="mono">{{ s.id }}</code>
          </div>
        </dd>

        <dt>groups</dt>
        <dd>
          <template v-if="idCard.groups.length">
            <div v-for="g in idCard.groups" :key="g.key" class="row">
              <span class="status" :class="{ ok: g.status === 'valid' }">{{ g.status }}</span>
              <code class="mono">{{ g.key }}</code>
            </div>
          </template>
          <span v-else class="none">none</span>
        </dd>

        <dt>metadata</dt>
        <dd>
          <template v-if="idCard.meta && Object.keys(idCard.meta).length">
            <div v-for="(val, key) in idCard.meta" :key="key" class="row">
              <span class="purposes">{{ key }}</span>
              <span class="mono">{{ val }}</span>
            </div>
          </template>
          <span v-else class="none">none</span>
        </dd>
      </dl>
    </section>

    <section class="hint" v-if="hint">{{ hint }}</section>

    <section class="actions">
      <button :disabled="!canAct" @click="getTime">Get server time</button>
      <button :disabled="!canAct" @click="pingSelf">Ping self (e2e round-trip)</button>
    </section>

    <section class="peer">
      <div class="k">send a command to a peer</div>
      <div class="peer-row">
        <input
          v-model="peerId"
          type="text"
          spellcheck="false"
          autocapitalize="off"
          placeholder="k.<peer id>"
        />
        <button class="ghost" :disabled="!targetId" @click="useSelfAsPeer">use self</button>
      </div>
      <div class="peer-cmds">
        <button :disabled="!canSendPeer" @click="sendPeerCommand('version')">version</button>
        <button :disabled="!canSendPeer" @click="sendPeerCommand('finger')">finger</button>
      </div>
      <p class="peer-note" v-if="peerId && !peerValid">A peer id must start with <code>k.</code></p>
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
.card {
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 0.85rem 1rem 1rem;
  margin-bottom: 1.5rem;
}
.card > .k {
  color: var(--muted);
  font-size: 0.72rem;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  margin-bottom: 0.6rem;
}
.card dl {
  margin: 0;
  display: grid;
  grid-template-columns: 6rem 1fr;
  gap: 0.4rem 0.75rem;
  font-size: 0.82rem;
}
.card dt {
  color: var(--muted);
  text-align: right;
}
.card dd {
  margin: 0;
  min-width: 0;
}
.card .row {
  display: flex;
  gap: 0.6rem;
  align-items: baseline;
  padding: 0.1rem 0;
}
.card .mono {
  font-family: ui-monospace, "SF Mono", Menlo, monospace;
  color: var(--accent);
  word-break: break-all;
}
.card .purposes {
  min-width: 6.5rem;
  color: var(--fg);
}
.card .status {
  min-width: 4rem;
  color: var(--warn);
}
.card .status.ok {
  color: var(--ok);
}
.card .none {
  color: var(--muted);
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
.peer {
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 0.85rem 1rem 1rem;
  margin-bottom: 1.75rem;
}
.peer .k {
  color: var(--muted);
  font-size: 0.72rem;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  margin-bottom: 0.55rem;
}
.peer-row {
  display: flex;
  gap: 0.5rem;
  margin-bottom: 0.6rem;
}
.peer-row input {
  flex: 1;
  min-width: 0;
  background: #010409;
  border: 1px solid var(--border);
  border-radius: 8px;
  color: var(--fg);
  padding: 0.55rem 0.7rem;
  font-family: ui-monospace, "SF Mono", Menlo, monospace;
  font-size: 0.82rem;
}
.peer-row input:focus {
  outline: none;
  border-color: var(--accent);
}
.peer-cmds {
  display: flex;
  gap: 0.6rem;
}
button.ghost {
  background: transparent;
  color: var(--muted);
  border: 1px solid var(--border);
}
button.ghost:hover:not(:disabled) {
  color: var(--fg);
  opacity: 1;
}
.peer-note {
  color: var(--warn);
  font-size: 0.78rem;
  margin: 0.6rem 0 0;
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
