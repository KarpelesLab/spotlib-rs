<script setup>
defineProps({
  card: { type: Object, required: true },
  title: { type: String, default: "identity card" },
});

function fmtTime(unixSecs) {
  if (!unixSecs) return "—";
  return new Date(unixSecs * 1000)
    .toISOString()
    .replace("T", " ")
    .replace(".000Z", "Z");
}
</script>

<template>
  <section class="card">
    <div class="k">{{ title }}</div>
    <dl>
      <dt>address</dt>
      <dd><code class="mono">{{ card.id }}</code></dd>

      <dt>issued</dt>
      <dd>{{ fmtTime(card.issued) }}</dd>

      <dt>subkeys</dt>
      <dd>
        <div v-for="s in card.subkeys" :key="s.id" class="row">
          <span class="purposes">{{ s.purposes.join(", ") || "—" }}</span>
          <code class="mono">{{ s.id }}</code>
        </div>
      </dd>

      <dt>groups</dt>
      <dd>
        <template v-if="card.groups.length">
          <div v-for="g in card.groups" :key="g.key" class="row">
            <span class="status" :class="{ ok: g.status === 'valid' }">{{ g.status }}</span>
            <code class="mono">{{ g.key }}</code>
          </div>
        </template>
        <span v-else class="none">none</span>
      </dd>

      <dt>metadata</dt>
      <dd>
        <template v-if="card.meta && Object.keys(card.meta).length">
          <div v-for="(val, key) in card.meta" :key="key" class="row">
            <span class="purposes">{{ key }}</span>
            <span class="mono">{{ val }}</span>
          </div>
        </template>
        <span v-else class="none">none</span>
      </dd>
    </dl>
  </section>
</template>
