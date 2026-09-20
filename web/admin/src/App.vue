<script setup lang="ts">
import { computed, ref } from "vue";
import { AdminAPI } from "./api";
import type { Algorithm, APIKey, IssuedKey, Overview, Route, Tenant } from "./types";

const props = defineProps<{ mountPath: string }>();

const emptyOverview = (): Overview => ({ tenants: [], routes: [], keys: [], usage: {} });
const tokenInput = ref("");
const token = ref("");
const data = ref<Overview>(emptyOverview());
const locked = ref(true);
const busy = ref(false);
const error = ref("");
const secret = ref<{ title: string; value: IssuedKey } | null>(null);

const tenantID = ref("");
const tenantName = ref("");
const algorithm = ref<Algorithm>("sliding_window");
const tenantLimit = ref(100);
const windowSeconds = ref(60);

const routeTenant = ref("");
const routePrefix = ref("/anthropic/");
const routeUpstream = ref("https://api.anthropic.com");
const routeHeader = ref("x-api-key");
const routeEnv = ref("ANTHROPIC_API_KEY");

const client = computed(() => new AdminAPI(props.mountPath, token.value));

async function run(operation: () => Promise<void>) {
  busy.value = true;
  error.value = "";
  try {
    await operation();
  } catch (cause) {
    error.value = cause instanceof Error ? cause.message : String(cause);
  } finally {
    busy.value = false;
  }
}

async function refresh() {
  data.value = await client.value.overview();
  data.value.usage ||= {};
  if (!routeTenant.value && data.value.tenants.length) {
    routeTenant.value = data.value.tenants[0].id;
  }
}

async function unlock() {
  const candidate = tokenInput.value.trim();
  if (!candidate) return;
  token.value = candidate;
  await run(async () => {
    await refresh();
    tokenInput.value = "";
    locked.value = false;
  });
  if (error.value) token.value = "";
}

function lock() {
  token.value = "";
  tokenInput.value = "";
  data.value = emptyOverview();
  secret.value = null;
  locked.value = true;
  error.value = "";
}

async function createTenant() {
  const id = tenantID.value.trim();
  if (!id) return;
  await run(async () => {
    const windowMs = Math.max(1, windowSeconds.value) * 1000;
    await client.value.request("POST", "/tenants", {
      id,
      name: tenantName.value.trim() || id,
      algorithm: algorithm.value,
      limit: tenantLimit.value,
      window_ms: windowMs,
      rate: tenantLimit.value / Math.max(1, windowMs / 1000),
      burst: tenantLimit.value,
    });
    tenantID.value = "";
    tenantName.value = "";
    routeTenant.value = id;
    await refresh();
  });
}

async function addRoute() {
  if (!routeTenant.value) return;
  await run(async () => {
    await client.value.request("POST", `/tenants/${encodeURIComponent(routeTenant.value)}/routes`, {
      path_prefix: routePrefix.value.trim(),
      upstream: routeUpstream.value.trim(),
      strip_prefix: true,
      auth_header: routeHeader.value.trim(),
      auth_env: routeEnv.value.trim(),
    });
    await refresh();
  });
}

function reveal(title: string, value: IssuedKey) {
  secret.value = { title, value };
  window.scrollTo({ top: 0, behavior: "smooth" });
}

async function issueKey(tenant: Tenant) {
  await run(async () => {
    const issued = await client.value.request<IssuedKey>(
      "POST", `/tenants/${encodeURIComponent(tenant.id)}/keys`, {},
    );
    reveal(`New key for ${tenant.id}`, issued);
    await refresh();
  });
}

async function toggleTenant(tenant: Tenant) {
  if (tenant.enabled && !window.confirm(
    `Cut off ${tenant.id}? Every key and route for this teammate stops serving after config reload.`,
  )) return;
  await run(async () => {
    await client.value.request("PUT", `/tenants/${encodeURIComponent(tenant.id)}`, {
      name: tenant.name,
      enabled: !tenant.enabled,
      algorithm: tenant.algorithm,
      rate: tenant.rate,
      burst: tenant.burst,
      window_ms: tenant.window_ms,
      limit: tenant.limit,
    });
    await refresh();
  });
}

async function rotateKey(key: APIKey) {
  if (!window.confirm(
    `Rotate ${key.id}? The replacement is shown once and the old key enters a 24-hour grace window.`,
  )) return;
  await run(async () => {
    const issued = await client.value.request<IssuedKey>(
      "POST", `/keys/${encodeURIComponent(key.id)}/rotate`, {},
    );
    reveal("Replacement key, old key works for 24 hours", issued);
    await refresh();
  });
}

async function revokeKey(key: APIKey) {
  if (!window.confirm(
    `Revoke ${key.id} immediately? It stops working on every replica after config reload.`,
  )) return;
  await run(async () => {
    await client.value.request("DELETE", `/keys/${encodeURIComponent(key.id)}`);
    await refresh();
  });
}

async function deleteRoute(route: Route) {
  if (!window.confirm(
    `Delete ${route.path_prefix} for ${route.tenant_id}? Requests on this path will stop routing.`,
  )) return;
  await run(async () => {
    await client.value.request("DELETE", `/routes/${encodeURIComponent(route.id)}`);
    await refresh();
  });
}

function policyOf(tenant: Tenant): string {
  return tenant.algorithm === "sliding_window"
    ? `${tenant.limit} per ${tenant.window_ms / 1000}s`
    : `${tenant.rate}/s burst ${tenant.burst}`;
}
</script>

<template>
  <header>
    <div>
      <h1>tollgate<b>.</b> console</h1>
      <div class="sub">One key per teammate, one budget each. The provider credential stays in this gateway's environment.</div>
    </div>
    <div v-if="!locked" id="hdr-actions" class="row">
      <button :disabled="busy" @click="run(refresh)">Refresh</button>
      <button @click="lock">Lock</button>
    </div>
  </header>

  <main>
    <div v-if="locked" id="gate-screen">
      <form class="card" @submit.prevent="unlock">
        <h2>Admin token</h2>
        <label for="token">ADMIN_TOKEN from the gateway's environment</label>
        <input id="token" v-model="tokenInput" type="password" autocomplete="off" spellcheck="false" placeholder="paste it here">
        <div class="note">Held in this tab's memory only. Never written to storage, never put in a URL.</div>
        <div class="row action-row"><button class="primary" :disabled="busy || !tokenInput.trim()">Unlock</button></div>
        <div v-if="error" id="gate-err" class="err" role="alert">{{ error }}</div>
      </form>
    </div>

    <div v-else id="console-app">
      <div v-if="error" class="err banner" role="alert">{{ error }}</div>
      <div v-if="secret" class="secret" role="status">
        <b>{{ secret.title }}</b>
        <code>{{ secret.value.key }}</code>
        <div class="why">Copy it now. Only its hash is stored, so this is the last time anyone can read it. Give it to {{ secret.value.tenant }} and have them set it as their SDK api_key, with base_url pointed at this gateway.</div>
        <button class="secret-close" @click="secret = null">I copied it</button>
      </div>

      <section>
        <h2>Teammates</h2>
        <div class="card wrap">
          <table id="tenants">
            <thead><tr><th>Tenant</th><th>Policy</th><th>State</th><th class="num">Requests</th><th class="num">429s</th><th>Keys</th><th>Routes</th><th></th></tr></thead>
            <tbody>
              <tr v-for="tenant in data.tenants" :key="tenant.id">
                <td class="mono">{{ tenant.id }}<div class="sub">{{ tenant.name }}</div></td>
                <td class="mono">{{ policyOf(tenant) }}</td>
                <td><span class="pill" :class="tenant.enabled ? 'on' : 'off'">{{ tenant.enabled ? 'open' : 'shut' }}</span></td>
                <td class="num">{{ (data.usage[tenant.id]?.requests || 0).toLocaleString() }}</td>
                <td class="num" :class="{ limited: (data.usage[tenant.id]?.limited || 0) > 0 }">{{ (data.usage[tenant.id]?.limited || 0).toLocaleString() }}</td>
                <td class="num">{{ tenant.active_keys }}</td><td class="num">{{ tenant.routes }}</td>
                <td><div class="row"><button :disabled="busy" @click="issueKey(tenant)">Issue key</button><button :disabled="busy" :class="{ danger: tenant.enabled }" @click="toggleTenant(tenant)">{{ tenant.enabled ? 'Cut off' : 'Restore' }}</button></div></td>
              </tr>
              <tr v-if="!data.tenants.length"><td colspan="8" class="note">No tenants yet. Add one below.</td></tr>
            </tbody>
          </table>
          <div class="note">Request and 429 counts come from this gateway process's metrics registry. Behind multiple replicas, scrape /metrics for fleet-wide numbers.</div>
        </div>
      </section>

      <section>
        <h2>Add a teammate</h2>
        <form class="card gate" @submit.prevent="createTenant">
          <div class="grid">
            <div><label for="t-id">Tenant id</label><input id="t-id" v-model="tenantID" required placeholder="alice" spellcheck="false"></div>
            <div><label for="t-name">Display name</label><input id="t-name" v-model="tenantName" placeholder="Alice"></div>
            <div><label for="t-algo">Limiter</label><select id="t-algo" v-model="algorithm"><option value="sliding_window">sliding window</option><option value="token_bucket">token bucket</option></select></div>
            <div><label for="t-limit">Requests per window</label><input id="t-limit" v-model.number="tenantLimit" type="number" min="1" required></div>
            <div><label for="t-window">Window, seconds</label><input id="t-window" v-model.number="windowSeconds" type="number" min="1" required></div>
            <div><button class="primary" :disabled="busy">Create</button></div>
          </div>
        </form>
      </section>

      <section>
        <h2>Point a teammate at an upstream</h2>
        <form class="card" @submit.prevent="addRoute">
          <div class="grid">
            <div><label for="r-tenant">Tenant</label><select id="r-tenant" v-model="routeTenant" required><option v-for="tenant in data.tenants" :key="tenant.id" :value="tenant.id">{{ tenant.id }}</option></select></div>
            <div><label for="r-prefix">Path prefix</label><input id="r-prefix" v-model="routePrefix" required spellcheck="false"></div>
            <div><label for="r-upstream">Upstream</label><input id="r-upstream" v-model="routeUpstream" required type="url" spellcheck="false"></div>
            <div><label for="r-header">Inject header</label><input id="r-header" v-model="routeHeader" spellcheck="false"></div>
            <div><label for="r-env">From env var</label><input id="r-env" v-model="routeEnv" spellcheck="false"></div>
            <div><button class="primary" :disabled="busy || !routeTenant">Add route</button></div>
          </div>
          <div class="note">The gateway reads that env var at request time and attaches it upstream. The value never enters this page, API, or Postgres.</div>
        </form>
      </section>

      <section>
        <h2>Routes</h2>
        <div class="card wrap"><table id="routes"><thead><tr><th>Tenant</th><th>Prefix</th><th>Upstream</th><th>Credential</th><th></th></tr></thead><tbody>
          <tr v-for="route in data.routes" :key="route.id"><td class="mono">{{ route.tenant_id }}</td><td class="mono">{{ route.path_prefix }}</td><td class="mono">{{ route.upstream }}</td><td class="mono">{{ route.credential_set ? `$${route.credential_from}` : 'none' }}</td><td><button class="danger" :disabled="busy" @click="deleteRoute(route)">Delete</button></td></tr>
          <tr v-if="!data.routes.length"><td colspan="5" class="note">No routes yet.</td></tr>
        </tbody></table></div>
      </section>

      <section>
        <h2>Keys</h2>
        <div class="card wrap"><table id="keys"><thead><tr><th>Key id</th><th>Tenant</th><th>Status</th><th>Issued</th><th></th></tr></thead><tbody>
          <tr v-for="key in data.keys" :key="key.id"><td class="mono">{{ key.id }}</td><td class="mono">{{ key.tenant_id }}</td><td><span class="pill" :class="key.status === 'active' ? 'on' : key.status === 'revoked' ? 'off' : ''">{{ key.status }}</span></td><td class="mono">{{ new Date(key.created_at).toLocaleString() }}</td><td><div class="row"><button :disabled="busy || key.status !== 'active'" @click="rotateKey(key)">Rotate</button><button class="danger" :disabled="busy || key.status === 'revoked'" @click="revokeKey(key)">Revoke</button></div></td></tr>
          <tr v-if="!data.keys.length"><td colspan="5" class="note">No keys yet.</td></tr>
        </tbody></table><div class="note">Only each secret's SHA-256 is stored. Rotate hands out a replacement and leaves the old key working for 24 hours; revoke kills it now.</div></div>
      </section>
    </div>
  </main>
</template>
