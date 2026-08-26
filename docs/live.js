// The live half of the page: a real tollgate gateway, a real Redis token
// bucket, shared by everyone who has this page open.
//
// Nothing here simulates anything. The button issues a request through the
// gateway to a demo upstream; what comes back is the gateway's own answer, and
// the rate-limit headers are the ones its Redis Lua script wrote. The key below
// is public on purpose: it is scoped to a tenant whose only route points at an
// echo service, so the worst anyone can do with it is exhaust a bucket that
// refills every second.

// Wrapped in its own scope: app.js runs in the same global and already
// declares $, state and friends. Two classic scripts sharing one scope is how
// you get "identifier already declared" at load and a blank instrument.
(() => {
const GATEWAY = 'https://gateway-production-dcde.up.railway.app';
const DEMO_KEY = 'tg_k67b733b4b295_Ob2dTQIX15fDW8drcd87eXhWHs3sznUGJcBRzFGfivk';

const el = (id) => document.getElementById(id);
const state = { limit: 12, remaining: null, mine: 0, limited: 0, inflight: false };

function setState(kind, text) {
  const node = el('live-state');
  node.className = `live-state ${kind}`;
  node.textContent = text;
}

// Tokens are drawn from the bucket's own numbers, so a token that vanishes
// without you pressing anything is somebody else's request, not an animation.
function drawBucket(prevRemaining) {
  const b = el('bucket');
  const limit = state.limit;
  const rem = state.remaining ?? limit;
  b.innerHTML = '';
  for (let i = 0; i < limit; i++) {
    const t = document.createElement('div');
    t.className = 'tok';
    if (i >= rem) t.classList.add('spent');
    b.appendChild(t);
  }
  el('l-rem').textContent = rem;
  el('l-limit').textContent = limit;
  el('l-mine').textContent = state.mine;
  const l429 = el('l-429');
  l429.textContent = state.limited;
  l429.className = state.limited ? 'bad' : '';
  if (prevRemaining != null && rem < prevRemaining - 0.5) return rem;
  return rem;
}

function log(code, note, mine) {
  const wrap = el('log');
  const row = document.createElement('div');
  const cls = code === 429 ? 'limited' : code >= 400 || code === 0 ? 'err' : '';
  const t = new Date().toLocaleTimeString('en-GB', { hour12: false });
  row.innerHTML =
    `<span class="t">${t}</span><span class="code ${cls}">${code || 'ERR'}</span>` +
    `<span>${note}</span><span class="who">${mine ? 'you' : ''}</span>`;
  wrap.prepend(row);
  while (wrap.children.length > 40) wrap.lastChild.remove();
}

function readHeaders(res) {
  const lim = Number(res.headers.get('X-RateLimit-Limit'));
  const rem = Number(res.headers.get('X-RateLimit-Remaining'));
  if (Number.isFinite(lim) && lim > 0) state.limit = lim;
  if (Number.isFinite(rem)) state.remaining = rem;
  return Number(res.headers.get('Retry-After'));
}

async function send({ quiet = false } = {}) {
  try {
    const res = await fetch(`${GATEWAY}/demo/echo`, {
      headers: { Authorization: `Bearer ${DEMO_KEY}` },
    });
    const retry = readHeaders(res);
    state.mine += 1;
    if (res.status === 429) {
      state.limited += 1;
      if (!quiet) log(429, `rate limited, retry after ${retry || 1}s`, true);
      else log(429, `rate limited, retry after ${retry || 1}s`, true);
    } else if (res.ok) {
      log(res.status, 'proxied to the upstream', true);
    } else {
      log(res.status, 'gateway said no', true);
    }
    setState('up', 'gateway live');
    drawBucket();
    return res.status;
  } catch (e) {
    log(0, 'could not reach the gateway', true);
    setState('down', 'gateway unreachable');
    return 0;
  }
}

// A sleeping service answers the first request slowly rather than not at all,
// so this says so instead of looking broken.
async function probe() {
  setState('waking', 'waking the gateway');
  const started = performance.now();
  try {
    const res = await fetch(`${GATEWAY}/demo/echo`, {
      headers: { Authorization: `Bearer ${DEMO_KEY}` },
    });
    readHeaders(res);
    const ms = Math.round(performance.now() - started);
    setState('up', 'gateway live');
    el('live-meta').textContent =
      `${GATEWAY.replace('https://', '')} · woke in ${ms} ms`;
    el('send').disabled = false;
    el('burst').disabled = false;
    drawBucket();
    log(res.status, 'first contact', false);
  } catch (e) {
    setState('down', 'gateway unreachable');
    el('live-meta').textContent = 'it may be asleep; reload to try again';
  }
}

// Poll gently so a token disappearing because of somebody else is visible.
// HEAD-like polling would still spend a token, so this only refreshes after
// your own requests and on a slow timer that costs one token a minute.
function watch() {
  setInterval(async () => {
    if (document.hidden || state.inflight) return;
    const before = state.remaining;
    state.inflight = true;
    try {
      const res = await fetch(`${GATEWAY}/demo/echo`, {
        headers: { Authorization: `Bearer ${DEMO_KEY}` },
      });
      readHeaders(res);
      if (before != null && state.remaining < before - 1) {
        log(res.status, `${before - state.remaining - 1} taken by someone else`, false);
      }
      drawBucket();
    } catch { /* leave the last known state on screen */ }
    finally { state.inflight = false; }
  }, 60000);
}

el('send').addEventListener('click', () => send());
el('burst').addEventListener('click', async () => {
  el('burst').disabled = true;
  for (let i = 0; i < 15; i++) {
    await send({ quiet: true });
  }
  el('burst').disabled = false;
});

drawBucket();
probe().then(watch);

// ---- section tabs -------------------------------------------------------
const tabs = [...document.querySelectorAll('.tabs a')];
const targets = tabs.map((a) => document.querySelector(a.getAttribute('href'))).filter(Boolean);
const spy = new IntersectionObserver((entries) => {
  const visible = entries.filter((e) => e.isIntersecting)
    .sort((a, b) => b.intersectionRatio - a.intersectionRatio)[0];
  if (!visible) return;
  tabs.forEach((a) =>
    a.setAttribute('aria-current', String(a.getAttribute('href') === `#${visible.target.id}`)));
}, { rootMargin: '-96px 0px -55% 0px', threshold: [0.05, 0.3] });
targets.forEach((t) => spy.observe(t));
})();
