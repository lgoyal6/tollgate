// tollgate demo: the real limiter code (Go, compiled to WASM) run as two
// gateways on a virtual clock: per-replica counters vs one shared store.

let last = null;
const $ = (id) => document.getElementById(id);
const fmt = (n) => Number(n).toLocaleString('en-US');

const go = new Go();
WebAssembly.instantiateStreaming(fetch('demo/tollgate.wasm'), go.importObject).then((r) => {
  go.run(r.instance); // resolves tgRun global, then parks
  $('led').dataset.state = 'on';
  $('led-label').textContent = 'engine loaded · virtual clock';
  $('panel').hidden = false;
  run();
});

for (const [id, unit] of [['rate', '/s'], ['replicas', ''], ['offered', '/s']]) {
  $(id).addEventListener('input', () => { $(id + '-val').textContent = $(id).value + unit; });
}
$('go').addEventListener('click', run);

function run() {
  if (typeof tgRun !== 'function') return;
  const rate = +$('rate').value;
  const res = JSON.parse(tgRun($('algo').value, rate, rate, +$('replicas').value, +$('offered').value, 30));
  if (res.error) {
    $('verdict').className = 'verdict bad';
    $('verdict').textContent = res.error;
    return;
  }
  last = res;
  drawChart(res);
  renderTiles(res);

  const n = +$('replicas').value;
  const v = $('verdict');
  const perRepPerSec = Math.round(res.total_per_replica / 30);
  const sharedPerSec = Math.round(res.total_shared / 30);
  const overshoot = (res.over_admit_ratio).toFixed(2);
  const withinPolicy = res.total_shared <= res.max_admitted;

  if (!withinPolicy) {
    v.className = 'verdict bad';
    v.textContent = `the shared store exceeded the policy bound (${fmt(res.total_shared)} > ${fmt(res.max_admitted)}): that would be a real bug in the limiter math.`;
    return;
  }
  v.className = 'verdict ok';
  v.textContent =
    `policy says ${fmt(rate)}/s. per-replica counters admitted ${fmt(perRepPerSec)}/s (${overshoot}x the ceiling, ` +
    `${fmt(res.total_per_replica - res.total_shared)} requests over 30s that should have been throttled).\n` +
    `the shared store admitted ${fmt(sharedPerSec)}/s and never crossed the policy bound of ${fmt(res.max_admitted)} ` +
    `for this horizon. same replicas, same load balancer; the only difference is where the counter lives.`;
}

function renderTiles(res) {
  const t = (l, v) => `<div class="tile"><span class="t-label">${l}</span><span class="t-value">${v}</span></div>`;
  $('tiles').innerHTML =
    t('offered', fmt(res.total_offered)) +
    t('per-replica admitted', fmt(res.total_per_replica)) +
    t('shared-store admitted', fmt(res.total_shared)) +
    t('over-admission', (res.over_admit_ratio).toFixed(2) + '<small>x</small>') +
    t('policy bound', fmt(res.max_admitted));
}

// ---------- chart ----------

const W = 720, H = 300, PL = 52, PR = 20, PT = 16, PB = 34;

function drawChart(res) {
  const tl = res.timeline;
  const ceiling = res.ceiling_per_sec;
  const maxY = Math.max(ceiling * 1.15, ...tl.map((s) => Math.max(s.per_replica, s.shared_store)));
  const x = (sec) => PL + (W - PL - PR) * sec / (tl.length - 1);
  const y = (v) => H - PB - (H - PT - PB) * v / maxY;

  const line = (pick) => tl.map((s, i) => (i ? 'L' : 'M') + x(s.second).toFixed(1) + ' ' + y(pick(s)).toFixed(1)).join(' ');

  let g = '';
  for (let i = 0; i <= 4; i++) {
    const yy = PT + (H - PT - PB) * i / 4;
    g += `<line class="grid" x1="${PL}" y1="${yy}" x2="${W - PR}" y2="${yy}"/>`;
    g += `<text class="axis-label" x="${PL - 8}" y="${yy + 4}" text-anchor="end">${fmt(Math.round(maxY * (4 - i) / 4))}</text>`;
  }
  for (let i = 0; i <= 5; i++) {
    const sec = Math.round((tl.length - 1) * i / 5);
    g += `<text class="axis-label" x="${x(sec)}" y="${H - 12}" text-anchor="middle">${sec}s</text>`;
  }

  // red tint for the over-admitted region between ceiling and per-replica curve
  const overPts = tl.map((s) => [x(s.second), y(Math.max(s.per_replica, ceiling))]);
  let area = 'M' + overPts.map((p) => p[0].toFixed(1) + ' ' + p[1].toFixed(1)).join(' L');
  area += ` L${x(tl.length - 1).toFixed(1)} ${y(ceiling).toFixed(1)} L${x(0).toFixed(1)} ${y(ceiling).toFixed(1)} Z`;
  g += `<path class="over" d="${area}"/>`;

  g += `<line class="ceiling" x1="${PL}" y1="${y(ceiling)}" x2="${W - PR}" y2="${y(ceiling)}"/>`;
  g += `<text class="ceiling-label" x="${W - PR - 4}" y="${y(ceiling) - 6}" text-anchor="end">policy: ${fmt(ceiling)}/s</text>`;

  g += `<path class="series-b" d="${line((s) => s.per_replica)}"/>`;
  g += `<path class="series-a" d="${line((s) => s.shared_store)}"/>`;
  g += `<g id="hover-layer"></g>`;
  $('chart').innerHTML = g;
}

$('chart').addEventListener('mousemove', (ev) => {
  if (!last) return;
  const svg = $('chart');
  const rect = svg.getBoundingClientRect();
  const px = (ev.clientX - rect.left) * W / rect.width;
  const tl = last.timeline;
  const sec = Math.max(0, Math.min(tl.length - 1, Math.round((px - PL) * (tl.length - 1) / (W - PL - PR))));
  const s = tl[sec];

  const layer = document.getElementById('hover-layer');
  if (layer) {
    const xx = PL + (W - PL - PR) * sec / (tl.length - 1);
    layer.innerHTML = `<line class="crosshair" x1="${xx}" y1="${PT}" x2="${xx}" y2="${H - PB}"/>`;
  }
  const tip = $('tooltip');
  tip.hidden = false;
  tip.textContent = `t=${s.second}s\nper-replica: ${fmt(s.per_replica)}/s\nshared store: ${fmt(s.shared_store)}/s\noffered: ${fmt(s.offered)}/s`;
  tip.style.left = Math.min(ev.clientX - rect.left + 14, rect.width - 170) + 'px';
  tip.style.top = (ev.clientY - rect.top + 10) + 'px';
});
$('chart').addEventListener('mouseleave', () => {
  $('tooltip').hidden = true;
  const layer = document.getElementById('hover-layer');
  if (layer) layer.innerHTML = '';
});
