// tollgate demo: the real limiter code (Go, compiled to WASM) run as two
// gateways on a virtual clock: per-replica counters vs one shared store.

let ready = false;
const $ = (id) => document.getElementById(id);
const fmt = (n) => Math.round(n).toLocaleString('en-US');
const usd = (n) => '$' + n.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
const css = (n) => getComputedStyle(document.documentElement).getPropertyValue(n).trim();
const INK = css('--ink'), OX = css('--ox'), SUB = css('--sub'), FAINT = css('--faint'), HAIR = css('--hair'), BAD = css('--bad');

const go = new Go();
WebAssembly.instantiateStreaming(fetch('demo/tollgate.wasm'), go.importObject).then((r) => {
  go.run(r.instance); // resolves tgRun global, then parks
  ready = true;
  $('led-label').textContent = 'engine live · wasm · virtual clock';
  $('go').disabled = false;
  run();
});

for (const [id, unit] of [['rate', '/s'], ['replicas', ''], ['offered', '/s']]) {
  $(id).addEventListener('input', () => {
    $(id + '-val').textContent = (+$(id).value).toLocaleString('en-US') + unit;
  });
}
$('go').addEventListener('click', run);

const PRICE = 0.002; // illustrative $ per LLM request; labeled as such in the table

function run() {
  if (!ready || typeof tgRun !== 'function') return;
  const rate = +$('rate').value;
  const res = JSON.parse(tgRun($('algo').value, rate, rate, +$('replicas').value, +$('offered').value, 30));
  if (res.error) {
    const v = $('verdict');
    v.className = 'verdict bad';
    v.textContent = res.error;
    return;
  }
  drawChart(res);

  $('b-offered').textContent = fmt(res.total_offered);
  $('b-bound').textContent = fmt(res.max_admitted);
  $('b-per').textContent = fmt(res.total_per_replica);
  $('b-shared').textContent = fmt(res.total_shared);
  $('b-over').textContent = res.over_admit_ratio.toFixed(2) + '×';

  const over = Math.max(0, res.total_per_replica - res.max_admitted);
  $('r-count').textContent = fmt(over);
  $('r-cost').textContent = usd(over * PRICE);
  $('r-day').textContent = usd(over * PRICE * 2880); // 30s → 24h at the same load

  const v = $('verdict');
  const withinPolicy = res.total_shared <= res.max_admitted;
  if (!withinPolicy) {
    v.className = 'verdict bad';
    v.innerHTML = `<b>The shared store exceeded the policy bound</b> (${fmt(res.total_shared)} &gt; ` +
      `${fmt(res.max_admitted)}): that would be a real bug in the limiter math. Please open an issue ` +
      `with these knob values.`;
    return;
  }
  const perSec = Math.round(res.total_per_replica / 30);
  v.className = 'verdict';
  if (res.over_admit_ratio <= 1.02) {
    v.innerHTML = `At this load each replica's share sits under the ceiling, so even wrong counting ` +
      `stays lucky: <b>nothing was over-admitted</b>. Raise the offered load past ceiling &times; replicas ` +
      `and run it again; correctness that depends on light traffic is not correctness.`;
  } else {
    v.innerHTML = `Policy says ${fmt(rate)}/s. Per-replica counters admitted ${fmt(perSec)}/s, ` +
      `<b>${res.over_admit_ratio.toFixed(2)}&times; the ceiling</b>; the shared store never crossed the ` +
      `policy bound. Same replicas, same balancer, same algorithm; the only difference is where the ` +
      `counter lives.`;
  }
}

// ---------- chart ----------

const W = 1200, H = 380, PL = 64, PR = 24, PT = 22, PB = 42;

function drawChart(res) {
  const tl = res.timeline;
  const ceiling = res.ceiling_per_sec;
  const maxY = Math.max(ceiling * 1.15, ...tl.map((s) => Math.max(s.per_replica, s.shared_store, s.offered)));
  const x = (sec) => PL + (W - PL - PR) * sec / (tl.length - 1);
  const y = (v) => H - PB - (H - PT - PB) * v / maxY;
  const line = (pick) => tl.map((s, i) => (i ? 'L' : 'M') + x(s.second).toFixed(1) + ' ' + y(pick(s)).toFixed(1)).join(' ');
  const label = (tx, ty, text, fill, anchor = 'start') =>
    `<text x="${tx}" y="${ty}" text-anchor="${anchor}" fill="${fill}" font-size="13" font-style="italic" font-family="Times New Roman, serif">${text}</text>`;

  let g = '';
  for (let i = 0; i <= 4; i++) {
    const yy = PT + (H - PT - PB) * i / 4;
    g += `<line x1="${PL}" y1="${yy}" x2="${W - PR}" y2="${yy}" stroke="${HAIR}" stroke-width="1"/>`;
    g += `<text x="${PL - 8}" y="${yy + 4}" text-anchor="end" fill="${FAINT}" font-size="12" font-family="Times New Roman, serif">${fmt(maxY * (4 - i) / 4)}</text>`;
  }
  for (let i = 0; i <= 5; i++) {
    const sec = Math.round((tl.length - 1) * i / 5);
    g += `<text x="${x(sec)}" y="${H - 14}" text-anchor="middle" fill="${FAINT}" font-size="12" font-family="Times New Roman, serif">${sec}s</text>`;
  }

  // over-admitted region between the ceiling and the per-replica curve
  const overPts = tl.map((s) => [x(s.second), y(Math.max(s.per_replica, ceiling))]);
  let area = 'M' + overPts.map((p) => p[0].toFixed(1) + ' ' + p[1].toFixed(1)).join(' L');
  area += ` L${x(tl.length - 1).toFixed(1)} ${y(ceiling).toFixed(1)} L${x(0).toFixed(1)} ${y(ceiling).toFixed(1)} Z`;
  g += `<path d="${area}" fill="${BAD}" fill-opacity=".08"/>`;

  g += `<path d="${line((s) => s.offered)}" fill="none" stroke="${FAINT}" stroke-width="1.5" stroke-dasharray="2 4"/>`;
  g += `<line x1="${PL}" y1="${y(ceiling)}" x2="${W - PR}" y2="${y(ceiling)}" stroke="${INK}" stroke-width="1.2"/>`;
  g += label(W - PR - 4, y(ceiling) - 7, `policy ${fmt(ceiling)}/s`, INK, 'end');
  g += `<path d="${line((s) => s.per_replica)}" fill="none" stroke="${SUB}" stroke-width="2" stroke-dasharray="6 5"/>`;
  g += `<path d="${line((s) => s.shared_store)}" fill="none" stroke="${OX}" stroke-width="2.5"/>`;

  const mid = Math.floor(tl.length / 2);
  g += label(x(mid), y(tl[mid].offered) - 8, 'offered', FAINT, 'middle');
  g += label(x(mid), y(tl[mid].per_replica) - 8, 'per-replica counters', SUB, 'middle');
  g += label(x(mid), y(tl[mid].shared_store) + 18, 'one shared store', OX, 'middle');
  $('chart').innerHTML = g;
}
