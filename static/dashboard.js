async function getJSON(url) { const r = await fetch(url); return r.json(); }
function esc(s){return String(s ?? '').replace(/[&<>\"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));}
async function loadSummary(){
  const d = await getJSON('/api/summary');
  for (const id of ['total','blocked','flagged','allowed']) document.getElementById(id).textContent = d[id];
  const cats = Object.entries(d.by_category || {}); const max = Math.max(1, ...cats.map(x=>x[1]));
  document.getElementById('categories').innerHTML = cats.length ? cats.map(([k,v]) => `<div class="bar"><span>${esc(k)}</span><div class="track"><div class="fill" style="width:${(v/max)*100}%"></div></div><b>${v}</b></div>`).join('') : '<p>No detections yet.</p>';
  document.getElementById('ips').innerHTML = (d.top_ips || []).map(x=>`<div class="ip-row"><span>${esc(x.ip)}</span><b>${x.count}</b></div>`).join('') || '<p>No events yet.</p>';
}
async function loadEvents(){
  const rows = await getJSON('/api/events?limit=50');
  document.getElementById('events').innerHTML = rows.map(e => `<tr><td>${esc(new Date(e.ts).toLocaleString())}</td><td>${esc(e.ip)}</td><td>${esc(e.path)}</td><td class="decision-${esc(e.decision)}">${esc(e.decision)}</td><td>${esc(e.reason)}</td><td>${esc(e.max_severity)}</td></tr>`).join('') || '<tr><td colspan="6">No events yet.</td></tr>';
}
async function refreshAll(){ await Promise.all([loadSummary(), loadEvents()]); }
refreshAll(); setInterval(refreshAll, 5000);
