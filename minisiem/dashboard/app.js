// Mini SIEM dashboard. All log-derived text goes through textContent: logs carry attacker-controlled payloads.
"use strict";

function apiKey() {
  const m = location.hash.match(/key=([^&]+)/);
  if (m) {
    sessionStorage.setItem("minisiem_key", decodeURIComponent(m[1]));
    history.replaceState(null, "", location.pathname);  // keep the key out of the address bar
  }
  let k = sessionStorage.getItem("minisiem_key");
  if (!k) {
    k = prompt("Mini SIEM API key") || "";
    sessionStorage.setItem("minisiem_key", k);
  }
  return k;
}
const KEY = apiKey();

async function api(path, params = {}) {
  const qs = new URLSearchParams(Object.entries(params).filter(([, v]) => v));
  const r = await fetch(`/api/${path}?${qs}`, { headers: { Authorization: `Bearer ${KEY}` } });
  if (r.status === 401) {
    sessionStorage.removeItem("minisiem_key");
    throw new Error("invalid API key; reload to enter it again");
  }
  if (!r.ok) throw new Error(`${path}: HTTP ${r.status}`);
  return r.json();
}

function el(tag, text, cls) {
  const e = document.createElement(tag);
  if (text !== undefined && text !== null) e.textContent = String(text);
  if (cls) e.className = cls;
  return e;
}

function sevBadge(sev) {
  const td = el("td");
  td.append(el("span", sev, `badge sev-${sev}`));
  return td;
}

const fmtTime = (t) => t.replace("T", " ").slice(0, 19);

const charts = {};
function chart(id, type, labels, datasets, opts = {}) {
  if (charts[id]) {
    charts[id].data.labels = labels;
    charts[id].data.datasets.forEach((d, i) => (d.data = datasets[i].data));
    charts[id].update("none");
    return;
  }
  charts[id] = new Chart(document.getElementById(id), {
    type, data: { labels, datasets },
    options: { maintainAspectRatio: false, animation: false, plugins: { legend: { display: datasets.length > 1 } },
               scales: { x: { ticks: { color: "#9aa4b2" } }, y: { ticks: { color: "#9aa4b2" }, beginAtZero: true } },
               ...opts },
  });
}

function filters() {
  const minutes = document.getElementById("f-period").value;
  return {
    severity: document.getElementById("f-severity").value,
    event_type: document.getElementById("f-type").value,
    ip: document.getElementById("f-ip").value.trim(),
    since: minutes ? new Date(Date.now() - minutes * 60000).toISOString() : "",
  };
}

function renderAlerts(alerts) {
  const body = document.getElementById("t-alerts");
  body.replaceChildren();
  if (!alerts.length) body.append(Object.assign(el("tr"), { innerHTML: '<td colspan="7" class="text-secondary">No alerts</td>' }));
  for (const a of alerts) {
    const tr = el("tr", null, "alert-row");
    tr.append(el("td", fmtTime(a.timestamp)), sevBadge(a.severity), el("td", a.title), el("td", a.src_ip ?? "–"),
              el("td", a.host ?? "–"), el("td", a.mitre), el("td", a.description));
    const detail = el("tr", null, "d-none");
    const td = el("td");
    td.colSpan = 7;
    td.append(el("div", `Rule: ${a.rule}`, "small text-secondary mb-1"), el("pre", a.evidence.join("\n"), "evidence mb-0"));
    detail.append(td);
    tr.addEventListener("click", () => detail.classList.toggle("d-none"));
    body.append(tr, detail);
  }
}

function renderEvents(events) {
  const body = document.getElementById("t-events");
  body.replaceChildren();
  for (const e of events) {
    const tr = el("tr");
    tr.append(el("td", fmtTime(e.timestamp)), el("td", e.event_type), el("td", e.src_ip ?? "–"), el("td", e.user ?? "–"),
              el("td", e.status ?? "–"), el("td", e.host ?? "–"), el("td", e.raw, "raw"));
    body.append(tr);
  }
}

async function refresh() {
  try {
    const f = filters();
    const alertFilters = { severity: f.severity, ip: f.ip, since: f.since };
    const [stats, alerts, events] = await Promise.all([
      api("stats"), api("alerts", { ...alertFilters, limit: 100 }), api("events", { ...f, limit: 100 }),
    ]);
    document.getElementById("s-events").textContent = stats.total_events;
    document.getElementById("s-alerts").textContent = stats.total_alerts;
    document.getElementById("s-critical").textContent = stats.critical_alerts;
    document.getElementById("s-high").textContent = stats.high_alerts;

    const minutes = [...new Set([...stats.timeline, ...stats.alert_timeline].map((p) => p.minute))].sort();
    const series = (pts) => { const m = Object.fromEntries(pts.map((p) => [p.minute, p.count])); return minutes.map((x) => m[x] || 0); };
    chart("c-timeline", "line", minutes.map((m) => m.slice(5).replace("T", " ")), [
      { label: "events", data: series(stats.timeline), borderColor: "#4c9be8", tension: 0.2 },
      { label: "alerts", data: series(stats.alert_timeline), borderColor: "#e8644c", tension: 0.2 },
    ]);
    chart("c-types", "bar", stats.attack_types.map((t) => t.type), [
      { label: "alerts", data: stats.attack_types.map((t) => t.count), backgroundColor: "#e8644c" }], { indexAxis: "y" });
    chart("c-ips", "bar", stats.top_ips.map((t) => t.ip), [
      { label: "events", data: stats.top_ips.map((t) => t.count), backgroundColor: "#4c9be8" }], { indexAxis: "y" });

    renderAlerts(alerts);
    renderEvents(events);
    document.getElementById("status").textContent = `updated ${new Date().toLocaleTimeString()}`;
  } catch (err) {
    document.getElementById("status").textContent = err.message;
  }
}

document.getElementById("filters").addEventListener("input", refresh);
document.getElementById("filters").addEventListener("reset", () => setTimeout(refresh));
refresh();
setInterval(refresh, 5000);
