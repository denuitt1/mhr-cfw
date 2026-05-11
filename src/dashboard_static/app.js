"use strict";

const POLL_MS = 30_000;
const LOG_POLL_MS = 3_000;

const tabs = document.querySelectorAll(".tab");
const panels = document.querySelectorAll(".tab-panel");
const toastBox = document.getElementById("toast");

let pollTimer = null;
let currentConfig = null;
const toggleInFlight = new Set();

function showToast(message, kind = "") {
  const el = document.createElement("div");
  el.className = "toast " + kind;
  el.textContent = message;
  toastBox.appendChild(el);
  setTimeout(() => el.remove(), 5000);
}

async function fetchJSON(url, opts) {
  let resp;
  try { resp = await fetch(url, opts); }
  catch (e) { return { ok: false, status: 0, data: { error: String(e) } }; }
  let data = null;
  try { data = await resp.json(); } catch {}
  return { ok: resp.ok, status: resp.status, data };
}

function dotFor(state) {
  const s = String(state || "amber").toLowerCase();
  const cls = (s === "green" || s === "ok") ? "green"
            : (s === "red" || s === "error") ? "red"
            : "amber";
  const el = document.createElement("span");
  el.className = "dot " + cls;
  return el;
}

function makeRow({ state, label, meta, action }) {
  const r = document.createElement("div");
  r.className = "row";
  if (meta && meta.length > 9) r.classList.add("row-stacked");
  r.appendChild(dotFor(state));
  const l = document.createElement("span");
  l.className = "label";
  l.textContent = label;
  r.appendChild(l);
  if (meta) {
    const m = document.createElement("span");
    m.className = "meta";
    m.textContent = meta;
    r.appendChild(m);
  }
  if (action) r.appendChild(action);
  return r;
}

function rowState(item) {
  if (item.state) return item.state;
  return item.ok ? "green" : "red";
}

function setBindings(cfg) {
  for (const el of document.querySelectorAll("[data-bind]")) {
    const k = el.dataset.bind;
    if (cfg[k] != null) el.textContent = cfg[k];
  }
  const yt = document.getElementById("youtube-toggle");
  if (yt && !toggleInFlight.has("youtube-toggle")) yt.checked = !!cfg.youtube_via_relay;
}

function renderStatus(snap) {
  const sniDots = document.querySelector("#card-sni .dots");
  sniDots.innerHTML = "";
  for (const item of snap.sni || []) {
    sniDots.appendChild(makeRow({
      state: item.ok ? "green" : "red",
      label: item.name,
      meta: item.ok ? `${item.latency_ms} ms` : (item.error || "fail"),
    }));
  }

  const dDots = document.querySelector("#card-direct .dots");
  dDots.innerHTML = "";
  if (snap.direct) {
    dDots.appendChild(makeRow({
      state: snap.direct.ok ? "green" : "red",
      label: snap.direct.name || "front_domain",
      meta: snap.direct.ok ? `${snap.direct.latency_ms} ms` : (snap.direct.error || "fail"),
    }));
  }

  const sDots = document.querySelector("#card-scripts .dots");
  sDots.innerHTML = "";
  for (const item of snap.scripts || []) {
    let meta = item.reason || "";
    if (item.last_seen_s != null) meta = `${item.last_seen_s}s ago`;
    if (item.expires_in_s != null) meta = `cooldown ${item.expires_in_s}s`;
    sDots.appendChild(makeRow({
      state: rowState(item),
      label: "…" + (item.sid_short || ""),
      meta,
    }));
  }

  const wDots = document.querySelector("#card-worker .dots");
  wDots.innerHTML = "";
  if (snap.worker) {
    let meta = snap.worker.reason || "";
    if (snap.worker.last_seen_s != null) meta = `${snap.worker.last_seen_s}s ago`;
    const upstreamConfigured = snap.upstream && snap.upstream.configured;
    wDots.appendChild(makeRow({
      state: rowState(snap.worker),
      label: upstreamConfigured ? "GAS → Worker → upstream" : "GAS → Worker → target",
      meta,
    }));
  }

  const uDots = document.querySelector("#card-upstream .dots");
  uDots.innerHTML = "";
  if (snap.upstream) {
    if (!snap.upstream.configured) {
      uDots.appendChild(makeRow({
        state: "amber",
        label: "Forwarder",
        meta: snap.upstream.reason || "not configured",
      }));
    } else {
      uDots.appendChild(makeRow({
        state: snap.upstream.ok ? "green" : "red",
        label: "Forwarder",
        meta: snap.upstream.ok
          ? `${snap.upstream.latency_ms} ms`
          : (snap.upstream.error || "fail"),
      }));
    }
  }

  renderCert(snap.cert || {});
  renderSystem(snap.system || {});
  renderLan(snap.lan || {});

  document.getElementById("last-refresh").textContent =
    `Updated ${new Date().toLocaleTimeString()}`;
}

function renderSystem(info) {
  const ci = document.querySelector("#card-system .system-info");
  ci.innerHTML = "";
  const dl = document.createElement("dl");
  const fields = [
    ["Python", info.python],
    ["Implementation", info.implementation],
    ["OS", info.os],
    ["Machine", info.machine],
    ["Hostname", info.hostname],
    ["CWD", info.cwd],
  ];
  for (const [k, v] of fields) {
    if (v == null || v === "") continue;
    const dt = document.createElement("dt"); dt.textContent = k;
    const dd = document.createElement("dd"); dd.textContent = String(v);
    dl.appendChild(dt); dl.appendChild(dd);
  }
  ci.appendChild(dl);
}

function renderLan(lan) {
  const toggle = document.getElementById("lan-toggle");
  if (toggle && !toggleInFlight.has("lan-toggle")) toggle.checked = !!lan.enabled;
  const box = document.querySelector("#card-lan .lan-info");
  if (!box) return;
  box.innerHTML = "";
  if (!lan.enabled) return;
  const addLine = (label, items) => {
    if (!items || !items.length) return;
    const row = document.createElement("div");
    row.className = "lan-row";
    const lbl = document.createElement("span");
    lbl.className = "lan-label";
    lbl.textContent = label;
    row.appendChild(lbl);
    const list = document.createElement("div");
    list.className = "lan-list";
    for (const addr of items) {
      const code = document.createElement("code");
      code.textContent = addr;
      list.appendChild(code);
    }
    row.appendChild(list);
    box.appendChild(row);
  };
  addLine("HTTP", lan.http_addresses);
  addLine("SOCKS5", lan.socks_addresses);
  if (!(lan.http_addresses || []).length && !(lan.socks_addresses || []).length) {
    const p = document.createElement("p");
    p.className = "hint";
    p.textContent = "Enabled, but no LAN interfaces detected.";
    box.appendChild(p);
  }
}

function renderCert(cert) {
  const ci = document.querySelector("#card-cert .cert-info");
  ci.innerHTML = "";
  const dl = document.createElement("dl");
  const fields = [
    ["Path", cert.path],
    ["Subject", cert.subject],
    ["Issuer", cert.issuer],
    ["Expires", cert.not_after],
  ];
  for (const [k, v] of fields) {
    if (v == null) continue;
    const dt = document.createElement("dt"); dt.textContent = k;
    const dd = document.createElement("dd"); dd.textContent = String(v);
    dl.appendChild(dt); dl.appendChild(dd);
  }
  if (cert.error) {
    const dt = document.createElement("dt"); dt.textContent = "Error";
    const dd = document.createElement("dd"); dd.textContent = cert.error;
    dl.appendChild(dt); dl.appendChild(dd);
  }
  ci.appendChild(dl);

  const flags = document.getElementById("cert-flags");
  if (flags) {
    flags.innerHTML = "";
    const mk = (iconId, ok, heading, body) => {
      const span = document.createElement("span");
      span.className = "cert-flag " + (ok ? "ok" : "bad");
      span.tabIndex = 0;
      span.innerHTML =
        `<svg class="ico"><use href="#${iconId}"/></svg>` +
        `<span class="popover"><strong>${heading}</strong><span>${body}</span></span>`;
      return span;
    };
    if (cert.present != null) {
      flags.appendChild(mk(
        "i-check", cert.present,
        cert.present ? "Present on disk" : "Missing on disk",
        cert.present
          ? "The CA certificate file exists at the path above. The proxy can mint per-host certs from it."
          : "No CA file found at the path above. The proxy will fail to MITM HTTPS. Restart the proxy to auto-generate a new CA, or run --install-cert."
      ));
    }
    if (cert.is_trusted != null) {
      flags.appendChild(mk(
        "i-shield", cert.is_trusted,
        cert.is_trusted ? "Trusted by OS" : "Not trusted by OS",
        cert.is_trusted
          ? "The CA is in your OS trust store, so browsers and apps accept the per-host certs the proxy mints."
          : "The CA is not in your OS trust store. Browsers will show certificate warnings until you click Install."
      ));
    }
  }

  const installBtn = document.getElementById("cert-install");
  const uninstallBtn = document.getElementById("cert-uninstall");
  if (installBtn && uninstallBtn) {
    const trusted = cert.is_trusted === true;
    installBtn.style.display = trusted ? "none" : "";
    uninstallBtn.style.display = trusted ? "" : "none";
  }
}

async function refreshStatus(force) {
  const url = force ? "/api/status/refresh" : "/api/status";
  const res = await fetchJSON(url, { method: force ? "POST" : "GET" });
  if (res.ok && res.data) renderStatus(res.data);
}

function startPolling() {
  stopPolling();
  refreshStatus(false);
  pollTimer = setInterval(() => {
    if (document.visibilityState === "visible") refreshStatus(false);
  }, POLL_MS);
}

function stopPolling() {
  if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
}

let logTimer = null;
let lastLogTs = 0;

function renderLogs(lines) {
  const pane = document.getElementById("log-pane");
  if (!pane) return;
  const newest = lines.length ? lines[lines.length - 1].ts : 0;
  if (newest === lastLogTs) return;
  lastLogTs = newest;
  const atBottom = pane.scrollTop + pane.clientHeight >= pane.scrollHeight - 12;
  pane.innerHTML = "";
  for (const l of lines) {
    const div = document.createElement("div");
    div.className = "log-line " + (l.level || "");
    const t = new Date(l.ts * 1000);
    const hh = String(t.getHours()).padStart(2, "0");
    const mm = String(t.getMinutes()).padStart(2, "0");
    const ss = String(t.getSeconds()).padStart(2, "0");
    const ts = document.createElement("span");
    ts.className = "ts"; ts.textContent = `${hh}:${mm}:${ss}`;
    const lvl = document.createElement("span");
    lvl.className = "lvl"; lvl.textContent = l.level || "";
    const src = document.createElement("span");
    src.className = "src"; src.textContent = l.name || "";
    const msg = document.createTextNode(l.msg || "");
    div.append(ts, lvl, src, msg);
    pane.appendChild(div);
  }
  if (atBottom) pane.scrollTop = pane.scrollHeight;
}

async function fetchLogs() {
  const res = await fetchJSON("/api/logs");
  if (res.ok && res.data?.lines) renderLogs(res.data.lines);
}

function startLogPolling() {
  stopLogPolling();
  fetchLogs();
  logTimer = setInterval(() => {
    if (document.visibilityState === "visible") fetchLogs();
  }, LOG_POLL_MS);
}

function stopLogPolling() {
  if (logTimer) { clearInterval(logTimer); logTimer = null; }
}

document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "visible") {
    startPolling();
    startLogPolling();
  } else {
    stopPolling();
    stopLogPolling();
  }
});

tabs.forEach(t => t.addEventListener("click", () => {
  tabs.forEach(x => x.classList.toggle("active", x === t));
  const id = t.dataset.tab;
  panels.forEach(p => p.classList.toggle("active", p.id === id + "-tab"));
  if (id === "config") loadConfig();
}));

document.getElementById("refresh-btn").onclick = () => refreshStatus(true);

document.getElementById("cert-install").onclick = async () => {
  const res = await fetchJSON("/api/cert/install", { method: "POST" });
  if (res.data?.ok) showToast("CA installed in OS trust store", "ok");
  else showToast("CA install failed: " + (res.data?.error || ""), "error");
  refreshStatus(true);
};

document.getElementById("cert-uninstall").onclick = async () => {
  const res = await fetchJSON("/api/cert/uninstall", { method: "POST" });
  if (res.data?.ok) showToast("CA removed from OS trust store", "ok");
  else showToast("CA uninstall failed: " + (res.data?.error || ""), "error");
  refreshStatus(true);
};

const lanToggle = document.getElementById("lan-toggle");
lanToggle.addEventListener("change", async () => {
  toggleInFlight.add("lan-toggle");
  try {
    if (!currentConfig) {
      const cfg = await fetchJSON("/api/config");
      if (cfg.ok && cfg.data) currentConfig = cfg.data;
    }
    if (!currentConfig) { showToast("Config not loaded yet", "error"); return; }
    const desired = lanToggle.checked;
    const payload = {
      ...currentConfig,
      lan_sharing: desired,
      listen_host: desired ? "0.0.0.0" : "127.0.0.1",
    };
    lanToggle.disabled = true;
    const res = await fetchJSON("/api/config", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    lanToggle.disabled = false;
    if (res.ok && res.data?.ok) {
      currentConfig.lan_sharing = desired;
      currentConfig.listen_host = payload.listen_host;
      showToast(`LAN sharing: ${desired ? "on" : "off"} (proxy rebuilt)`, "ok");
      refreshStatus(false);
    } else {
      lanToggle.checked = !desired;
      const errs = res.data?.errors?.join("; ") || `HTTP ${res.status}`;
      showToast("Toggle failed: " + errs, "error");
    }
  } finally {
    toggleInFlight.delete("lan-toggle");
  }
});

const ytToggle = document.getElementById("youtube-toggle");
ytToggle.addEventListener("change", async () => {
  toggleInFlight.add("youtube-toggle");
  try {
    if (!currentConfig) {
      const cfg = await fetchJSON("/api/config");
      if (cfg.ok && cfg.data) currentConfig = cfg.data;
    }
    if (!currentConfig) { showToast("Config not loaded yet", "error"); return; }
    const desired = ytToggle.checked;
    const payload = { ...currentConfig, youtube_via_relay: desired };
    ytToggle.disabled = true;
    const res = await fetchJSON("/api/config", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    ytToggle.disabled = false;
    if (res.ok && res.data?.ok) {
      currentConfig.youtube_via_relay = desired;
      showToast(`YouTube via relay: ${desired ? "on" : "off"}`, "ok");
    } else {
      ytToggle.checked = !desired;
      const errs = res.data?.errors?.join("; ") || `HTTP ${res.status}`;
      showToast("Toggle failed: " + errs, "error");
    }
  } finally {
    toggleInFlight.delete("youtube-toggle");
  }
});

function fieldFor(key, value) {
  const wrap = document.createElement("div");
  wrap.className = "field";
  const lab = document.createElement("label");
  lab.textContent = key;
  lab.htmlFor = "field-" + key;
  wrap.appendChild(lab);

  let input;
  if (typeof value === "boolean") {
    input = document.createElement("input");
    input.type = "checkbox";
    input.checked = value;
    input.dataset.kind = "bool";
  } else if (typeof value === "number") {
    input = document.createElement("input");
    input.type = "number";
    input.value = value;
    input.dataset.kind = "number";
  } else if (Array.isArray(value)) {
    input = document.createElement("textarea");
    if (value.every(v => typeof v === "string" || v == null)) {
      input.value = value.filter(v => v != null).join("\n");
      input.dataset.kind = "strlist";
      input.placeholder = "one entry per line";
    } else {
      input.value = JSON.stringify(value, null, 2);
      input.dataset.kind = "json";
    }
  } else if (value && typeof value === "object") {
    input = document.createElement("textarea");
    const entries = Object.entries(value);
    if (entries.every(([, v]) => typeof v === "string")) {
      input.value = entries.map(([k, v]) => `${k} = ${v}`).join("\n");
      input.dataset.kind = "strmap";
      input.placeholder = "key = value, one per line";
    } else {
      input.value = JSON.stringify(value, null, 2);
      input.dataset.kind = "json";
    }
  } else {
    input = document.createElement("input");
    input.type = "text";
    input.value = value == null ? "" : String(value);
    input.dataset.kind = "string";
  }
  input.id = "field-" + key;
  input.dataset.key = key;
  wrap.appendChild(input);
  return wrap;
}

const CONFIG_GROUPS = {
  Relay: [
    "auth_key", "mode",
    "google_ip", "front_domain", "front_domains",
    "script_ids",
    "verify_ssl", "parallel_relay",
    "relay_timeout",
  ],
  Upstream: [
    "upstream_forwarder_url",
    "forwarder_hosts",
  ],
  Listeners: [
    "listen_host", "listen_port",
    "socks5_enabled", "socks5_host", "socks5_port",
  ],
  Routing: [
    "block_hosts", "bypass_hosts",
    "direct_google_allow", "direct_google_exclude",
    "hosts",
  ],
  Timeouts: [
    "tls_connect_timeout", "tcp_connect_timeout",
    "max_response_body_bytes",
  ],
  Downloads: [
    "chunked_download_extensions",
    "chunked_download_min_size", "chunked_download_chunk_size",
    "chunked_download_max_parallel", "chunked_download_max_chunks",
  ],
};

const CONFIG_DEFAULTS = {
  forwarder_hosts: [],
  upstream_forwarder_url: "",
};

const HIDDEN_CONFIG_KEYS = new Set([
  "youtube_via_relay",
  "lan_sharing",
  "dashboard_enabled",
  "dashboard_host",
  "dashboard_port",
]);

function categorizeConfig(keys) {
  const visible = keys.filter(k => !HIDDEN_CONFIG_KEYS.has(k));
  const used = new Set();
  const groups = {};
  for (const [cat, list] of Object.entries(CONFIG_GROUPS)) {
    const present = list.filter(k => visible.includes(k));
    if (present.length) {
      groups[cat] = present;
      present.forEach(k => used.add(k));
    }
  }
  const leftover = visible.filter(k => !used.has(k)).sort();
  if (leftover.length) groups["Other"] = leftover;
  return groups;
}

function activateSubtab(cat) {
  for (const t of document.querySelectorAll(".subtab")) {
    t.classList.toggle("active", t.dataset.cat === cat);
  }
  for (const g of document.querySelectorAll(".field-group")) {
    g.classList.toggle("active", g.dataset.cat === cat);
  }
}

async function loadConfig() {
  const res = await fetchJSON("/api/config");
  if (!res.ok || !res.data) {
    showToast("Failed to load config", "error");
    return;
  }
  currentConfig = res.data;
  for (const [k, v] of Object.entries(CONFIG_DEFAULTS)) {
    if (!(k in currentConfig)) currentConfig[k] = Array.isArray(v) ? [...v] : v;
  }
  setBindings(currentConfig);

  const form = document.getElementById("config-form");
  form.innerHTML = "";

  const groups = categorizeConfig(Object.keys(currentConfig));
  const cats = Object.keys(groups);

  const subnav = document.createElement("div");
  subnav.className = "subtabs";
  for (const cat of cats) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "subtab";
    btn.textContent = cat;
    btn.dataset.cat = cat;
    btn.addEventListener("click", () => activateSubtab(cat));
    subnav.appendChild(btn);
  }
  form.appendChild(subnav);

  for (const cat of cats) {
    const fs = document.createElement("div");
    fs.className = "field-group";
    fs.dataset.cat = cat;
    for (const k of groups[cat]) {
      fs.appendChild(fieldFor(k, currentConfig[k]));
    }
    form.appendChild(fs);
  }

  if (cats.length) activateSubtab(cats[0]);
}

function readForm() {
  const out = {};
  for (const el of document.querySelectorAll("#config-form [data-key]")) {
    const key = el.dataset.key;
    const kind = el.dataset.kind;
    if (kind === "bool") out[key] = el.checked;
    else if (kind === "number") {
      out[key] = el.value === "" ? null : Number(el.value);
    } else if (kind === "strlist") {
      out[key] = el.value
        .split("\n")
        .map(s => s.trim())
        .filter(s => s.length > 0);
    } else if (kind === "strmap") {
      const m = {};
      for (const line of el.value.split("\n")) {
        const t = line.trim();
        if (!t) continue;
        const eq = t.indexOf("=");
        if (eq < 0) {
          throw new Error(`field "${key}": expected "key = value", got "${t}"`);
        }
        m[t.slice(0, eq).trim()] = t.slice(eq + 1).trim();
      }
      out[key] = m;
    } else if (kind === "json") {
      const txt = el.value.trim();
      if (txt === "") { out[key] = null; continue; }
      try { out[key] = JSON.parse(txt); }
      catch { throw new Error(`invalid JSON in field "${key}"`); }
    } else {
      out[key] = el.value;
    }
  }
  return out;
}

document.getElementById("save-config").onclick = async () => {
  let payload;
  try { payload = readForm(); }
  catch (e) { showToast(e.message, "error"); return; }

  if (currentConfig) {
    for (const k of HIDDEN_CONFIG_KEYS) {
      if (k in currentConfig) payload[k] = currentConfig[k];
    }
  }

  const res = await fetchJSON("/api/config", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (res.ok && res.data?.ok) {
    const applied = (res.data.applied || []).join(", ") || "(no changes)";
    let msg = `Saved. Applied: ${applied}.`;
    if (res.data.rebuilt) msg += " Proxy rebuilt.";
    if (res.data.dashboard_restart_required?.length) {
      msg += " Dashboard config changed — restart the proxy process.";
    }
    showToast(msg, "ok");
    loadConfig();
    refreshStatus(true);
  } else {
    const errs = res.data?.errors?.join("; ") || `HTTP ${res.status}`;
    showToast("Save failed: " + errs, "error");
  }
};

document.getElementById("reset-config").onclick = () => loadConfig();

(async () => {
  const cfg = await fetchJSON("/api/config");
  if (cfg.ok && cfg.data) {
    currentConfig = cfg.data;
    setBindings(cfg.data);
  }
  startPolling();
  startLogPolling();
})();
