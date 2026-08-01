const MODULES = ["git", "js", "config", "path", "methods", "wordpress", "joomla", "react"];
let currentScanId = null;
let ws = null;
let customPaths = [];
let findingsCache = [];
let logsCache = [];
let uploadedTargets = [];
let pingTimer = null;

function $(id) { return document.getElementById(id); }

function initModules() {
  const box = $("modules");
  box.innerHTML = "";
  MODULES.forEach((m) => {
    const id = `mod_${m}`;
    const label = document.createElement("label");
    label.className = "flex items-center gap-2 text-slate-300";
    label.innerHTML = `<input type="checkbox" id="${id}" checked class="accent-cyan-400" /> ${m}`;
    box.appendChild(label);
  });
  const modFilter = $("modFilter");
  MODULES.forEach((m) => {
    const opt = document.createElement("option");
    opt.value = m;
    opt.textContent = m;
    modFilter.appendChild(opt);
  });
}

function selectedModules() {
  return MODULES.filter((m) => $(`mod_${m}`)?.checked);
}

function countTargetsInBox() {
  const lines = $("targets").value.split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith("#"));
  $("targetsCount").textContent = `${lines.length} target${lines.length === 1 ? "" : "s"}`;
  return lines;
}

async function uploadTargetsFile(mode) {
  const file = $("targetsFile").files[0];
  if (!file) {
    alert("Choose a domains/IPs .txt file first");
    return;
  }
  const fd = new FormData();
  fd.append("file", file);
  const up = await fetch("/api/targets/upload", { method: "POST", body: fd }).then((r) => r.json());
  if (up.error) {
    alert(up.error);
    return;
  }
  uploadedTargets = up.targets || [];
  const text = up.targets_text || uploadedTargets.join("\n");
  if (mode === "merge") {
    const existing = new Set(countTargetsInBox());
    uploadedTargets.forEach((t) => existing.add(t));
    $("targets").value = Array.from(existing).join("\n");
  } else {
    $("targets").value = text;
  }
  countTargetsInBox();
  $("targetsInfo").textContent = `loaded ${up.count} targets from ${file.name}`;
}

async function refreshHistory() {
  const rows = await fetch("/api/scans").then((r) => r.json());
  const el = $("history");
  el.innerHTML = "";
  rows.slice(0, 30).forEach((s) => {
    const div = document.createElement("button");
    div.className = "w-full text-left px-2 py-2 rounded border border-slate-800 hover:border-cyan-700";
    const hits = s.summary?.finding_count ?? s.progress?.hits ?? 0;
    div.innerHTML = `<div class="text-cyan-200">${s.id}</div><div class="text-xs text-slate-400">${s.status} · ${hits} findings</div>`;
    div.onclick = () => selectScan(s.id);
    el.appendChild(div);
  });
}

async function selectScan(id) {
  currentScanId = id;
  $("scanMeta").textContent = `scan ${id}`;
  connectWs(id);
  const scan = await fetch(`/api/scans/${id}`).then((r) => r.json());
  if (scan.progress) renderProgress(scan.progress);
  await reloadFindings();
  await reloadResults();
  await reloadLogs();
}

function connectWs(id) {
  if (ws) {
    try { ws.close(); } catch (_) {}
  }
  if (pingTimer) {
    clearInterval(pingTimer);
    pingTimer = null;
  }
  const proto = location.protocol === "https:" ? "wss" : "ws";
  ws = new WebSocket(`${proto}://${location.host}/ws/scans/${id}`);
  ws.onopen = () => { $("connState").textContent = "ws: connected"; };
  ws.onclose = () => { $("connState").textContent = "ws: disconnected"; };
  ws.onmessage = (ev) => {
    const msg = JSON.parse(ev.data);
    if (msg.scan_id && msg.scan_id !== currentScanId) return;
    if (msg.type === "progress") renderProgress(msg.data);
    if (msg.type === "finding") {
      findingsCache.unshift(msg.data);
      renderFindings();
      reloadResults();
    }
    if (msg.type === "log") {
      logsCache.push(msg.data);
      if (logsCache.length > 1000) logsCache = logsCache.slice(-1000);
      renderLogs();
    }
  };
  pingTimer = setInterval(() => {
    if (ws && ws.readyState === 1) ws.send("ping");
  }, 15000);
}

function renderProgress(p) {
  const pct = Math.min(100, p.percent || 0);
  $("bar").style.width = `${pct}%`;
  $("pctLabel").textContent = `${pct.toFixed(1)}%`;
  $("etaLabel").textContent = p.eta_seconds != null ? `ETA ${Math.round(p.eta_seconds)}s` : "ETA —";
  $("rps").textContent = (p.rps || 0).toFixed(1);
  $("queued").textContent = p.queued || 0;
  $("done").textContent = p.done || 0;
  $("failed").textContent = p.failed || 0;
  $("hits").textContent = p.hits || 0;
  $("currentLabel").textContent = `${p.current_module || "-"} @ ${p.current_target || "-"}`;
  const mb = $("moduleBars");
  mb.innerHTML = "";
  Object.entries(p.module_progress || {}).forEach(([name, mp]) => {
    const total = Math.max(mp.total || 1, 1);
    const done = mp.done || 0;
    const width = Math.min(100, (done / total) * 100);
    const row = document.createElement("div");
    row.innerHTML = `<div class="flex justify-between"><span>${name}</span><span>${done}/${mp.total || "?"} hits=${mp.hits || 0}</span></div>
      <div class="h-1.5 bg-slate-800 rounded overflow-hidden"><div class="h-full bg-cyan-500" style="width:${width}%"></div></div>`;
    mb.appendChild(row);
  });
}

async function reloadFindings() {
  if (!currentScanId) return;
  const q = $("findQ").value.trim();
  const sev = $("sevFilter").value;
  const mod = $("modFilter").value;
  const params = new URLSearchParams();
  if (q) params.set("q", q);
  if (sev) params.set("severity", sev);
  if (mod) params.set("module", mod);
  findingsCache = await fetch(`/api/scans/${currentScanId}/findings?${params}`).then((r) => r.json());
  renderFindings();
}

async function reloadResults() {
  if (!currentScanId) return;
  const data = await fetch(`/api/scans/${currentScanId}/results`).then((r) => r.json());
  const box = $("resultSummary");
  const sev = data.by_severity || {};
  const hosts = data.vulnerable_hosts || [];
  box.innerHTML = `
    <div class="stat">Findings <b>${data.finding_count || 0}</b></div>
    <div class="stat">Vuln hosts <b>${hosts.length}</b></div>
    <div class="stat">Critical <b class="sev-critical">${sev.critical || 0}</b></div>
    <div class="stat">High <b class="sev-high">${sev.high || 0}</b></div>
    <div class="stat">Secrets <b>${(data.secrets || []).length}</b></div>
  `;

  const vulnBody = $("vulnHostsBody");
  if (!hosts.length) {
    vulnBody.innerHTML = `<tr><td colspan="5" class="py-3 text-slate-500">No vulnerable hosts yet.</td></tr>`;
    $("vulnHostDetail").classList.add("hidden");
  } else {
    vulnBody.innerHTML = "";
    hosts.forEach((h) => {
      const tr = document.createElement("tr");
      tr.className = "find-row border-t border-slate-800";
      tr.innerHTML = `
        <td class="py-2 pr-2 text-cyan-200 font-mono">${escapeHtml(h.host || "")}</td>
        <td class="py-2 pr-2">${escapeHtml((h.methods || []).join(", "))}</td>
        <td class="py-2 pr-2">${escapeHtml((h.modules || []).join(", "))}</td>
        <td class="py-2 pr-2">${escapeHtml((h.severities || []).join(", "))}</td>
        <td class="py-2">${h.finding_count || 0}</td>`;
      tr.onclick = () => {
        const detail = $("vulnHostDetail");
        detail.classList.remove("hidden");
        detail.textContent = JSON.stringify(h, null, 2);
      };
      vulnBody.appendChild(tr);
    });
  }

  const files = data.vuln_files || {};
  $("vulnFilesInfo").textContent = files.dir
    ? `Saved under ${files.dir} · env/git/js/wordpress/joomla/react2shell/methods`
    : "Vuln artifact files will appear after findings land.";

  const secretsEl = $("secretsBox");
  const secrets = data.secrets || [];
  if (!secrets.length) {
    secretsEl.innerHTML = `<div class="text-slate-500">No secrets extracted yet.</div>`;
    return;
  }
  secretsEl.innerHTML = secrets.map((s) =>
    `<div class="secret-row">
      <span class="text-amber-300">${escapeHtml(s.kind || "secret")}</span>
      <span class="text-emerald-300 font-mono">${escapeHtml(s.value || "")}</span>
      <span class="text-slate-500 truncate" title="${escapeHtml(s.source_url || "")}">${escapeHtml(s.source_url || "")}</span>
    </div>`
  ).join("");
}

function renderFindings() {
  const body = $("findingsBody");
  body.innerHTML = "";
  if (!findingsCache.length) {
    body.innerHTML = `<tr><td colspan="6" class="py-4 text-slate-500">No findings yet.</td></tr>`;
    return;
  }
  findingsCache.forEach((f) => {
    const tr = document.createElement("tr");
    tr.className = "find-row border-t border-slate-800";
    tr.innerHTML = `<td class="py-2 pr-2 sev-${f.severity}">${f.severity}</td>
      <td class="py-2 pr-2">${escapeHtml(f.module || "")}</td>
      <td class="py-2 pr-2">${escapeHtml(f.type || "")}</td>
      <td class="py-2 pr-2">${escapeHtml(f.title || "")}</td>
      <td class="py-2 pr-2 truncate max-w-[220px]" title="${escapeHtml(f.url || "")}">${escapeHtml(f.url || "")}</td>
      <td class="py-2">${(f.confidence ?? 0).toFixed(2)}</td>`;
    tr.onclick = () => {
      const ev = $("evidence");
      ev.classList.remove("hidden");
      ev.textContent = JSON.stringify(f, null, 2);
    };
    body.appendChild(tr);
  });
}

async function reloadLogs() {
  if (!currentScanId) return;
  const level = $("logLevel").value;
  const params = new URLSearchParams({ limit: "400" });
  if (level) params.set("level", level);
  logsCache = await fetch(`/api/scans/${currentScanId}/logs?${params}`).then((r) => r.json());
  renderLogs();
}

function renderLogs() {
  const level = $("logLevel").value;
  const el = $("logs");
  const items = level ? logsCache.filter((l) => l.level === level) : logsCache;
  const view = items.slice(-300);
  el.innerHTML = view.map((l) =>
    `<div class="log-${l.level}">[${l.timestamp || ""}] [${l.level}] [${l.module}] ${escapeHtml(l.message || "")}</div>`
  ).join("");
  el.scrollTop = el.scrollHeight;
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  })[c]);
}

async function startScan() {
  const targets_text = $("targets").value;
  if (!targets_text.trim()) {
    alert("Add or upload at least one domain/IP target");
    return;
  }
  const file = $("wordlist").files[0];
  if (file) {
    const fd = new FormData();
    fd.append("file", file);
    fd.append("mode", $("pathsMode").value);
    const up = await fetch("/api/wordlists/upload", { method: "POST", body: fd }).then((r) => r.json());
    customPaths = up.paths_preview || [];
    $("wordlistInfo").textContent = `uploaded ${up.count} paths`;
    const text = await file.text();
    customPaths = text.split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith("#"));
  }
  const body = {
    targets_text,
    modules: selectedModules(),
    threads: Number($("threads").value || 50),
    timeout: Number($("timeout").value || 8),
    retries: Number($("retries").value || 1),
    rate_limit_per_host: Number($("rateLimit").value || 50),
    paths_mode: $("pathsMode").value,
    custom_paths: customPaths,
    scope_notes: $("scope").value,
  };
  const res = await fetch("/api/scans", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  }).then((r) => r.json());
  if (res.error) {
    alert(res.error);
    return;
  }
  findingsCache = [];
  logsCache = [];
  await selectScan(res.id);
  await refreshHistory();
}

async function stopScan() {
  if (!currentScanId) return;
  await fetch(`/api/scans/${currentScanId}/stop`, { method: "POST" });
}

function exportFmt(fmt) {
  if (!currentScanId) return;
  window.open(`/api/scans/${currentScanId}/export/${fmt}`, "_blank");
}

$("startBtn").onclick = startScan;
$("stopBtn").onclick = stopScan;
$("exportJson").onclick = () => exportFmt("json");
$("exportCsv").onclick = () => exportFmt("csv");
$("exportMd").onclick = () => exportFmt("md");
$("exportVulns").onclick = () => exportFmt("vulns_csv");
$("exportHosts").onclick = () => exportFmt("hosts");
$("refreshResults").onclick = () => { reloadFindings(); reloadResults(); };
$("targetsReplaceBtn").onclick = () => uploadTargetsFile("replace");
$("targetsMergeBtn").onclick = () => uploadTargetsFile("merge");
$("targets").addEventListener("input", countTargetsInBox);
$("targetsFile").addEventListener("change", () => {
  if ($("targetsFile").files[0]) uploadTargetsFile("replace");
});
$("sevFilter").onchange = reloadFindings;
$("modFilter").onchange = reloadFindings;
$("findQ").oninput = () => {
  clearTimeout(window.__fq);
  window.__fq = setTimeout(reloadFindings, 250);
};
$("logLevel").onchange = reloadLogs;

initModules();
countTargetsInBox();
refreshHistory();
setInterval(refreshHistory, 10000);
