const MODULES = ["git", "js", "config", "path", "methods", "wordpress", "joomla", "react"];
const state = {
  tab: "uploads",
  uploadKind: "targets",
  uploads: [],
  jobs: [],
  allScans: [],
  scanId: null,
  provider: "",
  results: null,
  findings: [],
  logs: [],
  ws: null,
  pingTimer: null,
  jobsRefreshPending: false,
  resultsRefreshPending: false,
  logsRefreshPending: false,
  resultReloadTimer: null,
};

const $ = (id) => document.getElementById(id);
const esc = (value) => String(value ?? "").replace(/[&<>"']/g, (char) => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
})[char]);

async function api(url, options = {}) {
  const response = await fetch(url, options);
  let data = null;
  try { data = await response.json(); } catch (_) { data = {}; }
  if (!response.ok) throw new Error(data.detail || data.error || `Request failed (${response.status})`);
  return data;
}

function formatNumber(value) {
  return Number(value || 0).toLocaleString();
}

function formatBytes(bytes) {
  const size = Number(bytes || 0);
  if (size < 1024) return `${size} B`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
  return `${(size / 1024 / 1024).toFixed(1)} MB`;
}

function formatEta(seconds) {
  if (seconds == null || !Number.isFinite(Number(seconds))) return "—";
  const value = Math.max(0, Number(seconds));
  if (value < 60) return `${Math.round(value)}s`;
  if (value < 3600) return `${Math.round(value / 60)}m`;
  return `${(value / 3600).toFixed(1)}h`;
}

function showTab(name) {
  state.tab = name;
  document.querySelectorAll(".tab-view").forEach((el) => el.classList.toggle("hidden", el.id !== `tab-${name}`));
  document.querySelectorAll(".nav-tab").forEach((el) => el.classList.toggle("active", el.dataset.tab === name));
  if (name === "uploads") refreshUploads();
  if (name === "jobs") refreshJobs();
  if (name === "results") reloadResults();
  if (name === "logs") reloadLogs();
}

function initModules() {
  $("modules").innerHTML = MODULES.map((name) => `
    <label class="module-option">
      <input id="mod_${name}" type="checkbox" checked />
      <span>${esc(name === "methods" ? "HTTP methods" : name)}</span>
    </label>`).join("");
  $("modFilter").innerHTML += MODULES.map((name) => `<option value="${name}">${name}</option>`).join("");
}

function selectedModules() {
  return MODULES.filter((name) => $(`mod_${name}`)?.checked);
}

function setupUploadDropzone() {
  document.querySelectorAll(".kind-option").forEach((button) => {
    button.onclick = () => {
      state.uploadKind = button.dataset.kind;
      document.querySelectorAll(".kind-option").forEach((item) => item.classList.toggle("active", item === button));
    };
  });
  const zone = $("dropZone");
  const input = $("uploadFile");
  input.onchange = () => { $("chosenFile").textContent = input.files[0]?.name || "No file selected"; };
  ["dragenter", "dragover"].forEach((event) => zone.addEventListener(event, (ev) => {
    ev.preventDefault();
    zone.classList.add("dragging");
  }));
  ["dragleave", "drop"].forEach((event) => zone.addEventListener(event, (ev) => {
    ev.preventDefault();
    zone.classList.remove("dragging");
  }));
  zone.addEventListener("drop", (ev) => {
    if (!ev.dataTransfer.files.length) return;
    input.files = ev.dataTransfer.files;
    $("chosenFile").textContent = input.files[0].name;
  });
}

async function uploadFile() {
  const file = $("uploadFile").files[0];
  if (!file) {
    $("uploadMessage").innerHTML = '<span class="text-amber-300">Choose a file first.</span>';
    return;
  }
  const button = $("uploadBtn");
  button.disabled = true;
  button.textContent = "Uploading…";
  const body = new FormData();
  body.append("file", file);
  body.append("kind", state.uploadKind);
  try {
    const record = await api("/api/uploads", { method: "POST", body });
    $("uploadMessage").innerHTML = `<span class="text-emerald-300">Saved ${esc(record.original_name)} · ${formatNumber(record.item_count)} entries</span>`;
    $("uploadFile").value = "";
    $("chosenFile").textContent = "No file selected";
    await refreshUploads();
  } catch (error) {
    $("uploadMessage").innerHTML = `<span class="text-red-300">${esc(error.message)}</span>`;
  } finally {
    button.disabled = false;
    button.textContent = "Upload file";
  }
}

async function refreshUploads() {
  try {
    state.uploads = await api("/api/uploads");
    renderUploads();
    populateUploadSelects();
  } catch (error) {
    $("uploadList").innerHTML = `<div class="text-red-300 text-sm">${esc(error.message)}</div>`;
  }
}

function renderUploads() {
  const list = $("uploadList");
  if (!state.uploads.length) {
    list.innerHTML = '<div class="py-16 text-center text-sm text-slate-500">No files uploaded to this server yet.</div>';
    return;
  }
  list.innerHTML = state.uploads.map((file) => `
    <div class="upload-row">
      <div class="file-icon">${file.kind === "targets" ? "TGT" : "PTH"}</div>
      <div class="min-w-0">
        <div class="text-sm text-slate-200 truncate" title="${esc(file.original_name)}">${esc(file.original_name)}</div>
        <div class="meta">${formatNumber(file.item_count)} entries · ${formatBytes(file.size_bytes)} · ${esc((file.created_at || "").replace("T", " ").slice(0, 16))}</div>
      </div>
      <span class="pill">${file.kind === "targets" ? "Targets" : "Wordlist"}</span>
      <button class="btn-ghost delete-upload" data-id="${esc(file.id)}">Delete</button>
    </div>`).join("");
  list.querySelectorAll(".delete-upload").forEach((button) => {
    button.onclick = async () => {
      if (!confirm("Delete this uploaded file from the server? Existing jobs keep their copied target configuration.")) return;
      try {
        await api(`/api/uploads/${encodeURIComponent(button.dataset.id)}`, { method: "DELETE" });
        await refreshUploads();
      } catch (error) {
        alert(error.message);
      }
    };
  });
}

function populateUploadSelects() {
  const targets = state.uploads.filter((item) => item.kind === "targets" && item.exists !== false);
  const wordlists = state.uploads.filter((item) => item.kind === "wordlist" && item.exists !== false);
  const targetSelect = $("jobTargetsUpload");
  const wordlistSelect = $("jobWordlistUpload");
  const targetValue = targetSelect.value;
  const wordlistValue = wordlistSelect.value;
  targetSelect.innerHTML = targets.length
    ? targets.map((item) => `<option value="${esc(item.id)}">${esc(item.original_name)} · ${formatNumber(item.item_count)} targets</option>`).join("")
    : '<option value="">Upload a targets file first</option>';
  wordlistSelect.innerHTML = '<option value="">None — built-ins only</option>' +
    wordlists.map((item) => `<option value="${esc(item.id)}">${esc(item.original_name)} · ${formatNumber(item.item_count)} paths</option>`).join("");
  if (targets.some((item) => item.id === targetValue)) targetSelect.value = targetValue;
  if (wordlists.some((item) => item.id === wordlistValue)) wordlistSelect.value = wordlistValue;
}

async function openJobModal() {
  await refreshUploads();
  if (!state.uploads.some((item) => item.kind === "targets" && item.exists !== false)) {
    showTab("uploads");
    $("uploadMessage").innerHTML = '<span class="text-amber-300">Upload a targets file before creating a job.</span>';
    return;
  }
  $("jobError").textContent = "";
  $("jobModal").classList.remove("hidden");
}

function closeJobModal() {
  $("jobModal").classList.add("hidden");
}

async function startJob() {
  const targetsUploadId = $("jobTargetsUpload").value;
  if (!targetsUploadId) {
    $("jobError").textContent = "Select an uploaded targets file.";
    return;
  }
  const body = {
    job_name: $("jobName").value.trim(),
    targets_upload_id: targetsUploadId,
    wordlist_upload_id: $("jobWordlistUpload").value,
    modules: selectedModules(),
    threads: Number($("threads").value || 100),
    timeout: Number($("timeout").value || 8),
    retries: Number($("retries").value || 1),
    rate_limit_per_host: Number($("rateLimit").value || 50),
    paths_mode: $("pathsMode").value,
    method_test_trace: $("methodTrace").checked,
    redact_secrets: !$("storeFullSecrets").checked,
    scope_notes: $("scope").value,
  };
  if (!body.modules.length) {
    $("jobError").textContent = "Enable at least one scan module.";
    return;
  }
  const button = $("startBtn");
  button.disabled = true;
  button.textContent = "Starting…";
  try {
    const response = await api("/api/scans", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    state.scanId = response.id;
    closeJobModal();
    showTab("jobs");
    await refreshJobs();
    selectScan(response.id, false);
  } catch (error) {
    $("jobError").textContent = error.message;
  } finally {
    button.disabled = false;
    button.textContent = "Start job";
  }
}

async function refreshJobs() {
  if (state.jobsRefreshPending) return;
  state.jobsRefreshPending = true;
  try {
    state.allScans = await api("/api/scans?compact=true&limit=100&include_archived=true");
    state.jobs = state.allScans.filter((job) => !job.archived);
    if (!state.scanId && state.allScans.length) state.scanId = state.allScans[0].id;
    renderJobs();
    syncScanSelectors();
  } catch (error) {
    $("jobsGrid").innerHTML = `<div class="text-red-300">${esc(error.message)}</div>`;
  } finally {
    state.jobsRefreshPending = false;
  }
}

function renderJobs() {
  const running = state.jobs.filter((job) => ["running", "pending", "stopping"].includes(job.status));
  const completed = state.jobs.filter((job) => job.status === "completed");
  const totalHits = state.jobs.reduce((sum, job) => sum + Number(job.summary?.finding_count ?? job.progress?.hits ?? 0), 0);
  $("runningBadge").textContent = running.length;
  $("runningBadge").classList.toggle("hidden", !running.length);
  $("jobsOverview").innerHTML = `
    <div class="stat-card"><span>Total jobs</span><b>${state.jobs.length}</b></div>
    <div class="stat-card"><span>Running</span><b class="text-cyan-300">${running.length}</b></div>
    <div class="stat-card"><span>Completed</span><b class="text-emerald-300">${completed.length}</b></div>
    <div class="stat-card"><span>Total hit signals</span><b>${formatNumber(totalHits)}</b></div>`;
  $("jobsEmpty").classList.toggle("hidden", Boolean(state.jobs.length));
  $("jobsGrid").innerHTML = state.jobs.map(jobCard).join("");
  $("jobsGrid").querySelectorAll(".view-results").forEach((button) => {
    button.onclick = () => {
      selectScan(button.dataset.id, false);
      showTab("results");
    };
  });
  $("jobsGrid").querySelectorAll(".view-logs").forEach((button) => {
    button.onclick = () => {
      selectScan(button.dataset.id, false);
      showTab("logs");
    };
  });
  $("jobsGrid").querySelectorAll(".job-action").forEach((button) => {
    button.onclick = async () => {
      const id = button.dataset.id;
      const action = button.dataset.action;
      if (action === "stop") {
        if (!confirm("Stop this job and cancel its server-side scan?")) return;
        button.disabled = true;
        button.textContent = "Stopping…";
        try {
          const response = await api(`/api/scans/${encodeURIComponent(id)}/stop`, { method: "POST" });
          if (!response.stopped) throw new Error("The server could not find an active worker for this job.");
          const job = state.jobs.find((item) => item.id === id);
          if (job) job.status = response.status || "stopping";
          renderJobs();
        } catch (error) {
          alert(error.message);
        }
      } else {
        if (!confirm("Remove this job from Jobs? Its results, findings, and artifacts will be preserved.")) return;
        button.disabled = true;
        button.textContent = "Deleting…";
        try {
          await api(`/api/scans/${encodeURIComponent(id)}`, { method: "DELETE" });
          await refreshJobs();
        } catch (error) {
          button.disabled = false;
          button.textContent = "Delete";
          alert(error.message);
        }
      }
    };
  });
}

function jobCard(job) {
  const progress = job.progress || {};
  const pct = Math.max(0, Math.min(100, Number(progress.percent || (job.status === "completed" ? 100 : 0))));
  const config = job.config || {};
  const name = config.job_name || `Scan ${job.id}`;
  const modules = config.modules || [];
  const canStop = ["running", "pending"].includes(job.status);
  const isStopping = job.status === "stopping";
  return `
    <article class="job-card ${esc(job.status)}">
      <div class="job-card-head">
        <div class="min-w-0"><div class="job-title truncate">${esc(name)}</div><div class="job-id">${esc(job.id)} · ${formatNumber(config.target_count ?? (config.targets || []).length)} targets</div></div>
        <span class="status-badge ${esc(job.status)}">${esc(job.status)}</span>
      </div>
      <div class="flex justify-between text-[11px] text-slate-500 mt-4 mb-1.5"><span>${pct.toFixed(1)}%</span><span>ETA ${formatEta(progress.eta_seconds)}</span></div>
      <div class="progress-track"><div class="progress-fill" style="width:${pct}%"></div></div>
      <div class="job-stats">
        <div>RPS<b>${Number(progress.rps || 0).toFixed(1)}</b></div>
        <div>Done<b>${formatNumber(progress.done)}</b></div>
        <div>Failed<b>${formatNumber(progress.failed)}</b></div>
        <div>Hits<b>${formatNumber(progress.hits ?? job.summary?.finding_count)}</b></div>
        <div>Secrets<b>${formatNumber(progress.secrets)}</b></div>
      </div>
      <div class="text-[11px] text-slate-500 truncate mt-3">${esc(progress.current_module || "idle")} ${progress.current_target ? `@ ${esc(progress.current_target)}` : ""}</div>
      <div class="module-pills">${modules.map((name) => `<span>${esc(name)}</span>`).join("")}</div>
      <div class="flex gap-2 justify-end mt-4">
        ${isStopping
          ? '<button class="btn-ghost" disabled>Stopping…</button>'
          : `<button class="btn-destructive job-action" data-id="${esc(job.id)}" data-action="${canStop ? "stop" : "delete"}">${canStop ? "Stop" : "Delete"}</button>`}
        <button class="btn-ghost view-logs" data-id="${esc(job.id)}">Logs</button>
        <button class="btn-ghost view-results" data-id="${esc(job.id)}">Results →</button>
      </div>
    </article>`;
}

function syncScanSelectors() {
  ["resultScanSelect", "logScanSelect"].forEach((id) => {
    const select = $(id);
    const current = state.scanId || select.value;
    select.innerHTML = state.allScans.map((job) => {
      const name = job.config?.job_name || `Scan ${job.id}`;
      const suffix = job.archived ? "results preserved" : job.status;
      return `<option value="${esc(job.id)}">${esc(name)} · ${esc(suffix)}</option>`;
    }).join("");
    if (state.allScans.some((job) => job.id === current)) select.value = current;
  });
}

function selectScan(id, connect = true) {
  state.scanId = id;
  state.provider = "";
  syncScanSelectors();
  if (connect) connectWs(id);
  else connectWs(id);
}

function connectWs(id) {
  if (state.ws) {
    try { state.ws.close(); } catch (_) {}
  }
  if (state.pingTimer) clearInterval(state.pingTimer);
  if (!id) return;
  const protocol = location.protocol === "https:" ? "wss" : "ws";
  state.ws = new WebSocket(`${protocol}://${location.host}/ws/scans/${encodeURIComponent(id)}`);
  state.ws.onopen = () => {
    $("connState").textContent = "Live channel connected";
    $("connDot").classList.remove("offline");
  };
  state.ws.onclose = () => {
    $("connState").textContent = "Live channel offline";
    $("connDot").classList.add("offline");
    if (state.scanId === id) {
      setTimeout(() => {
        if (state.scanId === id && (!state.ws || state.ws.readyState === WebSocket.CLOSED)) connectWs(id);
      }, 2000);
    }
  };
  state.ws.onmessage = (event) => {
    const message = JSON.parse(event.data);
    if (message.scan_id && message.scan_id !== state.scanId) return;
    if (message.type === "progress") {
      const job = state.jobs.find((item) => item.id === state.scanId);
      if (job) job.progress = message.data;
      if (state.tab === "jobs") renderJobs();
    }
    if (message.type === "finding") {
      state.findings.unshift(message.data);
      if (state.tab === "results") scheduleResultsReload();
    }
    if (message.type === "log") {
      state.logs.push(message.data);
      if (state.logs.length > 1200) state.logs = state.logs.slice(-1200);
      if (state.tab === "logs") renderLogs();
    }
  };
  state.pingTimer = setInterval(() => {
    if (state.ws?.readyState === 1) state.ws.send("ping");
  }, 15000);
}

function scheduleResultsReload() {
  if (state.resultReloadTimer) clearTimeout(state.resultReloadTimer);
  state.resultReloadTimer = setTimeout(reloadResults, 500);
}

async function reloadResults() {
  if (!state.scanId) {
    $("resultSummary").innerHTML = '<div class="text-slate-500 text-sm">Select a job first.</div>';
    return;
  }
  if (state.resultsRefreshPending) return;
  state.resultsRefreshPending = true;
  try {
    const providerQuery = state.provider ? `?provider=${encodeURIComponent(state.provider)}` : "";
    const [results, findings] = await Promise.all([
      api(`/api/scans/${encodeURIComponent(state.scanId)}/results${providerQuery}`),
      api(`/api/scans/${encodeURIComponent(state.scanId)}/findings`),
    ]);
    state.results = results;
    const seen = new Set();
    state.findings = findings.filter((finding) => {
      const key = finding.id || `${finding.type}|${finding.target}|${finding.url}|${finding.title}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
    renderResults();
    renderFindings();
  } catch (error) {
    $("resultSummary").innerHTML = `<div class="text-red-300">${esc(error.message)}</div>`;
  } finally {
    state.resultsRefreshPending = false;
  }
}

function renderResults() {
  const data = state.results || {};
  const severity = data.by_severity || {};
  const hosts = data.vulnerable_hosts || [];
  $("resultSummary").innerHTML = `
    <div class="stat-card"><span>Unique findings</span><b>${formatNumber(data.finding_count)}</b></div>
    <div class="stat-card"><span>Vulnerable hosts</span><b>${formatNumber(hosts.length)}</b></div>
    <div class="stat-card"><span>Critical</span><b class="sev-critical">${formatNumber(severity.critical)}</b></div>
    <div class="stat-card"><span>High</span><b class="sev-high">${formatNumber(severity.high)}</b></div>
    <div class="stat-card"><span>Unique secrets</span><b>${formatNumber((data.secrets || []).length)}</b></div>`;
  renderProviderFilters(data.providers || []);
  renderSecrets(data.secrets || []);
  const hostBody = $("vulnHostsBody");
  hostBody.innerHTML = hosts.length ? hosts.map((host, index) => `
    <tr class="find-row vuln-row" data-index="${index}">
      <td class="text-cyan-200 font-mono">${esc(host.host)}</td>
      <td>${esc((host.methods || []).join(", "))}</td>
      <td>${esc((host.severities || []).join(", "))}</td>
      <td>${formatNumber(host.finding_count)}</td>
    </tr>`).join("") : '<tr><td colspan="4" class="text-slate-500">No vulnerable hosts yet.</td></tr>';
  hostBody.querySelectorAll(".vuln-row").forEach((row) => {
    row.onclick = () => {
      $("vulnHostDetail").classList.remove("hidden");
      $("vulnHostDetail").textContent = JSON.stringify(hosts[Number(row.dataset.index)], null, 2);
    };
  });
}

function renderProviderFilters(providers) {
  const allCount = providers.reduce((sum, item) => sum + Number(item.count || 0), 0);
  $("providerFilters").innerHTML = [`
    <button class="provider-chip ${state.provider ? "" : "active"}" data-provider="">
      <span class="provider-mark">ALL</span><span>All APIs</span><b>${allCount}</b>
    </button>`, ...providers.map((item) => `
    <button class="provider-chip ${state.provider === item.id ? "active" : ""}" data-provider="${esc(item.id)}">
      ${item.logo ? `<img src="${esc(item.logo)}" alt="" loading="lazy" />` : `<span class="provider-mark">${esc(item.label.slice(0, 2).toUpperCase())}</span>`}
      <span>${esc(item.label)}</span><b>${formatNumber(item.count)}</b>
    </button>`)].join("");
  $("providerFilters").querySelectorAll(".provider-chip").forEach((button) => {
    button.onclick = () => {
      state.provider = button.dataset.provider;
      reloadResults();
    };
  });
}

function renderSecrets(secrets) {
  const providers = new Map((state.results?.providers || []).map((item) => [item.id, item]));
  $("secretsBox").innerHTML = secrets.length ? secrets.map((secret, index) => {
    const provider = providers.get(secret.provider) || {};
    return `
    <div class="secret-card">
      <span class="secret-kind">${provider.logo ? `<img src="${esc(provider.logo)}" alt="" />` : ""}<span>${esc(secret.kind)}</span></span>
      <code class="secret-value">${esc(secret.value)}</code>
      <span class="text-slate-500 break-all" title="${esc((secret.sources || []).join("\n"))}">${esc(secret.source_url || "")}</span>
      <span class="secret-actions"><span class="pill">${formatNumber(secret.occurrences)} occurrence${secret.occurrences === 1 ? "" : "s"}</span><button class="btn-ghost copy-secret" data-index="${index}">Copy full value</button></span>
    </div>`;
  }).join("") : '<div class="py-8 text-center text-sm text-slate-500">No extracted secrets for this filter.</div>';
  $("secretsBox").querySelectorAll(".copy-secret").forEach((button) => {
    button.onclick = async () => {
      await copyText(String(secrets[Number(button.dataset.index)]?.value || ""));
      button.textContent = "Copied";
      setTimeout(() => { button.textContent = "Copy full value"; }, 1200);
    };
  });
}

async function copyText(value) {
  if (navigator.clipboard && window.isSecureContext) {
    await navigator.clipboard.writeText(value);
    return;
  }
  const input = document.createElement("textarea");
  input.value = value;
  input.style.position = "fixed";
  input.style.opacity = "0";
  document.body.appendChild(input);
  input.select();
  document.execCommand("copy");
  input.remove();
}

function renderFindings() {
  const query = $("findQ").value.trim().toLowerCase();
  const severity = $("sevFilter").value;
  const moduleName = $("modFilter").value;
  const rows = state.findings.filter((finding) => {
    if (severity && finding.severity !== severity) return false;
    if (moduleName && finding.module !== moduleName) return false;
    return !query || JSON.stringify(finding).toLowerCase().includes(query);
  });
  $("findingsBody").innerHTML = rows.length ? rows.map((finding, index) => `
    <tr class="find-row finding-row" data-index="${index}">
      <td class="sev-${esc(finding.severity)}">${esc(finding.severity)}</td>
      <td>${esc(finding.module)}</td>
      <td class="max-w-[190px] truncate" title="${esc(finding.title)}">${esc(finding.title)}</td>
      <td class="max-w-[210px] truncate font-mono text-cyan-200" title="${esc(finding.url)}">${esc(finding.url)}</td>
    </tr>`).join("") : '<tr><td colspan="4" class="text-slate-500">No findings for this filter.</td></tr>';
  $("findingsBody").querySelectorAll(".finding-row").forEach((row) => {
    row.onclick = () => {
      $("evidence").classList.remove("hidden");
      $("evidence").textContent = JSON.stringify(rows[Number(row.dataset.index)], null, 2);
    };
  });
}

async function reloadLogs() {
  if (!state.scanId) {
    $("logs").innerHTML = '<div class="text-slate-500">Select a job first.</div>';
    return;
  }
  if (state.logsRefreshPending) return;
  state.logsRefreshPending = true;
  try {
    const params = new URLSearchParams({ limit: "800" });
    if ($("logLevel").value) params.set("level", $("logLevel").value);
    state.logs = await api(`/api/scans/${encodeURIComponent(state.scanId)}/logs?${params}`);
    renderLogs();
  } catch (error) {
    $("logs").innerHTML = `<div class="text-red-300">${esc(error.message)}</div>`;
  } finally {
    state.logsRefreshPending = false;
  }
}

function renderLogs() {
  const level = $("logLevel").value;
  const logs = level ? state.logs.filter((item) => item.level === level) : state.logs;
  const job = state.jobs.find((item) => item.id === state.scanId);
  $("terminalTitle").textContent = job?.config?.job_name || state.scanId || "No job selected";
  $("logs").innerHTML = logs.slice(-800).map((item) =>
    `<div class="log-${esc(item.level)}"><span class="text-slate-600">${esc(item.timestamp || "")}</span> [${esc(item.level)}] [${esc(item.module)}] ${esc(item.message)}</div>`
  ).join("") || '<div class="text-slate-500">No logs available.</div>';
  $("logs").scrollTop = $("logs").scrollHeight;
}

function exportFormat(format) {
  if (state.scanId) window.open(`/api/scans/${encodeURIComponent(state.scanId)}/export/${format}`, "_blank");
}

function bindEvents() {
  document.querySelectorAll(".nav-tab").forEach((button) => button.onclick = () => showTab(button.dataset.tab));
  $("uploadBtn").onclick = uploadFile;
  $("refreshUploads").onclick = refreshUploads;
  $("createJobBtn").onclick = openJobModal;
  $("openJobFromUploads").onclick = openJobModal;
  $("closeJobModal").onclick = closeJobModal;
  $("cancelJob").onclick = closeJobModal;
  $("startBtn").onclick = startJob;
  $("jobModal").onclick = (event) => { if (event.target === $("jobModal")) closeJobModal(); };
  $("resultScanSelect").onchange = () => { selectScan($("resultScanSelect").value); reloadResults(); };
  $("logScanSelect").onchange = () => { selectScan($("logScanSelect").value); reloadLogs(); };
  $("refreshResults").onclick = reloadResults;
  $("sevFilter").onchange = renderFindings;
  $("modFilter").onchange = renderFindings;
  $("findQ").oninput = renderFindings;
  $("logLevel").onchange = reloadLogs;
  $("clearLogs").onclick = () => { $("logs").innerHTML = ""; };
  $("exportJson").onclick = () => exportFormat("json");
  $("exportCsv").onclick = () => exportFormat("csv");
  $("exportVulns").onclick = () => exportFormat("vulns_csv");
  $("exportHosts").onclick = () => exportFormat("hosts");
}

async function init() {
  initModules();
  setupUploadDropzone();
  bindEvents();
  await Promise.all([refreshUploads(), refreshJobs()]);
  if (state.scanId) connectWs(state.scanId);
  setInterval(refreshJobs, 4000);
  setInterval(() => {
    if (state.tab === "logs") reloadLogs();
    if (state.tab === "results") reloadResults();
  }, 3000);
}

init();
