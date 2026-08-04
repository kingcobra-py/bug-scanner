const MODULES = ["git", "js", "config", "path", "methods", "wordpress", "joomla", "react"];
const state = {
  tab: "uploads",
  uploadKind: "targets",
  uploads: [],
  jobs: [],
  allScans: [],
  servers: [],
  scanId: null,
  provider: "",
  results: null,
  logs: [],
  ws: null,
  pingTimer: null,
  jobsRefreshPending: false,
  serversRefreshPending: false,
  resultsRefreshPending: false,
  resultsRequestScan: null,
  resultsController: null,
  resultsCache: new Map(),
  resultsCacheAt: new Map(),
  logsRefreshPending: false,
  resultReloadTimer: null,
};

const $ = (id) => document.getElementById(id);
const esc = (value) => String(value ?? "").replace(/[&<>"']/g, (char) => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
})[char]);

async function api(url, options = {}) {
  let response;
  try {
    response = await fetch(url, options);
  } catch (error) {
    if (error?.name === "AbortError") throw error;
    const reason = error?.message || "Failed to fetch";
    throw new Error(
      `Cannot reach the scanner API (${url}). ${reason}. ` +
      "Usually the service is restarting or saturated by a large running scan — wait a moment and retry."
    );
  }
  let data = null;
  try { data = await response.json(); } catch (_) { data = {}; }
  const detail = data.detail;
  const detailText = Array.isArray(detail)
    ? detail.map((item) => item.msg || JSON.stringify(item)).join("; ")
    : detail;
  if (!response.ok) throw new Error(detailText || data.error || `Request failed (${response.status})`);
  return data;
}

function formatNumber(value) {
  return Number(value || 0).toLocaleString();
}

function formatBytes(bytes) {
  const size = Number(bytes || 0);
  if (size < 1024) return `${size} B`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
  if (size < 1024 * 1024 * 1024) return `${(size / 1024 / 1024).toFixed(1)} MB`;
  return `${(size / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

function formatEta(seconds) {
  if (seconds == null || !Number.isFinite(Number(seconds))) return "—";
  const value = Math.max(0, Number(seconds));
  if (value < 60) return `${Math.round(value)}s`;
  if (value < 3600) return `${Math.round(value / 60)}m`;
  return `${(value / 3600).toFixed(1)}h`;
}

function withSearchText(finding) {
  return {
    ...finding,
    _search: [finding.severity, finding.module, finding.type, finding.title, finding.url, finding.timestamp]
      .join(" ")
      .toLowerCase(),
  };
}

function formatHitTime(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return String(value).replace("T", " ").replace(/\+.*/, "").slice(0, 19);
  }
  const pad = (n) => String(n).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}

function showTab(name) {
  state.tab = name;
  document.querySelectorAll(".tab-view").forEach((el) => {
    const isActive = el.id === `tab-${name}`;
    el.classList.toggle("hidden", !isActive);
    if (isActive) {
      el.classList.remove("tab-anim");
      // Re-trigger the fade-in keyframe each time this tab becomes active.
      void el.offsetWidth;
      el.classList.add("tab-anim");
    }
  });
  document.querySelectorAll(".nav-tab").forEach((el) => el.classList.toggle("active", el.dataset.tab === name));
  if (name === "uploads") refreshUploads();
  if (name === "jobs") refreshJobs();
  if (name === "servers") refreshServers();
  if (name === "results") reloadResults();
  if (name === "logs") reloadLogs();
}

function initModules() {
  $("modules").innerHTML = MODULES.map((name) => `
    <label class="module-option">
      <input id="mod_${name}" type="checkbox" checked />
      <span>${esc(name === "methods" ? "HTTP methods" : name)}</span>
    </label>`).join("");
}

function secretKindLabel(kind) {
  if (kind === "aws_cred") return "aws_access_key:aws_secret_key";
  return kind || "secret";
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
  if (!zone || !input) return;
  input.onchange = () => {
    const label = $("chosenFile");
    if (label) label.textContent = input.files[0]?.name || "No file selected";
  };
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
    const label = $("chosenFile");
    if (label) label.textContent = input.files[0].name;
  });
}

const MAX_UPLOAD_BYTES = 5 * 1024 * 1024 * 1024;
const UPLOAD_CONCURRENCY = 4;

function setUploadProgress(sent, total, label = "Uploading chunks…") {
  const pct = total ? Math.min(100, (sent / total) * 100) : 0;
  $("uploadProgress").classList.remove("hidden");
  $("uploadProgressLabel").textContent = label;
  $("uploadProgressPercent").textContent = `${pct.toFixed(1)}%`;
  $("uploadProgressBar").style.width = `${pct}%`;
  $("uploadProgressBytes").textContent = `${formatBytes(sent)} / ${formatBytes(total)}`;
}

function uploadChunk(uploadId, index, blob, onProgress) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("PUT", `/api/uploads/chunks/${encodeURIComponent(uploadId)}/${index}`);
    xhr.setRequestHeader("Content-Type", "application/octet-stream");
    xhr.upload.onprogress = (event) => {
      if (event.lengthComputable) onProgress(event.loaded);
    };
    xhr.onerror = () => reject(new Error(`Network error uploading chunk ${index + 1}`));
    xhr.onload = () => {
      let data = {};
      try { data = JSON.parse(xhr.responseText || "{}"); } catch (_) {}
      if (xhr.status >= 200 && xhr.status < 300) resolve(data);
      else reject(new Error(data.detail || `Chunk ${index + 1} failed (${xhr.status})`));
    };
    xhr.send(blob);
  });
}

async function uploadFileInChunks(file, kind) {
  const resumeKey = `bb-upload:${kind}:${file.name}:${file.size}:${file.lastModified}`;
  let session = null;
  const savedId = sessionStorage.getItem(resumeKey);
  if (savedId) {
    try {
      session = await api(`/api/uploads/chunks/${encodeURIComponent(savedId)}`);
    } catch (_) {
      sessionStorage.removeItem(resumeKey);
    }
  }
  if (!session || Number(session.total_size) !== file.size) {
    session = await api("/api/uploads/chunks/init", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ filename: file.name, kind, total_size: file.size }),
    });
    sessionStorage.setItem(resumeKey, session.id);
  }

  const chunkSize = Number(session.chunk_size);
  const totalChunks = Number(session.total_chunks);
  const complete = new Set((session.received_chunks || []).map(Number));
  const uploaded = new Map();
  for (const index of complete) {
    uploaded.set(index, Math.min(chunkSize, file.size - index * chunkSize));
  }
  const active = new Map();
  const update = () => {
    const sent = [...uploaded.values()].reduce((sum, value) => sum + value, 0)
      + [...active.values()].reduce((sum, value) => sum + value, 0);
    setUploadProgress(sent, file.size);
  };
  update();

  const pending = Array.from({ length: totalChunks }, (_, index) => index)
    .filter((index) => !complete.has(index));
  let cursor = 0;
  async function worker() {
    while (cursor < pending.length) {
      const index = pending[cursor++];
      const start = index * chunkSize;
      const blob = file.slice(start, Math.min(file.size, start + chunkSize));
      let lastError = null;
      for (let attempt = 1; attempt <= 3; attempt++) {
        try {
          active.set(index, 0);
          await uploadChunk(session.id, index, blob, (loaded) => {
            active.set(index, loaded);
            update();
          });
          active.delete(index);
          uploaded.set(index, blob.size);
          update();
          lastError = null;
          break;
        } catch (error) {
          active.delete(index);
          lastError = error;
          if (attempt < 3) await new Promise((resolve) => setTimeout(resolve, attempt * 750));
        }
      }
      if (lastError) throw lastError;
    }
  }
  await Promise.all(
    Array.from({ length: Math.min(UPLOAD_CONCURRENCY, pending.length || 1) }, () => worker())
  );
  setUploadProgress(file.size, file.size, "Processing target file…");
  const record = await api(`/api/uploads/chunks/${encodeURIComponent(session.id)}/complete`, {
    method: "POST",
  });
  sessionStorage.removeItem(resumeKey);
  return record;
}

async function uploadFile() {
  const file = $("uploadFile").files[0];
  if (!file) {
    $("uploadMessage").innerHTML = '<span class="text-amber-300">Choose a file first.</span>';
    return;
  }
  if (file.size > MAX_UPLOAD_BYTES) {
    $("uploadMessage").innerHTML = '<span class="text-red-300">File exceeds the 5 GB upload limit.</span>';
    return;
  }
  const button = $("uploadBtn");
  button.disabled = true;
  button.textContent = "Uploading…";
  $("uploadMessage").textContent = "";
  setUploadProgress(0, file.size, "Preparing chunks…");
  try {
    const record = await uploadFileInChunks(file, state.uploadKind);
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
      <button class="btn-ghost download-upload" data-id="${esc(file.id)}">Download</button>
      <button class="btn-ghost delete-upload" data-id="${esc(file.id)}">Delete</button>
    </div>`).join("");
  list.querySelectorAll(".download-upload").forEach((button) => {
    button.onclick = () => {
      window.location.href = `/api/uploads/${encodeURIComponent(button.dataset.id)}/download`;
    };
  });
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
  await Promise.all([refreshUploads(), refreshServers()]);
  if (!state.uploads.some((item) => item.kind === "targets" && item.exists !== false)) {
    showTab("uploads");
    $("uploadMessage").innerHTML = '<span class="text-amber-300">Upload a targets file before creating a job.</span>';
    return;
  }
  $("jobError").textContent = "";
  setExploitsEnabled(false);
  if ($("exploitCommand")) $("exploitCommand").value = "id";
  if ($("exploitAll")) $("exploitAll").checked = true;
  renderJobServerPicker();
  $("jobModal").classList.add("open");
}

function closeJobModal() {
  $("jobModal").classList.remove("open");
}

function exploitsEnabled() {
  return $("toggleExploits")?.classList.contains("active") ?? false;
}

function setExploitsEnabled(enabled) {
  const button = $("toggleExploits");
  const options = $("exploitOptions");
  const stateLabel = $("exploitToggleState");
  if (!button || !options || !stateLabel) return;
  button.classList.toggle("active", enabled);
  button.setAttribute("aria-pressed", enabled ? "true" : "false");
  options.classList.toggle("hidden", !enabled);
  stateLabel.textContent = enabled ? "On" : "Off";
}

async function startJob(event) {
  if (event?.preventDefault) event.preventDefault();
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
    worker_processes: Number($("workerProcesses").value || 1),
    timeout: Number($("timeout").value || 8),
    retries: Number($("retries").value || 1),
    rate_limit_per_host: Number($("rateLimit").value || 50),
    paths_mode: $("pathsMode").value,
    method_test_trace: $("methodTrace").checked,
    exploit_enabled: exploitsEnabled(),
    exploit_command: ($("exploitCommand")?.value || "id").trim() || "id",
    exploit_all: exploitsEnabled() && Boolean($("exploitAll")?.checked),
    redact_secrets: false,
    scope_notes: $("scope").value,
    ssh_server_ids: selectedServerIds(),
  };
  if (!body.modules.length) {
    $("jobError").textContent = "Enable at least one scan module.";
    return;
  }
  const button = $("startBtn");
  button.disabled = true;
  button.textContent = "Starting…";
  $("jobError").textContent = "";
  try {
    const response = await api("/api/scans", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!response?.id) throw new Error("Scanner did not return a job id.");
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
    if (!state.allScans.some((job) => job.id === state.scanId)) {
      state.scanId = state.allScans[0]?.id || null;
    }
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
  const totalSecrets = state.jobs.reduce((sum, job) => sum + Number(job.progress?.secrets ?? job.summary?.secret_count ?? 0), 0);
  $("runningBadge").textContent = running.length;
  $("runningBadge").classList.toggle("hidden", !running.length);
  $("jobsOverview").innerHTML = `
    <div class="stat-card"><span>Total jobs</span><b>${state.jobs.length}</b></div>
    <div class="stat-card"><span>Running</span><b class="text-cyan-300">${running.length}</b></div>
    <div class="stat-card"><span>Completed</span><b class="text-emerald-300">${completed.length}</b></div>
    <div class="stat-card"><span>Secret credentials</span><b>${formatNumber(totalSecrets)}</b></div>`;
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
      } else if (action === "resume") {
        if (!confirm("Resume this job from its last checkpoint?")) return;
        button.disabled = true;
        button.textContent = "Resuming…";
        try {
          const response = await api(`/api/scans/${encodeURIComponent(id)}/resume`, { method: "POST" });
          const job = state.jobs.find((item) => item.id === id);
          if (job) job.status = response.status || "running";
          selectScan(id, true);
          await refreshJobs();
        } catch (error) {
          button.disabled = false;
          button.textContent = "Resume";
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
  const total = Number(progress.total || config.target_count || 0);
  const finished = Number(progress.done || 0) + Number(progress.failed || 0);
  const canResume = ["stopped", "failed"].includes(job.status) && (!total || finished < total);
  const isStoppedEarly = job.status === "stopped" && pct > 0 && pct < 100;
  const statusLabel = isStoppedEarly ? `stopped @ ${pct.toFixed(1)}%` : job.status;
  const serverCount = Array.isArray(config.ssh_server_ids) ? config.ssh_server_ids.length : 0;
  return `
    <article class="job-card ${esc(job.status)}">
      <div class="job-card-head">
        <div class="min-w-0"><div class="job-title truncate">${esc(name)}</div><div class="job-id">${esc(job.id)} · ${formatNumber(config.target_count ?? (config.targets || []).length)} targets${Number(config.worker_processes) > 1 ? ` · ${config.worker_processes} processes` : ""}${serverCount ? ` · ${serverCount} SSH` : ""} · ${esc(formatHitTime(job.updated_at || job.created_at))}</div></div>
        <span class="status-badge ${esc(job.status)}" title="${esc(job.status)}">${esc(statusLabel)}</span>
      </div>
      <div class="flex justify-between text-[11px] text-slate-500 mt-4 mb-1.5"><span>${pct.toFixed(1)}%</span><span>ETA ${formatEta(progress.eta_seconds)}</span></div>
      <div class="progress-track"><div class="progress-fill" style="width:${pct}%"></div></div>
      <div class="job-stats">
        <div title="Actual completed HTTP attempts per second (including probes, retries, and redirects)">HTTP RPS<b>${Number(progress.rps || 0).toFixed(1)}</b></div>
        <div title="Domains/IPs that finished the full selected-module pipeline">Done<b>${formatNumber(progress.done)}</b></div>
        <div title="Domains/IPs that failed hard during their pipeline">Failed<b>${formatNumber(progress.failed)}</b></div>
        <div title="Unique hosts that produced at least one finding">Vulnerable hosts<b>${formatNumber(progress.vulnerable_hosts ?? job.summary?.vulnerable_host_count ?? 0)}</b></div>
        <div>Secrets<b>${formatNumber(progress.secrets)}</b></div>
      </div>
      <div class="text-[11px] text-slate-500 truncate mt-3">${esc(progress.current_module || "idle")} ${progress.current_target ? `@ ${esc(progress.current_target)}` : ""}</div>
      <div class="module-pills">${modules.map((name) => `<span>${esc(name)}</span>`).join("")}</div>
      <div class="flex gap-2 justify-end mt-4 flex-wrap">
        ${canResume ? `<button class="btn-primary job-action" data-id="${esc(job.id)}" data-action="resume">Resume</button>` : ""}
        ${isStopping
          ? '<button class="btn-ghost" disabled>Stopping…</button>'
          : `<button class="btn-destructive job-action" data-id="${esc(job.id)}" data-action="${canStop ? "stop" : "delete"}">${canStop ? "Stop" : "Delete"}</button>`}
        <button class="btn-ghost view-logs" data-id="${esc(job.id)}">Logs</button>
        <button class="btn-ghost view-results" data-id="${esc(job.id)}">Results →</button>
      </div>
    </article>`;
}

function selectedServerIds() {
  return [...document.querySelectorAll("#jobServers input[type=checkbox]:checked")].map((el) => el.value);
}

function renderJobServerPicker() {
  const box = $("jobServers");
  if (!box) return;
  if (!state.servers.length) {
    box.innerHTML = "";
    return;
  }
  box.innerHTML = state.servers.map((server) => `
    <label>
      <input type="checkbox" value="${esc(server.id)}" />
      <span>${esc(server.label || server.host)} <small class="text-slate-500">${esc(server.endpoint || `${server.host}:${server.port}`)}</small></span>
    </label>`).join("");
}

async function refreshServers(forceMetrics = false) {
  if (state.serversRefreshPending) return;
  state.serversRefreshPending = true;
  try {
    state.servers = forceMetrics
      ? await api("/api/servers/refresh", { method: "POST" })
      : await api("/api/servers");
    renderServers();
    renderJobServerPicker();
  } catch (error) {
    const grid = $("serversGrid");
    if (grid) grid.innerHTML = `<div class="text-red-300">${esc(error.message)}</div>`;
  } finally {
    state.serversRefreshPending = false;
  }
}

function metricPct(metrics, key) {
  const value = Number(metrics?.[key] || 0);
  if (!Number.isFinite(value)) return 0;
  return Math.max(0, Math.min(100, value));
}

function serverCard(server) {
  const metrics = server.metrics || {};
  const online = server.status === "online" || metrics.online === true;
  const cpu = metricPct(metrics, "cpu_percent");
  const mem = metricPct(metrics, "memory_percent");
  const disk = metricPct(metrics, "disk_percent");
  const authLabel = server.auth_type === "password" ? "Password" : "Key";
  return `
    <article class="ssh-card" data-id="${esc(server.id)}">
      <div class="ssh-card-head">
        <div class="ssh-card-title">
          <div class="ssh-rack" aria-hidden="true">▮</div>
          <div class="min-w-0">
            <div class="ssh-host">${esc(server.label || server.host)}</div>
            <div class="ssh-endpoint">${esc(server.endpoint || `${server.host}:${server.port}`)}</div>
          </div>
        </div>
        <span class="status-badge ${online ? "online" : "offline"}">${online ? "Online" : "Offline"}</span>
      </div>
      <div class="ssh-meta">
        <div class="ssh-meta-box"><span>Username</span><b>${esc(server.username || "ubuntu")}</b></div>
        <div class="ssh-meta-box"><span>Auth</span><b><span class="ssh-key-icon">⌁</span> ${esc(authLabel)}</b></div>
      </div>
      <div class="ssh-bars">
        <div class="ssh-bar-row"><span>CPU</span><div class="ssh-bar-track"><div class="ssh-bar-fill" style="width:${cpu}%"></div></div><b>${cpu.toFixed(0)}%</b></div>
        <div class="ssh-bar-row"><span>Memory</span><div class="ssh-bar-track"><div class="ssh-bar-fill mem" style="width:${mem}%"></div></div><b>${mem.toFixed(0)}%</b></div>
        <div class="ssh-bar-row"><span>Disk</span><div class="ssh-bar-track"><div class="ssh-bar-fill disk" style="width:${disk}%"></div></div><b>${disk.toFixed(0)}%</b></div>
      </div>
      <div class="ssh-mini-grid">
        <div class="ssh-mini"><span>Cores</span><b>${esc(metrics.cores ?? "-")}</b></div>
        <div class="ssh-mini"><span>Load</span><b>${esc(metrics.load ?? "-")}</b></div>
        <div class="ssh-mini"><span>Procs</span><b>${esc(metrics.procs ?? "-")}</b></div>
        <div class="ssh-mini"><span>Net</span><b>${esc(metrics.net ?? "-")}</b></div>
      </div>
      <div class="ssh-error">${esc(server.last_error || metrics.error || "")}</div>
      <div class="ssh-actions">
        <button class="btn-ghost server-action" data-id="${esc(server.id)}" data-action="install">⇩ Install Deps</button>
        <button class="btn-danger server-action" data-id="${esc(server.id)}" data-action="remove">Remove</button>
      </div>
    </article>`;
}

function renderServers() {
  const grid = $("serversGrid");
  const empty = $("serversEmpty");
  if (!grid || !empty) return;
  empty.classList.toggle("hidden", Boolean(state.servers.length));
  grid.innerHTML = state.servers.map(serverCard).join("");
  grid.querySelectorAll(".server-action").forEach((button) => {
    button.onclick = async () => {
      const id = button.dataset.id;
      const action = button.dataset.action;
      if (action === "remove") {
        if (!confirm("Remove this SSH server from the fleet?")) return;
        button.disabled = true;
        try {
          await api(`/api/servers/${encodeURIComponent(id)}`, { method: "DELETE" });
          await refreshServers();
        } catch (error) {
          button.disabled = false;
          alert(error.message);
        }
        return;
      }
      if (action === "install") {
        if (!confirm("Install Python dependencies on this remote host under /opt/bb-scanner?")) return;
        button.disabled = true;
        button.textContent = "Installing…";
        try {
          const result = await api(`/api/servers/${encodeURIComponent(id)}/install-deps`, { method: "POST" });
          if (!result.ok) throw new Error(result.message || "Install failed");
          await refreshServers();
        } catch (error) {
          alert(error.message);
          button.disabled = false;
          button.textContent = "Install Deps";
          await refreshServers();
        }
      }
    };
  });
}

async function addServer(event) {
  if (event?.preventDefault) event.preventDefault();
  const host = $("sshHost")?.value.trim();
  const privateKey = $("sshKey")?.value.trim();
  if (!host || !privateKey) {
    $("serverError").textContent = "Host and private key are required.";
    return;
  }
  const button = $("addServerBtn");
  button.disabled = true;
  button.textContent = "Adding…";
  $("serverError").textContent = "";
  try {
    await api("/api/servers", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        host,
        port: Number($("sshPort").value || 22),
        username: ($("sshUser").value || "ubuntu").trim() || "ubuntu",
        label: ($("sshLabel").value || "").trim(),
        auth_type: "key",
        private_key: privateKey,
      }),
    });
    $("serverForm").reset();
    $("sshPort").value = "22";
    $("sshUser").value = "ubuntu";
    await refreshServers();
  } catch (error) {
    $("serverError").textContent = error.message;
  } finally {
    button.disabled = false;
    button.textContent = "Add server";
  }
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
  if (state.scanId !== id) {
    if (state.resultsController) {
      state.resultsController.abort();
      state.resultsController = null;
      state.resultsRefreshPending = false;
    }
    state.results = null;
  }
  state.scanId = id;
  state.provider = "";
  syncScanSelectors();
  connectWs(id);
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
      // Keep the current page coherent via a throttled reload instead of
      // splicing live rows into a paginated list.
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
  // Large running scans take a long time to aggregate Results. Debounce hard
  // so finding spam does not abort/restart the in-flight request.
  if (state.resultReloadTimer) clearTimeout(state.resultReloadTimer);
  state.resultReloadTimer = setTimeout(() => reloadResults(false), 60000);
}

function applyResultsPayload(results) {
  state.results = results;
  renderResults();
}

async function reloadResults(force = false) {
  if (!state.scanId) {
    $("resultSummary").innerHTML = '<div class="text-slate-500 text-sm">Select a job first.</div>';
    return;
  }
  const scanId = state.scanId;
  const cached = state.resultsCache.get(scanId);
  if (cached) applyResultsPayload(cached);
  const job = state.allScans.find((item) => item.id === scanId);
  const active = ["running", "pending", "stopping"].includes(job?.status);
  if (cached && !force && !active) return;
  // Active scans: keep showing cache and refresh at most once per minute.
  if (cached && !force && active) {
    const age = Date.now() - Number(state.resultsCacheAt.get(scanId) || 0);
    if (age < 60000) return;
  }
  // Never abort an in-flight Results request for the same scan — that is what
  // made the UI report "Failed to fetch" on multi-GB jobs.
  if (state.resultsRefreshPending && state.resultsRequestScan === scanId) return;
  if (state.resultsController && state.resultsRequestScan === scanId) return;
  if (state.resultsController) state.resultsController.abort();
  const controller = new AbortController();
  state.resultsController = controller;
  state.resultsRequestScan = scanId;
  state.resultsRefreshPending = true;
  if (!cached && $("resultSummary")) {
    $("resultSummary").innerHTML =
      '<div class="text-slate-400 text-sm">Loading results… large running scans can take 1–2 minutes. Keep this tab open.</div>';
  }
  try {
    const results = await api(
      `/api/scans/${encodeURIComponent(scanId)}/results`,
      { signal: controller.signal },
    );
    if (state.scanId !== scanId) return;
    state.resultsCache.set(scanId, results);
    state.resultsCacheAt.set(scanId, Date.now());
    applyResultsPayload(results);
  } catch (error) {
    if (error?.name !== "AbortError" && state.scanId === scanId && !cached) {
      $("resultSummary").innerHTML = `<div class="text-red-300">${esc(error.message)}</div>`;
    }
  } finally {
    if (state.resultsController === controller) {
      state.resultsController = null;
      state.resultsRequestScan = null;
      state.resultsRefreshPending = false;
    }
  }
}

function renderResults() {
  const data = state.results || {};
  const severity = data.by_severity || {};
  $("resultSummary").innerHTML = `
    <div class="stat-card"><span>Unique findings</span><b>${formatNumber(data.finding_count)}</b></div>
    <div class="stat-card"><span>Critical</span><b class="sev-critical">${formatNumber(severity.critical)}</b></div>
    <div class="stat-card"><span>High</span><b class="sev-high">${formatNumber(severity.high)}</b></div>
    <div class="stat-card"><span>Unique secrets</span><b>${formatNumber((data.secrets || []).length)}</b></div>`;
  renderProviderFilters(data.providers || []);
  const filteredSecrets = (data.secrets || []).filter((s) => !state.provider || s.provider === state.provider);
  renderSecrets(filteredSecrets);
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
      // Cached secrets already hold every provider; re-render instantly
      // instead of asking the server to recompute and rewrite results.
      state.provider = button.dataset.provider;
      renderProviderFilters(providers);
      renderSecrets((state.results?.secrets || []).filter((s) => !state.provider || s.provider === state.provider));
    };
  });
}

function renderSecrets(secrets) {
  const providers = new Map((state.results?.providers || []).map((item) => [item.id, item]));
  state._secrets = secrets;
  $("secretsBox").innerHTML = secrets.length ? secrets.map((secret, index) => {
    const provider = providers.get(secret.provider) || {};
    return `
    <div class="secret-card">
      <span class="secret-kind">${provider.logo ? `<img src="${esc(provider.logo)}" alt="" />` : ""}<span>${esc(secretKindLabel(secret.kind))}</span></span>
      <code class="secret-value">${esc(secret.value)}</code>
      <span class="text-slate-500 break-all" title="${esc((secret.sources || []).join("\n"))}">${esc(secret.source_url || "")}</span>
      <span class="secret-actions"><span class="pill">${formatNumber(secret.occurrences)} occurrence${secret.occurrences === 1 ? "" : "s"}</span><button class="btn-ghost copy-secret" data-index="${index}">Copy full value</button></span>
    </div>`;
  }).join("") : '<div class="py-8 text-center text-sm text-slate-500">No extracted secrets for this filter.</div>';
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

async function purgeSelectedJob() {
  const scanId = state.scanId;
  if (!scanId) return;
  const job = state.allScans.find((item) => item.id === scanId);
  const name = job?.config?.job_name || `Scan ${scanId}`;
  if (!confirm(
    `Permanently delete "${name}" and ALL of its findings, logs, reports, and saved response files?\n\nThis cannot be undone.`
  )) return;
  const button = $("purgeResults");
  button.disabled = true;
  button.textContent = "Deleting…";
  try {
    await api(`/api/scans/${encodeURIComponent(scanId)}/purge`, { method: "DELETE" });
    state.resultsCache.delete(scanId);
    state.resultsCacheAt.delete(scanId);
    state.results = null;
    state.scanId = null;
    await refreshJobs();
    syncScanSelectors();
    await reloadResults();
  } catch (error) {
    alert(error.message);
  } finally {
    button.disabled = false;
    button.textContent = "Delete job + results";
  }
}

function on(id, event, handler) {
  const el = $(id);
  if (!el) return;
  el[event] = handler;
}

function bindEvents() {
  document.querySelectorAll(".nav-tab").forEach((button) => {
    button.onclick = () => showTab(button.dataset.tab);
  });
  on("uploadBtn", "onclick", uploadFile);
  on("refreshUploads", "onclick", refreshUploads);
  on("createJobBtn", "onclick", openJobModal);
  on("openJobFromUploads", "onclick", openJobModal);
  on("closeJobModal", "onclick", closeJobModal);
  on("cancelJob", "onclick", closeJobModal);
  on("startBtn", "onclick", startJob);
  on("jobForm", "onsubmit", startJob);
  on("toggleExploits", "onclick", () => setExploitsEnabled(!exploitsEnabled()));
  on("jobModal", "onclick", (event) => {
    if (event.target === $("jobModal")) closeJobModal();
  });
  on("resultScanSelect", "onchange", () => {
    selectScan($("resultScanSelect").value);
    reloadResults();
  });
  on("logScanSelect", "onchange", () => {
    selectScan($("logScanSelect").value);
    reloadLogs();
  });
  on("refreshResults", "onclick", () => reloadResults(true));
  on("purgeResults", "onclick", purgeSelectedJob);
  on("logLevel", "onchange", reloadLogs);
  on("clearLogs", "onclick", () => {
    if ($("logs")) $("logs").innerHTML = "";
  });
  on("exportJson", "onclick", () => exportFormat("json"));
  on("exportCsv", "onclick", () => exportFormat("csv"));
  on("exportVulns", "onclick", () => exportFormat("vulns_csv"));
  on("exportHosts", "onclick", () => exportFormat("hosts"));
  on("refreshServers", "onclick", () => refreshServers(true));
  on("serverForm", "onsubmit", addServer);
  on("addServerBtn", "onclick", addServer);
  const secretsBox = $("secretsBox");
  if (secretsBox) {
    secretsBox.addEventListener("click", async (event) => {
      const button = event.target.closest(".copy-secret");
      if (!button) return;
      const secret = state._secrets?.[Number(button.dataset.index)];
      if (!secret) return;
      await copyText(String(secret.value || ""));
      button.textContent = "Copied";
      setTimeout(() => { button.textContent = "Copy full value"; }, 1200);
    });
  }
}

async function init() {
  try {
    initModules();
    setupUploadDropzone();
    bindEvents();
  } catch (error) {
    console.error("UI bootstrap failed", error);
  }
  try {
    await Promise.all([refreshUploads(), refreshJobs(), refreshServers()]);
  } catch (error) {
    console.error("Initial data load failed", error);
  }
  if (state.scanId) connectWs(state.scanId);
  setInterval(refreshJobs, 4000);
  setInterval(() => {
    if (state.tab === "servers") refreshServers(true);
  }, 15000);
  setInterval(() => {
    if (state.tab === "logs") reloadLogs();
  }, 3000);
  // Results for huge scans is expensive — poll slowly and rely on cache/WS debounce.
  setInterval(() => {
    if (state.tab === "results") reloadResults(false);
  }, 30000);
}

init();
