/* Vedette frontend: no build step, vanilla JS. */
"use strict";

// --- tiny markdown renderer (headings, lists, bold, code, links) ---
function esc(s) {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
function inline(s) {
  s = esc(s);
  s = s.replace(/`([^`]+)`/g, "<code>$1</code>");
  s = s.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
  s = s.replace(/\[([^\]]+)\]\((https?:[^)]+)\)/g, '<a href="$2" target="_blank" rel="noopener">$1</a>');
  s = s.replace(/(^|\s)(https?:\/\/[^\s<]+)/g, '$1<a href="$2" target="_blank" rel="noopener">$2</a>');
  return s;
}
function renderMarkdown(md) {
  const lines = (md || "").split("\n");
  let html = "", inCode = false, inList = false;
  for (const line of lines) {
    if (line.trim().startsWith("```")) {
      html += inCode ? "</code></pre>" : "<pre><code>";
      inCode = !inCode;
      continue;
    }
    if (inCode) { html += esc(line) + "\n"; continue; }
    const h = line.match(/^(#{1,4})\s+(.*)/);
    if (h) {
      if (inList) { html += "</ul>"; inList = false; }
      html += "<h" + h[1].length + ">" + inline(h[2]) + "</h" + h[1].length + ">";
      continue;
    }
    if (/^\s*---+\s*$/.test(line)) { html += "<hr>"; continue; }
    const li = line.match(/^\s*[-*]\s+(.*)/);
    if (li) {
      if (!inList) { html += "<ul>"; inList = true; }
      html += "<li>" + inline(li[1]) + "</li>";
      continue;
    }
    if (inList) { html += "</ul>"; inList = false; }
    if (line.trim() === "") continue;
    html += "<p>" + inline(line) + "</p>";
  }
  if (inList) html += "</ul>";
  if (inCode) html += "</code></pre>";
  return html;
}

// --- app state ---
let pollTimer = null;
let currentReports = null;

async function api(path, opts) {
  const r = await fetch(path, opts);
  if (r.status === 401) { window.location = "/login"; throw new Error("unauthorized"); }
  return r;
}

async function loadUser() {
  const r = await api("/api/me");
  const me = await r.json();
  document.getElementById("user-email").textContent = me.email || "";
}

async function loadRuns() {
  const r = await api("/api/runs");
  const data = await r.json();
  const list = document.getElementById("run-list");
  if (!data.runs.length) { list.innerHTML = '<p class="muted">No runs yet.</p>'; return; }
  list.innerHTML = "";
  for (const run of data.runs) {
    const div = document.createElement("div");
    div.className = "run-item";
    div.innerHTML = '<span></span><span class="badge ' + esc(run.status) + '"></span>';
    div.children[0].textContent = run.org + " — " + (run.created || "").slice(0, 16).replace("T", " ");
    div.children[1].textContent = run.status;
    div.onclick = () => showRun(run.id);
    list.appendChild(div);
  }
}

document.getElementById("logout-btn").onclick = async () => {
  await api("/auth/logout", { method: "POST" });
  window.location = "/login";
};

const KNOWN_TYPES = ["company", "software", "domain"];

// Parse one textarea line: "Name", "Name=https://url", "Name|software",
// "https://example.com|domain". A |type suffix overrides the default.
function parseTargetLine(line, defaultType) {
  let spec = line.trim();
  let type = defaultType;
  const bar = spec.lastIndexOf("|");
  if (bar > 0) {
    const maybe = spec.slice(bar + 1).trim().toLowerCase();
    if (KNOWN_TYPES.includes(maybe)) {
      type = maybe;
      spec = spec.slice(0, bar).trim();
    }
  }
  let name = spec, url = "";
  const eq = spec.indexOf("=");
  if (eq > 0 && !spec.startsWith("http")) {
    name = spec.slice(0, eq).trim();
    url = spec.slice(eq + 1).trim();
  }
  return { name, url, type };
}

document.getElementById("assess-form").onsubmit = async (e) => {
  e.preventDefault();
  const errEl = document.getElementById("form-error");
  errEl.textContent = "";
  const defaultType = document.getElementById("f-type").value || "company";
  const targets = document.getElementById("f-targets").value
    .split("\n").map(s => s.trim()).filter(Boolean)
    .map(s => parseTargetLine(s, defaultType))
    .filter(t => t.name || t.url);
  if (!targets.length) { errEl.textContent = "at least one target is required"; return; }
  const body = {
    targets,
    default_type: defaultType,
    research_provider: document.getElementById("f-provider").value || null,
    research_model: document.getElementById("f-model").value.trim() || null,
  };
  const r = await api("/api/runs", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await r.json();
  if (!r.ok) { errEl.textContent = data.error || "failed to start"; return; }
  e.target.reset();
  loadRuns();
  showRun(data.id);
};

const PHASE_PCT = { starting: 5, triage: 12, research: 40, synthesize: 80, compare: 90, done: 100, queued: 0 };

function renderTargetProgress(targets) {
  const box = document.getElementById("run-target-progress");
  box.innerHTML = "";
  if (!targets) return;
  for (const [name, t] of Object.entries(targets)) {
    const div = document.createElement("div");
    div.className = "tprog";
    const pct = PHASE_PCT[t.phase] || 30;
    div.innerHTML = '<div class="tprog-label"></div>' +
      '<div class="progress tprog-bar"><div style="width:' + pct + '%"></div></div>' +
      '<div class="muted small"></div>';
    div.children[0].textContent = name;
    div.children[2].textContent = (t.phase || "") + (t.detail ? " — " + t.detail : "");
    box.appendChild(div);
  }
}

async function showRun(runId) {
  document.getElementById("detail-card").classList.remove("hidden");
  document.getElementById("detail-title").textContent = "Run " + runId;
  document.getElementById("report-tabs").innerHTML = "";
  document.getElementById("report-body").innerHTML = "";
  document.getElementById("detail-error").textContent = "";
  document.getElementById("run-target-progress").innerHTML = "";
  if (pollTimer) clearInterval(pollTimer);
  const poll = async () => {
    const r = await api("/api/runs/" + encodeURIComponent(runId));
    if (!r.ok) return;
    const st = await r.json();
    renderTargetProgress(st.targets);
    const prog = document.getElementById("run-progress");
    if (st.status === "running") {
      prog.classList.remove("hidden");
      document.getElementById("progress-bar").style.width =
        (PHASE_PCT[st.phase] || 30) + "%";
      document.getElementById("progress-detail").textContent =
        (st.phase || "") + (st.detail ? " — " + st.detail : "");
    } else {
      prog.classList.add("hidden");
      if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
      if (st.status === "failed") {
        document.getElementById("detail-error").textContent = "Run failed: " + (st.error || "");
      }
      loadReport(runId);
    }
    loadRuns();
  };
  await poll();
  pollTimer = setInterval(poll, 2500);
}

async function loadReport(runId) {
  const r = await api("/api/runs/" + encodeURIComponent(runId) + "/report");
  if (!r.ok) return;
  const data = await r.json();
  currentReports = data.reports || {};
  const tabs = document.getElementById("report-tabs");
  tabs.innerHTML = "";
  const names = Object.keys(currentReports);
  if (data.comparison) names.push("__comparison");
  if (!names.length) {
    document.getElementById("report-body").innerHTML = '<p class="muted">No report yet.</p>';
    return;
  }
  names.forEach((name, i) => {
    const b = document.createElement("button");
    b.className = "btn small" + (i === 0 ? " active" : "");
    b.textContent = name === "__comparison" ? "Comparison" : name;
    b.onclick = () => {
      tabs.querySelectorAll(".btn").forEach(x => x.classList.remove("active"));
      b.classList.add("active");
      document.getElementById("report-body").innerHTML = renderMarkdown(
        name === "__comparison" ? data.comparison : currentReports[name]);
    };
    tabs.appendChild(b);
  });
  tabs.children[0].click();
}

loadUser();
loadRuns();
