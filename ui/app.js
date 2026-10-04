/* Vedette frontend: no build step, vanilla JS. */
"use strict";

// --- tiny markdown renderer (headings, tables, lists, bold, code, links) ---
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
function splitRow(line) {
  return line.trim().replace(/^\||\|$/g, "").split("|").map(c => c.trim());
}
function renderMarkdown(md) {
  const lines = (md || "").split("\n");
  let html = "", inCode = false, listTag = null;
  const closeList = () => { if (listTag) { html += "</" + listTag + ">"; listTag = null; } };
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.trim().startsWith("```")) {
      closeList();
      html += inCode ? "</code></pre>" : "<pre><code>";
      inCode = !inCode;
      continue;
    }
    if (inCode) { html += esc(line) + "\n"; continue; }
    const h = line.match(/^(#{1,4})\s+(.*)/);
    if (h) {
      closeList();
      html += "<h" + h[1].length + ">" + inline(h[2]) + "</h" + h[1].length + ">";
      continue;
    }
    if (/^\s*---+\s*$/.test(line)) { closeList(); html += "<hr>"; continue; }
    // table: a header row containing | followed by a |---| separator row
    if (line.indexOf("|") !== -1 && i + 1 < lines.length &&
        /\|-/.test(lines[i + 1].replace(/ /g, ""))) {
      closeList();
      const heads = splitRow(line);
      html += "<table><thead><tr>" +
        heads.map(c => "<th>" + inline(c) + "</th>").join("") +
        "</tr></thead><tbody>";
      i += 2;
      while (i < lines.length && lines[i].indexOf("|") !== -1 && lines[i].trim() !== "") {
        html += "<tr>" + splitRow(lines[i]).map(c => "<td>" + inline(c) + "</td>").join("") + "</tr>";
        i++;
      }
      html += "</tbody></table>";
      i--;
      continue;
    }
    const li = line.match(/^\s*[-*]\s+(.*)/);
    const oli = line.match(/^\s*\d+[.)]\s+(.*)/);
    if (li || oli) {
      const tag = li ? "ul" : "ol";
      if (listTag !== tag) { closeList(); html += "<" + tag + ">"; listTag = tag; }
      html += "<li>" + inline((li || oli)[1]) + "</li>";
      continue;
    }
    closeList();
    if (line.trim() === "") continue;
    html += "<p>" + inline(line) + "</p>";
  }
  closeList();
  if (inCode) html += "</code></pre>";
  return html;
}

// --- app state ---
let pollTimer = null;
let currentReports = null;
let currentExport = null;  // {runId, reports, comparison} for HTML/PDF export
let watchedRunId = null;

// Vedette's compact theme adapter uses the palette model from the supplied
// theme reference and persists user choices locally in this browser.
const THEME_KEY = "vedette-theme";
const CUSTOM_THEMES_KEY = "vedette-custom-themes";
const THEMES = {
  dark:{bg:"#282c34",fg:"#9cdef2",panel:"#111111",border:"#355a66",red:"#e06c75"},
  light:{bg:"#f0ebe3",fg:"#5a5248",panel:"#faf6f0",border:"#d4cdc2",red:"#c47d5a"},
  midnight:{bg:"#0d1117",fg:"#c9d1d9",panel:"#161b22",border:"#30363d",red:"#f85149"},
  paper:{bg:"#faf8f5",fg:"#3b3836",panel:"#ffffff",border:"#d5d0c8",red:"#c5ac4a"},
  cyberpunk:{bg:"#0a0a0f",fg:"#0ff0fc",panel:"#12101a",border:"#9b30ff",red:"#e040fb"},
  retrowave:{bg:"#1a1a2e",fg:"#e94560",panel:"#16213e",border:"#533483",red:"#e94560"},
  forest:{bg:"#1b2a1b",fg:"#a8d5a2",panel:"#142414",border:"#3d6b3d",red:"#7cb871"},
  ocean:{bg:"#0b1a2c",fg:"#64d2ff",panel:"#091422",border:"#1e5074",red:"#4facfe"},
  ume:{bg:"#2b1b2e",fg:"#f5c2e7",panel:"#1e1420",border:"#6c4675",red:"#f5a0c0"},
  copper:{bg:"#1c1410",fg:"#e8c39e",panel:"#140f0a",border:"#7a5533",red:"#d4764e"},
  terminal:{bg:"#000000",fg:"#00ff41",panel:"#0a0a0a",border:"#003b00",red:"#00ff41"},
  organs:{bg:"#0a0406",fg:"#efe1c8",panel:"#15080a",border:"#3a1519",red:"#c83240"},
  lavender:{bg:"#f3eef8",fg:"#3d3551",panel:"#faf7ff",border:"#cec3de",red:"#9b6dcc"},
  gpt:{bg:"#212121",fg:"#ececec",panel:"#171717",border:"#424242",red:"#949494"},
  claude:{bg:"#262624",fg:"#f5f4f0",panel:"#30302e",border:"#4a4a47",red:"#c6613f"},
  cute:{bg:"#fff0f5",fg:"#d4608a",panel:"#fff8fa",border:"#f0c0d0",red:"#ff6b9d"}
};
function readCustomThemes() {
  try { return JSON.parse(localStorage.getItem(CUSTOM_THEMES_KEY) || "{}"); }
  catch (_) { return {}; }
}
function applyTheme(colors) {
  const root = document.documentElement;
  const vals = {"--bg":colors.bg,"--fg":colors.fg,"--panel":colors.panel,"--border":colors.border,"--red":colors.red,
    "--surface":colors.panel,"--surface-2":`color-mix(in srgb, ${colors.panel} 86%, ${colors.fg})`,
    "--line":colors.border,"--text":colors.fg,"--blue":colors.red,"--cyan":colors.fg,
    "--muted":`color-mix(in srgb, ${colors.fg} 66%, ${colors.bg})`,"--green":colors.fg};
  for (const [name, value] of Object.entries(vals)) root.style.setProperty(name, value);
  const rgb = colors.bg.match(/[a-f\d]{2}/gi)?.map(x => parseInt(x, 16)) || [0,0,0];
  const light = (rgb[0]*299 + rgb[1]*587 + rgb[2]*114)/1000 > 145;
  root.dataset.themeTone = light ? "light" : "dark";
  document.querySelector('meta[name="theme-color"]')?.setAttribute("content", colors.bg);
  for (const name of ["bg","fg","panel","border","red"]) {
    document.getElementById("color-" + name).value = colors[name];
  }
}
function initThemes() {
  const select = document.getElementById("theme-select");
  if (!select) return;
  const customs = readCustomThemes();
  for (const [label, group] of [["Preset themes", THEMES], ["My themes", customs]]) {
    const optgroup = document.createElement("optgroup"); optgroup.label = label;
    for (const name of Object.keys(group)) { const option = document.createElement("option"); option.value = name; option.textContent = name[0].toUpperCase()+name.slice(1); optgroup.append(option); }
    if (optgroup.children.length) select.append(optgroup);
  }
  let saved;
  try { saved = JSON.parse(localStorage.getItem(THEME_KEY) || "null"); } catch (_) {}
  const selected = saved?.name || "dark";
  select.value = selected;
  const colors = customs[selected] || THEMES[selected] || THEMES.dark;
  applyTheme(colors);
  document.getElementById("delete-theme").classList.toggle("hidden", !customs[selected]);
  select.onchange = () => {
    const colors = customs[select.value] || THEMES[select.value] || THEMES.dark;
    applyTheme(colors); localStorage.setItem(THEME_KEY, JSON.stringify({name:select.value}));
    document.getElementById("delete-theme").classList.toggle("hidden", !customs[select.value]);
    document.getElementById("theme-name").value = customs[select.value] ? select.value : "";
  };
  for (const name of ["bg","fg","panel","border","red"]) {
    document.getElementById("color-"+name).oninput = () => {
      const next = Object.fromEntries(["bg","fg","panel","border","red"].map(key => [key, document.getElementById("color-"+key).value]));
      applyTheme(next); localStorage.setItem(THEME_KEY, JSON.stringify({name:select.value, colors:next}));
    };
  }
  if (saved?.colors) applyTheme(saved.colors);
  document.getElementById("save-theme").onclick = () => {
    const name = document.getElementById("theme-name").value.trim();
    const message = document.getElementById("theme-message");
    if (!name) { message.textContent = "Enter a name for this theme."; return; }
    const current = readCustomThemes();
    if (Object.keys(THEMES).some(preset => preset.toLowerCase() === name.toLowerCase()) && !current[name]) { message.textContent = "Choose a name that does not match a preset."; return; }
    if (!current[name] && Object.keys(current).length >= 8) { message.textContent = "You can save up to 8 custom themes."; return; }
    current[name] = Object.fromEntries(["bg","fg","panel","border","red"].map(key => [key, document.getElementById("color-"+key).value]));
    localStorage.setItem(CUSTOM_THEMES_KEY, JSON.stringify(current));
    localStorage.setItem(THEME_KEY, JSON.stringify({name}));
    const existing = [...select.options].find(option => option.value === name);
    if (!existing) {
      let group = select.querySelector('optgroup[label="My themes"]');
      if (!group) { group=document.createElement("optgroup"); group.label="My themes"; select.append(group); }
      const option = document.createElement("option"); option.value=name; option.textContent=name; group.append(option);
    }
    select.value=name; document.getElementById("delete-theme").classList.remove("hidden"); message.textContent="Theme saved in this browser.";
  };
  document.getElementById("delete-theme").onclick = () => {
    const name=select.value, current=readCustomThemes(); if (!current[name]) return;
    delete current[name]; localStorage.setItem(CUSTOM_THEMES_KEY,JSON.stringify(current));
    localStorage.setItem(THEME_KEY,JSON.stringify({name:"dark"}));
    select.querySelectorAll("optgroup").forEach(group => [...group.options].forEach(option => { if (option.value === name) option.remove(); }));
    select.value="dark"; applyTheme(THEMES.dark); document.getElementById("delete-theme").classList.add("hidden");
    document.getElementById("theme-name").value=""; document.getElementById("theme-message").textContent="Custom theme deleted.";
  };
}

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

async function loadModelList() {
  // Model dropdown: config default + models already downloaded in Ollama
  // + a Custom entry revealing a freeform input. The hint line under the
  // field reports what the fetch found, so a silent failure is visible.
  // Preserves the current selection across refreshes.
  const sel = document.getElementById("f-model");
  const hint = document.getElementById("model-hint");
  const setHint = (t) => { if (hint) hint.textContent = t; };
  const prev = sel.value;
  sel.innerHTML = '<option value="">config default</option>';
  try {
    const r = await api("/api/ollama/models");
    if (r.ok) {
      const data = await r.json();
      const models = data.models || [];
      for (const m of models) {
        const opt = document.createElement("option");
        opt.value = m.name;
        opt.textContent = m.name + (m.size_gb ? " — " + m.size_gb + " GB" : "");
        sel.appendChild(opt);
      }
      setHint(data.available === false
        ? "Ollama is not reachable at " + (data.url || "http://localhost:11434") +
          (data.error ? " (" + data.error + ")" : "") +
          " — start the Ollama app or type a model id under Custom…"
        : models.length + " downloaded model" + (models.length === 1 ? "" : "s") + " found in Ollama");
    } else {
      setHint("Could not load the Ollama model list (server returned " + r.status + ").");
    }
  } catch (e) {
    setHint("Could not load the Ollama model list.");
  }
  const cust = document.createElement("option");
  cust.value = "__custom__";
  cust.textContent = "Custom…";
  sel.appendChild(cust);
  sel.value = [...sel.options].some(o => o.value === prev) ? prev : "";
  const wrap = document.getElementById("f-model-custom-wrap");
  if (wrap) wrap.classList.toggle("hidden", sel.value !== "__custom__");
}

document.getElementById("f-model").onchange = (e) => {
  document.getElementById("f-model-custom-wrap").classList
    .toggle("hidden", e.target.value !== "__custom__");
};

// Pull the downloaded-model list fresh whenever Ollama is chosen as the
// research backend, so the dropdown is never stale.
document.getElementById("f-provider").onchange = (e) => {
  if (e.target.value === "ollama") loadModelList();
};

// --- admin page ---
async function loadAdmin() {
  try {
    const r = await api("/api/config");
    const cfg = await r.json();
    const rb = cfg.research_backend || {}, sb = cfg.synthesis_backend || {};
    document.getElementById("admin-backends").innerHTML =
      '<div class="kv"><span>Research backend</span><strong></strong></div>' +
      '<div class="kv"><span>Synthesis backend</span><strong></strong></div>' +
      '<div class="kv"><span>Ollama URL</span><strong></strong></div>' +
      '<p class="muted small">Defaults live in config.yaml — edit the file and restart the server to change them.</p>';
    const rows = document.getElementById("admin-backends").querySelectorAll(".kv strong");
    rows[0].textContent = (rb.provider || "?") + " · " + (rb.model || "default model");
    rows[1].textContent = (sb.provider || "?") + " · " + (sb.model || "default model");
    rows[2].textContent = cfg.ollama_url || "";
    const a = cfg.auth || {};
    const pill = (on) => '<span class="badge ' + (on ? "done" : "") + '">' + (on ? "on" : "off") + "</span>";
    document.getElementById("admin-auth").innerHTML =
      '<div class="kv"><span>Google SSO</span>' + pill(a.google) + "</div>" +
      '<div class="kv"><span>OIDC SSO</span>' + pill(a.oidc) + "</div>" +
      '<div class="kv"><span>Local password</span>' + pill(a.local) + "</div>";
  } catch (e) {
    document.getElementById("admin-backends").innerHTML =
      '<p class="error">Could not load config.</p>';
  }
  loadAdminModels();
}

async function loadAdminModels() {
  const box = document.getElementById("admin-models");
  try {
    const r = await api("/api/ollama/models");
    const data = await r.json();
    if (!data.available) {
      box.innerHTML = '<p class="muted">Ollama is not reachable at ' +
        esc(data.url || "") + ".</p>";
      return;
    }
    if (!data.models.length) {
      box.innerHTML = '<p class="muted">No models downloaded yet.</p>';
      return;
    }
    let html = '<table class="models"><tr><th>Model</th><th>Size</th></tr>';
    for (const m of data.models) {
      html += "<tr><td>" + esc(m.name) + "</td><td>" +
        esc(String(m.size_gb)) + " GB</td></tr>";
    }
    box.innerHTML = html + "</table>";
  } catch (e) {
    box.innerHTML = '<p class="error">Could not reach Ollama.</p>';
  }
}

const _refreshModels = document.getElementById("refresh-models");
if (_refreshModels) _refreshModels.onclick = loadAdminModels;

async function handlePullSubmit(e) {
  e.preventDefault();
  const name = document.getElementById("pull-name").value.trim();
  const st = document.getElementById("pull-status");
  if (!name) return;
  st.textContent = "Pull started for " + name + " — this can take a while. Refresh the list when it finishes.";
  document.getElementById("pull-name").value = "";
  const r = await api("/api/ollama/pull", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name }),
  });
  const data = await r.json();
  if (!r.ok) st.textContent = data.error || "Pull failed to start.";
}
const _pullForm = document.getElementById("pull-form");
if (_pullForm) _pullForm.onsubmit = handlePullSubmit;

const TERMINAL_STATUSES = ["done", "failed", "stopped", "interrupted"];

function renderRunList(el, runs, emptyText, action) {
  if (!runs.length) { el.innerHTML = '<p class="muted">' + emptyText + "</p>"; return; }
  el.innerHTML = "";
  for (const run of runs) {
    const div = document.createElement("div");
    div.className = "run-item";
    div.innerHTML = '<span></span><span class="badge ' + esc(run.status) + '"></span>';
    div.children[0].textContent = run.org + " — " + (run.created || "").slice(0, 16).replace("T", " ");
    div.children[1].textContent = run.status;
    div.onclick = () => showRun(run.id);
    if (action === "stop" || action === "delete") {
      const btn = document.createElement("button");
      btn.className = "btn small" + (action === "stop" ? " danger" : "");
      btn.textContent = action === "stop" ? "Stop" : "Delete";
      btn.onclick = (e) => {
        e.stopPropagation();
        if (action === "stop") stopRun(run.id); else deleteRun(run.id);
      };
      div.appendChild(btn);
    }
    el.appendChild(div);
  }
}

async function stopRun(runId) {
  const r = await api("/api/runs/" + encodeURIComponent(runId) + "/stop", { method: "POST" });
  if (!r.ok) {
    const data = await r.json().catch(() => ({}));
    alert("Could not stop the run: " + (data.error || ("HTTP " + r.status)));
    return;
  }
  refreshRunLists();
}

async function deleteRun(runId) {
  if (!confirm("Delete run " + runId + " and all of its reports? This cannot be undone.")) return;
  const r = await api("/api/runs/" + encodeURIComponent(runId), { method: "DELETE" });
  if (!r.ok) {
    const data = await r.json().catch(() => ({}));
    alert("Could not delete the run: " + (data.error || ("HTTP " + r.status)));
    return;
  }
  if (watchedRunId === runId) {
    watchedRunId = null;
    if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
    document.getElementById("detail-card").classList.add("hidden");
  }
  refreshRunLists();
}

async function refreshRunLists() {
  const r = await api("/api/runs");
  const data = await r.json();
  const runs = data.runs || [];
  document.getElementById("run-count").textContent = String(runs.length).padStart(2, "0");
  const active = runs.filter(x => !TERMINAL_STATUSES.includes(x.status));
  renderRunList(document.getElementById("running-list"), active, "No scans running.", "stop");
  renderRunList(document.getElementById("run-list"),
    runs.filter(x => TERMINAL_STATUSES.includes(x.status)), "No runs yet.", "delete");
  const badge = document.getElementById("running-count");
  badge.textContent = active.length ? String(active.length) : "";
  badge.classList.toggle("hidden", !active.length);
}
// Alias kept for the run-detail poller below.
async function loadRuns() { return refreshRunLists(); }

async function loadActivity() {
  const box = document.getElementById("activity-list");
  try {
    const r = await api("/api/activity?limit=60");
    const data = await r.json();
    const state = document.getElementById("journal-state");
    const hint = document.getElementById("journal-hint");
    if (!data.enabled) {
      state.textContent = "OFFLINE";
      document.getElementById("journal-live").textContent = "● DISABLED";
      document.getElementById("journal-live").classList.add("inactive");
      hint.textContent = "Set DATABASE_URL to enable PostgreSQL";
      box.innerHTML = '<p class="empty-state">Connect a local PostgreSQL database with <code>DATABASE_URL</code> to keep a durable activity journal.</p>';
      return;
    }
    if (!r.ok) throw new Error(data.error || "Journal unavailable");
    state.textContent = "CONNECTED";
    document.getElementById("journal-live").textContent = "● CONNECTED";
    document.getElementById("journal-live").classList.remove("inactive");
    hint.textContent = data.events.length + " recent events · PostgreSQL";
    if (!data.events.length) { box.innerHTML = '<p class="empty-state">Your activity will appear here as you use Vedette.</p>'; return; }
    box.innerHTML = "";
    for (const event of data.events) {
      const row = document.createElement("div");
      row.className = "activity-row";
      const when = new Date(event.occurred_at).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" });
      const dot = document.createElement("span"); dot.className = "activity-dot";
      const main = document.createElement("div"); main.className = "activity-main";
      const title = document.createElement("strong"); title.textContent = event.action.replaceAll(".", " · ").replaceAll("_", " ");
      const sub = document.createElement("span"); sub.textContent = (event.resource || "workspace") + " · " + (event.actor || "system");
      const time = document.createElement("time"); time.textContent = when;
      main.append(title, sub); row.append(dot, main, time); box.append(row);
    }
  } catch (err) {
    document.getElementById("journal-state").textContent = "UNAVAILABLE";
    document.getElementById("journal-live").textContent = "● UNAVAILABLE";
    document.getElementById("journal-live").classList.add("inactive");
    document.getElementById("journal-hint").textContent = "Check local PostgreSQL settings";
    box.innerHTML = '<p class="empty-state">The PostgreSQL journal could not be reached. Check the local service and <code>DATABASE_URL</code>.</p>';
  }
}

document.getElementById("refresh-activity").onclick = loadActivity;

document.getElementById("logout-btn").onclick = async () => {
  await api("/auth/logout", { method: "POST" });
  window.location = "/login";
};

// --- pages ---
let currentPage = "new";
let runningTimer = null;

function showPage(name) {
  currentPage = name;
  document.querySelectorAll(".page").forEach(p =>
    p.classList.toggle("hidden", p.id !== "page-" + name));
  document.querySelectorAll(".nav-tab").forEach(b =>
    b.classList.toggle("active", b.dataset.page === name));
  if (runningTimer) { clearInterval(runningTimer); runningTimer = null; }
  if (name === "running") {
    refreshRunLists();
    runningTimer = setInterval(refreshRunLists, 3000);
  }
  else if (name === "history") { refreshRunLists(); }
  else if (name === "admin") { loadAdmin(); }
}

function placeDetail(page) {
  const slot = document.getElementById("detail-slot-" + page);
  const card = document.getElementById("detail-card");
  if (slot && card && card.parentNode !== slot) slot.appendChild(card);
}

const KNOWN_TYPES = ["company", "software", "domain", "person", "email"];

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
  const modelSel = document.getElementById("f-model").value;
  const modelCustom = document.getElementById("f-model-custom").value.trim();
  const body = {
    targets,
    default_type: defaultType,
    profile: document.getElementById("f-profile").value || "security",
    research_provider: document.getElementById("f-provider").value || null,
    research_model: modelSel === "__custom__" ? (modelCustom || null) : (modelSel || null),
  };
  const r = await api("/api/runs", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await r.json();
  if (!r.ok) { errEl.textContent = data.error || "failed to start"; return; }
  e.target.reset();
  document.getElementById("f-model-custom-wrap").classList.add("hidden");
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
  watchedRunId = runId;
  currentExport = null;
  placeDetail("running");
  if (currentPage !== "running" && currentPage !== "history") showPage("running");
  document.getElementById("detail-card").classList.remove("hidden");
  document.getElementById("detail-title").textContent = "Run " + runId;
  document.getElementById("report-tabs").innerHTML = "";
  document.getElementById("report-body").innerHTML = "";
  document.getElementById("detail-error").textContent = "";
  document.getElementById("run-target-progress").innerHTML = "";
  const _ra = document.getElementById("report-actions");
  if (_ra) _ra.classList.add("hidden");
  const _ds0 = document.getElementById("detail-stop");
  if (_ds0) _ds0.classList.remove("hidden");
  if (pollTimer) clearInterval(pollTimer);
  const poll = async () => {
    const r = await api("/api/runs/" + encodeURIComponent(runId));
    if (!r.ok) return;
    const st = await r.json();
    const terminal = TERMINAL_STATUSES.includes(st.status);
    placeDetail(terminal ? "history" : "running");
    if (terminal && currentPage === "running") showPage("history");
    renderTargetProgress(st.targets);
    const ds = document.getElementById("detail-stop");
    if (ds) ds.classList.toggle("hidden", st.status !== "running");
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
      if (st.status === "failed" || st.status === "interrupted") {
        document.getElementById("detail-error").textContent =
          (st.status === "interrupted" ? "Run interrupted: " : "Run failed: ") + (st.error || "");
      } else if (st.status === "stopped") {
        document.getElementById("detail-error").textContent = "Run stopped by operator — no report was generated.";
      } else {
        document.getElementById("detail-error").textContent = "";
      }
      loadReport(runId);
    }
    loadRuns();
  };
  await poll();
  pollTimer = setInterval(poll, 2500);
}

// --- report export: assessment brief (HTML download + print/PDF) ---
// Visual language mirrors the Converge ICT security brief: navy hero, DM
// Mono eyebrows, snapshot metrics, bottom-line + gaps cards, expandable
// research cards, evidence rows with status pills, gaps list, source trail.
function pillify(html) {
  return html.replace(/\[\s*high\s*\]/gi, '<span class="status ok">High</span>')
             .replace(/\[\s*medium\s*\]/gi, '<span class="status warn">Medium</span>')
             .replace(/\[\s*low\s*\]/gi, '<span class="status bad">Low</span>');
}

function splitSections(md) {
  // Split a report doc on ## headings; text before the first one is preamble.
  const sections = [];
  let cur = { title: null, body: [] };
  for (const line of (md || "").split("\n")) {
    const h = line.match(/^##\s+(.*)/);
    if (h) { sections.push(cur); cur = { title: h[1].trim(), body: [] }; }
    else cur.body.push(line);
  }
  sections.push(cur);
  return sections.filter(s => s.title !== null || s.body.join("").trim() !== "");
}

function parseBriefDoc(name, md) {
  const sections = splitSections(md);
  const pre = (sections.find(s => s.title === null) || { body: [] }).body.join("\n");
  const titleM = pre.match(/^#\s+(.*)/m);
  const genM = pre.match(/^Generated:\s*(.*)/mi);
  const typeM = pre.match(/^Target type:\s*(.*)/mi);
  const get = (t) => {
    const s = sections.find(x => x.title && x.title.toLowerCase() === t);
    return s ? s.body.join("\n").trim() : "";
  };
  const axes = sections
    .filter(s => s.title && /^research:/i.test(s.title))
    .map(s => ({ title: s.title.replace(/^research:\s*/i, ""),
                 body: s.body.join("\n").trim() }));
  const sources = [];
  for (const line of get("source register").split("\n")) {
    const m = line.match(/(https?:\/\/[^\s)]+)/);
    if (m) sources.push(m[1].replace(/[.,;:]+$/, ""));
  }
  const uniqSources = [...new Set(sources)];
  const meta = [];
  for (const line of get("run metadata").split("\n")) {
    const m = line.match(/^\s*[-*]\s*([^:]+):\s*(.*)/);
    if (m) meta.push([m[1].trim(), m[2].trim()]);
  }
  const lead = pre.split("\n")
    .filter(l => !/^#\s/.test(l) && !/^Generated:/i.test(l) && !/^Target type:/i.test(l))
    .join("\n").trim();
  return {
    name,
    title: (titleM ? titleM[1].trim() : name).replace(/^Vedette Assessment:\s*/i, ""),
    gen: genM ? genM[1].trim() : "",
    type: typeM ? typeM[1].trim() : "",
    identity: get("target identity"),
    brief: get("brief") || get("assessment brief"),
    axes, sources: uniqSources, meta, lead,
  };
}

function confCounts(doc) {
  const all = doc.brief + "\n" + doc.axes.map(a => a.body).join("\n");
  const c = (re) => (all.match(re) || []).length;
  return { high: c(/\[\s*high\s*\]/gi), medium: c(/\[\s*medium\s*\]/gi),
           low: c(/\[\s*low\s*\]/gi) };
}

function firstParas(md, n) {
  return (md || "").split(/\n\s*\n/).map(p => p.replace(/^#+\s+/, "").trim())
    .filter(p => p.length > 40).slice(0, n);
}

function axisSignal(body) {
  if (/\[\s*high\s*\]/i.test(body)) return ["conf-high", "High confidence"];
  if (/\[\s*medium\s*\]/i.test(body)) return ["conf-medium", "Medium confidence"];
  return ["conf-low", "Limited signal"];
}

function firstSentence(text) {
  const m = (text || "").replace(/\s+/g, " ").trim().match(/^[^.!?]+[.!?]/);
  const s = m ? m[0] : (text || "").trim().slice(0, 140);
  return s.length > 200 ? s.slice(0, 200) + "…" : s;
}

function collectGaps(doc, max) {
  const gaps = [];
  const seen = new Set();
  const push = (t) => {
    t = t.replace(/\[\s*(high|medium|low)\s*\]/gi, "").replace(/^[\s\-*>.\d.)]+/, "").trim();
    const key = t.slice(0, 60).toLowerCase();
    if (t.length > 15 && !seen.has(key)) { seen.add(key); gaps.push(t); }
  };
  const scan = (text, heuristic) => {
    for (const line of text.split("\n")) {
      if (gaps.length >= max) break;
      if (/\[\s*low\s*\]/i.test(line)) { push(line); continue; }
      if (heuristic && /^\s*[-*\d.]/.test(line) &&
          /gap|not found|no .* found|could not (be )?(found|verified|located|confirmed)|unknown|unclear|missing|unable to/i.test(line) &&
          line.trim().length > 25 && line.trim().length < 240) push(line);
    }
  };
  scan(doc.brief, false);
  for (const a of doc.axes) { if (gaps.length >= max) break; scan(a.body, gaps.length < 2); }
  return gaps;
}

function briefHero(runId, coverTitle, chips, copy) {
  return '<section class="hero">' +
    '<p class="eyebrow">Vedette assessment brief' + (chips.gen ? " · " + esc(chips.gen) : "") + "</p>" +
    "<h1>" + esc(coverTitle) + "</h1>" +
    (copy ? '<p class="hero-copy">' + esc(copy) + "</p>" : "") +
    '<div class="hero-meta">' + chips.items.map(c => "<span>" + esc(c) + "</span>").join("") + "</div>" +
    "</section>";
}

function briefSnapshot(metrics) {
  return '<section class="snapshot" aria-label="Assessment summary">' +
    metrics.map(m => '<div class="metric"><strong class="' + m.tone + '">' + m.n + "</strong><span>" + esc(m.label) + "</span></div>").join("") +
    "</section>";
}

function briefVerdictGrid(doc) {
  const verdict = firstParas(doc.brief, 1)[0] || "";
  const gaps = collectGaps(doc, 4);
  let html = '<section class="brief">';
  html += '<div class="card"><p class="eyebrow">Bottom line</p><h2>' + esc(doc.title) + "</h2>";
  html += '<div class="verdict">' + (verdict ? pillify(renderMarkdown(verdict)) : '<p class="muted">No synthesis available.</p>') + "</div></div>";
  html += '<div class="card"><p class="eyebrow">Highest-priority gaps</p>';
  if (gaps.length) {
    html += '<ul class="risk-list">' + gaps.map((g, i) =>
      "<li><b>" + (i + 1) + "</b><span>" + inline(g) + "</span></li>").join("") + "</ul>";
  } else {
    html += '<p class="muted">No material gaps flagged by the assessment.</p>';
  }
  html += "</div></section>";
  if (doc.identity && doc.identity.trim()) {
    html += '<details class="card identity"><summary>Target identity</summary>' +
      renderMarkdown(doc.identity) + "</details>";
  }
  return html;
}

function briefAxes(doc) {
  if (!doc.axes.length) return "";
  let html = '<section aria-label="Research axes"><div class="section-head"><div>' +
    '<p class="eyebrow">Axis by axis</p><h2>Research findings</h2></div>' +
    "<p>Expand a card for the full findings of each research axis.</p></div>";
  html += '<div class="question-grid">';
  doc.axes.forEach((a, i) => {
    const [cls, label] = axisSignal(a.body);
    const qid = String(i + 1).padStart(2, "0");
    html += '<article class="q"><button aria-expanded="false">' +
      '<span class="qid">' + qid + "</span>" +
      '<span class="qtitle">' + esc(a.title) + "</span>" +
      '<span class="pill ' + cls + '">' + label + "</span>" +
      '<span class="chev">+</span></button>' +
      '<div class="answer"><h3>Findings</h3>' + pillify(renderMarkdown(a.body)) + "</div></article>";
  });
  return html + "</div></section>";
}

function briefEvidence(doc) {
  if (!doc.axes.length) return "";
  let html = '<section class="evidence"><div class="section-head"><div>' +
    '<p class="eyebrow">Collection check</p><h2>What the research established</h2></div>' +
    "<p>Signal strength per axis, from the assessing model's stated confidence.</p></div>";
  for (const a of doc.axes) {
    const [cls, label] = axisSignal(a.body);
    const st = cls === "conf-high" ? ["ok", "Strong"] : cls === "conf-medium" ? ["warn", "Partial"] : ["bad", "Thin"];
    const firstLine = a.body.split("\n").map(l => l.replace(/^#+\s+/, "").trim()).find(l => l && !/^[\-*\d.)\s]*$/.test(l)) || "";
    html += '<div class="evidence-row"><h3>' + esc(a.title) + "</h3><p>" +
      esc(firstSentence(firstLine.replace(/\[\s*(high|medium|low)\s*\]/gi, ""))) +
      '</p><span class="status ' + st[0] + '">' + st[1] + "</span></div>";
  }
  return html + "</section>";
}

function briefGapsSection(doc) {
  const gaps = collectGaps(doc, 9);
  if (!gaps.length) return "";
  return '<section class="rfp"><p class="eyebrow">Next action</p><h2>Close these gaps next</h2><ol>' +
    gaps.map(g => "<li>" + inline(g) + "</li>").join("") + "</ol></section>";
}

function briefSources(sources, gen) {
  if (!sources.length) return "";
  const host = (u) => { try { return new URL(u).hostname.replace(/^www\./, ""); } catch (e) { return u; } };
  return '<section><div class="section-head"><div><p class="eyebrow">Selected sources</p><h2>Evidence trail</h2></div>' +
    "<p>" + (gen ? "Research completed " + esc(gen) + ". " : "") + "Each claim retains the caveat attached to its source.</p></div>" +
    '<ul class="source-list">' + sources.map(u =>
      '<li><a href="' + esc(u) + '" target="_blank" rel="noopener">' + esc(host(u)) + "</a></li>").join("") +
    "</ul>" +
    '<p class="method">Confidence labels reflect the assessing model\'s stated confidence in each judgment: High = well-supported by sources, Medium = partially supported, Low = thin or missing evidence. This brief is assessment output, not legal advice.</p></section>';
}

const BRIEF_CSS = [
  "@import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=Manrope:wght@400;500;600;700;800&display=swap');",
  ":root{color-scheme:light dark;--bg:#f3f5f1;--panel:#ffffff;--panel2:#e8ece6;--ink:#142018;--muted:#536159;--line:#cbd3cd;--navy:#0b2b35;--green:#0a7b57;--green2:#d9efe6;--amber:#a96708;--amber2:#fae8c6;--red:#a13a32;--red2:#f7ded9;--blue:#246e8f;--shadow:0 12px 34px rgba(9,34,29,.09);--radius:10px}",
  "@media (prefers-color-scheme:dark){:root{--bg:#0d1514;--panel:#14201e;--panel2:#1a2926;--ink:#edf4ef;--muted:#aebbb4;--line:#30413c;--navy:#b7e5e3;--green:#58d4a6;--green2:#153d31;--amber:#f0b258;--amber2:#3e2d15;--red:#f0897f;--red2:#40231f;--blue:#74bad8;--shadow:0 16px 36px rgba(0,0,0,.28)}}",
  "*{box-sizing:border-box}html{scroll-behavior:smooth}",
  "body{margin:0;background:var(--bg);color:var(--ink);font-family:Manrope,system-ui,sans-serif;line-height:1.55}",
  "a{color:inherit}button{font:inherit}",
  ".wrap{max-width:1180px;margin:auto;padding:28px 24px 70px}",
  ".hero{background:var(--navy);color:#f1faf7;padding:34px 36px 28px;border-radius:4px 4px 18px 4px;position:relative;overflow:hidden;box-shadow:var(--shadow);-webkit-print-color-adjust:exact;print-color-adjust:exact}",
  ".hero:after{content:'';position:absolute;width:350px;height:350px;border:1px solid rgba(255,255,255,.16);border-radius:50%;right:-170px;top:-190px;box-shadow:0 0 0 38px rgba(255,255,255,.035),0 0 0 76px rgba(255,255,255,.025)}",
  ".eyebrow{font:500 12px 'DM Mono',monospace;letter-spacing:.12em;text-transform:uppercase;color:#9ed9c4;margin:0 0 10px}",
  ".card .eyebrow,.rfp .eyebrow,.section-head .eyebrow{color:var(--muted)}",
  ".hero h1{font-size:clamp(30px,4.5vw,54px);line-height:.98;letter-spacing:-.055em;margin:0;max-width:820px;font-weight:800}",
  ".hero-copy{max-width:780px;color:#c9ddd6;font-size:16px;margin:18px 0 24px}",
  ".hero-meta{display:flex;gap:14px;flex-wrap:wrap;font:500 12px 'DM Mono',monospace;color:#cde4dc}",
  ".hero-meta span{padding:7px 10px;border:1px solid rgba(255,255,255,.2);border-radius:3px}",
  ".snapshot{display:grid;grid-template-columns:repeat(4,1fr);gap:1px;background:var(--line);margin:20px 0 34px;border:1px solid var(--line);box-shadow:var(--shadow)}",
  ".metric{background:var(--panel);padding:18px 20px;min-height:116px}",
  ".metric strong{font-size:31px;letter-spacing:-.05em;display:block;line-height:1.1}",
  ".metric span{display:block;color:var(--muted);font-size:12px;margin-top:7px}",
  ".metric .tone-green{color:var(--green)}.metric .tone-amber{color:var(--amber)}.metric .tone-red{color:var(--red)}",
  ".brief{display:grid;grid-template-columns:1.15fr .85fr;gap:20px;margin-bottom:38px}",
  ".card{background:var(--panel);border:1px solid var(--line);padding:24px;border-radius:var(--radius)}",
  ".card h2,.section-head h2{font-size:24px;letter-spacing:-.035em;margin:0 0 12px}",
  ".verdict{font-size:16px;line-height:1.6;margin:0;color:var(--ink)}",
  ".verdict p{margin:0}",
  ".risk-list{list-style:none;padding:0;margin:0;display:grid;gap:12px}",
  ".risk-list li{display:grid;grid-template-columns:27px 1fr;gap:10px;align-items:start}",
  ".risk-list b{font:500 12px 'DM Mono',monospace;width:25px;height:25px;display:grid;place-items:center;border-radius:50%;background:var(--red2);color:var(--red)}",
  ".risk-list span{font-size:13px;color:var(--muted)}",
  ".identity{margin:0 0 38px}.identity summary{cursor:pointer;font-weight:700}.identity pre{margin:14px 0 0}",
  ".section-head{display:flex;justify-content:space-between;gap:24px;align-items:end;margin:0 0 16px}",
  ".section-head p{margin:0;color:var(--muted);font-size:13px;max-width:580px}",
  ".pill{font:500 11px 'DM Mono',monospace;border-radius:999px;padding:5px 9px;white-space:nowrap}",
  ".pill.conf-high{background:var(--green2);color:var(--green)}.pill.conf-medium{background:var(--amber2);color:var(--amber)}.pill.conf-low{background:var(--red2);color:var(--red)}",
  ".question-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px;margin-bottom:40px}",
  ".q{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);overflow:hidden}",
  ".q button{width:100%;border:0;background:transparent;color:var(--ink);padding:18px;text-align:left;display:grid;grid-template-columns:auto 1fr auto;gap:12px;align-items:start;cursor:pointer}",
  ".qid{font:500 12px 'DM Mono',monospace;color:var(--muted);padding-top:3px}",
  ".qtitle{font-weight:700;line-height:1.35}",
  ".chev{font-size:18px;color:var(--muted);transform:rotate(0);transition:.2s}",
  ".q button[aria-expanded='true'] .chev{transform:rotate(45deg)}",
  ".answer{display:none;border-top:1px solid var(--line);padding:18px;background:var(--panel2)}",
  ".answer.show{display:block}",
  ".answer h3{font:500 11px 'DM Mono',monospace;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin:0 0 6px}",
  ".answer p{margin:0 0 12px;font-size:13px}.answer p:last-child{margin:0}",
  ".answer a,.source-list a{color:var(--blue);text-decoration-thickness:1px;text-underline-offset:3px}",
  ".answer pre{background:var(--panel);padding:12px;border-radius:6px;overflow-x:auto;font-size:12px}",
  ".answer table{width:100%;border-collapse:collapse;font-size:12px;margin:10px 0}",
  ".answer th,.answer td{border:1px solid var(--line);padding:6px 9px;text-align:left;vertical-align:top}",
  ".answer th{background:var(--panel)}",
  ".evidence{margin-bottom:38px}",
  ".evidence-row{display:grid;grid-template-columns:170px 1fr auto;gap:18px;padding:16px 0;border-bottom:1px solid var(--line);align-items:start}",
  ".evidence-row:first-of-type{border-top:1px solid var(--line)}",
  ".evidence-row h3{font-size:14px;margin:0}.evidence-row p{font-size:13px;color:var(--muted);margin:0}",
  ".status{font:500 11px 'DM Mono',monospace;border-radius:999px;padding:5px 9px;white-space:nowrap}",
  ".status.ok{color:var(--green);background:var(--green2)}.status.warn{color:var(--amber);background:var(--amber2)}.status.bad{color:var(--red);background:var(--red2)}",
  ".rfp{background:var(--panel);border:1px solid var(--line);padding:24px;margin-bottom:38px;border-radius:var(--radius)}",
  ".rfp ol{columns:2;column-gap:38px;margin:16px 0 0;padding-left:20px}.rfp li{break-inside:avoid;font-size:13px;margin:0 0 10px;padding-left:5px}",
  ".source-list{columns:2;column-gap:38px;font-size:12px;padding-left:18px;margin:0}.source-list li{break-inside:avoid;margin-bottom:9px}",
  ".method{font-size:12px;color:var(--muted);margin-top:24px;border-top:1px solid var(--line);padding-top:15px}",
  ".target-sep{border:0;border-top:2px solid var(--line);margin:44px 0}",
  ".muted{color:var(--muted)}",
  "@media(max-width:820px){.wrap{padding:16px 14px 60px}.hero{padding:26px 22px}.snapshot{grid-template-columns:repeat(2,1fr)}.brief{grid-template-columns:1fr}.question-grid{grid-template-columns:1fr}.evidence-row{grid-template-columns:1fr}.evidence-row .status{justify-self:start}.source-list{columns:1}.rfp ol{columns:1}}",
  "@media(max-width:500px){.snapshot{grid-template-columns:1fr}.metric{min-height:0}.section-head{display:block}.q button{grid-template-columns:auto 1fr}.chev{display:none}}",
  "@media print{",
  ".answer{display:block!important;border-top:1px solid var(--line)}",
  ".q button{cursor:default}.q button .chev{display:none}",
  ".brief,.question-grid{grid-template-columns:1fr}",
  ".q,.card,.evidence-row,.rfp{break-inside:avoid}",
  ".target-block{break-before:page}.target-block:first-of-type{break-before:avoid}",
  "}"
].join("\n");

const BRIEF_SCRIPT = "(function(){document.querySelectorAll('.q > button').forEach(function(btn){btn.addEventListener('click',function(){var answer=btn.nextElementSibling;var open=btn.getAttribute('aria-expanded')==='true';btn.setAttribute('aria-expanded',String(!open));answer.classList.toggle('show',!open);});});}());";

function buildReportHTML(runId, reports, comparison) {
  const names = Object.keys(reports || {});
  const docs = names.map(n => parseBriefDoc(n, reports[n]));
  const allSources = [...new Set(docs.flatMap(d => d.sources))];
  const gen = (docs[0] && docs[0].gen) || "";
  const coverTitle = docs.length === 1 ? docs[0].title : names.length + "-target assessment";
  // hero chips: type/profile/backend/sources
  const meta0 = docs.length ? docs[0].meta : [];
  const metaVal = (k) => { const m = meta0.find(x => x[0].toLowerCase() === k); return m ? m[1] : ""; };
  const backend = metaVal("research_backend").split("/").pop() || "";
  const chips = {
    gen,
    items: [docs[0] && docs[0].type, metaVal("profile"), backend,
            allSources.length + " sources"].filter(Boolean),
  };
  const verdict0 = docs.length ? firstParas(docs[0].brief, 1)[0] || "" : "";
  const heroCopy = verdict0 ? firstSentence(verdict0.replace(/\[\s*(high|medium|low)\s*\]/gi, "")) : "";
  let body = '<main class="wrap">';
  body += briefHero(runId, coverTitle, chips, heroCopy);
  docs.forEach((doc, di) => {
    const cc = confCounts(doc);
    if (docs.length > 1) {
      if (di > 0) body += '<hr class="target-sep">';
      body += '<div class="target-block"><p class="eyebrow">Target ' + (di + 1) + " of " + docs.length + "</p><h2 style=\"font-size:28px;letter-spacing:-.03em;margin:0 0 4px\">" + esc(doc.title) + "</h2>" +
        (doc.type ? '<p class="muted" style="margin:0 0 6px">' + esc(doc.type) + "</p>" : "") + "</div>";
    }
    body += briefSnapshot([
      { n: doc.axes.length, label: "research axes completed", tone: "" },
      { n: cc.high, label: "high-confidence judgments", tone: "tone-green" },
      { n: cc.medium, label: "medium-confidence judgments", tone: "tone-amber" },
      { n: cc.low, label: "low-confidence / gaps", tone: "tone-red" },
    ]);
    body += briefVerdictGrid(doc);
    body += briefAxes(doc);
    body += briefEvidence(doc);
    body += briefGapsSection(doc);
  });
  if (comparison) {
    const cd = parseBriefDoc("Comparison", comparison);
    body += '<hr class="target-sep"><section><p class="eyebrow">Cross-target comparison</p>' +
      "<h2 style=\"font-size:28px;letter-spacing:-.03em;margin:0 0 12px\">" + esc(cd.title) + "</h2>" +
      (cd.lead ? pillify(renderMarkdown(cd.lead)) : "") + "</section>";
    for (const u of cd.sources) if (!allSources.includes(u)) allSources.push(u);
  }
  body += briefSources(allSources, gen);
  body += "</main>";
  return "<!DOCTYPE html><html><head><meta charset=\"utf-8\">" +
    "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">" +
    "<title>Vedette Assessment Brief — " + esc(runId) + "</title>" +
    "<style>" + BRIEF_CSS + "</style></head><body>" + body +
    "<script>" + BRIEF_SCRIPT + "</script></body></html>";
}

function exportReportHTML() {
  if (!currentExport) return;
  const html = buildReportHTML(currentExport.runId, currentExport.reports,
                               currentExport.comparison);
  const blob = new Blob([html], { type: "text/html" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "vedette-" + currentExport.runId + "-brief.html";
  document.body.appendChild(a);
  a.click();
  setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
}

function printReport() {
  // Print / save-as-PDF via the browser's print dialog.
  if (!currentExport) return;
  const html = buildReportHTML(currentExport.runId, currentExport.reports,
                               currentExport.comparison);
  const w = window.open("", "_blank");
  if (!w) { alert("Allow pop-ups to print the report."); return; }
  w.document.write(html);
  w.document.close();
  w.focus();
  w.print();
}

async function loadReport(runId) {
  const r = await api("/api/runs/" + encodeURIComponent(runId) + "/report");
  if (!r.ok) return;
  const data = await r.json();
  currentReports = data.reports || {};
  currentExport = { runId, reports: currentReports, comparison: data.comparison || null };
  const tabs = document.getElementById("report-tabs");
  tabs.innerHTML = "";
  const names = Object.keys(currentReports);
  if (data.comparison) names.push("__comparison");
  const _ract = document.getElementById("report-actions");
  if (_ract) _ract.classList.toggle("hidden", !names.length);
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

document.querySelectorAll(".nav-tab").forEach(b => { b.onclick = () => showPage(b.dataset.page); });
const _detailStop = document.getElementById("detail-stop");
if (_detailStop) _detailStop.onclick = () => { if (watchedRunId) stopRun(watchedRunId); };
const _expH = document.getElementById("export-html");
if (_expH) _expH.onclick = exportReportHTML;
const _expP = document.getElementById("export-pdf");
if (_expP) _expP.onclick = printReport;
loadUser();
refreshRunLists();
loadActivity();
loadModelList();
initThemes();
setInterval(loadActivity, 15000);
