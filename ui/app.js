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

async function loadRuns() {
  const r = await api("/api/runs");
  const data = await r.json();
  document.getElementById("run-count").textContent = String(data.runs.length).padStart(2, "0");
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
  const body = {
    targets,
    default_type: defaultType,
    profile: document.getElementById("f-profile").value || "security",
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
loadActivity();
initThemes();
setInterval(loadActivity, 15000);
