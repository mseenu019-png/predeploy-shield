"use strict";

const scene = document.querySelector(".studio-scene");
const machine = document.querySelector(".machine");
const coreGlyph = document.querySelector(".machine-core span");
const stageLabel = document.getElementById("stage-label");
const progressBar = document.getElementById("scroll-progress-bar");
const telemetryEngine = document.getElementById("telemetry-engine");
const telemetryExecution = document.getElementById("telemetry-execution");
const telemetryCoverage = document.getElementById("telemetry-coverage");
const telemetryGate = document.getElementById("telemetry-gate");
const coreStatus = document.getElementById("core-status");
const simButtons = [...document.querySelectorAll(".sim-pill")];

const stageNames = {
  overview: "Overview",
  isolation: "Archive isolated",
  audit: "Inspecting patterns",
  gate: "Release decision",
};
const stageTelemetry = {
  overview: { engine: "Hybrid Static + AI", execution: "Zero-run isolation", coverage: "Secrets · CWE · Cloud config", gate: "BLOCK / WARN / PASS" },
  isolation: { engine: "Zip Slip Guard", execution: "5 MB / 50-file cap", coverage: "Text-only · No imports", gate: "Sandbox ready" },
  audit: { engine: "Static + Gemini", execution: "Rule IDs + Context", coverage: "Keys · SQLi · XSS · Docker", gate: "Risk-weighted" },
  gate: { engine: "Deterministic Gate", execution: "Unified Code Diffs", coverage: "Findings + Day-1 Checklist", gate: "BLOCK / WARN / PASS" },
};
const simPresets = {
  clean: { state: "PASS", glyph: "✓", label: "0 / PASS", status: "Simulated · 0 / PASS — Clean Repo", gate: "0 / PASS" },
  warn: { state: "WARN", glyph: "!", label: "62 / WARN", status: "Simulated · 62 / WARN — Leaked Key intercepted", gate: "62 / WARN" },
  block: { state: "BLOCK", glyph: "✕", label: "94 / BLOCK", status: "Simulated · 94 / BLOCK — Critical Exploit locked out", gate: "94 / BLOCK" },
};

const stages = [...document.querySelectorAll(".story-stage")];
let activeSim = null;
let scrollFrame = 0;

function applyStage(stageEl) {
  if (!stageEl) return;
  const key = stageEl.dataset.stage;
  scene.dataset.stage = key;
  for (const s of stages) s.classList.toggle("is-active", s === stageEl);
  if (!activeSim) {
    stageLabel.textContent = stageNames[key];
    const t = stageTelemetry[key];
    if (t && telemetryEngine) {
      telemetryEngine.textContent = t.engine;
      telemetryExecution.textContent = t.execution;
      telemetryCoverage.textContent = t.coverage;
      telemetryGate.textContent = t.gate;
    }
  }
  const atWorkspace = document.getElementById("scan-workspace").getBoundingClientRect().top < innerHeight * .6;
  for (const link of document.querySelectorAll(".step-nav a")) {
    const selected = atWorkspace ? link.hash === "#scan-workspace" : link.hash === "#" + (stageEl.id === "deployment-gate" ? "audit" : stageEl.id);
    if (selected) link.setAttribute("aria-current", "step"); else link.removeAttribute("aria-current");
  }
}

const stageObserver = new IntersectionObserver(entries => {
  const visible = entries.filter(e => e.isIntersecting).sort((a, b) => b.intersectionRatio - a.intersectionRatio);
  if (visible.length) applyStage(visible[0].target);
}, { rootMargin: "-25% 0px -45% 0px", threshold: [0.1, 0.35, 0.6] });
for (const stage of stages) stageObserver.observe(stage);

function updateScrollProgress() {
  scrollFrame = 0;
  const maxScroll = Math.max(1, document.documentElement.scrollHeight - innerHeight);
  const ratio = Math.min(1, Math.max(0, scrollY / maxScroll));
  if (progressBar) progressBar.style.setProperty("--scroll-progress", ratio.toFixed(4));
  const atWorkspace = document.getElementById("scan-workspace").getBoundingClientRect().top < innerHeight * .6;
  if (atWorkspace) {
    for (const link of document.querySelectorAll(".step-nav a")) {
      if (link.hash === "#scan-workspace") link.setAttribute("aria-current", "step");
      else link.removeAttribute("aria-current");
    }
  }
}
function queueScroll() {
  if (!scrollFrame) scrollFrame = requestAnimationFrame(updateScrollProgress);
}
addEventListener("scroll", queueScroll, { passive: true });
addEventListener("resize", queueScroll);
updateScrollProgress();
applyStage(stages[0]);

function clearSimulation() {
  activeSim = null;
  delete scene.dataset.sim;
  if (coreGlyph) coreGlyph.textContent = "✓";
  for (const btn of simButtons) btn.setAttribute("aria-pressed", "false");
}

for (const btn of simButtons) {
  btn.addEventListener("click", () => {
    const key = btn.dataset.sim;
    const preset = simPresets[key];
    if (!preset) return;
    activeSim = key;
    scene.dataset.sim = key;
    document.body.dataset.state = preset.state;
    if (coreGlyph) coreGlyph.textContent = preset.glyph;
    if (stageLabel) stageLabel.textContent = preset.label;
    if (telemetryGate) telemetryGate.textContent = preset.gate;
    if (coreStatus) coreStatus.textContent = preset.status;
    for (const item of simButtons) item.setAttribute("aria-pressed", String(item === btn));
  });
}

document.addEventListener("shield-state-change", event => {
  if (event.detail?.state) clearSimulation();
});

document.addEventListener("shield-preferences", () => {
  machine.style.transform = "";
  for (const el of document.querySelectorAll(".studio-action, .primary, .sim-pill")) el.style.transform = "";
  updateScrollProgress();
});

for (const link of document.querySelectorAll('a[href^="#"]')) {
  link.addEventListener("click", event => {
    const target = document.getElementById(link.hash.slice(1));
    if (!target) return;
    event.preventDefault();
    target.focus({preventScroll:true});
    target.scrollIntoView({behavior:document.body.dataset.motion === "reduced" ? "instant" : "smooth", block:"start"});
    history.replaceState(null, "", link.hash);
    if (target.id === "scan-workspace") spotlightWorkspace();
  });
}
scene.addEventListener("pointermove", event => {
  if (event.pointerType !== "mouse" || document.body.dataset.motion !== "full") return;
  const bounds = scene.getBoundingClientRect();
  const x = (event.clientY - bounds.top) / bounds.height - .5;
  const y = (event.clientX - bounds.left) / bounds.width - .5;
  machine.style.transform = "rotateX(" + (-x * 10) + "deg) rotateY(" + (y * 16) + "deg)";
});
scene.addEventListener("pointerleave", () => { machine.style.transform = ""; });

let spotlightSeen = false;
try { spotlightSeen = localStorage.getItem("shield-workspace-seen") === "true"; } catch {}
let spotlightTimer = 0;
function spotlightWorkspace() {
  if (spotlightSeen) return;
  spotlightSeen = true;
  try { localStorage.setItem("shield-workspace-seen", "true"); } catch {}
  const workspace = document.getElementById("scan-workspace");
  workspace.classList.add("arrival");
  document.getElementById("status").textContent = "Start with a project ZIP, a public GitHub URL, or load the sample vulnerable project.";
  spotlightTimer = setTimeout(() => workspace.classList.remove("arrival"), 4500);
}
const arrivalObserver = new IntersectionObserver(entries => {
  if (entries.some(entry => entry.isIntersecting)) {
    spotlightWorkspace();
    arrivalObserver.disconnect();
  }
}, {threshold:.15});
arrivalObserver.observe(document.querySelector(".setup"));
document.addEventListener("visibilitychange", () => {
  document.body.classList.toggle("page-hidden", document.hidden);
});

/* Tactile drag-and-drop dropzone with file metadata preview */
const dropzone = document.getElementById("zip-panel");
const fileInput = document.getElementById("file");
const fileMeta = document.getElementById("file-meta");

function formatBytes(bytes) {
  if (bytes >= 1_000_000) return (bytes / 1_000_000).toFixed(2) + " MB";
  return Math.max(0.1, bytes / 1000).toFixed(1) + " KB";
}
function showFileMeta(file) {
  if (!fileMeta) return;
  if (!file) { fileMeta.hidden = true; fileMeta.textContent = ""; return; }
  fileMeta.textContent = file.name + " · " + formatBytes(file.size);
  fileMeta.hidden = false;
}
document.addEventListener("shield-file-selected", event => showFileMeta(event.detail?.file || null));

if (dropzone && fileInput) {
  let dragDepth = 0;
  for (const type of ["dragenter", "dragover"]) {
    dropzone.addEventListener(type, event => {
      event.preventDefault();
      if (type === "dragenter") dragDepth++;
      dropzone.classList.add("is-dragover");
    });
  }
  dropzone.addEventListener("dragleave", () => {
    dragDepth = Math.max(0, dragDepth - 1);
    if (dragDepth === 0) dropzone.classList.remove("is-dragover");
  });
  dropzone.addEventListener("drop", event => {
    event.preventDefault();
    dragDepth = 0;
    dropzone.classList.remove("is-dragover");
    const dropped = event.dataTransfer?.files?.[0];
    if (!dropped) return;
    if (!dropped.name.toLowerCase().endsWith(".zip")) {
      const statusEl = document.getElementById("status");
      if (statusEl) { statusEl.classList.add("error"); statusEl.textContent = "Please drop a .zip archive."; }
      return;
    }
    const transfer = new DataTransfer();
    transfer.items.add(dropped);
    fileInput.files = transfer.files;
    fileInput.dispatchEvent(new Event("change", { bubbles: true }));
  });
  dropzone.addEventListener("keydown", event => {
    if (event.target === dropzone && (event.key === "Enter" || event.key === " ")) {
      event.preventDefault();
      fileInput.click();
    }
  });
}

/* Magnetic hover pull (±3px) on primary pill buttons */
const reduceMotionQuery = matchMedia("(prefers-reduced-motion: reduce)");
for (const pill of document.querySelectorAll(".studio-action, .primary, .sim-pill")) {
  pill.addEventListener("pointermove", event => {
    if (event.pointerType !== "mouse" || document.body.dataset.motion === "reduced" || reduceMotionQuery.matches) return;
    const rect = pill.getBoundingClientRect();
    const dx = Math.max(-3, Math.min(3, ((event.clientX - rect.left) / rect.width - 0.5) * 6));
    const dy = Math.max(-3, Math.min(3, ((event.clientY - rect.top) / rect.height - 0.5) * 6));
    pill.style.transform = `translate3d(${dx.toFixed(2)}px, ${dy.toFixed(2)}px, 0)`;
  });
  pill.addEventListener("pointerleave", () => { pill.style.transform = ""; });
  pill.addEventListener("blur", () => { pill.style.transform = ""; });
}
