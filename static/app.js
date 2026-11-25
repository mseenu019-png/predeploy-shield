"use strict";

const byId = (id) => document.getElementById(id);
const form = byId("scan-form");
const tabs = [...document.querySelectorAll('[role="tab"]')];
const status = byId("status");
const result = byId("result");
let sampleFile = null;
let activeReport = null;
let selectedSeverity = "all";
let scoreFrame = 0;

function setCoreState(state) {
  document.body.dataset.state = state;
  byId("core-status").textContent = state === "scanning" ? "Shield core scanning" : state === "idle" ? "Shield core ready" : "Deployment gate · " + state;
  document.dispatchEvent(new CustomEvent("shield-state-change", { detail: { state } }));
}

function pathMatches(path, pattern) {
  // Bounded glob matching without user-controlled regular expressions.
  let position = 0, token = 0, star = -1, retry = 0;
  while (position < path.length) {
    if (pattern[token] === "?" || pattern[token] === path[position]) { position++; token++; }
    else if (pattern[token] === "*") { star = token++; retry = position; }
    else if (star >= 0) { token = star + 1; position = ++retry; }
    else return false;
  }
  while (pattern[token] === "*") token++;
  return token === pattern.length;
}

function updateFindingVisibility() {
  const patterns = byId("ignore").value.split(",").map(p => p.trim()).filter(Boolean).slice(0, 30);
  let hiddenByPath = 0, visible = 0;
  for (const card of result.querySelectorAll(".finding")) {
    const ignored = patterns.some(pattern => pathMatches(card.dataset.path, pattern));
    if (ignored) hiddenByPath++;
    card.hidden = ignored || (selectedSeverity !== "all" && card.dataset.severity !== selectedSeverity);
    if (!card.hidden) visible++;
  }
  const note = byId("filter-note");
  if (note) note.textContent = visible + " findings shown · " + hiddenByPath + " hidden by path preferences. Verdict and export cover the full scan.";
}
document.addEventListener("shield-preferences", () => {
  updateFindingVisibility();
  if (document.body.dataset.motion === "reduced") {
    cancelAnimationFrame(scoreFrame);
    const score = result.querySelector(".score-value");
    if (score && activeReport) score.textContent = activeReport.risk_score;
  }
});

function activate(tab) {
  for (const item of tabs) {
    const active = item === tab;
    item.setAttribute("aria-selected", String(active));
    item.tabIndex = active ? 0 : -1;
    const panel = byId(item.getAttribute("aria-controls"));
    panel.hidden = !active;
    panel.querySelector("input").disabled = !active;
  }
}

for (const tab of tabs) {
  tab.addEventListener("click", () => activate(tab));
  tab.addEventListener("keydown", (event) => {
    const next = {
      Home: tabs[0], End: tabs.at(-1),
      ArrowLeft: tabs[1 - tabs.indexOf(tab)], ArrowRight: tabs[1 - tabs.indexOf(tab)],
    }[event.key];
    if (next) {
      event.preventDefault();
      activate(next);
      next.focus();
    }
  });
}

function add(parent, tag, text, className) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  element.textContent = text;
  parent.append(element);
  return element;
}

function render(report) {
  activeReport = report;
  selectedSeverity = "all";
  setCoreState(report.verdict);
  const verdict = add(result, "div", "", "verdict");
  const namespace = "http://www.w3.org/2000/svg";
  const gauge = document.createElementNS(namespace, "svg");
  gauge.setAttribute("viewBox", "0 0 120 120");
  gauge.setAttribute("class", "gauge");
  gauge.setAttribute("role", "img");
  gauge.setAttribute("aria-label", "Risk score " + report.risk_score + " out of 100");
  for (const progress of [false, true]) {
    const circle = document.createElementNS(namespace, "circle");
    for (const [key, value] of Object.entries({cx:60, cy:60, r:52})) circle.setAttribute(key, value);
    if (progress) {
      circle.setAttribute("class", "progress");
      circle.setAttribute("stroke-dasharray", (report.risk_score / 100 * 327) + " 327");
    }
    gauge.append(circle);
  }
  const score = document.createElementNS(namespace, "text");
  score.setAttribute("x", "60"); score.setAttribute("y", "63");
  score.setAttribute("class", "score-value");
  score.textContent = report.risk_score;
  cancelAnimationFrame(scoreFrame);
  if (document.body.dataset.motion !== "reduced") {
    const start = performance.now();
    const tick = now => {
      const progress = Math.min(1, (now - start) / 650);
      score.textContent = Math.round(report.risk_score * progress);
      if (progress < 1 && score.isConnected && !document.hidden) scoreFrame = requestAnimationFrame(tick);
      else score.textContent = report.risk_score;
    };
    scoreFrame = requestAnimationFrame(tick);
  }
  gauge.append(score);
  const caption = document.createElementNS(namespace, "text");
  caption.setAttribute("x", "60"); caption.setAttribute("y", "80");
  caption.setAttribute("class", "gauge-label"); caption.textContent = "RISK / 100";
  gauge.append(caption);
  verdict.append(gauge);
  add(verdict, "span", ({BLOCK:"BLOCKED FOR PROD", WARN:"WARN", PASS:"APPROVED"})[report.verdict], "badge " + report.verdict.toLowerCase());

  add(result, "p", report.executive_summary, "summary");
  const mode = report.analysis_mode === "gemini_assisted" ? "Gemini-assisted checklist" : "Deterministic analysis";
  const coverage = report.coverage;
  add(result, "p", `${coverage.scanned_files} files scanned · ${coverage.skipped_files} skipped · ${mode}`, "coverage");

  const counts = Object.fromEntries(["critical", "high", "medium", "low"].map(level => [level, report.findings.filter(f => f.severity === level).length]));
  add(result, "p", Object.entries(counts).map(([level, count]) => level.toUpperCase() + " " + count).join(" · "), "severity-strip");
  const exportButton = add(result, "button", "Export report (.md)", "secondary");
  exportButton.type = "button";
  exportButton.addEventListener("click", () => exportReport(report));
  add(result, "h3", "Top fixes");
  const fixes = add(result, "ul", "");
  for (const fix of [...new Set(report.findings.map(f => f.remediation))].slice(0, 3)) add(fixes, "li", fix);
  const telemetry = add(result, "details", "", "engineer-only");
  add(telemetry, "summary", "Scan telemetry");
  add(telemetry, "pre", JSON.stringify({coverage:report.coverage, analysis_mode:report.analysis_mode}, null, 2));
  add(result, "h3", "Findings");
  const note = add(result, "p", "", "hint");
  note.id = "filter-note";
  const filters = add(result, "div", "", "filters");
  filters.setAttribute("role", "group");
  filters.setAttribute("aria-label", "Filter findings by severity");
  const findingList = add(result, "div", "");
  for (const level of ["all", "critical", "high", "medium", "low"]) {
    const filter = add(filters, "button", level[0].toUpperCase() + level.slice(1));
    filter.type = "button";
    filter.setAttribute("aria-pressed", String(level === "all"));
    filter.addEventListener("click", () => {
      for (const button of filters.children) button.setAttribute("aria-pressed", String(button === filter));
      selectedSeverity = level;
      updateFindingVisibility();
      status.textContent = level === "all" ? "Showing all findings." : "Showing " + counts[level] + " " + level + " findings.";
    });
  }
  if (report.findings.length === 0) add(result, "p", "No findings in the inspected files.");
  for (const finding of report.findings) {
    const details = add(findingList, "details", "", "finding");
    details.dataset.severity = finding.severity;
    details.dataset.path = finding.file;
    const heading = add(details, "summary", "");
    add(heading, "span", finding.severity, "badge " + finding.severity);
    add(heading, "span", " " + finding.rule_id);
    add(heading, "span", " · " + finding.file + ":" + finding.line, "engineer-only");
    add(details, "p", finding.category, "engineer-only");
    add(details, "p", finding.exploit_scenario);
    add(details, "p", finding.remediation);
    if (finding.snippet) {
      const excerpt = add(details, "pre", "", "engineer-only");
      add(excerpt, "code", finding.snippet, "diff-line diff-remove");
    }
    if (finding.remediation_diff) {
      const block = add(details, "pre", "", "engineer-only");
      for (const line of finding.remediation_diff.split("\n")) {
        add(block, "code", line, "diff-line " + (line.startsWith("-") ? "diff-remove" : line.startsWith("+") ? "diff-add" : ""));
      }
      const copy = add(details, "button", "Copy fix", "secondary engineer-only");
      copy.type = "button";
      copy.addEventListener("click", async () => {
        try { await navigator.clipboard.writeText(finding.remediation_diff); status.textContent = "Fix copied. Review before applying."; }
        catch { status.textContent = "Clipboard unavailable. Select and copy the patch text."; }
      });
    }
  }

  add(result, "h3", "Day-one hardening");
  const checklist = add(result, "ul", "");
  for (const item of report.day1_hardening_checklist) add(checklist, "li", item);
  result.hidden = false;
  updateFindingVisibility();
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const upload = byId("zip-tab").getAttribute("aria-selected") === "true";
  const button = byId("submit");
  activeReport = null;
  cancelAnimationFrame(scoreFrame);
  result.replaceChildren();
  result.hidden = true;
  status.classList.remove("error");
  byId("empty").hidden = true;

  if (upload && !sampleFile && byId("file").files[0]?.size > 5_000_000) {
    status.classList.add("error");
    status.textContent = "Your ZIP exceeds the 5 MB limit.";
    return;
  }

  const fields = new FormData(form);
  if (upload && sampleFile) fields.set("file", sampleFile);
  const options = { method: "POST", body: fields, signal: AbortSignal.timeout(60_000) };
  if (!upload) {
    options.headers = { "Content-Type": "application/json" };
    options.body = JSON.stringify(Object.fromEntries(fields));
  }
  button.disabled = true;
  byId("sample").disabled = true;
  setCoreState("scanning");
  status.textContent = "Scan in progress…";
  try {
    const response = await fetch("/api/scan/" + (upload ? "zip" : "github"), options);
    const payload = await response.json().catch(() => null);
    if (!response.ok) throw new Error(payload?.detail || "Scan failed. Try again shortly.");
    render(payload);
    status.textContent = `Scan complete. ${payload.verdict}. ${payload.findings.length} findings.`;
  } catch (error) {
    setCoreState("idle");
    status.classList.add("error");
    status.textContent = error.name === "TimeoutError" ? "The scan timed out. Try again shortly." : error.message;
  } finally {
    button.disabled = false;
    byId("sample").disabled = false;
  }
});


function exportReport(report) {
  const escape = value => String(value).replace(/[\\`*_{}[\]<>#|]/g, "\\$&");
  const lines = ["# PreDeploy Shield audit", "", report.verdict + " · " + report.risk_score + "/100", "", report.executive_summary,
    "", "Mode · " + report.analysis_mode, "", "Scanned files · " + report.coverage.scanned_files,
    "", "Skipped files · " + report.coverage.skipped_files, "", "Tests included · " + Boolean(report.coverage.include_tests)];
  for (const finding of report.findings) {
    lines.push("", "## " + escape(finding.severity + " · " + finding.rule_id),
      "", escape(finding.file) + " · line " + finding.line, "", escape(finding.exploit_scenario), "", escape(finding.remediation));
    if (finding.remediation_diff) lines.push("", ...finding.remediation_diff.split("\n").map(line => "    " + line));
  }
  lines.push("", "## Day-one hardening", "", ...report.day1_hardening_checklist.map(item => "- " + escape(item)));
  const url = URL.createObjectURL(new Blob([lines.join("\n")], {type:"text/markdown;charset=utf-8"}));
  const link = document.createElement("a");
  link.href = url; link.download = "predeploy-shield-report.md"; link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

byId("sample").addEventListener("click", async () => {
  byId("sample").disabled = true;
  try {
    const response = await fetch("/api/sample");
    if (!response.ok) throw new Error("Sample unavailable.");
    sampleFile = new File([await response.blob()], "sample-vulnerable.zip", {type:"application/zip"});
    byId("file").required = false;
    document.dispatchEvent(new CustomEvent("shield-file-selected", { detail: { file: sampleFile } }));
    status.textContent = "Sample vulnerable project loaded. Run security scan to inspect it.";
  } catch (error) { status.textContent = error.message; }
  finally { byId("sample").disabled = false; }
});
byId("file").addEventListener("change", () => {
  sampleFile = null;
  byId("file").required = true;
  const picked = byId("file").files[0] || null;
  document.dispatchEvent(new CustomEvent("shield-file-selected", { detail: { file: picked } }));
});
