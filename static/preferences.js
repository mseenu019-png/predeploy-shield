"use strict";

const systemMotion = matchMedia("(prefers-reduced-motion: reduce)");
const preferenceFields = {
  theme: ["orbital", "stealth", "daylight"],
  motion: ["full", "subtle", "reduced"],
  density: ["engineer", "executive"],
  target: ["public_cloud", "internal_tool", "hackathon_mvp"],
  sensitivity: ["moderate_user_data", "high_auth_payments", "low_public_static"],
};
let savedPreferences = {};
try {
  const stored = JSON.parse(localStorage.getItem("shield-preferences") || "{}");
  if (stored && typeof stored === "object") savedPreferences = stored;
} catch { /* Storage can be disabled by the browser. */ }
for (const [id, values] of Object.entries(preferenceFields)) {
  if (values.includes(savedPreferences[id])) document.getElementById(id).value = savedPreferences[id];
}
document.getElementById("include-tests").checked = savedPreferences.includeTests === true;
document.getElementById("ignore").value = typeof savedPreferences.ignore === "string" ? savedPreferences.ignore.slice(0, 500) : "";

function applyPreferences(save = false) {
  const values = {};
  for (const id of Object.keys(preferenceFields)) values[id] = document.getElementById(id).value;
  values.includeTests = document.getElementById("include-tests").checked;
  values.ignore = document.getElementById("ignore").value;
  document.body.dataset.theme = values.theme;
  document.body.dataset.motion = systemMotion.matches ? "reduced" : values.motion;
  document.body.dataset.density = values.density;
  if (save) {
    try {
      localStorage.setItem("shield-preferences", JSON.stringify(values));
      document.getElementById("preferences-status").textContent = "Preferences saved on this device.";
    } catch {
      document.getElementById("preferences-status").textContent = "Preferences apply for this visit. Browser storage is unavailable.";
    }
  }
  document.dispatchEvent(new Event("shield-preferences"));
}
for (const id of [...Object.keys(preferenceFields), "include-tests", "ignore"]) {
  document.getElementById(id).addEventListener("change", () => applyPreferences(true));
}
document.getElementById("ignore").addEventListener("input", () => applyPreferences(true));
systemMotion.addEventListener("change", () => applyPreferences());
applyPreferences();

const preferenceDrawer = document.querySelector(".preferences");
preferenceDrawer.addEventListener("keydown", event => {
  if (event.key === "Escape") {
    preferenceDrawer.open = false;
    preferenceDrawer.querySelector("summary").focus();
  }
});

const orbitCanvas = document.getElementById("orbit");
const orbitContext = orbitCanvas.getContext("2d");
let orbitFrame = 0;
let lastFrame = 0;
let angle = 0;
let orbitVisible = true;
let orbitWidth = 0;
let orbitHeight = 0;
const sphereLines = [];
for (let latitude = -60; latitude <= 60; latitude += 30) {
  const points = [];
  const lat = latitude * Math.PI / 180;
  for (let step = 0; step <= 64; step++) {
    const longitude = step * Math.PI / 32;
    points.push([Math.cos(lat) * Math.cos(longitude), Math.sin(lat), Math.cos(lat) * Math.sin(longitude)]);
  }
  sphereLines.push(points);
}
for (let longitude = 0; longitude < 180; longitude += 30) {
  const points = [];
  const lon = longitude * Math.PI / 180;
  for (let step = 0; step <= 64; step++) {
    const lat = step * Math.PI / 32;
    points.push([Math.cos(lat) * Math.cos(lon), Math.sin(lat), Math.cos(lat) * Math.sin(lon)]);
  }
  sphereLines.push(points);
}
function drawOrbit() {
  if (!orbitContext) return;
  const ctx = orbitContext;
  ctx.clearRect(0, 0, orbitWidth, orbitHeight);
  const color = getComputedStyle(document.body).getPropertyValue("--orbit-color").trim();
  ctx.strokeStyle = color; ctx.fillStyle = color;
  const radius = Math.min(orbitHeight * .43, orbitWidth * .28);
  const center = orbitWidth * .76;
  const project = ([x, y, z]) => {
    const rotatedX = x * Math.cos(angle) + z * Math.sin(angle);
    const rotatedZ = z * Math.cos(angle) - x * Math.sin(angle);
    const scale = 3 / (3 - rotatedZ * .3);
    return [center + rotatedX * radius * scale, orbitHeight * .48 + y * radius * scale];
  };
  for (const points of sphereLines) {
    ctx.beginPath();
    points.forEach((point, index) => {
      const [x, y] = project(point);
      if (index === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
    });
    ctx.globalAlpha = .3; ctx.stroke();
  }
  ctx.globalAlpha = .85;
  for (let i = 0; i < 16; i++) {
    const [x, y] = project(sphereLines[i % sphereLines.length][(i * 7) % 64]);
    ctx.beginPath(); ctx.arc(x, y, 2.5, 0, Math.PI * 2); ctx.fill();
  }
  if (document.body.dataset.motion === "full") {
    ctx.globalAlpha = .4;
    for (let i = 0; i < 24; i++) {
      const x = i * 137.7 % Math.max(1, orbitWidth);
      const y = (i * 81.3 + angle * 20) % Math.max(1, orbitHeight);
      ctx.fillRect(x, y, 1.5, 1.5);
    }
  }
  ctx.globalAlpha = .65; ctx.font = "12px monospace";
  ctx.fillText("021.937.832 // SHIELD-CORE", Math.max(12, center - radius), orbitHeight - 18);
  ctx.globalAlpha = 1;
}
function animateOrbit(timestamp) {
  orbitFrame = 0;
  if (document.hidden || !orbitVisible || document.body.dataset.motion === "reduced") return;
  if (timestamp - lastFrame > 33) {
    angle += document.body.dataset.motion === "full" ? .009 : .002;
    drawOrbit(); lastFrame = timestamp;
  }
  orbitFrame = requestAnimationFrame(animateOrbit);
}
function restartOrbit() {
  cancelAnimationFrame(orbitFrame); orbitFrame = 0;
  drawOrbit();
  if (orbitContext && !document.hidden && orbitVisible && document.body.dataset.motion !== "reduced") orbitFrame = requestAnimationFrame(animateOrbit);
}
new ResizeObserver(entries => {
  const {width, height} = entries[0].contentRect;
  orbitWidth = width; orbitHeight = height;
  const ratio = Math.min(devicePixelRatio || 1, 1.5);
  orbitCanvas.width = Math.round(width * ratio); orbitCanvas.height = Math.round(height * ratio);
  if (orbitContext) orbitContext.setTransform(ratio, 0, 0, ratio, 0, 0);
  restartOrbit();
}).observe(orbitCanvas);
new IntersectionObserver(entries => { orbitVisible = entries[0].isIntersecting; restartOrbit(); }).observe(orbitCanvas);
document.addEventListener("visibilitychange", restartOrbit);
document.addEventListener("shield-preferences", restartOrbit);
for (const card of document.querySelectorAll(".card")) {
  card.addEventListener("pointermove", event => {
    if (event.pointerType !== "mouse" || document.body.dataset.motion !== "full" || card.contains(document.activeElement)) return;
    const bounds = card.getBoundingClientRect();
    const x = Math.max(-3.5, Math.min(3.5, (event.clientY - bounds.top - bounds.height / 2) / bounds.height * -7));
    const y = Math.max(-3.5, Math.min(3.5, (event.clientX - bounds.left - bounds.width / 2) / bounds.width * 7));
    card.style.transform = "perspective(1200px) rotateX(" + x + "deg) rotateY(" + y + "deg)";
  });
  const reset = () => { card.style.transform = ""; };
  card.addEventListener("pointerleave", reset);
  card.addEventListener("focusin", reset);
  document.addEventListener("shield-preferences", reset);
}
