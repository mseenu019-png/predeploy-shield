"use strict";

const scene = document.querySelector(".studio-scene");
const machine = document.querySelector(".machine");
const stageLabel = document.getElementById("stage-label");
const stageNames = {overview:"Overview", isolation:"Archive isolated", audit:"Inspecting patterns", gate:"Release decision"};
const stages = [...document.querySelectorAll(".story-stage")];
let stageFrame = 0;

function updateStage() {
  stageFrame = 0;
  const guideLine = innerHeight * .45;
  let current = stages[0];
  for (const stage of stages) {
    if (stage.getBoundingClientRect().top <= guideLine) current = stage;
  }
  scene.dataset.stage = current.dataset.stage;
  stageLabel.textContent = stageNames[current.dataset.stage];
  const atWorkspace = document.getElementById("scan-workspace").getBoundingClientRect().top < innerHeight * .6;
  for (const link of document.querySelectorAll(".step-nav a")) {
    const selected = atWorkspace ? link.hash === "#scan-workspace" : link.hash === "#" + (current.id === "deployment-gate" ? "audit" : current.id);
    if (selected) link.setAttribute("aria-current", "step"); else link.removeAttribute("aria-current");
  }
}
function queueStage() {
  if (!stageFrame) stageFrame = requestAnimationFrame(updateStage);
}
addEventListener("scroll", queueStage, {passive:true});
addEventListener("resize", queueStage);
document.addEventListener("shield-preferences", () => {
  machine.style.transform = "";
  updateStage();
});
updateStage();

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
