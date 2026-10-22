import { ParticleStudio } from "./engine.js";
import { FORM, SETTINGS } from "./config.js";

const DPR_CAP = 2;
// container: the preview frame (the canvas is position:absolute; inset:0; width/height 100%).
function mount(container, canvas, SETTINGS, FORM) {
  const studio = new ParticleStudio(canvas, { ...SETTINGS });
  // prefers-reduced-motion: calm the flow (host spec).
  if (window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
    studio.setSpeed(Math.min(SETTINGS.speed, 0.12));
  }
  const resize = () => {
    const w = container.clientWidth, h = container.clientHeight;
    if (!w || !h) return;
    studio.resize(w, h, Math.min(window.devicePixelRatio || 1, DPR_CAP)); // CSS px + dpr
  };
  resize();
  new ResizeObserver(resize).observe(container);
  // First form: particles "gather" in from a wide sphere (scale 4), morph 2.6 s.
  studio.showForm(FORM.kind, FORM.seed, "gather");
  let playing = true, last = performance.now();
  new IntersectionObserver(([e]) => { playing = e.isIntersecting; last = performance.now(); }, { threshold: 0.01 }).observe(container);
  const tick = (now) => {
    const dt = Math.min(0.05, (now - last) / 1000);
    last = now;
    if (playing) studio.renderFrame(dt);
    requestAnimationFrame(tick);
  };
  requestAnimationFrame(tick);
  // Later: new seed/archetype → studio.showForm(kind, seed, "morph");
  // count change → studio.setCount(n); studio.showForm(kind, seed, "implode").
  // prefers-reduced-motion: studio.setSpeed(Math.min(speed, 0.12)).
  return studio;
}

// Host bootstrap: brain.html calls mountBrain(container) with the #brain-canvas
// element. We create the WebGL canvas inside it (position:absolute; inset:0) and
// run the verbatim mount() with config.js' SETTINGS + FORM.
export function mountBrain(container) {
  const canvas = document.createElement("canvas");
  canvas.style.position = "absolute";
  canvas.style.inset = "0";
  canvas.style.width = "100%";
  canvas.style.height = "100%";
  canvas.style.display = "block";
  if (getComputedStyle(container).position === "static") container.style.position = "relative";
  container.appendChild(canvas);
  return mount(container, canvas, SETTINGS, FORM);
}

export { mount };
