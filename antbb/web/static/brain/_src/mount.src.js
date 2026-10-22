import { ParticleStudio } from "./engine";

const DPR_CAP = 2;
// container: the preview frame (the canvas is position:absolute; inset:0; width/height 100%).
function mount(container, canvas, SETTINGS, FORM) {
  const studio = new ParticleStudio(canvas, { ...SETTINGS });
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
}
