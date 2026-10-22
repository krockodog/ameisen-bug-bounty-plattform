/* antbb – Additiver 3D-Sprite-Layer (Three.js, self-hosted ESM).
 * Transparenter WebGL-Canvas HINTER dem 2D-Canvas und ÜBER der gemalten Bühne
 * (antmap_colony.js zeichnet das Nest-Artwork + die fremde Ausgrabung).
 * Dieser Layer zeigt NUR die vom Nutzer gestalteten Charaktere als Billboard-
 * Sprites an den von antmap.js berechneten Anker-Positionen (Königin = Thron,
 * jeder Agent = seine Kammer). KEIN schwebender Hügel, KEINE Scope-Amöbe, keine
 * Bodentextur mehr – die Bühne liegt darunter. Harter 2D-Fallback bleibt.
 */
import * as THREE from 'three';

(function () {
  "use strict";

  function webgl2ok() {
    try {
      const c = document.createElement('canvas');
      return !!(window.WebGL2RenderingContext && c.getContext('webgl2'));
    } catch (e) { return false; }
  }
  const REDUCED = window.matchMedia &&
    window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const CORES = navigator.hardwareConcurrency || 8;
  const MEM = navigator.deviceMemory || 8;
  const LOWEND = CORES < 4 || MEM < 2;
  const FORCE2D = /[?&]no3d\b/.test(location.search) ||
                  /[?&]force2d\b/.test(location.search);

  if (FORCE2D || !webgl2ok() || REDUCED || LOWEND) {
    window.__antmap3d = { active: false, reason:
      FORCE2D ? 'force2d' : (!webgl2ok() ? 'no-webgl2'
        : (REDUCED ? 'reduced-motion' : 'low-end')) };
    try { console.info('[antmap3d] 2D-Fallback:', window.__antmap3d.reason); } catch (e) {}
    return;
  }

  const wrap = document.getElementById('antmap-wrap');
  const canvas = document.getElementById('antmap-3d');
  if (!wrap || !canvas || !(window.AntMap && window.AntMap.getSnapshot)) {
    window.__antmap3d = { active: false, reason: 'no-bridge' };
    return;
  }

  const renderer = new THREE.WebGLRenderer({ canvas: canvas, alpha: true,
    antialias: true, powerPreference: 'high-performance' });
  renderer.setClearColor(0x000000, 0);
  const DPR = Math.min(window.devicePixelRatio || 1, 2);
  renderer.setPixelRatio(DPR);
  if ('outputColorSpace' in renderer) renderer.outputColorSpace = THREE.SRGBColorSpace;

  const scene = new THREE.Scene();
  let camera = new THREE.OrthographicCamera(-400, 400, 300, -300, -2000, 4000);
  function placeCamera() {
    camera.position.set(0, 1000, 150);
    camera.up.set(0, 0, -1);
    camera.lookAt(0, 0, 0);
  }
  placeCamera();
  scene.add(new THREE.AmbientLight(0xffffff, 1.0));

  const STATECOL = {
    idle: 0x6a5a40, running: 0xffcf7a, done: 0xffe4a8, blocked: 0xff4d6a
  };

  const SPRITE = {
    queen:       'queen_tq.png',
    worker:      'worker_tq.png',
    soldier_off: 'soldier_off_tq.png',
    soldier_def: 'soldier_def_tq.png',
    scout:       'scout_tq.png'
  };
  const texLoader = new THREE.TextureLoader();
  const texCache = {};
  function getTex(key) {
    if (texCache[key]) return texCache[key];
    const t = texLoader.load('/static/sprites/' + SPRITE[key]);
    if ('colorSpace' in t) t.colorSpace = THREE.SRGBColorSpace;
    t.anisotropy = 4;
    texCache[key] = t;
    return t;
  }

  function makeGlowTex() {
    const c = document.createElement('canvas'); c.width = c.height = 128;
    const g = c.getContext('2d');
    const grd = g.createRadialGradient(64, 64, 2, 64, 64, 64);
    grd.addColorStop(0.0, 'rgba(255,255,255,1)');
    grd.addColorStop(0.35, 'rgba(255,255,255,0.42)');
    grd.addColorStop(1.0, 'rgba(255,255,255,0)');
    g.fillStyle = grd; g.fillRect(0, 0, 128, 128);
    const t = new THREE.CanvasTexture(c);
    if ('colorSpace' in t) t.colorSpace = THREE.SRGBColorSpace;
    return t;
  }
  const GLOW = makeGlowTex();

  // Figur = Zustands-Glow (hinten) + Kontakt-Schatten (unten) + Sprite (vorne).
  function makeFigure(key, height) {
    const grp = new THREE.Group();
    // weicher Kontakt-Schatten, damit die Figur in der Kammer "sitzt"
    const shadow = new THREE.Sprite(new THREE.SpriteMaterial({ map: GLOW,
      color: 0x000000, transparent: true, opacity: 0.38, depthTest: false,
      depthWrite: false, blending: THREE.NormalBlending }));
    shadow.center.set(0.5, 0.5); shadow.renderOrder = 0;
    grp.add(shadow);

    const glowMat = new THREE.SpriteMaterial({ map: GLOW, color: STATECOL.idle,
      transparent: true, opacity: 0.0, depthTest: false, depthWrite: false,
      blending: THREE.AdditiveBlending });
    const glow = new THREE.Sprite(glowMat); glow.renderOrder = 1;
    glow.center.set(0.5, 0.60);
    grp.add(glow);

    const mat = new THREE.SpriteMaterial({ map: getTex(key), color: 0xffffff,
      transparent: true, depthTest: false, depthWrite: false });
    const spr = new THREE.Sprite(mat); spr.renderOrder = 2;
    spr.center.set(0.5, 0.06);
    grp.add(spr);

    grp.userData = { glow: glow, glowMat: glowMat, spr: spr, mat: mat,
      shadow: shadow, height: height, aspect: 0.58 };
    return grp;
  }

  function sizeFigure(grp) {
    const m = grp.userData.mat.map;
    if (m && m.image && m.image.width) {
      grp.userData.aspect = m.image.width / m.image.height;
    }
    const h = grp.userData.height * FIGSCALE, a = grp.userData.aspect;
    grp.userData.spr.scale.set(h * a, h, 1);
    const gh = h * 0.70;
    grp.userData.glow.scale.set(gh * Math.max(a, 0.5), gh, 1);
    grp.userData.shadow.scale.set(h * a * 0.9, h * 0.34, 1);
  }

  function applyFigState(grp, state, t, opts) {
    opts = opts || {};
    const running = state === 'running';
    const ud = grp.userData;
    const tint = state === 'idle' ? new THREE.Color(0xd9cfbc)
                                   : new THREE.Color(0xffffff);
    ud.mat.color.lerp(tint, 0.10);
    const tgtOp = state === 'idle' ? 0.96 : 1.0;
    ud.mat.opacity += (tgtOp - ud.mat.opacity) * 0.15;
    ud.glowMat.color.lerp(new THREE.Color(STATECOL[state] || STATECOL.idle), 0.2);
    let base = state === 'idle' ? 0.05 : (state === 'done' ? 0.20 : 0.55);
    let pulse = running ? (0.25 + 0.25 * Math.sin(t * (opts.cmd ? 6.0 : 3.2))) : 0;
    const tgt = base + pulse + (opts.extra || 0);
    ud.glowMat.opacity += (tgt - ud.glowMat.opacity) * 0.2;
  }

  // ---- Instanzen ----------------------------------------------------------
  const queen = makeFigure('queen', 132); scene.add(queen);
  const ants = {};
  const masters = {};
  function ensureAnt(id) {
    if (ants[id]) return ants[id];
    const g = makeFigure('worker', 64); scene.add(g); ants[id] = g; return g;
  }
  function ensureMaster(id, mrole) {
    if (masters[id]) return masters[id];
    let key = mrole === 'scout' ? 'scout'
            : (mrole === 'off' ? 'soldier_off' : 'soldier_def');
    const g = makeFigure(key, mrole === 'scout' ? 80 : 86);
    scene.add(g); masters[id] = { grp: g, mrole: mrole }; return masters[id];
  }

  let W = 800, H = 420, FIGSCALE = 1;
  function toWorld(x, y) { return { x: x - W / 2, z: y - H / 2 }; }
  function resize(snap) {
    W = snap.W || wrap.clientWidth; H = snap.H || Math.round(W * 0.52);
    canvas.style.width = W + 'px'; canvas.style.height = H + 'px';
    renderer.setSize(W, H, false);
    camera.left = -W / 2; camera.right = W / 2;
    camera.top = H / 2; camera.bottom = -H / 2;
    camera.updateProjectionMatrix();
  }
  function place(grp, node, baseY, bob) {
    const w = toWorld(node.x, node.y);
    grp.position.x = w.x; grp.position.z = w.z;
    grp.position.y = (baseY || 0) + (bob || 0);
    sizeFigure(grp);
  }

  let lastW = 0, lastH = 0;
  function tick() {
    const snap = window.AntMap.getSnapshot();
    if (snap) {
      if (snap.W !== lastW || snap.H !== lastH) { resize(snap); lastW = snap.W; lastH = snap.H; }
      const t = snap.t || 0;
      FIGSCALE = snap.narrow ? 0.52 : 1;

      if (snap.queen) {
        const cmd = !!snap.queen.commanding;
        place(queen, snap.queen, 0, REDUCED ? 0 : Math.sin(t * 1.2) * 1.5);
        applyFigState(queen, cmd ? 'running' : 'idle', t, { cmd: cmd, extra: 0.2 });
      }
      if (snap.ants) {
        snap.ants.forEach((a, i) => {
          const g = ensureAnt(a.id);
          place(g, a, 0, REDUCED ? 0 : Math.sin(t * 2.2 + i) * 1.0);
          applyFigState(g, a.state || 'idle', t,
            { cmd: !!a.commanding, extra: a.commanding ? 0.15 : 0 });
        });
      }
      if (snap.masters) {
        snap.masters.forEach(m => {
          const rec = ensureMaster(m.id, m.mrole);
          const g = rec.grp;
          place(g, m, 0, REDUCED ? 0 : Math.sin(t * 2.4 + (m.mrole === 'scout' ? 1 : 0)) * 1.2);
          let st = 'idle';
          if (m.mrole === 'scout') st = m.out ? 'running' : 'idle';
          else if (m.mrole === 'off') st = m.out ? 'running' : 'idle';
          else st = 'done';
          applyFigState(g, st, t, { extra: m.out ? 0.2 : 0 });
        });
      }
    }
    renderer.render(scene, camera);
    requestAnimationFrame(tick);
  }

  window.__antmap3d = { active: true, scene: scene, mode: 'sprites' };
  const first = window.AntMap.getSnapshot();
  if (first) { resize(first); lastW = first.W; lastH = first.H; }
  requestAnimationFrame(tick);
  try { console.info('[antmap3d] 3D-Sprite-Layer aktiv (Three r' + THREE.REVISION + ')'); } catch (e) {}
})();
