/* antbb – BÜHNE: der gemalte Ameisen-Nest-Querschnitt IST die Oberfläche.
 * Läuft IMMER (nicht nur als Fallback) als Layer 0, hinter dem 3D-Sprite-Layer.
 *  - Links: unsere Kolonie = das vom Nutzer gemalte Querschnitt-Artwork (hell,
 *    warm, lampenbeleuchtet). Jede Agenten-Kammer wird state-gekoppelt beleuchtet.
 *  - Rechts (bzw. unten am Handy): das ZIEL als eigene, kühlere, dunklere
 *    Ausgrabung (fremder Boden) – ein frisch gegrabenes Zell-Raster. Echte Funde
 *    = aufgebrochene, farbig glühende Kammern; Leerzustand = dunkle Siegel-Zellen.
 *  - Ein Tunnel vom Thron gräbt sich nach rechts ins Ziel; Pheromon-Ameisen
 *    wandern (offensiv magenta, defensiv cyan) – eine Spur, KEIN Klecks.
 * Die Stufe (Thronsaal → breiter Bau → radiale Hive-Stadt) wächst mit REALEM
 * Scope/Scan. Alles state-gekoppelt; keine Deko, kein Fake, ehrliche Leerzustände.
 */
(function () {
  "use strict";
  const wrap = document.getElementById("antmap-wrap");
  if (!wrap || !(window.AntMap && window.AntMap.getSnapshot)) return;
  const targetId = window.ANTBB ? window.ANTBB.targetId : null;
  const targetName = (window.ANTBB && window.ANTBB.targetName) || "";
  const REDUCED = window.matchMedia &&
    window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  // ---- Artwork-Stufen -----------------------------------------------------
  const TIER1_VARIANTS = ["ref1_throne", "ref2_throne2", "ref3_symmetric"];
  function baseFor(tier) {
    if (tier === 3) return "ref4_radial";
    if (tier === 2) return "ref5_wide";
    const i = ((targetId || 0) % TIER1_VARIANTS.length + TIER1_VARIANTS.length)
              % TIER1_VARIANTS.length;
    return TIER1_VARIANTS[i];
  }
  const WEBP = (function () {
    try { return document.createElement("canvas").toDataURL("image/webp")
      .indexOf("data:image/webp") === 0; } catch (e) { return false; }
  })();
  const imgCache = {};
  function getImg(base) {
    if (imgCache[base]) return imgCache[base];
    const im = new Image(); im.decoding = "async";
    im.src = "/static/colony/" + base + (WEBP ? ".webp" : ".jpg");
    imgCache[base] = im; return im;
  }

  const SEVCOL = {
    critical: [255, 86, 86], high: [255, 150, 60], medium: [255, 206, 112],
    low: [120, 200, 255], info: [150, 230, 190]
  };

  // ---- DOM: Bühnen-Canvas (normal) + Glow-Canvas (screen) -----------------
  const layer = document.createElement("div");
  layer.id = "antmap-colony";
  const stage = document.createElement("canvas"); stage.id = "antmap-stage";
  const fx = document.createElement("canvas"); fx.id = "antmap-colony-fx";
  layer.appendChild(stage); layer.appendChild(fx);
  wrap.insertBefore(layer, wrap.firstChild);
  const sctx = stage.getContext("2d");
  const fctx = fx.getContext("2d");

  // ---- Stufen-Auswahl aus REALEN Werten ----------------------------------
  function pickTier(snap, actCount) {
    const m = snap.mode || {};
    const scope = m.in_scope_count || 0;
    const off = (snap.effective || m.effective_mode) === "offensive";
    if (off || scope >= 5 || actCount >= 6) return 3;
    if (scope >= 2 || actCount >= 3) return 2;
    return 1;
  }

  // ---- Findings-Polling (echte Funde) ------------------------------------
  let findings = [];
  async function pollFindings() {
    if (targetId == null) return;
    try {
      const r = await fetch("/api/targets/" + targetId + "/findings");
      const d = await r.json();
      if (Array.isArray(d)) findings = d;
    } catch (e) {}
    setTimeout(pollFindings, 4000);
  }

  // ---- Canvas-Größe -------------------------------------------------------
  let DPR = 1, W = 0, H = 0;
  function sizeCanvas(snap) {
    DPR = Math.min(window.devicePixelRatio || 1, 2);
    W = snap.W || wrap.clientWidth; H = snap.H || Math.round(W * 0.52);
    [stage, fx].forEach(c => {
      c.width = Math.round(W * DPR); c.height = Math.round(H * DPR);
      c.style.width = W + "px"; c.style.height = H + "px";
    });
    sctx.setTransform(DPR, 0, 0, DPR, 0, 0);
    fctx.setTransform(DPR, 0, 0, DPR, 0, 0);
  }

  // Deterministisches Wobble (für Erd-Kontur, kein Zufall pro Frame)
  function wob(seed) {
    return Math.sin(seed * 12.9898) * 43758.5453 % 1;
  }

  function roundRectPath(c, x, y, w, h, r) {
    c.beginPath();
    c.moveTo(x + r, y);
    c.arcTo(x + w, y, x + w, y + h, r);
    c.arcTo(x + w, y + h, x, y + h, r);
    c.arcTo(x, y + h, x, y, r);
    c.arcTo(x, y, x + w, y, r);
    c.closePath();
  }

  function glow(c, x, y, r, col, a) {
    const g = c.createRadialGradient(x, y, 1, x, y, r);
    g.addColorStop(0, "rgba(" + col[0] + "," + col[1] + "," + col[2] + "," + a.toFixed(3) + ")");
    g.addColorStop(0.45, "rgba(" + col[0] + "," + col[1] + "," + col[2] + "," + (a * 0.4).toFixed(3) + ")");
    g.addColorStop(1, "rgba(" + col[0] + "," + col[1] + "," + col[2] + ",0)");
    c.fillStyle = g;
    c.beginPath(); c.arc(x, y, r, 0, Math.PI * 2); c.fill();
  }

  // ---- gezackte Erd-Trennkante (Kolonie | Ziel) --------------------------
  function seamPath(c, snap, extendInto) {
    // Pfad entlang des Kolonie-Bereichs, rechts (PC) bzw. unten (Handy) gezackt.
    const col = snap.stage.colony;
    const nrw = snap.narrow;
    c.beginPath();
    if (!nrw) {
      const sx = col.x + col.w;
      c.moveTo(col.x, col.y);
      c.lineTo(sx - 10, col.y);
      const steps = 22;
      for (let i = 0; i <= steps; i++) {
        const yy = col.y + (i / steps) * col.h;
        const jag = 14 * Math.sin(yy * 0.05) + 9 * Math.sin(yy * 0.13 + 2) + (extendInto || 0);
        c.lineTo(sx + jag, yy);
      }
      c.lineTo(col.x, col.y + col.h);
    } else {
      const sy = col.y + col.h;
      c.moveTo(col.x, col.y);
      c.lineTo(col.x + col.w, col.y);
      c.lineTo(col.x + col.w, sy - 10);
      const steps = 22;
      for (let i = steps; i >= 0; i--) {
        const xx = col.x + (i / steps) * col.w;
        const jag = 12 * Math.sin(xx * 0.05) + 7 * Math.sin(xx * 0.12 + 2) + (extendInto || 0);
        c.lineTo(xx, sy + jag);
      }
      c.lineTo(col.x, col.y);
    }
    c.closePath();
  }

  function drawColonyArt(snap, img) {
    const col = snap.stage.colony;
    sctx.save();
    seamPath(sctx, snap, 6);
    sctx.clip();
    // cover-fit
    if (img && img.complete && img.naturalWidth) {
      const iw = img.naturalWidth, ih = img.naturalHeight;
      const s = Math.max((col.w + 24) / iw, col.h / ih);
      const dw = iw * s, dh = ih * s;
      const dx = col.x + (col.w - dw) / 2;
      const dy = col.y + (col.h - dh) / 2;
      sctx.drawImage(img, dx, dy, dw, dh);
    } else {
      sctx.fillStyle = "#2a1d10"; sctx.fillRect(col.x, col.y, col.w, col.h);
    }
    // nur dezente Rand-Vignette INNEN, Mitte bleibt hell (Artwork strahlt)
    const vg = sctx.createRadialGradient(col.x + col.w * 0.5, col.y + col.h * 0.45,
      Math.min(col.w, col.h) * 0.30, col.x + col.w * 0.5, col.y + col.h * 0.5,
      Math.max(col.w, col.h) * 0.72);
    vg.addColorStop(0, "rgba(10,6,2,0)");
    vg.addColorStop(1, "rgba(10,6,2,0.42)");
    sctx.fillStyle = vg; sctx.fillRect(col.x, col.y, col.w, col.h);
    sctx.restore();
  }

  function drawSeam(snap) {
    // erdiger Grat mit Rim-Licht entlang der Trennkante
    sctx.save();
    sctx.lineJoin = "round";
    seamPath(sctx, snap, 6);
    sctx.lineWidth = 7;
    sctx.strokeStyle = "rgba(28,18,8,0.95)";
    sctx.stroke();
    seamPath(sctx, snap, 3);
    sctx.lineWidth = 2;
    sctx.strokeStyle = "rgba(255,210,150,0.28)"; // warmes Rim-Licht Kolonie-Seite
    sctx.stroke();
    sctx.restore();
  }

  function drawExcavation(snap, t, actCount, running) {
    const e = snap.stage.excav;
    // fremder, KÜHLER + dunkler Boden
    sctx.save();
    roundRectPath(sctx, e.x, e.y, e.w, e.h, 10);
    sctx.clip();
    const g = sctx.createLinearGradient(e.x, e.y, e.x + e.w, e.y + e.h);
    g.addColorStop(0, "#15110b");
    g.addColorStop(0.5, "#0d0f14");
    g.addColorStop(1, "#090b11");
    sctx.fillStyle = g; sctx.fillRect(e.x, e.y, e.w, e.h);
    // kühler Schleier (macht's "fremd")
    sctx.fillStyle = "rgba(30,46,74,0.16)";
    sctx.fillRect(e.x, e.y, e.w, e.h);
    // Boden-Körnung
    for (let i = 0; i < 60; i++) {
      const rx = e.x + (wob(i + 1) + 1) / 2 * e.w;
      const ry = e.y + (wob(i + 99) + 1) / 2 * e.h;
      sctx.fillStyle = (i % 2) ? "rgba(60,50,38,0.25)" : "rgba(40,48,64,0.22)";
      sctx.beginPath(); sctx.arc(rx, ry, 1.2 + (i % 3), 0, Math.PI * 2); sctx.fill();
    }
    sctx.restore();

    // Zell-Raster: gegrabene Kammern des Ziels (Siegel-Zellen, dunkel)
    const cols = e.cols, rows = e.rows;
    const pad = 8;
    const cw = (e.w - pad * 2) / cols, cwh = (e.h - pad * 2) / rows;
    const cellW = cw * 0.84, cellH = cwh * 0.80;
    const cells = [];
    for (let r = 0; r < rows; r++) {
      for (let cI = 0; cI < cols; cI++) {
        const cx = e.x + pad + cI * cw + (cw - cellW) / 2;
        const cy = e.y + pad + r * cwh + (cwh - cellH) / 2;
        cells.push({ x: cx, y: cy, w: cellW, h: cellH,
                     cx: cx + cellW / 2, cy: cy + cellH / 2 });
      }
    }
    // alle Zellen zunächst als dunkle, versiegelte Nischen (Erd-Kragen + Loch)
    cells.forEach(cell => {
      roundRectPath(sctx, cell.x, cell.y, cell.w, cell.h, 5);
      sctx.fillStyle = "rgba(10,8,6,0.78)"; sctx.fill();
      sctx.lineWidth = 2; sctx.strokeStyle = "rgba(52,40,28,0.7)"; sctx.stroke();
      // innerer Schatten-Kern
      const ig = sctx.createRadialGradient(cell.cx, cell.cy, 1, cell.cx, cell.cy, cell.w * 0.5);
      ig.addColorStop(0, "rgba(0,0,0,0.5)"); ig.addColorStop(1, "rgba(0,0,0,0)");
      sctx.fillStyle = ig; sctx.fillRect(cell.x, cell.y, cell.w, cell.h);
    });

    // Rahmen + Beschriftung
    roundRectPath(sctx, e.x, e.y, e.w, e.h, 10);
    sctx.lineWidth = 1.5; sctx.strokeStyle = "rgba(120,150,200,0.35)"; sctx.stroke();
    const off = (snap.effective) === "offensive";
    const title = "ZIEL · AUSGRABUNG" + (targetName ? " (" + targetName + ")" : "");
    const sub = off ? "offensiv: Tunnel gräbt sich hinein" : "defensiv: Inspektion von außen";
    sctx.textAlign = "left";
    sctx.font = "600 12px system-ui, sans-serif";
    const tw = sctx.measureText(title).width;
    sctx.fillStyle = "rgba(8,10,16,0.55)";
    roundRectPath(sctx, e.x, e.y - 22, tw + 12, 18, 5); sctx.fill();
    sctx.fillStyle = "rgba(214,228,252,0.95)";
    sctx.fillText(title, e.x + 5, e.y - 9);
    sctx.font = "10px system-ui, sans-serif";
    const sw = sctx.measureText(sub).width;
    sctx.fillStyle = "rgba(8,10,16,0.5)";
    roundRectPath(sctx, e.x, e.y + e.h + 4, sw + 12, 16, 5); sctx.fill();
    sctx.fillStyle = "rgba(196,210,238,0.9)";
    sctx.fillText(sub, e.x + 5, e.y + e.h + 15);
    return cells;
  }

  function drawTunnel(snap, t) {
    const tu = snap.stage.tunnel;
    const off = (snap.effective) === "offensive";
    const dx = tu.x2 - tu.x1, dy = tu.y2 - tu.y1;
    const len = Math.hypot(dx, dy) || 1;
    const nx = -dy / len, ny = dx / len;
    const bow = Math.min(len * 0.12, 34);
    const cx = (tu.x1 + tu.x2) / 2 + nx * bow;
    const cy = (tu.y1 + tu.y2) / 2 + ny * bow;
    // gegrabener Kanal (dunkle Rinne mit erdigem Rand)
    sctx.save();
    sctx.lineCap = "round";
    sctx.beginPath();
    sctx.moveTo(tu.x1, tu.y1); sctx.quadraticCurveTo(cx, cy, tu.x2, tu.y2);
    sctx.lineWidth = 16; sctx.strokeStyle = "rgba(24,16,8,0.9)"; sctx.stroke();
    sctx.beginPath();
    sctx.moveTo(tu.x1, tu.y1); sctx.quadraticCurveTo(cx, cy, tu.x2, tu.y2);
    sctx.lineWidth = 9; sctx.strokeStyle = "rgba(8,6,4,0.95)"; sctx.stroke();
    sctx.restore();
    return { cx, cy };
  }

  // ---- FX: Pheromon-Spur entlang des Tunnels -----------------------------
  function pheromone(snap, ctrl, t) {
    const tu = snap.stage.tunnel;
    const off = (snap.effective) === "offensive";
    const col = off ? [255, 61, 240] : [56, 224, 255];
    const np = 7;
    for (let i = 0; i < np; i++) {
      let u = ((t * 0.16 + i / np) % 1);
      if (REDUCED) u = (i + 0.5) / np;
      const om = 1 - u;
      const px = om * om * tu.x1 + 2 * om * u * ctrl.cx + u * u * tu.x2;
      const py = om * om * tu.y1 + 2 * om * u * ctrl.cy + u * u * tu.y2;
      const a = 0.5 + 0.4 * Math.sin((u + i) * 3);
      glow(fctx, px, py, 9, col, 0.4 * a);
      fctx.fillStyle = "rgba(" + col[0] + "," + col[1] + "," + col[2] + "," + (0.8 * a).toFixed(2) + ")";
      fctx.beginPath(); fctx.arc(px, py, 1.8, 0, Math.PI * 2); fctx.fill();
    }
  }

  // ---- Render-Schleife (immer) -------------------------------------------
  let lastW = 0, lastH = 0;
  function frame() {
    const snap = window.AntMap.getSnapshot();
    if (snap && snap.stage) {
      if (snap.W !== lastW || snap.H !== lastH) { sizeCanvas(snap); lastW = snap.W; lastH = snap.H; }
      const t = snap.t || 0;
      let actCount = 0, running = 0;
      const blockedIds = {};
      (snap.chambers || []).forEach(c => {
        if (c.state === "running") { actCount++; running++; }
        else if (c.state === "done") actCount++;
        else if (c.state === "blocked") blockedIds[c.id] = true;
      });
      const tier = pickTier(snap, actCount);
      const img = getImg(baseFor(tier));

      // ---- Bühne (normal) ----
      sctx.clearRect(0, 0, W, H);
      sctx.fillStyle = "#09060329"; // fast schwarz, minimal
      sctx.fillStyle = "#0a0702"; sctx.fillRect(0, 0, W, H);
      drawColonyArt(snap, img);
      const ctrl = drawTunnel(snap, t);
      const cells = drawExcavation(snap, t, actCount, running);
      drawSeam(snap);

      // Blockierte Kammern (z.B. fehlende Oversight) = versiegelt/verschüttet
      (snap.chambers || []).forEach(c => {
        if (c.state !== "blocked") return;
        sctx.save();
        const r = Math.max(20, Math.min(W, H) * 0.045);
        // Schutt-Kappe
        const g = sctx.createRadialGradient(c.x, c.y, 1, c.x, c.y, r);
        g.addColorStop(0, "rgba(8,6,4,0.9)"); g.addColorStop(1, "rgba(8,6,4,0)");
        sctx.fillStyle = g; sctx.beginPath(); sctx.arc(c.x, c.y, r, 0, Math.PI * 2); sctx.fill();
        // Kreuz-Schraffur
        sctx.strokeStyle = "rgba(90,70,50,0.55)"; sctx.lineWidth = 1.2;
        for (let k = -3; k <= 3; k++) {
          sctx.beginPath();
          sctx.moveTo(c.x - r * 0.7 + k * 5, c.y - r * 0.7);
          sctx.lineTo(c.x - r * 0.7 + k * 5 + r * 1.4, c.y + r * 0.7);
          sctx.stroke();
        }
        // kleines Schloss
        sctx.fillStyle = "rgba(230,200,150,0.9)";
        sctx.font = "13px system-ui"; sctx.textAlign = "center";
        sctx.fillText("🔒", c.x, c.y + 5);
        sctx.restore();
      });

      // ---- FX / Glows (screen) ----
      fctx.clearRect(0, 0, W, H);
      const pulse = REDUCED ? 0.6 : (0.5 + 0.5 * Math.sin(t * 2.0));
      const r = Math.max(30, Math.min(W, H) * 0.072);

      // Thron der Königin: warmes Bloom
      const qCmd = snap.queen && snap.queen.commanding;
      glow(fctx, snap.throne.x, snap.throne.y, r * 1.5,
        [255, 198, 120], qCmd ? (0.5 + 0.2 * pulse) : 0.34);
      glow(fctx, snap.throne.x, snap.throne.y, r * 0.6, [255, 240, 205], 0.3);

      // Agenten-Kammern state-gekoppelt beleuchten (warme Lampen)
      (snap.chambers || []).forEach(c => {
        if (c.state === "blocked") return; // dunkel/versiegelt (Bühne)
        let a;
        if (c.state === "running") a = 0.42 + 0.38 * pulse;
        else if (c.state === "done") a = 0.5;
        else a = 0.12; // idle: schwach glimmend
        glow(fctx, c.x, c.y, r, [255, 196, 112], a);
        glow(fctx, c.x, c.y, r * 0.38, [255, 240, 208], a * 0.7);
      });

      // Ziel-Ausgrabung: nur so viele Zellen aufgebrochen/glühend wie ECHTE Funde
      const lit = Math.min(findings.length, cells.length);
      for (let i = 0; i < lit; i++) {
        const f = findings[i];
        const sev = (f && f.severity) || "info";
        const sc = SEVCOL[sev] || SEVCOL.info;
        const cell = cells[i];
        const boost = (sev === "critical" || sev === "high") ? 1.25 : 1.0;
        const a = running > 0 ? (0.5 + 0.35 * pulse) : 0.62;
        glow(fctx, cell.cx, cell.cy, Math.max(cell.w, cell.h) * 0.9 * boost, sc, a);
        glow(fctx, cell.cx, cell.cy, cell.w * 0.3 * boost, [255, 244, 220], a * 0.5);
      }
      // "+N weitere" wenn mehr Funde als Zellen
      if (findings.length > cells.length) {
        const e = snap.stage.excav;
        fctx.fillStyle = "rgba(255,230,200,0.95)";
        fctx.font = "600 10px system-ui"; fctx.textAlign = "right";
        fctx.fillText("+" + (findings.length - cells.length) + " weitere Funde", e.x + e.w, e.y + e.h + 15);
      }

      // Pheromon-Spur Tunnel (nur wenn offensiv ODER aktive Agenten)
      if ((snap.effective === "offensive") || running > 0) pheromone(snap, ctrl, t);
    }
    requestAnimationFrame(frame);
  }

  window.__antmapColony = { active: true, pickTier: pickTier, baseFor: baseFor };
  const first = window.AntMap.getSnapshot();
  if (first) sizeCanvas(first);
  // Tier-Bilder vorladen
  [1, 2, 3].forEach(tt => getImg(baseFor(tt)));
  requestAnimationFrame(frame);
  pollFindings();
  window.addEventListener("resize", function () {
    const s = window.AntMap.getSnapshot(); if (s) sizeCanvas(s);
  });
  try { console.info("[antmap-colony] Bühne aktiv (WebP=" + WEBP + ")"); } catch (e) {}
})();
