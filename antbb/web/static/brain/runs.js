/* 🐜 Pentest-/Bugbounty-Runs als leuchtende Ameisen-Knoten im Neuronalen Gehirn.
 *
 * Rein additiv & nicht-destruktiv: eigener Canvas-Layer ÜBER dem GPU-Partikelfeld
 * (brain-canvas), UNTER dem Ameisenvolk-Overlay/Panel. Berührt three.js nicht.
 *
 * Jeder ECHTE Lauf aus der persistenten Run-Historie (GET /api/runs → Tabelle
 * run_history) wird zu einem Knoten: eine kleine laufende Ameise (vorhandenes
 * Sprite), die eine verblassende PHEROMONSPUR hinterlässt (Ameisenstraße).
 * Farbe = Modus (offensiv magenta / defensiv cyan) bzw. höchste Severity.
 * Hover → Tooltip (Ziel, wann, Modus, Funde/Severity). Neue Runs = neue Knoten.
 *
 * Nichts erfunden: ausschließlich reale Runs aus der DB. Leere DB → kein Knoten.
 * Performant: begrenzte Knotenzahl, kurze Trails, ein rAF-Loop, DPR-gedeckelt.
 */
(function () {
  "use strict";
  var host = document.getElementById("brain-canvas");
  if (!host) return;
  var REDUCED = window.matchMedia &&
    window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  var SEV_COL = {
    critical: [255, 86, 86], high: [255, 150, 60], medium: [255, 206, 112],
    low: [120, 200, 255], info: [150, 230, 190]
  };
  var CYAN = [56, 224, 255], MAGENTA = [255, 61, 240];

  // --- Canvas-Layer anlegen ------------------------------------------------
  var cv = document.createElement("canvas");
  cv.id = "brain-runs-layer";
  cv.style.cssText = "position:fixed;inset:0;width:100vw;height:100vh;" +
    "z-index:2;pointer-events:none;";
  (host.parentNode || document.body).appendChild(cv);
  var ctx = cv.getContext("2d");
  var DPR = Math.min(window.devicePixelRatio || 1, 2);
  var W = 0, H = 0;
  function resize() {
    W = window.innerWidth; H = window.innerHeight;
    cv.width = Math.floor(W * DPR); cv.height = Math.floor(H * DPR);
    ctx.setTransform(DPR, 0, 0, DPR, 0, 0);
  }
  resize();
  window.addEventListener("resize", resize);

  // --- Ameisen-Sprite (vorhandenes Asset) ----------------------------------
  var sprite = new Image(); sprite.decoding = "async";
  sprite.src = "/static/sprites/scout_tq.png";
  var spriteReady = false;
  sprite.onload = function () { spriteReady = true; };

  // --- Tooltip (HTML, via Fenster-Mausposition; Layer selbst klick-neutral) -
  var tip = document.createElement("div");
  tip.style.cssText = "position:fixed;z-index:6;pointer-events:none;display:none;" +
    "max-width:260px;background:rgba(8,12,20,.92);border:1px solid rgba(56,224,255,.35);" +
    "border-radius:8px;padding:.45rem .6rem;color:#dbe7ff;font:12px/1.4 system-ui,sans-serif;" +
    "box-shadow:0 6px 24px rgba(0,0,0,.6);text-shadow:0 0 6px rgba(56,224,255,.3);";
  document.body.appendChild(tip);
  var mouse = { x: -1, y: -1, on: false };
  window.addEventListener("mousemove", function (e) { mouse.x = e.clientX; mouse.y = e.clientY; mouse.on = true; });
  window.addEventListener("mouseout", function () { mouse.on = false; });

  function esc(s) { var d = document.createElement("div"); d.textContent = (s == null ? "" : String(s)); return d.innerHTML; }

  // --- Run-Daten → Knoten --------------------------------------------------
  var nodes = [];
  function colorFor(run) {
    if (run.offensive || run.mode === "offensive" || run.active || run.fuzz) {
      // offensiv: Severity-getönt, sonst magenta
      return run._sev ? (SEV_COL[run._sev] || MAGENTA) : MAGENTA;
    }
    return run._sev ? (SEV_COL[run._sev] || CYAN) : CYAN;
  }
  function topSeverity(sevObj) {
    var order = ["critical", "high", "medium", "low", "info"];
    for (var i = 0; i < order.length; i++) {
      if (sevObj && sevObj[order[i]]) return order[i];
    }
    return null;
  }

  // Deterministische Pseudo-Zufallsposition pro Run (stabil über Reloads).
  function hash(n) { var x = Math.sin(n * 127.1 + 311.7) * 43758.5453; return x - Math.floor(x); }

  function buildNodes(runs) {
    var next = [];
    // Obere ~62% des Viewports, damit das Ameisenvolk-Overlay unten frei bleibt.
    var top = H * 0.10, bot = H * 0.62;
    for (var i = 0; i < runs.length && i < 120; i++) {
      var r = runs[i];
      var key = String(r.id != null ? r.id : (r.run_id || i));
      var seed = 0; for (var k = 0; k < key.length; k++) seed = (seed * 31 + key.charCodeAt(k)) >>> 0;
      var hx = hash(seed + 1), hy = hash(seed + 2);
      var baseX = 40 + hx * (W - 80);
      var baseY = top + hy * (bot - top);
      try { r._sev = topSeverity(typeof r.severity === "string" ? JSON.parse(r.severity || "{}") : (r.severity || {})); }
      catch (e) { r._sev = null; }
      // bestehenden Knoten (gleicher key) beibehalten → sanfte Kontinuität
      var prev = null;
      for (var p = 0; p < nodes.length; p++) { if (nodes[p].key === key) { prev = nodes[p]; break; } }
      next.push(prev || {
        key: key, run: r, bx: baseX, by: baseY,
        x: baseX, y: baseY, phase: hash(seed + 3) * Math.PI * 2,
        amp: 10 + hash(seed + 4) * 16, spd: 0.25 + hash(seed + 5) * 0.4,
        trail: [], born: performance.now(), col: colorFor(r)
      });
      next[next.length - 1].run = r; next[next.length - 1].col = colorFor(r);
    }
    nodes = next;
  }

  var loaded = false;
  function loadRuns() {
    var ctrl = ("AbortController" in window) ? new AbortController() : null;
    if (ctrl) setTimeout(function () { try { ctrl.abort(); } catch (e) {} }, 6000);
    fetch("/api/runs", { signal: ctrl ? ctrl.signal : undefined })
      .then(function (r) { return r.ok ? r.json() : []; })
      .then(function (runs) { loaded = true; if (Array.isArray(runs)) buildNodes(runs); })
      .catch(function () { loaded = true; /* leer lassen, kein Crash */ });
  }
  loadRuns();
  setInterval(loadRuns, 20000); // neue Runs erscheinen als neue Knoten

  // --- Render-Schleife -----------------------------------------------------
  var t0 = performance.now();
  var TRAIL_MAX = REDUCED ? 0 : 14;
  function frame(now) {
    var t = (now - t0) / 1000;
    ctx.clearRect(0, 0, W, H);
    var hovered = null, hbd = 22 * 22;

    for (var i = 0; i < nodes.length; i++) {
      var n = nodes[i];
      // sanfte Lissajous-Drift um die Basisposition (Ameise „läuft")
      var nx = n.bx + Math.cos(t * n.spd + n.phase) * n.amp;
      var ny = n.by + Math.sin(t * n.spd * 1.3 + n.phase) * n.amp * 0.7;
      var vx = nx - n.x, vy = ny - n.y;
      n.x = nx; n.y = ny;
      var c = n.col;

      // Pheromonspur: verblassende Segmente hinter der Ameise
      if (TRAIL_MAX > 0) {
        n.trail.push({ x: n.x, y: n.y });
        if (n.trail.length > TRAIL_MAX) n.trail.shift();
        for (var s = 0; s < n.trail.length - 1; s++) {
          var a = (s / n.trail.length) * 0.5;
          ctx.strokeStyle = "rgba(" + c[0] + "," + c[1] + "," + c[2] + "," + a.toFixed(3) + ")";
          ctx.lineWidth = 1 + (s / n.trail.length) * 1.6;
          ctx.beginPath();
          ctx.moveTo(n.trail[s].x, n.trail[s].y);
          ctx.lineTo(n.trail[s + 1].x, n.trail[s + 1].y);
          ctx.stroke();
        }
      }

      // Glow-Knoten
      var pulse = REDUCED ? 0.7 : (0.6 + 0.4 * Math.sin(t * 2 + n.phase));
      var g = ctx.createRadialGradient(n.x, n.y, 0, n.x, n.y, 13);
      g.addColorStop(0, "rgba(" + c[0] + "," + c[1] + "," + c[2] + "," + (0.9 * pulse).toFixed(2) + ")");
      g.addColorStop(1, "rgba(" + c[0] + "," + c[1] + "," + c[2] + ",0)");
      ctx.fillStyle = g;
      ctx.beginPath(); ctx.arc(n.x, n.y, 13, 0, Math.PI * 2); ctx.fill();

      // Ameise (ausgerichtet in Laufrichtung), sonst heller Kern
      if (spriteReady && !REDUCED) {
        var ang = Math.atan2(vy, vx);
        ctx.save();
        ctx.translate(n.x, n.y);
        ctx.rotate(ang + Math.PI / 2);
        ctx.globalAlpha = 0.92;
        ctx.shadowColor = "rgba(" + c[0] + "," + c[1] + "," + c[2] + ",0.8)";
        ctx.shadowBlur = 8;
        ctx.drawImage(sprite, -7, -7, 14, 14);
        ctx.restore();
        ctx.globalAlpha = 1;
      } else {
        ctx.fillStyle = "rgba(255,255,255,0.9)";
        ctx.beginPath(); ctx.arc(n.x, n.y, 2.4, 0, Math.PI * 2); ctx.fill();
      }

      // Hover-Test
      if (mouse.on) {
        var dx = mouse.x - n.x, dy = mouse.y - n.y, d2 = dx * dx + dy * dy;
        if (d2 < hbd) { hovered = n; hbd = d2; }
      }
    }

    // Tooltip
    if (hovered) {
      var r = hovered.run;
      var mode = (r.offensive || r.mode === "offensive" || r.active || r.fuzz) ? "offensiv" : "defensiv";
      var sevStr = "";
      try {
        var so = typeof r.severity === "string" ? JSON.parse(r.severity || "{}") : (r.severity || {});
        sevStr = Object.keys(so).map(function (k) { return esc(k) + ":" + esc(so[k]); }).join(" · ");
      } catch (e) {}
      tip.innerHTML =
        "<b>🐜 " + esc(r.target_name || ("Lauf " + hovered.key)) + "</b><br>" +
        '<span style="color:#8fd">' + esc(mode) + "</span>" +
        (r.when ? " · " + esc(r.when) : "") + "<br>" +
        "Funde: " + esc(r.finding_count != null ? r.finding_count : 0) +
        (sevStr ? "<br><span style='color:#9fb0cc'>" + sevStr + "</span>" : "") +
        (r.status && r.status !== "done" ? "<br><span style='color:#ff7b72'>" + esc(r.status) + "</span>" : "");
      tip.style.display = "block";
      tip.style.left = Math.min(mouse.x + 14, W - 270) + "px";
      tip.style.top = Math.min(mouse.y + 14, H - 90) + "px";
    } else {
      tip.style.display = "none";
    }

    // Leerzustand (ehrlich): dezenter Hinweis, wenn keine Runs vorhanden.
    if (loaded && nodes.length === 0) {
      ctx.fillStyle = "rgba(150,170,200,0.5)";
      ctx.font = "12px system-ui, sans-serif"; ctx.textAlign = "center";
      ctx.fillText("Noch keine Läufe — der erste Pentest erscheint hier als Ameise.", W / 2, H * 0.14);
    }
    requestAnimationFrame(frame);
  }
  requestAnimationFrame(frame);
  try { console.info("[brain-runs] Lauf-Knoten-Layer aktiv."); } catch (e) {}
})();
