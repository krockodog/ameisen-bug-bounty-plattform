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

  // =========================================================================
  // ZEITRAFFER-PLAYER: einen echten Lauf (Pentest/Bugbounty/WLAN) abspielen
  // =========================================================================
  // UI: Auswahl + Play/Pause + Geschwindigkeit + Fortschritt.
  // Animation: Ameisen laufen chronologisch entlang der Event-Pfad-Pheromonspur.
  // Daten: GET /api/runs + GET /api/runs/{id}/timeline – nichts erfunden.
  var player = {
    open: false, playing: false, speed: 2, progress: 0, // 0..1
    run: null, events: [],
    // animierte Ameisen dieses Laufs (eigene Schicht, dimmt die anderen)
    ants: [], path: [], lastTick: 0
  };

  function injectPlayerUI() {
    if (document.getElementById("brain-tl-bar")) return;
    var bar = document.createElement("div");
    bar.id = "brain-tl-bar";
    bar.innerHTML =
      '<div class="tl-head"><span class="tl-ant">🐜</span> <strong>Zeitraffer</strong>' +
      ' <span class="tl-sub">Lauf abspielen</span></div>' +
      '<div class="tl-row">' +
      '  <select id="tl-run" title="Lauf aus der Run-Historie"><option value="">— Lauf wählen —</option></select>' +
      '  <button id="tl-play" class="tl-btn" title="Play/Pause" disabled>▶</button>' +
      '  <select id="tl-speed" title="Geschwindigkeit">' +
      '    <option value="1">1×</option><option value="2" selected>2×</option>' +
      '    <option value="4">4×</option><option value="8">8×</option>' +
      '  </select>' +
      '</div>' +
      '<div class="tl-row">' +
      '  <input id="tl-scrub" type="range" min="0" max="1000" value="0" disabled>' +
      '  <span id="tl-label" class="tl-label">kein Lauf</span>' +
      '</div>' +
      '<div id="tl-meta" class="tl-meta"></div>';
    document.body.appendChild(bar);

    var css = document.createElement("style");
    css.id = "brain-tl-style";
    css.textContent =
      "#brain-tl-bar{position:fixed;left:1rem;bottom:1rem;z-index:5;width:340px;max-width:92vw;" +
      "background:rgba(8,12,20,.9);border:1px solid rgba(56,224,255,.28);border-radius:10px;" +
      "box-shadow:0 0 26px rgba(56,224,255,.14);padding:.55rem .7rem;color:#cfe7ff;" +
      "backdrop-filter:blur(4px);font:12px/1.35 system-ui,sans-serif;}" +
      "#brain-tl-bar .tl-head{display:flex;align-items:center;gap:.35rem;margin-bottom:.35rem;}" +
      "#brain-tl-bar .tl-ant{filter:drop-shadow(0 0 6px rgba(210,153,34,.55));}" +
      "#brain-tl-bar .tl-sub{color:#8a92a6;font-weight:400;margin-left:.2rem;}" +
      "#brain-tl-bar .tl-row{display:flex;gap:.4rem;align-items:center;margin:.25rem 0;}" +
      "#brain-tl-bar select,#brain-tl-bar button,#brain-tl-bar input[type=range]{" +
      "background:#101726;color:#cfe7ff;border:1px solid #1d2740;border-radius:5px;" +
      "padding:.25rem .4rem;font:inherit;}" +
      "#brain-tl-bar select{flex:1;min-width:0;}" +
      "#brain-tl-bar .tl-btn{flex:0 0 auto;min-width:2.2rem;cursor:pointer;}" +
      "#brain-tl-bar .tl-btn:hover{box-shadow:0 0 12px rgba(56,224,255,.25);}" +
      "#brain-tl-bar input[type=range]{flex:1;accent-color:#38e0ff;}" +
      "#brain-tl-bar .tl-label{flex:0 0 auto;color:#9fb0cc;font-size:.72rem;min-width:4.5rem;text-align:right;}" +
      "#brain-tl-bar .tl-meta{color:#8a92a6;font-size:.72rem;min-height:1.1em;}" +
      "@media (prefers-reduced-motion:reduce){#brain-tl-bar .tl-btn{box-shadow:none}}";
    document.head.appendChild(css);

    document.getElementById("tl-run").addEventListener("change", onPickRun);
    document.getElementById("tl-play").addEventListener("click", togglePlay);
    document.getElementById("tl-speed").addEventListener("change", function (e) {
      player.speed = parseFloat(e.target.value) || 1;
    });
    document.getElementById("tl-scrub").addEventListener("input", function (e) {
      player.progress = (parseInt(e.target.value, 10) || 0) / 1000;
      player.playing = false;
      document.getElementById("tl-play").textContent = "▶";
      applyProgress();
    });
  }

  function typeLabel(t) {
    return t === "wlan" ? "WLAN" : (t === "bugbounty" ? "Bugbounty" : "Pentest");
  }

  function refreshRunSelect(runs) {
    var sel = document.getElementById("tl-run");
    if (!sel) return;
    var cur = sel.value;
    sel.innerHTML = '<option value="">— Lauf wählen —</option>';
    (runs || []).forEach(function (r) {
      var opt = document.createElement("option");
      opt.value = String(r.id);
      var mode = (r.offensive || r.mode === "offensive" || r.active || r.fuzz) ? "offensiv" : "defensiv";
      opt.textContent = (r.when || "?").slice(0, 16) + " · " +
        (r.target_name || ("#" + r.target_id)) + " · " + mode +
        " · " + (r.finding_count || 0) + " Funde";
      sel.appendChild(opt);
    });
    if (cur) sel.value = cur;
  }

  // Hook into existing loadRuns success path: also refresh the player select.
  var _origBuild = buildNodes;
  buildNodes = function (runs) {
    _origBuild(runs);
    refreshRunSelect(runs);
  };

  function onPickRun() {
    var id = document.getElementById("tl-run").value;
    player.playing = false;
    document.getElementById("tl-play").textContent = "▶";
    player.progress = 0; player.ants = []; player.path = []; player.events = []; player.run = null;
    document.getElementById("tl-scrub").value = 0;
    document.getElementById("tl-scrub").disabled = true;
    document.getElementById("tl-play").disabled = true;
    document.getElementById("tl-label").textContent = "lädt …";
    document.getElementById("tl-meta").textContent = "";
    if (!id) { document.getElementById("tl-label").textContent = "kein Lauf"; return; }
    fetch("/api/runs/" + encodeURIComponent(id) + "/timeline")
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (data) {
        if (!data || !data.ok) {
          document.getElementById("tl-label").textContent = "nicht verfügbar";
          return;
        }
        player.run = data.run;
        player.events = data.events || [];
        buildPath();
        document.getElementById("tl-play").disabled = false;
        document.getElementById("tl-scrub").disabled = false;
        document.getElementById("tl-label").textContent = "0/" + player.events.length;
        document.getElementById("tl-meta").textContent =
          typeLabel(data.run.type) + " · " + (data.run.target_name || "") +
          " · " + (data.run.finding_count || 0) + " Funde · " +
          player.events.length + " Schritte";
        applyProgress();
      })
      .catch(function () {
        document.getElementById("tl-label").textContent = "Fehler";
      });
  }

  function buildPath() {
    // Deterministischer Pfad durch den Viewport (oben Mitte → Bogen → unten rechts),
    // ein Punkt pro Event. Basis aus Run-ID, damit Reloads stabil bleiben.
    var n = player.events.length || 1;
    var seed = 0;
    var key = String((player.run && (player.run.run_id || player.run.id)) || 0);
    for (var k = 0; k < key.length; k++) seed = (seed * 31 + key.charCodeAt(k)) >>> 0;
    function h(i) { var x = Math.sin((seed + i) * 12.9898) * 43758.5453; return x - Math.floor(x); }
    var path = [];
    for (var i = 0; i < n; i++) {
      var u = n === 1 ? 0.5 : i / (n - 1);
      var x = 60 + u * (W - 120) + (h(i) - 0.5) * 30;
      var y = H * 0.18 + Math.sin(u * Math.PI) * (H * 0.28) + (h(i + 7) - 0.5) * 20;
      path.push({ x: x, y: y, ev: player.events[i] });
    }
    player.path = path;
    // Eine Leit-Ameise + bis zu 4 Begleiter (Schwarm-Feeling, performant)
    player.ants = [];
    var count = Math.min(5, Math.max(1, Math.ceil(n / 6)));
    for (var a = 0; a < count; a++) {
      player.ants.push({
        u: -a * 0.04, // leichter Versatz hinter der Leit-Ameise
        trail: [], x: path[0] ? path[0].x : 0, y: path[0] ? path[0].y : 0
      });
    }
  }

  function togglePlay() {
    if (!player.run || !player.path.length) return;
    player.playing = !player.playing;
    document.getElementById("tl-play").textContent = player.playing ? "⏸" : "▶";
    if (player.playing && player.progress >= 0.999) player.progress = 0;
    player.lastTick = performance.now();
  }

  function applyProgress() {
    var path = player.path;
    if (!path.length) return;
    var u = Math.max(0, Math.min(1, player.progress));
    var idx = Math.min(path.length - 1, Math.floor(u * (path.length - 1)));
    document.getElementById("tl-scrub").value = Math.round(u * 1000);
    document.getElementById("tl-label").textContent =
      (idx + 1) + "/" + path.length;
    var ev = path[idx] && path[idx].ev;
    if (ev && player.run) {
      document.getElementById("tl-meta").textContent =
        typeLabel(player.run.type) + " · " +
        (ev.kind === "finding" ? "🔍 " : (ev.kind === "start" ? "▶ " : (ev.kind === "end" ? "■ " : "• "))) +
        (ev.title || ev.kind) +
        (ev.severity ? " [" + ev.severity + "]" : "") +
        (ev.agent ? " · " + ev.agent : "");
    }
  }

  function posOnPath(u) {
    var path = player.path;
    if (!path.length) return { x: 0, y: 0, ang: 0, idx: 0 };
    var max = path.length - 1;
    var f = Math.max(0, Math.min(1, u)) * max;
    var i = Math.floor(f);
    var t = f - i;
    var a = path[i], b = path[Math.min(max, i + 1)];
    var x = a.x + (b.x - a.x) * t;
    var y = a.y + (b.y - a.y) * t;
    var ang = Math.atan2(b.y - a.y, b.x - a.x);
    return { x: x, y: y, ang: ang, idx: i };
  }

  // Patch the existing frame() to also advance/draw the timelapse.
  var _origFrame = frame;
  frame = function (now) {
    // Advance playback before drawing
    if (player.playing && player.path.length) {
      var dt = Math.min(0.05, (now - (player.lastTick || now)) / 1000);
      player.lastTick = now;
      // Gesamtdauer skaliert mit Event-Zahl (ca. 0.55s pro Schritt bei 1×)
      var total = Math.max(2.5, player.path.length * 0.55);
      player.progress += (dt * player.speed) / total;
      if (player.progress >= 1) {
        player.progress = 1; player.playing = false;
        document.getElementById("tl-play").textContent = "▶";
      }
      applyProgress();
    }

    // Call original (clears + draws idle nodes)
    _origFrame(now);

    // Dim idle nodes slightly while a run is loaded
    if (player.run && player.path.length) {
      ctx.fillStyle = "rgba(0,0,0,0.28)";
      ctx.fillRect(0, 0, W, H);
      // Draw the full pheromone path (faint)
      ctx.strokeStyle = "rgba(56,224,255,0.18)";
      ctx.lineWidth = 1.4;
      ctx.beginPath();
      for (var i = 0; i < player.path.length; i++) {
        var p = player.path[i];
        if (i === 0) ctx.moveTo(p.x, p.y); else ctx.lineTo(p.x, p.y);
      }
      ctx.stroke();
      // Event beads
      var reached = Math.floor(player.progress * (player.path.length - 1));
      for (var j = 0; j < player.path.length; j++) {
        var pj = player.path[j];
        var ev = pj.ev || {};
        var col = ev.severity && SEV_COL[String(ev.severity).toLowerCase()]
          ? SEV_COL[String(ev.severity).toLowerCase()]
          : (player.run.type === "wlan" ? [255, 198, 120]
            : (player.run.type === "bugbounty" ? MAGENTA : CYAN));
        var on = j <= reached;
        ctx.beginPath();
        ctx.fillStyle = on
          ? "rgba(" + col[0] + "," + col[1] + "," + col[2] + ",0.95)"
          : "rgba(80,90,110,0.55)";
        ctx.arc(pj.x, pj.y, on ? 3.2 : 2.2, 0, Math.PI * 2);
        ctx.fill();
        if (on && (ev.kind === "finding" || ev.kind === "start" || ev.kind === "end")) {
          var g = ctx.createRadialGradient(pj.x, pj.y, 0, pj.x, pj.y, 10);
          g.addColorStop(0, "rgba(" + col[0] + "," + col[1] + "," + col[2] + ",0.55)");
          g.addColorStop(1, "rgba(" + col[0] + "," + col[1] + "," + col[2] + ",0)");
          ctx.fillStyle = g; ctx.beginPath(); ctx.arc(pj.x, pj.y, 10, 0, Math.PI * 2); ctx.fill();
        }
      }
      // Moving ants with trails
      var baseCol = player.run.type === "wlan" ? [255, 198, 120]
        : (player.run.type === "bugbounty" ? MAGENTA : CYAN);
      for (var a = 0; a < player.ants.length; a++) {
        var ant = player.ants[a];
        var uu = Math.max(0, Math.min(1, player.progress + ant.u));
        var pos = posOnPath(uu);
        ant.x = pos.x; ant.y = pos.y;
        if (!REDUCED) {
          ant.trail.push({ x: ant.x, y: ant.y });
          if (ant.trail.length > 18) ant.trail.shift();
          for (var s = 0; s < ant.trail.length - 1; s++) {
            var ta = (s / ant.trail.length) * 0.55;
            ctx.strokeStyle = "rgba(" + baseCol[0] + "," + baseCol[1] + "," + baseCol[2] + "," + ta.toFixed(3) + ")";
            ctx.lineWidth = 1 + (s / ant.trail.length) * 2;
            ctx.beginPath();
            ctx.moveTo(ant.trail[s].x, ant.trail[s].y);
            ctx.lineTo(ant.trail[s + 1].x, ant.trail[s + 1].y);
            ctx.stroke();
          }
        }
        // glow + sprite
        var gg = ctx.createRadialGradient(ant.x, ant.y, 0, ant.x, ant.y, 14);
        gg.addColorStop(0, "rgba(" + baseCol[0] + "," + baseCol[1] + "," + baseCol[2] + ",0.85)");
        gg.addColorStop(1, "rgba(" + baseCol[0] + "," + baseCol[1] + "," + baseCol[2] + ",0)");
        ctx.fillStyle = gg; ctx.beginPath(); ctx.arc(ant.x, ant.y, 14, 0, Math.PI * 2); ctx.fill();
        if (spriteReady && !REDUCED) {
          ctx.save();
          ctx.translate(ant.x, ant.y);
          ctx.rotate(pos.ang + Math.PI / 2);
          ctx.globalAlpha = 0.95;
          ctx.shadowColor = "rgba(" + baseCol[0] + "," + baseCol[1] + "," + baseCol[2] + ",0.9)";
          ctx.shadowBlur = 10;
          ctx.drawImage(sprite, -9, -9, 18, 18);
          ctx.restore();
          ctx.globalAlpha = 1;
        } else {
          ctx.fillStyle = "#fff"; ctx.beginPath(); ctx.arc(ant.x, ant.y, 2.6, 0, Math.PI * 2); ctx.fill();
        }
      }
    }
    // IMPORTANT: _origFrame already scheduled the next rAF. Our wrapper replaced
    // `frame`, so the next tick calls US. Do NOT schedule another rAF here.
  };

  injectPlayerUI();

  requestAnimationFrame(frame);
  try { console.info("[brain-runs] Lauf-Knoten-Layer + Zeitraffer aktiv."); } catch (e) {}
})();
