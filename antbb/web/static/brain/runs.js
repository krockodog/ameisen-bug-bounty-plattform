/* 🐜 Pentest-/Bugbounty-/WLAN-Runs als leuchtende Ameisen-Knoten im Brain.
 *
 * Rein additiv: Canvas-Layer ÜBER dem GPU-Partikelfeld, UNTER dem Ameisenvolk.
 * Premium-Motion: gedämpfte Verfolgung der Drift-Bahn, geglättete Heading,
 * distanz-basierte Pheromonspur (kein Frame-Stotter), Bloom-Glows.
 * Zeitraffer: flüssiges Path-Following mit Look-ahead + Trail-Kontinuität.
 *
 * Nur echte Runs aus /api/runs (Red/Pentest/Bugbounty/WLAN). Blue Queen = /blue.
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

  // --- Canvas --------------------------------------------------------------
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

  var sprite = new Image(); sprite.decoding = "async";
  sprite.src = "/static/sprites/scout_tq.png";
  var spriteReady = false;
  sprite.onload = function () { spriteReady = true; };

  var tip = document.createElement("div");
  tip.style.cssText = "position:fixed;z-index:6;pointer-events:none;display:none;" +
    "max-width:280px;background:rgba(8,12,20,.94);border:1px solid rgba(56,224,255,.4);" +
    "border-radius:10px;padding:.5rem .7rem;color:#dbe7ff;font:12px/1.45 system-ui,sans-serif;" +
    "box-shadow:0 8px 28px rgba(0,0,0,.65),0 0 18px rgba(56,224,255,.12);" +
    "text-shadow:0 0 6px rgba(56,224,255,.3);backdrop-filter:blur(6px);";
  document.body.appendChild(tip);
  var mouse = { x: -1, y: -1, on: false };
  window.addEventListener("mousemove", function (e) {
    mouse.x = e.clientX; mouse.y = e.clientY; mouse.on = true;
  });
  window.addEventListener("mouseout", function () { mouse.on = false; });

  function esc(s) {
    var d = document.createElement("div");
    d.textContent = (s == null ? "" : String(s));
    return d.innerHTML;
  }

  // --- Helpers -------------------------------------------------------------
  function colorFor(run) {
    if (run.offensive || run.mode === "offensive" || run.active || run.fuzz) {
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
  function hash(n) {
    var x = Math.sin(n * 127.1 + 311.7) * 43758.5453;
    return x - Math.floor(x);
  }
  function angDelta(from, to) {
    var d = to - from;
    while (d > Math.PI) d -= Math.PI * 2;
    while (d < -Math.PI) d += Math.PI * 2;
    return d;
  }
  function lerp(a, b, t) { return a + (b - a) * t; }
  function damp(cur, goal, lambda, dt) {
    return lerp(cur, goal, 1 - Math.exp(-lambda * dt));
  }

  // Distanz-basierte Pheromon-Samples (kontinuierlich, frame-rate unabhängig).
  function pushTrail(trail, x, y, maxLen, minDist) {
    var last = trail.length ? trail[trail.length - 1] : null;
    if (last) {
      var dx = x - last.x, dy = y - last.y;
      if (dx * dx + dy * dy < minDist * minDist) return;
    }
    trail.push({ x: x, y: y });
    while (trail.length > maxLen) trail.shift();
  }

  function strokeTrail(trail, col, baseAlpha, baseWidth) {
    if (trail.length < 2) return;
    for (var s = 0; s < trail.length - 1; s++) {
      var a = (s / trail.length) * baseAlpha;
      ctx.strokeStyle = "rgba(" + col[0] + "," + col[1] + "," + col[2] + "," + a.toFixed(3) + ")";
      ctx.lineWidth = baseWidth * (0.4 + (s / trail.length) * 0.9);
      ctx.lineCap = "round";
      ctx.lineJoin = "round";
      ctx.beginPath();
      ctx.moveTo(trail[s].x, trail[s].y);
      ctx.lineTo(trail[s + 1].x, trail[s + 1].y);
      ctx.stroke();
    }
    // Bloom-Schimmer entlang der frischen Spur.
    var tip = trail[trail.length - 1];
    var g = ctx.createRadialGradient(tip.x, tip.y, 0, tip.x, tip.y, 16);
    g.addColorStop(0, "rgba(" + col[0] + "," + col[1] + "," + col[2] + ",0.22)");
    g.addColorStop(1, "rgba(" + col[0] + "," + col[1] + "," + col[2] + ",0)");
    ctx.fillStyle = g;
    ctx.beginPath(); ctx.arc(tip.x, tip.y, 16, 0, Math.PI * 2); ctx.fill();
  }

  // --- Nodes ---------------------------------------------------------------
  var nodes = [];
  var TRAIL_MAX = REDUCED ? 0 : 36;
  var TRAIL_MIN = 2.4;
  var FOLLOW = 5.5;       // Positions-Dämpfung (höher = enger an Bahn)
  var TURN = 7.0;         // Heading-Dämpfung

  function isBlueRun(r) {
    if (!r) return false;
    var m = String(r.mode || "").toLowerCase();
    var t = String(r.type || "").toLowerCase();
    var n = String(r.target_name || "").toLowerCase();
    return m === "blue" || t === "blue" || n.indexOf("blue-queen") === 0 ||
      r.colony === "blue";
  }

  function buildNodes(runs) {
    var next = [];
    var top = H * 0.10, bot = H * 0.62;
    for (var i = 0; i < runs.length && i < 120; i++) {
      var r = runs[i];
      if (isBlueRun(r)) continue;
      var key = String(r.id != null ? r.id : (r.run_id || i));
      var seed = 0;
      for (var k = 0; k < key.length; k++) seed = (seed * 31 + key.charCodeAt(k)) >>> 0;
      var hx = hash(seed + 1), hy = hash(seed + 2);
      var baseX = 40 + hx * (W - 80);
      var baseY = top + hy * (bot - top);
      try {
        r._sev = topSeverity(typeof r.severity === "string"
          ? JSON.parse(r.severity || "{}") : (r.severity || {}));
      } catch (e) { r._sev = null; }

      var prev = null;
      for (var p = 0; p < nodes.length; p++) {
        if (nodes[p].key === key) { prev = nodes[p]; break; }
      }
      if (prev) {
        prev.run = r;
        prev.col = colorFor(r);
        // Basis sanft nachziehen (Resize), Position selbst bleibt kontinuierlich.
        prev.bx = damp(prev.bx, baseX, 1.2, 0.05);
        prev.by = damp(prev.by, baseY, 1.2, 0.05);
        next.push(prev);
      } else {
        next.push({
          key: key, run: r, bx: baseX, by: baseY,
          x: baseX, y: baseY,
          tx: baseX, ty: baseY,
          heading: hash(seed + 6) * Math.PI * 2,
          phase: hash(seed + 3) * Math.PI * 2,
          amp: 14 + hash(seed + 4) * 22,
          spd: 0.22 + hash(seed + 5) * 0.35,
          trail: [], born: performance.now(), col: colorFor(r)
        });
      }
    }
    nodes = next;
  }

  var loaded = false;
  function loadRuns() {
    var ctrl = ("AbortController" in window) ? new AbortController() : null;
    if (ctrl) setTimeout(function () { try { ctrl.abort(); } catch (e) {} }, 6000);
    fetch("/api/runs", { signal: ctrl ? ctrl.signal : undefined })
      .then(function (r) { return r.ok ? r.json() : []; })
      .then(function (runs) {
        loaded = true;
        if (Array.isArray(runs)) buildNodes(runs);
      })
      .catch(function () { loaded = true; });
  }
  loadRuns();
  setInterval(loadRuns, 20000);

  // --- Idle render ---------------------------------------------------------
  var t0 = performance.now();
  var lastFrame = 0;

  function frame(now) {
    var dt = lastFrame ? Math.min(0.05, (now - lastFrame) / 1000) : 0.016;
    lastFrame = now;
    var t = (now - t0) / 1000;
    ctx.clearRect(0, 0, W, H);
    var hovered = null, hbd = 24 * 24;

    for (var i = 0; i < nodes.length; i++) {
      var n = nodes[i];
      // Organische Lissajous-Bahn als ZIEL — Position folgt gedämpft (kein Snap).
      n.tx = n.bx + Math.cos(t * n.spd + n.phase) * n.amp;
      n.ty = n.by + Math.sin(t * n.spd * 1.27 + n.phase * 1.1) * n.amp * 0.72;
      if (REDUCED) {
        n.x = n.tx; n.y = n.ty;
      } else {
        n.x = damp(n.x, n.tx, FOLLOW, dt);
        n.y = damp(n.y, n.ty, FOLLOW, dt);
      }
      var vx = n.tx - n.x, vy = n.ty - n.y;
      // Heading aus tatsächlicher Bewegungsrichtung, geglättet.
      if (vx * vx + vy * vy > 0.04) {
        var want = Math.atan2(vy, vx);
        n.heading += angDelta(n.heading, want) * (1 - Math.exp(-TURN * dt));
      }
      var c = n.col;

      if (TRAIL_MAX > 0) {
        pushTrail(n.trail, n.x, n.y, TRAIL_MAX, TRAIL_MIN);
        strokeTrail(n.trail, c, 0.55, 2.2);
      }

      // Bloom-Knoten
      var pulse = REDUCED ? 0.7 : (0.62 + 0.38 * Math.sin(t * 1.8 + n.phase));
      var g = ctx.createRadialGradient(n.x, n.y, 0, n.x, n.y, 16);
      g.addColorStop(0, "rgba(" + c[0] + "," + c[1] + "," + c[2] + "," + (0.85 * pulse).toFixed(2) + ")");
      g.addColorStop(0.45, "rgba(" + c[0] + "," + c[1] + "," + c[2] + "," + (0.28 * pulse).toFixed(2) + ")");
      g.addColorStop(1, "rgba(" + c[0] + "," + c[1] + "," + c[2] + ",0)");
      ctx.fillStyle = g;
      ctx.beginPath(); ctx.arc(n.x, n.y, 16, 0, Math.PI * 2); ctx.fill();

      if (spriteReady && !REDUCED) {
        ctx.save();
        ctx.translate(n.x, n.y);
        ctx.rotate(n.heading + Math.PI / 2);
        ctx.globalAlpha = 0.94;
        ctx.shadowColor = "rgba(" + c[0] + "," + c[1] + "," + c[2] + ",0.85)";
        ctx.shadowBlur = 10;
        ctx.drawImage(sprite, -8, -8, 16, 16);
        ctx.restore();
        ctx.globalAlpha = 1;
        ctx.shadowBlur = 0;
      } else {
        ctx.fillStyle = "rgba(255,255,255,0.92)";
        ctx.beginPath(); ctx.arc(n.x, n.y, 2.6, 0, Math.PI * 2); ctx.fill();
      }

      if (mouse.on) {
        var dx = mouse.x - n.x, dy = mouse.y - n.y, d2 = dx * dx + dy * dy;
        if (d2 < hbd) { hovered = n; hbd = d2; }
      }
    }

    if (hovered) {
      var r = hovered.run;
      var mode = (r.offensive || r.mode === "offensive" || r.active || r.fuzz)
        ? "offensiv" : "defensiv";
      var sevStr = "";
      try {
        var so = typeof r.severity === "string"
          ? JSON.parse(r.severity || "{}") : (r.severity || {});
        sevStr = Object.keys(so).map(function (k) {
          return esc(k) + ":" + esc(so[k]);
        }).join(" · ");
      } catch (e) {}
      tip.innerHTML =
        "<b>🐜 " + esc(r.target_name || ("Lauf " + hovered.key)) + "</b><br>" +
        '<span style="color:#8fd">' + esc(mode) + "</span>" +
        (r.when ? " · " + esc(r.when) : "") + "<br>" +
        "Funde: " + esc(r.finding_count != null ? r.finding_count : 0) +
        (sevStr ? "<br><span style='color:#9fb0cc'>" + sevStr + "</span>" : "") +
        (r.status && r.status !== "done"
          ? "<br><span style='color:#ff7b72'>" + esc(r.status) + "</span>" : "");
      tip.style.display = "block";
      tip.style.left = Math.min(mouse.x + 14, W - 290) + "px";
      tip.style.top = Math.min(mouse.y + 14, H - 100) + "px";
    } else {
      tip.style.display = "none";
    }

    if (loaded && nodes.length === 0) {
      ctx.fillStyle = "rgba(150,170,200,0.55)";
      ctx.font = "12px system-ui, sans-serif";
      ctx.textAlign = "center";
      ctx.fillText(
        "Noch keine Läufe — der erste Pentest erscheint hier als Ameise.",
        W / 2, H * 0.14
      );
    }
    requestAnimationFrame(frame);
  }

  // =========================================================================
  // ZEITRAFFER-PLAYER
  // =========================================================================
  var player = {
    open: false, playing: false, speed: 2, progress: 0,
    run: null, events: [],
    ants: [], path: [], lastTick: 0,
    displayProgress: 0 // geglätteter Fortschritt (kein Scrub-Hüpfen)
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
      "#brain-tl-bar{position:fixed;left:1rem;bottom:1rem;z-index:5;width:360px;max-width:92vw;" +
      "background:linear-gradient(160deg,rgba(8,12,20,.94),rgba(12,18,32,.9));" +
      "border:1px solid rgba(56,224,255,.32);border-radius:12px;" +
      "box-shadow:0 0 32px rgba(56,224,255,.16),0 8px 28px rgba(0,0,0,.45);" +
      "padding:.65rem .8rem;color:#cfe7ff;backdrop-filter:blur(8px);" +
      "font:12px/1.4 system-ui,sans-serif;}" +
      "#brain-tl-bar .tl-head{display:flex;align-items:center;gap:.4rem;margin-bottom:.4rem;}" +
      "#brain-tl-bar .tl-ant{filter:drop-shadow(0 0 8px rgba(210,153,34,.6));font-size:1.05rem;}" +
      "#brain-tl-bar .tl-sub{color:#8a92a6;font-weight:400;margin-left:.15rem;}" +
      "#brain-tl-bar .tl-row{display:flex;gap:.45rem;align-items:center;margin:.3rem 0;}" +
      "#brain-tl-bar select,#brain-tl-bar button,#brain-tl-bar input[type=range]{" +
      "background:#101726;color:#cfe7ff;border:1px solid #1d2740;border-radius:6px;" +
      "padding:.3rem .45rem;font:inherit;transition:box-shadow .25s,border-color .25s;}" +
      "#brain-tl-bar select{flex:1;min-width:0;}" +
      "#brain-tl-bar select:focus,#brain-tl-bar button:hover{" +
      "border-color:rgba(56,224,255,.55);box-shadow:0 0 14px rgba(56,224,255,.22);outline:none;}" +
      "#brain-tl-bar .tl-btn{flex:0 0 auto;min-width:2.4rem;cursor:pointer;}" +
      "#brain-tl-bar input[type=range]{flex:1;accent-color:#38e0ff;}" +
      "#brain-tl-bar .tl-label{flex:0 0 auto;color:#9fb0cc;font-size:.72rem;min-width:4.5rem;text-align:right;}" +
      "#brain-tl-bar .tl-meta{color:#8a92a6;font-size:.72rem;min-height:1.15em;letter-spacing:.01em;}" +
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
      // Bei großem Scrub-Sprung Trails leeren, sonst nahtlos weiterglätten.
      var jump = Math.abs(player.progress - player.displayProgress);
      if (jump > 0.08) {
        player.displayProgress = player.progress;
        player.ants.forEach(function (a) { a.trail = []; });
      }
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
      if (isBlueRun(r)) return;
      var opt = document.createElement("option");
      opt.value = String(r.id);
      var mode = (r.offensive || r.mode === "offensive" || r.active || r.fuzz)
        ? "offensiv" : "defensiv";
      opt.textContent = (r.when || "?").slice(0, 16) + " · " +
        (r.target_name || ("#" + r.target_id)) + " · " + mode +
        " · " + (r.finding_count || 0) + " Funde";
      sel.appendChild(opt);
    });
    if (cur) sel.value = cur;
  }

  var _origBuild = buildNodes;
  buildNodes = function (runs) {
    _origBuild(runs);
    refreshRunSelect(runs);
  };

  function onPickRun() {
    var id = document.getElementById("tl-run").value;
    player.playing = false;
    document.getElementById("tl-play").textContent = "▶";
    player.progress = 0; player.displayProgress = 0;
    player.ants = []; player.path = []; player.events = []; player.run = null;
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
        if (isBlueRun(data.run)) {
          document.getElementById("tl-label").textContent = "Blue → /blue";
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
    var n = player.events.length || 1;
    var seed = 0;
    var key = String((player.run && (player.run.run_id || player.run.id)) || 0);
    for (var k = 0; k < key.length; k++) seed = (seed * 31 + key.charCodeAt(k)) >>> 0;
    function h(i) {
      var x = Math.sin((seed + i) * 12.9898) * 43758.5453;
      return x - Math.floor(x);
    }
    var path = [];
    for (var i = 0; i < n; i++) {
      var u = n === 1 ? 0.5 : i / (n - 1);
      // Weicher Bogen mit leichten organischen Offsets.
      var x = 70 + u * (W - 140) + Math.sin(u * Math.PI * 2.2) * 18 + (h(i) - 0.5) * 16;
      var y = H * 0.20 + Math.sin(u * Math.PI) * (H * 0.30) +
        Math.sin(u * Math.PI * 3) * 12 + (h(i + 7) - 0.5) * 14;
      path.push({ x: x, y: y, ev: player.events[i] });
    }
    player.path = path;
    player.ants = [];
    var count = Math.min(5, Math.max(1, Math.ceil(n / 6)));
    for (var a = 0; a < count; a++) {
      var p0 = path[0] || { x: 0, y: 0 };
      player.ants.push({
        u: -a * 0.045,
        trail: [],
        x: p0.x, y: p0.y,
        heading: 0
      });
    }
  }

  function togglePlay() {
    if (!player.run || !player.path.length) return;
    player.playing = !player.playing;
    document.getElementById("tl-play").textContent = player.playing ? "⏸" : "▶";
    if (player.playing && player.progress >= 0.999) {
      player.progress = 0;
      player.displayProgress = 0;
      player.ants.forEach(function (a) { a.trail = []; });
    }
    player.lastTick = performance.now();
  }

  function applyProgress() {
    var path = player.path;
    if (!path.length) return;
    var u = Math.max(0, Math.min(1, player.progress));
    var idx = Math.min(path.length - 1, Math.floor(u * (path.length - 1)));
    document.getElementById("tl-scrub").value = Math.round(u * 1000);
    document.getElementById("tl-label").textContent = (idx + 1) + "/" + path.length;
    var ev = path[idx] && path[idx].ev;
    if (ev && player.run) {
      document.getElementById("tl-meta").textContent =
        typeLabel(player.run.type) + " · " +
        (ev.kind === "finding" ? "🔍 " : (ev.kind === "start" ? "▶ " :
          (ev.kind === "end" ? "■ " : "• "))) +
        (ev.title || ev.kind) +
        (ev.severity ? " [" + ev.severity + "]" : "") +
        (ev.agent ? " · " + ev.agent : "");
    }
  }

  // Catmull-Rom-ähnliche Abtastung für weiche Kurven zwischen Event-Punkten.
  function posOnPath(u) {
    var path = player.path;
    if (!path.length) return { x: 0, y: 0, ang: 0, idx: 0 };
    var max = path.length - 1;
    var f = Math.max(0, Math.min(1, u)) * max;
    var i = Math.floor(f);
    var t = f - i;
    // Smoothstep für weichere Segmentübergänge.
    var ts = t * t * (3 - 2 * t);
    var p0 = path[Math.max(0, i - 1)];
    var p1 = path[i];
    var p2 = path[Math.min(max, i + 1)];
    var p3 = path[Math.min(max, i + 2)];
    // Catmull-Rom
    var t2 = ts * ts, t3 = t2 * ts;
    var x = 0.5 * ((2 * p1.x) + (-p0.x + p2.x) * ts +
      (2 * p0.x - 5 * p1.x + 4 * p2.x - p3.x) * t2 +
      (-p0.x + 3 * p1.x - 3 * p2.x + p3.x) * t3);
    var y = 0.5 * ((2 * p1.y) + (-p0.y + p2.y) * ts +
      (2 * p0.y - 5 * p1.y + 4 * p2.y - p3.y) * t2 +
      (-p0.y + 3 * p1.y - 3 * p2.y + p3.y) * t3);
    // Look-ahead für stabile Heading.
    var look = posOnPathLinear(Math.min(1, u + 0.012));
    var ang = Math.atan2(look.y - y, look.x - x);
    return { x: x, y: y, ang: ang, idx: i };
  }

  function posOnPathLinear(u) {
    var path = player.path;
    if (!path.length) return { x: 0, y: 0 };
    var max = path.length - 1;
    var f = Math.max(0, Math.min(1, u)) * max;
    var i = Math.floor(f);
    var t = f - i;
    var a = path[i], b = path[Math.min(max, i + 1)];
    return { x: a.x + (b.x - a.x) * t, y: a.y + (b.y - a.y) * t };
  }

  var _origFrame = frame;
  frame = function (now) {
    var dt = Math.min(0.05, (now - (player.lastTick || now)) / 1000);
    if (player.playing && player.path.length) {
      player.lastTick = now;
      var total = Math.max(2.8, player.path.length * 0.6);
      player.progress += (dt * player.speed) / total;
      if (player.progress >= 1) {
        player.progress = 1;
        player.playing = false;
        document.getElementById("tl-play").textContent = "▶";
      }
      applyProgress();
    } else {
      player.lastTick = now;
    }
    // Display-Progress glätten → Ameisen hüpfen nicht bei Speed-Wechseln.
    if (REDUCED) {
      player.displayProgress = player.progress;
    } else {
      var gap = Math.abs(player.progress - player.displayProgress);
      var rate = gap > 0.1 ? 14 : 8;
      player.displayProgress = damp(player.displayProgress, player.progress, rate, dt);
    }

    _origFrame(now);

    if (player.run && player.path.length) {
      ctx.fillStyle = "rgba(0,0,0,0.30)";
      ctx.fillRect(0, 0, W, H);

      // Pheromon-Pfad mit Glow
      ctx.save();
      ctx.strokeStyle = "rgba(56,224,255,0.14)";
      ctx.lineWidth = 3.2;
      ctx.lineCap = "round";
      ctx.lineJoin = "round";
      ctx.shadowColor = "rgba(56,224,255,0.35)";
      ctx.shadowBlur = 12;
      ctx.beginPath();
      for (var i = 0; i < player.path.length; i++) {
        var p = player.path[i];
        if (i === 0) ctx.moveTo(p.x, p.y); else ctx.lineTo(p.x, p.y);
      }
      ctx.stroke();
      ctx.shadowBlur = 0;
      ctx.strokeStyle = "rgba(56,224,255,0.28)";
      ctx.lineWidth = 1.3;
      ctx.stroke();
      ctx.restore();

      var reached = Math.floor(player.displayProgress * (player.path.length - 1));
      for (var j = 0; j < player.path.length; j++) {
        var pj = player.path[j];
        var ev = pj.ev || {};
        var col = ev.severity && SEV_COL[String(ev.severity).toLowerCase()]
          ? SEV_COL[String(ev.severity).toLowerCase()]
          : (player.run.type === "wlan" ? [255, 198, 120]
            : (player.run.type === "bugbounty" ? MAGENTA : CYAN));
        var on = j <= reached;
        if (on) {
          var glow = ctx.createRadialGradient(pj.x, pj.y, 0, pj.x, pj.y, 12);
          glow.addColorStop(0, "rgba(" + col[0] + "," + col[1] + "," + col[2] + ",0.5)");
          glow.addColorStop(1, "rgba(" + col[0] + "," + col[1] + "," + col[2] + ",0)");
          ctx.fillStyle = glow;
          ctx.beginPath(); ctx.arc(pj.x, pj.y, 12, 0, Math.PI * 2); ctx.fill();
        }
        ctx.beginPath();
        ctx.fillStyle = on
          ? "rgba(" + col[0] + "," + col[1] + "," + col[2] + ",0.95)"
          : "rgba(80,90,110,0.5)";
        ctx.arc(pj.x, pj.y, on ? 3.4 : 2.2, 0, Math.PI * 2);
        ctx.fill();
      }

      var baseCol = player.run.type === "wlan" ? [255, 198, 120]
        : (player.run.type === "bugbounty" ? MAGENTA : CYAN);

      for (var a = 0; a < player.ants.length; a++) {
        var ant = player.ants[a];
        var uu = Math.max(0, Math.min(1, player.displayProgress + ant.u));
        var pos = posOnPath(uu);
        // Gedämpfte Positionsfolge — kein Teleport entlang der Spur.
        if (REDUCED) {
          ant.x = pos.x; ant.y = pos.y; ant.heading = pos.ang;
        } else {
          ant.x = damp(ant.x, pos.x, 14, dt);
          ant.y = damp(ant.y, pos.y, 14, dt);
          ant.heading += angDelta(ant.heading, pos.ang) * (1 - Math.exp(-10 * dt));
        }
        if (!REDUCED) {
          pushTrail(ant.trail, ant.x, ant.y, 28, 2.0);
          strokeTrail(ant.trail, baseCol, 0.65, 2.6);
        }
        var gg = ctx.createRadialGradient(ant.x, ant.y, 0, ant.x, ant.y, 18);
        gg.addColorStop(0, "rgba(" + baseCol[0] + "," + baseCol[1] + "," + baseCol[2] + ",0.88)");
        gg.addColorStop(0.5, "rgba(" + baseCol[0] + "," + baseCol[1] + "," + baseCol[2] + ",0.25)");
        gg.addColorStop(1, "rgba(" + baseCol[0] + "," + baseCol[1] + "," + baseCol[2] + ",0)");
        ctx.fillStyle = gg;
        ctx.beginPath(); ctx.arc(ant.x, ant.y, 18, 0, Math.PI * 2); ctx.fill();

        if (spriteReady && !REDUCED) {
          ctx.save();
          ctx.translate(ant.x, ant.y);
          ctx.rotate(ant.heading + Math.PI / 2);
          ctx.globalAlpha = 0.96;
          ctx.shadowColor = "rgba(" + baseCol[0] + "," + baseCol[1] + "," + baseCol[2] + ",0.95)";
          ctx.shadowBlur = 12;
          ctx.drawImage(sprite, -10, -10, 20, 20);
          ctx.restore();
          ctx.globalAlpha = 1;
          ctx.shadowBlur = 0;
        } else {
          ctx.fillStyle = "#fff";
          ctx.beginPath(); ctx.arc(ant.x, ant.y, 2.8, 0, Math.PI * 2); ctx.fill();
        }
      }
    }
  };

  injectPlayerUI();
  requestAnimationFrame(frame);
  try { console.info("[brain-runs] Premium Lauf-Knoten + Zeitraffer aktiv."); } catch (e) {}
})();
