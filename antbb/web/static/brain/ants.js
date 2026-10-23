/* 🐜 Ameisenvolk-Overlay für das Neuronale Gehirn der Königin.
 *
 * Rein additiv: eigene DOM+Canvas-Schicht ÜBER dem GPU-Partikelfeld.
 * Premium-Motion: organisches Wander-Steering, gedämpfte Geschwindigkeit,
 * sanfter Gang (kein Hüpfen), kontinuierliche Pheromonspur auf Canvas.
 *
 * NUR Red-Kolonie (Pentest/Bugbounty/WLAN-Soldaten). Blue Queen lebt
 * ausschließlich unter /blue — keine Blue-Soldaten hier.
 * Klick auf eine Ameise öffnet Playbooks/SKILL.md im Detail-Panel.
 */
(function () {
  "use strict";

  var SPR = "/static/sprites/";
  var ROLE_SPRITE = {
    queen:  [SPR + "queen_front.png",       SPR + "queen_tq.png"],
    scout:  [SPR + "scout_front.png",       SPR + "scout_tq.png"],
    worker: [SPR + "worker_front.png",      SPR + "worker_tq.png"],
    def:    [SPR + "soldier_def_front.png", SPR + "soldier_def_tq.png"],
    off:    [SPR + "soldier_off_front.png", SPR + "soldier_off_tq.png"]
  };

  // Red-Soldaten (Brain). Blue-* Namen werden bewusst ausgeschlossen.
  var NAME_ROLE = {
    recon: "scout", osint: "scout", scanning: "scout", takeover: "scout",
    wifi: "off", verify: "off", poc: "off", fuzz: "off", llmsec: "off",
    infra: "def", auth: "def", api: "def", cloud: "def", mobile: "def",
    codeaudit: "worker", analysis: "worker", reporting: "worker", threatintel: "worker"
  };

  function isBlueSoldier(name) {
    if (!name) return false;
    var n = String(name).toLowerCase();
    return n.indexOf("blue") === 0 || n.indexOf("blue-") === 0 ||
      n === "defense" || n === "hardening" || n === "honeypot" ||
      n === "remediation" || n === "swscan" || n.indexOf("blue_") === 0;
  }

  function roleFor(name) {
    if (isBlueSoldier(name)) return null;
    return NAME_ROLE[name] || null;
  }

  var reduce = window.matchMedia &&
    window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  function injectStyle() {
    if (document.getElementById("ant-colony-style")) return;
    var css = [
      ".ant-colony{position:fixed;left:0;right:0;bottom:0;height:36vh;min-height:240px;",
        "z-index:3;pointer-events:none;overflow:hidden;}",
      ".ant-colony::before{content:'';position:absolute;left:0;right:0;bottom:0;height:52%;",
        "background:linear-gradient(180deg,rgba(0,0,0,0) 0%,rgba(8,6,4,0) 18%,",
        "rgba(28,16,6,.38) 68%,rgba(42,22,8,.58) 100%);pointer-events:none;}",
      ".ant-colony canvas.ant-pheromone{position:absolute;inset:0;width:100%;height:100%;",
        "pointer-events:none;}",
      ".ant{position:absolute;left:0;bottom:0;will-change:transform;pointer-events:auto;cursor:pointer;",
        "transform-origin:50% 85%;filter:drop-shadow(0 6px 10px rgba(0,0,0,.55));",
        "transition:filter .6s ease;}",
      ".ant:focus-visible{outline:2px solid rgba(56,224,255,.7);outline-offset:3px;}",
      ".ant img{display:block;height:100%;width:auto;image-rendering:auto;",
        "user-select:none;-webkit-user-drag:none;}",
      ".ant.queen{filter:drop-shadow(0 0 18px rgba(255,180,70,.5)) ",
        "drop-shadow(0 8px 16px rgba(0,0,0,.75));}",
      ".ant.active{filter:drop-shadow(0 0 14px rgba(56,224,255,.75)) ",
        "drop-shadow(0 6px 10px rgba(0,0,0,.55));}",
      ".ant .ant-label{position:absolute;left:50%;bottom:100%;transform:translateX(-50%);",
        "margin-bottom:4px;font-size:10px;letter-spacing:.04em;color:#cfe7ff;",
        "background:rgba(8,12,20,.78);border:1px solid rgba(56,224,255,.28);",
        "border-radius:7px;padding:2px 7px;white-space:nowrap;opacity:.42;",
        "transition:opacity .45s ease;text-shadow:0 0 6px rgba(56,224,255,.45);",
        "box-shadow:0 0 12px rgba(56,224,255,.12);pointer-events:none;}",
      ".ant.active .ant-label,.ant:hover .ant-label{opacity:.95;}",
      ".ant-colony .ant-caption{position:absolute;left:50%;bottom:6px;transform:translateX(-50%);",
        "font-size:11px;color:#9fd0ff;opacity:.55;letter-spacing:.07em;",
        "pointer-events:none;text-shadow:0 0 10px rgba(0,0,0,.85);",
        "background:rgba(6,10,18,.35);padding:2px 10px;border-radius:999px;",
        "border:1px solid rgba(56,224,255,.12);}"
    ].join("");
    var el = document.createElement("style");
    el.id = "ant-colony-style";
    el.textContent = css;
    document.head.appendChild(el);
  }

  function makeAnt(role, cls, heightPx) {
    var wrap = document.createElement("div");
    wrap.className = "ant" + (cls ? " " + cls : "");
    wrap.style.height = heightPx + "px";
    var pair = ROLE_SPRITE[role] || ROLE_SPRITE.worker;
    var img = document.createElement("img");
    img.src = cls === "queen" ? pair[0] : pair[1];
    img.alt = role + "-Ameise";
    img.loading = "eager";
    img.draggable = false;
    wrap.appendChild(img);
    return wrap;
  }

  // --- State ---------------------------------------------------------------
  var host, pheromoneCv, pheromoneCtx, soldiers = [], queenEl = null, raf = 0;
  var last = 0, hostH = 240, hostW = 800, dpr = 1;
  var TRAIL_MAX = reduce ? 0 : 48;
  var TRAIL_MIN_DIST = 2.2; // px between pheromone samples (continuous, not stutter)

  function ensureHost() {
    if (host) return;
    host = document.createElement("div");
    host.className = "ant-colony";
    host.setAttribute("aria-hidden", "true");

    pheromoneCv = document.createElement("canvas");
    pheromoneCv.className = "ant-pheromone";
    host.appendChild(pheromoneCv);
    pheromoneCtx = pheromoneCv.getContext("2d");

    var cap = document.createElement("div");
    cap.className = "ant-caption";
    cap.id = "ant-colony-caption";
    cap.textContent = "🐜 Das Ameisenvolk · Königin + Soldaten";
    host.appendChild(cap);

    var mountTarget = document.querySelector("main") || document.body;
    mountTarget.appendChild(host);

    queenEl = makeAnt("queen", "queen", Math.round(window.innerHeight * 0.26));
    host.appendChild(queenEl);
    layoutQueen();
    resizePheromone();
  }

  function resizePheromone() {
    if (!host || !pheromoneCv) return;
    hostW = host.clientWidth || window.innerWidth;
    hostH = host.clientHeight || Math.round(window.innerHeight * 0.36);
    dpr = Math.min(window.devicePixelRatio || 1, 2);
    pheromoneCv.width = Math.floor(hostW * dpr);
    pheromoneCv.height = Math.floor(hostH * dpr);
    pheromoneCtx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }

  function layoutQueen() {
    if (!queenEl) return;
    queenEl.style.zIndex = "120";
    // Queen uses transform exclusively (no left thrashing).
    queenEl.style.left = "0";
    queenEl.style.bottom = "0";
  }

  function filterRedSoldiers(soldierNodes) {
    var out = [];
    for (var i = 0; i < soldierNodes.length; i++) {
      var n = soldierNodes[i];
      var name = (n.label || n.id || "").replace(/^soldier:/, "");
      if (roleFor(name)) out.push(n);
    }
    return out;
  }


  function wireSoldierOpen(el, name) {
    if (el.dataset && el.dataset.wiredOpen === "1") return;
    if (el.dataset) el.dataset.wiredOpen = "1";
    el.title = "Playbooks & SKILL.md von " + name + " öffnen";
    el.setAttribute("role", "button");
    el.setAttribute("tabindex", "0");
    el.setAttribute("data-soldier", name);
    function open() {
      window.dispatchEvent(new CustomEvent("antbb-open-soldier", { detail: { name: name } }));
    }
    el.addEventListener("click", function (ev) { ev.stopPropagation(); open(); });
    el.addEventListener("keydown", function (ev) {
      if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); open(); }
    });
  }

  function buildColony(soldierNodes) {
    ensureHost();
    soldierNodes = filterRedSoldiers(soldierNodes);

    var byName = {};
    soldiers.forEach(function (s) { byName[s.name] = s; });

    var keep = {};
    var W = hostW || window.innerWidth;
    var baseH = Math.max(72, Math.round(window.innerHeight * 0.12));
    var next = [];

    soldierNodes.forEach(function (n, i) {
      var name = (n.label || n.id || "").replace(/^soldier:/, "");
      var role = roleFor(name);
      if (!role) return;
      var findings = (n.counts && n.counts.findings) || 0;
      var active = findings > 0;
      var prev = byName[name];

      if (prev) {
        // Kontinuität: Position/Velocity behalten — KEIN Teleport-Rebuild.
        prev.active = active;
        prev.el.classList.toggle("active", active);
        var lab = prev.el.querySelector(".ant-label");
        if (lab) lab.textContent = name + (findings ? " · " + findings : "");
        wireSoldierOpen(prev.el, name);
        // Sanfte Zielgeschwindigkeit anpassen (kein Sprung).
        var targetSpd = (active ? 22 : 11) * (0.7 + (prev._seed || 0.5) * 0.6);
        prev.spdGoal = targetSpd;
        next.push(prev);
        keep[name] = true;
        return;
      }

      var depth = 0.82 + ((i % 5) * 0.06);
      var h = Math.round(baseH * depth);
      var el = makeAnt(role, active ? "active" : "", h);
      var label = document.createElement("span");
      label.className = "ant-label";
      label.textContent = name + (findings ? " · " + findings : "");
      el.appendChild(label);
      wireSoldierOpen(el, name);
      host.appendChild(el);

      var seed = (hashStr(name) % 1000) / 1000;
      var dir = seed < 0.5 ? -1 : 1;
      var spd = (active ? 22 : 11) * (0.7 + seed * 0.6);
      var ant = {
        el: el, name: name, role: role, active: active,
        x: seed * W,
        y: (i % 5) * (baseH * 0.11),
        vx: dir * spd,
        vy: 0,
        spdGoal: spd,
        heading: dir >= 0 ? 0 : Math.PI,
        gait: seed * Math.PI * 2,
        gaitSpd: (active ? 7.5 : 5.2) + seed * 1.8,
        wander: seed * Math.PI * 2,
        wanderSpd: 0.35 + seed * 0.45,
        trail: [],
        h: h,
        z: Math.round(depth * 100),
        _seed: seed,
        glow: active ? 1 : 0
      };
      el.style.zIndex = String(ant.z);
      next.push(ant);
      keep[name] = true;
    });

    // Entfernte Soldaten (z.B. Blue) aus DOM nehmen.
    soldiers.forEach(function (s) {
      if (!keep[s.name] && s.el && s.el.parentNode) s.el.parentNode.removeChild(s.el);
    });
    soldiers = next;

    var cap = document.getElementById("ant-colony-caption");
    if (cap) {
      cap.textContent = "🐜 Das Ameisenvolk · Königin + " + soldiers.length + " Soldaten";
    }
  }

  function hashStr(s) {
    var h = 2166136261;
    for (var i = 0; i < s.length; i++) {
      h ^= s.charCodeAt(i);
      h = Math.imul(h, 16777619);
    }
    return h >>> 0;
  }

  // Kürzester Winkel-Delta (−π..π).
  function angDelta(from, to) {
    var d = to - from;
    while (d > Math.PI) d -= Math.PI * 2;
    while (d < -Math.PI) d += Math.PI * 2;
    return d;
  }

  function pushTrail(ant, x, y) {
    if (TRAIL_MAX <= 0) return;
    var t = ant.trail;
    var lastP = t.length ? t[t.length - 1] : null;
    if (lastP) {
      var dx = x - lastP.x, dy = y - lastP.y;
      if (dx * dx + dy * dy < TRAIL_MIN_DIST * TRAIL_MIN_DIST) return;
    }
    t.push({ x: x, y: y, a: ant.active ? 0.55 : 0.32 });
    while (t.length > TRAIL_MAX) t.shift();
  }

  function drawPheromones() {
    if (!pheromoneCtx) return;
    pheromoneCtx.clearRect(0, 0, hostW, hostH);
    for (var i = 0; i < soldiers.length; i++) {
      var s = soldiers[i];
      var trail = s.trail;
      if (trail.length < 2) continue;
      var col = s.active ? [56, 224, 255] : [210, 160, 90];
      // Eine durchgehende Kurve statt stotternder Segmente.
      pheromoneCtx.beginPath();
      pheromoneCtx.moveTo(trail[0].x, hostH - trail[0].y - s.h * 0.15);
      for (var k = 1; k < trail.length; k++) {
        var p = trail[k];
        pheromoneCtx.lineTo(p.x, hostH - p.y - s.h * 0.15);
      }
      var alpha = s.active ? 0.42 : 0.22;
      pheromoneCtx.strokeStyle = "rgba(" + col[0] + "," + col[1] + "," + col[2] + "," + alpha + ")";
      pheromoneCtx.lineWidth = s.active ? 2.4 : 1.5;
      pheromoneCtx.lineCap = "round";
      pheromoneCtx.lineJoin = "round";
      pheromoneCtx.shadowColor = "rgba(" + col[0] + "," + col[1] + "," + col[2] + ",0.45)";
      pheromoneCtx.shadowBlur = s.active ? 8 : 4;
      pheromoneCtx.stroke();
      pheromoneCtx.shadowBlur = 0;

      // Weiches Ausfaden am Schwanz: Overlay mit abnehmender Deckkraft.
      for (var s2 = 0; s2 < trail.length - 1; s2++) {
        var a = (s2 / trail.length) * (s.active ? 0.35 : 0.18);
        pheromoneCtx.strokeStyle = "rgba(" + col[0] + "," + col[1] + "," + col[2] + "," + a.toFixed(3) + ")";
        pheromoneCtx.lineWidth = 1 + (s2 / trail.length) * (s.active ? 2.2 : 1.4);
        pheromoneCtx.beginPath();
        var y0 = hostH - trail[s2].y - s.h * 0.15;
        var y1 = hostH - trail[s2 + 1].y - s.h * 0.15;
        pheromoneCtx.moveTo(trail[s2].x, y0);
        pheromoneCtx.lineTo(trail[s2 + 1].x, y1);
        pheromoneCtx.stroke();
      }
    }
  }

  function tick(now) {
    var dt = last ? Math.min(0.05, (now - last) / 1000) : 0.016;
    last = now;
    var W = hostW || window.innerWidth;
    var t = now / 1000;

    // Königin: ruhiges Atmen + leichtes Wiegen (kein Hüpfen).
    if (queenEl && !reduce) {
      var breath = 1 + Math.sin(t * 1.1) * 0.018;
      var sway = Math.sin(t * 0.55) * 1.2;
      queenEl.style.transform =
        "translate3d(" + (W * 0.5) + "px,0,0) translateX(-50%) " +
        "rotate(" + sway + "deg) scale(" + breath + ")";
    } else if (queenEl) {
      queenEl.style.transform =
        "translate3d(" + (W * 0.5) + "px,0,0) translateX(-50%)";
    }

    for (var i = 0; i < soldiers.length; i++) {
      var s = soldiers[i];
      if (!reduce) {
        // Organisches Wander-Steering: langsame Kursänderung + gedämpfte Speed.
        s.wander += s.wanderSpd * dt;
        var steer = Math.sin(s.wander) * 0.55 + Math.sin(s.wander * 1.7 + s._seed * 4) * 0.25;
        var desiredHeading = s.heading + steer * dt * 1.8;
        // Geschwindigkeit exponentiell an Zielgeschwindigkeit angleichen.
        var curSpd = Math.sqrt(s.vx * s.vx + s.vy * s.vy) || s.spdGoal;
        curSpd += (s.spdGoal - curSpd) * (1 - Math.exp(-dt * 3.2));
        // Heading glätten (kein 180°-Flip).
        var faceTarget = Math.atan2(0, s.vx >= 0 ? 1 : -1);
        // Bevorzuge aktuelle Laufrichtung; Steer mischt rein.
        var want = s.vx >= 0 ? 0 : Math.PI;
        want += steer * 0.35;
        s.heading += angDelta(s.heading, want) * (1 - Math.exp(-dt * 5));
        s.vx = Math.cos(s.heading) * curSpd;
        // Sehr leichte vertikale Drift (Boden-Krabbeln), stark gedämpft.
        s.vy += (steer * 8 - s.vy) * (1 - Math.exp(-dt * 4));
        s.vy = Math.max(-6, Math.min(6, s.vy));

        s.x += s.vx * dt;
        s.y += s.vy * dt;
        // Bodenkorridor halten (kein Springen aus der Schicht).
        var yMin = 0, yMax = hostH * 0.22;
        if (s.y < yMin) { s.y = yMin; s.vy = Math.abs(s.vy) * 0.3; }
        if (s.y > yMax) { s.y = yMax; s.vy = -Math.abs(s.vy) * 0.3; }

        // Sanfter Wrap außerhalb des Sichtfelds; Trail leeren (keine Querlinie).
        if (s.x < -80) { s.x = W + 60; s.trail = []; }
        else if (s.x > W + 80) { s.x = -60; s.trail = []; }

        s.gait += s.gaitSpd * dt;
        pushTrail(s, s.x, s.y);
      }

      // Gang: winzige Vertikal-Oszillation (≤1.4px) — ameisenhaft, kein Hüpfen.
      var bob = reduce ? 0 : Math.sin(s.gait) * (s.active ? 1.35 : 0.9);
      var tilt = reduce ? 0 : Math.sin(s.gait) * (s.active ? 1.6 : 1.0) +
        (s.vx >= 0 ? 0 : 0);
      // Face über scaleX, nie über abrupte Rotate-Flips.
      var face = s.vx >= 0 ? 1 : -1;
      // Glow-Pulse für aktive Soldaten (Filter bleibt CSS; nur Opacity-Label).
      s.glow += ((s.active ? 1 : 0) - s.glow) * (1 - Math.exp(-dt * 3));

      s.el.style.transform =
        "translate3d(" + s.x.toFixed(2) + "px," + (-bob - s.y).toFixed(2) + "px,0) " +
        "scaleX(" + face + ") rotate(" + tilt.toFixed(2) + "deg)";
    }

    if (!reduce) drawPheromones();
    raf = requestAnimationFrame(tick);
  }

  function start(soldierNodes) {
    injectStyle();
    buildColony(soldierNodes);
    resizePheromone();
    if (raf) cancelAnimationFrame(raf);
    last = 0;
    raf = requestAnimationFrame(tick);
  }

  function loadAndStart() {
    fetch("/api/brain/nodes")
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (g) {
        var sol = (g && g.nodes ? g.nodes : []).filter(function (n) {
          return n.type === "soldier" && !isBlueSoldier((n.label || n.id || "").replace(/^soldier:/, ""));
        });
        if (!sol.length) {
          sol = Object.keys(NAME_ROLE).map(function (name) {
            return { type: "soldier", label: name, id: "soldier:" + name, counts: { findings: 0 } };
          });
        }
        start(sol);
      })
      .catch(function () {
        start(Object.keys(NAME_ROLE).map(function (name) {
          return { type: "soldier", label: name, id: "soldier:" + name, counts: { findings: 0 } };
        }));
      });
  }

  // Status-Refresh: nur Labels/Aktivität — Positionen bleiben (kein Rebuild-Hüpfen).
  function schedule() { setInterval(loadAndStart, 20000); }

  function init() { loadAndStart(); schedule(); }
  if (document.readyState === "loading")
    document.addEventListener("DOMContentLoaded", init);
  else init();

  window.addEventListener("resize", function () {
    if (queenEl) queenEl.style.height = Math.round(window.innerHeight * 0.26) + "px";
    resizePheromone();
  });
})();
