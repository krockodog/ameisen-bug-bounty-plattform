/* 🐜 Ameisenvolk-Overlay für das Neuronale Gehirn der Königin.
 *
 * Rein additiv und nicht-destruktiv: legt eine eigene DOM-Schicht ÜBER das
 * GPU-Partikelfeld (brain-canvas), ohne die three.js-Engine oder das
 * Knoten-Panel zu berühren. Nutzt die von der Nutzerin gestalteten Sprites
 * (web/static/sprites/*). Die Königin steht prominent, die 18 Soldaten
 * krabbeln als Arbeiter/Späher/Soldaten-Ameisen umher. Aktive Soldaten
 * (mit Funden bzw. laufendem Scan) werden hervorgehoben und bewegen sich
 * lebhafter. Pointer-events: none → das Overlay fängt keine Klicks ab.
 *
 * Keine Secrets, keine PII. Läuft auch mit leerer DB (dann ruhiges Krabbeln).
 */
(function () {
  "use strict";

  var SPR = "/static/sprites/";
  // Rolle → Sprite-Paar (front / dreiviertel). Nur echte, vorhandene Assets.
  var ROLE_SPRITE = {
    queen:   [SPR + "queen_front.png",       SPR + "queen_tq.png"],
    scout:   [SPR + "scout_front.png",       SPR + "scout_tq.png"],
    worker:  [SPR + "worker_front.png",      SPR + "worker_tq.png"],
    def:     [SPR + "soldier_def_front.png", SPR + "soldier_def_tq.png"],
    off:     [SPR + "soldier_off_front.png", SPR + "soldier_off_tq.png"]
  };

  // Soldaten-Name → Rolle (Sprite-Zuordnung passend zur Aufgabe des Soldaten).
  var NAME_ROLE = {
    recon: "scout", osint: "scout", scanning: "scout", takeover: "scout",
    wifi: "off", verify: "off", poc: "off", fuzz: "off", llmsec: "off",
    infra: "def", auth: "def", api: "def", cloud: "def", mobile: "def",
    codeaudit: "worker", analysis: "worker", reporting: "worker", threatintel: "worker"
  };

  function roleFor(name) { return NAME_ROLE[name] || "worker"; }

  var reduce = window.matchMedia &&
    window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  // --- Overlay-Container + minimaler Style (gekapselt, kein globaler Leak) ---
  function injectStyle() {
    if (document.getElementById("ant-colony-style")) return;
    var css = [
      ".ant-colony{position:fixed;left:0;right:0;bottom:0;height:34vh;min-height:230px;",
        "z-index:3;pointer-events:none;overflow:hidden;}",
      /* dezenter Boden, passt zum Schwarz/Bloom-Theme */
      ".ant-colony::before{content:'';position:absolute;left:0;right:0;bottom:0;height:46%;",
        "background:linear-gradient(180deg,rgba(0,0,0,0) 0%,rgba(10,7,4,.0) 20%,",
        "rgba(30,18,8,.32) 70%,rgba(40,22,8,.5) 100%);}",
      ".ant{position:absolute;bottom:0;will-change:transform;",
        "transform-origin:50% 100%;filter:drop-shadow(0 6px 10px rgba(0,0,0,.6));}",
      ".ant img{display:block;height:100%;width:auto;image-rendering:auto;}",
      ".ant.queen{filter:drop-shadow(0 0 16px rgba(255,180,70,.45)) ",
        "drop-shadow(0 8px 14px rgba(0,0,0,.7));}",
      ".ant.active{filter:drop-shadow(0 0 12px rgba(56,224,255,.7)) ",
        "drop-shadow(0 6px 10px rgba(0,0,0,.6));}",
      ".ant .ant-label{position:absolute;left:50%;bottom:100%;transform:translateX(-50%);",
        "margin-bottom:3px;font-size:10px;letter-spacing:.03em;color:#cfe7ff;",
        "background:rgba(8,12,20,.7);border:1px solid rgba(56,224,255,.25);",
        "border-radius:6px;padding:1px 6px;white-space:nowrap;opacity:0;",
        "transition:opacity .4s;text-shadow:0 0 6px rgba(56,224,255,.4);}",
      ".ant.active .ant-label{opacity:.92;}",
      ".ant-colony .ant-caption{position:absolute;left:50%;bottom:4px;transform:translateX(-50%);",
        "font-size:11px;color:#9fd0ff;opacity:.5;letter-spacing:.06em;",
        "pointer-events:none;text-shadow:0 0 8px rgba(0,0,0,.8);}"
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
    // Dreiviertel-Ansicht für die krabbelnden Soldaten wirkt lebendiger,
    // Frontansicht für die stehende Königin.
    img.src = cls === "queen" ? pair[0] : pair[1];
    img.alt = role + "-Ameise";
    img.loading = "eager";
    wrap.appendChild(img);
    return wrap;
  }

  var host, soldiers = [], queenEl = null, raf = 0;

  function buildColony(soldierNodes) {
    if (!host) {
      host = document.createElement("div");
      host.className = "ant-colony";
      host.setAttribute("aria-hidden", "true");
      var cap = document.createElement("div");
      cap.className = "ant-caption";
      cap.textContent = "🐜 Das Ameisenvolk · Königin + " + soldierNodes.length + " Soldaten";
      host.appendChild(cap);
      // In den Haupt-Inhaltsbaum einhängen (nicht body): stellt sicher, dass das
      // Overlay zuverlässig ÜBER dem WebGL-Partikelfeld kompositiert wird.
      var mountTarget = document.querySelector("main") || document.body;
      mountTarget.appendChild(host);

      // Königin prominent in der Mitte.
      queenEl = makeAnt("queen", "queen", Math.round(window.innerHeight * 0.26));
      host.appendChild(queenEl);
    }

    // Vorhandene Soldaten-Ameisen entfernen und neu aufbauen (Status-Refresh).
    soldiers.forEach(function (s) { if (s.el && s.el.parentNode) s.el.parentNode.removeChild(s.el); });
    soldiers = [];

    var W = window.innerWidth;
    var baseH = Math.max(70, Math.round(window.innerHeight * 0.12));
    soldierNodes.forEach(function (n, i) {
      var name = (n.label || n.id || "").replace(/^soldier:/, "");
      var role = roleFor(name);
      var findings = (n.counts && n.counts.findings) || 0;
      var active = findings > 0;
      // leichte Größen-Staffelung für Tiefe
      var depth = 0.82 + ((i % 5) * 0.06);
      var h = Math.round(baseH * depth);
      var el = makeAnt(role, active ? "active" : "", h);
      var label = document.createElement("span");
      label.className = "ant-label";
      label.textContent = name + (findings ? " · " + findings : "");
      el.appendChild(label);
      host.appendChild(el);

      soldiers.push({
        el: el, name: name, active: active,
        x: Math.random() * W,
        // aktive Soldaten laufen lebhafter
        vx: (Math.random() < 0.5 ? -1 : 1) * (active ? 14 : 7) * (0.6 + Math.random() * 0.8),
        bob: Math.random() * Math.PI * 2,
        bobSpd: (active ? 5.2 : 3.2) + Math.random() * 1.5,
        yOff: (i % 5) * (baseH * 0.12), // Tiefenversatz nach unten
        h: h, face: 1, z: Math.round(depth * 100)
      });
      el.style.zIndex = String(soldiers[soldiers.length - 1].z);
    });

    layoutStatic();
  }

  function layoutStatic() {
    if (queenEl) {
      queenEl.style.left = "50%";
      queenEl.style.transform = "translateX(-50%)";
      queenEl.style.zIndex = "120";
    }
  }

  var last = 0;
  function tick(now) {
    var dt = last ? Math.min(0.05, (now - last) / 1000) : 0.016;
    last = now;
    var W = window.innerWidth;
    for (var i = 0; i < soldiers.length; i++) {
      var s = soldiers[i];
      if (!reduce) {
        s.x += s.vx * dt;
        s.bob += s.bobSpd * dt;
        if (s.x < -60) { s.x = W + 40; }
        else if (s.x > W + 60) { s.x = -40; }
        s.face = s.vx >= 0 ? 1 : -1;
      }
      var bobY = reduce ? 0 : Math.sin(s.bob) * (s.active ? 5 : 3);
      var tilt = reduce ? 0 : Math.sin(s.bob) * (s.active ? 2.4 : 1.4);
      s.el.style.left = s.x + "px";
      s.el.style.bottom = s.yOff + "px";
      s.el.style.transform =
        "scaleX(" + s.face + ") translateY(" + (-bobY) + "px) rotate(" + tilt + "deg)";
    }
    raf = requestAnimationFrame(tick);
  }

  function start(soldierNodes) {
    injectStyle();
    buildColony(soldierNodes);
    if (raf) cancelAnimationFrame(raf);
    last = 0;
    raf = requestAnimationFrame(tick);
  }

  function loadAndStart() {
    fetch("/api/brain/nodes")
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (g) {
        var sol = (g && g.nodes ? g.nodes : []).filter(function (n) { return n.type === "soldier"; });
        // Fallback: falls (noch) keine Soldaten gemeldet werden, ruhiges 18er-Volk.
        if (!sol.length) {
          var FALLBACK = Object.keys(NAME_ROLE);
          sol = FALLBACK.map(function (name) {
            return { type: "soldier", label: name, id: "soldier:" + name, counts: { findings: 0 } };
          });
        }
        start(sol);
      })
      .catch(function () {
        var FALLBACK = Object.keys(NAME_ROLE);
        start(FALLBACK.map(function (name) {
          return { type: "soldier", label: name, id: "soldier:" + name, counts: { findings: 0 } };
        }));
      });
  }

  // Periodischer Status-Refresh (an Soldaten-Aktivität gekoppelt), schonend.
  function schedule() { setInterval(loadAndStart, 20000); }

  function init() { loadAndStart(); schedule(); }
  if (document.readyState === "loading")
    document.addEventListener("DOMContentLoaded", init);
  else init();

  window.addEventListener("resize", function () {
    // leichte Re-Layout-Hilfe bei Größenänderung (kein Vollneuaufbau nötig)
    if (queenEl) queenEl.style.height = Math.round(window.innerHeight * 0.26) + "px";
  });
})();
