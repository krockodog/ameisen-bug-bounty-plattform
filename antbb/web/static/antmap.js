/* antbb – Schwarm-Karte: Geometrie + Zustand + Interaktion.
 * Die eigentliche Bühne (gemaltes Nest-Querschnitt-Artwork, Kammer-Lampen,
 * fremde Ausgrabung = Scope) malt antmap_colony.js IMMER als Layer 0.
 * Dieses File ist die EINZIGE Geometrie-/Zustands-Quelle: es berechnet, wo
 * Thron (Königin) und die Agenten-Kammern im Artwork liegen, und stellt sie
 * über getSnapshot() dem 3D-Sprite-Layer (antmap3d.js) und der Bühne bereit.
 * Kein schwebender Hügel, keine Magenta-Amöbe mehr.
 */
(function () {
  "use strict";
  const wrap = document.getElementById("antmap-wrap");
  const canvas = document.getElementById("antmap");
  if (!wrap || !canvas) return;
  const ctx = canvas.getContext("2d");
  const tip = document.getElementById("antmap-tip");
  const modeLine = document.getElementById("map-mode-line");
  const REDUCED = window.matchMedia &&
    window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  const COL = {
    idle: "#7d8799", running: "#ffcf7a", done: "#ffe4a8", blocked: "#ff4d6a",
    cyan: "#38e0ff", green: "#3fff9d", magenta: "#ff3df0", amber: "#ffc24d",
    queen: "#ffd36e", soldier: "#9fd0ff", scout: "#7affd1", bg0: "#151b2e",
    bg1: "#080b14"
  };

  // ---- Topologie: 9 reale Agenten -> je eine Kammer -----------------------
  const AGENTS = ["recon", "mobile", "scanning", "api", "infra", "osint",
                  "cloud", "auth", "llmsec", "fuzz", "verify",
                  "analysis", "threatintel", "poc", "reporting"];
  const ROLE = {
    recon: "Recon-Master", mobile: "Mobile-Hunter", scanning: "Web-Hunter",
    api: "API-Tester", infra: "Network-Hunter", osint: "OSINT-Hunter",
    cloud: "Cloud-Hunter", auth: "Auth-Specialist", llmsec: "LLM-Security",
    fuzz: "Fuzzer (offensiv)", verify: "Payload-Specialist (aktiv)",
    analysis: "Red-Team-Operator", threatintel: "Threat-Intel", poc: "Exploit-Developer",
    reporting: "Report-Engineer"
  };
  const LABEL = {
    recon: "Recon", mobile: "Mobile", scanning: "Web", api: "API",
    infra: "Netz", osint: "OSINT", cloud: "Cloud", auth: "Auth",
    llmsec: "LLM", fuzz: "Fuzzer", verify: "Verify", analysis: "Analyse",
    threatintel: "Intel", poc: "PoC", reporting: "Report"
  };
  const AREAS = [{ id: "web", label: "Web" }];

  let mode = (window.ANTBB && window.ANTBB.mode) || { effective_mode: "defensive", offensive_allowed: false };
  const targetId = window.ANTBB ? window.ANTBB.targetId : null;

  function mkNode(o) {
    return Object.assign({
      x: 0, y: 0, px: 0, py: 0, tx: 0, ty: 0,
      state: "idle", task: "wartet auf Befehl", scope: "", findings: 0,
      phase: Math.random() * Math.PI * 2
    }, o);
  }
  const nodes = {};
  nodes.queen = mkNode({ id: "queen", kind: "queen", label: "Königin", role: "Orchestrator (neuronales Gehirn)" });
  nodes.ants = {};
  AGENTS.forEach((n, i) => {
    nodes.ants[n] = mkNode({ id: n, kind: "ant", label: LABEL[n], role: ROLE[n], lane: i });
  });
  nodes.masters = [];
  AREAS.forEach((a, ai) => {
    ["scout", "off", "def"].forEach((rk) => {
      const labels = { scout: "Scout", off: "Offensiv-Master", def: "Defensiv-Master" };
      const roles = {
        scout: "kartiert das Ziel von außen (läuft zuerst raus)",
        off: "gräbt sich ins Ziel – nur bei effektiv offensiv",
        def: "bleibt im Nest, überwacht von innen"
      };
      nodes.masters.push(mkNode({
        id: a.id + "-" + rk, kind: "master", mrole: rk, area: a.label,
        label: labels[rk] + " · " + a.label, role: roles[rk], areaIdx: ai
      }));
    });
  });

  function allNodes() {
    return [nodes.queen, ...nodes.masters, ...AGENTS.map(n => nodes.ants[n])];
  }

  // ---- Geometrie: Bühne (Kolonie links, Ausgrabung rechts) ----------------
  let W = 0, H = 0, DPR = 1, narrow = false;
  let COLONY = { x: 0, y: 0, w: 0, h: 0 };   // Bereich fürs gemalte Nest
  let EXCAV = { x: 0, y: 0, w: 0, h: 0, cols: 4, rows: 4 }; // fremdes Ziel
  let THRONE = { x: 0, y: 0 };
  let SEAM = { x0: 0, y0: 0, x1: 0, y1: 0 };
  let TUNNEL = { x1: 0, y1: 0, x2: 0, y2: 0 };
  // Kammer-Anker fraktional (vom Kolonie-Bereich). Mitte bleibt für Thron frei.
  const CHAM_PC = [
    [0.12, 0.24], [0.12, 0.52], [0.14, 0.80],   // linke Galerie (3)
    [0.86, 0.24], [0.86, 0.52], [0.84, 0.80],   // rechte Galerie (3)
    [0.35, 0.85], [0.65, 0.85], [0.50, 0.14]    // unten 2 + oben 1
  ];
  const CHAM_PHONE = [
    [0.12, 0.20], [0.30, 0.12], [0.70, 0.12], [0.88, 0.20],
    [0.10, 0.52], [0.90, 0.52], [0.32, 0.60], [0.68, 0.60], [0.50, 0.66]
  ];

  function layout() {
    DPR = Math.min(window.devicePixelRatio || 1, 2);
    const cw = wrap.clientWidth || 900;
    narrow = cw < 560;
    const ch = narrow ? Math.round(cw * 1.06) : Math.round(cw * 0.52);
    W = cw; H = ch;
    canvas.width = Math.round(W * DPR); canvas.height = Math.round(H * DPR);
    canvas.style.width = W + "px"; canvas.style.height = H + "px";
    ctx.setTransform(DPR, 0, 0, DPR, 0, 0);

    const cham = narrow ? CHAM_PHONE : CHAM_PC;
    if (narrow) {
      COLONY = { x: 0, y: 0, w: W, h: Math.round(H * 0.56) };
      EXCAV = { x: W * 0.06, y: H * 0.635, w: W * 0.88, h: H * 0.33, cols: 5, rows: 3 };
      THRONE = { x: W * 0.50, y: COLONY.h * 0.40 };
      SEAM = { x0: 0, y0: COLONY.h, x1: W, y1: COLONY.h };
      TUNNEL = { x1: THRONE.x, y1: THRONE.y + 30, x2: W * 0.50, y2: EXCAV.y + EXCAV.h / 2 };
    } else {
      COLONY = { x: 0, y: 0, w: Math.round(W * 0.605), h: H };
      EXCAV = { x: W * 0.645, y: H * 0.12, w: W * 0.335, h: H * 0.78, cols: 4, rows: 4 };
      THRONE = { x: COLONY.w * 0.50, y: H * 0.46 };
      SEAM = { x0: COLONY.w, y0: 0, x1: COLONY.w, y1: H };
      TUNNEL = { x1: THRONE.x + 40, y1: THRONE.y + 10, x2: EXCAV.x, y2: EXCAV.y + EXCAV.h * 0.5 };
    }
    // Agenten-Kammern im Kolonie-Bereich verankern
    AGENTS.forEach((n, i) => {
      const f = cham[i] || [0.5, 0.5];
      nodes.ants[n].homeX = COLONY.x + f[0] * COLONY.w;
      nodes.ants[n].homeY = COLONY.y + f[1] * COLONY.h;
    });
    buildGrain();
  }

  let grain = null;
  function buildGrain() {
    grain = document.createElement("canvas");
    grain.width = Math.max(1, Math.round(W)); grain.height = Math.max(1, Math.round(H));
    const g = grain.getContext("2d");
    const n = Math.round(W * H / 1400);
    for (let i = 0; i < n; i++) {
      const a = Math.random() * 0.03;
      g.fillStyle = "rgba(255,225,180," + a.toFixed(3) + ")";
      g.fillRect(Math.random() * W, Math.random() * H, 1, 1);
    }
  }

  // ---- Zustands-Updates von der API --------------------------------------
  function updateAgents(agents, queen) {
    if (agents) {
      AGENTS.forEach(n => {
        const a = agents[n];
        if (!a) return;
        const nd = nodes.ants[n];
        nd.state = a.state || "idle";
        nd.task = a.task || nd.task;
        nd.scope = a.scope || "";
        nd.findings = a.findings || 0;
      });
    }
    if (queen) {
      nodes.queen.commanding = !!queen.active;
      nodes.queen.cmdAgents = queen.command_agents || [];
      nodes.queen.task = queen.last_msg ? queen.last_msg.slice(0, 80) : nodes.queen.task;
    }
  }
  function setMode(m) { if (m) { mode = m; refreshModeLine(); } }
  function refreshModeLine() {
    if (!modeLine) return;
    const off = mode.effective_mode === "offensive";
    modeLine.innerHTML = "Effektiver Modus: <b style='color:" +
      (off ? COL.magenta : COL.cyan) + "'>" + (off ? "OFFENSIV" : "DEFENSIV") +
      "</b> — " + (off
        ? "Scout &amp; Offensiv-Master graben sich durch den Tunnel ins Ziel."
        : "Agenten inspizieren das Ziel nur von außen; Offensiv-Master bleibt im Nest.") +
      (mode.reason ? " · " + mode.reason : "");
  }

  // ---- Ziel-Positionen (statische Anker, sanftes Lerp) --------------------
  function lerpP(a, b, p) { return { x: a.x + (b.x - a.x) * p, y: a.y + (b.y - a.y) * p }; }
  function computeTargets(t) {
    const off = mode.effective_mode === "offensive";
    nodes.queen.tx = THRONE.x; nodes.queen.ty = THRONE.y;
    AGENTS.forEach((n) => {
      const nd = nodes.ants[n];
      nd.tx = nd.homeX; nd.ty = nd.homeY;
    });
    const tunnelMid = lerpP({ x: TUNNEL.x1, y: TUNNEL.y1 }, { x: TUNNEL.x2, y: TUNNEL.y2 }, 0.58);
    nodes.masters.forEach((m) => {
      if (m.mrole === "def") {
        m.tx = THRONE.x - 46; m.ty = THRONE.y + 18; m._out = false;
      } else if (m.mrole === "scout") {
        const reconRunning = nodes.ants.recon && nodes.ants.recon.state === "running";
        if (reconRunning || off) { m.tx = tunnelMid.x - 14; m.ty = tunnelMid.y - 10; m._out = true; }
        else { m.tx = THRONE.x + 44; m.ty = THRONE.y + 18; m._out = false; }
      } else { // offensiver Master
        if (off) { m.tx = tunnelMid.x + 16; m.ty = tunnelMid.y + 12; m._out = true; }
        else { m.tx = THRONE.x + 30; m.ty = THRONE.y + 30; m._out = false; }
      }
    });
  }

  // ---- Zeichnen (nur Fallback-Figuren; Bühne liegt in antmap_colony.js) ---
  function clamp(v, a, b) { return Math.max(a, Math.min(b, v)); }
  function is3D() { return !!(window.__antmap3d && window.__antmap3d.active); }
  function stateColor(st) { return COL[st] || COL.idle; }

  function drawBG() {
    ctx.clearRect(0, 0, W, H);
    // leichte, warme Rand-Vignette; Mitte frei, damit das Artwork strahlt
    if (grain) { ctx.globalAlpha = 0.6; ctx.drawImage(grain, 0, 0); ctx.globalAlpha = 1; }
  }

  function drawQueenGlyph(nd, t) {
    const pulse = REDUCED ? 0.5 : (0.5 + 0.5 * Math.sin(t * 1.4));
    const r = 20;
    const g = ctx.createRadialGradient(nd.x, nd.y, 2, nd.x, nd.y, r * 2.6);
    g.addColorStop(0, "rgba(255,221,140,0.55)");
    g.addColorStop(0.5, "rgba(255,170,90,0.16)");
    g.addColorStop(1, "rgba(0,0,0,0)");
    ctx.fillStyle = g;
    ctx.beginPath(); ctx.arc(nd.x, nd.y, r * 2.6, 0, Math.PI * 2); ctx.fill();
    const cg = ctx.createRadialGradient(nd.x, nd.y - 2, 1, nd.x, nd.y, r);
    cg.addColorStop(0, "#fff3cf"); cg.addColorStop(1, "#d98a2c");
    ctx.fillStyle = cg; ctx.shadowColor = COL.queen; ctx.shadowBlur = 18 + pulse * 6;
    ctx.beginPath(); ctx.arc(nd.x, nd.y, r * (0.74 + pulse * 0.05), 0, Math.PI * 2); ctx.fill();
    ctx.shadowBlur = 0;
    ctx.fillStyle = "#fff6da"; ctx.font = "16px system-ui"; ctx.textAlign = "center";
    ctx.fillText("👑", nd.x, nd.y - r - 6);
    ctx.fillStyle = "rgba(255,236,196,0.92)"; ctx.font = "600 11px system-ui";
    ctx.fillText("Königin · tippen = Kammer", nd.x, nd.y + r + 15);
  }

  function drawAntGlyph(nd) {
    const col = stateColor(nd.state);
    ctx.save();
    ctx.translate(nd.x, nd.y);
    // warmes Kammer-Lämpchen + Chitin-Körper
    ctx.fillStyle = col; ctx.shadowColor = col; ctx.shadowBlur = 10;
    [[-4, 1.9], [0, 2.5], [4.4, 2.1]].forEach(([ox, rr]) => {
      ctx.beginPath(); ctx.ellipse(ox, 0, rr, rr * 0.72, 0, 0, Math.PI * 2); ctx.fill();
    });
    ctx.restore(); ctx.shadowBlur = 0;
    ctx.fillStyle = "rgba(255,236,200,0.85)"; ctx.font = "600 9px system-ui"; ctx.textAlign = "center";
    ctx.fillText(nd.label, nd.x, nd.y - 9);
  }

  function drawMasterGlyph(nd, t) {
    const off = mode.effective_mode === "offensive";
    let col = COL.soldier;
    if (nd.mrole === "scout") col = COL.scout;
    else if (nd.mrole === "off") col = nd._out ? COL.magenta : COL.idle;
    else col = COL.green;
    const r = 7;
    ctx.save();
    ctx.translate(nd.x, nd.y);
    ctx.beginPath();
    if (nd.mrole === "scout") {
      ctx.moveTo(0, -r); ctx.lineTo(r * 0.9, r * 0.8); ctx.lineTo(0, r * 0.4);
      ctx.lineTo(-r * 0.9, r * 0.8); ctx.closePath();
    } else {
      ctx.arc(0, 0, r, 0, Math.PI * 2);
    }
    ctx.fillStyle = "rgba(14,20,34,0.9)"; ctx.fill();
    ctx.lineWidth = 1.8; ctx.strokeStyle = col;
    ctx.shadowColor = col; ctx.shadowBlur = 10; ctx.stroke();
    ctx.restore(); ctx.shadowBlur = 0;
    ctx.fillStyle = "rgba(220,232,255,0.8)"; ctx.font = "9px system-ui"; ctx.textAlign = "center";
    const lbl = nd.mrole === "scout" ? "Scout" : (nd.mrole === "off" ? "Off-Master" : "Def-Master");
    ctx.fillText(lbl, nd.x, nd.y + r + 11);
  }

  // ---- Render-Schleife ----------------------------------------------------
  let t0 = performance.now();
  function frame(now) {
    const t = (now - t0) / 1000;
    computeTargets(t);
    const ease = REDUCED ? 1 : 0.10;
    allNodes().forEach(nd => {
      nd.px = nd.x; nd.py = nd.y;
      if (nd.x === 0 && nd.y === 0) { nd.x = nd.tx; nd.y = nd.ty; }
      nd.x += (nd.tx - nd.x) * ease;
      nd.y += (nd.ty - nd.y) * ease;
    });
    drawBG();
    // Figuren übernimmt der 3D-Sprite-Layer; nur im Fallback malen wir Glyphen.
    if (!is3D()) {
      AGENTS.forEach(n => drawAntGlyph(nodes.ants[n]));
      nodes.masters.forEach(m => drawMasterGlyph(m, t));
      drawQueenGlyph(nodes.queen, t);
    }
    requestAnimationFrame(frame);
  }

  // ---- Hit-Test / Tooltip -------------------------------------------------
  function hit(mx, my) {
    const cand = [{ nd: nodes.queen, r: 30, name: "Königin" }];
    nodes.masters.forEach(m => cand.push({ nd: m, r: 15, name: m.label }));
    AGENTS.forEach(n => cand.push({ nd: nodes.ants[n], r: 20, name: n }));
    let best = null, bd = 1e9;
    cand.forEach(c => {
      const d = Math.hypot(c.nd.x - mx, c.nd.y - my);
      if (d < c.r && d < bd) { bd = d; best = c; }
    });
    return best;
  }
  function showTip(c, cx, cy) {
    const nd = c.nd;
    let html = "<b>" + (nd.label || c.name) + "</b>";
    if (nd.role) html += "<br><span class='r'>" + nd.role + "</span>";
    if (nd.kind === "ant" || nd.kind === "queen" || nd.kind === "master") {
      const st = nd.state || (nd.kind === "queen" ? (nd.commanding ? "running" : "idle") : "idle");
      html += "<br>Zustand: <b style='color:" + stateColor(st) + "'>" + stLabel(st) + "</b>";
      if (nd.task) html += "<br>Aufgabe: " + esc(nd.task);
      if (nd.scope) html += "<br>Scope: " + esc(nd.scope);
      if (nd.findings) html += "<br>Findings: " + nd.findings;
      if (nd.kind === "master") html += "<br>Bereich: " + esc(nd.area || "Web") +
        (nd._out ? " · <b style='color:" + COL.magenta + "'>im Tunnel</b>" : " · <b>im Nest</b>");
    }
    tip.innerHTML = html; tip.hidden = false;
    const tw = tip.offsetWidth, th = tip.offsetHeight;
    tip.style.left = clamp(cx + 12, 4, W - tw - 4) + "px";
    tip.style.top = clamp(cy + 12, 4, H - th - 4) + "px";
  }
  function stLabel(s) {
    return { idle: "idle", running: "läuft", done: "fertig", blocked: "geblockt" }[s] || s;
  }
  function esc(s) { return String(s).replace(/[<>&]/g, c => ({ "<": "&lt;", ">": "&gt;", "&": "&amp;" }[c])); }

  function relPos(e) {
    const r = canvas.getBoundingClientRect();
    const p = (e.touches && e.touches[0]) || e;
    return { x: p.clientX - r.left, y: p.clientY - r.top };
  }
  canvas.addEventListener("mousemove", e => {
    const { x, y } = relPos(e);
    const c = hit(x, y);
    if (c) { canvas.style.cursor = "pointer"; showTip(c, x, y); }
    else { canvas.style.cursor = "default"; tip.hidden = true; }
  });
  canvas.addEventListener("mouseleave", () => { tip.hidden = true; });
  function tap(e) {
    const { x, y } = relPos(e);
    const c = hit(x, y);
    if (!c) { tip.hidden = true; return; }
    if (c.nd.kind === "queen") { e.preventDefault(); toggleChamber(); return; }
    showTip(c, x, y);
  }
  canvas.addEventListener("click", tap);
  canvas.addEventListener("touchstart", tap, { passive: false });

  // ---- Königin-Kammer -----------------------------------------------------
  const chamber = document.getElementById("queen-chamber");
  const cbody = document.getElementById("chamber-body");
  let brainData = null, curTab = "brain";
  function toggleChamber() {
    const open = chamber.classList.toggle("open");
    chamber.setAttribute("aria-hidden", open ? "false" : "true");
    if (open && !brainData) loadBrain();
    else if (open) renderTab();
  }
  const cxb = document.getElementById("chamber-close");
  if (cxb) cxb.addEventListener("click", () => { chamber.classList.remove("open"); chamber.setAttribute("aria-hidden", "true"); });
  document.querySelectorAll(".ctab").forEach(b => {
    b.addEventListener("click", () => {
      document.querySelectorAll(".ctab").forEach(x => x.classList.remove("active"));
      b.classList.add("active"); curTab = b.dataset.tab; renderTab();
    });
  });
  async function loadBrain() {
    cbody.innerHTML = "<p class='hint'>lädt Gedächtnis…</p>";
    try {
      const r = await fetch("/api/brain/" + targetId);
      brainData = await r.json();
    } catch (e) { cbody.innerHTML = "<p class='blocked'>Fehler beim Laden.</p>"; return; }
    renderTab();
  }
  function renderTab() {
    if (!brainData) return;
    if (curTab === "brain") renderBrain();
    else if (curTab === "memgraph") renderMemgraph();
    else renderMemories();
  }
  function renderBrain() {
    const b = brainData.brain;
    let h = "<div class='cham-sec'><h4>🧠 Neuronales Gehirn</h4>";
    h += "<p>Policy: <b>" + b.mode_policy + "</b> · Effektiv: <b style='color:" +
      (b.effective_mode === "offensive" ? COL.magenta : COL.cyan) + "'>" + b.effective_mode + "</b></p>";
    h += "<p>Oversight: " + (b.oversight ? "<b style='color:" + COL.green + "'>✔ gesetzt</b>" : "<b style='color:" + COL.blocked + "'>✘ fehlt</b>") +
      " · In-Scope: <b>" + b.in_scope_count + "</b> · Agenten: <b>" + b.agent_count + "</b></p>";
    h += "<p class='r'>" + esc(b.reason) + "</p>";
    h += "<p><b>Verhaltensregeln:</b></p><ul class='cham-list'>";
    b.rules.forEach(r => h += "<li>" + esc(r) + "</li>");
    h += "</ul>";
    h += "<div class='cham-links'>" +
      "<a href='#mode-card' onclick=\"document.querySelector('.mode-card').scrollIntoView({behavior:'smooth'});return true;\">↗ Modus-Steuerung</a> · " +
      "<a href='#swarm' onclick=\"document.getElementById('swarm').scrollIntoView({behavior:'smooth'});return true;\">↗ Swarm-Control</a></div>";
    h += "</div>";
    // ---- Capability-Registry (Skills/Playbooks/Tools je Soldat) ----
    const cap = b.capabilities;
    if (cap && cap.soldiers) {
      h += "<div class='cham-sec'><h4>👑 Capability-Registry (Königin-Gedächtnis)</h4>";
      h += "<p>Soldaten: <b>" + cap.soldier_count + "</b> · Playbooks: <b>" +
        cap.playbook_count + "</b> · Tools: <b>" + cap.tool_count + "</b></p>";
      h += "<p class='r'>Beim Start frisch aus den Soldaten aufgebaut (Single Source of Truth). Keine Secrets.</p>";
      h += "<ul class='cham-list'>";
      cap.soldiers.forEach(function (so) {
        h += "<li><b>" + esc(so.specialty) + "</b> <span class='r'>(" + esc(so.name) + ")</span>";
        if (so.playbooks && so.playbooks.length) {
          h += "<ul class='cham-list'>";
          so.playbooks.forEach(function (pb) {
            const gate = pb.oversight_required ? "OVERSIGHT" : "frei";
            const col = pb.mode === "offensive" ? COL.magenta : COL.cyan;
            h += "<li><span style='color:" + col + "'>[" + esc(pb.mode) + "/" + gate + "]</span> " +
              esc(pb.name) + " <span class='r'>· " + esc((pb.tools || []).join(", ")) + "</span></li>";
          });
          h += "</ul>";
        }
        h += "</li>";
      });
      h += "</ul></div>";
    }
    cbody.innerHTML = h;
  }
  function renderMemories() {
    const m = brainData.memories;
    let h = "<div class='cham-sec'><h4>📚 Memories</h4>";
    h += "<p><b>Scopes (" + m.scopes.length + ")</b></p>";
    if (m.scopes.length) {
      h += "<ul class='cham-list'>";
      m.scopes.forEach(s => h += "<li>" + esc(s.kind) + ": <code>" + esc(s.value) + "</code> " +
        (s.allowed ? "<span style='color:" + COL.green + "'>in-scope</span>" : "<span style='color:" + COL.blocked + "'>out</span>") + "</li>");
      h += "</ul>";
    } else h += "<p class='r'>Noch keine Scopes gespeichert.</p>";
    h += "<p><b>Frühere Funde (" + m.findings_total + ")</b></p>";
    if (m.findings.length) {
      h += "<ul class='cham-list'>";
      m.findings.slice(0, 12).forEach(f => h += "<li class='sev-" + f.severity + "'><b>" + esc(f.severity) +
        "</b> " + esc(f.title) + " <span class='r'>· " + esc(f.asset) + "</span></li>");
      h += "</ul>";
      if (m.findings_total > 12) h += "<p class='r'>… und " + (m.findings_total - 12) + " weitere.</p>";
    } else h += "<p class='r'>Noch keine Funde gespeichert.</p>";
    h += "<p><b>Routinen</b></p><p class='r'>" + esc(m.routines_note) + "</p>";
    h += "<p><b>Baseline-Messungen</b></p><p class='r'>" + esc(m.baselines_note) + "</p>";
    h += "</div>";
    cbody.innerHTML = h;
  }
  function renderMemgraph() {
    const g = brainData.memgraph;
    if (g.empty || !g.nodes.length) {
      cbody.innerHTML = "<div class='cham-sec'><h4>🕸️ Memgraph</h4>" +
        "<p class='r'>Noch keine Daten im Gedächtnis-Graph (keine Scopes/Funde gespeichert).</p></div>";
      return;
    }
    const w = Math.max(260, Math.min((cbody.clientWidth || 360) - 20, 520)), ht = 172;
    const cx0 = w / 2, cy0 = ht / 2;
    const pos = {};
    const ring = { target: 0, scope: 1, "scope-out": 1, finding: 2, severity: 3 };
    const counts = {};
    g.nodes.forEach(n => { const r = ring[n.type] || 2; counts[r] = (counts[r] || 0) + 1; });
    const seen = {};
    g.nodes.forEach(n => {
      const r = ring[n.type] || 2;
      seen[r] = (seen[r] || 0);
      const total = counts[r];
      const rad = r === 0 ? 0 : 22 + r * 40;
      const ang = total <= 1 ? -Math.PI / 2 : (seen[r] / total) * Math.PI * 2 - Math.PI / 2;
      pos[n.id] = { x: cx0 + Math.cos(ang) * rad, y: cy0 + Math.sin(ang) * rad * 0.70, n };
      seen[r]++;
    });
    const nc = { target: COL.queen, scope: COL.cyan, "scope-out": COL.blocked, finding: COL.amber, severity: COL.green };
    let svg = "<div class='cham-sec'><h4>🕸️ Memgraph</h4><p class='r'>Knoten: Target → Scopes → Funde → Severity</p>";
    svg += "<svg width='" + w + "' height='" + ht + "' class='memgraph-svg'>";
    g.edges.forEach(e => {
      const a = pos[e.from], b = pos[e.to];
      if (!a || !b) return;
      svg += "<line x1='" + a.x.toFixed(1) + "' y1='" + a.y.toFixed(1) + "' x2='" + b.x.toFixed(1) +
        "' y2='" + b.y.toFixed(1) + "' stroke='rgba(120,160,220,0.28)' stroke-width='1'/>";
    });
    Object.values(pos).forEach(p => {
      const col = nc[p.n.type] || COL.idle;
      const rr = p.n.type === "target" ? 9 : (p.n.type === "severity" ? 7 : 5);
      svg += "<circle cx='" + p.x.toFixed(1) + "' cy='" + p.y.toFixed(1) + "' r='" + rr +
        "' fill='" + col + "' opacity='0.9'><title>" + esc(p.n.label) + "</title></circle>";
      if (p.n.type === "target" || p.n.type === "severity")
        svg += "<text x='" + p.x.toFixed(1) + "' y='" + (p.y - rr - 3).toFixed(1) +
          "' fill='rgba(210,220,245,0.8)' font-size='9' text-anchor='middle'>" + esc(p.n.label) + "</text>";
    });
    svg += "</svg></div>";
    cbody.innerHTML = svg;
  }

  // ---- Status-Polling -----------------------------------------------------
  async function pollStatus() {
    try {
      const r = await fetch("/api/targets/" + targetId + "/scan/status");
      const d = await r.json();
      if (d.mode) setMode(d.mode);
      if (d.agents) updateAgents(d.agents, d.queen);
    } catch (e) {}
    setTimeout(pollStatus, 1600);
  }

  // ---- Bridge für Bühne (colony) + 3D-Sprite-Layer ------------------------
  window.AntMap = { updateAgents, setMode };
  window.AntMap.getSnapshot = function () {
    const q = nodes.queen;
    return {
      W: W, H: H, DPR: DPR, t: (performance.now() - t0) / 1000,
      mode: mode, effective: mode.effective_mode, narrow: narrow,
      stage: {
        colony: { x: COLONY.x, y: COLONY.y, w: COLONY.w, h: COLONY.h },
        excav: { x: EXCAV.x, y: EXCAV.y, w: EXCAV.w, h: EXCAV.h, cols: EXCAV.cols, rows: EXCAV.rows },
        seam: SEAM, tunnel: TUNNEL
      },
      throne: { x: THRONE.x, y: THRONE.y },
      queen: { x: q.x, y: q.y, state: q.commanding ? "running" : "idle", commanding: !!q.commanding },
      // Rückwärts-Kompatibilität: 3D liest "hill" als Thron-Anker, "carc" als Ziel.
      hill: { x: THRONE.x, y: THRONE.y },
      carc: { x: EXCAV.x + EXCAV.w / 2, y: EXCAV.y + EXCAV.h / 2, rx: EXCAV.w / 2, ry: EXCAV.h / 2 },
      soldiers: [],
      masters: nodes.masters.map(m => ({ id: m.id, mrole: m.mrole, x: m.x, y: m.y,
               px: m.px, py: m.py, out: !!m._out })),
      ants: AGENTS.map(n => { const a = nodes.ants[n];
        return { id: n, label: a.label, role: a.role, x: a.x, y: a.y, homeX: a.homeX, homeY: a.homeY,
                 state: a.state || "idle", findings: a.findings || 0,
                 commanding: !!(q.cmdAgents && q.cmdAgents.indexOf(n) >= 0) }; }),
      chambers: AGENTS.map(n => { const a = nodes.ants[n];
        return { id: n, label: a.label, role: a.role, x: a.homeX, y: a.homeY,
                 state: a.state || "idle", findings: a.findings || 0 }; })
    };
  };
  layout();
  refreshModeLine();
  window.addEventListener("resize", () => { layout(); });
  requestAnimationFrame(frame);
  pollStatus();
  if (location.hash.indexOf("#kammer") === 0) {
    var want = location.hash.split("-")[1] || "brain";
    document.querySelectorAll(".ctab").forEach(function(x){
      x.classList.toggle("active", x.dataset.tab === want); });
    curTab = want;
    chamber.classList.add("open");
    chamber.setAttribute("aria-hidden", "false");
    loadBrain();
  }
})();
