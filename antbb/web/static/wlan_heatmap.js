/* antbb 🐜 · WLAN-Coverage-Heatmap
 * Passiv: verortete RSSI-Messpunkte (echte Werte aus /api/wlan/scan) werden per
 * Klick auf einem Grundriss/Raster platziert, persistent gespeichert und als
 * IDW-interpolierte Heatmap (gut=grün → schlecht=rot) gerendert. Design: antbb
 * Schwarz-Theme + Ameisen-Look (Sprites laufen entlang Pheromonspur). Keine
 * Angriffe, nichts erfunden – ohne Scan ein ehrlicher Hinweis.
 */
(function () {
  "use strict";
  const TID = (typeof window.ANTBB_TARGET_ID !== "undefined" && window.ANTBB_TARGET_ID != null)
    ? window.ANTBB_TARGET_ID : null;
  const qs = (id) => document.getElementById(id);
  const tq = (q) => (TID ? (q + "target_id=" + TID) : q.replace(/[?&]$/, ""));

  let CANVAS, CTX, DATA = { points: [], aps: [], samples: [] };
  let FLOORPLAN_IMG = null;          // Image oder null
  let PENDING = null;                // {samples, ap_meta, ort} wartet auf Klick-Position
  let booted = false;
  let antPhase = 0;

  // ---- RSSI → Qualität/Farbe --------------------------------------------
  // gut -55, ok -67, schwach -75, funkloch darunter. t=0 (schlecht) .. 1 (gut)
  function rssiToT(rssi) {
    if (rssi == null) return null;
    const lo = -90, hi = -45;
    return Math.max(0, Math.min(1, (rssi - lo) / (hi - lo)));
  }
  function tColor(t, a) {
    // grün (gut) → gelb → rot (schlecht)
    const r = t < 0.5 ? 255 : Math.round(255 * (1 - (t - 0.5) * 2));
    const g = t > 0.5 ? 255 : Math.round(255 * (t * 2));
    return "rgba(" + r + "," + g + ",40," + (a == null ? 1 : a) + ")";
  }

  // ---- Daten laden -------------------------------------------------------
  async function loadData() {
    try {
      const r = await fetch("/api/wlan/heatmap?" + tq("?"));
      DATA = await r.json();
    } catch (e) { DATA = { points: [], aps: [], samples: [] }; }
    fillApSelect();
    render();
  }
  async function loadFloorplan() {
    try {
      const r = await fetch("/api/wlan/heatmap/floorplan?" + tq("?"));
      const j = await r.json();
      if (j && j.floorplan && j.floorplan.data_url) {
        const img = new Image();
        img.onload = function () { FLOORPLAN_IMG = img; render(); };
        img.src = j.floorplan.data_url;
      } else { FLOORPLAN_IMG = null; render(); }
    } catch (e) { FLOORPLAN_IMG = null; }
  }

  function fillApSelect() {
    const sel = qs("heat-ap");
    if (!sel) return;
    const cur = sel.value;
    sel.innerHTML = '<option value="__best__">Bestes Signal (aggregiert)</option>';
    (DATA.aps || []).forEach(a => {
      const o = document.createElement("option");
      o.value = a.bssid;
      o.textContent = (a.ssid || "(versteckt)") + " · " + a.bssid +
        (a.is_own ? " · eigen" : "") + (a.band ? " · " + a.band + "G" : "");
      sel.appendChild(o);
    });
    if ([...sel.options].some(o => o.value === cur)) sel.value = cur;
  }

  function selectedRssiAt(p) {
    const sel = qs("heat-ap");
    const mode = sel ? sel.value : "__best__";
    if (mode === "__best__") return p.best_rssi;
    return (p.rssi && p.rssi[mode] != null) ? p.rssi[mode] : null;
  }

  // ---- Rendering ---------------------------------------------------------
  function setStatus(msg, cls) {
    const s = qs("heat-status");
    if (s) { s.textContent = msg; s.className = "wlan-status" + (cls ? " " + cls : ""); }
  }

  function drawGrid(w, h) {
    CTX.fillStyle = "#05070c";
    CTX.fillRect(0, 0, w, h);
    CTX.strokeStyle = "rgba(56,224,255,0.08)";
    CTX.lineWidth = 1;
    const step = 40;
    for (let x = 0; x <= w; x += step) { CTX.beginPath(); CTX.moveTo(x, 0); CTX.lineTo(x, h); CTX.stroke(); }
    for (let y = 0; y <= h; y += step) { CTX.beginPath(); CTX.moveTo(0, y); CTX.lineTo(w, y); CTX.stroke(); }
  }

  function drawFloorplan(w, h) {
    try {
      CTX.globalAlpha = 0.55;
      CTX.drawImage(FLOORPLAN_IMG, 0, 0, w, h);
      CTX.globalAlpha = 1;
    } catch (e) {}
  }

  // IDW-Interpolation über ein grobes Gitter, dann weich gezeichnet
  function drawInterpolation(w, h, pts) {
    if (pts.length < 1) return;
    const cell = 14;                 // Auflösung der Interpolation (Performance)
    const power = 2.2;
    CTX.globalAlpha = 0.45;
    for (let gy = 0; gy < h; gy += cell) {
      for (let gx = 0; gx < w; gx += cell) {
        const px = gx + cell / 2, py = gy + cell / 2;
        let num = 0, den = 0, exact = null;
        for (const p of pts) {
          const dx = px - p.sx, dy = py - p.sy;
          const d2 = dx * dx + dy * dy;
          if (d2 < 1) { exact = p.t; break; }
          const wgt = 1 / Math.pow(d2, power / 2);
          num += wgt * p.t; den += wgt;
        }
        const t = exact != null ? exact : (den ? num / den : null);
        if (t == null) continue;
        CTX.fillStyle = tColor(t, 0.5);
        CTX.fillRect(gx, gy, cell, cell);
      }
    }
    CTX.globalAlpha = 1;
  }

  function drawPheromone(w, h, pts) {
    if (pts.length < 2) return;
    const ordered = pts.slice().sort((a, b) => (a.sx - b.sx) || (a.sy - b.sy));
    CTX.save();
    CTX.strokeStyle = "rgba(56,224,255,0.35)";
    CTX.lineWidth = 2;
    CTX.setLineDash([2, 8]);
    CTX.shadowColor = "rgba(56,224,255,0.6)"; CTX.shadowBlur = 8;
    CTX.beginPath();
    ordered.forEach((p, i) => { i ? CTX.lineTo(p.sx, p.sy) : CTX.moveTo(p.sx, p.sy); });
    CTX.stroke();
    CTX.restore();
    return ordered;
  }

  function drawAnt(x, y, ang) {
    CTX.save();
    CTX.translate(x, y); CTX.rotate(ang);
    CTX.fillStyle = "#12161f"; CTX.strokeStyle = "#d29922"; CTX.lineWidth = 1;
    [[-4, 2.6], [0, 3.2], [5, 2.4]].forEach(seg => {
      CTX.beginPath(); CTX.ellipse(seg[0], 0, seg[1], seg[1] * 0.75, 0, 0, Math.PI * 2);
      CTX.fill(); CTX.stroke();
    });
    CTX.strokeStyle = "rgba(210,153,34,0.9)";
    [[-1, -1], [-1, 1], [2, -1], [2, 1]].forEach(l => {
      CTX.beginPath(); CTX.moveTo(l[0], 0); CTX.lineTo(l[0] + l[1] * 3, l[1] * 4); CTX.stroke();
    });
    CTX.restore();
  }

  function render() {
    if (!CTX) return;
    const w = CANVAS.width, h = CANVAS.height;
    if (FLOORPLAN_IMG) { CTX.fillStyle = "#05070c"; CTX.fillRect(0, 0, w, h); drawFloorplan(w, h); }
    else drawGrid(w, h);

    const pts = (DATA.points || []).map(p => {
      const rssi = selectedRssiAt(p);
      return { sx: p.x * w, sy: p.y * h, rssi, t: rssiToT(rssi), ort: p.ort };
    }).filter(p => p.t != null);

    if (qs("heat-interp") && qs("heat-interp").checked) drawInterpolation(w, h, pts);

    let ordered = null;
    if (qs("heat-ants") && qs("heat-ants").checked) ordered = drawPheromone(w, h, pts);

    // Messpunkte als leuchtende Marker
    pts.forEach(p => {
      CTX.save();
      CTX.shadowColor = tColor(p.t, 1); CTX.shadowBlur = 14;
      CTX.fillStyle = tColor(p.t, 0.95);
      CTX.beginPath(); CTX.arc(p.sx, p.sy, 8, 0, Math.PI * 2); CTX.fill();
      CTX.restore();
      CTX.fillStyle = "#e8ecf5"; CTX.font = "11px system-ui";
      CTX.fillText((p.rssi != null ? p.rssi + "dBm" : "") + (p.ort ? " " + p.ort : ""), p.sx + 11, p.sy + 4);
    });

    // Ameisen entlang der Pheromonspur (dezent animiert)
    if (ordered && ordered.length >= 2) {
      for (let i = 0; i < ordered.length - 1; i++) {
        const a = ordered[i], b = ordered[i + 1];
        const f = (antPhase + i * 0.33) % 1;
        const x = a.sx + (b.sx - a.sx) * f, y = a.sy + (b.sy - a.sy) * f;
        drawAnt(x, y, Math.atan2(b.sy - a.sy, b.sx - a.sx));
      }
    }

    const c = qs("heat-count");
    if (c) c.textContent = (DATA.point_count || 0) + " Punkt(e) · " +
      (DATA.sample_count || 0) + " Messwert(e)";
  }

  function animate() {
    if ((qs("heat-ants") && qs("heat-ants").checked) && (DATA.points || []).length >= 2) {
      antPhase = (antPhase + 0.006) % 1;
      render();
    }
    requestAnimationFrame(animate);
  }

  // ---- Messen (passiver Scan) + Platzieren ------------------------------
  async function measureHere() {
    setStatus("Passiver Scan läuft… (iw/nmcli)", "busy");
    let scan;
    try {
      const r = await fetch("/api/wlan/scan");
      scan = await r.json();
    } catch (e) { setStatus("Scan fehlgeschlagen: " + e, "err"); return; }
    const aps = (scan && scan.aps) || [];
    if (!aps.length) {
      setStatus(scan && scan.reason
        ? ("Kein Scan möglich: " + scan.reason + " – keine Fake-Daten.")
        : "Keine APs gefunden (ehrlich leer). Adapter/Rechte prüfen.", "warn");
      return;
    }
    const samples = {}, ap_meta = {};
    aps.forEach(a => {
      if (a.bssid && a.rssi != null) {
        samples[a.bssid] = a.rssi;
        ap_meta[a.bssid] = { ssid: a.ssid || "", channel: a.channel, band: a.band || "" };
      }
    });
    if (!Object.keys(samples).length) { setStatus("Scan ohne verwertbare RSSI-Werte.", "warn"); return; }
    PENDING = { samples, ap_meta, ort: (qs("heat-ort").value || "").trim() };
    const chk = qs("heat-place"); if (chk) { chk.disabled = false; chk.checked = true; }
    setStatus(Object.keys(samples).length + " AP(s) gemessen – jetzt auf die Karte klicken, um die Position zu setzen.", "ok");
  }

  async function placeAt(nx, ny) {
    if (!PENDING) return;
    setStatus("Speichere Messpunkt…", "busy");
    try {
      const body = {
        x: nx, y: ny, samples: PENDING.samples, ap_meta: PENDING.ap_meta,
        ort: PENDING.ort, own_bssids: [], target_id: TID
      };
      const r = await fetch("/api/wlan/heatmap/sample", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
      });
      if (!r.ok) throw new Error("HTTP " + r.status);
      setStatus("Messpunkt gespeichert.", "ok");
    } catch (e) { setStatus("Speichern fehlgeschlagen: " + e, "err"); return; }
    PENDING = null;
    const chk = qs("heat-place"); if (chk) { chk.checked = false; chk.disabled = true; }
    await loadData();
  }

  function onCanvasClick(ev) {
    if (!PENDING || !(qs("heat-place") && qs("heat-place").checked)) return;
    const rect = CANVAS.getBoundingClientRect();
    const nx = (ev.clientX - rect.left) / rect.width;
    const ny = (ev.clientY - rect.top) / rect.height;
    placeAt(Math.max(0, Math.min(1, nx)), Math.max(0, Math.min(1, ny)));
  }

  async function uploadFloorplan(file) {
    const reader = new FileReader();
    reader.onload = async function () {
      try {
        const r = await fetch("/api/wlan/heatmap/floorplan", {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ data_url: reader.result, filename: file.name,
            mime: file.type || "image/png", target_id: TID })
        });
        if (!r.ok) throw new Error("HTTP " + r.status);
        setStatus("Grundriss gesetzt.", "ok");
        await loadFloorplan();
      } catch (e) { setStatus("Grundriss-Upload fehlgeschlagen: " + e, "err"); }
    };
    reader.readAsDataURL(file);
  }

  async function clearFloorplan() {
    try { await fetch("/api/wlan/heatmap/floorplan?" + tq("?"), { method: "DELETE" }); } catch (e) {}
    FLOORPLAN_IMG = null; render();
  }

  async function clearAll() {
    if (!confirm("Alle Messpunkte dieser Heatmap löschen?")) return;
    try { await fetch("/api/wlan/heatmap?" + tq("?"), { method: "DELETE" }); } catch (e) {}
    await loadData();
  }

  function wire() {
    CANVAS = qs("heat-canvas"); if (!CANVAS) return;
    CTX = CANVAS.getContext("2d");
    CANVAS.addEventListener("click", onCanvasClick);
    qs("heat-measure").addEventListener("click", measureHere);
    qs("heat-clear").addEventListener("click", clearAll);
    qs("heat-ap").addEventListener("change", render);
    qs("heat-interp").addEventListener("change", render);
    qs("heat-ants").addEventListener("change", render);
    qs("heat-floorplan").addEventListener("change", (e) => {
      if (e.target.files && e.target.files[0]) uploadFloorplan(e.target.files[0]);
    });
    qs("heat-floorplan-clear").addEventListener("click", clearFloorplan);
    const fileLabel = document.querySelector(".wlan-file");
    if (fileLabel) fileLabel.addEventListener("click", () => qs("heat-floorplan").click());
    requestAnimationFrame(animate);
  }

  function boot() {
    if (booted) return; booted = true;
    wire(); loadFloorplan(); loadData();
  }

  window.addEventListener("antbb:wlan-tab", (e) => {
    if (e.detail && e.detail.tab === "heatmap") boot();
  });
  // Falls Deep-Link direkt auf heatmap
  document.addEventListener("DOMContentLoaded", () => {
    const panel = qs("wlan-panel-heatmap");
    if (panel && !panel.hidden) boot();
  });
})();
