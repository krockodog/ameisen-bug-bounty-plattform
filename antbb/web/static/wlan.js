/* antbb – Passive WLAN-Coverage/Site-Survey + Scan-first Zielauswahl.
 * KEINE Angriffe: Scan → klickbare AP-Liste → Auswahl füllt SSID/BSSID.
 * Adapter-Dropdown, Band-Filter, Suche, Auto-Refresh. honest-empty. */
(function () {
  "use strict";
  const TID = window.ANTBB_TARGET_ID || null;
  const root = document.getElementById("wlan-view");
  if (!root) return;

  function esc(s) {
    return (s == null ? "" : String(s)).replace(/[&<>"]/g, c =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  }
  function qs(id) { return document.getElementById(id); }

  const BANDCOL = { "2.4": "#ffcf7a", "5": "#7ad0ff", "6": "#b79fff" };
  function rssiColor(r) {
    if (r == null) return "#5a6172";
    if (r >= -60) return "#3fffa3";
    if (r >= -70) return "#9fe08a";
    if (r >= -80) return "#ffcf7a";
    return "#ff6b6b";
  }
  function signalBars(rssi) {
    // 0..4 Balken aus dBm
    let n = 0;
    if (rssi != null) {
      if (rssi >= -55) n = 4;
      else if (rssi >= -65) n = 3;
      else if (rssi >= -75) n = 2;
      else if (rssi >= -85) n = 1;
    }
    let h = '<span class="wlan-bars" title="' + (rssi != null ? rssi + " dBm" : "?") + '">';
    for (let i = 1; i <= 4; i++) {
      h += '<i class="' + (i <= n ? "on" : "") + '" style="height:' + (4 + i * 3) + 'px"></i>';
    }
    return h + "</span>";
  }

  // ---- shared selection (Offensiv-Panel hört mit) ----
  window.ANTBB_WLAN_SELECTED = window.ANTBB_WLAN_SELECTED || null;
  function selectAp(ap) {
    window.ANTBB_WLAN_SELECTED = ap;
    try {
      window.dispatchEvent(new CustomEvent("antbb:wlan-selected", { detail: ap }));
    } catch (e) {}
    renderSelectionBar();
    // Zeile highlighten
    root.querySelectorAll("tr.wlan-ap-row").forEach(tr => {
      tr.classList.toggle("selected", ap && tr.getAttribute("data-bssid") === ap.bssid);
    });
  }

  let ADAPTERS = [];
  let LAST_SCAN = { aps: [], tool: null, iface: "", reason: "", enabled: false, tools: {} };
  let LAST_SURVEY = null;
  let autoTimer = null;
  let busy = false;

  async function loadAdapters() {
    try {
      const r = await fetch("/api/wlan/adapters");
      const j = await r.json();
      ADAPTERS = j.adapters || [];
      return j;
    } catch (e) {
      ADAPTERS = [];
      return { adapters: [], reason: "Adapter-API nicht erreichbar." };
    }
  }

  function currentIface() {
    const el = qs("wlan-iface");
    return el && el.value ? el.value : "";
  }
  function currentBand() {
    const el = qs("wlan-band");
    return el && el.value ? el.value : "";
  }
  function currentQuery() {
    const el = qs("wlan-filter");
    return (el && el.value || "").trim().toLowerCase();
  }

  function filteredAps() {
    let aps = (LAST_SCAN.aps || []).slice();
    const band = currentBand();
    const q = currentQuery();
    if (band) aps = aps.filter(a => String(a.band) === band);
    if (q) {
      aps = aps.filter(a =>
        (a.ssid || "").toLowerCase().includes(q) ||
        (a.bssid || "").toLowerCase().includes(q) ||
        (a.encryption || "").toLowerCase().includes(q));
    }
    // Signal stärkste oben; fehlendes RSSI ans Ende; connected zuerst
    aps.sort((a, b) => {
      if (!!b.connected - !!a.connected) return (b.connected ? 1 : 0) - (a.connected ? 1 : 0);
      const ra = a.rssi == null ? -999 : a.rssi;
      const rb = b.rssi == null ? -999 : b.rssi;
      return rb - ra;
    });
    return aps;
  }

  async function doScan() {
    if (busy) return;
    busy = true;
    const status = qs("wlan-scan-status");
    if (status) {
      status.textContent = "Scan läuft… (nmcli/iw, kann ein paar Sekunden dauern)";
      status.className = "wlan-status busy";
    }
    const iface = currentIface();
    // Ein Aufruf: Survey mit scan=1 → frische APs + Kanal/Coverage/Empfehlungen
    const u = "/api/wlan/survey?" + (TID ? ("target_id=" + TID + "&") : "") +
      "scan=1" + (iface ? ("&iface=" + encodeURIComponent(iface)) : "");
    try {
      const r = await fetch(u);
      if (!r.ok) throw new Error("HTTP " + r.status);
      LAST_SURVEY = await r.json();
      const sc = LAST_SURVEY.scan || {};
      LAST_SCAN = {
        aps: LAST_SURVEY.aps || sc.aps || [],
        tool: sc.tool || null,
        iface: sc.iface || iface || "",
        reason: sc.reason || "",
        tools: LAST_SURVEY.tools || {},
        enabled: LAST_SURVEY.enabled
      };
      if (status) {
        const n = (LAST_SCAN.aps || []).length;
        if (n) {
          status.textContent = n + " AP(s) · tool=" + (LAST_SCAN.tool || "?") +
            (LAST_SCAN.iface ? (" · " + LAST_SCAN.iface) : "") +
            " – Zeile anklicken = Ziel wählen";
          status.className = "wlan-status ok";
        } else {
          status.textContent = LAST_SCAN.reason ||
            "Keine APs gefunden (ehrlich leer). Adapter/WLAN prüfen.";
          status.className = "wlan-status warn";
        }
      }
    } catch (e) {
      LAST_SCAN = { aps: [], tool: null, reason: "Scan fehlgeschlagen: " + e, tools: {} };
      LAST_SURVEY = null;
      if (status) {
        status.textContent = LAST_SCAN.reason;
        status.className = "wlan-status err";
      }
    }
    busy = false;
    renderBody();
  }

  async function loadSurveyOnly() {
    try {
      const u = "/api/wlan/survey?" + (TID ? ("target_id=" + TID + "&") : "") + "scan=0";
      LAST_SURVEY = await (await fetch(u)).json();
    } catch (e) {
      LAST_SURVEY = null;
    }
  }

  function renderShell() {
    let adapterOpts = '<option value="">auto (nmcli / alle)</option>';
    ADAPTERS.forEach(a => {
      const mark = a.preferred ? " ★ bevorzugt" : "";
      const caps = [];
      if (a.monitor) caps.push("monitor");
      if (a.injection) caps.push("injection");
      const extra = caps.length ? (" · " + caps.join("/")) : "";
      adapterOpts += '<option value="' + esc(a.iface) + '"' +
        (a.preferred ? ' selected' : '') + '>' +
        esc(a.label || a.iface) + esc(mark) + esc(extra) + "</option>";
    });

    root.innerHTML = `
      <div class="wlan-toolbar" id="wlan-toolbar">
        <div class="wlan-toolbar-row">
          <label class="wlan-field">Adapter
            <select id="wlan-iface">${adapterOpts}</select>
          </label>
          <label class="wlan-field">Band
            <select id="wlan-band">
              <option value="">alle</option>
              <option value="2.4">2.4 GHz</option>
              <option value="5">5 GHz</option>
              <option value="6">6 GHz</option>
            </select>
          </label>
          <label class="wlan-field grow">Suche
            <input type="search" id="wlan-filter" placeholder="SSID, BSSID, Security…" autocomplete="off">
          </label>
          <label class="wlan-field wlan-check">
            <input type="checkbox" id="wlan-autorefresh"> Auto-Refresh (30 s)
          </label>
          <button type="button" id="wlan-scan-btn" class="wlan-primary">🛰️ Scannen</button>
        </div>
        <div id="wlan-scan-status" class="wlan-status">Bereit – Scannen startet die Umgebungsaufnahme. Klick auf eine Zeile wählt das Ziel-WLAN.</div>
      </div>
      <div id="wlan-selection" class="wlan-selection empty">Kein WLAN ausgewählt – auf eine Zeile in der Liste klicken.</div>
      <div id="wlan-ap-table-wrap"></div>
      <div id="wlan-analysis"></div>
      <div id="wlan-points"></div>`;
    wireToolbar();
    renderSelectionBar();
    renderBody();
  }

  function renderSelectionBar() {
    const el = qs("wlan-selection");
    if (!el) return;
    const ap = window.ANTBB_WLAN_SELECTED;
    if (!ap) {
      el.className = "wlan-selection empty";
      el.innerHTML = "Kein WLAN ausgewählt – auf eine Zeile in der Liste klicken (kein Copy-Paste nötig).";
      return;
    }
    el.className = "wlan-selection active";
    el.innerHTML = `
      <div class="wlan-sel-main">
        <span class="wlan-sel-ssid">${esc(ap.ssid || "(versteckt)")}</span>
        ${ap.connected ? '<span class="badge wlan-badge-conn">verbunden</span>' : ""}
        <code class="wlan-sel-bssid">${esc(ap.bssid)}</code>
        <span class="badge" style="border-color:${BANDCOL[ap.band] || "#8a92a6"};color:${BANDCOL[ap.band] || "#8a92a6"};">${esc(ap.band || "?")} GHz</span>
        <span>Ch ${ap.channel ?? "?"}</span>
        <span style="color:${rssiColor(ap.rssi)};">${ap.rssi ?? "?"} dBm</span>
        <span class="badge">${esc(ap.encryption || "?")}</span>
      </div>
      <div class="wlan-sel-actions">
        <button type="button" id="wlan-use-engagement" title="SSID/BSSID ins Offensiv-Engagement übernehmen">→ Offensiv / Engagement</button>
        <button type="button" id="wlan-clear-sel" class="wlan-ghost">Auswahl löschen</button>
      </div>`;
    const clr = qs("wlan-clear-sel");
    if (clr) clr.onclick = () => selectAp(null);
    const use = qs("wlan-use-engagement");
    if (use) use.onclick = () => {
      // Offensiv-Tab öffnen + Event nochmal feuern
      const tab = document.querySelector('#wlan-tabs .wtab[data-tab="offensive"]');
      if (tab) tab.click();
      selectAp(ap);
    };
  }

  function renderApTable() {
    const wrap = qs("wlan-ap-table-wrap");
    if (!wrap) return;
    const aps = filteredAps();
    let h = `<h4>Sichtbare Access Points <small>(${aps.length}${
      (LAST_SCAN.aps || []).length !== aps.length
        ? " von " + (LAST_SCAN.aps || []).length
        : ""
    } · nach Signal sortiert)</small></h4>`;
    if (!aps.length) {
      h += `<p class="hint">${esc(LAST_SCAN.reason || "Noch kein Scan – Button „Scannen“ drücken.")}</p>`;
      wrap.innerHTML = h;
      return;
    }
    h += `<div class="wlan-table-scroll"><table class="wlan-aps wlan-aps-interactive">
      <thead><tr>
        <th></th><th>SSID</th><th>BSSID</th><th>Kanal</th><th>Band</th>
        <th>Signal</th><th>Security</th><th></th>
      </tr></thead><tbody>`;
    const selB = window.ANTBB_WLAN_SELECTED && window.ANTBB_WLAN_SELECTED.bssid;
    aps.forEach(a => {
      const sel = selB && a.bssid === selB ? " selected" : "";
      const conn = a.connected ? " connected" : "";
      h += `<tr class="wlan-ap-row${sel}${conn}" data-bssid="${esc(a.bssid)}" tabindex="0" title="Klicken zum Auswählen">
        <td>${a.connected ? '<span class="wlan-dot-conn" title="verbunden"></span>' : ""}</td>
        <td class="wlan-ssid">${esc(a.ssid || "(versteckt)")}</td>
        <td><code>${esc(a.bssid)}</code></td>
        <td>${a.channel ?? "?"}</td>
        <td><span class="badge" style="border-color:${BANDCOL[a.band] || "#8a92a6"};color:${BANDCOL[a.band] || "#8a92a6"};">${esc(a.band || "?")} GHz</span></td>
        <td class="wlan-sig">${signalBars(a.rssi)} <span style="color:${rssiColor(a.rssi)};">${a.rssi ?? "?"} dBm</span></td>
        <td><span class="badge wlan-sec-${esc((a.encryption || "").toLowerCase())}">${esc(a.encryption || "?")}</span></td>
        <td><button type="button" class="wlan-pick" data-bssid="${esc(a.bssid)}">wählen</button></td>
      </tr>`;
    });
    h += `</tbody></table></div>
      <p class="hint">Klick auf eine Zeile setzt SSID/BSSID automatisch – kein Copy-Paste. Verbundene Netze sind markiert.</p>`;
    wrap.innerHTML = h;
    wrap.querySelectorAll("tr.wlan-ap-row").forEach(tr => {
      const pick = () => {
        const b = tr.getAttribute("data-bssid");
        const ap = (LAST_SCAN.aps || []).find(x => x.bssid === b);
        if (ap) selectAp(ap);
      };
      tr.addEventListener("click", pick);
      tr.addEventListener("keydown", ev => {
        if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); pick(); }
      });
    });
  }

  function renderChannelBars(ca) {
    const usage = (ca && ca.channel_usage) || {};
    let h = "";
    ["2.4", "5", "6"].forEach(band => {
      const u = usage[band] || {};
      const chans = Object.keys(u);
      if (!chans.length) return;
      const max = Math.max.apply(null, chans.map(c => u[c]));
      h += `<div class="wlan-band"><div class="hint">${band} GHz</div><div class="wlan-chbars">`;
      chans.sort((a, b) => +a - +b).forEach(c => {
        const pct = Math.round(100 * u[c] / max);
        h += `<div class="wlan-chbar" title="Kanal ${c}: ${u[c]} AP(s)">
          <div class="wlan-chbar-fill" style="height:${Math.max(12, pct)}%;background:${BANDCOL[band]};"></div>
          <div class="wlan-chbar-lbl">${c}</div></div>`;
      });
      h += `</div></div>`;
    });
    if (!h) return `<p class="hint">Keine Kanal-Daten (noch kein Scan).</p>`;
    h += `<p class="hint">2,4 GHz überlappungsfrei nur auf 1 / 6 / 11.</p>`;
    return h;
  }

  function renderAnalysis() {
    const el = qs("wlan-analysis");
    if (!el) return;
    const s = LAST_SURVEY || {};
    const ca = s.channel_analysis || {};
    const cov = s.coverage || {};
    const rec = s.recommendations || {};
    let h = "";
    h += `<h4>Kanal-Belegung &amp; Störung</h4>`;
    h += renderChannelBars(ca);
    const si = ca.self_interference || [];
    if (si.length) {
      h += `<div class="wlan-warn"><strong>⚠ Selbst-Störung eigener APs (${si.length}):</strong><ul>`;
      si.forEach(c => { h += `<li>[${esc(c.severity)}] ${esc(c.note)}</li>`; });
      h += `</ul></div>`;
    } else if ((ca.own_ap_count || 0) >= 2) {
      h += `<p class="hint ok">✅ Keine Selbst-Störung zwischen den getaggten eigenen APs.</p>`;
    }

    h += `<h4>Abdeckung (${cov.measured_count || 0} Messpunkt(e), Funklöcher: ${cov.dead_zone_count || 0})</h4>`;
    const pts = cov.points || [];
    if (!pts.length) {
      h += `<p class="hint">Noch keine Messpunkte. Unten aus dem Scan übernehmen.</p>`;
    } else {
      h += `<div class="wlan-coverage">`;
      pts.forEach(p => {
        const c = rssiColor(p.best_rssi);
        h += `<div class="wlan-point" style="border-color:${c};">
          <div class="wlan-point-label">${esc(p.label)}</div>
          <div class="wlan-point-rssi" style="color:${c};">${p.best_rssi ?? "?"} dBm</div>
          <div class="hint">${esc(p.quality)}${p.is_dead_zone ? " · ⚠ Funkloch" : ""}</div></div>`;
      });
      h += `</div>`;
    }

    h += `<h4>🧭 Optimierungs-Empfehlungen</h4>`;
    const all = [].concat(rec.channel_recommendations || [],
      rec.band_steering_hint ? [rec.band_steering_hint] : [],
      rec.tx_power_hint ? [rec.tx_power_hint] : [],
      rec.placement || []);
    if (!all.length) {
      h += `<p class="hint">Zu wenig Daten – zuerst scannen.</p>`;
    } else {
      h += `<ul class="wlan-recs">`;
      all.forEach(r => { h += `<li>${esc(r)}</li>`; });
      h += `</ul><p class="hint">${esc(rec.note || "")}</p>`;
    }
    el.innerHTML = h;
  }

  function renderPointsForm() {
    const el = qs("wlan-points");
    if (!el) return;
    const ap = window.ANTBB_WLAN_SELECTED;
    const sampleHint = ap
      ? `${ap.bssid}=${ap.rssi != null ? ap.rssi : -70}`
      : "aa:bb:cc:dd:ee:ff=-58";
    el.innerHTML = `
      <h4>Messpunkt hinzufügen</h4>
      <div class="row" style="gap:.4rem;flex-wrap:wrap;align-items:flex-end;">
        <label>Standort<br><input type="text" id="wlan-label" placeholder="z.B. Wohnzimmer"></label>
        <label>Samples (BSSID=RSSI)<br>
          <input type="text" id="wlan-samples" placeholder="${esc(sampleHint)}" style="min-width:280px;"></label>
        <label>eigene BSSIDs (optional)<br>
          <input type="text" id="wlan-own" placeholder="aus Auswahl" style="min-width:180px;"></label>
        <button type="button" id="wlan-fill-from-sel" ${ap ? "" : "disabled"}>aus Auswahl füllen</button>
        <button type="button" id="wlan-addpoint">Speichern</button>
      </div>
      <div id="wlan-msg" class="hint"></div>`;

    const fill = qs("wlan-fill-from-sel");
    if (fill) fill.onclick = () => {
      const a = window.ANTBB_WLAN_SELECTED;
      if (!a) return;
      qs("wlan-samples").value = `${a.bssid}=${a.rssi != null ? a.rssi : -70}`;
      qs("wlan-own").value = a.bssid;
      if (!qs("wlan-label").value) qs("wlan-label").value = a.ssid || "Messpunkt";
    };
    // Auto-fill wenn Auswahl existiert und Felder leer
    if (ap && qs("wlan-samples") && !qs("wlan-samples").value) {
      qs("wlan-samples").value = `${ap.bssid}=${ap.rssi != null ? ap.rssi : -70}`;
      qs("wlan-own").value = ap.bssid;
    }
    const apBtn = qs("wlan-addpoint");
    if (apBtn) apBtn.onclick = async () => {
      const label = (qs("wlan-label").value || "").trim();
      const raw = (qs("wlan-samples").value || "").trim();
      const own = (qs("wlan-own").value || "").split(",").map(x => x.trim()).filter(Boolean);
      const samples = {};
      raw.split(",").forEach(pair => {
        const [b, r] = pair.split("=");
        if (b && r != null && r.trim() !== "") samples[b.trim().toLowerCase()] = parseInt(r, 10);
      });
      if (!label || !Object.keys(samples).length) {
        qs("wlan-msg").textContent = "Standort + mind. ein BSSID=RSSI nötig (oder „aus Auswahl füllen“).";
        return;
      }
      const body = { label, samples, own_bssids: own };
      if (TID) body.target_id = TID;
      const res = await fetch("/api/wlan/point", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
      });
      if (res.ok) {
        qs("wlan-msg").textContent = "✅ gespeichert";
        await loadSurveyOnly();
        renderAnalysis();
      } else {
        qs("wlan-msg").textContent = "Fehler beim Speichern.";
      }
    };
  }

  function renderBody() {
    renderApTable();
    renderAnalysis();
    renderPointsForm();
    renderSelectionBar();
  }

  function wireToolbar() {
    const btn = qs("wlan-scan-btn");
    if (btn) btn.onclick = () => doScan();
    const band = qs("wlan-band");
    if (band) band.onchange = () => renderApTable();
    const filter = qs("wlan-filter");
    if (filter) filter.oninput = () => renderApTable();
    const ar = qs("wlan-autorefresh");
    if (ar) ar.onchange = () => {
      if (autoTimer) { clearInterval(autoTimer); autoTimer = null; }
      if (ar.checked) {
        doScan();
        autoTimer = setInterval(() => { if (!busy) doScan(); }, 30000);
      }
    };
  }


  // ---- Königin: Ein-Klick-Voll-Scan (defensiv) ----
  const CHECK_DEFAULTS = [
    {id:"scan", label:"Umgebungs-Scan (APs/Beacons)"},
    {id:"konfig", label:"Verschlüsselungs-/Konfig-Check"},
    {id:"optim", label:"Kanal-/Band-Optimierung"},
    {id:"coverage", label:"Coverage / Selbst-Störung / Funklöcher"}
  ];

  async function loadFullChecks() {
    const box = qs("wlan-queen-checks");
    if (!box) return;
    let checks = CHECK_DEFAULTS;
    try {
      const j = await (await fetch("/api/wlan/full-scan/checks")).json();
      if (j.checks && j.checks.length) checks = j.checks;
    } catch (e) {}
    box.innerHTML = checks.map(c =>
      `<label class="wlan-check-item"><input type="checkbox" class="wlan-full-check" value="${esc(c.id)}" checked> ${esc(c.label)}</label>`
    ).join("");
  }

  function selectedChecks() {
    return Array.prototype.slice.call(document.querySelectorAll(".wlan-full-check:checked"))
      .map(el => el.value);
  }

  function wireQueen() {
    const all = qs("wlan-sel-all");
    const none = qs("wlan-sel-none");
    const btn = qs("wlan-full-scan-btn");
    if (all) all.onclick = () => {
      document.querySelectorAll(".wlan-full-check").forEach(c => { c.checked = true; });
    };
    if (none) none.onclick = () => {
      document.querySelectorAll(".wlan-full-check").forEach(c => { c.checked = false; });
    };
    if (btn) btn.onclick = async () => {
      const status = qs("wlan-full-status");
      const ov = qs("wlan-full-oversight");
      const checks = selectedChecks();
      if (!checks.length) {
        if (status) { status.textContent = "Keine Checks gewählt – „Alle auswählen“ oder Haken setzen."; status.className = "wlan-status warn"; }
        return;
      }
      if (!ov || !ov.checked) {
        if (status) { status.textContent = "BLOCKIERT: Oversight-Häkchen setzen – Königin dispatcht sonst nichts."; status.className = "wlan-status err"; }
        return;
      }
      if (status) { status.textContent = "👑 Königin dispatcht WLAN-Voll-Scan…"; status.className = "wlan-status busy"; }
      btn.disabled = true;
      try {
        const body = {
          iface: currentIface() || null,
          checks: checks,
          oversight_ack: true,
          target_id: TID
        };
        const r = await fetch("/api/wlan/full-scan", {
          method: "POST", headers: {"Content-Type":"application/json"},
          body: JSON.stringify(body)
        });
        const j = await r.json();
        if (j.blocked) {
          if (status) { status.textContent = "⛔ " + (j.reason || "blockiert"); status.className = "wlan-status err"; }
        } else {
          // Ergebnis in die bestehende Ansicht übernehmen
          if (j.scan) {
            LAST_SCAN = {
              aps: (j.scan.aps || []),
              tool: j.scan.tool || null,
              iface: j.scan.iface || currentIface() || "",
              reason: j.scan.reason || "",
              tools: (j.survey && j.survey.tools) || {},
              enabled: j.survey ? j.survey.enabled : false
            };
          }
          if (j.survey) LAST_SURVEY = j.survey;
          else if (j.scan) {
            LAST_SURVEY = LAST_SURVEY || {};
            LAST_SURVEY.aps = j.scan.aps || [];
            LAST_SURVEY.scan = j.scan;
          }
          renderBody();
          const n = (LAST_SCAN.aps || []).length;
          const issues = (j.konfig || []).length;
          if (status) {
            status.textContent = "✅ " + (j.reason || "fertig") +
              ` · ${n} AP(s) · ${issues} Konfig-Hinweis(e) · checks=[${(j.checks_run||[]).join(",")}]`;
            status.className = "wlan-status ok";
          }
        }
      } catch (e) {
        if (status) { status.textContent = "Voll-Scan fehlgeschlagen: " + e; status.className = "wlan-status err"; }
      }
      btn.disabled = false;
    };
  }

  // Boot
  (async function boot() {
    root.innerHTML = "<p class='hint'>WLAN-Menü wird geladen…</p>";
    await loadAdapters();
    await loadSurveyOnly();
    await loadFullChecks();
    wireQueen();
    renderShell();
    // Wenn Survey schon APs hat (selten ohne Scan), zeigen; sonst warten auf Button.
    if (LAST_SURVEY && (LAST_SURVEY.aps || []).length) {
      LAST_SCAN.aps = LAST_SURVEY.aps;
      renderBody();
    }
  })();
})();
