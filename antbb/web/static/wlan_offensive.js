/* antbb – Offensiv / Airgorah (web-nativ).
 * Feature-Umfang wie Airgorah (MIT, martin-olivier/airgorah): Monitor-Status,
 * AP+Clients, Handshake/PMKID, Deauth, Crack, Evil-Twin – alles hinter
 * Engagement-Gate + Oversight + ANTBB_WIFI=1. Default-deny, dry_run aus Browser,
 * keine autonomen Ketten. Scope-Engagements liegen im Tab „WLAN-Scope“. */
(function () {
  "use strict";
  const root = document.getElementById("wlan-offensive-view");
  if (!root) return;
  function esc(s){return (s==null?"":String(s)).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));}
  async function j(url, opts){ const r = await fetch(url, opts); return r.json(); }

  let STATUS = {enabled:false, missing:[], legal_notice:"", oversight_prompt:""};
  let AIR = null;
  let ENGS = [];

  async function reload(){
    try { STATUS = await j("/api/wlan/offensive/status"); } catch(e){}
    try { AIR = await j("/api/wlan/airgorah/status"); } catch(e){ AIR=null; }
    try { ENGS = (await j("/api/wlan/engagements")).engagements || []; } catch(e){ ENGS=[]; }
    render();
  }

  function activeEngagements(){
    const now = Date.now()/1000;
    return ENGS.filter(e => !e.revoked && e.oversight && e.start_ts<=now && now<=e.end_ts);
  }

  function render(){
    const act = activeEngagements();
    const armed = STATUS.enabled && act.length>0;
    const priv = (AIR && AIR.privileges) || {};
    const mon = (AIR && AIR.monitor) || {};
    const caveats = (AIR && AIR.caveats) || [];
    const tools = (AIR && AIR.tools) || {};
    const sel = window.ANTBB_WLAN_SELECTED;

    let h = "";
    h += `<div class="card" style="border-color:#ff7b6b;">
      <strong>⚖ Rechtshinweis</strong>
      <p class="hint">${esc(STATUS.legal_notice||"Nur mit ausdrücklicher Autorisierung. §202a-c StGB / CFAA.")}</p>
      <p class="hint">Airgorah-Referenz: <a href="https://github.com/martin-olivier/airgorah" target="_blank" rel="noopener">martin-olivier/airgorah</a>
        (MIT) – Workflow web-nativ, kein GTK-Embed.</p></div>`;

    // Status-Leiste
    h += `<div class="row" style="gap:.5rem;flex-wrap:wrap;margin:.5rem 0;">
      <span class="badge">${STATUS.enabled?"ANTBB_WIFI=1 ✔":"ANTBB_WIFI nicht gesetzt ✘"}</span>
      <span class="badge" style="border-color:${armed?'#3fffa3':'#ff7b6b'};color:${armed?'#3fffa3':'#ff7b6b'};">
        ${armed?("SCHARF – "+act.length+" Engagement"):"GESPERRT (default-deny)"}</span>
      <span class="badge">${priv.is_root?"Root ✔":(priv.sudo_nopasswd?"sudo NOPASSWD ✔":"kein Root/NOPASSWD ✘")}</span>
      <span class="badge" style="border-color:${mon.monitor?'#3fffa3':'#ffcf7a'};color:${mon.monitor?'#3fffa3':'#ffcf7a'};">
        Monitor ${mon.iface||"?"}: ${mon.monitor?"AN":(mon.raw_type||"aus")}</span>
    </div>`;

    if (caveats.length) {
      h += `<div class="wlan-warn"><strong>Hinweise (ehrlich):</strong><ul>`;
      caveats.forEach(c => { h += `<li>${esc(c)}</li>`; });
      h += `</ul></div>`;
    }

    // Tool-Matrix (Airgorah-ähnlich)
    h += `<div class="card"><strong>🧰 Tool-Status (Airgorah-Workflow)</strong>
      <div class="wlan-tool-grid">`;
    const toolOrder = ["iw","airmon-ng","airodump-ng","aireplay-ng","aircrack-ng",
      "hcxdumptool","hashcat","mdk4","nmcli","hostapd","wifiphisher","eaphammer"];
    toolOrder.forEach(t => {
      const ok = !!tools[t];
      h += `<span class="badge" style="border-color:${ok?'#3fffa3':'#5a6172'};color:${ok?'#3fffa3':'#8a92a6'};">${esc(t)} ${ok?"✔":"–"}</span>`;
    });
    h += `</div>
      <p class="hint">Preferred iface: <code>${esc((AIR&&AIR.preferred_iface)||"?")}</code>
        · Scope-Engagements verwalten im Tab <b>WLAN-Scope</b>
        (${act.length} aktiv).</p>
    </div>`;

    // Ziel aus Coverage
    h += `<div class="card"><strong>Ziel (aus Coverage-Auswahl)</strong>
      <p class="hint">${sel
        ? (`<strong>${esc(sel.ssid||"(versteckt)")}</strong> <code>${esc(sel.bssid)}</code>
            · Ch ${sel.channel??"?"} · ${esc(sel.encryption||"?")}`)
        : "Kein WLAN gewählt – Tab Coverage → Scannen → Zeile anklicken."}</p>
      <div class="row" style="flex-wrap:wrap;gap:.4rem;margin-top:.4rem;">
        <input id="ao-bssid" placeholder="Ziel-BSSID"/>
        <input id="ao-ssid" placeholder="Ziel-SSID"/>
        <input id="ao-cmac" placeholder="Client-MAC (Deauth, optional)"/>
        <input id="ao-cap" placeholder="Capture-Pfad (Crack)"/>
        <input id="ao-channel" placeholder="Kanal" style="width:5rem;"/>
        <button type="button" id="ao-from-sel" ${sel?"":"disabled"}>aus Coverage-Auswahl</button>
        <button type="button" id="ao-clients">Clients abfragen</button>
      </div>
      <pre id="ao-clients-out" class="hint" style="white-space:pre-wrap;margin-top:.4rem;"></pre>
    </div>`;

    // Airgorah-Aktionen
    const dis = armed ? "" : "disabled";
    h += `<div class="card"><strong>🗡️ Airgorah-Aktionen (Gate-pflichtig)</strong>
      <p class="hint">Browser startet Tools im dry_run (Status/Gate-Test). Scharfer Lauf nur
        CLI/operator mit Hardware+Root. Keine autonomen Ketten.</p>
      <div class="wlan-air-actions">
        <button type="button" data-act="handshake-capture" ${dis}
          title="WPA-Handshake/PMKID gegen autorisierte BSSID">📡 Handshake / PMKID-Capture</button>
        <button type="button" data-act="targeted-deauth" ${dis}
          title="Gezielter Deauth – trennt Clients">⚡ Gezielter Deauth ⚠</button>
        <button type="button" data-act="offline-crack" ${dis}
          title="Offline gegen eigene Capture">🔓 Offline-Crack</button>
        <button type="button" data-act="evil-twin-demo" ${dis}
          title="Evil-Twin Demo – Awareness">👻 Evil-Twin / Fake-AP Demo</button>
      </div>
      ${armed?"":`<p class="hint" style="color:#ff7b6b;">Gesperrt: kein aktives autorisiertes Engagement
        (Tab WLAN-Scope) oder ANTBB_WIFI≠1. Monitor-Mode/Root-Hinweise siehe oben.</p>`}
      <pre id="ao-out" class="hint" style="white-space:pre-wrap;margin-top:.4rem;"></pre>
    </div>`;

    // Credentials
    h += `<div class="card"><strong>Abgefangene Credentials (NUR maskiert)</strong>
      <button type="button" id="co-reload">neu laden</button>
      <button type="button" id="co-purge">alle löschen (Purge)</button>
      <div id="co-list" class="hint"></div></div>`;

    root.innerHTML = h;
    wire();
    applySelection(window.ANTBB_WLAN_SELECTED);
    loadCreds();
  }

  function applySelection(ap) {
    if (!ap) return;
    const set = (id, v) => { const el = document.getElementById(id); if (el && v != null) el.value = v; };
    set("ao-bssid", ap.bssid || "");
    set("ao-ssid", ap.ssid || "");
    if (ap.channel != null) set("ao-channel", String(ap.channel));
  }

  function wire(){
    const g=(id)=>document.getElementById(id);
    const val=(id)=>(g(id)&&g(id).value||"").trim();

    const aoFrom = g("ao-from-sel");
    if (aoFrom) aoFrom.onclick = () => applySelection(window.ANTBB_WLAN_SELECTED);

    const clientsBtn = g("ao-clients");
    if (clientsBtn) clientsBtn.onclick = async () => {
      const out = g("ao-clients-out");
      if (out) out.textContent = "frage Clients…";
      const iface = (AIR && AIR.preferred_iface) || "";
      const u = `/api/wlan/clients?iface=${encodeURIComponent(iface)}&bssid=${encodeURIComponent(val("ao-bssid"))}`;
      try {
        const res = await j(u);
        if (out) {
          out.textContent = (res.honest_empty ? "ℹ️ " : "✅ ") +
            (res.reason || "") +
            (res.clients && res.clients.length
              ? ("\n" + res.clients.map(c=>JSON.stringify(c)).join("\n"))
              : "\n(keine Clients – ehrlich leer)");
        }
      } catch (e) {
        if (out) out.textContent = "Fehler: " + e;
      }
    };

    root.querySelectorAll("[data-act]").forEach(b=> b.onclick = async ()=>{
      const out = g("ao-out"); out.textContent="läuft (dry_run / Gate-Check)…";
      const res = await j(`/api/wlan/offensive/${b.dataset.act}`, {method:"POST",
        headers:{"Content-Type":"application/json"},
        body: JSON.stringify({bssid:val("ao-bssid"), ssid:val("ao-ssid"),
          client_mac:val("ao-cmac"), capture_path:val("ao-cap"),
          channel: val("ao-channel") ? parseInt(val("ao-channel"),10) : null,
          dry_run:true})});
      out.textContent = (res.allowed?"✅ ":"⛔ ") + (res.reason||"") +
        (res.honest_empty?" [honest-empty]":"") + (res.tool?(" tool="+res.tool):"") +
        (res.detail && res.detail.warning ? ("\n⚠ "+res.detail.warning) : "");
      loadCreds();
    });
    g("co-reload").onclick = loadCreds;
    g("co-purge").onclick = async ()=>{ await fetch("/api/wlan/credentials",{method:"DELETE"}); loadCreds(); };
  }

  async function loadCreds(){
    const el = document.getElementById("co-list"); if(!el) return;
    let c=[]; try{ c=(await j("/api/wlan/credentials")).credentials||[]; }catch(e){}
    if(!c.length){ el.innerHTML="<p class='hint'>keine (ehrlich leer).</p>"; return; }
    el.innerHTML = c.map(x=>`<div>• [${esc(x.kind)}] ${esc(x.masked)} <span class="hint">(eng#${x.engagement_id}, sha256 gesalzen)</span></div>`).join("");
  }

  window.addEventListener("antbb:wlan-selected", (ev) => {
    applySelection(ev.detail || null);
    const el = document.getElementById("ao-from-sel");
    if (el) el.disabled = !ev.detail;
  });
  window.addEventListener("antbb:wlan-tab", (ev) => {
    if (ev.detail && ev.detail.tab === "offensive") reload();
  });

  reload();
})();
