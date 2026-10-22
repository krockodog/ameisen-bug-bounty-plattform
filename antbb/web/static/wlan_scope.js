/* antbb – WLAN-Scope (eigenes Menü): Engagement-Allowlist, default-deny.
 * Getrennt von Coverage/Scan und Offensiv/Airgorah. Kein Auto-Allowlist. */
(function () {
  "use strict";
  const root = document.getElementById("wlan-scope-view");
  if (!root) return;
  function esc(s){return (s==null?"":String(s)).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));}
  async function j(url, opts){ const r = await fetch(url, opts); return r.json(); }

  let ENGS = [];
  let STATUS = {oversight_prompt: ""};

  async function reload(){
    try { STATUS = await j("/api/wlan/offensive/status"); } catch(e){}
    try { ENGS = (await j("/api/wlan/engagements")).engagements || []; } catch(e){ ENGS=[]; }
    render();
  }

  function render(){
    const sel = window.ANTBB_WLAN_SELECTED;
    const selHint = sel
      ? (`Auswahl aus Coverage: <strong>${esc(sel.ssid||"(versteckt)")}</strong> <code>${esc(sel.bssid)}</code>`)
      : "Noch kein WLAN gewählt – im Tab Coverage scannen und Zeile anklicken.";
    const now = Date.now()/1000;
    const active = ENGS.filter(e => !e.revoked && e.oversight && e.start_ts<=now && now<=e.end_ts);

    let h = "";
    h += `<div class="row" style="gap:.5rem;flex-wrap:wrap;margin:.3rem 0 .6rem;">
      <span class="badge" style="border-color:${active.length?'#3fffa3':'#ff7b6b'};color:${active.length?'#3fffa3':'#ff7b6b'};">
        ${active.length ? (active.length + " aktive(s) Engagement") : "kein aktives Engagement (default-deny)"}</span>
      <span class="badge">${ENGS.length} gesamt</span>
    </div>`;

    h += `<div class="card wlan-scope-create">
      <strong>Neues Autorisierungs-Engagement</strong>
      <p class="hint" id="sc-sel-hint">${selHint}</p>
      <div class="row" style="flex-wrap:wrap;gap:.4rem;margin-top:.4rem;align-items:flex-end;">
        <label class="wlan-field">Name<input id="sc-name" placeholder="Auftragsname"></label>
        <label class="wlan-field grow">BSSID-Allowlist<input id="sc-bssid" placeholder="aa:bb:… (Komma)"></label>
        <label class="wlan-field grow">SSID-Allowlist<input id="sc-ssid" placeholder="MeinWLAN (Komma)"></label>
        <label class="wlan-field">Client-MAC<input id="sc-cmac" placeholder="optional"></label>
        <label class="wlan-field">Ort<input id="sc-loc" placeholder="optional"></label>
        <label class="wlan-field">Dauer (h)<input id="sc-hours" type="number" value="8" style="width:5rem;"></label>
        <label class="wlan-field wlan-check" title="${esc(STATUS.oversight_prompt||'')}">
          <input type="checkbox" id="sc-ov"> Human Oversight bestätigen</label>
        <button type="button" id="sc-from-sel" ${sel?"":"disabled"}>aus Coverage-Auswahl</button>
        <button type="button" id="sc-create" class="wlan-primary">+ Engagement anlegen</button>
      </div>
      <p class="hint">Default-deny: ohne aktives, im Zeitfenster liegendes Engagement mit Oversight
        bleibt jede Offensiv-Aktion blockiert. Kein neues Ziel wird automatisch in eine Allowlist geschrieben.</p>
    </div>`;

    h += `<div class="card"><strong>Engagements</strong>`;
    if (!ENGS.length) h += `<p class="hint">keine Engagements – Scope ist leer (alles gesperrt).</p>`;
    ENGS.forEach(e=>{
      const isActive = !e.revoked && e.oversight && e.start_ts<=now && now<=e.end_ts;
      h += `<div class="wlan-eng-row">
        <div>
          <span>#${e.id} <strong>${esc(e.name)}</strong></span>
          <span class="badge">${isActive?"aktiv ✔":(e.revoked?"widerrufen":"inaktiv")}</span>
          <div class="hint">BSSID:[${esc((e.bssids||[]).join(", "))}] · SSID:[${esc((e.ssids||[]).join(", "))}]
            · Oversight:${e.oversight?"✔":"✘"}
            ${e.location?(" · Ort:"+esc(e.location)):""}</div>
        </div>
        <div class="wlan-eng-actions">
          <button type="button" data-ov="${e.id}" data-val="${e.oversight?0:1}">
            ${e.oversight?"Oversight aus":"Oversight an"}</button>
          <button type="button" data-revoke="${e.id}">widerrufen</button>
        </div>
      </div>`;
    });
    h += `</div>`;

    h += `<p class="hint">Tipp: Nach dem Anlegen → Tab „Offensiv / Airgorah“ für Handshake/Deauth/Crack
      (nur gegen diese Allowlist, weiterhin Oversight-pflichtig).</p>`;

    root.innerHTML = h;
    wire();
    applySelection(window.ANTBB_WLAN_SELECTED);
  }

  function applySelection(ap){
    if (!ap) return;
    const set = (id,v)=>{ const el=document.getElementById(id); if(el&&v!=null) el.value=v; };
    set("sc-bssid", ap.bssid||"");
    set("sc-ssid", ap.ssid||"");
    const nm=document.getElementById("sc-name");
    if (nm && !nm.value) set("sc-name", (ap.ssid||"WLAN")+"-Engagement");
    const hint=document.getElementById("sc-sel-hint");
    if (hint) hint.innerHTML = `Auswahl aus Coverage: <strong>${esc(ap.ssid||"(versteckt)")}</strong> <code>${esc(ap.bssid)}</code>`;
  }

  function wire(){
    const g=id=>document.getElementById(id);
    const val=id=>(g(id)&&g(id).value||"").trim();
    const list=id=>val(id).split(",").map(x=>x.trim()).filter(Boolean);
    const from=g("sc-from-sel");
    if (from) from.onclick=()=>applySelection(window.ANTBB_WLAN_SELECTED);
    g("sc-create").onclick = async ()=>{
      const name=val("sc-name");
      const bssids=list("sc-bssid"), ssids=list("sc-ssid");
      if (!name || (!bssids.length && !ssids.length)) {
        alert("Name + mind. eine BSSID oder SSID nötig."); return;
      }
      await j("/api/wlan/engagements", {method:"POST",
        headers:{"Content-Type":"application/json"},
        body: JSON.stringify({name, bssids, ssids, client_mac:val("sc-cmac"),
          location:val("sc-loc"), duration_hours: parseFloat(val("sc-hours")||"8"),
          oversight: !!(g("sc-ov")&&g("sc-ov").checked),
          target_id: window.ANTBB_TARGET_ID || null})});
      reload();
    };
    root.querySelectorAll("[data-ov]").forEach(b=> b.onclick = async ()=>{
      await j(`/api/wlan/engagements/${b.dataset.ov}/oversight`, {method:"POST",
        headers:{"Content-Type":"application/json"},
        body:JSON.stringify({confirmed: b.dataset.val==="1"})});
      reload();
    });
    root.querySelectorAll("[data-revoke]").forEach(b=> b.onclick = async ()=>{
      await j(`/api/wlan/engagements/${b.dataset.revoke}/revoke`, {method:"POST"});
      reload();
    });
  }

  window.addEventListener("antbb:wlan-selected", (ev)=>{
    applySelection(ev.detail||null);
    const el=document.getElementById("sc-from-sel");
    if (el) el.disabled = !ev.detail;
  });
  window.addEventListener("antbb:wlan-tab", (ev)=>{
    if (ev.detail && ev.detail.tab === "scope") reload();
  });

  reload();
})();
