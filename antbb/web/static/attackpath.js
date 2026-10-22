/* antbb – DAG-Angriffspfad-Visualisierung (reines SVG/JS, Dark-Theme).
   NUR Darstellung: zeigt hypothetische Pfade + Remediation. Kein Executor. */
(function () {
  "use strict";
  const TID = window.ANTBB_TARGET_ID;
  const host = document.getElementById("attackpath-view");
  if (!TID || !host) return;
  function esc(s){return (s==null?"":String(s)).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));}
  const SEVCOL = {critical:"#ff4d6a",high:"#ff7b6b",medium:"#ffa94d",low:"#ffcf7a",info:"#8a92a6"};
  const STAGE_X = {internet:60, asset:250, foothold:470, escalation:700, impact:930};
  const STAGE_LBL = {internet:"Internet", asset:"Asset", foothold:"Foothold",
    escalation:"Eskalation", impact:"Impact"};

  fetch("/api/targets/"+TID+"/attackpath").then(r=>r.json()).then(g=>{
    if (g.empty){ host.innerHTML="<p class='hint'>Keine Befunde – kein Angriffspfad (ehrlicher Leerzustand).</p>"; return; }
    renderGraph(g);
    renderPaths(g);
  }).catch(()=>{ host.innerHTML="<p class='hint'>Angriffspfad nicht verfügbar.</p>"; });

  function renderGraph(g){
    // Knoten pro Stage vertikal stapeln.
    const byStage = {};
    g.nodes.forEach(n=>{ (byStage[n.stage]=byStage[n.stage]||[]).push(n); });
    const pos = {};
    const rowH = 70; let maxRows = 0;
    Object.keys(byStage).forEach(st=>{
      byStage[st].forEach((n,i)=>{ pos[n.id] = {x: STAGE_X[st]||500, y: 70 + i*rowH}; });
      maxRows = Math.max(maxRows, byStage[st].length);
    });
    const W = 1040, H = Math.max(260, 90 + maxRows*rowH);
    let svg = `<svg width="100%" viewBox="0 0 ${W} ${H}" style="background:#0d1117;border:1px solid #233;border-radius:8px;">`;
    svg += `<defs><marker id="arr" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto">
      <path d="M0,0 L7,3 L0,6 Z" fill="#4a5568"/></marker></defs>`;
    // Stage-Labels
    Object.keys(STAGE_X).forEach(st=>{
      svg += `<text x="${STAGE_X[st]}" y="28" fill="#5b6672" font-size="12" font-family="sans-serif">${STAGE_LBL[st]||st}</text>`;
    });
    // Kanten (gestrichelt = hypothetisch)
    g.edges.forEach(e=>{
      const a=pos[e.from], b=pos[e.to]; if(!a||!b) return;
      svg += `<line x1="${a.x+70}" y1="${a.y}" x2="${b.x-70}" y2="${b.y}" stroke="#4a5568"
        stroke-width="1.3" stroke-dasharray="5,4" marker-end="url(#arr)"><title>${esc(e.label)} — Fix: ${esc(e.remediation)}</title></line>`;
    });
    // Knoten
    g.nodes.forEach(n=>{
      const p=pos[n.id]; if(!p) return;
      const col = n.type==="finding" ? (SEVCOL[n.severity]||"#8a92a6")
        : n.type==="origin" ? "#f85149" : "#2563eb";
      const label = (n.label||"").slice(0,22);
      svg += `<g><rect x="${p.x-66}" y="${p.y-16}" width="132" height="32" rx="6"
        fill="#161b22" stroke="${col}" stroke-width="1.6"/>`;
      if (n.type==="finding" && n.verified)
        svg += `<circle cx="${p.x+58}" cy="${p.y-10}" r="4" fill="#3fffa3"><title>VERIFIZIERT</title></circle>`;
      svg += `<text x="${p.x}" y="${p.y+4}" fill="#e6edf3" font-size="11" text-anchor="middle"
        font-family="sans-serif">${esc(label)}</text><title>${esc(n.label)} [${esc(n.type)}${n.severity?"/"+esc(n.severity):""}]</title></g>`;
    });
    svg += `</svg>`;
    host.insertAdjacentHTML("beforeend", svg);
    host.insertAdjacentHTML("beforeend",
      `<p class='hint'>${esc(g.note)} Gestrichelte Kanten = hypothetisch; grüner Punkt = verifizierter Befund.</p>`);
  }

  function renderPaths(g){
    if(!g.paths||!g.paths.length) return;
    let h = "<h2>Pfadliste (textuell, mit Remediation)</h2>";
    g.paths.forEach(p=>{
      h += `<div style="margin:.6rem 0;"><strong>Asset ${esc(p.asset)}</strong>
        <span class="badge" style="border:1px solid ${SEVCOL[p.max_severity]||'#888'};color:${SEVCOL[p.max_severity]||'#888'}">max ${esc(p.max_severity)}</span><ul>`;
      p.steps.forEach(s=>{
        const tag = s.verified ? "VERIFIZIERT" : (s.status||"offen");
        h += `<li>[${esc(s.severity)}/${esc(tag)}] <strong>${esc(s.finding)}</strong> → <em>könnte ermöglichen:</em> ${esc(s.enables)}<br>
          <span class="hint">Fix: ${esc(s.remediation)}</span></li>`;
      });
      h += "</ul></div>";
    });
    host.insertAdjacentHTML("beforeend", h);
  }
})();
