/* antbb – Rating + Risiko-Heatmap-Rendering (reines HTML/CSS/JS). */
(function () {
  "use strict";
  const TID = window.ANTBB_TARGET_ID;
  const rv = document.getElementById("rating-view");
  const hv = document.getElementById("heatmap-view");
  if (!TID || !rv) return;
  function esc(s){return (s==null?"":String(s)).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));}
  const GRADE_COL = {A:"#3fffa3",B:"#9fe08a",C:"#ffcf7a",D:"#ffa94d",E:"#ff7b6b",F:"#ff4d6a"};

  function heatColor(intensity){
    // 0 -> transparent, 1 -> rot. Grün->gelb->rot Verlauf.
    if (!intensity) return "transparent";
    const i = Math.max(0, Math.min(1, intensity));
    const r = Math.round(60 + 195*i), g = Math.round(220 - 170*i), b = Math.round(120 - 90*i);
    return `rgba(${r},${g},${b},${0.25+0.55*i})`;
  }

  fetch("/api/targets/"+TID+"/rating").then(r=>r.json()).then(rating => {
    const g = rating.grade, col = GRADE_COL[g]||"#8a92a6";
    let h = `<div style="display:flex;align-items:center;gap:1rem;flex-wrap:wrap;">
      <span style="font-size:2.2rem;font-weight:800;color:${col};">${g}</span>
      <span style="font-size:1.3rem;">${rating.score}/100</span>
      <span class="hint">Risikopunkte: ${rating.risk_points} · verifiziert: ${rating.verified_count}</span>
    </div><div class="row" style="margin:.5rem 0;">`;
    Object.entries(rating.subscores).forEach(([dim,v])=>{
      const c = GRADE_COL[v.grade]||"#8a92a6";
      h += `<span class="badge" style="border:1px solid ${c};color:${c};">${esc(dim)}: ${v.grade} (${v.score})</span>`;
    });
    h += `</div>`;
    const a = rating.assessment;
    if (a) h += `<p class="hint"><strong>KI-Einschätzung</strong> (${esc(a.source)}, ${esc(a.disclaimer)}):<br>${esc(a.text)}</p>`;
    rv.innerHTML = h;
    renderHeat(rating.heatmap);
  }).catch(()=>{ rv.innerHTML = "<p class='hint'>Rating nicht verfügbar.</p>"; });

  function renderHeat(hm){
    if (!hm || !hm.total_cells){ hv.innerHTML = "<p class='hint'>Keine zählbaren Befunde – keine Heatmap.</p>"; return; }
    const sevs = hm.severities, dims = hm.dimensions, sm = hm.severity_matrix;
    let h = "<table class='heatmap-grid'><tr><th>Kategorie \\ Severity</th>";
    sevs.forEach(sv => h += `<th>${esc(sv)}</th>`);
    h += "<th>Σ Risiko</th></tr>";
    dims.forEach(d => {
      h += `<tr><td class="hm-dim">${esc(d)}</td>`;
      sevs.forEach(sv => {
        const c = sm[d][sv];
        const bg = heatColor(c.intensity);
        h += `<td class="hm-cell" style="background:${bg};" title="${esc(d)} / ${esc(sv)}: ${c.count} Befund(e), Risiko ${c.risk}">${c.count? c.count : '<span class=hm-empty>·</span>'}</td>`;
      });
      h += `<td class="hm-cell">${hm.row_totals[d]}</td></tr>`;
    });
    h += "</table><p class='hint'>Farbe = Risikobeitrag (rating.py-Gewichtung). Zahl = Anzahl Befunde.</p>";
    hv.innerHTML = h;
  }
})();
