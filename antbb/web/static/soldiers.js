/* antbb – Soldaten-Karten (Octogents-Stil, Dark-Terminal).
 * Rendert pro Soldat eine Karte mit Kopf (Avatar+Name+Rolle), Fortschritts-
 * Badge, Tabs (Spawn · Skills · Vault), Playbook-Checklisten mit konkreten
 * Aufgaben, Datei-Chips (todo.md / RESULTS / SKILL.md / Mems) und editierbarer
 * Detailansicht (Overrides + Mems). Reines HTML/CSS/JS, keine Lib.
 */
(function () {
  "use strict";
  const root = document.getElementById("soldier-cards");
  if (!root) return;
  const TID = window.ANTBB_TARGET_ID || null;
  const AVATARS = ["👾","🛸","👻","🤖","🐜","🕷️","🦾","🧿","🔭","📡","🛰️","🧬","🔑","🧨","📶","⚙️"];
  const filterBox = document.getElementById("soldier-filter");

  function api(url, opts) { return fetch(url, opts).then(r => r.json()); }
  function esc(s){return (s==null?"":String(s)).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));}

  let REG = null;           // capabilities registry
  const DETAIL = {};        // name -> detail payload cache

  function taskKey(pb, task){ return "task:" + pb + ":" + task; }

  function doneCount(detail) {
    let done = 0, total = 0;
    const ovmap = {};
    (detail.overrides||[]).forEach(o => { ovmap[o.playbook+"|"+o.key] = o.value; });
    (detail.soldier.playbooks||[]).forEach(pb => {
      (pb.task_items||[]).forEach(ti => {
        total++;
        const v = ovmap[pb.name+"|"+taskKey(pb.name, ti.task)];
        if (v === "done" || v === "verifiziert") done++;
      });
    });
    return {done, total, ovmap};
  }

  function card(sol) {
    const idx = (REG.soldiers.indexOf(sol)) % AVATARS.length;
    const el = document.createElement("div");
    el.className = "soldier-card";
    el.dataset.name = sol.name;
    el.dataset.search = (sol.name+" "+sol.specialty+" "+sol.role+" "+
      (sol.playbooks||[]).map(p=>p.name+" "+(p.task_items||[]).map(t=>t.task).join(" ")).join(" ")).toLowerCase();
    el.innerHTML = `
      <div class="sc-head">
        <span class="sc-avatar">${AVATARS[idx]}</span>
        <div class="sc-id">
          <div class="sc-name">${esc(sol.specialty||sol.name)}</div>
          <div class="sc-role">${esc(sol.role)}</div>
        </div>
        <span class="sc-badge" data-badge>…</span>
      </div>
      <div class="sc-tabs">
        <button data-tab="skills" class="active">Skills</button>
        <button data-tab="spawn">Spawn</button>
        <button data-tab="vault">Vault</button>
      </div>
      <div class="sc-bar"><span data-bar></span></div>
      <div class="sc-body" data-body>lädt…</div>
      <div class="sc-files">
        <span class="chip" data-file="todo">todo.md</span>
        <span class="chip" data-file="active">ACTIVE_RESULTS.md</span>
        <span class="chip" data-file="passive">PASSIVE_RESULTS.md</span>
        <span class="chip" data-file="skill">SKILL.md</span>
        <span class="chip" data-file="mem">🧠 Mems</span>
      </div>`;
    root.appendChild(el);

    const body = el.querySelector("[data-body]");
    el.querySelectorAll(".sc-tabs button").forEach(b => {
      b.onclick = () => {
        el.querySelectorAll(".sc-tabs button").forEach(x=>x.classList.remove("active"));
        b.classList.add("active");
        renderTab(sol.name, b.dataset.tab, body);
      };
    });
    el.querySelectorAll(".sc-files .chip").forEach(c => {
      c.onclick = () => renderFile(sol.name, c.dataset.file, body);
    });

    loadDetail(sol.name).then(()=>{ renderTab(sol.name, "skills", body); updateBadge(sol.name, el); });
    return el;
  }

  function loadDetail(name) {
    const u = "/api/soldiers/" + encodeURIComponent(name) + (TID?("?target_id="+TID):"");
    return api(u).then(d => { DETAIL[name] = d; return d; });
  }

  function updateBadge(name, el) {
    const d = DETAIL[name]; if (!d) return;
    const {done, total} = doneCount(d);
    const badge = el.querySelector("[data-badge]");
    badge.textContent = done + "/" + total;
    badge.className = "sc-badge " + (done===total && total>0 ? "full" : done>0 ? "part" : "");
    const pct = total? Math.round(100*done/total):0;
    el.querySelector("[data-bar]").style.width = pct + "%";
  }

  function renderTab(name, tab, body) {
    const d = DETAIL[name]; if (!d) return;
    if (tab === "skills") return renderSkills(name, body);
    if (tab === "spawn") return renderSpawn(name, body);
    if (tab === "vault") return renderVault(name, body);
  }

  function renderSkills(name, body) {
    const d = DETAIL[name];
    const {ovmap} = doneCount(d);
    let h = "";
    (d.soldier.playbooks||[]).forEach(pb => {
      const enabledOv = ovmap[pb.name+"|enabled"];
      const enabled = !(enabledOv && ["false","0","no","off"].includes(String(enabledOv).toLowerCase()));
      h += `<div class="pb ${enabled?"":"pb-off"}">
        <div class="pb-head">
          <label class="pb-en"><input type="checkbox" ${enabled?"checked":""}
            data-pb-enable="${esc(pb.name)}"> ${esc(pb.name)}</label>
          <span class="pb-mode ${pb.mode}">${pb.mode}${pb.oversight_required?" · OVERSIGHT":""}</span>
        </div>
        <div class="pb-desc">${esc(pb.description)}</div>
        <ul class="tasks">`;
      (pb.task_items||[]).forEach(ti => {
        const v = ovmap[pb.name+"|"+taskKey(pb.name, ti.task)] || "offen";
        const checked = (v==="done"||v==="verifiziert");
        h += `<li>
          <label><input type="checkbox" ${checked?"checked":""}
            data-task-pb="${esc(pb.name)}" data-task="${esc(ti.task)}">
            ${esc(ti.task)}</label>
          <span class="tstat ${checked?"done":"open"}">${checked?v:"offen"}</span>
          ${ti.oversight?'<span class="tov">🔒</span>':''}
        </li>`;
      });
      h += `</ul></div>`;
    });
    body.innerHTML = h;
    body.querySelectorAll("[data-task]").forEach(cb => {
      cb.onchange = () => {
        const pb = cb.dataset.taskPb, task = cb.dataset.task;
        const val = cb.checked ? "done" : "offen";
        post("/api/soldiers/"+encodeURIComponent(name)+"/override",
             {playbook:pb, key:taskKey(pb,task), value:val})
          .then(()=>loadDetail(name)).then(()=>{ refreshCard(name); });
      };
    });
    body.querySelectorAll("[data-pb-enable]").forEach(cb => {
      cb.onchange = () => {
        post("/api/soldiers/"+encodeURIComponent(name)+"/override",
             {playbook:cb.dataset.pbEnable, key:"enabled", value: cb.checked?"true":"false"})
          .then(()=>loadDetail(name)).then(()=>refreshCard(name));
      };
    });
  }

  function renderSpawn(name, body) {
    const d = DETAIL[name];
    const ov = (d.overrides||[]).find(o=>o.playbook===""&&o.key==="enabled");
    const enabled = !(ov && ["false","0","no","off"].includes(String(ov.value).toLowerCase()));
    body.innerHTML = `
      <p class="hint">Soldat für den nächsten Schwarm-Lauf zuweisen. Scope + Oversight
         bleiben Pflicht; offensive Playbooks laufen nur bei freigeschaltetem Offensiv-Modus.</p>
      <label class="pb-en"><input type="checkbox" ${enabled?"checked":""} data-soldier-enable>
        Soldat aktiviert (nimmt am Lauf teil)</label>
      <p class="hint">Zum Starten: oben in der Scan-Sektion „Scan starten" nutzen –
         die Königin dispatcht alle aktivierten Soldaten.</p>`;
    body.querySelector("[data-soldier-enable]").onchange = (e) => {
      post("/api/soldiers/"+encodeURIComponent(name)+"/override",
           {playbook:"", key:"enabled", value: e.target.checked?"true":"false"})
        .then(()=>loadDetail(name)).then(()=>refreshCard(name));
    };
  }

  function renderVault(name, body) {
    const d = DETAIL[name];
    let h = `<p class="hint">Editierbare Dateien/Daten des Soldaten:</p>
      <div class="vault-grid">
        <button class="vfile" data-file="todo">📄 todo.md</button>
        <button class="vfile" data-file="active">📄 ACTIVE_RESULTS.md</button>
        <button class="vfile" data-file="passive">📄 PASSIVE_RESULTS.md</button>
        <button class="vfile" data-file="skill">📄 SKILL.md</button>
        <button class="vfile" data-file="mem">🧠 Mems</button>
      </div>
      <div class="vault-view" data-vault>Datei wählen…</div>`;
    body.innerHTML = h;
    body.querySelectorAll(".vfile").forEach(b=>{
      b.onclick = () => renderFile(name, b.dataset.file, body, body.querySelector("[data-vault]"));
    });
  }

  function renderFile(name, file, body, target) {
    const d = DETAIL[name];
    // Wenn Vault-View existiert, dorthin; sonst Body ersetzen.
    let tgt = target || body.querySelector("[data-vault]");
    if (!tgt) { renderVault(name, body); tgt = body.querySelector("[data-vault]"); }
    if (file === "mem") return renderMems(name, tgt);
    let txt = "";
    if (file === "todo") {
      txt = "# todo.md — " + name + "\n\n";
      (d.soldier.playbooks||[]).forEach(pb => {
        txt += "## " + pb.name + " ["+pb.mode+(pb.oversight_required?" · oversight":"")+"]\n";
        (pb.task_items||[]).forEach(ti => { txt += "- [ ] " + ti.task + "\n"; });
        txt += "\n";
      });
    } else if (file === "skill") {
      const sk = d.soldier.skill || {};
      const full = sk.skill_md || ("# SKILL.md — " + (sk.name||name) + "\n\n" + (sk.summary||d.soldier.role));
      tgt.innerHTML = `<p class="hint">SKILL.md (Octogent-Format${sk.skill_md_edited?", bearbeitet":""}) — editierbar:</p>
        <textarea data-skill-md style="width:100%;max-width:none;min-height:220px;font-family:monospace;font-size:.7rem;">${esc(full)}</textarea>
        <button data-skill-save>SKILL.md speichern</button>`;
      tgt.querySelector("[data-skill-save]").onclick = () => {
        post("/api/soldiers/"+encodeURIComponent(name)+"/override",
             {playbook:"", key:"skill_md", value: tgt.querySelector("[data-skill-md]").value})
          .then(()=>loadDetail(name)).then(()=>renderFile(name, "skill", body, tgt));
      };
      return;
    } else if (file === "active" || file === "passive") {
      const want = file === "active" ? ["VERIFIZIERT","ZU BESTÄTIGEN","BEDINGT"] : ["BESTÄTIGT(PASSIV)","REFERENZ",""];
      const rows = (d.results||[]).filter(r => want.includes(r.status||""));
      txt = "# " + (file==="active"?"ACTIVE":"PASSIVE") + "_RESULTS.md — letzter Lauf\n\n";
      if (!rows.length) txt += "_(keine Ergebnisse — ehrlicher Leerzustand)_\n";
      rows.forEach(r => { txt += `- [${r.severity}] ${r.title} — ${r.status||"n/a"} @ ${r.asset||"n/a"}\n`; });
    }
    tgt.innerHTML = `<pre class="vault-pre">${esc(txt)}</pre>`;
  }

  function renderMems(name, tgt) {
    const d = DETAIL[name];
    let h = `<div class="mem-add">
        <textarea data-mem-text placeholder="Neue Mem/Notiz für ${esc(name)} …"></textarea>
        <button data-mem-save>Mem speichern</button>
      </div><ul class="mem-list">`;
    (d.mems||[]).forEach(m => {
      h += `<li><span>${esc(m.text)}</span>
        <button class="mem-del" data-mem-id="${m.id}">✕</button></li>`;
    });
    h += `</ul>`;
    tgt.innerHTML = h;
    tgt.querySelector("[data-mem-save]").onclick = () => {
      const t = tgt.querySelector("[data-mem-text]").value.trim();
      if (!t) return;
      post("/api/soldiers/"+encodeURIComponent(name)+"/mem", {text:t})
        .then(()=>loadDetail(name)).then(()=>renderMems(name, tgt));
    };
    tgt.querySelectorAll(".mem-del").forEach(b => {
      b.onclick = () => fetch("/api/soldiers/"+encodeURIComponent(name)+"/mem/"+b.dataset.memId,
        {method:"DELETE"}).then(()=>loadDetail(name)).then(()=>renderMems(name, tgt));
    });
  }

  function post(url, obj) {
    return fetch(url, {method:"POST", headers:{"Content-Type":"application/json"},
      body: JSON.stringify(obj)}).then(r=>r.json());
  }

  function refreshCard(name) {
    const el = root.querySelector('.soldier-card[data-name="'+CSS.escape(name)+'"]');
    if (!el) return;
    updateBadge(name, el);
    const active = el.querySelector(".sc-tabs button.active");
    if (active) renderTab(name, active.dataset.tab, el.querySelector("[data-body]"));
  }

  if (filterBox) {
    filterBox.oninput = () => {
      const q = filterBox.value.toLowerCase().trim();
      root.querySelectorAll(".soldier-card").forEach(c => {
        c.style.display = (!q || c.dataset.search.includes(q)) ? "" : "none";
      });
    };
  }

  function renderPhases(reg) {
    const host = document.getElementById("octogent-phases");
    if (!host) return;
    let h = "<div class='phase-strip'>";
    (reg.octogent_phases||[]).forEach(ph => {
      const off = ph.mode === "offensive";
      h += `<div class="phase-box ${off?'ph-off':'ph-def'}" title="${esc(ph.note||'')}">
        <div class="phase-name">${esc(ph.label)}</div>
        <div class="phase-sol">${(ph.soldiers||[]).map(esc).join(", ")}</div>
        <div class="phase-tools hint">${(ph.tools||[]).map(esc).join(" · ")}</div>
        ${off?'<span class="pb-mode offensive">offensiv · oversight</span>':'<span class="pb-mode">defensiv</span>'}
      </div>`;
    });
    h += "</div>";
    const sug = reg.scope_suggestions;
    if (sug) {
      h += `<p class="hint">📌 Scope-Vorschläge (NICHT automatisch erlaubt — default-deny bleibt): `
        + (sug.targets||[]).map(esc).join(", ")
        + (sug.separate_engagement?` · separat: ${(sug.separate_engagement||[]).map(esc).join(", ")}`:"")
        + `</p>`;
    }
    host.innerHTML = h;
  }


  function renderBluePhases(reg) {
    const host = document.getElementById("octogent-phases");
    if (!host) return;
    const phases = reg.blue_phases || ["assess","harden","defend","remediate","verify"];
    const labels = {assess:"Assess", harden:"Harden", defend:"Defend",
                    remediate:"Remediate", verify:"Verify"};
    host.innerHTML = '<div class="phase-row">' + phases.map(ph =>
      '<div class="phase-chip blue"><b>' + (labels[ph]||ph) + '</b></div>').join("") + "</div>"
      + '<p class="hint">Verteidigungs-Phasen der Blue Queen (Assess → Harden → Defend → Remediate → Verify).</p>';
  }

  api("/api/soldiers").then(reg => {
    REG = reg;
    root.innerHTML = "";
    const colony = (window.ANTBB_COLONY || "").toLowerCase();
    let list = (reg.soldiers||[]);
    if (colony === "blue") {
      list = list.filter(s => s.colony === "blue" || (s.name||"").startsWith("blue-"));
      renderBluePhases(reg);
    } else {
      list = list.filter(s => s.colony !== "blue" && !(s.name||"").startsWith("blue-"));
      renderPhases(reg);
    }
    REG.soldiers = list;
    list.forEach(card);
    const sum = document.getElementById("soldier-summary");
    if (sum) {
      const pbs = list.reduce((n,s)=>n+(s.playbooks||[]).length,0);
      const tasks = list.reduce((n,s)=>n+((s.skill&&s.skill.task_count)||0),0);
      sum.textContent = list.length + " Soldaten · " + pbs + " Playbooks · " + tasks + " Aufgaben"
        + (colony === "blue" ? " · 🛡 Blue Queen" : "");
    }
  }).catch(e => { root.innerHTML = "<p class='blocked'>Fehler beim Laden der Soldaten.</p>"; });
})();
