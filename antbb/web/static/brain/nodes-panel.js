/* Neuronales Gehirn — Node-/Log-Overlay.
 *
 * Rein additiv: liest /api/brain/nodes, /node/..., /logs und ruft die
 * HUMAN-ONLY Lösch-/Reset-Endpunkte NUR nach einer Bestätigung durch die
 * Nutzerin auf (window.confirm). Jeder destruktive Call sendet das Flag
 * human_confirm=true (serverseitig hart erzwungen; Agenten/Königin kommen
 * hier nicht heran). Die GPU-Partikel-Engine wird nicht berührt.
 */
(function () {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const TYPE_LABEL = { target: "🎯 Ziele", run: "🌀 Läufe", finding: "🐞 Funde",
    soldier: "🐜 Soldaten" };
  const TYPE_ORDER = ["run", "target", "soldier", "finding"];

  // Blue Queen hat eigene Ansicht (/blue) — nie im Brain-Panel listen.
  function isBlueSoldier(n) {
    if (!n) return false;
    if (n.colony === "blue") return true;
    const name = String(n.label || n.id || "").replace(/^soldier:/, "").toLowerCase();
    return name.startsWith("blue") || name.startsWith("blue-") ||
      ["defense", "hardening", "honeypot", "remediation", "swscan"].includes(name);
  }

  // Menschliche Bestätigung inkl. Backup-Hinweis.
  function humanConfirm(msg) {
    return window.confirm(
      msg + "\n\nWirklich fortfahren? Es wird automatisch ein DB-Backup angelegt." +
      "\n(Nur ein Mensch darf dies auslösen — Agenten/Königin nicht.)");
  }

  async function api(url, opts) {
    const r = await fetch(url, opts || {});
    let body = null;
    try { body = await r.json(); } catch (e) { body = null; }
    return { ok: r.ok, status: r.status, body };
  }
  const hc = (u) => (u.indexOf("?") >= 0 ? u + "&" : u + "?") + "human_confirm=true";

  // --------------------------- Knoten laden ---------------------------
  let GRAPH = null;
  async function loadNodes() {
    const res = await api("/api/brain/nodes");
    if (!res.ok) { $("bp-nodes").textContent = "Fehler beim Laden."; return; }
    GRAPH = res.body;
    renderCounts(GRAPH.counts, GRAPH.stuck_runs);
    renderNodes(GRAPH.nodes);
  }

  function renderCounts(c, stuck) {
    const el = $("bp-counts");
    el.innerHTML = "";
    const chips = [
      ["Ziele", c.targets], ["Läufe", c.runs], ["Funde", c.findings],
      ["Logs", c.logs],
    ];
    chips.forEach(([k, v]) => {
      const s = document.createElement("span");
      s.className = "bp-chip"; s.textContent = `${k}: ${v}`; el.appendChild(s);
    });
    if (c.stuck_runs > 0) {
      const s = document.createElement("span");
      s.className = "bp-chip warn"; s.textContent = `⚠ hängt/läuft: ${c.stuck_runs}`;
      el.appendChild(s);
    }
  }

  function renderNodes(nodes) {
    const host = $("bp-nodes");
    host.innerHTML = "";
    const byType = {};
    nodes.forEach((n) => {
      if (n.type === "soldier" && isBlueSoldier(n)) return;
      (byType[n.type] = byType[n.type] || []).push(n);
    });
    TYPE_ORDER.forEach((t) => {
      const list = byType[t];
      if (!list || !list.length) return;
      const h = document.createElement("div");
      h.className = "bp-group";
      h.textContent = (TYPE_LABEL[t] || t) + " (" + list.length + ")";
      host.appendChild(h);
      list.forEach((n) => host.appendChild(nodeRow(n)));
    });
  }

  function nodeRow(n) {
    const row = document.createElement("div");
    row.className = "bp-node";
    const dot = document.createElement("span");
    dot.className = "bp-dot " + (n.severity || n.type);
    row.appendChild(dot);
    const lbl = document.createElement("span");
    lbl.className = "lbl";
    lbl.textContent = n.label || n.id;
    row.appendChild(lbl);
    // Status-/Lauf-Badge
    if (n.type === "run") {
      const b = document.createElement("span");
      b.className = "bp-badge " + (n.status || "");
      b.textContent = n.status;
      row.appendChild(b);
      if (n.running) {
        const rb = document.createElement("button");
        rb.className = "bp-reset"; rb.textContent = "⟲ reset";
        rb.title = "Lauf zurücksetzen (human-only)";
        rb.onclick = (e) => { e.stopPropagation(); resetRun(n); };
        row.appendChild(rb);
      }
    } else if (n.type === "soldier") {
      const pb = (n.counts && n.counts.playbooks) || 0;
      if (pb) {
        const badge = document.createElement("span");
        badge.className = "bp-badge";
        badge.title = pb + " Playbooks";
        badge.textContent = pb + " PB";
        row.appendChild(badge);
      }
      const rb = document.createElement("button");
      rb.className = "bp-reset"; rb.textContent = "⟲";
      rb.title = "Soldat-Anzeige zurücksetzen (human-only)";
      rb.onclick = (e) => { e.stopPropagation(); resetAgent(n); };
      row.appendChild(rb);
    } else if (n.severity) {
      const b = document.createElement("span");
      b.className = "bp-badge"; b.textContent = n.severity;
      row.appendChild(b);
    }
    row.onclick = () => openDetail(n);
    return row;
  }

  // --------------------------- Detail ---------------------------
  async function openDetail(n) {
    const [type, ...rest] = n.id.split(":");
    const rid = rest.join(":");
    const res = await api(`/api/brain/node/${encodeURIComponent(type)}/${encodeURIComponent(rid)}`);
    const body = $("bp-detail-body");
    if (!res.ok) { body.innerHTML = "<p>Nicht gefunden.</p>"; }
    else { body.innerHTML = detailHtml(res.body, n); }
    $("bp-detail").style.display = "flex";
    $("bp-detail").classList.toggle("sol-wide", !!(res.body && res.body.type === "soldier"));
    wireDetailActions(res.body, n);
    wireSoldierTabs(body);
  }

  function esc(s) { return (s == null ? "" : String(s)).replace(/[&<>"]/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c])); }

  function detailHtml(d, n) {
    if (d.type === "target") {
      const t = d.target;
      let h = `<h3>🎯 ${esc(t.name)}</h3><table>
        <tr><td class="bp-kv">Status</td><td>${t.archived_at ? "archiviert" : "aktiv"}</td></tr>
        <tr><td class="bp-kv">Funde</td><td>${d.finding_count}</td></tr>
        <tr><td class="bp-kv">Läufe</td><td>${d.runs.length}</td></tr></table>`;
      h += `<p><button class="btn-danger" data-act="del-target" data-id="${t.id}">🗑 Ziel hart löschen (Purge)</button>
        <span class="bp-hint">Nicht der Papierkorb — endgültig. Königin-Wissen bleibt.</span></p>`;
      if (d.findings.length) {
        h += "<h4>Funde</h4><table>";
        d.findings.forEach((f) => { h += `<tr><td class="bp-kv">[${esc(f.severity)}]</td>
          <td>${esc(f.title)}</td><td><button class="btn-danger" data-act="del-finding" data-id="${f.id}">🗑</button></td></tr>`; });
        h += "</table>";
      }
      return h;
    }
    if (d.type === "run") {
      const r = d.run;
      let h = `<h3>🌀 Lauf ${esc(r.run_id)}</h3><table>
        <tr><td class="bp-kv">Status</td><td>${esc(d.status_label)} (${esc(r.status)})</td></tr>
        <tr><td class="bp-kv">Log-Zeilen</td><td>${d.log_count}</td></tr></table>`;
      if (d.running) {
        h += `<p><button class="bp-reset" data-act="reset-run" data-id="${esc(r.run_id)}">⟲ Lauf zurücksetzen</button></p>`;
      }
      h += `<p><button class="btn-danger" data-act="del-run" data-id="${esc(r.run_id)}">🗑 Lauf + Logs löschen</button></p>`;
      h += logsHtml(d.logs);
      return h;
    }
    if (d.type === "finding") {
      const f = d.finding;
      let h = `<h3>🐞 ${esc(f.title)}</h3><table>
        <tr><td class="bp-kv">Schwere</td><td>${esc(f.severity)}</td></tr>
        <tr><td class="bp-kv">Status</td><td>${esc(f.status)}</td></tr>
        <tr><td class="bp-kv">Soldat</td><td>${esc(f.agent)}</td></tr>
        <tr><td class="bp-kv">Asset</td><td>${esc(f.asset)}</td></tr>
        <tr><td class="bp-kv">Zeit</td><td>${esc(f.created_fmt)}</td></tr></table>`;
      h += `<p><button class="btn-danger" data-act="del-finding" data-id="${f.id}">🗑 Fund löschen</button></p>`;
      h += logsHtml(d.logs);
      return h;
    }
    if (d.type === "soldier") {
      return soldierDetailHtml(d);
    }
    return "<p>—</p>";
  }

  /** Kleiner sicherer Markdown→HTML-Renderer für SKILL.md (kein HTML aus Quelle). */
  function mdLite(src) {
    const lines = String(src || "").replace(/\r\n/g, "\n").split("\n");
    let html = "", inCode = false, inUl = false, inOl = false;
    const closeLists = () => {
      if (inUl) { html += "</ul>"; inUl = false; }
      if (inOl) { html += "</ol>"; inOl = false; }
    };
    const inline = (s) => esc(s)
      .replace(/`([^`]+)`/g, "<code>$1</code>")
      .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
      .replace(/\*([^*]+)\*/g, "<em>$1</em>");
    for (let i = 0; i < lines.length; i++) {
      const raw = lines[i];
      if (raw.trim().startsWith("```")) {
        if (inCode) { html += "</code></pre>"; inCode = false; }
        else { closeLists(); html += "<pre class='skill-pre'><code>"; inCode = true; }
        continue;
      }
      if (inCode) { html += esc(raw) + "\n"; continue; }
      if (/^---+$/.test(raw.trim()) && i < 8) { closeLists(); continue; } // YAML-Frontmatter-Trenner
      if (/^(name|description|version|source|license)\s*:/.test(raw) && i < 12) {
        closeLists();
        const m = raw.match(/^(\w+)\s*:\s*(.*)$/);
        if (m) html += `<div class="skill-meta"><span>${esc(m[1])}</span>${inline(m[2].replace(/^"|"$/g,""))}</div>`;
        continue;
      }
      const hm = raw.match(/^(#{1,4})\s+(.*)$/);
      if (hm) {
        closeLists();
        const lvl = hm[1].length;
        html += `<h${lvl + 2} class="skill-h">${inline(hm[2])}</h${lvl + 2}>`;
        continue;
      }
      if (/^>\s?/.test(raw)) {
        closeLists();
        html += `<blockquote class="skill-quote">${inline(raw.replace(/^>\s?/, ""))}</blockquote>`;
        continue;
      }
      if (/^[-*]\s+/.test(raw)) {
        if (!inUl) { closeLists(); html += "<ul class='skill-ul'>"; inUl = true; }
        html += `<li>${inline(raw.replace(/^[-*]\s+/, ""))}</li>`;
        continue;
      }
      if (/^\d+\.\s+/.test(raw)) {
        if (!inOl) { closeLists(); html += "<ol class='skill-ol'>"; inOl = true; }
        html += `<li>${inline(raw.replace(/^\d+\.\s+/, ""))}</li>`;
        continue;
      }
      if (!raw.trim()) { closeLists(); continue; }
      closeLists();
      html += `<p class="skill-p">${inline(raw)}</p>`;
    }
    closeLists();
    if (inCode) html += "</code></pre>";
    return html || "<p class='bp-hint'>_(SKILL.md leer)_</p>";
  }

  function soldierDetailHtml(d) {
    const pbs = d.playbooks || [];
    const sk = d.skill || {};
    const skillMd = sk.skill_md || "";
    const title = d.specialty || d.name;
    let h = `<div class="sol-detail">
      <div class="sol-hero">
        <span class="sol-ant" aria-hidden="true">🐜</span>
        <div>
          <h3>${esc(title)}</h3>
          <div class="sol-sub"><code>${esc(d.name)}</code>
            ${d.colony === "blue" ? '' : '<span class="pb-mode">⚔ red</span>'}
          </div>
          <p class="sol-role">${esc(d.role || sk.summary || "")}</p>
        </div>
      </div>
      <div class="sol-stats">
        <span class="sol-stat"><b>${pbs.length}</b> Playbooks</span>
        <span class="sol-stat"><b>${(sk.task_count != null ? sk.task_count : pbs.reduce((n,p)=>n+(p.task_items||[]).length,0))}</b> Aufgaben</span>
        <span class="sol-stat"><b>${d.finding_count || 0}</b> Funde</span>
        <span class="sol-stat">${skillMd ? "SKILL.md ✓" : "kein SKILL.md"}</span>
      </div>
      <div class="sol-tabs">
        <button type="button" class="active" data-sol-tab="playbooks">Playbooks</button>
        <button type="button" data-sol-tab="skill">SKILL.md</button>
        <button type="button" data-sol-tab="findings">Funde</button>
      </div>
      <div data-sol-pane="playbooks">`;
    if (!pbs.length) {
      h += `<p class="bp-hint">Keine Playbooks in der Registry — ehrlicher Leerzustand.</p>`;
    } else {
      pbs.forEach((pb) => {
        const tasks = pb.task_items || [];
        h += `<div class="sol-pb ${pb.mode === "offensive" ? "off" : "def"}">
          <div class="sol-pb-head">
            <strong>${esc(pb.name)}</strong>
            <span class="pb-mode ${pb.mode || ""}">${esc(pb.mode || "defensive")}${pb.oversight_required ? " · OVERSIGHT" : ""}</span>
          </div>
          <p class="sol-pb-desc">${esc(pb.description || "")}</p>`;
        if (pb.tools && pb.tools.length) {
          h += `<div class="sol-tools">${pb.tools.map((t) => `<span class="chip">${esc(t)}</span>`).join("")}</div>`;
        }
        if (tasks.length) {
          h += `<ol class="sol-tasks">`;
          tasks.forEach((ti) => {
            const t = (typeof ti === "string") ? ti : (ti.task || "");
            const ov = (typeof ti === "object" && ti.oversight) ? " 🔒" : "";
            h += `<li>${esc(t)}${ov}</li>`;
          });
          h += `</ol>`;
        }
        h += `</div>`;
      });
    }
    h += `</div>
      <div data-sol-pane="skill" style="display:none">
        <div class="skill-md">${skillMd ? mdLite(skillMd) : "<p class='bp-hint'>Kein SKILL.md für diesen Soldaten hinterlegt.</p>"}</div>
      </div>
      <div data-sol-pane="findings" style="display:none">`;
    if (!(d.findings || []).length) {
      h += `<p class="bp-hint">Noch keine Funde dieses Soldaten.</p>`;
    } else {
      h += "<table>";
      d.findings.forEach((f) => {
        h += `<tr><td class="bp-kv">[${esc(f.severity)}]</td><td>${esc(f.title)}</td></tr>`;
      });
      h += "</table>";
    }
    h += `</div>
      <p class="sol-actions">
        <button class="bp-reset" data-act="reset-agent" data-id="${esc(d.name)}">⟲ Anzeige zurücksetzen</button>
      </p>
    </div>`;
    return h;
  }

  function wireSoldierTabs(body) {
    const tabs = body.querySelectorAll("[data-sol-tab]");
    if (!tabs.length) return;
    tabs.forEach((btn) => {
      btn.onclick = () => {
        tabs.forEach((x) => x.classList.remove("active"));
        btn.classList.add("active");
        body.querySelectorAll("[data-sol-pane]").forEach((p) => {
          p.style.display = p.getAttribute("data-sol-pane") === btn.getAttribute("data-sol-tab") ? "" : "none";
        });
      };
    });
  }

  function logsHtml(logs) {
    if (!logs || !logs.length) return '<p class="bp-hint">Keine Log-Zeilen.</p>';
    let h = "<h4>Logs</h4><div class='bp-logs'>";
    logs.forEach((l) => {
      h += `<div class="bp-logline"><span class="t">${esc(l.created_fmt)}</span> `
        + `<span class="a">[${esc(l.agent || l.kind)}]</span> ${esc(l.msg || l.kind)}</div>`;
    });
    return h + "</div>";
  }

  function wireDetailActions(d, n) {
    const body = $("bp-detail-body");
    body.querySelectorAll("[data-act]").forEach((btn) => {
      btn.onclick = async () => {
        const act = btn.getAttribute("data-act");
        const id = btn.getAttribute("data-id");
        if (act === "del-target") {
          if (!humanConfirm(`Ziel #${id} ENDGÜLTIG löschen (Purge inkl. Funde/Läufe)?`)) return;
          await doWrite(hc(`/api/brain/target/${id}`), "DELETE");
        } else if (act === "del-finding") {
          if (!humanConfirm(`Fund #${id} löschen?`)) return;
          await doWrite(hc(`/api/brain/finding/${id}`), "DELETE");
        } else if (act === "del-run") {
          if (!humanConfirm(`Lauf ${id} inkl. Logs löschen?`)) return;
          await doWrite(hc(`/api/brain/run/${encodeURIComponent(id)}`), "DELETE");
        } else if (act === "reset-run") {
          if (!humanConfirm(`Lauf ${id} zurücksetzen (Teil-Artefakte verwerfen)?`)) return;
          await doWrite(hc(`/api/brain/run/${encodeURIComponent(id)}/reset`), "POST");
        } else if (act === "reset-agent") {
          if (!humanConfirm(`Soldat ${id} zurücksetzen?`)) return;
          await doWrite(hc(`/api/brain/agent/${encodeURIComponent(id)}/reset`), "POST");
        }
        closeDetail(); loadNodes();
      };
    });
  }

  async function doWrite(url, method) {
    const res = await api(url, { method: method,
      headers: { "x-human-confirm": "1", "content-type": "application/json" },
      body: JSON.stringify({ human_confirm: true }) });
    if (!res.ok) { alert("Abgelehnt/Fehler (" + res.status + "): "
      + ((res.body && res.body.detail) || "")); }
    return res;
  }

  function resetRun(n) {
    const rid = n.id.split(":").slice(1).join(":");
    if (!humanConfirm(`Lauf ${rid} zurücksetzen?`)) return;
    doWrite(hc(`/api/brain/run/${encodeURIComponent(rid)}/reset`), "POST").then(loadNodes);
  }
  function resetAgent(n) {
    const name = n.id.split(":").slice(1).join(":");
    if (!humanConfirm(`Soldat ${name} zurücksetzen?`)) return;
    doWrite(hc(`/api/brain/agent/${encodeURIComponent(name)}/reset`), "POST").then(loadNodes);
  }
  function closeDetail() { $("bp-detail").style.display = "none"; }

  // --------------------------- Logs-Tab ---------------------------
  async function loadLogs() {
    const t = $("bp-log-target").value.trim();
    const r = $("bp-log-run").value.trim();
    let url = "/api/brain/logs?limit=300";
    if (t) url += "&target_id=" + encodeURIComponent(t);
    if (r) url += "&run_id=" + encodeURIComponent(r);
    const res = await api(url);
    const host = $("bp-logs");
    if (!res.ok) { host.textContent = "Fehler."; return; }
    const logs = res.body.logs || [];
    if (!logs.length) { host.innerHTML = '<p class="bp-hint">Keine Logs (gefiltert).</p>'; return; }
    host.innerHTML = logs.map((l) =>
      `<div class="bp-logline"><span class="t">${esc(l.created_fmt)}</span> `
      + `<span class="a">[${esc(l.agent || l.kind)}]</span> ${esc(l.msg || l.kind)}</div>`).join("");
  }

  async function deleteLogs() {
    const t = $("bp-log-target").value.trim();
    const r = $("bp-log-run").value.trim();
    let scopeTxt, url = "/api/brain/logs";
    const q = [];
    if (r) { q.push("run_id=" + encodeURIComponent(r)); scopeTxt = "Lauf " + r; }
    if (t) { q.push("target_id=" + encodeURIComponent(t)); scopeTxt = (scopeTxt ? scopeTxt + " / " : "") + "Target " + t; }
    if (!q.length) { q.push("all=true"); scopeTxt = "ALLE Logs"; }
    if (!humanConfirm(`${scopeTxt} löschen?`)) return;
    url += "?" + q.join("&") + "&human_confirm=true";
    await doWrite(url, "DELETE");
    loadLogs();
  }

  // --------------------------- Alles löschen ---------------------------
  async function deleteAll() {
    if (!humanConfirm("ALLE operativen Daten löschen (Ziele, Funde, Läufe, Logs)?")) return;
    if (!humanConfirm("Zweite Bestätigung: Das kann nicht rückgängig gemacht werden (außer via Backup).")) return;
    await doWrite(hc("/api/brain/all"), "DELETE");
    loadNodes();
  }

  // --------------------------- Wiring ---------------------------
  function switchTab(tab) {
    document.querySelectorAll(".bp-tabs button").forEach((b) =>
      b.classList.toggle("active", b.getAttribute("data-tab") === tab));
    $("bp-view-nodes").style.display = tab === "nodes" ? "" : "none";
    $("bp-view-logs").style.display = tab === "logs" ? "" : "none";
    if (tab === "logs") loadLogs();
  }

  function init() {
    $("bp-refresh").onclick = loadNodes;
    $("bp-toggle").onclick = () => $("brain-panel").classList.toggle("collapsed");
    $("bp-detail-close").onclick = closeDetail;
    $("bp-detail").onclick = (e) => { if (e.target === $("bp-detail")) closeDetail(); };
    $("bp-del-all").onclick = deleteAll;
    $("bp-log-apply").onclick = loadLogs;
    $("bp-log-del").onclick = deleteLogs;
    document.querySelectorAll(".bp-tabs button").forEach((b) =>
      b.onclick = () => switchTab(b.getAttribute("data-tab")));
    // Ameisen-Overlay: Klick auf Soldat öffnet dieselbe Detailansicht (Playbooks/SKILL).
    window.addEventListener("antbb-open-soldier", (ev) => {
      const name = ev && ev.detail && ev.detail.name;
      if (!name) return;
      openDetail({ id: "soldier:" + name, type: "soldier", label: name });
    });
    loadNodes();
    setInterval(loadNodes, 15000); // Lauf-/Hänge-Status aktuell halten
  }
  if (document.readyState === "loading")
    document.addEventListener("DOMContentLoaded", init);
  else init();
})();
