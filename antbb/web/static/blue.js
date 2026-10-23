/* antbb – Blue Queen UI: Colony-Start, Stats, Jobs, Blue-Läufe.
 * Eigenständige Ansicht /blue — kein Brain-Mix.
 */
(function () {
  "use strict";
  const log = document.getElementById("blue-run-log");
  const form = document.getElementById("blue-run-form");
  const apply = document.getElementById("blue-apply");
  const ackWrap = document.getElementById("blue-ack-wrap");

  function append(msg) {
    if (!log) return;
    log.textContent += msg + "\n";
    log.scrollTop = log.scrollHeight;
  }

  if (apply && ackWrap) {
    apply.addEventListener("change", () => {
      ackWrap.style.display = apply.checked ? "" : "none";
    });
  }

  if (form) {
    form.addEventListener("submit", function (ev) {
      ev.preventDefault();
      const fd = new FormData(form);
      const body = {
        target_id: fd.get("target_id") ? parseInt(fd.get("target_id"), 10) : null,
        apply_fixes: !!fd.get("apply_fixes"),
        oversight_ack: !!fd.get("oversight_ack"),
        online: true,
      };
      if (log) log.textContent = "🛡 Blue Queen orchestriert die Verteidigungs-Ameisen…\n";
      const go = form.querySelector(".blue-go");
      if (go) { go.disabled = true; go.textContent = "läuft…"; }
      fetch("/api/blue/run", {
        method: "POST", headers: {"Content-Type": "application/json"},
        body: JSON.stringify(body)
      }).then(r => r.json()).then(d => {
        if (d.error) { append("⛔ " + d.error); return; }
        append("✅ run " + d.run_id + " · " + d.finding_count + " Findings · "
               + d.closed_count + " nachweislich geschlossen");
        append("Severity: " + JSON.stringify(d.severity || {}));
        (d.findings || []).slice(0, 40).forEach(f => {
          append(" · [" + f.severity + "/" + f.status + "] " + f.title);
        });
        loadBlueRuns();
        setTimeout(() => location.reload(), 1200);   // Ledger/Zähler frisch vom Server (SSR)
      }).catch(e => append("Fehler: " + e))
        .finally(() => {
          if (go) { go.disabled = false; go.textContent = "🐜🛡 Kolonie starten"; }
        });
    });
  }

  const jobForm = document.getElementById("blue-job-form");
  if (jobForm) {
    jobForm.addEventListener("submit", function (ev) {
      ev.preventDefault();
      const fd = new FormData(jobForm);
      fetch("/api/blue/jobs", {
        method: "POST", headers: {"Content-Type": "application/json"},
        body: JSON.stringify({
          name: fd.get("name"), kind: fd.get("kind"),
          interval_sec: parseInt(fd.get("interval_sec") || "86400", 10)
        })
      }).then(r => r.json()).then(d => {
        if (d.ok) location.reload();
        else alert(d.error || "Fehler");
      });
    });
  }
  document.querySelectorAll(".blue-job-run").forEach(btn => {
    btn.addEventListener("click", function () {
      const id = btn.dataset.id;
      btn.disabled = true; btn.textContent = "läuft…";
      fetch("/api/blue/jobs/" + id + "/run", {method: "POST"})
        .then(r => r.json()).then(d => {
          alert(d.ok
            ? ("OK: " + d.finding_count + " Findings, " + d.closed_count + " geschlossen")
            : ("Fehler: " + (d.error || "?")));
          location.reload();
        }).catch(e => { alert(e); btn.disabled = false; btn.textContent = "jetzt ausführen"; });
    });
  });

  function setStat(id, val) {
    const el = document.getElementById(id);
    if (el) el.textContent = String(val);
  }

  function loadCaps() {
    fetch("/api/blue").then(r => r.json()).then(cap => {
      const sols = cap.soldiers || [];
      let pbs = 0, tasks = 0;
      sols.forEach(s => {
        const list = s.playbooks || [];
        pbs += list.length;
        list.forEach(pb => { tasks += (pb.task_items || pb.tasks || []).length; });
        if (s.skill && s.skill.task_count) {
          /* skill.task_count already sums tasks; prefer playbook walk above */
        }
      });
      // Prefer registry skill totals when richer
      const skillTasks = sols.reduce((n, s) => n + ((s.skill && s.skill.task_count) || 0), 0);
      setStat("bst-soldiers", cap.soldier_count != null ? cap.soldier_count : sols.length);
      setStat("bst-playbooks", pbs);
      setStat("bst-tasks", skillTasks || tasks);
    }).catch(() => {});
  }

  function loadBlueRuns() {
    const host = document.getElementById("blue-runs-list");
    if (!host) return;
    fetch("/api/runs?colony=blue").then(r => r.json()).then(rows => {
      const list = Array.isArray(rows) ? rows : (rows.runs || []);
      if (!list.length) {
        host.innerHTML = "<p class='hint'>Noch keine Blue-Queen-Läufe. Starte oben die Kolonie.</p>";
        return;
      }
      let h = "<ul class='blue-run-list'>";
      list.slice(0, 25).forEach(r => {
        const rid = r.run_id || r.id || "?";
        const fc = r.finding_count != null ? r.finding_count : (r.findings || 0);
        const cc = r.closed_count != null ? r.closed_count : 0;
        const when = r.finished_at || r.started_at || r.ts || "";
        const label = when ? new Date(Number(when) * (Number(when) < 1e12 ? 1000 : 1)).toLocaleString("de-DE") : "";
        h += "<li><code>" + String(rid).replace(/[<>&]/g, "") + "</code>"
          + " · findings=" + fc + " · geschlossen=" + cc
          + (label ? " · " + label : "") + "</li>";
      });
      h += "</ul>";
      host.innerHTML = h;
    }).catch(() => {
      host.innerHTML = "<p class='hint'>Läufe konnten nicht geladen werden.</p>";
    });
  }

  loadCaps();
  loadBlueRuns();

  // Attack-Log laden
  (function loadAttackLog() {
    const body = document.getElementById("alog-body");
    const sum = document.getElementById("alog-summary");
    if (!body) return;
    fetch("/api/blue/attacklog?limit=50").then(r => r.json()).then(d => {
      const rows = d.events || [];
      if (sum) sum.textContent = (d.total != null ? d.total : rows.length) + " Einträge · append-only";
      if (!rows.length) {
        body.innerHTML = '<tr><td colspan="6" class="hint">Noch keine Attack-Log-Einträge. '
          + 'Wächter-Lauf mit Events erzeugt Detections/Diverts/Protects hier.</td></tr>';
        return;
      }
      body.innerHTML = rows.map(e => {
        const ts = e.ts ? new Date(e.ts * 1000).toLocaleString() : "—";
        const esc = s => String(s == null ? "" : s).replace(/[&<>"]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;"}[c]));
        return "<tr><td>" + esc(ts) + "</td><td><code>" + esc(e.event_type) + "</code></td><td>"
          + esc(e.source) + "</td><td>" + esc(e.action) + "</td><td>" + esc(e.countermeasure)
          + "</td><td>" + esc(e.outcome) + "</td></tr>";
      }).join("");
    }).catch(err => {
      if (body) body.innerHTML = '<tr><td colspan="6" class="hint">Attack-Log: ' + err + "</td></tr>";
    });
  })();

})();
