/* antbb – Blue Queen UI: Colony-Start + Job-Scheduler. */
(function () {
  "use strict";
  const log = document.getElementById("blue-run-log");
  const form = document.getElementById("blue-run-form");
  const apply = document.getElementById("blue-apply");
  const ackWrap = document.getElementById("blue-ack-wrap");
  if (apply && ackWrap) {
    apply.addEventListener("change", () => {
      ackWrap.style.display = apply.checked ? "" : "none";
    });
  }
  function append(msg) {
    if (!log) return;
    log.textContent += msg + "\n";
    log.scrollTop = log.scrollHeight;
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
      if (log) log.textContent = "Starte Blue Queen…\n";
      fetch("/api/blue/run", {
        method: "POST", headers: {"Content-Type": "application/json"},
        body: JSON.stringify(body)
      }).then(r => r.json()).then(d => {
        if (d.error) { append("⛔ " + d.error); return; }
        append("✅ run " + d.run_id + " · " + d.finding_count + " Findings · "
               + d.closed_count + " nachweislich geschlossen");
        append("Severity: " + JSON.stringify(d.severity || {}));
        (d.findings || []).slice(0, 30).forEach(f => {
          append(" · [" + f.severity + "/" + f.status + "] " + f.title);
        });
      }).catch(e => append("Fehler: " + e));
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
})();
