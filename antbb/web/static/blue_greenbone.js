/* antbb – Blue Queen: Greenbone/OpenVAS-Karte (/blue).
 * Status, Report-Import (defensiv) und Scoped-Scan (nur mit Oversight).
 * Alle Ausgaben werden escaped; keine Zugangsdaten im Client.
 */
(function () {
  "use strict";
  const badge = document.getElementById("gb-badge");
  if (!badge) return;
  const msg = document.getElementById("gb-status-msg");
  const out = document.getElementById("gb-result");
  const impForm = document.getElementById("gb-import-form");
  const scanForm = document.getElementById("gb-scan-form");
  const ack = document.getElementById("gb-ack");
  const scanGo = document.getElementById("gb-scan-go");
  const esc = s => String(s == null ? "" : s).replace(/[&<>"']/g,
    c => ({"&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;"}[c]));

  function show(html) { out.hidden = false; out.innerHTML = html; }

  function refreshStatus() {
    fetch("/api/blue/greenbone/status").then(r => r.json()).then(st => {
      let cls = "gb-off", txt = "Greenbone nicht verfügbar";
      if (st.available) {
        cls = st.can_scan ? "gb-ok" : "gb-warn";
        txt = "Greenbone erreichbar" + (st.version ? " · GMP " + st.version : "")
            + (st.can_scan ? "" : " · nur Import");
      }
      badge.className = "gb-badge " + cls;
      badge.textContent = txt;
      let m = st.message || st.error || "";
      if (st.available && st.feed_note) m += " Feed: " + st.feed_note + ".";
      if (st.drop_files && st.drop_files.length)
        m += " Drop (" + st.drop_dir + "): " + st.drop_files.slice(-3).join(", ") + ".";
      msg.textContent = m;
      if (scanGo) scanGo.title = st.can_scan ? "" : "Greenbone/Zugangsdaten fehlen – Start wird ehrlich abgelehnt";
    }).catch(() => {
      badge.className = "gb-badge gb-off";
      badge.textContent = "Status nicht abrufbar";
    });
  }

  function renderImport(d) {
    if (!d.ok) { show('<p class="gb-err">⛔ ' + esc(d.error || "Import fehlgeschlagen") + "</p>"); return; }
    const s = d.summary || {}, sev = s.severity || {};
    let h = "<p><strong>" + esc(d.report_file) + "</strong> · " + esc(s.format) + " · "
      + esc(s.result_count) + " Ergebnis(se) auf " + esc(s.hosts) + " Host(s) — "
      + ["critical", "high", "medium", "low"].map(k =>
          '<span class="gb-sev gb-sev-' + k + '">' + k + " " + (sev[k] || 0) + "</span>").join(" ")
      + "</p>";
    if (d.out_of_scope_skipped) h += "<p class='hint'>" + esc(d.out_of_scope_skipped)
      + " Ergebnis(se) außerhalb des Scopes verworfen (default-deny).</p>";
    if (d.persisted) h += "<p class='hint'>" + esc(d.persisted) + " Finding(s) beim Ziel gespeichert.</p>";
    const hints = d.hints || [];
    h += "<h5>🎫 Härtungs-/Ticket-Hinweise (High/Critical)</h5>";
    if (!hints.length) h += "<p class='hint'>Keine High/Critical-Funde – nichts zu härten.</p>";
    else h += "<ul>" + hints.slice(0, 25).map(x =>
      '<li><span class="gb-sev gb-sev-' + esc(x.severity) + '">' + esc(x.severity) + "</span> <code>"
      + esc(x.ticket_id) + "</code> " + esc(x.title) + " → <strong>" + esc(x.route_to) + "</strong> ("
      + esc(x.host_count) + " Host(s)" + (x.cves && x.cves.length ? ", " + esc(x.cves.slice(0, 3).join(", ")) : "")
      + ")<br><span class='hint'>Lösung laut Greenbone (" + esc(x.solution_type || "k. A.") + "): "
      + esc(x.solution) + "</span></li>").join("") + "</ul>";
    const f = d.findings || [];
    if (f.length) h += "<details><summary>" + f.length + " Finding(s)</summary><ul>" + f.slice(0, 100).map(x =>
      '<li><span class="gb-sev gb-sev-' + esc(x.severity) + '">' + esc(x.severity) + "</span> " + esc(x.title)
      + " <span class='hint'>[" + esc(x.status) + (x.qod != null ? ", QoD " + esc(x.qod) : "") + "]</span></li>"
    ).join("") + "</ul></details>";
    show(h);
  }

  if (impForm) impForm.addEventListener("submit", ev => {
    ev.preventDefault();
    const go = document.getElementById("gb-import-go");
    go.disabled = true; go.textContent = "importiere…";
    fetch("/api/blue/greenbone/import", {method: "POST", body: new FormData(impForm)})
      .then(r => r.json()).then(renderImport)
      .catch(e => show('<p class="gb-err">⛔ ' + esc(e) + "</p>"))
      .finally(() => { go.disabled = false; go.textContent = "Importieren"; refreshStatus(); });
  });

  if (ack && scanGo) ack.addEventListener("change", () => { scanGo.disabled = !ack.checked; });

  if (scanForm) scanForm.addEventListener("submit", ev => {
    ev.preventDefault();
    const fd = new FormData(scanForm);
    scanGo.disabled = true; scanGo.textContent = "starte…";
    fetch("/api/blue/greenbone/scan", {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({target_id: parseInt(fd.get("target_id"), 10), host: fd.get("host"),
                            oversight_ack: !!fd.get("oversight_ack")})
    }).then(r => r.json().then(d => ({status: r.status, d}))).then(({status, d}) => {
      if (d.ok) show("<p>✅ Scan gestartet · Task <code>" + esc(d.task_id) + "</code> · Config "
        + esc(d.scan_config) + ". Nach Abschluss Report in Greenbone exportieren und oben importieren, oder "
        + "<code>GET /api/blue/greenbone/scan/" + esc(d.task_id) + "?fetch=1</code>.</p>");
      else show('<p class="gb-err">⛔ ' + esc(d.error || d.detail || ("HTTP " + status)) + "</p>");
    }).catch(e => show('<p class="gb-err">⛔ ' + esc(e) + "</p>"))
      .finally(() => { scanGo.textContent = "Scan starten"; scanGo.disabled = !ack.checked; });
  });

  refreshStatus();
})();
