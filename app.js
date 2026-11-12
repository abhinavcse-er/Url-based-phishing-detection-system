(() => {
  "use strict";
  const form = document.getElementById("scanForm");
  const input = document.getElementById("urlInput");
  const button = document.getElementById("scanBtn");
  const result = document.getElementById("result");
  const hint = document.getElementById("hint");
  const API_BASE = String(window.PHISHING_API_BASE || "").replace(/\/$/, "");
  document.getElementById("year").textContent = new Date().getFullYear();

  function escapeHTML(value) {
    return String(value ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
  }
  function showError(message) {
    result.className = "result error";
    result.innerHTML = '<div class="result-top"><h3>Could not complete scan</h3><span class="verdict">ERROR</span></div><p class="result-summary">' + escapeHTML(message) + '</p>';
  }
  function normalizeVerdict(label) {
    const value = String(label || "").toLowerCase();
    if (value.includes("phish") || value === "malicious" || value === "high risk") return "phishing";
    if (value.includes("suspicious") || value.includes("medium")) return "suspicious";
    return "safe";
  }
  function renderResult(data) {
    const verdict = data && data.verdict ? data.verdict : {};
    const details = data && data.details ? data.details : {};
    const features = details.features || {};
    const score = Math.max(0, Math.min(100, Number(verdict.risk_score) || 0));
    const kind = normalizeVerdict(verdict.label);
    const labels = {safe:"LOW RISK SIGNALS", suspicious:"SUSPICIOUS", phishing:"HIGH RISK"};
    const summary = {safe:"No major warning signs were found by these checks. This does not guarantee the site is safe.",suspicious:"Some URL characteristics look unusual. Verify the domain independently before interacting.",phishing:"Several warning signs were detected. Avoid entering credentials or payment information."};
    const ml = data && data.ml_result ? data.ml_result : null;
    const mlHTML = data && data.ml_status === "used" && ml
      ? '<div class="ml-result"><strong>ML model assessment</strong><span>' + escapeHTML(ml.ml_label_text || "Unknown") + ' · Class ' + escapeHTML(ml.ml_label) + '</span>' +
        (ml.ml_phishing_probability !== null && ml.ml_phishing_probability !== undefined
          ? '<small>Estimated phishing probability: ' + Math.round(Number(ml.ml_phishing_probability) * 100) + '%</small>'
          : '<small>Probability estimate unavailable</small>') +
        '<small class="ml-note">Model estimate, not a guarantee of website safety.</small></div>'
      : '<div class="ml-result"><strong>ML model assessment</strong><small>Unavailable for this scan.</small></div>';
    const reasons = Array.isArray(verdict.reasons) ? verdict.reasons : [];
    const reasonHTML = reasons.length ? reasons.map(item => '<li>' + escapeHTML(item.reason || "Risk indicator") + ' (+' + escapeHTML(item.points ?? 0) + ')</li>').join("") : "<li>No configured warning indicators were triggered.</li>";
    result.className = "result " + kind;
    result.innerHTML = '<div class="result-top"><h3>Scan assessment</h3><span class="verdict">' + labels[kind] + '</span></div>' +
      '<div class="score-line"><span>Heuristic risk score</span><strong>' + score + '/100</strong></div><div class="meter"><span style="width:' + score + '%"></span></div>' +
      '<p class="result-summary">' + summary[kind] + '</p><h4>Signals found</h4><ul class="reason-list">' + reasonHTML + '</ul>' + mlHTML +
      '<p class="result-url">Analyzed: ' + escapeHTML(details.parsed_url || input.value.trim()) + (features.uses_https === false ? ' · HTTP (not HTTPS)' : '') + '</p>';
  }
  async function scan(event) {
    event.preventDefault();
    const url = input.value.trim();
    if (!url) { hint.textContent = "Please enter a URL to scan."; input.focus(); return; }
    if (url.length > 2048) { showError("The URL is too long. Please use a shorter URL."); return; }
    if (!API_BASE) { showError("The API endpoint has not been configured yet. Deploy the FastAPI backend and set PHISHING_API_BASE in api-config.js."); return; }
    button.disabled = true;
    button.querySelector("span").textContent = "Analyzing…";
    result.className = "result";
    result.innerHTML = '<p class="result-summary">Analyzing URL patterns. Please wait…</p>';
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 20000);
    try {
      const response = await fetch(API_BASE + "/api/scan", {
        method:"POST", headers:{"Content-Type":"application/json"},
        body:JSON.stringify({url}), signal:controller.signal
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.detail || "The API returned HTTP " + response.status + ".");
      if (!data.verdict || !data.details) throw new Error("Unexpected response from the scan API.");
      renderResult(data);
    } catch (error) {
      showError(error.name === "AbortError" ? "The server took too long to respond. It may be waking up; please try again." : (error.message || "Network error. Check the backend URL and CORS settings."));
    } finally {
      clearTimeout(timeout);
      button.disabled = false;
      button.querySelector("span").textContent = "Analyze URL";
    }
  }
  form.addEventListener("submit", scan);
  document.querySelectorAll("[data-example]").forEach(btn => btn.addEventListener("click", () => {
    input.value = btn.dataset.example;
    input.focus();
  }));
})();