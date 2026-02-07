// ✅ Change this to your backend FastAPI URL (can be local IP or deployed domain)
const API_BASE = "http://10.89.70.31:5500";


// DOM elements
const input = document.getElementById("urlInput");
const btn = document.getElementById("scanBtn");
const result = document.getElementById("result");

// Event listeners
btn.addEventListener("click", scan);
input.addEventListener("keypress", e => { if (e.key === "Enter") scan(); });

// ✅ Sanitize text before rendering to HTML
function sanitize(s) {
  return String(s).replace(/[<>&'"]/g, c => ({
    "<": "&lt;", ">": "&gt;", "&": "&amp;", "'": "&#39;", '"': "&quot;"
  }[c]));
}

// ✅ Add commas to large numbers
function formatNumber(n) {
  return n.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

// ✅ Query parameter inspection (basic ML-style feature extraction)
function renderQueryParamsInfo(details) {
  const urlObj = new URL(details.parsed_url);
  let params = Array.from(urlObj.searchParams.entries());
  const suspiciousWords = ["password", "login", "verify", "token", "session", "account"];
  const suspiciousParams = params.some(([key, value]) =>
    suspiciousWords.some(word =>
      key.toLowerCase().includes(word) || value.toLowerCase().includes(word)
    )
  );

  return `
    <div>Query Params</div><div>${params.length}</div>
    <div>Suspicious Params</div><div>${suspiciousParams ? "Yes" : "No"}</div>
  `;
}

// ✅ ML-inspired risk interpretation
function formatVerdict(score) {
  if (score === 0) {
    return {
      label: "Benign",
      explanation: `✅ Prediction: Benign — Model confidence: 100%. No malicious indicators detected.`
    };
  }
  if (score > 0 && score <= 25) {
    return {
      label: "Low Risk",
      explanation: `🟢 Prediction: Low Risk — Classified as likely safe with ${(100 - score).toFixed(1)}% confidence. Minor anomalies observed.`
    };
  }
  if (score > 25 && score <= 50) {
    return {
      label: "Suspicious",
      explanation: `🟡 Prediction: Suspicious — ${(100 - score).toFixed(1)}% confidence. Behavioral patterns partially match known malicious signatures. Further investigation recommended.`
    };
  }
  if (score > 50 && score <= 75) {
    return {
      label: "High Risk",
      explanation: `🟠 Prediction: High Risk — Strong correlation with phishing or malicious activity detected (${score}% risk). Proceed with caution.`
    };
  }
  return {
    label: "Malicious",
    explanation: `❌ Prediction: Malicious — Classified as a high-confidence threat (${score}% risk). Immediate blocking or avoidance strongly advised.`
  };
}

// ✅ Main scanning function
async function scan() {
  const url = input.value.trim();
  if (!url) return;

  btn.disabled = true;
  btn.textContent = "Scanning…";
  result.className = "result hidden"; // Reset classes
  result.innerHTML = `<p>Scanning <strong>${sanitize(url)}</strong>…</p>`;
  result.classList.remove("hidden");

  try {
    const res = await fetch(`${API_BASE}/api/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });

    if (!res.ok) throw new Error("Scan failed");
    const data = await res.json();

    const v = data.verdict;
    const f = data.details.features;
    const verdictText = formatVerdict(v.risk_score);

    // ✅ Add verdict class
    if (v.risk_score === 0 || v.risk_score <= 25) result.classList.add("safe");
    else if (v.risk_score <= 50) result.classList.add("warning");
    else if (v.risk_score <= 75) result.classList.add("danger");
    else result.classList.add("critical");

    // ✅ Final result UI
    result.innerHTML = `
      <div style="display:flex;justify-content:space-between;align-items:center;">
        <h3 style="margin:0;">Scan Result</h3>
        <span class="badge">${sanitize(verdictText.label)}</span>
      </div>
      <p class="explanation">${sanitize(verdictText.explanation)}</p>

      <div class="kv">
        <div>URL</div><div>${sanitize(data.details.parsed_url)}</div>
        <div>Domain</div><div>${sanitize(data.details.domain)}</div>
        <div>Subdomain</div><div>${sanitize(data.details.subdomain || "(none)")}</div>
        <div>Uses HTTPS</div><div>${f.uses_https ? "Yes" : "No"}</div>
        <div>Suspicious TLD</div><div>${f.suspicious_tld ? "Yes" : "No"}</div>
        <div>IP Host</div><div>${f.is_ip_host ? "Yes" : "No"}</div>
        <div>URL Shortener</div><div>${f.uses_shortener ? "Yes" : "No"}</div>
        <div>URL Length</div><div>${formatNumber(f.url_length)}</div>
        <div>Host Length</div><div>${formatNumber(f.host_length)}</div>
        <div>Dots in Host</div><div>${f.num_dots}</div>
        <div>Digits in Host</div><div>${f.num_digits_host}</div>
        ${renderQueryParamsInfo(data.details)}
      </div>

      <div class="reasons">
        <h4>Why this verdict:</h4>
        <ul>
          ${v.reasons.length 
            ? v.reasons.map(r => `<li>+${r.points} — ${sanitize(r.reason)}</li>`).join("")
            : "<li>No major risks detected.</li>"}
        </ul>
      </div>
    `;
  } catch (err) {
    result.classList.add("error");
    result.innerHTML = `<p>Error: ${sanitize(err.message)}</p>`;
  } finally {
    btn.disabled = false;
    btn.textContent = "Scan";
  }
}

// ✅ Example (for dev console testing)
// const test = formatVerdict(68);
// console.log(test.label);
// console.log(test.explanation);
