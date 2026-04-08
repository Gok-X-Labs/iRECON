/* =========================================================
   iRECON — Frontend Script v2.4
   Features:
     - Single IOC lookup
     - Bulk IOC analysis (multiple IOCs, sequential with progress)
     - External links on VT / AbuseIPDB / OTX cards
   Stateless. Nothing stored locally.
   ========================================================= */

"use strict";

let emailMode = false;
let currentResults = null;
let currentMode = "single";   // "single" | "bulk"
let bulkAborted  = false;

// ── External URL builders ──────────────────────────────────
// Given a query string and its detected type, return the correct
// search URL for each intelligence platform.
const EXTERNAL_URLS = {
  virustotal: (query, type) => {
    if (type === "ip")     return `https://www.virustotal.com/gui/ip-address/${encodeURIComponent(query)}`;
    if (type === "domain") return `https://www.virustotal.com/gui/domain/${encodeURIComponent(query)}`;
    if (type === "url")    return `https://www.virustotal.com/gui/url/${btoa(query).replace(/=/g,"")}`;
    if (type === "hash")   return `https://www.virustotal.com/gui/file/${encodeURIComponent(query)}`;
    return `https://www.virustotal.com/gui/search/${encodeURIComponent(query)}`;
  },
  abuseipdb: (query, type) => {
    if (type === "ip") return `https://www.abuseipdb.com/check/${encodeURIComponent(query)}`;
    return `https://www.abuseipdb.com/`;
  },
  otx: (query, type) => {
    if (type === "ip")     return `https://otx.alienvault.com/indicator/ip/${encodeURIComponent(query)}`;
    if (type === "domain") return `https://otx.alienvault.com/indicator/domain/${encodeURIComponent(query)}`;
    if (type === "url")    return `https://otx.alienvault.com/indicator/url/${encodeURIComponent(query)}`;
    if (type === "hash")   return `https://otx.alienvault.com/indicator/file/${encodeURIComponent(query)}`;
    return `https://otx.alienvault.com/`;
  },
};

// ── Input type detection ───────────────────────────────────
const TYPE_PATTERNS = {
  ip:     /^(\d{1,3}\.){3}\d{1,3}(\/\d+)?$|^[0-9a-fA-F:]+:[0-9a-fA-F:]*$/,
  url:    /^https?:\/\//i,
  hash32: /^[a-fA-F0-9]{32}$/,
  hash40: /^[a-fA-F0-9]{40}$/,
  hash64: /^[a-fA-F0-9]{64}$/,
  domain: /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/,
};
const TYPE_LABELS = {
  ip: "IP Address", url: "URL",
  hash32: "MD5 Hash", hash40: "SHA1 Hash", hash64: "SHA256 Hash",
  domain: "Domain",
};

function detectType(val) {
  const v = val.trim();
  for (const [type, rx] of Object.entries(TYPE_PATTERNS)) {
    if (rx.test(v)) return type;
  }
  return null;
}

// Normalise hash types to "hash" for URL building
function normaliseType(t) {
  if (!t) return "unknown";
  if (t.startsWith("hash")) return "hash";
  return t;
}

document.getElementById("queryInput").addEventListener("input", function () {
  const tag  = document.getElementById("inputTypeTag");
  const type = detectType(this.value.trim());
  if (type) { tag.textContent = TYPE_LABELS[type]; tag.classList.remove("hidden"); }
  else        tag.classList.add("hidden");
});
document.getElementById("queryInput").addEventListener("keydown", e => {
  if (e.key === "Enter") runLookup();
});

// Bulk textarea: live count
document.getElementById("bulkInput").addEventListener("input", updateBulkCount);

function updateBulkCount() {
  const lines = parseBulkInput();
  const el    = document.getElementById("bulkCount");
  el.textContent = lines.length > 0 ? `${lines.length} IOC${lines.length > 1 ? "s" : ""} detected` : "";
}

function parseBulkInput() {
  return document.getElementById("bulkInput").value
    .split("\n")
    .map(l => l.trim())
    .filter(l => l.length > 0 && detectType(l));
}

// ── Mode toggle ────────────────────────────────────────────
function setMode(mode) {
  currentMode = mode;
  document.getElementById("singleMode").classList.toggle("hidden", mode !== "single");
  document.getElementById("bulkMode").classList.toggle("hidden",   mode !== "bulk");
  document.getElementById("modeSingle").classList.toggle("active", mode === "single");
  document.getElementById("modeBulk").classList.toggle("active",   mode === "bulk");
  clearResults();
  document.getElementById("bulkResultsSection").classList.add("hidden");
  document.getElementById("bulkProgress").classList.add("hidden");
}

// ── Email mode toggle ──────────────────────────────────────
function toggleEmailMode() {
  emailMode = !emailMode;
  const panel = document.getElementById("emailPanel");
  const btn   = document.getElementById("emailToggleBtn");
  const single= document.getElementById("singleMode");
  const bulk  = document.getElementById("bulkMode");
  const hints = document.querySelector(".search-hints");
  const modeRow = document.querySelector(".mode-toggle-row");
  if (emailMode) {
    panel.classList.remove("hidden");
    single.classList.add("hidden"); bulk.classList.add("hidden");
    if (hints) hints.classList.add("hidden");
    if (modeRow) modeRow.classList.add("hidden");
    btn.textContent = "← Back to IOC lookup";
  } else {
    panel.classList.add("hidden");
    setMode(currentMode);
    if (hints) hints.classList.remove("hidden");
    if (modeRow) modeRow.classList.remove("hidden");
    btn.innerHTML = `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect width="20" height="16" x="2" y="4" rx="2"/><path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7"/></svg> Analyze Email Headers instead`;
  }
}

// ── Profile enforcement gate ─────────────────────────────────
/**
 * Call at the top of every analysis function.
 * Returns true if analysis may proceed, false if the analyst must
 * select a profile first (and opens the selector for them).
 */
function _requireProfile() {
  if (_activeProfileId) return true;
  // No profile — open selector instead of running analysis
  _setModalTitle("SELECT PROFILE — Required before analysis");
  _openProfileModal();
  _renderProfileList();
  return false;
}

// ── Single lookup ──────────────────────────────────────────
async function runLookup() {
  if (!_requireProfile()) return;
  const query = document.getElementById("queryInput").value.trim();
  if (!query) return;
  setLoading(true); clearResults();
  document.getElementById("bulkResultsSection").classList.add("hidden");
  _timerStart();

  const sid = _beginSession();

  // 35-second timeout — VT is capped at 12s, all others at 10s;
  // phase 2 (ASN + infra HTTP) runs concurrently but can add up to 8s.
  // 35s gives safe headroom without making analysts wait on genuine hangs.
  const controller = new AbortController();
  const timeoutId  = setTimeout(() => controller.abort(), 35000);

  try {
    const res  = await fetch("/api/lookup", {
      method: "POST",
      headers: {"Content-Type": "application/json", "X-Session-ID": sid, "X-Profile-ID": _activeProfileId || ""},
      body: JSON.stringify({ query }),
      signal: controller.signal,
    });
    clearTimeout(timeoutId);
    const data = await res.json();
    if (res.status === 403 && (data.detail || "").startsWith("NO_PROFILE")) {
      _requireProfile(); return;
    }
    if (!res.ok) { showError("Lookup Failed", data.detail || "An error occurred"); return; }
    currentResults = data;
    renderResults(data);
  } catch (err) {
    clearTimeout(timeoutId);
    const msg = err.name === "AbortError"
      ? "Request timed out — VT analysis is taking longer than expected. Try again."
      : "Could not connect to local server: " + err.message;
    showError("Connection Error", msg);
  } finally {
    setLoading(false);
    _timerStop();
    await _endSession(sid);
  }
}

// ── Bulk lookup ────────────────────────────────────────────
async function runBulkLookup() {
  if (!_requireProfile()) return;
  const iocs = parseBulkInput();
  if (!iocs.length) return;

  bulkAborted = false;
  clearResults();
  document.getElementById("resultsSection").classList.add("hidden");
  document.getElementById("bulkResultsSection").classList.add("hidden");
  document.getElementById("bulkResultsList").innerHTML = "";
  _timerStart();

  // Show progress bar
  const prog     = document.getElementById("bulkProgress");
  const progBar  = document.getElementById("bulkProgressBar");
  const progLabel= document.getElementById("bulkProgressLabel");
  const progFrac = document.getElementById("bulkProgressFrac");
  prog.classList.remove("hidden");

  const results = [];
  let done = 0;

  const sid = _beginSession();

  for (const ioc of iocs) {
    if (bulkAborted) break;
    progLabel.textContent = `Analyzing: ${ioc}`;
    progFrac.textContent  = `${done}/${iocs.length}`;
    progBar.style.width   = `${Math.round((done / iocs.length) * 100)}%`;

    try {
      const res  = await fetch("/api/lookup", {
        method: "POST",
        headers: {"Content-Type": "application/json", "X-Session-ID": sid, "X-Profile-ID": _activeProfileId || ""},
        body: JSON.stringify({ query: ioc }),
      });
      const data = await res.json();
      results.push({ ioc, data: res.ok ? data : null, error: res.ok ? null : (data.detail || "Error") });
    } catch (err) {
      results.push({ ioc, data: null, error: err.message });
    }
    done++;
    progFrac.textContent = `${done}/${iocs.length}`;
    progBar.style.width  = `${Math.round((done / iocs.length) * 100)}%`;
    renderBulkResults(results, iocs.length);
  }

  progLabel.textContent = "Analysis complete";
  document.getElementById("bulkBtn").disabled = false;
  _timerStop();
  await _endSession(sid);
}

function renderBulkResults(results, total) {
  const section  = document.getElementById("bulkResultsSection");
  const list     = document.getElementById("bulkResultsList");
  const summary  = document.getElementById("bulkSummary");
  section.classList.remove("hidden");

  // Summary chips
  const counts = { HIGH: 0, MEDIUM: 0, LOW: 0, ERROR: 0 };
  results.forEach(r => {
    if (r.error) counts.ERROR++;
    else counts[(r.data?.risk?.severity || "LOW")]++;
  });
  summary.innerHTML = `
    ${counts.HIGH   ? `<span class="bulk-sev-chip high">${counts.HIGH} ${sevLabel("HIGH")}</span>` : ""}
    ${counts.MEDIUM ? `<span class="bulk-sev-chip medium">${counts.MEDIUM} ${sevLabel("MEDIUM")}</span>` : ""}
    ${counts.LOW    ? `<span class="bulk-sev-chip low">${counts.LOW} ${sevLabel("LOW")}</span>` : ""}
    ${counts.ERROR  ? `<span class="bulk-sev-chip error">${counts.ERROR} ERROR</span>` : ""}
    <span class="bulk-sev-chip neutral">${results.length}/${total} done</span>
  `;

  // Rows
  list.innerHTML = "";
  results.forEach((r, idx) => {
    const row = document.createElement("div");
    row.className = "bulk-row";
    const risk      = r.data?.risk || {};
    const severity  = (risk.severity || "LOW").toLowerCase();
    const score     = risk.total_score ?? risk.score ?? 0;
    const itype     = r.data?.input_type || "unknown";
    const itypeNorm = normaliseType(itype);
    const typeMap   = { ip: "IP", domain: "Domain", url: "URL", hash: "Hash" };
    const vtUrl     = EXTERNAL_URLS.virustotal(r.ioc, itypeNorm);
    const abUrl     = EXTERNAL_URLS.abuseipdb(r.ioc, itypeNorm);
    const otxUrl    = EXTERNAL_URLS.otx(r.ioc, itypeNorm);

    if (r.error) {
      row.innerHTML = `
        <div class="bulk-row-main">
          <span class="bulk-row-ioc">${escHtml(r.ioc)}</span>
          <span class="bulk-row-type">—</span>
          <span class="bulk-row-score">—</span>
          <span class="bulk-sev-chip error">Error</span>
          <div class="bulk-ext-links"></div>
          <button class="bulk-expand-btn" disabled>—</button>
        </div>
        <div class="bulk-row-error">${escHtml(r.error)}</div>`;
    } else {
      const vtDet    = r.data?.virustotal?.malicious ?? "—";
      const abConf   = r.data?.abuseipdb?.abuse_confidence_score ?? null;
      const otxData  = r.data?.otx || {};
      const otxNoKey = (otxData.error || "").toLowerCase().includes("key not configured") ||
                       (otxData.error || "").toLowerCase().includes("api key not");
      const pulses   = otxNoKey ? "No key" : (otxData.pulse_count ?? "—");

      row.innerHTML = `
        <div class="bulk-row-main">
          <span class="bulk-row-ioc" title="${escHtml(r.ioc)}">${escHtml(r.ioc)}</span>
          <span class="bulk-row-type">${escHtml(typeMap[itype] || itype)}</span>
          <span class="bulk-row-score ${severity} art-score-clickable" data-ioc="${escHtml(r.ioc)}" title="Investigate ${escHtml(r.ioc)} in new tab">${score}</span>
          <span class="bulk-sev-chip ${severity}">${verdictLabel(risk)}</span>
          <div class="bulk-ext-links">
            <a href="${vtUrl}"  target="_blank" rel="noopener" class="ext-link-btn vt-btn"  title="View on VirusTotal">VT</a>
            ${itypeNorm === "ip" ? `<a href="${abUrl}" target="_blank" rel="noopener" class="ext-link-btn ab-btn" title="View on AbuseIPDB">ABUSE</a>` : ""}
            <a href="${otxUrl}" target="_blank" rel="noopener" class="ext-link-btn otx-btn" title="View on OTX">OTX</a>
          </div>
          <button class="bulk-expand-btn" onclick="toggleBulkRow(${idx})">Details &#x25BE;</button>
        </div>
        ${bulkSignalChips(r.data)}
        <div class="bulk-row-detail hidden" id="bulk-detail-${idx}"></div>`;

      // Store data for expand
      row.dataset.idx = idx;
    }
    list.appendChild(row);
    if (r.data) window[`__bulkData_${idx}`] = r.data;
  });
}

function toggleBulkRow(idx) {
  const detail = document.getElementById(`bulk-detail-${idx}`);
  const btn    = detail.closest(".bulk-row").querySelector(".bulk-expand-btn");
  if (detail.classList.contains("hidden")) {
    detail.classList.remove("hidden");
    btn.innerHTML = "Details &#x25B4;";
    if (!detail.dataset.rendered) {
      detail.dataset.rendered = "1";
      const data = window[`__bulkData_${idx}`];
      if (data) {
        const grid = document.createElement("div");
        grid.className = "services-grid bulk-inline-grid";
        if (data.virustotal) grid.appendChild(buildVTCard(data.virustotal,  data.query, normaliseType(data.input_type)));
        if (data.abuseipdb)  grid.appendChild(buildAbuseCard(data.abuseipdb, data.query, normaliseType(data.input_type)));
        if (data.otx)        grid.appendChild(buildOTXCard(data.otx,         data.query, normaliseType(data.input_type)));
        detail.appendChild(grid);
      }
    }
  } else {
    detail.classList.add("hidden");
    btn.innerHTML = "Details &#x25BE;";
  }
}

// ── Bulk signal chips (entropy / homoglyph / rapid-deploy / URL heuristics) ───
// Shown on domain and URL rows.  Returns an HTML string of chips.
function bulkSignalChips(data) {
  if (!data) return "";
  const itype = data.input_type || "";
  if (itype !== "domain" && itype !== "url" && itype !== "ip") return "";

  const chips = [];

  // Domain Entropy
  const entropy = data.entropy || {};
  if (entropy.entropy_level && entropy.entropy_level !== "Low") {
    const cls = entropy.entropy_level === "High" ? "bsc-high" : "bsc-med";
    chips.push(`<span class="bulk-signal-chip ${cls}" title="${escHtml(entropy.comment || '')}">` +
               `&#x1D4D; ${escHtml(entropy.entropy_level)} Entropy</span>`);
  }

  // Homoglyph / Brand Impersonation
  const brand = data.brand_similarity || {};
  if (brand.brand_impersonation_flag) {
    const cls = brand.confidence === "High" ? "bsc-danger" : "bsc-warn";
    chips.push(`<span class="bulk-signal-chip ${cls}" title="${escHtml(brand.comment || '')}">` +
               `&#x26A0; Resembles ${escHtml(brand.matched_brand || "brand")}</span>`);
  }

  // Rapid Deployment Infrastructure
  const infra = data.infrastructure || {};
  if (infra.rapid_deploy_flag || infra.is_rapid_deployment) {
    chips.push(`<span class="bulk-signal-chip bsc-infra" title="${escHtml(infra.label || '')}">` +
               `&#x1F3D7; ${escHtml(infra.provider || "Rapid Deploy")}</span>`);
  }

  // URL heuristic signals
  const uh = data.url_heuristics || {};
  const uhSigs = uh.signals || [];

  if (uhSigs.includes("path_keywords_high") || uhSigs.includes("path_keywords_present")) {
    const kws = (uh.path_keywords || []).slice(0, 3).join(", ");
    const cls = uhSigs.includes("path_keywords_high") ? "bsc-danger" : "bsc-warn";
    chips.push(`<span class="bulk-signal-chip ${cls}" title="${escHtml(uh.comment || '')}">` +
               `&#x1F511; Path: ${escHtml(kws)}</span>`);
  }
  if (uhSigs.includes("open_redirect_param")) {
    chips.push(`<span class="bulk-signal-chip bsc-warn" title="${escHtml(uh.comment || '')}">` +
               `&#x21AA; Open Redirect</span>`);
  }
  if (uhSigs.includes("encoded_params") || uhSigs.includes("base64_in_query")) {
    chips.push(`<span class="bulk-signal-chip bsc-med" title="Encoded/obfuscated parameters detected">` +
               `&#x1F510; Encoded Params</span>`);
  }
  if (uhSigs.includes("double_slash_path") || uhSigs.includes("brand_in_path")) {
    chips.push(`<span class="bulk-signal-chip bsc-danger" title="${escHtml(uh.comment || '')}">` +
               `&#x26A0; Path Confusion</span>`);
  }
  if (uhSigs.includes("ip_host")) {
    chips.push(`<span class="bulk-signal-chip bsc-warn" title="IP address used as hostname">` +
               `&#x1F4CD; IP Host</span>`);
  }
  if (uhSigs.includes("very_long_path") || uhSigs.includes("long_path")) {
    chips.push(`<span class="bulk-signal-chip bsc-med" title="Long URL path">` +
               `&#x21C4; Long Path (${uh.path_length || "?"})</span>`);
  }

  // Checks executed bar — green = passed, yellow = failed/incomplete, grey = N/A
  const checksStatus = (data.risk && data.risk.checks_status) || data.checks_status || {};
  const checksPassed  = checksStatus.passed  || [];
  const checksFailed  = checksStatus.failed  || [];
  const checksSkipped = checksStatus.skipped || [];
  // Backward-compat: if no checks_status, fall back to old flat list (all green)
  const checksLegacy = (checksPassed.length === 0 && checksFailed.length === 0 && checksSkipped.length === 0)
    ? ((data.risk && data.risk.checks_executed) || data.checks_executed || [])
    : [];
  const checksHtml = (checksPassed.length || checksFailed.length || checksSkipped.length || checksLegacy.length)
    ? `<div class="bulk-checks-bar"><span class="bulk-checks-label">CHECKS:</span>${
        checksPassed.map(c  => `<span class="bulk-check-pill bulk-check-pill--ok"   title="${escHtml(c)}: completed">${escHtml(c)}</span>`).join("")
      }${checksFailed.map(c  => `<span class="bulk-check-pill bulk-check-pill--warn" title="${escHtml(c)}: failed or incomplete">${escHtml(c)}</span>`).join("")
      }${checksSkipped.map(c => `<span class="bulk-check-pill bulk-check-pill--skip" title="${escHtml(c)}: N/A for this IOC type">${escHtml(c)}</span>`).join("")
      }${checksLegacy.map(c  => `<span class="bulk-check-pill bulk-check-pill--ok"   title="${escHtml(c)}: completed">${escHtml(c)}</span>`).join("")
      }</div>`
    : "";

  const chipsHtml = chips.length
    ? `<div class="bulk-signal-chips">${chips.join("")}</div>`
    : "";

  return chipsHtml + checksHtml;
}

// ── EML file helpers ───────────────────────────────────────
let _emlFile = null;

function onEmlFileSelected(e) {
  const f = e.target.files[0];
  if (!f) return;
  if (!f.name.toLowerCase().endsWith(".eml")) {
    showError("Invalid File", "Only .eml files are accepted.");
    e.target.value = ""; return;
  }
  if (f.size > 5 * 1024 * 1024) {
    showError("File Too Large", "Maximum file size is 5 MB.");
    e.target.value = ""; return;
  }
  _emlFile = f;
  document.getElementById("emlFileName").textContent = f.name;
  document.getElementById("emlClearBtn").classList.remove("hidden");
  // Clear the textarea to signal EML takes priority
  document.getElementById("emailInput").placeholder = "EML file selected — textarea will be ignored";
}

function clearEmlFile() {
  _emlFile = null;
  document.getElementById("emlFileInput").value = "";
  document.getElementById("emlFileName").textContent = "";
  document.getElementById("emlClearBtn").classList.add("hidden");
  document.getElementById("emailInput").placeholder = "Paste raw email headers here...";
}

// ── File Analysis ────────────────────────────────────────────
let _analysisFile = null;
let _fileMode = false;

function toggleFileMode() {
  _fileMode = !_fileMode;
  const filePanel  = document.getElementById("filePanel");
  const emailPanel = document.getElementById("emailPanel");
  const fileBtn    = document.getElementById("fileToggleBtn");
  const emailBtn   = document.getElementById("emailToggleBtn");
  const single     = document.getElementById("singleMode");
  const bulk       = document.getElementById("bulkMode");
  const hints      = document.querySelector(".search-hints");
  const modeRow    = document.querySelector(".mode-toggle-row");

  if (_fileMode) {
    filePanel.classList.remove("hidden");
    emailPanel.classList.add("hidden");
    single.classList.add("hidden");
    bulk.classList.add("hidden");
    if (hints)   hints.classList.add("hidden");
    if (modeRow) modeRow.classList.add("hidden");
    fileBtn.innerHTML = `← Back to IOC lookup`;
    // Also reset email mode if it was active
    emailMode = false;
    emailBtn.innerHTML = `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect width="20" height="16" x="2" y="4" rx="2"/><path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7"/></svg> Analyze Email Headers instead`;
  } else {
    filePanel.classList.add("hidden");
    setMode(currentMode);
    if (hints)   hints.classList.remove("hidden");
    if (modeRow) modeRow.classList.remove("hidden");
    fileBtn.innerHTML = `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg> Analyze File instead`;
  }
}

function onFileSelected(e) {
  const f = e.target.files[0];
  if (!f) return;
  if (f.size > 10 * 1024 * 1024) {
    showError("File Too Large", "Maximum file size is 10 MB.");
    e.target.value = "";
    return;
  }
  _analysisFile = f;
  const sizeKb = (f.size / 1024).toFixed(0);
  document.getElementById("fileSelectedName").textContent = f.name;
  document.getElementById("fileSelectedSize").textContent = `${sizeKb} KB`;
  document.getElementById("fileSelectedRow").classList.remove("hidden");
  document.getElementById("fileDropZone").classList.add("has-file");
  document.getElementById("fileAnalyzeBtn").disabled = false;
}

function clearFileSelection() {
  _analysisFile = null;
  document.getElementById("fileInput").value = "";
  document.getElementById("fileSelectedRow").classList.add("hidden");
  document.getElementById("fileDropZone").classList.remove("has-file");
  document.getElementById("fileAnalyzeBtn").disabled = true;
}

async function runFileAnalysis() {
  if (!_requireProfile()) return;
  if (!_analysisFile) {
    showError("No File", "Select a file to analyze.");
    return;
  }

  setLoading(true); clearResults();
  _timerStart();
  const sid = _beginSession();

  try {
    const form = new FormData();
    form.append("file", _analysisFile);

    const res = await fetch("/api/file/analyze", {
      method: "POST",
      body: form,
      headers: {
        "X-Session-ID":  sid,
        "X-Profile-ID":  _activeProfileId || "",
      },
    });
    const data = await res.json();
    if (!res.ok) {
      showError("Analysis Failed", data.detail || "Could not analyze file");
      return;
    }
    renderFileResults(data);
  } catch (err) {
    showError("Connection Error", "Could not connect to local server: " + err.message);
  } finally {
    setLoading(false);
    _timerStop();
    await _endSession(sid);
  }
}

function renderFileResults(data) {
  // Show results section, reveal file tab, switch to it
  document.getElementById("resultsSection").classList.remove("hidden");
  document.getElementById("fileTab").style.display = "";
  switchTab("file", document.getElementById("fileTab"));

  // Reset the IOC-analysis tabs (they're irrelevant for file analysis)
  document.getElementById("riskBanner").style.display    = "none";
  document.getElementById("riskFactors").style.display   = "none";
  document.getElementById("singleChecksBar").style.display = "none";

  const container = document.getElementById("fileContent");
  const filename    = data.filename    || "Unknown file";
  const urlCount    = (data.url_results || []).length;
  const qrCount     = (data.qr_results  || []).length;
  const attUrlCount = (data.attachment_url_results || []).length;
  const totalHigh   = data.total_high   || 0;
  const totalMed    = data.total_medium || 0;

  const severityBadge = totalHigh > 0
    ? `<span class="email-art-badge high">${totalHigh} HIGH</span>`
    : totalMed > 0
    ? `<span class="email-art-badge medium">${totalMed} MEDIUM</span>`
    : `<span class="email-art-badge low">All Clean</span>`;

  const statParts = [];
  if (urlCount)    statParts.push(`${urlCount} URL${urlCount!==1?"s":""}`);
  if (qrCount)     statParts.push(`${qrCount} QR code${qrCount!==1?"s":""}`);
  if (attUrlCount) statParts.push(`${attUrlCount} embedded link${attUrlCount!==1?"s":""}`);

  let html = `
  <div class="infra-detail-card file-intel-header" style="margin-bottom:10px;">
    <div class="file-intel-title">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
      File Artifact Intelligence
    </div>
    <div class="file-intel-meta">
      <span class="file-intel-name">${escHtml(filename)}</span>
      ${data.content_type ? `<span class="file-intel-ct">${escHtml(data.content_type)}</span>` : ""}
    </div>
    <div class="file-intel-summary">
      <span class="file-intel-counts">${statParts.length ? statParts.join(" · ") : "No artifacts"}</span>
      ${severityBadge}
    </div>
    <div class="email-safe-mode-banner">
      🔒 Safe Processing Mode — No DNS resolution · No HTTP requests to artifacts · TI API lookups only
    </div>
  </div>`;

  // No artifacts at all
  const totalResults = urlCount + qrCount + attUrlCount
    + (data.domain_results||[]).length + (data.ip_results||[]).length
    + (data.attachment_results||[]).length;

  if (totalResults === 0) {
    html += `<div class="infra-detail-card email-art-section" style="color:var(--text-3);font-size:12px;text-align:center;padding:24px;">
      No URLs or QR codes detected in <strong>${escHtml(filename)}</strong>
    </div>`;
    container.innerHTML = html;
    return;
  }

  // Redirect chain summary
  const rs = data.redirect_summary;
  if (rs) {
    const rSusp   = rs.suspicious_chains || 0;
    const rAnal   = rs.analysed || 0;
    const rStatus = rSusp > 0 ? "danger" : rAnal > 0 ? "clean" : "neutral";
    html += `<div class="email-redir-summary email-redir-summary--${rStatus}">
      <span class="email-redir-summary__icon">${rSusp > 0 ? "⚠" : rAnal > 0 ? "✓" : "—"}</span>
      <span class="email-redir-summary__title">Redirect Analysis</span>
      <span class="email-redir-summary__detail">
        ${rAnal > 0 ? `<span class="email-redir-summary__pill analysed">Analysed ${rAnal} suspicious URL${rAnal!==1?"s":""}</span>` : ""}
        ${rSusp > 0 ? `<span class="email-redir-summary__pill suspicious">${rSusp} suspicious chain${rSusp!==1?"s":""}</span>`
                    : rAnal > 0 ? `<span class="email-redir-summary__pill clean">No suspicious chains</span>` : ""}
      </span>
    </div>`;
  }

  // URLs
  if (data.url_results?.length) {
    html += `<div class="infra-detail-card email-art-section" style="margin-bottom:10px;">
      <div class="infra-detail-title">URLs</div>
      ${data.url_results.map(_artifactRow).join("")}
    </div>`;
  }

  // QR codes
  if (data.qr_results?.length) {
    html += `<div class="infra-detail-card email-art-section" style="margin-bottom:10px;">
      <div class="infra-detail-title">QR Codes</div>
      ${data.qr_results.map(_artifactRow).join("")}
    </div>`;
  }

  // Attachment hash
  if (data.attachment_results?.length) {
    html += `<div class="infra-detail-card email-art-section" style="margin-bottom:10px;">
      <div class="infra-detail-title">File Hash Reputation</div>
      ${data.attachment_results.map(r => {
        const meta = `<div class="email-art-attach-meta">${escHtml(r.filename||filename)} · ${r.size ? Math.round(r.size/1024)+"KB" : ""}</div>`;
        return `<div>${meta}${_artifactRow(r)}</div>`;
      }).join("")}
    </div>`;
  }

  container.innerHTML = html;

  // Wire Analyze IOC click-through (same event delegation as email tab)
  container.querySelectorAll(".email-art-action-btn.analyze").forEach(btn => {
    btn.addEventListener("click", () => {
      const ioc = btn.dataset.ioc;
      if (ioc) window.open(`/?ioc=${encodeURIComponent(ioc)}`, "_blank");
    });
  });
}

// ── Email analysis ─────────────────────────────────────────
async function runEmailAnalysis() {
  if (!_requireProfile()) return;
  const raw = document.getElementById("emailInput").value.trim();

  // Validate: need either EML file or pasted headers
  if (!_emlFile && !raw) {
    showError("No Input", "Paste email headers or upload an .eml file.");
    return;
  }

  setLoading(true); clearResults();
  _timerStart();
  const sid = _beginSession();
  try {
    let data;

    if (_emlFile) {
      // EML file path: multipart/form-data to /api/email/upload
      const form = new FormData();
      form.append("file", _emlFile);
      const res = await fetch("/api/email/upload", {
        method: "POST", body: form,
        headers: {"X-Session-ID": sid, "X-Profile-ID": _activeProfileId || ""},
      });
      data = await res.json();
      if (!res.ok) { showError("Parse Failed", data.detail || "Could not parse EML file"); return; }
    } else {
      // Plain header text path: JSON to /api/email
      const res = await fetch("/api/email", {
        method: "POST",
        headers: {"Content-Type": "application/json", "X-Session-ID": sid, "X-Profile-ID": _activeProfileId || ""},
        body: JSON.stringify({ raw_headers: raw, gateways: [] }),
      });
      data = await res.json();
      if (!res.ok) { showError("Parse Failed", data.detail || "Could not parse email headers"); return; }
    }

    renderEmailResults(data);
  } catch (err) {
    showError("Connection Error", "Could not connect to local server: " + err.message);
  } finally {
    setLoading(false);
    _timerStop();
    await _endSession(sid);
  }
}
// ── UI state helpers ───────────────────────────────────────
function setLoading(on) {
  document.getElementById("loadingState").classList.toggle("hidden", !on);
  document.getElementById("lookupBtn").disabled = on;
  // Speed up the logo spin while analysis is running, snap back when done
  document.querySelector(".logo-icon")?.classList.toggle("logo-icon--analyzing", on);
}
function clearResults() {
  document.getElementById("resultsSection").classList.add("hidden");
  document.getElementById("errorState").classList.add("hidden");
}
function showError(title, msg) {
  document.getElementById("errorTitle").textContent  = title;
  document.getElementById("errorMessage").textContent = msg;
  document.getElementById("errorState").classList.remove("hidden");
}
function switchTab(name, btn) {
  document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
  document.querySelectorAll(".tab-panel").forEach(p => p.classList.remove("active"));
  btn.classList.add("active");
  document.getElementById(`tab-${name}`).classList.add("active");
}

// ── Single result renderer ─────────────────────────────────
function renderResults(data) {
  const section = document.getElementById("resultsSection");
  section.classList.remove("hidden"); section.classList.add("fade-in");

  const risk     = data.risk || {};
  const score    = risk.score ?? 0;
  const severity = (risk.severity || "LOW").toLowerCase();

  document.getElementById("riskQuery").textContent = data.query || "";
  const scoreEl = document.getElementById("riskScore");
  scoreEl.textContent = score;
  scoreEl.className = `risk-score-value ${severity}`;
  const badge = document.getElementById("riskBadge");
  badge.textContent = verdictLabel(risk);
  badge.className   = `risk-badge ${severity}`;


  const typeMap = { ip: "IP Address", domain: "Domain", url: "URL", hash: "File Hash" };
  document.getElementById("inputTypeChip").textContent = typeMap[data.input_type] || data.input_type;

  // Chips
  const infra = data.infrastructure || {};
  const infraChip = document.getElementById("infraChip");
  infra.provider && infra.provider !== "Unknown" && infra.provider !== "Unresolved"
    ? (infraChip.textContent = infra.provider, infraChip.classList.remove("hidden"))
    : infraChip.classList.add("hidden");

  const entropy = data.entropy || {};
  const entropyChip = document.getElementById("entropyChip");
  entropy.entropy_level && entropy.entropy_level !== "Low"
    ? (entropyChip.textContent = `Entropy: ${entropy.entropy_level}`, entropyChip.classList.remove("hidden"))
    : entropyChip.classList.add("hidden");

  const tldRisk = data.tld_risk || {};
  const tldChip = document.getElementById("tldChip");
  const _tldLevel = tldRisk.risk_level || "";
  if (_tldLevel === "High" || _tldLevel === "Moderate") {
    tldChip.className = "tld-chip" + (_tldLevel === "High" ? " tld-high" : "");
    tldChip.textContent = _tldLevel === "High"
      ? `High-risk TLD ${tldRisk.tld || ""}`
      : `Elevated TLD ${tldRisk.tld || ""}`;
  } else {
    tldChip.className = "tld-chip hidden";
  }

  const brand = data.brand_similarity || {};
  const brandChip = document.getElementById("brandChip");
  brand.brand_impersonation_flag
    ? (brandChip.textContent = `⚠ Resembles ${brand.matched_brand}`, brandChip.classList.remove("hidden"))
    : brandChip.classList.add("hidden");

  renderRiskPills(risk.factors || [], severity);

  // ── Checks executed bar — inject below risk factor pills ─────────────────
  // Shows green/yellow chips for every check that ran (VT, OTX, Age, TLD, etc.)
  // Same _checksBar() used by Bulk and Email artifact rows; wire it to the
  // dedicated #singleChecksBar container so Single IOC matches the other views.
  const singleChecksBar = document.getElementById("singleChecksBar");
  if (singleChecksBar) {
    const checksHtml = _checksBar(risk);
    singleChecksBar.innerHTML = checksHtml;
    singleChecksBar.classList.toggle("hidden", !checksHtml);
  }

  const infraAlert = document.getElementById("infraAlert");
  infra.is_rapid_deployment && infra.label
    ? (document.getElementById("infraAlertText").textContent = `${infra.provider}: ${infra.label}`, infraAlert.classList.remove("hidden"))
    : infraAlert.classList.add("hidden");

  const brandAlert = document.getElementById("brandAlert");
  brand.brand_impersonation_flag
    ? (document.getElementById("brandAlertText").textContent = `${brand.comment} (${brand.method}, ${brand.confidence} confidence)`, brandAlert.classList.remove("hidden"))
    : brandAlert.classList.add("hidden");

  const q    = data.query || "";
  const itype = normaliseType(data.input_type);
  renderReputationTab(data, q, itype);
  renderDnsTab(data);
  renderInfraTab(data);
  renderBreakdownTab(data);
  switchTab("reputation", document.querySelector("[data-tab='reputation']"));
  document.getElementById("emailTab").style.display = "none";

  // ── Async redirect chain — fetched separately so it never blocks the main response ──
  // URLScan live scans take 10–45 seconds; we fire-and-forget after the UI is rendered.
  if (data.input_type === "url" && data.query) {
    _fetchRedirectChainAsync(data.query);
  }
}

// ── Risk factor pills ──────────────────────────────────────
function renderRiskPills(factors, severity) {
  const row = document.getElementById("riskFactors");
  if (!factors.length) { row.classList.add("hidden"); return; }
  row.classList.remove("hidden");
  row.innerHTML = "";
  factors.forEach(f => {
    const pill = document.createElement("div");
    pill.className = `risk-factor-pill ${severity}`;
    pill.innerHTML = `<span style="opacity:.7">+${f.points}</span><span>${escHtml(f.reason)}</span>`;
    row.appendChild(pill);
  });
}

// ── Severity display labels ───────────────────────────────
// Maps backend severity key → fallback display text (used when verdict unavailable).
// Underlying risk.severity values (LOW/MEDIUM/HIGH) and CSS classes unchanged.
const _SEV_LABEL = {
  LOW:    "Low Threat",
  MEDIUM: "Needs Review",
  HIGH:   "Likely Malicious",
};
function sevLabel(s) { return _SEV_LABEL[(s || "").toUpperCase()] || s || "Low Threat"; }
// Prefer backend verdict over static map — verdict distinguishes HIGHLY vs LIKELY MALICIOUS.
function verdictLabel(risk) {
  if (risk?.verdict) return _fmtVerdict(risk.verdict);
  return sevLabel(risk?.severity);
}
function _fmtVerdict(v) {
  const map = {
    "LOW THREAT":      "Low Threat",
    "NEEDS REVIEW":    "Needs Review",
    "LIKELY MALICIOUS":  "Likely Malicious",
    "HIGHLY MALICIOUS":  "Highly Malicious",
  };
  return map[v] || v;
}


function renderReputationTab(data, query, itype) {
  const grid = document.getElementById("reputationGrid");
  grid.innerHTML = "";
  if (data.virustotal) grid.appendChild(buildVTCard(data.virustotal,   query, itype));
  if (data.abuseipdb)  grid.appendChild(buildAbuseCard(data.abuseipdb,  query, itype));
  if (data.otx)        grid.appendChild(buildOTXCard(data.otx,          query, itype));
  if (data.whois && (data.whois.age_days !== null || data.whois.creation_date))
                       grid.appendChild(buildWhoisCard(data.whois));
  if (data.entropy)    grid.appendChild(buildEntropyCard(data.entropy));
  if (data.tld_risk)   grid.appendChild(buildTldCard(data.tld_risk, data.brand_similarity));

  // Inline banner when OTX key is not configured — surfaces the config issue
  // clearly so analysts don't mistake missing data for a clean result.
  const otxErr = (data.otx?.error || "").toLowerCase();
  if (otxErr.includes("key not configured") || otxErr.includes("api key not")) {
    const banner = document.createElement("div");
    banner.className = "otx-key-missing-banner";
    banner.innerHTML = `⚠ <strong>AlienVault OTX key not configured.</strong>
      OTX intelligence is unavailable — pulse counts will show 0.
      <span style="opacity:.75">Add your OTX API key in the Analyst Profile to enable full enrichment.</span>`;
    grid.after(banner);
  }
}

// ── Card builders ──────────────────────────────────────────

// Helper: build the external-link row for a card header
function extLinkRow(service, query, itype) {
  if (!query || !itype || itype === "unknown") return "";
  const urlFn = EXTERNAL_URLS[service];
  if (!urlFn) return "";
  const url = urlFn(query, itype);
  const labels = { virustotal: "Open in VirusTotal ↗", abuseipdb: "Open in AbuseIPDB ↗", otx: "Open in OTX ↗" };
  return `<a href="${url}" target="_blank" rel="noopener" class="card-ext-link">${labels[service]}</a>`;
}

function buildVTCard(vt, query, itype) {
  const card = createCard("VirusTotal", extLinkRow("virustotal", query, itype));
  if (vt.error) { setCardStatus(card, "error"); card.appendChild(p("error-note", vt.error)); return card; }

  // Hash not in VT database — informational, not an error
  if (vt.not_found) {
    setCardStatus(card, "ok", "Not in database");
    card.innerHTML += `<div class="error-note" style="color:var(--text-3);font-style:italic;font-size:11px;margin-top:6px;">${escHtml(vt.note || "Hash not found in VirusTotal database.")}</div>`;
    return card;
  }

  const m = vt.malicious || 0;
  setCardStatus(card, m > 2 ? "bad" : m > 0 ? "warn" : "ok", m > 0 ? `${m} detections` : "Clean");
  card.innerHTML += `
    ${statRow("Malicious",  `<span class="stat-val malicious">${m}</span>`)}
    ${statRow("Suspicious", `<span class="stat-val suspicious">${vt.suspicious||0}</span>`)}
    ${statRow("Harmless",   `<span class="stat-val harmless">${vt.harmless||0}</span>`)}
    ${statRow("Undetected", `<span class="stat-val">${vt.undetected||0}</span>`)}
    ${vt.reputation != null ? statRow("Reputation", `<span class="stat-val">${vt.reputation}</span>`) : ""}
    ${vt.file_type ? statRow("File Type", `<span class="stat-val">${vt.file_type}</span>`) : ""}
    ${vt.file_size ? statRow("File Size", `<span class="stat-val">${formatBytes(vt.file_size)}</span>`) : ""}
    ${vt.last_seen ? statRow("Last Seen", `<span class="stat-val" style="font-size:10px">${formatDate(vt.last_seen)}</span>`) : ""}`;
  if (vt.tags?.length) {
    const w = document.createElement("div");
    w.style.cssText = "margin-top:10px;display:flex;flex-wrap:wrap;gap:4px;";
    vt.tags.slice(0,8).forEach(t => { const c = document.createElement("span"); c.className="record-chip"; c.style.fontSize="10px"; c.textContent=t; w.appendChild(c); });
    card.appendChild(w);
  }
  return card;
}

function buildAbuseCard(abuse, query, itype) {
  const card = createCard("AbuseIPDB", extLinkRow("abuseipdb", query, itype));
  if (abuse.error) { setCardStatus(card, "error"); card.appendChild(p("error-note", abuse.error)); return card; }
  const conf = abuse.abuse_confidence_score || 0;
  setCardStatus(card, conf > 75 ? "bad" : conf > 25 ? "warn" : "ok", `${conf}% confidence`);
  card.innerHTML += `
    ${statRow("Abuse Score",    `<span class="stat-val ${conf > 50 ? "malicious" : conf > 5 ? "suspicious" : ""}">${conf}%</span>`)}
    ${statRow("Total Reports",  `<span class="stat-val">${abuse.total_reports||0}</span>`)}
    ${statRow("Distinct Users", `<span class="stat-val">${abuse.num_distinct_users||0}</span>`)}
    ${abuse.country_code ? statRow("Country",    `<span class="stat-val">${abuse.country_code}</span>`) : ""}
    ${abuse.isp          ? statRow("ISP",         `<span class="stat-val" style="font-size:11px">${abuse.isp}</span>`) : ""}
    ${abuse.usage_type   ? statRow("Usage Type",  `<span class="stat-val" style="font-size:11px">${abuse.usage_type}</span>`) : ""}
    ${statRow("TOR Exit Node",  `<span class="stat-val ${abuse.is_tor?"malicious":""}">${abuse.is_tor?"YES":"No"}</span>`)}
    ${abuse.last_reported_at ? statRow("Last Report", `<span class="stat-val" style="font-size:10px">${formatDate(abuse.last_reported_at)}</span>`) : ""}`;
  return card;
}

function buildOTXCard(otx, query, itype) {
  // Determine card title — show fallback source when domain intelligence was used
  const intelSrc   = otx.intelligence_source || "";
  const isFallback = intelSrc.includes("Fallback");
  const cardTitle  = isFallback ? "AlienVault OTX" : "AlienVault OTX";

  // For URL lookups, always link to the domain page on OTX.
  // OTX's /indicator/url/ page expects a raw URL which breaks with
  // encodeURIComponent (produces "Invalid url" error on OTX site).
  // The fallback_domain is always set by lookup_url (even on no-data).
  let extQuery, extItype;
  if (itype === "url") {
    // Prefer the explicit fallback_domain; derive from query as last resort
    if (otx.fallback_domain) {
      extQuery = otx.fallback_domain;
    } else {
      try { extQuery = new URL(query).hostname; } catch(e) { extQuery = query; }
    }
    extItype = "domain";
  } else {
    extQuery = (isFallback && otx.fallback_domain) ? otx.fallback_domain : query;
    extItype = (isFallback && otx.fallback_domain) ? "domain" : itype;
  }
  const card = createCard(cardTitle, extLinkRow("otx", extQuery, extItype));
  if (otx.error) {
    // Distinguish "key not configured" from a real API error
    const isNoKey = otx.error.toLowerCase().includes("key not configured") ||
                    otx.error.toLowerCase().includes("api key not");
    if (isNoKey) {
      setCardStatus(card, "skip", "No Key");
      const msg = document.createElement("div");
      msg.className = "error-note";
      msg.style.cssText = "color:var(--text-3);font-style:italic;font-size:11px;margin-top:6px;";
      msg.textContent = "OTX API key not configured — add it in your Analyst Profile.";
      card.appendChild(msg);
    } else {
      setCardStatus(card, "error");
      card.appendChild(p("error-note", otx.error));
    }
    return card;
  }
  const pulses    = otx.pulse_count || 0;
  const fileScore = (otx.file_score != null) ? parseFloat(otx.file_score) : null;
  const families  = (otx.malware_families || []).map(f => typeof f === "string" ? f : (f.display_name||f.name||"")).filter(Boolean);

  // Card status: file_score >= 5 is a hard malicious signal; pulses are secondary
  const isBad  = pulses > 5 || (fileScore != null && fileScore >= 5);
  const isWarn = !isBad && (pulses > 0 || (fileScore != null && fileScore >= 1));
  const statusLabel = (fileScore != null && fileScore >= 1)
    ? `Score ${fileScore}${pulses > 0 ? ` · ${pulses} pulse(s)` : ""}`
    : pulses > 0 ? `${pulses} pulse(s)` : "No pulses";
  setCardStatus(card, isBad ? "bad" : isWarn ? "warn" : "ok", statusLabel);

  // Intelligence source label — shown for URL lookups that fell back to domain data
  if (intelSrc) {
    const srcDiv = document.createElement("div");
    srcDiv.style.cssText = "font-size:10px;margin-bottom:8px;padding:3px 8px;border-radius:4px;display:inline-block;";
    if (isFallback) {
      srcDiv.style.cssText += "background:rgba(250,204,21,0.08);color:var(--yellow);border:1px solid rgba(250,204,21,0.2);";
      const domLabel = otx.fallback_domain ? ` · ${otx.fallback_domain}` : "";
      srcDiv.textContent = intelSrc + domLabel;
    } else {
      srcDiv.style.cssText += "background:rgba(74,222,128,0.06);color:var(--text-3);border:1px solid rgba(74,222,128,0.15);";
      srcDiv.textContent = intelSrc;
    }
    card.appendChild(srcDiv);
  }

  const scoreClass   = fileScore == null ? "" : fileScore >= 10 ? "malicious" : fileScore >= 5 ? "suspicious" : "";
  const scoreDerived = otx.file_score_derived === true;
  const scoreLabel   = scoreDerived ? "VT-Derived Score" : "File Score";
  const scoreTitle   = scoreDerived
    ? "Score derived from VT detection ratio (OTX sandbox data unavailable)"
    : "OTX behavioral/sandbox score";
  const scoreRow     = fileScore != null
    ? statRow(scoreLabel, `<span class="stat-val ${scoreClass}" title="${scoreTitle}">${fileScore}${scoreDerived ? " ⓘ" : ""}</span>`)
    : "";

  card.innerHTML += `
    ${statRow("Pulse Count", `<span class="stat-val ${pulses>0?"suspicious":""}">${pulses}</span>`)}
    ${scoreRow}
    ${otx.country  ? statRow("Country",   `<span class="stat-val">${otx.country}</span>`) : ""}
    ${otx.asn      ? statRow("ASN",       `<span class="stat-val" style="font-size:11px">${otx.asn}</span>`) : ""}
    ${otx.city     ? statRow("City",      `<span class="stat-val">${otx.city}</span>`) : ""}
    ${otx.file_type? statRow("File Type", `<span class="stat-val">${otx.file_type}</span>`) : ""}`;
  const highRiskTags = (otx.high_risk_tags || []).filter(Boolean);
  if (highRiskTags.length) {
    const d = document.createElement("div"); d.style.marginTop = "10px";
    d.innerHTML = `<div style="font-size:10px;color:var(--text-3);text-transform:uppercase;letter-spacing:.1em;margin-bottom:5px;">Threat Tags</div>`;
    highRiskTags.forEach(t => { const c = document.createElement("span"); c.className="record-chip"; c.style.cssText="color:var(--red);border-color:rgba(248,113,113,0.2);background:var(--red-dim);font-size:10px;"; c.textContent=t; d.appendChild(c); });
    card.appendChild(d);
  }
  if (families.length) {
    const d = document.createElement("div"); d.style.marginTop = "10px";
    d.innerHTML = `<div style="font-size:10px;color:var(--text-3);text-transform:uppercase;letter-spacing:.1em;margin-bottom:5px;">Malware Families</div>`;
    families.forEach(f => { const c = document.createElement("span"); c.className="record-chip"; c.style.cssText="color:var(--red);border-color:rgba(248,113,113,0.2);background:var(--red-dim);font-size:10px;"; c.textContent=f; d.appendChild(c); });
    card.appendChild(d);
  }
  return card;
}


function buildWhoisCard(whois) {
  const card = createCard("WHOIS / Domain Age");
  const age = whois.age_days;
  setCardStatus(card, age !== null && age < 30 ? "warn" : "ok", age !== null ? `${age} days old` : "Age unknown");
  card.innerHTML += `
    ${age !== null ? statRow("Age (days)",  `<span class="stat-val ${age<30?"suspicious":age<90?"":"harmless"}">${age}</span>`) : ""}
    ${whois.creation_date   ? statRow("Created",  `<span class="stat-val" style="font-size:11px">${formatDate(whois.creation_date)}</span>`) : ""}
    ${whois.expiration_date ? statRow("Expires",  `<span class="stat-val" style="font-size:11px">${formatDate(whois.expiration_date)}</span>`) : ""}
    ${whois.registrar       ? statRow("Registrar",`<span class="stat-val" style="font-size:11px">${whois.registrar}</span>`) : ""}`;
  return card;
}

function buildEntropyCard(entropy) {
  const card = createCard("Domain Entropy");
  const lvl  = entropy.entropy_level || "Low";
  const lvlMap = { Low: "ok", Moderate: "warn", High: "bad" };
  setCardStatus(card, lvlMap[lvl] || "ok", `${lvl} (${entropy.entropy_score})`);
  const pct = Math.min(100, (entropy.entropy_score / 5) * 100);
  const colorClass = lvl === "High" ? "entropy-high" : lvl === "Moderate" ? "entropy-mod" : "entropy-low";
  card.innerHTML += `
    ${statRow("Score", `<span class="stat-val">${entropy.entropy_score}</span>`)}
    ${statRow("Level", `<span class="stat-val">${lvl}</span>`)}
    <div class="entropy-bar-wrap" style="margin-top:10px;">
      <div class="entropy-bar-track"><div class="entropy-bar-fill ${colorClass}" style="width:${pct}%"></div></div>
    </div>
    <div style="margin-top:8px;font-size:11px;color:var(--text-3);line-height:1.4;">${escHtml(entropy.comment||"")}</div>`;
  return card;
}

function buildTldCard(tldRisk, brandSim) {
  const card  = createCard("Domain Intelligence");
  const level = tldRisk?.risk_level || "Unknown";

  // Card status: "ok" (green) | "warn" (yellow) | "bad" (red)
  const statusMap = { High: "bad", Moderate: "warn", Low: "ok", Unknown: "ok" };
  const labelMap  = { High: "High-risk TLD", Moderate: "Elevated TLD", Low: "TLD OK", Unknown: "TLD OK" };
  setCardStatus(card, statusMap[level] || "ok", labelMap[level] || "TLD OK");

  // Risk level badge colour
  const badgeCls = level === "High" ? "malicious" : level === "Moderate" ? "suspicious" : "";
  card.innerHTML += `
    ${statRow("TLD",      `<span class="stat-val">${escHtml(tldRisk?.tld || "—")}</span>`)}
    ${statRow("TLD Risk", `<span class="stat-val ${badgeCls}">${escHtml(level)}</span>`)}
    ${tldRisk?.comment ? `<div style="margin-top:8px;font-size:11px;color:${level==="High"?"var(--red)":level==="Moderate"?"var(--yellow)":"var(--text-3)"};line-height:1.4;">${escHtml(tldRisk.comment)}</div>` : ""}`;
  if (brandSim?.brand_impersonation_flag) {
    card.innerHTML += `
      <div style="margin-top:10px;padding-top:10px;border-top:1px solid var(--border);">
        ${statRow("Brand Match", `<span class="stat-val malicious">${escHtml(brandSim.matched_brand||"")}</span>`)}
        ${statRow("Confidence",  `<span class="stat-val suspicious">${escHtml(brandSim.confidence||"")}</span>`)}
        ${statRow("Method",      `<span class="stat-val" style="font-size:11px">${escHtml(brandSim.method||"")}</span>`)}
      </div>`;
  }
  return card;
}

// ── DNS tab ────────────────────────────────────────────────
function renderDnsTab(data) {
  const container = document.getElementById("dnsContent");
  const dns = data.dns;
  if (!dns) { container.innerHTML = `<div class="empty-state">DNS data not available for this input type.</div>`; return; }

  let html = `<div class="dns-section">
    <div class="dns-section-title">Email Authentication</div>
    <div>
      ${authChip("SPF",   dns.spf)}
      ${dkimChip(dns.dkim)}
      ${authChip("DMARC", dns.dmarc)}
    </div>`;
  if (dns.spf?.records?.length)
    html += `<div style="margin-top:8px;">${dns.spf.records.map(r=>`<span class="record-chip" style="font-size:10px;color:var(--green)">${escHtml(r)}</span>`).join("")}</div>`;
  if (dns.dkim?.found && dns.dkim.record)
    html += `<div style="margin-top:6px;padding:8px 10px;background:rgba(0,0,0,0.2);border-radius:4px;font-size:10px;font-family:var(--font-mono);color:var(--text-2);word-break:break-all;">DKIM selector: <span style="color:var(--cyan)">${escHtml(dns.dkim.selector)}</span> — ${escHtml(dns.dkim.record.slice(0,120))}…</div>`;
  if (dns.dmarc?.records?.length)
    html += `<div style="margin-top:8px;">${dns.dmarc.records.map(r=>`<span class="record-chip" style="font-size:10px;color:var(--cyan)">${escHtml(r)}</span>`).join("")}</div>`;
  html += `</div>`;

  if (dns.a_records?.length)     html += dnsSection("A Records",     dns.a_records);
  if (dns.mx_records?.length)    html += dnsSection("MX Records",    dns.mx_records);
  if (dns.ns_records?.length)    html += dnsSection("NS Records",    dns.ns_records);
  if (dns.cname_records?.length) html += dnsSection("CNAME Records", dns.cname_records);
  if (dns.txt_records?.length)   html += dnsSection("TXT Records",   dns.txt_records);
  container.innerHTML = html || `<div class="empty-state">No DNS data found.</div>`;
}

function dnsSection(title, records) {
  return `<div class="dns-section"><div class="dns-section-title">${title}</div><div>${records.map(r=>`<span class="record-chip">${escHtml(r)}</span>`).join("")}</div></div>`;
}
function authChip(label, obj) {
  if (!obj) return "";
  const cls  = obj.found ? "pass" : "missing";
  const icon = obj.found ? "✓" : "✗";
  const tip  = (obj.records||[]).join(", ").slice(0,100);
  return `<span class="auth-result ${cls}" title="${escHtml(tip)}">${icon} ${label}: ${obj.status || (obj.found?"Found":"Missing")}</span>`;
}
function dkimChip(dkim) {
  if (!dkim) return "";
  const cls  = dkim.found ? "found" : "notfound";
  const icon = dkim.found ? "✓" : "—";
  const tip  = dkim.found ? `Selector: ${dkim.selector}` : "No common selectors found";
  return `<span class="dkim-chip ${cls}" title="${escHtml(tip)}">${icon} DKIM: ${dkim.found ? `Found (${dkim.selector})` : "Not probed"}</span>`;
}

// ── Infrastructure tab ─────────────────────────────────────
// ── Redirect Chain Analysis renderer ──────────────────────
function _renderRedirectChain(rc) {
  if (!rc) return "";

  // Neither API key configured
  if (!rc.vt_available && !rc.urlscan_available) {
    return `<div class="infra-detail-card redir-chain-card" style="margin-bottom:10px;">
      <div class="infra-detail-title">Redirect Chain Analysis</div>
      <div class="redir-unavailable">No redirect intelligence sources configured — add a VirusTotal or URLScan.io API key to enable redirect chain analysis.</div>
    </div>`;
  }

  const hops     = rc.hop_results || [];
  const hasRedir = rc.has_redirects;
  const sources  = rc.sources || [];

  // Build the visual hop chain
  let chainHtml = "";
  hops.forEach((hop, i) => {
    const isLast        = i === hops.length - 1;
    const isFirst       = i === 0;
    const isIntermediate = hop.intermediate === true || hop.score === null;
    const icon          = isFirst ? "🌐" : isLast && hasRedir ? "🎯" : "↪";
    const analyzeUrl    = `/?ioc=${encodeURIComponent(hop.domain)}&type=domain`;

    let rightHtml;
    if (isIntermediate) {
      // Intermediate hop — no score shown, just an Analyze button
      rightHtml = `
        <a href="${analyzeUrl}" target="_blank" rel="noopener noreferrer"
           class="redir-analyze-btn" title="Full analysis of ${escHtml(hop.domain)} in new tab">
          Analyze&nbsp;↗
        </a>`;
    } else {
      // Final (or only) hop — show full score + verdict
      const cls = _scoreCls(hop.severity);
      const labelCls = isLast && hasRedir && cls === "high" ? "redir-hop-danger" : "";
      rightHtml = `
        <span class="risk-score-value ${cls} art-score-clickable"
              style="font-size:13px;font-weight:700;border-radius:4px;padding:1px 5px"
              data-ioc="${escHtml(hop.domain)}"
              title="Investigate ${escHtml(hop.domain)} in new tab"
        >${hop.score ?? 0}</span>
        <span class="bulk-sev-chip ${cls}" style="font-size:9px;flex-shrink:0">${escHtml(hop.verdict || hop.severity || "—")}</span>`;
    }

    const rowCls = isIntermediate ? "redir-hop redir-hop-intermediate" : "redir-hop";
    chainHtml += `<div class="${rowCls}">
      <div class="redir-hop-left">
        <span class="redir-hop-icon">${icon}</span>
        <span class="redir-hop-domain" title="${escHtml(hop.domain)}">${escHtml(hop.domain)}</span>
        ${hop.error ? `<span class="email-art-sig err" style="margin-left:6px">Error</span>` : ""}
      </div>
      <div class="redir-hop-right">${rightHtml}</div>
    </div>`;
    if (!isLast) chainHtml += `<div class="redir-arrow">↓</div>`;
  });

  // Summary badge
  const suspicious = rc.chain_suspicious;
  const badge = suspicious
    ? `<span class="redir-summary-badge danger">⚠ Chain terminates in high-risk infrastructure</span>`
    : `<span class="redir-summary-badge clean">Chain appears clean</span>`;

  // Source pill — single source now (URLScan primary, VT fallback)
  const sourceStr = rc.source || (sources.length ? sources.join(" + ") : "TI APIs");
  const isLiveScan = sourceStr.includes("live");
  const sourcePills = sources.length
    ? sources.map(s => `<span class="redir-source-pill">${escHtml(s)}</span>`).join("")
    : `<span class="redir-source-pill">${escHtml(sourceStr)}</span>`;

  const sourceLabel = sourceStr;
  const hopCount    = hops.length;
  const subTitle = hasRedir
    ? `${hopCount} hop${hopCount !== 1 ? "s" : ""} detected via ${sourceLabel}`
    : `No redirects detected — single-hop URL`;

  const footerNote = isLiveScan
    ? `${sourcePills} — URLScan ran a live Chromium browser scan; JS &amp; browser redirects captured`
    : `${sourcePills} — intelligence-only; no direct HTTP requests made to submitted URL`;

  return `<div class="infra-detail-card redir-chain-card" style="margin-bottom:10px;">
    <div class="redir-chain-header">
      <div class="infra-detail-title" style="margin:0">Redirect Chain Analysis</div>
      <div class="redir-chain-meta">
        <span class="redir-chain-subtitle">${escHtml(subTitle)}</span>
        ${badge}
      </div>
    </div>
    <div class="redir-chain-body">${chainHtml || "<div class='redir-unavailable'>No chain data available.</div>"}</div>
    <div class="redir-chain-footer">
      Sources: ${footerNote}
    </div>
  </div>`;
}

// ── Async redirect chain loader ────────────────────────────
// Called after renderResults so the main lookup never blocks on URLScan.
async function _fetchRedirectChainAsync(url) {
  const placeholder = document.getElementById("redirectChainPlaceholder");
  if (!placeholder) return;

  // ── Pulsing dot on the Infrastructure tab — signals to analyst that
  //    this tab still has data loading (redirect chain via URLScan live scan)
  const infraBtn = document.querySelector("[data-tab='infrastructure']");
  let dot = null;
  if (infraBtn) {
    dot = document.createElement("span");
    dot.className = "tab-loading-dot";
    dot.title = "Redirect chain loading via URLScan live scan…";
    infraBtn.appendChild(dot);
  }
  const _removeDot = () => { if (dot && dot.parentNode) dot.parentNode.removeChild(dot); };

  // Show spinner inside the card while URLScan live scan runs
  placeholder.innerHTML = `
    <div class="infra-detail-card" style="display:flex;align-items:center;gap:12px;color:var(--text-3);font-size:12px;">
      <div class="redir-spinner"></div>
      <span>Fetching redirect chain via URLScan live scan&hellip; (may take up to 45s)</span>
    </div>`;

  try {
    const controller = new AbortController();
    const tid = setTimeout(() => controller.abort(), 90000);
    const res  = await fetch("/api/redirect-chain", {
      method: "POST",
      headers: {"Content-Type": "application/json", "X-Profile-ID": _activeProfileId || ""},
      body: JSON.stringify({ url }),
      signal: controller.signal,
    });
    clearTimeout(tid);
    const rc = await res.json();
    _removeDot();
    placeholder.innerHTML = _renderRedirectChain(rc);
  } catch (err) {
    _removeDot();
    placeholder.innerHTML = `
      <div class="infra-detail-card">
        <div class="infra-detail-title">Redirect Chain Analysis</div>
        <div class="redir-unavailable" style="color:var(--text-3);">
          ${err.name === "AbortError" ? "URLScan scan timed out — try again shortly." : "Could not fetch redirect chain: " + escHtml(err.message)}
        </div>
      </div>`;
  }
}

function renderInfraTab(data) {
  const container = document.getElementById("infraContent");
  const infra = data.infrastructure || {};
  const tls   = data.tls    || {};
  const subs  = data.subdomains || {};
  let html = "";

  // ── Redirect Chain — rendered async via _fetchRedirectChainAsync ──────────
  if (data.input_type === "url") {
    html += `<div id="redirectChainPlaceholder"></div>`;
  }

  if (infra.provider) {
    const isRapid  = infra.is_rapid_deployment || infra.rapid_deploy_flag;
    const catColor = isRapid ? "var(--orange)" : "var(--cyan)";
    html += `<div class="infra-detail-card">
      <div class="infra-detail-title">Hosting Provider Detection</div>
      <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:10px;">
        <div style="font-size:20px;font-weight:700;color:${catColor};font-family:var(--font-mono);">${escHtml(infra.provider)}</div>
        ${infra.hosting_category ? `<span class="record-chip" style="font-size:10px;">${escHtml(infra.hosting_category)}</span>` : ""}
        ${infra.detection_method ? `<span class="record-chip" style="font-size:10px;color:var(--text-3);">via ${escHtml(infra.detection_method)}</span>` : ""}
        ${isRapid ? `<span class="record-chip" style="color:var(--orange);border-color:rgba(251,146,60,.3);background:rgba(251,146,60,.1);font-size:10px;">Rapid Deployment</span>` : ""}
      </div>
      ${infra.label ? `<div style="font-size:12px;color:var(--orange);line-height:1.5;">${escHtml(infra.label)}</div>` : ""}
    </div>`;
  }

  if (!tls.error && tls.issuer) {
    const freshness = (tls.tls_freshness || "Established").toLowerCase();
    const fClass = freshness === "new" ? "new" : freshness === "recent" ? "recent" : "established";
    html += `<div class="infra-detail-card">
      <div class="infra-detail-title">TLS Certificate</div>
      ${statRow("Issuer",     `<span class="stat-val" style="font-size:11px">${escHtml(tls.issuer)}</span>`)}
      ${statRow("Subject CN", `<span class="stat-val" style="font-size:11px">${escHtml(tls.subject_cn||"—")}</span>`)}
      ${tls.tls_age_days != null ? statRow("Certificate Age", `<span class="stat-val">${tls.tls_age_days} days <span class="tls-freshness-badge ${fClass}" style="margin-left:8px">${tls.tls_freshness}</span></span>`) : ""}
      ${tls.not_before ? statRow("Issued",  `<span class="stat-val" style="font-size:11px">${escHtml(tls.not_before.slice(0,10))}</span>`) : ""}
      ${tls.not_after  ? statRow("Expires", `<span class="stat-val" style="font-size:11px">${escHtml(tls.not_after.slice(0,10))}</span>`)  : ""}
      ${tls.san_count != null ? statRow("SAN Count", `<span class="stat-val">${tls.san_count}</span>`) : ""}
    </div>`;
    if (tls.sans?.length) {
      html += `<div class="infra-detail-card"><div class="infra-detail-title">Subject Alternative Names</div>
        <div style="display:flex;flex-wrap:wrap;gap:5px;margin-top:6px;">${tls.sans.map(s=>`<span class="record-chip" style="font-size:10px">${escHtml(s)}</span>`).join("")}</div>
      </div>`;
    }
  } else if (tls.error) {
    html += `<div class="infra-detail-card"><div class="infra-detail-title">TLS Certificate</div><div class="error-note">${escHtml(tls.error)}</div></div>`;
  }

  if (subs && !subs.error) {
    const lvl = subs.explosion_level || "None";
    const flagColor = lvl === "High" ? "var(--red)" : lvl === "Elevated" ? "var(--yellow)" : "var(--green)";
    html += `<div class="infra-detail-card">
      <div class="infra-detail-title">Subdomain Exposure (CT Logs)</div>
      ${statRow("Unique Subdomains", `<span class="stat-val" style="color:${flagColor}">${subs.subdomain_count||0}</span>`)}
      ${statRow("Exposure Level",    `<span class="stat-val" style="color:${flagColor}">${lvl}</span>`)}
      ${subs.comment ? `<div style="margin-top:6px;font-size:11px;color:var(--text-3)">${escHtml(subs.comment)}</div>` : ""}
      ${subs.subdomains?.length ? `<div class="subdomain-list">${subs.subdomains.slice(0,30).map(s=>`<span class="subdomain-chip">${escHtml(s)}</span>`).join("")}</div>` : ""}
    </div>`;
  }

  container.innerHTML = html || `<div class="empty-state">Infrastructure data not available for this input type.</div>`;
}

// ── Checks Executed bar ─────────────────────────────────────
// Shared helper — renders a row of pill badges showing which analysis
// modules ran for an IOC. Used in Single IOC (Risk Breakdown tab),
// Email artifact rows, and Sender Domain Intelligence rows.
// A "failed" check is surfaced by the absence of its pill (or a future
// error chip), keeping the display clean.
function _checksBar(checksOrStatus, opts = {}) {
  // Accept either:
  //   - new format: { passed: [...], failed: [...], skipped: [...] }
  //   - old format: string[]  → all green (backward compat)
  //   - result object with .checks_status or .checks_executed on it
  let passed = [], failed = [], skipped = [];

  if (checksOrStatus && !Array.isArray(checksOrStatus) && typeof checksOrStatus === "object") {
    const cs = checksOrStatus.checks_status || checksOrStatus;
    passed  = cs.passed  || [];
    failed  = cs.failed  || [];
    skipped = cs.skipped || [];
    if (!passed.length && !failed.length && !skipped.length) {
      const legacy = checksOrStatus.checks_executed || [];
      passed = legacy;
    }
  } else if (Array.isArray(checksOrStatus)) {
    passed = checksOrStatus;
  }

  if (!passed.length && !failed.length && !skipped.length) return "";

  const cls = opts.compact ? "bulk-checks-bar bulk-checks-bar--compact" : "bulk-checks-bar";
  const pills =
    passed.map(c  => `<span class="bulk-check-pill bulk-check-pill--ok"      title="${escHtml(c)}: completed">${escHtml(c)}</span>`).join("") +
    failed.map(c  => `<span class="bulk-check-pill bulk-check-pill--warn"    title="${escHtml(c)}: failed or incomplete">${escHtml(c)}</span>`).join("") +
    skipped.map(c => `<span class="bulk-check-pill bulk-check-pill--skip"    title="${escHtml(c)}: N/A for this IOC type">${escHtml(c)}</span>`).join("");

  return `<div class="${cls}"><span class="bulk-checks-label">CHECKS:</span>${pills}</div>`;
}

// ── Risk Breakdown tab ─────────────────────────────────────
function renderBreakdownTab(data) {
  const container = document.getElementById("breakdownContent");
  const risk      = data.risk || {};
  const score     = risk.total_score ?? risk.score ?? 0;
  const severity  = (risk.severity || "LOW").toLowerCase();
  const maxScore  = risk.max_possible || 100;
  const pct       = Math.min(100, Math.round((score / maxScore) * 100));
  const breakdown = risk.breakdown || risk.factors || [];

  // ── Score / gauge header ──────────────────────────────────
  let html = `
    <div class="breakdown-header">
      <div class="breakdown-score-big ${severity}">${score}</div>
      <div class="breakdown-meta">
        <div class="breakdown-severity ${severity}">${verdictLabel(risk)}</div>
        <div class="breakdown-note">
          Normalised score from ${breakdown.length} contributing factor${breakdown.length !== 1 ? "s" : ""}.
          Scale: 0 – ${maxScore}.
        </div>
      </div>
      <div class="breakdown-gauge-wrap">
        <div class="breakdown-gauge-label">${pct}% of max</div>
        <div class="breakdown-gauge"><div class="breakdown-gauge-fill ${severity}" style="width:${pct}%"></div></div>
      </div>
    </div>`;

  // ── Factors list ──────────────────────────────────────────
  if (!breakdown.length) {
    html += `<div class="breakdown-clean"><span style="font-size:20px">✓</span><span>No risk factors detected. All signals returned clean.</span></div>`;
  } else {
    const sorted = [...breakdown].sort((a,b) => b.points - a.points);
    html += `<div class="breakdown-factors-list">`;
    sorted.forEach(f => {
      const pts    = f.points;
      const cls    = pts >= 15 ? "high-pts" : pts >= 8 ? "medium-pts" : "low-pts";
      const barPct = Math.min(100, (pts / 30) * 100);
      html += `
        <div class="breakdown-factor-row">
          <div class="bf-points ${cls}">+${pts}</div>
          <div class="bf-bar-wrap"><div class="bf-bar"><div class="bf-bar-fill ${cls}" style="width:${barPct}%"></div></div></div>
          <div class="bf-text"><div class="bf-reason">${escHtml(f.reason)}</div></div>
        </div>`;
    });
    html += `</div>`;
  }
  // ── Checks executed bar ───────────────────────────────────
  html += _checksBar(risk);

  container.innerHTML = html;
}
function renderEmailResults(data) {
  const section = document.getElementById("resultsSection");
  section.classList.remove("hidden"); section.classList.add("fade-in");
  document.getElementById("riskQuery").textContent = "Email Header Analysis";
  document.getElementById("inputTypeChip").textContent = "Email Headers";
  ["infraChip","entropyChip","tldChip","brandChip"].forEach(id => document.getElementById(id).classList.add("hidden"));
  document.getElementById("infraAlert").classList.add("hidden");
  document.getElementById("brandAlert").classList.add("hidden");

  // ── Compute overall email risk score ──────────────────────────────────
  // Collect every scored artifact + sender domain result, take the highest.
  const _allScored = [];
  const _intel = data.artifact_intel || {};
  for (const key of ["url_results","domain_results","ip_results","qr_results","ics_results","attachment_results","attachment_url_results"]) {
    for (const r of (_intel[key] || [])) {
      if (r.score != null) _allScored.push(r);
    }
  }
  const _senderIntel = data.sender_intel || {};
  for (const r of (_senderIntel.results || [])) {
    if (r.score != null) _allScored.push(r);
  }

  const _highCt = _allScored.filter(r => (r.severity||"").toUpperCase() === "HIGH").length;
  const _medCt  = _allScored.filter(r => (r.severity||"").toUpperCase() === "MEDIUM").length;

  let _topScore = 0, _topSeverity = "low", _topVerdict = "LOW THREAT";
  if (_allScored.length) {
    const _top = _allScored.reduce((a, b) => (b.score || 0) > (a.score || 0) ? b : a);
    _topScore    = _top.score    || 0;
    _topSeverity = (_top.severity || "LOW").toLowerCase();
    _topVerdict  = _top.verdict  || verdictLabel({severity: _top.severity});
  }

  const scoreEl = document.getElementById("riskScore");
  scoreEl.textContent = _allScored.length ? _topScore : "—";
  scoreEl.className   = _allScored.length ? `risk-score-value ${_topSeverity}` : "risk-score-value";

  const badge = document.getElementById("riskBadge");
  if (_allScored.length) {
    // Show verdict + artifact summary counts on the badge
    const _parts = [];
    if (_highCt > 0) _parts.push(`${_highCt} HIGH`);
    if (_medCt  > 0) _parts.push(`${_medCt} MEDIUM`);
    const _summary = _parts.length ? ` · ${_parts.join(" · ")}` : "";
    badge.textContent = _topVerdict + _summary;
    badge.className   = `risk-badge ${_topSeverity}`;
  } else {
    badge.textContent = "—";
    badge.className   = "risk-badge";
  }

  document.getElementById("riskFactors").classList.add("hidden");
  document.getElementById("emailTab").style.display = "";
  renderEmailTab(data);
  switchTab("email", document.getElementById("emailTab"));
}

function _authCls(result) {
  if (!result || result === "none" || result === "—") return "";
  return result === "pass" ? "harmless" : "suspicious";
}

function _scoreCls(severity) {
  return { HIGH: "high", MEDIUM: "medium", LOW: "low" }[(severity||"").toUpperCase()] || "low";
}

function _verdictBadge(r) {
  const cls = _scoreCls(r.severity);
  const label = r.verdict || r.severity || "Low Threat";
  return `<span class="bulk-sev-chip ${cls}" style="font-size:9px">${escHtml(label)}</span>`;
}

// Detect artifact type from its value — mirrors backend detect_input_type
function _iocType(ioc) {
  if (/^https?:\/\//i.test(ioc))                          return "url";
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(ioc.trim()))        return "ip";
  return "domain";
}

// Open an artifact in the Single IOC analyzer in a new tab
function openArtifactInTab(ioc) {
  const type = _iocType(ioc);
  const url  = "/?ioc=" + encodeURIComponent(ioc) + "&type=" + encodeURIComponent(type);
  window.open(url, "_blank");
}

// Clickable score chip — IOC stored in data-ioc attribute, never in onclick.
// Clicks are handled by the event-delegated listener on #emailContent below.
function _scoreChip(r) {
  const cls = _scoreCls(r.severity);
  const ioc = r.ioc || "";
  return `<span
    class="risk-score-value ${cls} art-score-clickable"
    style="font-size:14px;font-weight:700;cursor:pointer"
    data-ioc="${escHtml(ioc)}"
    title="Investigate in new tab"
  >${r.score ?? 0}</span>`;
}

// ── Artifact result row ─────────────────────────────────────────────────
function _artifactRow(r) {
  // Display raw URL when available (original URL with path), else the IOC key
  const displayIoc = r.raw_url || r.ioc;
  const sourceTag = r.source
    ? `<span class="email-art-source-tag">Extracted from ${escHtml(r.source)}</span>` : "";
  // Gateway unwrapping badge — shown when the original URL was a security gateway wrapper
  const gatewayTag = r.gateway_url
    ? `<div class="email-art-gateway-block">
         <span class="email-art-gateway-tag">🔓 ${escHtml(r.gateway_name || "Security Gateway")}</span>
         <div class="email-art-gateway-row"><span class="email-art-gateway-label">Wrapped URL:</span><span class="email-art-gateway-orig" title="${escHtml(r.gateway_url)}">${escHtml(r.gateway_url)}</span></div>
         <div class="email-art-gateway-row"><span class="email-art-gateway-label">Unwrapped Destination:</span><span class="email-art-gateway-dest" title="${escHtml(r.raw_url || r.ioc)}">${escHtml(r.raw_url || r.ioc)}</span></div>
       </div>`
    : "";
  const iocHtml    = `<span class="email-art-ioc" title="${escHtml(displayIoc)}">${escHtml(displayIoc)}</span>`;

  const signals = [];
  if (r.vt_malicious > 0) signals.push(`<span class="email-art-sig vt">VT:${r.vt_malicious}</span>`);
  if (r.otx_pulses   > 0) signals.push(`<span class="email-art-sig otx">OTX:${r.otx_pulses}</span>`);
  if (r.abuse_score  > 0) signals.push(`<span class="email-art-sig abuse">Abuse:${r.abuse_score}%</span>`);
  if (r.error)            signals.push(`<span class="email-art-sig err">Error</span>`);
  // Brand impersonation / homoglyph warning
  const _bs = r.brand_similarity || {};
  if (_bs.brand_impersonation_flag) {
    const _bMethod = _bs.method || "";
    const _bBrand  = _bs.matched_brand || "";
    const isHomoglyph = _bMethod.toLowerCase().includes("homoglyph");
    const sigLabel = isHomoglyph
      ? `⚠ Homoglyph: ${escHtml(_bBrand)}`
      : `⚠ Impersonates: ${escHtml(_bBrand)}`;
    signals.push(`<span class="email-art-sig brand-warn" title="${escHtml(_bs.comment || _bMethod)}">${sigLabel}</span>`);
  }

  // Action buttons — Safe UI: buttons trigger JS, not raw <a href> to artifact infra
  const _artType = _iocType(r.ioc);
  const vtUrl  = EXTERNAL_URLS.virustotal(r.ioc, _artType);
  const otxUrl = EXTERNAL_URLS.otx(r.ioc, _artType);
  const actions = `<div class="email-art-actions">
    <span class="email-art-action-btn analyze"
          data-ioc="${escHtml(r.ioc)}"
          title="Open full investigation in new tab">Analyze IOC</span>
    <a href="${vtUrl}"  target="_blank" rel="noopener" class="email-art-action-btn vt"  title="View on VirusTotal">VirusTotal</a>
    <a href="${otxUrl}" target="_blank" rel="noopener" class="email-art-action-btn otx" title="View on OTX">OTX</a>
  </div>`;

  // ── Inline redirect chain (enrichment result) ───────────────────────
  let redirHtml = "";

  // Elevation notice — shown when parent score was raised to match a high-risk redirect hop
  const elevFactor = (r.factors || []).find(f => f.key === "redirect_score_elevated");
  const elevHtml = elevFactor
    ? `<div class="art-redir-elevated">⬆ ${escHtml(elevFactor.detail)}</div>`
    : "";

  const rc = r.redirect_chain;
  if (rc === null) {
    // Explicitly skipped (LOW risk)
    redirHtml = `<div class="art-redir-skipped">↷ Redirect analysis skipped (low-risk)</div>`;
  } else if (rc && rc.hop_results && rc.hop_results.length > 0) {
    const chainCls   = rc.chain_suspicious ? "art-redir-chain--danger" : "art-redir-chain--clean";
    const chainLabel = rc.chain_suspicious ? "⚠ Suspicious chain" : "✓ Chain clean";
    const hops = rc.hop_results.map((h, i) => {
      const isLast = i === rc.hop_results.length - 1;
      const arrow  = i > 0 ? `<span class="art-redir-arrow">↓</span>` : "";
      if (h.intermediate) {
        return `${arrow}<span class="art-redir-hop art-redir-hop--intermediate" title="Intermediate hop — click Analyze to inspect">
          ${escHtml(h.domain)}
          <a class="art-redir-analyze" href="/?ioc=${encodeURIComponent(h.domain)}&type=domain" target="_blank">Analyze ↗</a>
        </span>`;
      }
      const hopCls = h.severity === "HIGH"   ? "art-redir-hop--high"
                   : h.severity === "MEDIUM" ? "art-redir-hop--medium"
                   : "art-redir-hop--low";
      const scoreHtml = h.score != null
        ? `<span class="art-redir-score ${hopCls}">${h.score}</span>`
        : "";
      return `${arrow}<span class="art-redir-hop ${isLast ? "art-redir-hop--final" : ""} ${hopCls}">
        ${escHtml(h.domain)}${scoreHtml}
      </span>`;
    }).join("");
    const srcLabel = rc.source ? `<span class="art-redir-src">via ${escHtml(rc.source)}</span>` : "";
    redirHtml = `${elevHtml}<div class="art-redir-chain ${chainCls}">
      <span class="art-redir-label ${rc.chain_suspicious ? "danger" : "clean"}">${chainLabel}</span>
      ${srcLabel}
      <div class="art-redir-hops">${hops}</div>
    </div>`;
  } else if (elevHtml) {
    redirHtml = elevHtml;
  }

  return `<div class="email-art-row">
    <div class="email-art-left">${sourceTag}${gatewayTag}${iocHtml}<div class="email-art-sigs">${signals.join("")}</div>${actions}${_checksBar(r, {compact: true})}${redirHtml}</div>
    <div class="email-art-right">${_scoreChip(r)} ${_verdictBadge(r)}</div>
  </div>`;
}

// ── Sender Domain Intelligence ──────────────────────────────────────────────
function _renderSenderIntel(senderIntel) {
  if (!senderIntel || senderIntel.error) return "";

  const results  = senderIntel.results  || [];
  const fields   = senderIntel.fields   || {};

  if (!results.length) return "";

  const rows = results.map(r => {
    const cls      = _scoreCls(r.severity);
    const vtUrl    = EXTERNAL_URLS.virustotal(r.domain, "domain");
    const otxUrl   = EXTERNAL_URLS.otx(r.domain, "domain");
    // Which header field(s) does this domain appear in?
    const fieldTags = Object.entries(fields)
      .filter(([, d]) => d === r.domain)
      .map(([f]) => `<span class="sender-field-tag">${escHtml(f.replace("_"," "))}</span>`)
      .join("");

    return `<div class="email-art-row sender-intel-row">
      <div class="email-art-left">
        <span class="email-art-ioc" title="${escHtml(r.domain)}">${escHtml(r.domain)}</span>
        <div class="sender-field-tags">${fieldTags}</div>
        <div class="email-art-actions">
          <span class="email-art-action-btn analyze" data-ioc="${escHtml(r.domain)}"
                title="Full investigation">Analyze IOC</span>
          <a href="${vtUrl}"  target="_blank" rel="noopener" class="email-art-action-btn vt">VirusTotal</a>
          <a href="${otxUrl}" target="_blank" rel="noopener" class="email-art-action-btn otx">OTX</a>
        </div>
        ${_checksBar(r, {compact: true})}
      </div>
      <div class="email-art-right">
        <span class="risk-score-value ${cls} art-score-clickable"
              style="font-size:14px;font-weight:700;cursor:pointer"
              data-ioc="${escHtml(r.domain)}"
              title="Investigate in new tab">${r.score ?? 0}</span>
        <span class="bulk-sev-chip ${cls}" style="font-size:9px">${escHtml(r.verdict||r.severity)}</span>
      </div>
    </div>`;
  }).join("");

  return `<div class="infra-detail-card sender-intel-card" style="margin-bottom:10px;">
    <div class="infra-detail-title">🕵️ Sender Domain Intelligence</div>
    ${rows}
  </div>`;
}

function renderEmailTab(data) {
  const container = document.getElementById("emailContent");

  // ── Pull the three layers ─────────────────────────────────────────────────
  const fv      = data.final_verdict  || {};
  const trust   = data.trust          || {};
  const arc     = data.arc            || trust.arc || {};
  const sid     = data.sender_identity|| trust.sender_identity || {};
  const flow    = data.mail_flow      || [];
  const records = data.auth_records   || [];
  const origin  = data.original_sender|| (data.transport||{}).origin || {};

  const spf   = fv.spf   || data.spf   || {};
  const dkim  = fv.dkim  || data.dkim  || {};
  const dmarc = fv.dmarc || data.dmarc || {};

  const spfCls  = spf.passed   ? "pass" : spf.result  && spf.result  !== "none" ? "fail" : "warn";
  const dkimCls = dkim.passed  ? "pass" : dkim.result && dkim.result !== "none" ? "fail" : "warn";
  const dmarcCls= dmarc.passed ? "pass" : dmarc.result&& dmarc.result!== "none" ? "fail" : "warn";

  // ═══════════════════════════════════════════════════════════════════════════
  // FINAL VERDICT SUMMARY — top of page, immediately visible
  // ═══════════════════════════════════════════════════════════════════════════
  const overrideHtml = fv.override_note
    ? `<div class="etl-override-note">${escHtml(fv.override_note)}</div>` : "";
  const arcBadge = fv.arc_influenced
    ? `<span class="etl-arc-badge">ARC-influenced</span>` : "";
  const srcTypeLabel = {
    "arc": "ARC Chain", "original": "Upstream Preserved",
    "gateway": "Gateway Evaluation", "fallback": "Fallback", "none": "No Data"
  }[fv.source_type || "none"] || "Evaluated";

  let html = `
  <div class="etl-verdict-banner">
    <div class="etl-verdict-chips">
      <div class="etl-verdict-chip ${spfCls}">
        <span class="etl-verdict-proto">SPF</span>
        <span class="etl-verdict-val">${escHtml((spf.result||"none").toUpperCase())}</span>
      </div>
      <div class="etl-verdict-chip ${dkimCls}">
        <span class="etl-verdict-proto">DKIM</span>
        <span class="etl-verdict-val">${escHtml((dkim.result||"none").toUpperCase())}</span>
      </div>
      <div class="etl-verdict-chip ${dmarcCls}">
        <span class="etl-verdict-proto">DMARC</span>
        <span class="etl-verdict-val">${escHtml((dmarc.result||"none").toUpperCase())}</span>
      </div>
    </div>
    <div class="etl-verdict-source">
      <span class="etl-src-type-badge">${escHtml(srcTypeLabel)}</span>
      <span class="etl-src-label">${escHtml(fv.source || data.auth_source || "")}</span>
      ${arcBadge}
    </div>
    ${overrideHtml}
  </div>`;

  // ═══════════════════════════════════════════════════════════════════════════
  // LAYER 1 — TRANSPORT FLOW (Received headers — ground truth)
  // ═══════════════════════════════════════════════════════════════════════════
  if (flow.length > 2) {
    const hops = flow.map((hop, i) => {
      const isFirst    = i === 0;
      const isLast     = i === flow.length - 1;
      const isGateway  = !!hop.gateway;
      const isInternal = hop.is_internal;
      const icon  = isFirst ? "🌐" : isLast ? "📥" : isGateway ? "🛡" : "↪";
      const cls   = isLast    ? "etl-hop mailbox"
                  : isGateway ? "etl-hop gateway"
                  : isFirst   ? "etl-hop origin"
                  : "etl-hop relay";
      const arrow = i < flow.length - 1 ? `<div class="etl-hop-arrow">↓</div>` : "";
      const ipTag = hop.ip && !isFirst && !isLast
        ? `<span class="etl-hop-ip">[${escHtml(hop.ip)}]</span>` : "";
      const tsTag = hop.timestamp
        ? `<span class="etl-hop-ts">${escHtml(hop.timestamp)}</span>` : "";
      const rcvTag = hop.receiving_host && !isLast
        ? `<span class="etl-hop-rcv">→ ${escHtml(hop.receiving_host)}</span>` : "";
      const intTag = isInternal
        ? `<span class="etl-hop-int-badge">internal</span>` : "";
      return `<div class="${cls}">
        <div class="etl-hop-main">
          <span class="etl-hop-icon">${icon}</span>
          <span class="etl-hop-label">${escHtml(hop.label || hop.hostname || "")}</span>
          ${hop.hostname && hop.hostname !== hop.label && !isFirst && !isLast
            ? `<span class="etl-hop-fqdn">${escHtml(hop.hostname)}</span>` : ""}
          ${ipTag}${intTag}
        </div>
        ${rcvTag || tsTag ? `<div class="etl-hop-detail">${rcvTag}${tsTag}</div>` : ""}
      </div>${arrow}`;
    }).join("");

    html += `<div class="infra-detail-card etl-card" style="margin-bottom:10px;">
      <div class="infra-detail-title">
        <span class="etl-layer-num">LAYER 1</span> Transport Flow
        <span class="etl-layer-note">Reconstructed from Received headers · oldest hop first</span>
      </div>`;

    // Origin sender block — ALWAYS from Received chain, NEVER from auth headers
    if (origin.hostname || origin.ip) {
      const ogGwBadge = origin.gateway_name
        ? `<span class="egat-type-tag original" style="font-size:8px">${escHtml(origin.gateway_name)}</span>` : "";

      // Build relay path from transport hops (skip Internet/Mailbox pseudo-hops)
      const relayHops = flow.filter(h => h.gateway && h.label !== "Internet" && h.label !== "Mailbox");
      const relayPathHtml = relayHops.length > 1
        ? `<div class="etl-relay-path">
            <span class="etl-relay-path-label">Relay path:</span>
            ${relayHops.map((h, i) =>
                `<span class="etl-relay-path-hop${i === 0 ? ' origin-hop' : ''}">${escHtml(h.label || h.hostname)}</span>`
                + (i < relayHops.length - 1 ? `<span class="etl-relay-path-arrow">→</span>` : "")
              ).join("")}
          </div>` : "";

      html += `<div class="etl-origin-row">
        <span class="etl-origin-icon">🌐</span>
        <div>
          <span class="etl-origin-label">True Origin — First External Hop</span>
          <span class="etl-origin-host">${escHtml(origin.hostname)}</span>
          ${origin.ip ? `<span class="etl-origin-ip">[${escHtml(origin.ip)}]</span>` : ""}
          ${ogGwBadge}
        </div>
      </div>
      ${relayPathHtml}
      <div class="etl-origin-caution">⚠ SPF is evaluated against each gateway's immediate upstream peer — not this origin. SPF failures downstream are expected when relay gateways are not listed in the sender's SPF record.</div>`;
    }

    html += `<div class="etl-flow-chain">${hops}</div></div>`;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // LAYER 2 — AUTHENTICATION TIMELINE (per-evaluator, never merged)
  // ═══════════════════════════════════════════════════════════════════════════
  if (records.length) {
    const recCards = records.map(r => {
      const name   = escHtml(r.gateway || r.server || r.evaluator || "Unknown");
      const spfR   = r.spf   || "—";
      const dkimR  = r.dkim  || "—";
      const dmarcR = r.dmarc || "—";

      const ctxLabel = r.context_label || `${r.gateway || "Gateway"} — Local Evaluation`;
      const ctxCls   = r.type === "AR-Original"  ? "original"
                     : r.is_policy_decision       ? "policy"
                     : r.type === "ARC"           ? "arc-eval"
                     :                              "local-eval";
      const typeTag = `<span class="egat-type-tag ${ctxCls}">${escHtml(ctxLabel)}</span>`;

      // evaluator_ip and relay context
      const rc = r.relay_context || {};
      let evalBlock = "";
      if (rc.has_mismatch) {
        // CONTEXTUAL explanation — specific to this relay chain, never generic
        const evalLabel   = rc.eval_gw_name
          ? `${escHtml(rc.eval_gw_name)} <span style="opacity:.7">(${escHtml(rc.eval_ip)})</span>`
          : escHtml(rc.eval_ip || "");
        const originLabel = rc.origin_gw_name
          ? `${escHtml(rc.origin_gw_name)} <span style="opacity:.7">(${escHtml(rc.origin_ip)})</span>`
          : escHtml(rc.origin_ip || "");
        evalBlock = `<div class="etl-relay-ctx">
          <div class="etl-relay-ctx-header">
            <span class="etl-relay-ctx-icon">⇄</span>
            <span class="etl-relay-ctx-title">IP Mismatch — Relay in Path</span>
          </div>
          <div class="etl-relay-ctx-row">
            <span class="etl-relay-ctx-key">Evaluated against</span>
            <span class="etl-relay-ctx-val relay">${evalLabel}</span>
          </div>
          <div class="etl-relay-ctx-row">
            <span class="etl-relay-ctx-key">True origin</span>
            <span class="etl-relay-ctx-val origin">${originLabel}</span>
          </div>
          ${rc.spf_context ? `<div class="etl-relay-ctx-note">${escHtml(rc.spf_context)}</div>` : ""}
        </div>`;
      } else if (r.evaluator_ip) {
        // No mismatch but IP present — just show it plainly
        evalBlock = `<div class="etl-auth-meta-row">
          <span class="etl-auth-meta-key">Evaluator upstream IP</span>
          <span class="etl-auth-meta-val">${escHtml(r.evaluator_ip)}</span>
        </div>`;
      }

      const mfHtml = r.mailfrom_domain
        ? `<div class="etl-auth-meta-row">
            <span class="etl-auth-meta-key">smtp.mailfrom</span>
            <span class="etl-auth-meta-val">${escHtml(r.mailfrom_domain)}</span>
          </div>` : "";

      const dkimDomHtml = r.dkim_signing_domain
        ? `<div class="etl-auth-meta-row">
            <span class="etl-auth-meta-key">DKIM d=</span>
            <span class="etl-auth-meta-val">${escHtml(r.dkim_signing_domain)}</span>
          </div>` : "";

      const dmarcFromHtml = r.dmarc_header_from
        ? `<div class="etl-auth-meta-row">
            <span class="etl-auth-meta-key">DMARC header.from</span>
            <span class="etl-auth-meta-val">${escHtml(r.dmarc_header_from)}</span>
          </div>` : "";

      const metaBlock = (evalBlock || mfHtml || dkimDomHtml || dmarcFromHtml)
        ? `<div class="etl-auth-meta">${evalBlock}${mfHtml}${dkimDomHtml}${dmarcFromHtml}</div>` : "";

      const policyNote = r.is_policy_decision
        ? `<div class="egat-policy-note">Policy decision — not a direct cryptographic SPF/DKIM/DMARC evaluation.</div>` : "";

      return `<div class="egat-gw-card${r.is_policy_decision ? " policy" : ""}">
        <div class="egat-gw-card-header">
          <span class="egat-gw-card-name">🛡 ${name}</span>
          <div class="egat-gw-card-tags">${typeTag}</div>
        </div>
        ${metaBlock}
        <div class="egat-result-row">
          <div class="egat-result-cell">
            <span class="egat-result-label">SPF</span>
            <span class="egat-val ${_authCls(spfR)}">${escHtml(spfR)}</span>
          </div>
          <div class="egat-result-cell">
            <span class="egat-result-label">DKIM</span>
            <span class="egat-val ${_authCls(dkimR)}">${escHtml(dkimR)}</span>
          </div>
          <div class="egat-result-cell">
            <span class="egat-result-label">DMARC</span>
            <span class="egat-val ${_authCls(dmarcR)}">${escHtml(dmarcR)}</span>
          </div>
        </div>
        ${policyNote}
      </div>`;
    }).join("");

    html += `<div class="infra-detail-card etl-card" style="margin-bottom:10px;">
      <div class="infra-detail-title">
        <span class="etl-layer-num">LAYER 2</span> Authentication Timeline
        <span class="etl-layer-note">One card per evaluating server · fields never merged across evaluators</span>
      </div>
      <div class="etl-auth-flow-note">Ordered oldest evaluator first · each result belongs to its own server only</div>
      <div class="egat-gw-list">${recCards}</div>
    </div>`;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // LAYER 3 — TRUST & DECISION LAYER
  // ═══════════════════════════════════════════════════════════════════════════
  let layer3Html = "";

  // 3a — ARC Chain
  if (arc.present) {
    const arcValid    = arc.chain_valid;
    const instances   = arc.instances || [];
    const trustedInst = arc.trusted_instance;
    const trustedGw   = arc.trusted_gateway_name || arc.trusted_domain || "";
    const trustedHost = arc.trusted_sealing_host  || "";

    const chainBadge = arcValid
      ? `<span class="arc-chain-status valid">✓ Valid Chain (${arc.instance_count} instance${arc.instance_count!==1?"s":""})</span>`
      : `<span class="arc-chain-status invalid">⚠ Incomplete / Invalid Chain</span>`;

    // Trusted summary — show vendor name + actual FQDN
    const trustedSummary = trustedInst != null
      ? `<div class="arc-trusted-summary">
          <span class="arc-trusted-label">Final system trusted:</span>
          <span class="arc-trusted-inst">ARC Instance i=${trustedInst}</span>
          ${trustedGw ? `<span class="arc-trusted-domain">${escHtml(trustedGw)}</span>` : ""}
          ${trustedHost && trustedHost !== (arc.trusted_domain || "")
            ? `<span class="arc-trusted-host">(${escHtml(trustedHost)})</span>` : ""}
          <span class="etl-layer-note" style="font-size:9px">sealed by this gateway — upstream auth preserved intact</span>
        </div>` : "";

    const instCards = instances.map(inst => {
      const trusted  = inst.instance === trustedInst;
      const cvCls    = inst.cv === "pass" || inst.cv === "none" ? "harmless" : "suspicious";
      const cvLabel  = inst.cv === "none" ? "none (first ARC stamp)" : inst.cv;
      const gwDisp   = inst.gateway_name || inst.domain || "unknown";
      // Show actual sealing host FQDN when it adds information beyond the vendor name
      const sealHost = inst.sealing_host || "";
      const sealHostHtml = sealHost && sealHost !== inst.domain
        ? `<span class="arc-seal-host">(${escHtml(sealHost)})</span>` : "";
      return `<div class="arc-inst-card${trusted ? " trusted" : ""}">
        <div class="arc-inst-header">
          <span class="arc-inst-num">ARC Instance i=${inst.instance}</span>
          ${trusted ? `<span class="arc-inst-trusted-badge">TRUSTED BY FINAL GATEWAY</span>` : ""}
        </div>
        <div class="arc-inst-meta">
          <span class="arc-inst-meta-item">Sealed by:
            <span class="arc-inst-meta-val">${escHtml(gwDisp)}</span>
            ${sealHostHtml}
          </span>
          ${inst.selector ? `<span class="arc-inst-meta-item">Selector: <span class="arc-inst-meta-val">${escHtml(inst.selector)}</span></span>` : ""}
          <span class="arc-inst-meta-item">cv=<span class="arc-inst-meta-val egat-val ${cvCls}" style="font-size:9px;padding:1px 5px">${escHtml(cvLabel)}</span></span>
        </div>
        <div class="arc-inst-auth">
          <span class="arc-inst-auth-label">Authentication state at this instance:</span>
          <div class="egat-result-row" style="margin-top:4px;">
            ${["spf","dkim","dmarc"].map(p => {
              const v = (inst[p]?.result) || "—";
              return `<div class="egat-result-cell">
                <span class="egat-result-label">${p.toUpperCase()}</span>
                <span class="egat-val ${_authCls(v)}">${escHtml(v)}</span>
              </div>`;
            }).join("")}
          </div>
        </div>
      </div>`;
    }).join("");

    layer3Html += `<div class="etl-trust-block">
      <div class="etl-trust-block-title">ARC Chain</div>
      <div class="arc-chain-header">${chainBadge}${trustedSummary}</div>
      <div class="arc-inst-list">${instCards}</div>
    </div>`;
  }

  // 3b — Sender Identity
  const fromD      = sid.rfc5322_from  || {};
  const rpD        = sid.return_path   || {};
  const envD       = sid.envelope_from || {};
  const replyD     = sid.reply_to      || {};
  const aln        = sid.alignment     || {};
  const mismatches = sid.mismatches    || [];
  const infoNotes  = sid.info_notes    || [];
  const espName    = sid.esp_detected  || "";

  if (fromD.address || rpD.address || sid.dkim_domain || mismatches.length || infoNotes.length) {

    // ── Alignment grid — clearly shows which domain was authenticated ──────
    const alnRows = [
      {
        label: "Visible From",
        value: fromD.domain || "—",
        role:  "Claimed sender domain (RFC5322.From)",
        cls:   "",
      },
      {
        label: "Envelope sender (smtp.mailfrom)",
        value: envD.domain || "—",
        role:  "Domain SPF is evaluated against — not the visible From",
        cls:   espName ? "esp" : (aln.spf_to_from === false ? "mismatch" : ""),
        badge: espName ? `<span class="sid-esp-badge">${escHtml(espName)}</span>` : "",
      },
      {
        label: "DKIM signing domain",
        value: sid.dkim_domain || "—",
        role:  "Domain that cryptographically signed the message",
        cls:   aln.dkim_to_from === true ? "match" : aln.dkim_to_from === false ? "mismatch" : "",
        badge: aln.dkim_to_from === true
          ? `<span class="sid-align-badge pass">✓ aligns with From</span>`
          : aln.dkim_to_from === false
          ? `<span class="sid-align-badge warn">≠ differs from From</span>` : "",
      },
      ...(rpD.address ? [{
        label: "Return-Path",
        value: rpD.address,
        role:  "Bounce destination (envelope)",
        cls:   "",
        badge: "",
      }] : []),
      ...(replyD.address ? [{
        label: "Reply-To",
        value: replyD.address,
        role:  "Replies go here — check if this differs from From",
        cls:   replyD.domain && fromD.domain && replyD.domain !== fromD.domain ? "mismatch" : "",
        badge: replyD.domain && fromD.domain && replyD.domain !== fromD.domain
          ? `<span class="sid-align-badge warn">≠ different domain</span>` : "",
      }] : []),
    ];

    const alnGridHtml = alnRows.map(row => `
      <div class="sid-aln-row">
        <div class="sid-aln-label">${escHtml(row.label)}</div>
        <div class="sid-aln-val ${row.cls || ''}">
          ${escHtml(row.value)}
          ${row.badge || ""}
        </div>
        <div class="sid-aln-role">${escHtml(row.role)}</div>
      </div>`).join("");

    // ── SPF evaluation note — explicit "SPF is about envelope, not From" ──
    const spfNoteHtml = aln.spf_note
      ? `<div class="sid-spf-note">
          <span class="sid-spf-note-icon">ℹ</span>
          <span>${escHtml(aln.spf_note)}</span>
        </div>` : "";

    // ── Alignment verdict note ─────────────────────────────────────────────
    const alnNoteHtml = aln.note
      ? `<div class="sid-aln-verdict ${aln.dmarc_passed ? 'pass' : 'warn'}">
          ${aln.dmarc_passed ? "✓" : "⚠"} ${escHtml(aln.note)}
        </div>` : "";

    // ── ESP notice (informational, not anomaly) ────────────────────────────
    const espHtml = espName
      ? `<div class="sid-esp-notice">
          <span class="sid-esp-notice-icon">📨</span>
          <div>
            <div class="sid-esp-notice-title">Third-party Email Service: ${escHtml(espName)}</div>
            <div class="sid-esp-notice-body">The envelope sender domain belongs to ${escHtml(espName)}.
            ESPs use their own domain for bounce handling — this is expected behaviour, not a spoofing indicator.</div>
          </div>
        </div>` : "";

    // ── Info notes (not anomalies — contextual explanations) ──────────────
    const infoHtml = infoNotes.map(n => `
      <div class="etl-mismatch info">
        <span class="etl-mismatch-icon">ℹ</span>
        <span class="etl-mismatch-text">
          <strong>${escHtml(n.field_a)}</strong> (${escHtml(n.value_a)}) ≠
          <strong>${escHtml(n.field_b)}</strong> (${escHtml(n.value_b)})
          <span class="etl-mismatch-note">— ${escHtml(n.note)}</span>
        </span>
      </div>`).join("");

    // ── Real anomalies (high/medium — actual suspicious signals) ──────────
    const mmHtml = mismatches.length
      ? mismatches.map(mm => `
          <div class="etl-mismatch ${mm.severity}">
            <span class="etl-mismatch-icon">${mm.severity === "high" ? "⚠" : "⚡"}</span>
            <span class="etl-mismatch-text">
              <strong>${escHtml(mm.field_a)}</strong> (${escHtml(mm.value_a)}) ≠
              <strong>${escHtml(mm.field_b)}</strong> (${escHtml(mm.value_b)})
              <span class="etl-mismatch-note">— ${escHtml(mm.note)}</span>
            </span>
          </div>`).join("")
      : `<div class="etl-mismatch ok">
          <span class="etl-mismatch-icon">✓</span>
          <span>No identity anomalies detected</span>
        </div>`;

    layer3Html += `<div class="etl-trust-block">
      <div class="etl-trust-block-title">Sender Identity &amp; Domain Alignment</div>

      <div class="sid-aln-grid">${alnGridHtml}</div>
      ${spfNoteHtml}
      ${alnNoteHtml}
      ${espHtml}

      ${infoNotes.length ? `<div class="sid-section-label">Informational — Not Anomalies</div>${infoHtml}` : ""}
      ${mismatches.length ? `<div class="sid-section-label suspicious">Anomalies Detected</div>` : ""}
      <div class="etl-mismatches">${mmHtml}</div>
    </div>`;
  }

  if (layer3Html) {
    html += `<div class="infra-detail-card etl-card" style="margin-bottom:10px;">
      <div class="infra-detail-title">
        <span class="etl-layer-num">LAYER 3</span> Trust &amp; Decision Layer
        <span class="etl-layer-note">ARC chain · sender identity · final verdict provenance</span>
      </div>
      ${layer3Html}
    </div>`;
  }

  // ── Anomalies ───────────────────────────────────────────────────────────
  if (data.anomalies?.length)
    html += `<div style="margin-bottom:10px"><div class="dns-section-title" style="margin-bottom:8px;">⚠ Anomalies Detected</div>${data.anomalies.map(a=>`<div class="anomaly-item"><span class="anomaly-icon">⚠</span><span>${escHtml(a)}</span></div>`).join("")}</div>`;

  // ── Sender Domain Intelligence ────────────────────────────────────────
  if (data.sender_intel) {
    html += _renderSenderIntel(data.sender_intel);
  }

  // ── Header details ──────────────────────────────────────────────────────
  const details = [["From",data.from],["To",data.to],["Reply-To",data.reply_to],["Return-Path",data.return_path],["Date",data.date],["Subject",data.subject],["Message-ID",data.message_id],["X-Mailer",data.x_mailer],["Originating IP",data.x_originating_ip]].filter(([,v])=>v);
  if (details.length)
    html += `<div class="infra-detail-card" style="margin-bottom:10px;"><div class="infra-detail-title">Header Details</div>${details.map(([k,v])=>statRow(k,`<span class="stat-val" style="font-size:11px;word-break:break-all">${escHtml(v)}</span>`)).join("")}</div>`;

  // ── Sending IPs ─────────────────────────────────────────────────────────
  if (data.sending_ips?.length)
    html += `<div class="infra-detail-card" style="margin-bottom:10px;"><div class="infra-detail-title">IPs from Received Chain</div><div style="display:flex;flex-wrap:wrap;gap:6px;margin-top:6px;">${data.sending_ips.map(ip=>`<span class="record-chip" style="color:var(--cyan)">${escHtml(ip)}</span>`).join("")}</div><div style="margin-top:10px;font-size:11px;color:var(--text-3);">Tip: Copy IPs above and run an IP lookup for full enrichment.</div></div>`;

  // ── ═══════════════════════════════════════════════════════════════════ ──
  // ── ARTIFACT INTELLIGENCE (EML upload only) ─────────────────────────────
  // ── ═══════════════════════════════════════════════════════════════════ ──
  const intel = data.artifact_intel;
  if (intel) {
    if (intel.error) {
      html += `<div class="email-art-section"><div class="email-art-header">⚠ Artifact scan error: ${escHtml(intel.error)}</div></div>`;
    } else {
      // Section header with summary counts
      const highCt = intel.total_high   || 0;
      const medCt  = intel.total_medium || 0;
      const counts = intel.artifact_counts || {};
      const summaryParts = [];
      if (counts.urls)             summaryParts.push(`${counts.urls} URL${counts.urls!==1?"s":""}`);
      if (counts.attachment_urls)  summaryParts.push(`${counts.attachment_urls} attachment link${counts.attachment_urls!==1?"s":""}`);
      if (counts.domains)     summaryParts.push(`${counts.domains} domain${counts.domains!==1?"s":""}`);
      if (counts.ips)         summaryParts.push(`${counts.ips} IP${counts.ips!==1?"s":""}`);
      if (counts.qr_codes)     summaryParts.push(`${counts.qr_codes} QR code${counts.qr_codes!==1?"s":""}`);
      if (counts.office_links) summaryParts.push(`${counts.office_links} Office link${counts.office_links!==1?"s":""}`);
      if (counts.ics_links)    summaryParts.push(`${counts.ics_links} calendar link${counts.ics_links!==1?"s":""}`);
      if (counts.attachments)  summaryParts.push(`${counts.attachments} attachment${counts.attachments!==1?"s":""}`);

      html += `<div class="email-art-divider">
        <span class="email-art-divider-label">EMAIL ARTIFACT INTELLIGENCE</span>
        <span class="email-art-divider-counts">
          ${summaryParts.join(" · ")}
          ${highCt   > 0 ? `<span class="email-art-badge high">${highCt} HIGH</span>`   : ""}
          ${medCt    > 0 ? `<span class="email-art-badge medium">${medCt} MEDIUM</span>` : ""}
          ${!highCt && !medCt ? `<span class="email-art-badge low">All Clean</span>` : ""}
        </span>
      </div>
      <div class="email-safe-mode-banner">
        🔒 Safe Processing Mode — No DNS resolution · No HTTP requests to artifacts · TI API lookups only
      </div>`;

      // ── Redirect chain analysis summary ───────────────────────────────
      const rs = intel.redirect_summary;
      if (rs) {
        const rAnalysed   = rs.analysed   || 0;
        const rSkipped    = rs.skipped    || 0;
        const rSuspicious = rs.suspicious_chains || 0;
        const rStatus     = rSuspicious > 0 ? "danger"
                          : rAnalysed  > 0 ? "clean"
                          : "neutral";
        const rIcon = rSuspicious > 0 ? "⚠" : rAnalysed > 0 ? "✓" : "—";
        html += `<div class="email-redir-summary email-redir-summary--${rStatus}">
          <span class="email-redir-summary__icon">${rIcon}</span>
          <span class="email-redir-summary__title">Redirect Analysis</span>
          <span class="email-redir-summary__detail">
            ${rAnalysed > 0
              ? `<span class="email-redir-summary__pill analysed">Analysed ${rAnalysed} suspicious URL${rAnalysed!==1?"s":""}</span>`
              : ""}
            ${rSkipped > 0
              ? `<span class="email-redir-summary__pill skipped">Skipped ${rSkipped} low-risk URL${rSkipped!==1?"s":""}</span>`
              : ""}
            ${rSuspicious > 0
              ? `<span class="email-redir-summary__pill suspicious">${rSuspicious} suspicious chain${rSuspicious!==1?"s":""} detected</span>`
              : rAnalysed > 0 ? `<span class="email-redir-summary__pill clean">No suspicious chains</span>` : ""}
          </span>
        </div>`;
      }  // end if (rs)

      // Display/link mismatches — phishing signal
      const mm = intel.mismatches || [];
      if (mm.length) {
        html += `<div class="infra-detail-card email-art-section" style="margin-bottom:10px;border-color:rgba(248,113,113,0.3);">
          <div class="infra-detail-title" style="color:var(--red)">⚠ Display/Link Mismatch${mm.length>1?"es":""} Detected</div>
          ${mm.map(m => `<div class="email-mismatch-row">
            <div><span class="stat-key">Displayed:</span> <span style="color:var(--text-1)">${escHtml(m.display_domain)}</span></div>
            <div><span class="stat-key">Actual link:</span> <span style="color:var(--red)">${escHtml(m.href_domain)}</span></div>
            ${m.unwrapped_href ? `<div class="email-mismatch-unwrapped"><span class="stat-key">Unwrapped destination:</span> <span style="color:var(--cyan);font-family:var(--font-mono);font-size:10px;">${escHtml(m.unwrapped_href)}</span></div>` : ""}
            <div class="email-mismatch-href">${escHtml(m.href)}</div>
          </div>`).join("<hr style='border-color:var(--border);margin:6px 0'>")}
        </div>`;
      }

      // URL results
      if (intel.url_results?.length) {
        html += `<div class="infra-detail-card email-art-section" style="margin-bottom:10px;">
          <div class="infra-detail-title">URLs</div>
          ${intel.url_results.map(_artifactRow).join("")}
        </div>`;
      }

      // Domain results
      if (intel.domain_results?.length) {
        html += `<div class="infra-detail-card email-art-section" style="margin-bottom:10px;">
          <div class="infra-detail-title">Domains</div>
          ${intel.domain_results.map(_artifactRow).join("")}
        </div>`;
      }

      // IP results
      if (intel.ip_results?.length) {
        html += `<div class="infra-detail-card email-art-section" style="margin-bottom:10px;">
          <div class="infra-detail-title">IP Addresses</div>
          ${intel.ip_results.map(_artifactRow).join("")}
        </div>`;
      }

      // QR Code + Office document link results
      if (intel.qr_results?.length) {
        const qrOnly     = intel.qr_results.filter(r => !r.source?.startsWith("Attachment:"));
        const officeOnly = intel.qr_results.filter(r =>  r.source?.startsWith("Attachment:"));
        if (qrOnly.length) {
          html += `<div class="infra-detail-card email-art-section" style="margin-bottom:10px;">
            <div class="infra-detail-title">🔲 QR Code Payloads</div>
            <div class="email-art-safe-note">URLs decoded from QR images — never fetched (Safe Processing Mode)</div>
            ${qrOnly.map(_artifactRow).join("")}
          </div>`;
        }
        if (officeOnly.length) {
          html += `<div class="infra-detail-card email-art-section" style="margin-bottom:10px;">
            <div class="infra-detail-title">📄 Office Document Links</div>
            <div class="email-art-safe-note">Hyperlinks extracted from .docx/.xlsx/.pptx attachments — never fetched (Safe Processing Mode)</div>
            ${officeOnly.map(_artifactRow).join("")}
          </div>`;
        }
      }

      // ICS Calendar results
      if (intel.ics_results?.length) {
        html += `<div class="infra-detail-card email-art-section" style="margin-bottom:10px;">
          <div class="infra-detail-title">📅 ICS Calendar Links</div>
          <div class="email-art-safe-note">URLs extracted from calendar attachment — never fetched (Safe Processing Mode)</div>
          ${intel.ics_results.map(_artifactRow).join("")}
        </div>`;
      }

      // Attachment results — file hash reputation
      if (intel.attachment_results?.length) {
        html += `<div class="infra-detail-card email-art-section" style="margin-bottom:10px;">
          <div class="infra-detail-title">Attachment Analysis</div>
          ${intel.attachment_results.map(r => {
            const meta = `<div class="email-art-attach-meta">${escHtml(r.filename||"unknown")} · ${escHtml(r.content_type||"")} · ${r.size ? Math.round(r.size/1024)+"KB" : "—"}</div>`;
            return `<div>${meta}${_artifactRow(r)}</div>`;
          }).join("")}
        </div>`;
      }

      // Attachment Intelligence — URLs extracted from inside PDF/HTML/TXT attachments
      if (intel.attachment_url_results?.length) {
        const attUrlHigh = intel.attachment_url_results.filter(r => (r.severity||"").toUpperCase() === "HIGH").length;
        const attUrlMed  = intel.attachment_url_results.filter(r => (r.severity||"").toUpperCase() === "MEDIUM").length;
        const attBadgeCls = attUrlHigh > 0 ? "high" : attUrlMed > 0 ? "medium" : "low";
        const attBadge    = attUrlHigh > 0 ? `${attUrlHigh} HIGH` : attUrlMed > 0 ? `${attUrlMed} MEDIUM` : "All Clean";
        html += `<div class="infra-detail-card email-art-section" style="margin-bottom:10px;">
          <div class="infra-detail-title" style="display:flex;align-items:center;gap:8px;">
            Attachment Intelligence
            <span class="email-art-badge ${attBadgeCls}">${attBadge}</span>
          </div>
          <div class="email-art-attach-intel-note">
            URLs extracted from inside attachments (PDF hyperlinks, HTML hrefs, TXT links).
            Each URL was unwrapped and scored independently.
          </div>
          ${intel.attachment_url_results.map(r => {
            const fileLabel = r.source_file
              ? `<div class="email-art-attach-meta">📎 ${escHtml(r.source_file)}</div>`
              : "";
            return `<div>${fileLabel}${_artifactRow(r)}</div>`;
          }).join("")}
        </div>`;
      }

      // No artifacts found at all
      const totalArtifacts = (counts.urls||0)+(counts.domains||0)+(counts.ips||0)+(counts.attachments||0);
      if (totalArtifacts === 0) {
        html += `<div class="infra-detail-card email-art-section" style="color:var(--text-3);font-size:12px;text-align:center;padding:20px;">
          No extractable IOC artifacts found in email body.
        </div>`;
      }
    }
  }

  container.innerHTML = html;
}

// ── DOM helpers ────────────────────────────────────────────
function createCard(title, extLinkHtml = "") {
  const card = document.createElement("div");
  card.className = "service-card";
  card.innerHTML = `<div class="service-header">
    <span class="service-name">${escHtml(title)}</span>
    <span class="service-status"></span>
  </div>
  ${extLinkHtml ? `<div class="card-ext-link-row">${extLinkHtml}</div>` : ""}`;
  return card;
}
function setCardStatus(card, status, label = "") {
  const el = card.querySelector(".service-status");
  if (el) {
    el.className  = `service-status ${status}`;
    el.textContent= label || {ok:"Clean",warn:"Suspicious",bad:"Malicious",error:"Error",skip:"N/A"}[status] || status;
  }
}
function statRow(key, valHtml) { return `<div class="stat-row"><span class="stat-key">${key}</span>${valHtml}</div>`; }
function p(cls, text)          { const el = document.createElement("p"); el.className = cls; el.textContent = text; return el; }
function formatDate(val) {
  if (!val) return "—";
  if (typeof val === "number") return new Date(val * 1000).toISOString().split("T")[0];
  try { return new Date(val).toISOString().split("T")[0]; } catch { return val; }
}
function formatBytes(bytes) {
  if (!bytes) return "—";
  const units = ["B","KB","MB","GB"]; let b = bytes, i = 0;
  while (b >= 1024 && i < units.length-1) { b /= 1024; i++; }
  return `${b.toFixed(1)} ${units[i]}`;
}
function escHtml(str) {
  if (!str) return "";
  return String(str).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}

// ── Artifact score badge — single global event delegation ──
// Attached to document.body (never replaced by innerHTML) so it
// survives tab switches, email re-renders, and redirect chain redraws.
// Covers #emailContent, #infraContent, and any future containers.
document.body.addEventListener("click", function(e) {
  // Score badge click → open investigation
  const badge = e.target.closest(".art-score-clickable");
  if (badge) {
    const ioc = badge.getAttribute("data-ioc");
    if (ioc) openArtifactInTab(ioc);
    return;
  }
  // "Analyze IOC" button click → same target
  const analyzeBtn = e.target.closest(".email-art-action-btn.analyze");
  if (analyzeBtn) {
    const ioc = analyzeBtn.getAttribute("data-ioc");
    if (ioc) openArtifactInTab(ioc);
  }
});

// ── Score modal ────────────────────────────────────────────
function toggleScoreModal() {
  const modal = document.getElementById("scoreModal");
  modal.classList.toggle("hidden");
  document.body.style.overflow = modal.classList.contains("hidden") ? "" : "hidden";
}
function closeScoreModalOnOverlay(event) {
  if (event.target === event.currentTarget) toggleScoreModal();
}
document.addEventListener("keydown", e => {
  if (e.key === "Escape") {
    const modal = document.getElementById("scoreModal");
    if (!modal.classList.contains("hidden")) toggleScoreModal();
  }
});

// ── Auto-run from URL params (?ioc=...&type=...) ──────────
// Allows artifact score badges to open a pre-filled, auto-running
// analysis in a new tab via openArtifactInTab().
(function _autoRunFromParams() {
  const params = new URLSearchParams(window.location.search);
  const ioc    = params.get("ioc");
  if (!ioc) return;
  const input = document.getElementById("queryInput");
  if (!input) return;
  // Populate the input field
  input.value = decodeURIComponent(ioc);
  // Fire the type-detection hint so the tag appears
  input.dispatchEvent(new Event("input"));
  // Run the analysis after a short tick so the UI is fully ready
  setTimeout(runLookup, 80);
})();
// ── Analysis Timer ──────────────────────────────────────────────────────────
// Shows "Analyzed in: Xs" / "Analyzed in: XmYs" in the header badge
// after each Single IOC, Bulk, or Email analysis completes.

let _analyzeStartTime = null;

function _timerStart() {
  _analyzeStartTime = performance.now();
  const badge = document.getElementById("analyzedInBadge");
  if (badge) badge.classList.add("hidden");
}

function _timerStop() {
  if (_analyzeStartTime === null) return;
  const ms      = performance.now() - _analyzeStartTime;
  _analyzeStartTime = null;

  const totalSec = Math.round(ms / 1000);
  const mins     = Math.floor(totalSec / 60);
  const secs     = totalSec % 60;

  let label;
  if (mins > 0) {
    label = `Analyzed in: ${String(mins).padStart(2,"0")}MINS ${String(secs).padStart(2,"0")}SEC`;
  } else {
    label = `Analyzed in: ${String(secs).padStart(2,"0")}SEC`;
  }

  const badge = document.getElementById("analyzedInBadge");
  const lbl   = document.getElementById("analyzedInLabel");
  if (badge && lbl) {
    lbl.textContent = label;
    badge.classList.remove("hidden");
  }
}

// ── Live Calls Panel ────────────────────────────────────────────────────────
// Tracks API calls made for a single analysis session only.
// Session resets on every new Analyze press — no cumulative history.
// Core principle: no IOC data stored — only API service names + counts.
// iRECON: "No data stored, logged, or transmitted beyond API calls."

let _liveCallsOpen  = false;
let _liveSessionId  = null;
let _liveCallsData  = null;
let _liveAnalyzing  = false;

function _generateSessionId() {
  return ([1e7]+-1e3+-4e3+-8e3+-1e11).replace(/[018]/g, c =>
    (c ^ crypto.getRandomValues(new Uint8Array(1))[0] & 15 >> c / 4).toString(16)
  );
}

function _liveCallsSetState(state) {
  const dot = document.getElementById("liveCallsDot");
  const lbl = document.getElementById("liveCallsLabel");
  const btn = document.getElementById("liveCallsBtn");
  if (!dot) return;
  dot.className = `live-calls-dot ${state}`;
  if (state === "idle") {
    lbl.textContent = "No Data Stored";
    btn.classList.remove("active");
  } else if (state === "running") {
    lbl.textContent = "Fetching\u2026";
    btn.classList.add("active");
  } else if (state === "done" && _liveCallsData) {
    const n = _liveCallsData.total || 0;
    lbl.textContent = `${n} request${n !== 1 ? "s" : ""}`;
    btn.classList.add("active");
  }
}

function toggleLiveCalls() {
  const panel = document.getElementById("liveCallsPanel");
  if (!panel) return;
  _liveCallsOpen = !_liveCallsOpen;
  panel.classList.toggle("hidden", !_liveCallsOpen);
  if (_liveCallsOpen) {
    _renderLiveCalls();
    setTimeout(() => document.addEventListener("click", _outsideLiveCalls), 0);
  } else {
    document.removeEventListener("click", _outsideLiveCalls);
  }
}

function _outsideLiveCalls(e) {
  const panel = document.getElementById("liveCallsPanel");
  const btn   = document.getElementById("liveCallsBtn");
  if (panel && !panel.contains(e.target) && btn && !btn.contains(e.target)) {
    _liveCallsOpen = false;
    panel.classList.add("hidden");
    document.removeEventListener("click", _outsideLiveCalls);
  }
}

async function _fetchLiveCalls(sid) {
  try {
    const res  = await fetch(`/api/session-calls/${sid}`);
    const data = await res.json();
    _liveCallsData = data;
    _liveCallsSetState("done");
    if (_liveCallsOpen) _renderLiveCalls();
  } catch(e) { /* silent — don't break analysis flow */ }
}

const _API_COLOURS = {
  virustotal: "#22d3ee",
  otx:        "#fb923c",
  abuseipdb:  "#a78bfa",
  urlscan:    "#34d399",
  crt_sh:     "#60a5fa",
  dns_whois:  "#60a5fa",
  other:      "#6b7280",
  violation:  "#f87171",
};

function _renderLiveCalls() {
  const body = document.getElementById("liveCallsBody");
  if (!body) return;
  const badge = document.getElementById("liveCallsSessionBadge");

  if (!_liveSessionId && !_liveCallsData) {
    if (badge) badge.textContent = "";
    body.innerHTML = `
      <div class="live-calls-idle">
        <div class="live-calls-idle-icon">&#x1F6E1;</div>
        <div>Waiting for analysis&hellip;</div>
        <div style="font-size:10px;margin-top:4px;color:var(--text-3)">Click Analyze to see live calls</div>
      </div>`;
    return;
  }

  if (_liveAnalyzing && !_liveCallsData) {
    if (badge) badge.textContent = `session ${(_liveSessionId||"").slice(0,8)}`;
    body.innerHTML = `
      <div class="live-calls-idle">
        <div class="live-calls-idle-icon">&#x23F3;</div>
        <div style="color:var(--cyan)">Analysis in progress&hellip;</div>
        <div style="font-size:10px;margin-top:4px;color:var(--text-3)">Panel updates on completion</div>
      </div>`;
    return;
  }

  if (!_liveCallsData) return;

  const d          = _liveCallsData;
  const total      = d.total      || 0;
  const apis       = d.apis       || {};
  const tl         = d.timeline   || [];
  const violations = d.violations || [];
  const done       = !_liveAnalyzing;

  if (badge) badge.textContent = `session ${(d.session_id||"").slice(0,8)}`;

  // ── Violation banner (Safe Processing breach) ──────────────────────────
  let html = "";
  if (violations.length) {
    html += `
      <div class="live-calls-violation-banner">
        <span class="live-calls-violation-icon">&#x26A0;</span>
        <div>
          <div class="live-calls-violation-title">SAFE PROCESSING VIOLATION</div>
          <div class="live-calls-violation-msg">${violations.length} direct request${violations.length > 1 ? "s" : ""} to non-TI infrastructure detected</div>
        </div>
      </div>`;
  }

  // ── Summary row ────────────────────────────────────────────────────────
  html += `
    <div class="live-calls-summary">
      <div>
        <div class="live-calls-total${violations.length ? " has-violations" : ""}">${total}</div>
        <div class="live-calls-total-label">requests</div>
      </div>
      <div class="live-calls-status ${done ? "done" : "running"}">${done ? "\u2713 COMPLETE" : "\u25CF LIVE"}</div>
    </div>
    <div class="live-calls-apis">`;

  // ── Per-service rows ───────────────────────────────────────────────────
  for (const [key, info] of Object.entries(apis)) {
    const isViolation = key === "violation";
    const colour      = isViolation ? "#f87171" : (_API_COLOURS[key] || "var(--cyan)");

    // Build method pills: "14× GET" "2× POST"
    const methods = info.methods || {};
    const methodPills = Object.entries(methods)
      .sort((a, b) => b[1] - a[1])
      .map(([m, n]) => `<span class="live-calls-method-pill ${m.toLowerCase()}">${n}&times;&nbsp;${m}</span>`)
      .join(" ");

    html += `
      <div class="live-calls-api-row${isViolation ? " violation-row" : ""}">
        <div class="live-calls-api-dot" style="background:${colour};box-shadow:0 0 4px ${colour}80"></div>
        <div class="live-calls-api-info">
          <span class="live-calls-api-name${isViolation ? " violation-name" : ""}">${escHtml(info.name)}</span>
          <span class="live-calls-api-methods">${methodPills}</span>
        </div>
        <span class="live-calls-api-count${isViolation ? " violation-count" : ""}">${info.calls}</span>
      </div>`;
  }
  html += `</div>`;

  // ── Call timeline ──────────────────────────────────────────────────────
  if (tl.length) {
    const tshow = tl.slice(0, 40);  // cap at 40 for panel height
    html += `<div class="live-calls-timeline-header">Call sequence <span style="color:var(--text-3);font-weight:400">(${tl.length})</span></div>
    <div class="live-calls-timeline">`;
    for (const item of tshow) {
      const isVio   = item.violation;
      const colour  = isVio ? "#f87171" : (_API_COLOURS[item.key] || "var(--cyan)");
      const ts      = item.t < 0.1 ? "0.0s" : `${item.t.toFixed(1)}s`;
      const method  = item.method || "GET";
      html += `
        <div class="live-calls-tl-item${isVio ? " violation-tl" : ""}">
          <span class="live-calls-tl-t">+${ts}</span>
          <span class="live-calls-tl-method ${method.toLowerCase()}">${method}</span>
          <div class="live-calls-tl-bar" style="background:${colour}"></div>
          <span class="live-calls-tl-name${isVio ? " violation-name" : ""}">${escHtml(item.api_name)}</span>
        </div>`;
    }
    if (tl.length > 40) {
      html += `<div style="padding:4px 0;font-size:9px;color:var(--text-3);text-align:center">… and ${tl.length - 40} more</div>`;
    }
    html += `</div>`;
  }

  body.innerHTML = html;
}

// Called at the start of every analysis to begin a fresh session
function _beginSession() {
  _liveSessionId = _generateSessionId();
  _liveCallsData = null;
  _liveAnalyzing = true;
  _liveCallsSetState("running");
  if (_liveCallsOpen) _renderLiveCalls();
  return _liveSessionId;
}

// Called after the response lands — fetches and renders the session summary
async function _endSession(sid) {
  _liveAnalyzing = false;
  await _fetchLiveCalls(sid);
}

// ═══════════════════════════════════════════════════════════════
// ANALYST PROFILE SYSTEM  —  iRECON BYOK
// ═══════════════════════════════════════════════════════════════

// ── State ──────────────────────────────────────────────────────
let _activeProfileId   = localStorage.getItem("iReconProfileId")   || null;
let _activeProfileName = localStorage.getItem("iReconProfileName")  || null;
let _profilePanelOpen  = false;
let _allProfiles       = [];
let _editingProfileId  = null;

// ── Boot ───────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  _refreshProfileBadge();
  _bootProfileCheck();
});

/**
 * On every page load: verify the stored profile ID still exists on the server.
 * If no profile is set, or the stored ID is stale/deleted, open the selector
 * immediately so the analyst can't accidentally run queries without a profile.
 */
async function _bootProfileCheck() {
  try {
    const res = await fetch("/api/profiles");
    _allProfiles = await res.json() || [];
  } catch(e) {
    _allProfiles = [];
  }

  // If a profile was previously chosen, verify it still exists
  if (_activeProfileId) {
    const stillExists = _allProfiles.some(p => p.id === _activeProfileId);
    if (!stillExists) {
      // Profile was deleted — clear stale state
      _activeProfileId   = null;
      _activeProfileName = null;
      localStorage.removeItem("iReconProfileId");
      localStorage.removeItem("iReconProfileName");
      _refreshProfileBadge();
    }
  }

  // No valid profile — force the selector open
  if (!_activeProfileId) {
    _setModalTitle("SELECT PROFILE — Required to run analysis");
    _openProfileModal();
    _renderProfileList();
  }
}

// ── Header badge ───────────────────────────────────────────────
function _refreshProfileBadge() {
  const dot    = document.getElementById("profileDot");
  const label  = document.getElementById("profileBtnLabel");
  const btn    = document.getElementById("profileBtn");
  const banner = document.getElementById("noProfileBanner");
  const hasProfile = Boolean(_activeProfileId && _activeProfileName);

  if (dot)   dot.className   = "profile-dot " + (hasProfile ? "active" : "no-keys");
  if (label) label.textContent = hasProfile ? _activeProfileName.slice(0, 16) : "Select Profile";
  if (btn)   btn.title = hasProfile ? `Active: ${_activeProfileName}` : "Select analyst profile to enable analysis";

  // Show / hide the warning banner in the search panel
  if (banner) banner.classList.toggle("hidden", hasProfile);
}

// ── Panel toggle ───────────────────────────────────────────────
function toggleProfilePanel() {
  const panel = document.getElementById("profilePanel");
  if (!panel) return;
  _profilePanelOpen = !_profilePanelOpen;
  panel.classList.toggle("hidden", !_profilePanelOpen);
  if (_profilePanelOpen) {
    _renderProfilePanel();
    setTimeout(() => document.addEventListener("click", _outsideProfilePanel, {once: false}), 50);
  } else {
    document.removeEventListener("click", _outsideProfilePanel);
  }
}

function _outsideProfilePanel(e) {
  const panel  = document.getElementById("profilePanel");
  const btn    = document.getElementById("profileBtn");
  const modal  = document.getElementById("profileModal");
  if (!_profilePanelOpen) return;
  const modalOpen = modal && !modal.classList.contains("hidden");
  if (modalOpen) return; // don't close panel while modal is open
  if (panel && !panel.contains(e.target) && btn && !btn.contains(e.target)) {
    _profilePanelOpen = false;
    panel.classList.add("hidden");
    document.removeEventListener("click", _outsideProfilePanel);
  }
}

// ── Panel render ───────────────────────────────────────────────
async function _renderProfilePanel() {
  _renderProfileActiveName();
  _renderProfileApiStatus("loading");
  try {
    const headers = _activeProfileId ? {"X-Profile-ID": _activeProfileId} : {};
    const res  = await fetch("/api/status", {headers});
    const data = await res.json();
    _renderProfileApiStatus("done", data);
  } catch(e) {
    _renderProfileApiStatus("error");
  }
}

function _renderProfileActiveName() {
  const nameEl = document.getElementById("profileActiveName");
  const dot    = document.getElementById("profileActiveDot");
  if (nameEl) nameEl.textContent = _activeProfileName || "No profile selected";
  if (dot)    dot.className = "profile-active-dot " + (_activeProfileName ? "on" : "off");
}

function _renderProfileApiStatus(state, data) {
  const el = document.getElementById("profileApiStatus");
  if (!el) return;
  if (state === "loading") {
    el.innerHTML = '<div class="profile-api-loading">Checking API connections&hellip;</div>';
    return;
  }
  if (state === "error") {
    el.innerHTML = '<div class="profile-api-loading" style="color:#f87171">Could not load API status</div>';
    return;
  }
  const SERVICES = [
    {key: "virustotal", label: "VirusTotal"},
    {key: "otx",        label: "AlienVault OTX"},
    {key: "abuseipdb",  label: "AbuseIPDB"},
    {key: "urlscan",    label: "URLScan.io"},
  ];
  let html = "";
  for (const {key, label} of SERVICES) {
    const svc     = (data || {})[key] || {};
    const enabled = svc.enabled;
    const badge = enabled
      ? '<span class="profile-api-badge connected">● Connected</span>'
      : '<span class="profile-api-badge missing">○ No Key</span>';
    html += `<div class="profile-api-row">
      <div class="profile-api-left">${badge}<span class="profile-api-name">${escHtml(label)}</span></div>
    </div>`;
  }
  el.innerHTML = html || '<div class="profile-api-loading">No data</div>';
}

// ── Profile selector modal ─────────────────────────────────────
function showProfileSelector() {
  _editingProfileId = null;
  _setModalTitle("SELECT PROFILE");
  _openProfileModal();
  _renderProfileList();
}

function showCreateProfile() {
  _editingProfileId = null;
  _setModalTitle("NEW PROFILE");
  _openProfileModal();
  _renderProfileForm(null);
}

function _setModalTitle(t) {
  const el = document.getElementById("profileModalTitle");
  if (el) el.textContent = t;
}

function _openProfileModal() {
  document.getElementById("profileModal")?.classList.remove("hidden");
}

function closeProfileModal() {
  document.getElementById("profileModal")?.classList.add("hidden");
}

// ── Profile list ───────────────────────────────────────────────
async function _renderProfileList() {
  const body = document.getElementById("profileModalBody");
  if (!body) return;
  body.innerHTML = '<div class="profile-api-loading">Loading profiles&hellip;</div>';
  try {
    const res = await fetch("/api/profiles");
    _allProfiles = await res.json();
  } catch(e) {
    body.innerHTML = '<div class="profile-api-loading" style="color:#f87171">Failed to load profiles</div>';
    return;
  }

  if (!_allProfiles.length) {
    body.innerHTML = `
      <div class="profile-empty-state">
        <div class="profile-empty-icon">&#x1F464;</div>
        <div style="margin-bottom:6px;color:var(--text-2)">No analyst profiles yet</div>
        <div style="color:var(--text-3);font-size:11px;margin-bottom:16px">Create a profile to store your API keys</div>
        <button class="profile-btn-primary" style="padding:9px 24px" onclick="showCreateProfile()">
          &#x2B; Create First Profile
        </button>
      </div>`;
    return;
  }

  let html = '<div class="profile-list">';
  for (const p of _allProfiles) {
    const isActive = p.id === _activeProfileId;
    const keyCount = Object.values(p.has_keys || {}).filter(Boolean).length;
    const total    = Object.keys(p.has_keys || {}).length || 4;
    const initial  = (p.name || "?").slice(0,1).toUpperCase();
    const activeBadge = isActive
      ? '<span class="profile-active-badge">ACTIVE</span>' : "";
    html += `
      <div class="profile-card${isActive ? " selected" : ""}">
        <div class="profile-card-left" onclick="selectProfile('${p.id}','${escHtml(p.name)}')">
          <div class="profile-card-icon">${initial}</div>
          <div class="profile-card-info">
            <div class="profile-card-name">${escHtml(p.name)} ${activeBadge}</div>
            <div class="profile-card-meta">${keyCount}/${total} keys configured</div>
          </div>
        </div>
        <div class="profile-card-actions">
          <button class="profile-card-btn select" onclick="selectProfile('${p.id}','${escHtml(p.name)}')">
            ${isActive ? "✓ Active" : "Use"}
          </button>
          <button class="profile-card-btn edit" onclick="editProfile('${p.id}')">Edit</button>
        </div>
      </div>`;
  }
  html += '</div>';
  html += `
    <div style="margin-top:12px;padding-top:12px;border-top:1px solid rgba(255,255,255,0.06)">
      <button class="profile-btn-primary" style="width:100%;padding:9px" onclick="showCreateProfile()">
        &#x2B; Create New Profile
      </button>
    </div>`;
  body.innerHTML = html;
}

// ── Select profile ─────────────────────────────────────────────
function selectProfile(id, name) {
  _activeProfileId   = id;
  _activeProfileName = name;
  localStorage.setItem("iReconProfileId",   id);
  localStorage.setItem("iReconProfileName", name);
  _refreshProfileBadge();
  document.getElementById("profileModal")?.classList.add("hidden");
  // Refresh panel if open
  if (_profilePanelOpen) _renderProfilePanel();
}

// ── Edit profile ───────────────────────────────────────────────
function editProfile(id) {
  _editingProfileId = id;
  const p = _allProfiles.find(x => x.id === id);
  if (!p) return;
  _setModalTitle("EDIT PROFILE — " + p.name);
  _renderProfileForm(p);
}

// ── Profile form (create + edit) ───────────────────────────────
function _renderProfileForm(profile) {
  const body = document.getElementById("profileModalBody");
  if (!body) return;
  const isEdit = !!profile;
  const name   = profile?.name || "";

  body.innerHTML = `
    <div class="profile-form">
      <div class="profile-form-row">
        <label class="profile-form-label" for="pfName">Profile Name</label>
        <input id="pfName" class="profile-form-input" type="text"
          placeholder="e.g. Analyst-Alpha" value="${escHtml(name)}" autocomplete="off"/>
      </div>

      <div class="profile-form-divider">
        API KEYS
        ${isEdit ? '<span style="font-size:9px;font-weight:400;color:var(--text-3);text-transform:none;letter-spacing:0">Leave blank to keep existing keys</span>' : ""}
      </div>

      ${_keyField("pfVt",      "VirusTotal",     "VT API key",       isEdit)}
      ${_keyField("pfOtx",     "AlienVault OTX", "OTX API key",      isEdit)}
      ${_keyField("pfAbuse",   "AbuseIPDB",      "AbuseIPDB key",    isEdit)}
      ${_keyField("pfUrlscan", "URLScan.io",     "URLScan API key",  isEdit)}

      <div id="pfTestResults" class="profile-test-results" style="display:none"></div>

      <div class="profile-form-btns">
        <button class="profile-form-cancel" onclick="${isEdit ? "_renderProfileList();_setModalTitle('SELECT PROFILE')" : "_renderProfileList();_setModalTitle('SELECT PROFILE')"}">
          ← Back
        </button>
        <button class="profile-form-test" onclick="testFormKeys()" title="Test all keys live">
          ⚡ Test
        </button>
        <button class="profile-form-save" onclick="${isEdit ? "saveEditProfile()" : "saveNewProfile()"}">
          ${isEdit ? "Save Changes" : "Create & Activate"}
        </button>
      </div>
    </div>`;
}

function _keyField(id, label, placeholder, isEdit) {
  const editHint = isEdit ? `placeholder="${placeholder} (leave blank to keep)"` : `placeholder="${placeholder}"`;
  return `<div class="profile-form-row">
    <label class="profile-form-label" for="${id}">${label}</label>
    <div class="profile-form-key-row">
      <input id="${id}" class="profile-form-input" type="password"
        ${editHint} autocomplete="new-password" spellcheck="false"/>
      <button type="button" class="profile-form-eye" onclick="_toggleKeyVis('${id}',this)" title="Show/hide key">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
          <circle cx="12" cy="12" r="3"/>
        </svg>
      </button>
    </div>
  </div>`;
}

function _toggleKeyVis(inputId, btn) {
  const input = document.getElementById(inputId);
  if (!input) return;
  input.type = input.type === "password" ? "text" : "password";
  btn.style.opacity = input.type === "text" ? "1" : "0.45";
}

function _getFormKeys() {
  return {
    virustotal: document.getElementById("pfVt")?.value      || "",
    otx:        document.getElementById("pfOtx")?.value     || "",
    abuseipdb:  document.getElementById("pfAbuse")?.value   || "",
    urlscan:    document.getElementById("pfUrlscan")?.value  || "",
  };
}

// ── Save new profile ───────────────────────────────────────────
async function saveNewProfile() {
  const name = document.getElementById("pfName")?.value?.trim();
  if (!name) { _showFormError("Profile name is required"); return; }
  const keys = _getFormKeys();
  const btn  = document.querySelector(".profile-form-save");
  if (btn) { btn.disabled = true; btn.textContent = "Creating…"; }
  try {
    const res = await fetch("/api/profiles", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({name, keys}),
    });
    const p = await res.json();
    if (!res.ok) { _showFormError(p.detail || "Error creating profile"); return; }
    // Auto-activate new profile
    selectProfile(p.id, p.name);
    await _renderProfileList();
    _setModalTitle("SELECT PROFILE");
  } catch(e) {
    _showFormError("Network error — is the server running?");
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = "Create & Activate"; }
  }
}

// ── Save edit ──────────────────────────────────────────────────
async function saveEditProfile() {
  const id   = _editingProfileId;
  const name = document.getElementById("pfName")?.value?.trim() || undefined;
  const keys = _getFormKeys();
  // Only include keys that were actually filled in (empty = keep existing)
  const changedKeys = Object.fromEntries(Object.entries(keys).filter(([,v]) => v.length > 0));
  const btn  = document.querySelector(".profile-form-save");
  if (btn) { btn.disabled = true; btn.textContent = "Saving…"; }
  try {
    const body = {name};
    if (Object.keys(changedKeys).length) body.keys = changedKeys;
    const res = await fetch(`/api/profiles/${id}`, {
      method: "PATCH",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(body),
    });
    const p = await res.json();
    if (!res.ok) { _showFormError(p.detail || "Error updating profile"); return; }
    // Update active name if this profile is selected
    if (id === _activeProfileId && p.name) {
      _activeProfileName = p.name;
      localStorage.setItem("iReconProfileName", p.name);
      _refreshProfileBadge();
    }
    // Refresh list
    _editingProfileId = null;
    await _renderProfileList();
    _setModalTitle("SELECT PROFILE");
  } catch(e) {
    _showFormError("Network error");
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = "Save Changes"; }
  }
}

// ── Delete ─────────────────────────────────────────────────────
async function deleteProfile(id, name) {
  if (!confirm(`Delete profile "${name}"?\n\nThis cannot be undone.`)) return;
  try {
    const res = await fetch(`/api/profiles/${id}`, {method: "DELETE"});
    if (!res.ok) { alert("Could not delete profile"); return; }
    if (_activeProfileId === id) {
      _activeProfileId   = null;
      _activeProfileName = null;
      localStorage.removeItem("iReconProfileId");
      localStorage.removeItem("iReconProfileName");
      _refreshProfileBadge();
      if (_profilePanelOpen) _renderProfilePanel();
    }
    await _renderProfileList();
  } catch(e) { alert("Network error"); }
}

// ── Key connection test ────────────────────────────────────────
async function testFormKeys() {
  const el = document.getElementById("pfTestResults");
  if (!el) return;
  el.style.display = "flex";
  el.style.flexDirection = "column";
  el.innerHTML = '<div class="profile-api-loading">⚡ Testing API connections&hellip;</div>';
  const keys = _getFormKeys();

  // Need at least one key to test
  const hasAny = Object.values(keys).some(v => v.trim().length > 0);
  if (!hasAny) {
    el.innerHTML = '<div class="profile-api-loading" style="color:#fbbf24">Enter at least one key to test</div>';
    return;
  }

  try {
    const res  = await fetch("/api/profiles/test-keys", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(keys),
    });
    const data = await res.json();
    const LABELS = {
      virustotal: "VirusTotal",
      otx:        "AlienVault OTX",
      abuseipdb:  "AbuseIPDB",
      urlscan:    "URLScan.io",
    };
    let html = "";
    for (const [svc, status] of Object.entries(data)) {
      const cls  = status === "connected" ? "connected"
                 : status === "missing"   ? "missing"
                 : status === "invalid"   ? "invalid" : "error";
      const icon = status === "connected" ? "✓"
                 : status === "missing"   ? "—" : "✗";
      const label = status === "connected" ? "Connected"
                  : status === "missing"   ? "No key"
                  : status === "invalid"   ? "Invalid key" : "Error";
      html += `<div class="profile-test-row">
        <span class="profile-test-svc">${escHtml(LABELS[svc] || svc)}</span>
        <span class="profile-api-badge ${cls}">${icon} ${label}</span>
      </div>`;
    }
    el.innerHTML = html;
  } catch(e) {
    el.innerHTML = '<div style="color:#f87171;font-size:11px">Test request failed</div>';
  }
}

// ── Helpers ────────────────────────────────────────────────────
function _showFormError(msg) {
  // Show error below form
  const existing = document.getElementById("pfFormError");
  if (existing) { existing.textContent = msg; return; }
  const body = document.getElementById("profileModalBody");
  if (!body) return;
  const el = document.createElement("div");
  el.id = "pfFormError";
  el.style.cssText = "color:#f87171;font-size:11px;font-family:var(--font-mono);padding:6px 0;";
  el.textContent = msg;
  body.appendChild(el);
}