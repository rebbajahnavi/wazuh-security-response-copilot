/**
 * SERC — Security Event Response Copilot
 * Vanilla JavaScript Frontend Controller
 * Communicates strictly with FastAPI backend via HTTP fetch()
 */

// State Management
const state = {
  currentAlert: null,
  currentAnalysis: null,
  sampleAlerts: [],
  isAnalyzing: false,
};

// API Base URL (relative or window origin)
const API_BASE = window.location.origin.includes("localhost") || window.location.origin.includes("127.0.0.1")
  ? "" // relative when served by FastAPI
  : "http://127.0.0.1:8000";

// DOM Elements
const elements = {
  backendStatus: document.getElementById("backend-status"),
  corpusCount: document.getElementById("corpus-count"),
  sampleSelect: document.getElementById("sample-select"),
  fileUploadInput: document.getElementById("file-upload-input"),
  btnValidate: document.getElementById("btn-validate"),
  btnAnalyze: document.getElementById("btn-analyze"),
  analyzeSpinner: document.getElementById("analyze-spinner"),
  analyzeBtnText: document.getElementById("analyze-btn-text"),
  alertSummaryBar: document.getElementById("alert-summary-bar"),
  metaRuleId: document.getElementById("meta-rule-id"),
  metaRuleLevel: document.getElementById("meta-rule-level"),
  metaAgentName: document.getElementById("meta-agent-name"),
  metaRuleDesc: document.getElementById("meta-rule-desc"),
  rawJsonEditor: document.getElementById("raw-json-editor"),
  jsonBody: document.getElementById("json-body"),
  toggleJsonBtn: document.getElementById("toggle-json-btn"),
  jsonToggleIcon: document.getElementById("json-toggle-icon"),
  btnCopyJson: document.getElementById("btn-copy-json"),
  jsonValidationMsg: document.getElementById("json-validation-msg"),
  pipelineBanner: document.getElementById("pipeline-status-banner"),
  resultsGrid: document.getElementById("results-grid"),
  simulationPill: document.getElementById("simulation-pill"),
  alertPlainExplanation: document.getElementById("alert-plain-explanation"),
  riskBadge: document.getElementById("risk-badge"),
  riskReason: document.getElementById("risk-reason"),
  observedFactsList: document.getElementById("observed-facts-list"),
  interpretationsList: document.getElementById("interpretations-list"),
  mitreTableBody: document.getElementById("mitre-table-body"),
  investigationStepsList: document.getElementById("investigation-steps-list"),
  responseRecommendationsList: document.getElementById("response-recommendations-list"),
  countTotal: document.getElementById("count-total"),
  countSupported: document.getElementById("count-supported"),
  countPartial: document.getElementById("count-partial"),
  countConflicting: document.getElementById("count-conflicting"),
  countInsufficient: document.getElementById("count-insufficient"),
  countReview: document.getElementById("count-review"),
  claimsContainer: document.getElementById("claims-container"),
  evidenceCountBadge: document.getElementById("evidence-count-badge"),
  evidenceContainer: document.getElementById("evidence-container"),
  feedbackHistoryList: document.getElementById("feedback-history-list"),
  toastContainer: document.getElementById("toast-container"),
};

// Initialize Application
document.addEventListener("DOMContentLoaded", () => {
  initHealthCheck();
  loadSampleAlerts();
  setupEventListeners();
});

// Event Listeners
function setupEventListeners() {
  // Dropdown selection
  elements.sampleSelect.addEventListener("change", (e) => {
    const alertId = e.target.value;
    if (alertId) loadAlertById(alertId);
  });

  // File Upload
  elements.fileUploadInput.addEventListener("change", handleFileUpload);

  // Validate Button
  elements.btnValidate.addEventListener("click", validateCurrentJson);

  // Analyze Button
  elements.btnAnalyze.addEventListener("click", executeAnalysis);

  // Toggle JSON visibility
  elements.toggleJsonBtn.addEventListener("click", () => {
    const isHidden = elements.jsonBody.style.display === "none";
    elements.jsonBody.style.display = isHidden ? "block" : "none";
    elements.jsonToggleIcon.textContent = isHidden ? "▼" : "▶";
  });

  // Copy JSON
  elements.btnCopyJson.addEventListener("click", () => {
    if (elements.rawJsonEditor.value) {
      navigator.clipboard.writeText(elements.rawJsonEditor.value);
      showToast("Alert JSON copied to clipboard", "success");
    }
  });

  // Raw JSON manual edits
  elements.rawJsonEditor.addEventListener("input", () => {
    try {
      const parsed = JSON.parse(elements.rawJsonEditor.value);
      state.currentAlert = parsed;
      updateSummaryBar(parsed);
      elements.btnAnalyze.disabled = false;
    } catch {
      // invalid JSON during typing, keep button state intact
    }
  });
}

// Health Check
async function initHealthCheck() {
  try {
    const res = await fetch(`${API_BASE}/api/health`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();

    elements.backendStatus.className = "status-indicator online";
    elements.backendStatus.querySelector(".status-text").textContent = "Backend Connected";
    elements.corpusCount.textContent = `${data.qdrant_vectors || 0} vectors`;

    if (data.mock_mode) {
      elements.simulationPill.style.display = "inline-block";
      elements.simulationPill.textContent = "Offline Simulation Mode";
    }
  } catch (err) {
    elements.backendStatus.className = "status-indicator offline";
    elements.backendStatus.querySelector(".status-text").textContent = "Backend Offline";
    showToast("Backend connection failed. Is the server running on port 8000?", "error");
  }
}

// Load Sample Alert Dropdown
async function loadSampleAlerts() {
  try {
    const res = await fetch(`${API_BASE}/api/alerts/samples`);
    if (!res.ok) throw new Error(`Failed to load samples: ${res.status}`);
    const samples = await res.json();
    state.sampleAlerts = samples;

    elements.sampleSelect.innerHTML = '<option value="" disabled selected>-- Select from 50+ Synthetic Wazuh Alerts --</option>';

    samples.forEach((s) => {
      const opt = document.createElement("option");
      opt.value = s.id;
      opt.textContent = `[Rule ${s.rule_id} | Lvl ${s.rule_level}] ${s.rule_description} (${s.agent_name})`;
      elements.sampleSelect.appendChild(opt);
    });

    // Auto-select first sample for immediate analyst exploration
    if (samples.length > 0) {
      elements.sampleSelect.value = samples[0].id;
      loadAlertById(samples[0].id);
    }
  } catch (err) {
    showToast(`Error loading sample alerts: ${err.message}`, "error");
  }
}

// Load Full Alert by ID
async function loadAlertById(alertId) {
  try {
    const res = await fetch(`${API_BASE}/api/alerts/samples/${alertId}`);
    if (!res.ok) throw new Error("Alert not found");
    const alert = await res.json();

    state.currentAlert = alert;
    elements.rawJsonEditor.value = JSON.stringify(alert, null, 2);
    updateSummaryBar(alert);
    elements.btnAnalyze.disabled = false;
    elements.jsonValidationMsg.style.display = "none";
  } catch (err) {
    showToast(`Failed to load alert: ${err.message}`, "error");
  }
}

// Update Top Metadata Summary
function updateSummaryBar(alert) {
  const rule = alert.rule || {};
  const agent = alert.agent || {};

  elements.metaRuleId.textContent = rule.id || "N/A";
  elements.metaRuleLevel.textContent = `Level ${rule.level ?? "--"}`;
  elements.metaAgentName.textContent = `${agent.name || "Unknown"} (${agent.ip || ""})`;
  elements.metaRuleDesc.textContent = rule.description || "No description provided";

  elements.alertSummaryBar.style.display = "flex";
}

// Handle JSON File Upload
function handleFileUpload(e) {
  const file = e.target.files[0];
  if (!file) return;

  const reader = new FileReader();
  reader.onload = (event) => {
    try {
      const parsed = JSON.parse(event.target.result);
      state.currentAlert = parsed;
      elements.rawJsonEditor.value = JSON.stringify(parsed, null, 2);
      updateSummaryBar(parsed);
      elements.btnAnalyze.disabled = false;
      showToast(`Loaded file: ${file.name}`, "success");
      validateCurrentJson();
    } catch (err) {
      showToast(`Invalid JSON file: ${err.message}`, "error");
    }
  };
  reader.readAsText(file);
}

// Validate JSON syntax & Wazuh schema
async function validateCurrentJson() {
  const raw = elements.rawJsonEditor.value.trim();
  if (!raw) {
    showValidationResult(false, ["Please paste or select alert JSON first."]);
    return;
  }

  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    showValidationResult(false, [`JSON Syntax Error: ${err.message}`]);
    return;
  }

  try {
    const res = await fetch(`${API_BASE}/api/alerts/validate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(parsed)
    });
    const result = await res.json();
    if (result.valid) {
      showValidationResult(true, ["Valid Wazuh alert schema verified."]);
    } else {
      showValidationResult(false, result.errors || ["Schema mismatch."]);
    }
  } catch (err) {
    showValidationResult(false, [`Backend validation check failed: ${err.message}`]);
  }
}

function showValidationResult(valid, messages) {
  elements.jsonValidationMsg.className = `validation-feedback ${valid ? "success" : "error"}`;
  elements.jsonValidationMsg.innerHTML = messages.map(m => `<div>${escapeHtml(m)}</div>`).join("");
  elements.jsonValidationMsg.style.display = "block";
}

// Execute Complete RAG Pipeline
async function executeAnalysis() {
  if (state.isAnalyzing) return;

  const raw = elements.rawJsonEditor.value.trim();
  if (!raw) {
    showToast("No alert JSON available to analyze.", "error");
    return;
  }

  let alertPayload;
  try {
    alertPayload = JSON.parse(raw);
  } catch (err) {
    showToast("Cannot analyze: Malformed JSON in editor.", "error");
    return;
  }

  // Set loading state
  state.isAnalyzing = true;
  elements.btnAnalyze.disabled = true;
  elements.analyzeSpinner.style.display = "inline-block";
  elements.analyzeBtnText.textContent = "Analyzing...";
  elements.pipelineBanner.style.display = "flex";
  elements.resultsGrid.style.display = "none";

  try {
    const res = await fetch(`${API_BASE}/api/alerts/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ alert: alertPayload, top_k: 5 })
    });

    if (!res.ok) {
      const errData = await res.json().catch(() => ({}));
      throw new Error(errData.detail?.message || errData.detail || `Server error (${res.status})`);
    }

    const data = await res.json();
    state.currentAnalysis = data;

    renderAnalysisResults(data);
    renderValidationResults(data.validation);
    renderRetrievedEvidence(data.retrieved_evidence);
    loadFeedbackHistory(data.alert_id);

    elements.resultsGrid.style.display = "grid";
    showToast(`Analysis completed in ${data.elapsed_ms}ms`, "success");
  } catch (err) {
    showToast(`Analysis failed: ${err.message}`, "error");
  } finally {
    state.isAnalyzing = false;
    elements.btnAnalyze.disabled = false;
    elements.analyzeSpinner.style.display = "none";
    elements.analyzeBtnText.textContent = "Analyze Alert";
    elements.pipelineBanner.style.display = "none";
  }
}

// Render Area B: Analysis Results
function renderAnalysisResults(data) {
  const analysis = data.analysis || {};
  const pixtral = data.pixtral_interpretation || {};

  // Plain-Language Interpretation
  elements.alertPlainExplanation.textContent =
    analysis.alert_summary || pixtral.summary || "No explanation provided.";

  // Risk Assessment
  const risk = analysis.risk_assessment || { level: "Medium", reason: "" };
  elements.riskBadge.textContent = risk.level || "Medium";
  elements.riskBadge.className = `risk-badge ${(risk.level || "medium").toLowerCase()}`;
  elements.riskReason.textContent = risk.reason || "";

  // Observed Facts
  elements.observedFactsList.innerHTML = (analysis.observed_facts || [])
    .map(fact => `<li>${escapeHtml(fact)}</li>`)
    .join("") || "<li>No observable facts extracted.</li>";

  // Interpretations
  elements.interpretationsList.innerHTML = (analysis.possible_interpretations || [])
    .map(interp => `<li>${escapeHtml(interp)}</li>`)
    .join("") || "<li>No alternative interpretations generated.</li>";

  // MITRE ATT&CK Mappings Table
  const mappings = analysis.mitre_mappings || [];
  if (mappings.length === 0) {
    elements.mitreTableBody.innerHTML = '<tr><td colspan="4" class="empty-cell">No MITRE ATT&CK mappings identified.</td></tr>';
  } else {
    elements.mitreTableBody.innerHTML = mappings.map(m => `
      <tr>
        <td><strong>${escapeHtml(m.technique_id || "N/A")}</strong></td>
        <td>${escapeHtml(m.technique_name || "Unknown")}</td>
        <td>${escapeHtml(m.tactic || "General")}</td>
        <td><span class="badge-pill">${escapeHtml(m.source || "inferred")}</span></td>
      </tr>
    `).join("");
  }

  // Recommended Investigation Steps
  elements.investigationStepsList.innerHTML = (analysis.recommended_investigation_steps || [])
    .map(step => `<li>${escapeHtml(step)}</li>`)
    .join("") || "<li>No investigation steps defined.</li>";

  // Response Recommendations
  elements.responseRecommendationsList.innerHTML = (analysis.response_recommendations || [])
    .map(rec => `<li>${escapeHtml(rec)}</li>`)
    .join("") || "<li>No response actions suggested.</li>";

  // Simulation Mode Pill
  if (data.pipeline_metadata?.is_mock) {
    elements.simulationPill.style.display = "inline-block";
    elements.simulationPill.textContent = "Offline Simulation Mode";
  } else {
    elements.simulationPill.style.display = "none";
  }
}

// Render Area C: Evidence-Backed Validator
function renderValidationResults(val) {
  if (!val) return;

  const summary = val.summary || {};
  elements.countTotal.textContent = val.total_claims || 0;
  elements.countSupported.textContent = summary["Supported"] || 0;
  elements.countPartial.textContent = summary["Partially supported"] || 0;
  elements.countConflicting.textContent = summary["Conflicting evidence"] || 0;
  elements.countInsufficient.textContent = summary["Insufficient evidence"] || 0;
  elements.countReview.textContent = summary["Requires review"] || 0;

  const claims = val.claims || [];
  if (claims.length === 0) {
    elements.claimsContainer.innerHTML = '<p class="empty-state">No claims evaluated.</p>';
    return;
  }

  elements.claimsContainer.innerHTML = claims.map(c => {
    const statusClass = getStatusClass(c.status);
    const pillClass = getPillClass(c.status);

    return `
      <div class="claim-card ${statusClass}" id="card-${c.claim_id}">
        <div class="claim-header">
          <span class="claim-id">${escapeHtml(c.claim_id)} • ${escapeHtml(c.claim_type || "Claim")}</span>
          <span class="claim-status-pill ${pillClass}">${escapeHtml(c.status)}</span>
        </div>
        <div class="claim-text">${escapeHtml(c.claim_text)}</div>
        <div class="claim-details">
          <div class="detail-row">
            <span class="k">Evaluation:</span>
            <span class="v">${escapeHtml(c.reason || "")}</span>
          </div>
          <div class="detail-row">
            <span class="k">Source:</span>
            <span class="v">${escapeHtml(c.evidence_source || "Unverified")}</span>
          </div>
          ${c.missing_evidence ? `
            <div class="detail-row missing">
              <span class="k">Missing:</span>
              <span class="v">${escapeHtml(c.missing_evidence)}</span>
            </div>
          ` : ""}
          <div class="detail-row">
            <span class="k">Next Step:</span>
            <span class="v">${escapeHtml(c.suggested_next_verification_step || "Analyst review")}</span>
          </div>
        </div>

        <div class="claim-actions">
          <span class="sub-hint">Analyst Feedback:</span>
          <div class="feedback-buttons">
            <button class="btn-feedback accept" onclick="submitClaimFeedback('${c.claim_id}', 'accepted')">✓ Accept</button>
            <button class="btn-feedback reject" onclick="submitClaimFeedback('${c.claim_id}', 'rejected')">✗ Reject</button>
            <button class="btn-feedback review" onclick="submitClaimFeedback('${c.claim_id}', 'needs_review')">? Review</button>
          </div>
        </div>
      </div>
    `;
  }).join("");
}

// Render Retrieved Evidence Cards
function renderRetrievedEvidence(evidenceList) {
  const ev = evidenceList || [];
  elements.evidenceCountBadge.textContent = `${ev.length} Records`;

  if (ev.length === 0) {
    elements.evidenceContainer.innerHTML = '<p class="empty-state">No matching cybersecurity dataset records retrieved.</p>';
    return;
  }

  elements.evidenceContainer.innerHTML = ev.map(item => `
    <div class="evidence-card">
      <div class="evidence-header">
        <span class="evidence-title">
          <span>${escapeHtml(item.incident_id || "Corpus Record")}</span>
          <span class="sim-score">Similarity: ${item.similarity_score ?? 0.0}</span>
        </span>
        <span class="badge-pill">${escapeHtml(item.attack_type || "Incident Pattern")}</span>
      </div>
      <div class="evidence-meta">
        ${item.mitre_technique_id ? `<span>MITRE: <strong>${escapeHtml(item.mitre_technique_id)}</strong> (${escapeHtml(item.mitre_technique_name || "")})</span>` : ""}
        ${item.nist_category ? `<span>NIST: <strong>${escapeHtml(item.nist_category)}</strong></span>` : ""}
        ${item.source_reference ? `<span>Ref: ${escapeHtml(item.source_reference)}</span>` : ""}
      </div>
      <div class="evidence-snippet">${escapeHtml(item.snippet || "No text available.")}</div>
    </div>
  `).join("");
}

// Submit Analyst Feedback for an Individual Claim
async function submitClaimFeedback(claimId, decision) {
  if (!state.currentAnalysis) return;

  const alertId = state.currentAnalysis.alert_id;
  const claim = (state.currentAnalysis.validation?.claims || []).find(c => c.claim_id === claimId);
  const claimText = claim ? claim.claim_text : "";

  try {
    const res = await fetch(`${API_BASE}/api/feedback`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        alert_id: alertId,
        claim_id: claimId,
        claim_text: claimText,
        decision: decision,
        notes: `Recorded from analyst dashboard (${decision})`
      })
    });

    if (!res.ok) throw new Error("Failed to save feedback");

    showToast(`Claim ${claimId} marked as ${decision}`, "success");
    loadFeedbackHistory(alertId);

    // Update active button state
    const card = document.getElementById(`card-${claimId}`);
    if (card) {
      card.querySelectorAll(".btn-feedback").forEach(b => b.classList.remove("active"));
      const targetBtn = card.querySelector(`.btn-feedback.${decision === 'needs_review' ? 'review' : decision}`);
      if (targetBtn) targetBtn.classList.add("active");
    }
  } catch (err) {
    showToast(`Error submitting feedback: ${err.message}`, "error");
  }
}

// Load Feedback History for current alert
async function loadFeedbackHistory(alertId) {
  try {
    const res = await fetch(`${API_BASE}/api/feedback/${alertId}`);
    if (!res.ok) return;
    const history = await res.json();

    if (history.length === 0) {
      elements.feedbackHistoryList.innerHTML = '<p class="empty-state">No analyst decisions recorded yet for this alert.</p>';
      return;
    }

    elements.feedbackHistoryList.innerHTML = history.map(h => `
      <div class="feedback-entry">
        <div>
          <strong>${escapeHtml(h.claim_id || "Alert Review")}:</strong>
          <span>Decision: <em>${escapeHtml(h.analyst_decision)}</em></span>
          ${h.analyst_notes ? `<span class="sub-hint">(${escapeHtml(h.analyst_notes)})</span>` : ""}
        </div>
        <span class="sub-hint">${escapeHtml(h.timestamp || "")}</span>
      </div>
    `).join("");
  } catch (err) {
    console.warn("Feedback history load error:", err);
  }
}

// CSS Helper Classes
function getStatusClass(status) {
  switch (status) {
    case "Supported": return "status-supported";
    case "Partially supported": return "status-partially";
    case "Conflicting evidence": return "status-conflicting";
    case "Insufficient evidence": return "status-insufficient";
    case "Requires review": return "status-review";
    default: return "";
  }
}

function getPillClass(status) {
  switch (status) {
    case "Supported": return "status-pill-supported";
    case "Partially supported": return "status-pill-partially";
    case "Conflicting evidence": return "status-pill-conflicting";
    case "Insufficient evidence": return "status-pill-insufficient";
    case "Requires review": return "status-pill-review";
    default: return "";
  }
}

// Toast Notifications
function showToast(message, type = "info") {
  const toast = document.createElement("div");
  toast.className = `toast ${type}`;
  toast.textContent = message;

  elements.toastContainer.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = "0";
    setTimeout(() => toast.remove(), 200);
  }, 3500);
}

// Utility: HTML Escape
function escapeHtml(str) {
  if (typeof str !== "string") return String(str ?? "");
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
