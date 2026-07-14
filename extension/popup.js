// SiftGuard — Popup script

document.addEventListener("DOMContentLoaded", () => {
  const elStatusCard  = document.getElementById("sg-status-card");
  const elStatusIcon  = document.getElementById("sg-status-icon");
  const elStatusLabel = document.getElementById("sg-status-label");
  const elDomain      = document.getElementById("sg-domain");
  const elDomainScore = document.getElementById("sg-domain-score");
  const elVisualScore = document.getElementById("sg-visual-score");
  const elBlocked     = document.getElementById("sg-blocked");
  const elFlagsSection = document.getElementById("sg-flags-section");
  const elFlagsList   = document.getElementById("sg-flags-list");

  // Query the active tab, then ask background for the cached result
  chrome.tabs.query({ active: true, currentWindow: true }, ([tab]) => {
    if (!tab) return renderUnknown();

    // Show domain immediately
    try {
      const hostname = new URL(tab.url).hostname;
      elDomain.textContent = hostname || tab.url;
    } catch {
      elDomain.textContent = tab.url || "unknown";
    }

    // Skip internal pages
    if (
      tab.url.startsWith("chrome://") ||
      tab.url.startsWith("chrome-extension://") ||
      tab.url.startsWith("about:")
    ) {
      return renderInternal();
    }

    // Request cached result from background
    chrome.runtime.sendMessage({ type: "SIFTGUARD_GET_RESULT" }, (result) => {
      if (chrome.runtime.lastError || !result) {
        return renderScanning();
      }
      if (result.status === "scanning") {
        return renderScanning();
      }
      renderResult(result);
    });
  });

  // ── Render states ───────────────────────────────────────

  function renderScanning() {
    setStatus("scanning", "⏳", "Scanning page…");
  }

  function renderUnknown() {
    setStatus("unknown", "❓", "No data yet");
    elDomainScore.textContent = "—";
    elVisualScore.textContent = "—";
    elBlocked.textContent = "—";
  }

  function renderInternal() {
    setStatus("safe", "🛡️", "Browser page — not analysed");
    elDomain.textContent = "Internal page";
    elDomainScore.textContent = "N/A";
    elVisualScore.textContent = "N/A";
    elBlocked.textContent = "No";
  }

  function renderResult(result) {
    const { domainRisk, visualMatch, blocked } = result;

    // Status card
    if (blocked) {
      setStatus("danger", "⛔", "Credential entry blocked");
    } else if ((domainRisk?.score ?? 0) >= 70 || visualMatch?.isClone) {
      setStatus("danger", "🚨", "High risk — do not enter credentials");
    } else if ((domainRisk?.score ?? 0) >= 40) {
      setStatus("warn", "⚠️", "Moderate risk detected");
    } else {
      setStatus("safe", "✅", "Page appears safe");
    }

    // Domain risk score
    const score = domainRisk?.score ?? 0;
    elDomainScore.textContent = `${score}/100`;
    elDomainScore.className = "sg-score " + riskClass(score);

    // Visual clone
    if (visualMatch?.isClone) {
      elVisualScore.textContent = `Clone of ${visualMatch.matchedPage} (${visualMatch.similarity}% match)`;
      elVisualScore.className = "sg-score sg-danger";
    } else if (visualMatch?.similarity > 0) {
      elVisualScore.textContent = `${visualMatch.similarity}% similarity (safe threshold)`;
      elVisualScore.className = "sg-score sg-ok";
    } else {
      elVisualScore.textContent = "No match";
      elVisualScore.className = "sg-score sg-ok";
    }

    // Blocked
    elBlocked.textContent = blocked ? "Yes" : "No";
    elBlocked.className = "sg-score " + (blocked ? "sg-danger" : "sg-ok");

    // Flags
    const flags = domainRisk?.flags ?? [];
    if (flags.length > 0) {
      elFlagsSection.style.display = "block";
      elFlagsList.innerHTML = "";
      flags.forEach((flag) => {
        const li = document.createElement("li");
        li.textContent = flag;
        elFlagsList.appendChild(li);
      });
    }
  }

  // ── Helpers ─────────────────────────────────────────────

  function setStatus(type, icon, label) {
    elStatusCard.className = "sg-status-card sg-status-" + type;
    elStatusIcon.textContent = icon;
    elStatusLabel.textContent = label;
  }

  function riskClass(score) {
    if (score >= 70) return "sg-danger";
    if (score >= 40) return "sg-warn";
    return "sg-ok";
  }
});