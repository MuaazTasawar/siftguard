// SiftGuard — Content Script (content.js)
// Runs in the context of every page.
// Phase 1: skeleton only — scan listener, result reporting.
// Domain risk + visual similarity engines wired in Phase 2 & 3.

(function () {
  "use strict";

  // Guard: don't run twice on same page
  if (window.__siftguardRunning) return;
  window.__siftguardRunning = true;

  // ── Listen for scan trigger from background ─────────────
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type !== "SIFTGUARD_SCAN") return;

    runAnalysis(message.url)
      .then((result) => {
        // Report result back to background
        chrome.runtime.sendMessage({ type: "SIFTGUARD_RESULT", payload: result });
        sendResponse({ ok: true });
      })
      .catch((err) => {
        console.error("[SiftGuard] Analysis error:", err);
        sendResponse({ ok: false, error: err.message });
      });

    return true; // async sendResponse
  });

  // ── Main analysis pipeline ──────────────────────────────
  async function runAnalysis(url) {
    let parsedUrl;
    try {
      parsedUrl = new URL(url);
    } catch {
      return buildResult(null, null, false);
    }

    // Phase 2 will replace these stubs with real engines
    const domainRisk = (typeof scoreDomain === "function")
      ? scoreDomain(parsedUrl)
      : { score: 0, flags: [], label: "unknown" };

    // Phase 3 will replace this stub with real pHash comparison
    const visualMatch = (typeof compareVisual === "function")
      ? await compareVisual(parsedUrl.hostname)
      : { isClone: false, matchedPage: null, similarity: 0 };

    // Determine if we should block
    const shouldBlock = domainRisk.score >= 70 || visualMatch.isClone;

    if (shouldBlock) {
      injectBlockOverlay(domainRisk, visualMatch);
    }

    return buildResult(domainRisk, visualMatch, shouldBlock);
  }

  // ── Result builder ──────────────────────────────────────
  function buildResult(domainRisk, visualMatch, blocked) {
    return {
      domainRisk: domainRisk ?? { score: 0, flags: [], label: "unknown" },
      visualMatch: visualMatch ?? { isClone: false, matchedPage: null, similarity: 0 },
      blocked,
    };
  }

  // ── Overlay injector (full implementation in Phase 4) ───
  function injectBlockOverlay(domainRisk, visualMatch) {
    // Phase 1: just freeze password fields as a placeholder
    // Full overlay UI comes in Phase 4
    const passwords = document.querySelectorAll('input[type="password"]');
    passwords.forEach((input) => {
      input.setAttribute("disabled", "true");
      input.setAttribute("data-siftguard-blocked", "true");
      input.style.outline = "3px solid #CC0000";
    });

    // Add a temporary banner so we can verify the extension works
    const banner = document.createElement("div");
    banner.id = "siftguard-temp-banner";
    banner.textContent = "⛔ SiftGuard: Suspicious page detected. Full overlay coming in Phase 4.";
    banner.style.cssText = `
      position: fixed;
      top: 0; left: 0; right: 0;
      z-index: 2147483647;
      background: #CC0000;
      color: #fff;
      font-family: sans-serif;
      font-size: 14px;
      font-weight: 600;
      text-align: center;
      padding: 10px 16px;
    `;
    document.body.prepend(banner);
  }
})();