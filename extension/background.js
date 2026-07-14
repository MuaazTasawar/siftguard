// SiftGuard — Service Worker (background.js)
// Listens for tab navigation events and triggers analysis
// via message passing to the content script.

const SIFTGUARD_VERSION = "1.0.0";

// ── State: per-tab analysis results ──────────────────────
const tabResults = {};

// ── On navigation committed (URL has changed, page loading) ──
chrome.webNavigation.onCommitted.addListener((details) => {
  // Only act on top-level frame navigation (not iframes)
  if (details.frameId !== 0) return;

  // Skip browser internal pages
  const url = details.url;
  if (
    url.startsWith("chrome://") ||
    url.startsWith("chrome-extension://") ||
    url.startsWith("about:") ||
    url.startsWith("edge://") ||
    url === "about:blank"
  ) return;

  // Clear previous result for this tab
  tabResults[details.tabId] = {
    url,
    status: "scanning",
    domainRisk: null,
    visualMatch: null,
    blocked: false,
    timestamp: Date.now(),
  };

  // Update popup badge to show scanning state
  chrome.action.setBadgeText({ text: "...", tabId: details.tabId });
  chrome.action.setBadgeBackgroundColor({ color: "#888888", tabId: details.tabId });

  // Send scan trigger to content script
  // Content script may not be ready immediately; retry with a small delay
  setTimeout(() => {
    chrome.tabs.sendMessage(details.tabId, { type: "SIFTGUARD_SCAN", url }, (response) => {
      if (chrome.runtime.lastError) {
        // Content script not yet injected (e.g. extension just installed) — ignore
        return;
      }
    });
  }, 600);
});

// ── On tab removed: clean up state ───────────────────────
chrome.tabs.onRemoved.addListener((tabId) => {
  delete tabResults[tabId];
});

// ── Message handler: receives results from content script ─
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!sender.tab) return;

  const tabId = sender.tab.id;

  if (message.type === "SIFTGUARD_RESULT") {
    const { domainRisk, visualMatch, blocked } = message.payload;

    tabResults[tabId] = {
      ...tabResults[tabId],
      status: "done",
      domainRisk,
      visualMatch,
      blocked,
      timestamp: Date.now(),
    };

    updateBadge(tabId, domainRisk, visualMatch, blocked);
    sendResponse({ ok: true });
  }

  if (message.type === "SIFTGUARD_GET_RESULT") {
    sendResponse(tabResults[tabId] || null);
  }

  return true; // Keep message channel open for async sendResponse
});

// ── Badge updater ─────────────────────────────────────────
function updateBadge(tabId, domainRisk, visualMatch, blocked) {
  if (blocked) {
    chrome.action.setBadgeText({ text: "⛔", tabId });
    chrome.action.setBadgeBackgroundColor({ color: "#CC0000", tabId });
    return;
  }

  const score = domainRisk?.score ?? 0;

  if (score >= 70 || visualMatch?.isClone) {
    chrome.action.setBadgeText({ text: "HIGH", tabId });
    chrome.action.setBadgeBackgroundColor({ color: "#CC0000", tabId });
  } else if (score >= 40) {
    chrome.action.setBadgeText({ text: "MED", tabId });
    chrome.action.setBadgeBackgroundColor({ color: "#E67E00", tabId });
  } else {
    chrome.action.setBadgeText({ text: "OK", tabId });
    chrome.action.setBadgeBackgroundColor({ color: "#1a7a3f", tabId });
  }
}