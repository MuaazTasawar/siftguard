// SiftGuard — Domain Risk Engine (domainRisk.js)
// Scores a URL's domain for phishing risk entirely client-side.
// Returns: { score: 0–100, flags: string[], label: "safe"|"moderate"|"high" }
//
// Loaded as a content script — no import/export syntax.
// knownPages.json is injected before this file via manifest content_scripts order,
// but since JSON can't be auto-executed, we embed the data reference via
// chrome.runtime.getURL + fetch inside an init call.
// For content script usage the data is hardcoded below to avoid async init
// complexity — knownPages.json is the source of truth for Phase 5 refactor.

const SIFTGUARD_KNOWN = {
  legitimateDomains: [
    "hbl.com", "google.com", "facebook.com", "instagram.com",
    "twitter.com", "x.com", "linkedin.com", "github.com",
    "microsoft.com", "live.com", "outlook.com", "hotmail.com",
    "apple.com", "icloud.com", "amazon.com", "paypal.com",
    "stripe.com", "bankislami.com.pk", "meezanbank.com",
    "ubl.com.pk", "mcb.com.pk", "alfalahbank.com",
    "jazzcash.com.pk", "easypaisa.com.pk", "daraz.pk"
  ],
  knownPhishingPatterns: [
    "hbl-secure", "hbl-login", "hbl-verify",
    "google-verify", "google-login", "facebook-login",
    "paypal-secure", "apple-id-verify", "microsoft-login",
    "account-verify", "secure-login", "banking-secure",
    "update-account", "confirm-identity"
  ],
  suspiciousTLDs: [
    ".tk", ".ml", ".ga", ".cf", ".gq",
    ".xyz", ".top", ".club", ".online",
    ".site", ".info", ".biz", ".pw",
    ".cc", ".ws", ".to"
  ],
  loginPagePaths: [
    "/login", "/signin", "/sign-in",
    "/account/login", "/auth/login",
    "/user/login", "/session/new",
    "/wp-login.php", "/admin/login",
    "/secure/login", "/banking/login"
  ]
};

// ── Public API ────────────────────────────────────────────
// Called from content.js as: scoreDomain(parsedUrl)
function scoreDomain(parsedUrl) {
  const hostname  = parsedUrl.hostname.toLowerCase();
  const pathname  = parsedUrl.pathname.toLowerCase();
  const protocol  = parsedUrl.protocol;

  const flags = [];
  let score   = 0;

  // ── 1. Protocol check ─────────────────────────────────
  if (protocol !== "https:") {
    score += 20;
    flags.push("Page uses HTTP instead of HTTPS — credentials sent unencrypted");
  }

  // ── 2. Legitimate domain whitelist ────────────────────
  // If the apex domain matches exactly → strong trust signal, cap at 5
  const apexDomain = extractApex(hostname);
  if (SIFTGUARD_KNOWN.legitimateDomains.includes(apexDomain)) {
    // Known-good domain: start from 0 and return early if no other signals
    const earlyFlags = [];
    const subScore = checkSubdomainAnomalies(hostname, apexDomain, earlyFlags);
    if (earlyFlags.length === 0 && subScore === 0) {
      return { score: 0, flags: [], label: "safe" };
    }
    // Known domain but suspicious subdomain — still score it
    score += subScore;
    flags.push(...earlyFlags);
    return finalise(Math.min(score, 60), flags); // cap at 60 for known apex
  }

  // ── 3. Typosquatting / brand impersonation ────────────
  const typoResult = checkTyposquatting(hostname);
  if (typoResult.isTypo) {
    score += 40;
    flags.push(`Domain looks like a typosquat of "${typoResult.target}" (edit distance: ${typoResult.distance})`);
  }

  // ── 4. Known phishing keyword patterns ───────────────
  const matchedPattern = SIFTGUARD_KNOWN.knownPhishingPatterns.find(
    (p) => hostname.includes(p)
  );
  if (matchedPattern) {
    score += 30;
    flags.push(`Domain contains known phishing keyword: "${matchedPattern}"`);
  }

  // ── 5. Brand name in subdomain (not apex) ────────────
  const brandInSubdomain = checkBrandInSubdomain(hostname);
  if (brandInSubdomain) {
    score += 25;
    flags.push(`Brand name "${brandInSubdomain}" appears in subdomain — likely impersonation`);
  }

  // ── 6. Suspicious TLD ────────────────────────────────
  const suspiciousTLD = SIFTGUARD_KNOWN.suspiciousTLDs.find(
    (tld) => hostname.endsWith(tld)
  );
  if (suspiciousTLD) {
    score += 20;
    flags.push(`Domain uses suspicious TLD: "${suspiciousTLD}"`);
  }

  // ── 7. Excessive subdomains ──────────────────────────
  const parts = hostname.split(".");
  if (parts.length > 4) {
    score += 15;
    flags.push(`Unusually deep subdomain structure (${parts.length} levels) — common in phishing`);
  }

  // ── 8. Hyphen abuse in domain ────────────────────────
  const hyphenCount = (hostname.match(/-/g) || []).length;
  if (hyphenCount >= 3) {
    score += 15;
    flags.push(`Domain contains ${hyphenCount} hyphens — common phishing pattern`);
  }

  // ── 9. Numeric IP as host ────────────────────────────
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
    score += 35;
    flags.push("Page is served from a raw IP address — legitimate sites use domain names");
  }

  // ── 10. Login path on unknown domain ─────────────────
  const isLoginPath = SIFTGUARD_KNOWN.loginPagePaths.some(
    (p) => pathname.startsWith(p)
  );
  if (isLoginPath && score > 0) {
    score += 10;
    flags.push("Login path detected on a suspicious domain — high credential theft risk");
  }

  // ── 11. Homoglyph characters in domain ───────────────
  const homoglyphResult = checkHomoglyphs(hostname);
  if (homoglyphResult.found) {
    score += 30;
    flags.push(`Homoglyph character detected: "${homoglyphResult.char}" looks like "${homoglyphResult.lookalike}"`);
  }

  return finalise(score, flags);
}

// ── Helpers ───────────────────────────────────────────────

function finalise(score, flags) {
  const clamped = Math.min(Math.max(score, 0), 100);
  let label;
  if (clamped >= 70)      label = "high";
  else if (clamped >= 40) label = "moderate";
  else                    label = "safe";
  return { score: clamped, flags, label };
}

// Extract apex domain (last two parts: example.com, example.com.pk → two or three parts)
function extractApex(hostname) {
  const parts = hostname.split(".");
  // Handle .com.pk, .co.uk, .net.pk style ccSLD
  const ccSLDs = ["com.pk", "co.uk", "net.pk", "org.pk", "gov.pk", "edu.pk", "ac.uk", "co.nz"];
  const joined = parts.slice(-3).join(".");
  if (ccSLDs.some((cc) => joined.endsWith(cc))) {
    return parts.slice(-3).join(".");
  }
  return parts.slice(-2).join(".");
}

// Check for suspicious subdomain patterns on a known-apex domain
function checkSubdomainAnomalies(hostname, apex, flags) {
  let score = 0;
  const subdomain = hostname.slice(0, hostname.length - apex.length - 1);
  if (!subdomain) return 0;

  // e.g. secure-login.hbl.com — suspicious subdomain keyword
  const suspiciousSubKeywords = ["secure", "login", "verify", "update", "account", "banking", "auth"];
  const matchedKw = suspiciousSubKeywords.find((kw) => subdomain.includes(kw));
  if (matchedKw) {
    score += 20;
    flags.push(`Suspicious keyword "${matchedKw}" in subdomain of known domain — may be compromised`);
  }

  // Very long subdomain (>30 chars) is unusual
  if (subdomain.length > 30) {
    score += 10;
    flags.push("Unusually long subdomain — sometimes used to obscure the real domain");
  }

  return score;
}

// Typosquatting: check edit distance against known legitimate domains
function checkTyposquatting(hostname) {
  const apex = extractApex(hostname);

  for (const legit of SIFTGUARD_KNOWN.legitimateDomains) {
    if (apex === legit) continue; // exact match handled above
    const dist = levenshtein(apex, legit);
    // Distance of 1 or 2 on short domains is very suspicious
    const threshold = legit.length <= 8 ? 1 : 2;
    if (dist <= threshold) {
      return { isTypo: true, target: legit, distance: dist };
    }
  }
  return { isTypo: false };
}

// Check if a known brand appears as a subdomain (not the apex)
function checkBrandInSubdomain(hostname) {
  const apex   = extractApex(hostname);
  const brands = SIFTGUARD_KNOWN.legitimateDomains.map((d) => d.split(".")[0]);
  const sub    = hostname.slice(0, hostname.length - apex.length - 1);
  if (!sub) return null;
  return brands.find((b) => sub.includes(b) && b.length > 3) || null;
}

// Detect common homoglyph substitutions
function checkHomoglyphs(hostname) {
  const homoglyphs = [
    { char: "0", lookalike: "o" },
    { char: "1", lookalike: "l" },
    { char: "rn", lookalike: "m" },
    { char: "vv", lookalike: "w" },
    { char: "cl", lookalike: "d" },
    { char: "rnicrosoft", lookalike: "microsoft" },
    { char: "paypa1", lookalike: "paypal" },
    { char: "g00gle", lookalike: "google" },
    { char: "faceb00k", lookalike: "facebook" },
  ];

  for (const { char, lookalike } of homoglyphs) {
    if (hostname.includes(char) && !hostname.includes(lookalike)) {
      return { found: true, char, lookalike };
    }
  }
  return { found: false };
}

// Levenshtein distance (iterative, O(n*m))
function levenshtein(a, b) {
  const m = a.length;
  const n = b.length;
  const dp = Array.from({ length: m + 1 }, (_, i) =>
    Array.from({ length: n + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0))
  );
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      if (a[i - 1] === b[j - 1]) {
        dp[i][j] = dp[i - 1][j - 1];
      } else {
        dp[i][j] = 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
      }
    }
  }
  return dp[m][n];
}