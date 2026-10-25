"use strict";

// Firefox exposes `browser`; Chromium browsers expose `chrome`. Both are promise-based in MV3.
const api = typeof browser !== "undefined" ? browser : chrome;

const HOST = "com.privacysentinel.host";
const lastByTab = new Map();           // tabId -> last URL inspected
const liveInFlight = new Map();        // tabId -> promise of a running live check

const HISTORY_LIMIT = 300;
const MERGE_WINDOW_MS = 10 * 60 * 1000; // repeat visits within 10 min are merged

const liveKey = (tabId) => `live_${tabId}`;

const scanKey = (tabId) => `scan_${tabId}`;

function isWebUrl(url) {
  try {
    return ["http:", "https:"].includes(new URL(url).protocol);
  } catch {
    return false;
  }
}

// Scan results contain full URLs (possibly with tokens), so keep them in
// memory-only session storage instead of writing them to disk.
function saveScan(tabId, scan) {
  return api.storage.session.set({ [scanKey(tabId)]: scan });
}

// History keeps only hostname, protocol, risk level, score and time. Paths and
// query strings are never stored, because they can contain private tokens.
let historyQueue = Promise.resolve();

function recordHistory(scan) {
  historyQueue = historyQueue.then(async () => {
    const data = await api.storage.local.get(["settings", "history"]);
    if (data.settings?.historyEnabled === false) return;

    const history = Array.isArray(data.history) ? data.history : [];
    const now = Date.now();
    const top = history[0];

    if (top && top.host === scan.hostname && now - top.ts < MERGE_WINDOW_MS) {
      top.ts = now;
      top.level = scan.level;
      top.score = scan.score;
      top.count = (top.count || 1) + 1;
    } else {
      history.unshift({
        host: scan.hostname,
        scheme: new URL(scan.url).protocol.replace(":", ""),
        level: scan.level,
        score: scan.score,
        ts: now,
        count: 1
      });
    }
    if (history.length > HISTORY_LIMIT) history.length = HISTORY_LIMIT;
    await api.storage.local.set({ history });
  }).catch((e) => console.error("[Privacy Sentinel] History error:", e));
  return historyQueue;
}

async function sendToNativeHost(message) {
  const response = await api.runtime.sendNativeMessage(HOST, message);
  if (!response || response.ok !== true || !response.result) {
    throw new Error(response?.error || "Invalid response from Python host");
  }
  return response.result;
}

function hintFor(message) {
  if (/not found/i.test(message)) {
    return "Run host/install_host.py, then restart the browser.";
  }
  if (/forbidden/i.test(message)) {
    return "The extension ID does not match the host. Re-run install_host.py with the ID from chrome://extensions.";
  }
  if (/exited|disconnected/i.test(message)) {
    return "The Python host crashed on start. Check that the Python path in the launcher still exists.";
  }
  return "Check that the Python host is installed.";
}

function setBadge(tabId, level) {
  const badges = {
    HIGH: ["!", "#ff6577"],
    REVIEW: ["?", "#ffc66d"],
    UNAVAILABLE: ["x", "#9eafc9"]
  };
  const [text, color] = badges[level] || ["", "#51e3c2"];
  Promise.resolve(api.action.setBadgeText({ tabId, text })).catch(() => {});
  if (text) {
    Promise.resolve(api.action.setBadgeBackgroundColor({ tabId, color }))
      .catch(() => {});
  }
}

async function inspectUrl(url, tabId, { force = false } = {}) {
  if (!Number.isInteger(tabId) || !isWebUrl(url)) return null;
  if (!force && lastByTab.get(tabId) === url) return null;

  lastByTab.set(tabId, url);
  const hostname = new URL(url).hostname;
  let scan;

  try {
    const result = await sendToNativeHost({ action: "analyze_url", url });
    const rawScore = result.score ?? result.risk_score;
    const score = rawScore == null ? null : Number(rawScore);
    const level = result.level
      || (score >= 40 ? "HIGH" : score >= 20 ? "REVIEW" : "LOW");

    scan = {
      status: "available",
      url,
      hostname,
      checkedAt: new Date().toISOString(),
      score,
      level,
      summary: result.summary || "Local heuristic analysis completed.",
      findings: Array.isArray(result.findings)
        ? result.findings.slice(0, 12).map(String)
        : [],
      error: ""
    };

    if (level === "HIGH") {
      Promise.resolve(api.notifications.create({
        type: "basic",
        iconUrl: "icons/icon128.png",
        title: "Privacy Sentinel warning",
        message: `Review this website: ${hostname}`
      })).catch((e) => console.error("[Privacy Sentinel] Notification failed:", e));
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error("[Privacy Sentinel] Native messaging failed:", message);

    lastByTab.delete(tabId);               // allow a retry on the next visit
    scan = {
      status: "unavailable",
      url,
      hostname,
      checkedAt: new Date().toISOString(),
      score: null,
      level: "UNAVAILABLE",
      summary: "Could not contact the local Python engine.",
      findings: [message, hintFor(message), "Navigation was not blocked."],
      error: message
    };
  }

  try {
    await saveScan(tabId, scan);
  } catch (storageError) {
    console.error("[Privacy Sentinel] Could not save scan:", storageError);
  }
  setBadge(tabId, scan.level);
  if (scan.status === "available" && scan.level !== "INVALID") {
    await recordHistory(scan);
  }
  return scan;
}

// User-initiated live checks (DNS, TLS certificate, domain registration,
// Safe Browsing). Query strings and fragments are stripped before sending.
function runLiveCheck(tabId, url) {
  if (liveInFlight.has(tabId)) return liveInFlight.get(tabId);
  if (!isWebUrl(url)) return Promise.reject(new Error("Unsupported page."));

  const parsed = new URL(url);
  const target = parsed.origin + parsed.pathname;

  const job = (async () => {
    let details;
    try {
      details = await sendToNativeHost({ action: "live_check", url: target });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      details = {
        status: "error",
        message: `${message} ${hintFor(message)}`,
        hostname: parsed.hostname,
        signals: []
      };
    }
    details.forUrl = url;
    details.checkedAt = new Date().toISOString();
    await api.storage.session.set({ [liveKey(tabId)]: details });
    return details;
  })().finally(() => liveInFlight.delete(tabId));

  liveInFlight.set(tabId, job);
  return job;
}

// Automatic inspection of top-level navigations.
api.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId !== 0) return;
  inspectUrl(details.url, details.tabId);
});

// Messages from our own popup.
api.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (sender.id !== api.runtime.id) return;   // ignore anything foreign

  if (msg?.action === "get_scan") {
    const key = scanKey(msg.tabId);
    api.storage.session
      .get(key)
      .then((data) => sendResponse({ scan: data[key] || null }))
      .catch((e) => sendResponse({ scan: null, error: String(e) }));
    return true;                                  // async response
  }

  if (msg?.action === "live_check") {
    runLiveCheck(msg.tabId, msg.url)
      .then((details) => sendResponse({ ok: true, details }))
      .catch((e) => sendResponse({ ok: false, error: String(e.message || e) }));
    return true;
  }

  if (msg?.action === "get_live") {
    const key = liveKey(msg.tabId);
    api.storage.session.get(key).then((data) => {
      const stored = data[key];
      sendResponse({
        running: liveInFlight.has(msg.tabId),
        details: stored && stored.forUrl === msg.url ? stored : null
      });
    });
    return true;
  }

  if (msg?.action === "get_history") {
    api.storage.local.get(["settings", "history"]).then((data) => {
      sendResponse({
        history: Array.isArray(data.history) ? data.history : [],
        enabled: data.settings?.historyEnabled !== false
      });
    });
    return true;
  }

  if (msg?.action === "clear_history") {
    historyQueue = historyQueue
      .then(() => api.storage.local.remove("history"))
      .then(() => sendResponse({ ok: true }))
      .catch((e) => sendResponse({ ok: false, error: String(e) }));
    return true;
  }

  if (msg?.action === "set_history_enabled") {
    api.storage.local.get("settings").then((data) =>
      api.storage.local.set({
        settings: { ...(data.settings || {}), historyEnabled: !!msg.enabled }
      })
    ).then(() => sendResponse({ ok: true }))
     .catch((e) => sendResponse({ ok: false, error: String(e) }));
    return true;
  }

  if (msg?.action === "rescan") {
    inspectUrl(msg.url, msg.tabId, { force: true })
      .then((scan) => sendResponse({ ok: true, scan }))
      .catch((e) => sendResponse({ ok: false, error: String(e) }));
    return true;                                  // async response
  }
});

api.tabs.onRemoved.addListener((tabId) => {
  lastByTab.delete(tabId);
  api.storage.session
    .remove([scanKey(tabId), liveKey(tabId)])
    .catch(console.error);
});

api.runtime.onInstalled.addListener(() => {
  console.log("[Privacy Sentinel] Extension installed or reloaded.");
});
