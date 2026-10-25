"use strict";

const api = typeof browser !== "undefined" ? browser : chrome;

const $ = (id) => document.getElementById(id);

const LEVEL_CLASS = {
  HIGH: "high",
  REVIEW: "review",
  LOW: "low",
  INVALID: "unavailable",
  UNAVAILABLE: "unavailable"
};

// All remote data is inserted with textContent only, never innerHTML.
function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}
const li = (text, className) => el("li", className, text);
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const send = (message) => api.runtime.sendMessage(message);

let currentTab = null;

/* ---------------- tabs ---------------- */
document.querySelectorAll(".tab").forEach((button) => {
  button.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((b) => b.classList.toggle("active", b === button));
    const showHistory = button.dataset.tab === "history";
    $("view-current").hidden = showHistory;
    $("view-history").hidden = !showHistory;
    if (showHistory) loadHistory();
  });
});

/* ---------------- current site ---------------- */
async function activeTab() {
  const [tab] = await api.tabs.query({ active: true, currentWindow: true });
  return tab;
}

async function getScan(tabId) {
  const reply = await send({ action: "get_scan", tabId });
  return reply?.scan ?? null;
}

async function rescan(tab) {
  const reply = await send({ action: "rescan", tabId: tab.id, url: tab.url });
  if (!reply?.ok) throw new Error(reply?.error || "Scan failed.");
  return reply.scan;
}

function showUnsupported() {
  $("hostname").textContent = "Unsupported browser page";
  $("url").textContent = "Open an HTTP or HTTPS website.";
  $("level").textContent = "NOT AVAILABLE";
  $("level").className = "unavailable";
  $("score").textContent = "--";
  $("summary").textContent = "Browser internal pages cannot be inspected.";
  $("findings").replaceChildren(li("Nothing to analyze on this page."));
  $("details-btn").disabled = true;
}

function showBusy() {
  $("level").textContent = "Checking…";
  $("level").className = "";
  $("score").textContent = "--";
  $("summary").textContent = "Asking the local Python engine…";
}

function showScan(scan) {
  const list = $("findings");
  list.replaceChildren();

  if (!scan) {
    $("level").textContent = "NO RESULT";
    $("level").className = "unavailable";
    $("score").textContent = "--";
    $("summary").textContent = "No scan result is available for this tab.";
    list.append(li("Press Refresh status to try again."));
    return;
  }

  $("level").textContent = scan.level;
  $("level").className = LEVEL_CLASS[scan.level] || "";
  $("score").textContent = scan.score == null ? "--" : `${scan.score}/100`;
  $("summary").textContent = scan.summary;

  (scan.findings || []).forEach((finding) => list.append(li(finding)));
  if (scan.checkedAt) {
    list.append(li("Checked at " + new Date(scan.checkedAt).toLocaleTimeString()));
  }
}

async function render({ force = false } = {}) {
  const tab = await activeTab();
  currentTab = tab;
  if (!tab?.id || !tab.url || !/^https?:/i.test(tab.url)) {
    showUnsupported();
    return;
  }

  $("hostname").textContent = new URL(tab.url).hostname;
  $("url").textContent = tab.url;
  $("details-btn").disabled = false;

  let scan = force ? null : await getScan(tab.id);
  if (!scan || scan.url !== tab.url) {
    showBusy();
    scan = await rescan(tab);
  }
  showScan(scan);
  await loadLive(tab);
}

async function run(options) {
  const button = $("refresh");
  button.disabled = true;
  try {
    await render(options);
  } catch (error) {
    $("level").textContent = "ERROR";
    $("level").className = "unavailable";
    $("summary").textContent = error.message;
  } finally {
    button.disabled = false;
  }
}

/* ---------------- link details ---------------- */
function fmtDate(value) {
  if (!value) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleDateString();
}

function fmtAge(days) {
  if (days == null) return null;
  if (days < 60) return `${days} day(s)`;
  const years = (days / 365).toFixed(1);
  return `${days} days (~${years} years)`;
}

function section(title, rows) {
  const wrap = el("div", "detail");
  wrap.append(el("h4", null, title));
  rows.forEach(([key, value]) => {
    if (value === null || value === undefined || value === "") return;
    const row = el("div", "kv");
    row.append(el("span", "k", key), el("span", "v", String(value)));
    wrap.append(row);
  });
  return wrap;
}

function renderDetails(d) {
  const body = $("details-body");
  body.replaceChildren();

  if (d.status === "error" || d.status === "blocked" || d.status === "invalid") {
    body.append(el("p", "note warn-text", d.message || "Live checks were not run."));
    return;
  }

  if (d.signals?.length) {
    const list = el("ul", "signals");
    d.signals.forEach((signal) => list.append(li(signal.text, signal.level)));
    body.append(list);
  }

  if (d.rdap) {
    body.append(section("DOMAIN REGISTRATION", [
      ["Registered", fmtDate(d.rdap.registered)],
      ["Domain age", fmtAge(d.rdap.age_days)],
      ["Last changed", fmtDate(d.rdap.last_changed)],
      ["Expires", fmtDate(d.rdap.expires)],
      ["Status", d.rdap.status === "success" ? null : d.rdap.message]
    ]));
  }

  if (d.tls) {
    const days = d.tls.days_left;
    body.append(section("CERTIFICATE (TLS)", [
      ["Issued by", d.tls.issuer],
      ["Issued to", d.tls.subject],
      ["Valid until", d.tls.valid_until],
      ["Days left", days == null ? null : days],
      ["Protocol", d.tls.tls_version],
      ["Status", d.tls.status === "success" ? null : d.tls.message]
    ]));
  }

  if (d.dns) {
    const rows = (d.dns.addresses || []).map((a) =>
      [a.is_global ? "Public IP" : "Non-public IP", a.address]);
    if (!rows.length) rows.push(["Status", d.dns.message]);
    body.append(section("DNS", rows));
  }

  if (d.safe_browsing) {
    body.append(section("SAFE BROWSING", [
      ["Result", d.safe_browsing.message],
      ["Threat types", (d.safe_browsing.threat_types || []).join(", ")]
    ]));
  }

  if (d.checkedAt) {
    body.append(el("p", "note", "Checked at " + new Date(d.checkedAt).toLocaleTimeString()));
  }
}

function setRunning(running) {
  $("details-btn").disabled = running;
  $("details-btn").textContent = running
    ? "Running live checks… (up to ~20 s)"
    : "Re-run details";
}

async function loadLive(tab) {
  const reply = await send({ action: "get_live", tabId: tab.id, url: tab.url });
  if (reply?.running) {
    await waitForLive(tab);
  } else if (reply?.details) {
    renderDetails(reply.details);
    $("details-btn").textContent = "Re-run details";
  }
}

async function waitForLive(tab) {
  setRunning(true);
  for (let i = 0; i < 40; i++) {
    await sleep(1500);
    const reply = await send({ action: "get_live", tabId: tab.id, url: tab.url });
    if (!reply?.running) {
      if (reply?.details) renderDetails(reply.details);
      break;
    }
  }
  setRunning(false);
}

$("details-btn").addEventListener("click", () => {
  $("confirm").hidden = false;
  $("details-btn").hidden = true;
});

$("confirm-cancel").addEventListener("click", () => {
  $("confirm").hidden = true;
  $("details-btn").hidden = false;
});

$("confirm-run").addEventListener("click", async () => {
  $("confirm").hidden = true;
  $("details-btn").hidden = false;
  if (!currentTab?.id) return;

  setRunning(true);
  $("details-body").replaceChildren(el("p", "note", "Contacting DNS, the site and rdap.org…"));
  try {
    const reply = await send({
      action: "live_check",
      tabId: currentTab.id,
      url: currentTab.url
    });
    if (!reply?.ok) throw new Error(reply?.error || "Live check failed.");
    renderDetails(reply.details);
  } catch (error) {
    $("details-body").replaceChildren(el("p", "note warn-text", error.message));
  } finally {
    setRunning(false);
  }
});

/* ---------------- history ---------------- */
let historyCache = [];

function ago(ts) {
  const minutes = Math.round((Date.now() - ts) / 60000);
  if (minutes < 1) return "just now";
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours} h ago`;
  return new Date(ts).toLocaleDateString();
}

function renderHistory() {
  const filter = $("filter").value.trim().toLowerCase();
  const items = historyCache.filter((e) => e.host.toLowerCase().includes(filter));
  const list = $("history-list");
  list.replaceChildren();
  $("history-empty").hidden = items.length > 0;
  $("history-empty").textContent = historyCache.length
    ? "No matches."
    : "No history yet.";

  items.forEach((entry) => {
    const row = el("li");
    const left = el("div");
    left.append(
      el("div", "host", entry.host),
      el("div", "meta",
        `${entry.scheme.toUpperCase()} · ${ago(entry.ts)}` +
        (entry.count > 1 ? ` · ${entry.count} visits` : ""))
    );
    const badge = el(
      "span",
      `badge ${LEVEL_CLASS[entry.level] || ""}`,
      entry.score == null ? entry.level : `${entry.level} ${entry.score}`
    );
    row.append(left, badge);
    list.append(row);
  });
}

async function loadHistory() {
  const reply = await send({ action: "get_history" });
  historyCache = reply?.history || [];
  $("history-enabled").checked = reply?.enabled !== false;
  renderHistory();
}

$("filter").addEventListener("input", renderHistory);

$("history-enabled").addEventListener("change", (event) => {
  send({ action: "set_history_enabled", enabled: event.target.checked });
});

// Two-click confirmation (window.confirm is unreliable inside popups).
let clearArmed = null;
$("clear-history").addEventListener("click", async () => {
  const button = $("clear-history");
  if (!clearArmed) {
    button.textContent = "Click again to delete everything";
    clearArmed = setTimeout(() => {
      clearArmed = null;
      button.textContent = "Clear history";
    }, 4000);
    return;
  }
  clearTimeout(clearArmed);
  clearArmed = null;
  button.textContent = "Clear history";
  await send({ action: "clear_history" });
  await loadHistory();
});

$("refresh").addEventListener("click", () => run({ force: true }));
run();
