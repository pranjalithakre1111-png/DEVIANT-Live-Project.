
const form = document.getElementById("scan-form");
const usernameInput = document.getElementById("username");
const scanButton = document.getElementById("scan-button");
const statusBox = document.getElementById("status");
const results = document.getElementById("results");

let latestReport = null;

const HISTORY_KEY = "deviant_scan_history_v1";

function getHistory() {
  try {
    const data = JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]");
    return Array.isArray(data) ? data : [];
  } catch {
    return [];
  }
}

function saveHistory(report) {
  const history = getHistory();

  history.unshift({
    username: report.profile.username,
    scan_id: report.scan_id,
    risk_score: report.risk_score,
    risk_level: report.risk_level,
    finding_count: report.finding_count,
    repositories_checked: report.repositories_checked,
    scanned_at: new Date().toISOString(),
    report
  });

  // Keep the 20 most recent scans.
  localStorage.setItem(HISTORY_KEY, JSON.stringify(history.slice(0, 20)));
  renderHistory();
}

function renderHistory() {
  const list = document.getElementById("history-list");
  if (!list) return;

  const history = getHistory();
  list.replaceChildren();

  if (!history.length) {
    const empty = document.createElement("div");
    empty.className = "empty";
    empty.innerHTML = `
      <div class="empty-icon">◷</div>
      <h3>No scan history yet</h3>
      <p>Complete a scan to see it listed here.</p>
    `;
    list.append(empty);
    return;
  }

  history.forEach((item, index) => {
    const article = document.createElement("article");
    article.className = "finding history-item";

    const bar = document.createElement("div");
    const level = String(item.risk_level || "low").toLowerCase();
    bar.className = "severity-bar " +
      (["low", "medium", "high"].includes(level) ? level : "low");

    const content = document.createElement("div");

    const top = document.createElement("div");
    top.className = "finding-top";

    const title = document.createElement("h3");
    title.textContent = "@" + item.username;

    const badge = document.createElement("span");
    badge.className = "severity";
    badge.textContent = `${item.risk_level} · ${item.risk_score}/100`;

    top.append(title, badge);

    const detail = document.createElement("p");
    const date = new Date(item.scanned_at);
    detail.textContent =
      `${Number(item.finding_count) || 0} findings · ` +
      `${Number(item.repositories_checked) || 0} repositories · ` +
      (Number.isNaN(date.getTime()) ? "Date unavailable" : date.toLocaleString());

    const actions = document.createElement("div");
    actions.className = "report-actions";

    const view = document.createElement("button");
    view.type = "button";
    view.className = "secondary-button";
    view.textContent = "View report";
    view.addEventListener("click", () => {
      latestReport = item.report;
      renderReport(item.report);
      results.classList.remove("hidden");
      results.scrollIntoView({ behavior: "smooth", block: "start" });
    });

    const download = document.createElement("button");
    download.type = "button";
    download.className = "secondary-button";
    download.textContent = "Download JSON";
    download.addEventListener("click", () => downloadReport(item.report));

    actions.append(view, download);
    content.append(top, detail, actions);
    article.append(bar, content);
    list.append(article);
  });
}

function downloadReport(report) {
  if (!report) return;

  const blob = new Blob(
    [JSON.stringify(report, null, 2)],
    { type: "application/json" }
  );

  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `deviant-${report.profile.username}-report.json`;
  a.click();

  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

document.getElementById("example-button").addEventListener("click", () => {
  usernameInput.value = "octocat";
  usernameInput.focus();
});

document.getElementById("new-scan").addEventListener("click", () => {
  results.classList.add("hidden");
  usernameInput.focus();
  window.scrollTo({ top: 0, behavior: "smooth" });
});

document.getElementById("download-report").addEventListener("click", () => {
  downloadReport(latestReport);
});

form.addEventListener("submit", async (event) => {
  event.preventDefault();

  const username = usernameInput.value.trim();
  if (!username) return;

  scanButton.disabled = true;
  scanButton.textContent = "Scanning…";
  statusBox.className = "status";
  statusBox.textContent =
    "Contacting GitHub public API and reviewing public profile/repository metadata…";

  results.classList.add("hidden");

  try {
    const response = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username })
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error || "Scan failed.");
    }

    latestReport = data;
    renderReport(data);
    saveHistory(data);

    statusBox.className = "status success";
    statusBox.textContent =
      `Live scan complete for @${data.profile.username}. Source: GitHub REST API.`;

    results.classList.remove("hidden");
    results.scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (error) {
    statusBox.className = "status error";
    statusBox.textContent =
      error.message || "Could not complete scan. Check the backend and internet connection.";
  } finally {
    scanButton.disabled = false;
    scanButton.innerHTML = 'Run scan <span>↗</span>';
  }
});

function renderReport(report) {
  const p = report.profile;

  document.getElementById("avatar").src = p.avatar_url || "";
  document.getElementById("profile-name").textContent = p.name || p.username;

  const link = document.getElementById("profile-link");
  link.href = p.profile_url;
  link.textContent = "@" + p.username + " ↗";

  document.getElementById("profile-bio").textContent =
    p.bio || "No public bio provided.";

  document.getElementById("score").textContent = report.risk_score;
  document.getElementById("level").textContent =
    report.risk_level + " exposure indicator";

  document.getElementById("score-fill").style.width =
    Math.max(0, Math.min(100, Number(report.risk_score) || 0)) + "%";

  document.getElementById("score-fill").style.background =
    report.risk_score >= 40
      ? "var(--red)"
      : report.risk_score >= 15
        ? "var(--amber)"
        : "var(--cyan)";

  document.getElementById("finding-count").textContent = report.finding_count;
  document.getElementById("repo-count").textContent = report.repositories_checked;
  document.getElementById("scan-time").textContent = "Scan ID " + report.scan_id;
  document.getElementById("source-label").textContent = report.source;
  document.getElementById("score-note").textContent = report.score_note;

  const list = document.getElementById("findings-list");
  list.replaceChildren();

  const findings = Array.isArray(report.findings) ? report.findings : [];
  document.getElementById("empty-findings").classList.toggle(
    "hidden",
    findings.length !== 0
  );

  for (const f of findings) {
    const article = document.createElement("article");
    article.className = "finding";

    const bar = document.createElement("div");
    const severityLevel = String(f.severity || "low").toLowerCase();
    bar.className = "severity-bar " +
      (["low", "medium", "high"].includes(severityLevel)
        ? severityLevel
        : "low");

    const content = document.createElement("div");
    const top = document.createElement("div");
    top.className = "finding-top";

    const title = document.createElement("h3");
    title.textContent = f.title;

    const severity = document.createElement("span");
    severity.className = "severity";
    severity.textContent = f.severity + " · " + f.category;

    top.append(title, severity);

    const detail = document.createElement("p");
    detail.textContent = f.detail;

    const rec = document.createElement("p");
    rec.className = "recommendation";
    rec.textContent = "RECOMMENDATION · " + f.recommendation;

    const source = document.createElement("a");
    source.href = f.source_url;
    source.target = "_blank";
    source.rel = "noopener noreferrer";
    source.textContent = "Open source evidence ↗";

    content.append(top, detail, rec, source);
    article.append(bar, content);
    list.append(article);
  }

  const limits = document.getElementById("limitations");
  limits.replaceChildren();

  for (const item of (Array.isArray(report.limitations) ? report.limitations : [])) {
    const li = document.createElement("li");
    li.textContent = item;
    limits.append(li);
  }
}

renderHistory();
