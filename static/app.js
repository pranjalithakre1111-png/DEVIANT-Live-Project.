const form = document.getElementById("scan-form");
const usernameInput = document.getElementById("username");
const scanButton = document.getElementById("scan-button");
const statusBox = document.getElementById("status");
const results = document.getElementById("results");
let latestReport = null;

document.getElementById("example-button").addEventListener("click", () => {
  usernameInput.value = "octocat";
  usernameInput.focus();
});
document.getElementById("new-scan").addEventListener("click", () => {
  results.classList.add("hidden");
  usernameInput.focus();
  window.scrollTo({top: 0, behavior: "smooth"});
});
document.getElementById("download-report").addEventListener("click", () => {
  if (!latestReport) return;
  const blob = new Blob([JSON.stringify(latestReport, null, 2)], {type: "application/json"});
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `deviant-${latestReport.profile.username}-report.json`;
  a.click();
  URL.revokeObjectURL(url);
});

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const username = usernameInput.value.trim();
  if (!username) return;
  scanButton.disabled = true;
  scanButton.textContent = "Scanning…";
  statusBox.className = "status";
  statusBox.textContent = "Contacting GitHub public API and reviewing public profile/repository metadata…";
  results.classList.add("hidden");
  try {
    const response = await fetch("/api/scan", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({username})
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Scan failed.");
    latestReport = data;
    renderReport(data);
    statusBox.className = "status success";
    statusBox.textContent = `Live scan complete for @${data.profile.username}. Source: GitHub REST API.`;
    results.classList.remove("hidden");
    results.scrollIntoView({behavior: "smooth", block: "start"});
  } catch (error) {
    statusBox.className = "status error";
    statusBox.textContent = error.message || "Could not complete scan. Check the backend and internet connection.";
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
  document.getElementById("profile-bio").textContent = p.bio || "No public bio provided.";
  document.getElementById("score").textContent = report.risk_score;
  document.getElementById("level").textContent = report.risk_level + " exposure indicator";
  document.getElementById("score-fill").style.width = report.risk_score + "%";
  document.getElementById("score-fill").style.background = report.risk_score >= 40 ? "var(--red)" : report.risk_score >= 15 ? "var(--amber)" : "var(--cyan)";
  document.getElementById("finding-count").textContent = report.finding_count;
  document.getElementById("repo-count").textContent = report.repositories_checked;
  document.getElementById("scan-time").textContent = "Scan ID " + report.scan_id;
  document.getElementById("source-label").textContent = report.source;
  document.getElementById("score-note").textContent = report.score_note;

  const list = document.getElementById("findings-list");
  list.replaceChildren();
  document.getElementById("empty-findings").classList.toggle("hidden", report.findings.length !== 0);
  for (const f of report.findings) {
    const article = document.createElement("article");
    article.className = "finding";
    const bar = document.createElement("div");
    bar.className = "severity-bar " + f.severity;
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
  for (const item of report.limitations) {
    const li = document.createElement("li");
    li.textContent = item;
    limits.append(li);
  }
}
