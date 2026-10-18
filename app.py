from flask import Flask, render_template, request, jsonify
import requests
import re
import json
from pathlib import Path
from datetime import datetime, timezone

app = Flask(__name__)
GITHUB_API = "https://api.github.com"
HEADERS = {
    "Accept": "application/vnd.github+json",
    "User-Agent": "DEVIANT-Live-Public-Footprint-Scanner"
}
TIMEOUT = 12
HISTORY_FILE = Path(__file__).with_name("scan_history.json")
MAX_HISTORY = 100

def load_history():
    try:
        if HISTORY_FILE.exists():
            data = json.loads(HISTORY_FILE.read_text(encoding="utf-8"))
            return data if isinstance(data, list) else []
    except (OSError, json.JSONDecodeError):
        pass
    return []

def save_history(report):
    history = load_history()
    # Keep only the fields needed for the history list and report preview.
    history.insert(0, {
        "scan_id": report.get("scan_id"),
        "scanned_at": report.get("scanned_at"),
        "username": report.get("profile", {}).get("username"),
        "profile_url": report.get("profile", {}).get("profile_url"),
        "risk_score": report.get("risk_score"),
        "risk_level": report.get("risk_level"),
        "finding_count": report.get("finding_count"),
        "repositories_checked": report.get("repositories_checked"),
        "findings": report.get("findings", []),
        "score_note": report.get("score_note"),
        "limitations": report.get("limitations", []),
        "source": report.get("source"),
        "scan_type": report.get("scan_type")
    })
    HISTORY_FILE.write_text(json.dumps(history[:MAX_HISTORY], indent=2), encoding="utf-8")

def mask_email(value):
    if not value or "@" not in value:
        return value
    name, domain = value.split("@", 1)
    if len(name) <= 2:
        masked = name[:1] + "*"
    else:
        masked = name[:2] + "*" * min(6, len(name) - 2)
    return masked + "@" + domain

def get_json(url):
    response = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
    if response.status_code == 404:
        return None, "not_found"
    if response.status_code == 403 and response.headers.get("X-RateLimit-Remaining") == "0":
        return None, "rate_limit"
    if response.status_code == 403:
        return None, "forbidden"
    response.raise_for_status()
    return response.json(), None

def add_finding(findings, category, title, detail, severity, source_url, recommendation):
    findings.append({
        "category": category,
        "title": title,
        "detail": detail,
        "severity": severity,
        "source_url": source_url,
        "recommendation": recommendation
    })

def analyze_public_github(username):
    profile, error = get_json(f"{GITHUB_API}/users/{username}")
    if error:
        if error == "not_found":
            return None, {"error": "GitHub username not found. Check spelling and try again."}
        if error == "rate_limit":
            return None, {"error": "GitHub's unauthenticated API rate limit has been reached. Wait and try later."}
        return None, {"error": "GitHub did not allow this request. Please try again later."}

    repos, repo_error = get_json(f"{GITHUB_API}/users/{username}/repos?per_page=100&sort=updated")
    if repo_error:
        repos = []
    findings = []
    profile_url = profile.get("html_url", f"https://github.com/{username}")

    bio = profile.get("bio") or ""
    location = profile.get("location") or ""
    blog = profile.get("blog") or ""
    public_email = profile.get("email") or ""

    # These are exposure indicators, not proof of compromise or a person's real-world identity.
    if public_email:
        add_finding(findings, "Contact information", "Public email listed",
                    f"A contact email is visible in the public GitHub API: {mask_email(public_email)}.",
                    "medium", profile_url,
                    "If you do not want strangers to contact you, remove the public email from profile settings.")
    if location:
        add_finding(findings, "Location exposure", "Public location listed",
                    f"The profile includes the location field: “{location}”. This may reveal a city or region.",
                    "low", profile_url,
                    "Use a broad region or leave this field blank if precise location privacy matters.")
    if blog:
        add_finding(findings, "External links", "External website linked",
                    f"The profile links to: {blog}. Review the destination and the information it reveals.",
                    "low", profile_url,
                    "Check that the linked site does not unintentionally expose personal contact details.")
    bio_patterns = [
        (r'\b\d{10}\b', "Phone-like number in bio", "high",
         "A 10-digit number pattern appears in the public bio. It may be a phone number; verify manually."),
        (r'[\w.+-]+@[\w-]+\.[\w.-]+', "Email-like text in bio", "medium",
         "An email-address pattern appears in the public bio. Verify whether it is intended to be public."),
        (r'\b(?:street|road|apartment|flat|house no\.?)\b', "Address-like text in bio", "high",
         "The bio contains words often used in addresses. Review the public text manually.")
    ]
    for pattern, title, severity, detail in bio_patterns:
        if re.search(pattern, bio, re.IGNORECASE):
            add_finding(findings, "Bio content", title, detail, severity, profile_url,
                        "Remove or generalize personal details that you do not want publicly visible.")

    # Inspect public repository names/descriptions only; no private repositories or secret scanning.
    risky_terms = [
        (r'\b(password|passwd|api[_ -]?key|secret|token)\b', "Credential-related wording", "medium"),
        (r'\b(phone|mobile|address|home address)\b', "Personal-information wording", "low"),
        (r'\b(student id|roll no|employee id)\b', "Identifier-related wording", "low")
    ]
    repo_matches = []
    for repo in repos if isinstance(repos, list) else []:
        text = f"{repo.get('name', '')} {repo.get('description') or ''}"
        for pattern, title, severity in risky_terms:
            if re.search(pattern, text, re.IGNORECASE):
                repo_matches.append({
                    "title": title,
                    "repo": repo.get("full_name", repo.get("name", "Public repository")),
                    "url": repo.get("html_url", profile_url),
                    "severity": severity,
                    "description": (repo.get("description") or "No description provided.")[:240]
                })
                break

    for match in repo_matches[:10]:
        add_finding(findings, "Public repository metadata", match["title"],
                    f"Repository “{match['repo']}” has wording worth reviewing: {match['description']}",
                    match["severity"], match["url"],
                    "Review the repository content yourself. This scanner checks names/descriptions only; it does not confirm that a secret exists.")

    # Simple transparent score: a demo indicator based on the number and severity of findings.
    weights = {"low": 5, "medium": 12, "high": 20}
    raw_score = sum(weights.get(f["severity"], 0) for f in findings)
    score = min(100, raw_score)
    if score >= 40:
        level = "Elevated"
    elif score >= 15:
        level = "Moderate"
    else:
        level = "Lower"

    return {
        "scan_id": datetime.now(timezone.utc).strftime("DV-%Y%m%d-%H%M%S"),
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "scan_type": "Live public GitHub profile and repository metadata",
        "source": "GitHub REST API",
        "profile": {
            "username": profile.get("login"),
            "name": profile.get("name"),
            "bio": bio,
            "location": location,
            "company": profile.get("company"),
            "blog": blog,
            "public_email": mask_email(public_email) if public_email else None,
            "followers": profile.get("followers", 0),
            "following": profile.get("following", 0),
            "public_repos": profile.get("public_repos", 0),
            "created_at": profile.get("created_at"),
            "profile_url": profile_url,
            "avatar_url": profile.get("avatar_url")
        },
        "repositories_checked": len(repos) if isinstance(repos, list) else 0,
        "findings": findings,
        "finding_count": len(findings),
        "risk_score": score,
        "risk_level": level,
        "score_note": "Heuristic exposure indicator for this prototype only; not a validated security rating and not evidence of malicious activity.",
        "limitations": [
            "Only public GitHub profile fields and public repository names/descriptions are checked.",
            "Private repositories, private account data, commit contents, and other social platforms are not scanned.",
            "A keyword match is a review prompt, not proof that sensitive data or a security incident exists.",
            "GitHub may rate-limit unauthenticated requests."
        ]
    }, None

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "project": "DEVIANT", "message": "Live public-footprint scanner is ready."})

@app.route("/api/history", methods=["GET"])
def scan_history():
    history = load_history()
    return jsonify({"total_scans": len(history), "scans": history})

@app.route("/api/scan", methods=["POST"])
def scan():
    payload = request.get_json(silent=True) or {}
    username = (payload.get("username") or "").strip()
    if not username:
        return jsonify({"error": "Enter a GitHub username."}), 400
    if not re.fullmatch(r"[A-Za-z0-9-]{1,39}", username) or username.startswith("-") or username.endswith("-") or "--" in username:
        return jsonify({"error": "Enter a valid GitHub username (letters, numbers, and single hyphens only)."}), 400
    try:
        result, error = analyze_public_github(username)
    except requests.Timeout:
        return jsonify({"error": "GitHub request timed out. Please try again."}), 504
    except requests.RequestException:
        return jsonify({"error": "Could not reach GitHub API. Check your internet connection and retry."}), 502
    if error:
        return jsonify(error), 404 if "not found" in error["error"].lower() else 502
    try:
        save_history(result)
    except OSError:
        # A successful live scan should still be returned if history cannot be written.
        app.logger.exception("Could not save scan history")
    return jsonify(result)

if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)
