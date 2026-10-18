# DEVIANT — Live Public Footprint Scanner

A beginner-friendly Flask project that fetches real, public GitHub profile and repository metadata through GitHub's REST API, identifies a small set of privacy/exposure review indicators, and displays evidence links and recommendations.

## Scope (important)
- Live source: GitHub REST API.
- Checks public profile fields, public repository names, and public repository descriptions.
- Does not access private repositories, private account data, or other social platforms.
- Keyword findings are review prompts, not proof of exposed secrets, identity, compromise, or wrongdoing.
- Score is a transparent prototype heuristic, not a validated security rating.
- Use for your own account or an account you have permission to assess.

## Setup on Windows / VS Code

Open the project folder in VS Code. Open Terminal and run:

```powershell
python --version
python -m venv venv
.\venv\Scripts\python.exe -m pip install -r requirements.txt
.\venv\Scripts\python.exe app.py
```

If you already have a virtual environment, you can use it instead of creating another one. Then open:

http://127.0.0.1:5000

Try the sample public account `octocat` using the form. The scan uses live data and needs an internet connection. GitHub may rate-limit unauthenticated requests.

## Project structure

- `app.py` — Flask server, GitHub API calls, transparent heuristic findings.
- `templates/index.html` — dashboard layout.
- `static/style.css` — responsive dark cybersecurity design.
- `static/app.js` — calls `/api/scan` and renders results.
- `requirements.txt` — Python dependencies.

## API routes
- `GET /` — dashboard.
- `GET /api/health` — backend status.
- `POST /api/scan` with JSON `{"username":"octocat"}` — live public GitHub scan.

## Mentor demo script
1. Explain that this prototype scans one supported public source (GitHub), not every website or social platform.
2. Enter `octocat` and run the scan.
3. Show the profile, count of public repositories checked, findings, source evidence links, recommendations, and JSON export.
4. Explain that the scanner fetches live API data; findings are rule-based and must be manually verified.
5. Explain limitations and possible future integration with other official APIs where access and terms permit.

## Notes
The API request is made from the Flask backend, so no CORS setup is needed for this single-origin app. No API key is required for basic public GitHub profile/repository endpoints, but unauthenticated rate limits apply.
