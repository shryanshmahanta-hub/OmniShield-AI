# OmniShield AI — complete project bundle

This bundle contains the FastAPI backend and a matte-black / white dashboard with a monochrome interactive neural-core homepage with an animated login-to-dashboard transition (see `README-FRONTEND.md`). It is a **working defensive triage/demo foundation**, not a production antivirus or a guarantee that a scan result is safe.

## Start locally

You need Python 3.11+ (the code is tested here on Python 3.13). From a terminal in this folder:

### Windows PowerShell

```powershell
cd omnishield-backend
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
Copy-Item .env.example .env
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

### macOS/Linux

```bash
cd omnishield-backend
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000/` or `http://127.0.0.1:8000/home3d` for the interactive neural-core homepage, `http://127.0.0.1:8000/demo` for the matte-black dashboard, or `http://127.0.0.1:8000/docs` for API documentation. `AUTH_MODE=off` is only intended for local development; it is rejected when `ENVIRONMENT=production`.

## Optional ML/scanners

From `omnishield-backend/`:

```bash
pip install -r requirements-ml.txt
python scripts/download_models.py --tasks sms email url prompt-injection dlp-ner
```

Model weights are **not included** in this ZIP. Inspect each model card and its `config.json` labels, set local model paths in `.env`, and enable only the models whose labels and licensing you verified. Model inference has not been benchmarked against a representative test corpus in this environment. QR image decoding is optional: `pip install -r requirements-qr.txt`. File scanning uses SHA-256 by default and needs a configured ClamAV executable or private inference endpoint to return a scanner verdict.

## Dataset acquisition

See [`omnishield-backend/datasets/README.md`](omnishield-backend/datasets/README.md) and `manifest.json`. Third-party dataset corpora are **not bundled**; use the downloader after reviewing current licenses and provenance. The included `demo_cases.jsonl` contains synthetic examples only and must not be used as evidence of model accuracy.

## What is included

- URL, SMS/chat, email, QR payload/image, prompt-injection, DLP, invoice and file-triage routes.
- Optional local deep-learning integrations with explicit `disabled`, `load_failed`, or other model status instead of invented outputs.
- Optional Google Web Risk lookup, ClamAV and private malware inference integration.
- Shared scan response schema, incident center endpoints, scan audit trail, sanitized logs, owner scoping, authentication hooks, CORS allowlist and per-process rate limiting.
- Basic screenshot-inspired UI with scan forms, results, incidents and audit views.

## Build with Docker

From this folder:

```bash
cp omnishield-backend/.env.example omnishield-backend/.env
docker build -t omnishield-ai .
docker run --rm -p 8000:8000 --env-file omnishield-backend/.env omnishield-ai
```

PowerShell equivalent for the first command: `Copy-Item omnishield-backend/.env.example omnishield-backend/.env`. The `.env` file is for local use; do not commit it. This container does not include model weights or optional scanners.

## Production caveats

Before exposing this to customers, configure Supabase JWT authentication, review organization-scoped access, set real CORS origins, use a managed shared database and distributed rate limiting, set upload/retention limits, and perform independent security/model evaluation. Demo invoice, agent-approval, and block/quarantine actions are simulations; they do not move money, block a browser, alter a mail gateway, or enforce operating-system policy. The API analyzes provided inputs only—it cannot automatically inspect messages on a user's device without a separately installed and permissioned integration.


## Upgraded backend v2 integration

The `omnishield-backend/` directory has been merged from **omnishield-ai-upgraded-backend-v2** into this project, replacing matching backend files and adding v2-only modules without duplicating paths. This includes Chat Guard, Invoice BEC Inspector, Agent Honeypot, session correlation, and their tests. The frontend remains a single-file dashboard at `frontend-demo/index.html`, served at `/demo`.

### Honest data and AI behavior

- Dashboard counts and AI-module status are populated from API responses where available; a security posture score is not invented.
- Example inputs are explicitly synthetic test examples using reserved `.invalid` domains. Use your own test content for real checks.
- A low risk score means configured checks did not find a strong signal; it is not proof that content is safe.
- Optional ML models, QR image decoding, Google Web Risk, and ClamAV require their separately documented dependencies/configuration. Model weights and API keys are not bundled.
- The animated entry screen is a visual workspace gate only, **not authentication**. Configure backend API authentication before exposing the service. Never deploy with `AUTH_MODE=off`.
- The incident store defaults and environment settings are in `omnishield-backend/.env.example`; review them for your deployment. For production, use a persistent/shared store, configure allowed origins and authentication, and put the service behind HTTPS.

See `omnishield-backend/README.md` for all API routes, setup steps, optional integrations, and limitations.


## Install OmniShield AI on your home screen

The dashboard includes a Progressive Web App (PWA) manifest, app icons, an install prompt where supported, and a conservative service worker. Run the backend and open `/demo` in a supported browser. On Android/desktop Chromium, use the **Install app** prompt or browser menu. On iPhone/iPad, open the site in Safari, tap **Share → Add to Home Screen → Add**.

PWA installation requires HTTPS on deployed hosts; `localhost` and `127.0.0.1` are allowed for local development. The service worker only caches the app shell and icons. It deliberately does not cache API responses, authentication responses, or scan submissions. Offline mode is limited to loading the shell; scans still require a reachable backend. The current entry screen is a visual demo gate, not user authentication.


## API 404 troubleshooting (frontend scan failed)

The dashboard sends scanner requests to the backend origin plus these registered paths, for example `POST /api/v1/scan/message` and `POST /api/v1/scan/url`. The backend registers these routes under `/api/v1/scan`; the regression test `tests/test_frontend_route_contract.py` checks that the main dashboard scan, history, AI-status, and PWA paths exist.

1. Start the backend and open the dashboard from **`http://127.0.0.1:8000/demo`** (avoid opening the HTML directly as `file://` when possible).
2. In **Settings → API base URL**, use only the server origin: `http://127.0.0.1:8000`. Do not use `/docs`, `/demo`, or a scanner endpoint. A trailing `/api` or `/api/v1` is normalized by the dashboard, but the origin-only form is recommended.
3. Open `http://127.0.0.1:8000/docs` and confirm `POST /api/v1/scan/message` is listed. A `404` indicates a path/version mismatch; `401` indicates missing/invalid auth; `503` usually means production auth is not configured. The dashboard now includes the HTTP method and complete request URL in scan errors.
4. If hosted frontend and backend use different origins, set `CORS_ALLOWED_ORIGINS` to the exact frontend origin in `.env`, then restart the backend. Do not use `*` for a credentialed production deployment.
5. Run `python -m pytest -q` from `omnishield-backend/` to run the backend and route-contract regression suite.

The original report did not include a browser Network trace, so the historical failing request could not be reproduced exactly from the supplied bundle alone. In this project snapshot the frontend scan paths match registered FastAPI routes; the new diagnostics make any future failing URL/method explicit instead of returning only `Request failed (404)`.

## Feature and demo limitations

- The dashboard uses rule-based local analysis by default. Optional Hugging Face models are disabled unless explicitly configured and weights are available locally; do not present disabled models as active.
- Rook-1/reference inference code must be treated as a development/mock integration unless a separately deployed, genuinely model-backed service is configured.
- QR image decoding requires the optional QR dependency set; payload analysis does not open the URL. A missing threat-intelligence match is not proof that a destination is safe.
- Invoice workflows currently compare structured invoice/vendor/payment fields. This bundle does **not** claim OCR or PDF invoice extraction unless a separately implemented PDF extraction service is added.
- Incident/audit data may use an in-memory store in the default development setup and can reset on restart. Configure the documented persistent store before relying on history.
- Use synthetic content for demonstrations. Do not paste customer secrets or production payment data into a hackathon demo.
