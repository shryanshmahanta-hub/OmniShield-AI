# OmniShield AI integration guide

OmniShield deliberately separates rule-based security checks from optional machine-learning inference. A module marked **enabled/configured** is not proof that its model weights are present or that inference succeeded. Every scan response's `ai_analysis` fields report `enabled`, `available`, `prediction`, `confidence`, and `status`. Never treat an unavailable prediction as a benign verdict.

## 1. Install optional model dependencies

From `omnishield-backend/` in your virtual environment:

```bash
pip install -r requirements.txt
pip install -r requirements-ml.txt
```

PyTorch/Transformers are optional for the baseline API. Model weights are not bundled in the ZIP. Review each model card, license, intended task, and label mapping before using it for security decisions.

## 2. Configure a local model

Copy `.env.example` to `.env`. For example, to enable the SMS classifier after placing compatible model files at a local path:

```dotenv
ENABLE_SMS_ML=true
SMS_ML_MODEL=./models/sms
SMS_ML_LABELS=
TEXT_ML_LOCAL_FILES_ONLY=true
```

Use the same pattern for `ENABLE_EMAIL_ML` / `EMAIL_ML_MODEL`, `ENABLE_URL_ML` / `URL_ML_MODEL`, and `ENABLE_PROMPT_ML` / `PROMPT_ML_MODEL`. Local-only mode avoids implicit downloads during a scan. To permit Hugging Face downloads, set `TEXT_ML_LOCAL_FILES_ONLY=false` (and `PROMPT_ML_LOCAL_FILES_ONLY=false` for prompt injection) intentionally, with network egress and model provenance reviewed.

**Label mapping matters:** if a model only reports generic `LABEL_0`/`LABEL_1`, provide a complete, verified comma-separated mapping in the matching `*_ML_LABELS` setting. Never guess which label means malicious. An unknown mapping must remain unavailable rather than produce a verdict.

## 3. External integrations

- `GOOGLE_WEB_RISK_API_KEY` enables URL reputation lookups. Without it, status reports `not_configured`; this is not a clean reputation result.
- `clamscan` must be installed in the backend runtime for ClamAV scanning to execute. `CLAMAV_BINARY` only selects the executable name.
- `MALWARE_INFERENCE_URL` and optional `MALWARE_INFERENCE_TOKEN` configure a separately hosted inference service; the project does not provide that service or its model weights.
- `ROOK_SERVICE_URL` configures the optional Rook enrichment endpoint; verify its deployment, authentication, privacy, and data-sharing behavior before enabling.
- Invoice text classification is not a bank-account ownership check and cannot establish payment legitimacy. Vendor-register and heuristic findings still need human review.

## 4. Verify the runtime

Start the backend and open `/docs`, then call `GET /api/v1/scan/ai-status`. It reports configuration and installed dependency availability without loading models or downloading weights. Run a scan and inspect its `ai_analysis` / `details` for actual per-request inference status. Common statuses include `disabled`, `load_failed`, `label_mapping_unknown`, `inference_failed`, and `success`.

## 5. Deployment guardrails

- Set `AUTH_MODE` to `api_key` or `supabase` for deployments; never expose the development `off` mode.
- Set explicit CORS origins, use HTTPS, restrict outbound network access, and keep secrets only in server-side environment variables.
- Benchmark models and evaluate false positives/negatives on a representative, permissioned dataset before using predictions operationally.
- Treat all predictions as signals for review, not proof that an artifact is safe or malicious. Do not send sensitive content to remote model providers without approval.
