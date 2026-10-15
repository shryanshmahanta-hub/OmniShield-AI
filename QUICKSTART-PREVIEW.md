# OmniShield AI — quick local preview (Windows)

## Fastest option
1. Extract the entire project ZIP to a normal folder (not inside the ZIP viewer).
2. Install Python 3.11 or newer if needed: https://www.python.org/downloads/windows/ . Enable **Add Python to PATH** during installation.
3. Double-click `START-OMNISHIELD-WINDOWS.bat` and allow the first dependency installation to finish. It may take a few minutes and requires internet access.
4. Your browser should open `http://127.0.0.1:8000/demo`. API documentation is at `http://127.0.0.1:8000/docs`.
5. Keep the terminal window titled **OmniShield AI Backend** open while testing. Press Ctrl+C in that window to stop the server.

The launcher creates a local virtual environment and copies `.env.example` to `.env` only if one does not already exist. It does not download optional AI model weights or configure API keys.

## Manual setup
Open PowerShell in the extracted project folder:

```powershell
cd omnishield-backend
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
Copy-Item .env.example .env
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Then visit `http://127.0.0.1:8000/demo`.

## What to test
- Use the example input fields to try the URL, message, email, DLP, invoice, and prompt-injection scanners.
- Open `/docs` to see the API routes and send test requests.
- Visit the incident and audit pages after running scans to see what the backend actually records.
- Check model/status responses. Optional model features can correctly report `disabled` until you configure them.

## Important limitations
- This is a local defensive triage/demo foundation, not a full antivirus product or proof that a file/message/site is safe.
- The entry/login animation is a visual workspace gate, not real user authentication.
- Optional ML weights, QR image decoding, Google Web Risk, and ClamAV are not automatically installed/configured by this launcher.
- Use synthetic test data for the first preview. Do not paste passwords, private messages, or real financial/customer data into a demo.
- The launcher binds only to `127.0.0.1`; it is not exposed to other devices or the public internet.
