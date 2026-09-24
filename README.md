# Flask MFA Demo — TOTP (School Project)

Password (factor 1: knowledge) + TOTP 6-digit code (factor 2: possession).

**Report (how it all works):** [REPORT.md](REPORT.md) — architecture, real TOTP math, sequence diagram, threat table, 3-min demo script.

## 1. Run — any PC (2 min)

**Windows:** copy the whole folder, double-click `start.bat`.
**Mac / Linux:** copy the folder, run `./start.sh`.

The script installs Python deps into a local `.venv` (internet needed once) and opens the browser automatically. Needs Python 3 installed — Windows installer must tick **"Add python.exe to PATH"**.

Manual equivalent:

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python app.py
# opens http://127.0.0.1:5000 (falls back to 5001/5002/8000 if busy)
```

Demo path:
1. Register → scan QR in Google Authenticator / Authy / 1Password
2. Login with password → enter 6-digit code → Dashboard
3. Wrong code → rejected. Backup codes work once each.

## 2. How it works (for report)

- **Register (`/register`):** `validate_password()` enforces 12+ chars, upper/lower/digit/symbol, blocklist, 5+ unique chars — server-side, before any secret/DB write (`app.py:44-61`, gate `app.py:146-150`). Then `generate_password_hash` stores the PBKDF2 hash (never plaintext), `pyotp.random_base32()` creates the TOTP secret → `otpauth://` URI → QR PNG (base64 data URI). 5 backup codes stored as JSON. Live green/red checklist on the form is cosmetic only.
- **Login step 1 (`/login`):** `check_password_hash` verifies password. On success: `session[mfa_pending]=True`, redirect to `/verify`. Throttle: 5 fails/IP → 30s lock.
- **Login step 2 (`/verify`):** `pyotp.TOTP(secret).verify(code, valid_window=1)` — RFC 6238: `HMAC-SHA1(secret, floor(time/30))` truncated to 6 digits. `valid_window=1` allows ±30s clock skew. Backup code path deletes code after use.
- **Session (`/dashboard`):** only if `session[user]` + `session[mfa_verified]`. `app.secret_key`-signed cookie. `/logout` clears session.
- **DB:** SQLite `users(username, password_hash, totp_secret, backup_codes)`.

## 3. Security analysis (copy into report)

**Threats mitigated:** password leaks / phishing (attacker needs time-based secret), replay (code expires in 30s), brute force (throttle + 6-digit space + window=1), DB leak (hashes, not passwords).

**Remaining risks / limitations:** no HTTPS (demo only — cookies sniffable), no encrypted TOTP secrets at rest, authenticator enrollment has no re-verification step, no rate-limit on `/verify`, `secret_key` hardcoded, no WebAuthn phishing-resistance.

**Why TOTP and not SMS:** works offline, no carrier cost, no SIM-swap, standard (RFC 4226/6238), QR provisioning is easy to demo.

## 4. Defense script (3 min)

1. Show DB row: hash ≠ password.
2. Login with password only → blocked at `/verify`.
3. Enter wrong TOTP → "Wrong code".
4. Enter correct TOTP from phone → Dashboard.
5. Wait 30s, reuse same code → fails (time-step expired).

## 5. Diagrams to draw

- Sequence: User → Flask (`check_password`) → Flask (`TOTP.verify`) → Dashboard
- Factor table: Factor 1 knowledge / Factor 2 possession / (future) inherence

## 6. References

RFC 4226 (HOTP), RFC 6238 (TOTP), `pyotp` docs, OWASP MFA cheat sheet.
