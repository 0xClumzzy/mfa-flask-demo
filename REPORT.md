# Multi-Factor Authentication in Python — Design, Operation, and Security Analysis

**Project:** Flask + TOTP MFA demo  
**Stack:** Python 3, Flask, pyotp, qrcode, SQLite, Werkzeug password hashing  
**Standard:** RFC 4226 (HOTP), RFC 6238 (TOTP)

---

## 1. Abstract

This project implements multi-factor authentication (MFA) for a web application. A user must present two independent factors to reach the protected dashboard:

| Factor class | Meaning | Used here |
|---|---|---|
| Knowledge | Something you know | Password (enforced strong by policy) |
| Possession | Something you have | 6-digit TOTP code from an authenticator app |

A stolen password alone is not enough to log in: the attacker must also control the victim's phone. Password strength is enforced *before* any secret is generated, so weak credentials never enter the system. The report below walks through every stage with the actual code, a real TOTP computation, and the security properties each stage provides.

---

## 2. System architecture

```
┌──────────┐   password form    ┌─────────────────────────────┐
│  Browser │ ─────────────────► │  Flask app (app.py)         │
│          │                    │  /register /login /verify   │
│          │ ◄───────────────── │  /dashboard  /logout        │
└────┬─────┘   HTML + QR        └──────┬──────────────┬───────┘
     │                                 │              │
     │ scan QR                         │ SQL          │ signed cookie
     ▼                                 ▼              ▼
┌──────────────┐               ┌─────────────┐  ┌────────────┐
│ Authenticator│  computes     │  SQLite DB  │  │  Session   │
│ app on phone │  6-digit code │  mfa.db     │  │  (Flask)   |
│ (offline)    │               │  users row  │  └────────────┘
└──────────────┘               └─────────────┘
```

**Components**

1. **Flask routes** — five endpoints orchestrate register → login → verify → dashboard → logout (`app.py:128-295`).
2. **Password policy** — `validate_password()` rejects weak passwords before the account exists (`app.py:44-61`), enforced server-side at `app.py:146-150`.
3. **SQLite database** — one table `users` stores `password_hash`, `totp_secret`, `backup_codes` (`app.py:78-90`).
4. **Session** — server-signed cookie carries `user`, `mfa_pending`, `mfa_verified` flags (`app.py:226-230`).
5. **Authenticator app** — any RFC 6238 app (Google Authenticator, Authy, 1Password). Holds the same secret as the server; computes codes offline.
6. **QR enrollment** — `otpauth://` URI rendered to PNG, inlined as base64 data URI (`app.py:93-98`).

---

## 3. Stage 1 — Enrollment (`POST /register`)

### 3.1 Strong password policy — the code that makes it possible

Three pieces work together. All server-side; the browser checklist is cosmetic.

**Piece 1 — the rules themselves (`app.py:36-41`):**

```python
PASSWORD_MIN_LENGTH = 12
COMMON_PASSWORDS = {
    "password", "password1", "password123", "123456789012",
    "qwertyuiop12", "letmein12345", "iloveyou1234", "admin1234567",
    "welcome12345", "changeme1234",
}
```

Why each exists: 12+ length defeats short-space brute force; the blocklist kills the passwords that appear in every leak corpus.

**Piece 2 — the validator, fail-closed (`app.py:44-61`):**

```python
def validate_password(password: str) -> list:
    """Return a list of failed rules; empty list == strong enough."""
    errors = []
    if len(password) < PASSWORD_MIN_LENGTH:
        errors.append(f"at least {PASSWORD_MIN_LENGTH} characters")
    if not re.search(r"[A-Z]", password):
        errors.append("one uppercase letter")
    if not re.search(r"[a-z]", password):
        errors.append("one lowercase letter")
    if not re.search(r"\d", password):
        errors.append("one digit")
    if not re.search(r"[^A-Za-z0-9]", password):
        errors.append("one symbol (!@#$...)")
    if password.lower() in COMMON_PASSWORDS:
        errors.append("not on the common-passwords blocklist")
    if password and len(set(password)) < 5:
        errors.append("at least 5 unique characters (no aaa...)")
    return errors
```

Design points:
- **Returns a list, not a boolean** — the UI can show *every* failed rule at once (`app.py:148`), better UX than failing one rule at a time.
- **`len(set(password)) < 5`** — blocks repetition padding like `Aaaaaaaaaaaa1!`, which technically satisfies length + classes but has ~7 characters of real entropy.
- **`password.lower() in COMMON_PASSWORDS`** — case-insensitive blocklist match, so `Password123` cannot sneak through.
- **Fail-closed semantics** — an *empty list* is the only pass condition; a new rule is added by appending an `errors.append(...)`, never by relaxing a check.

**Piece 3 — the enforcement gate (`app.py:146-150`):**

```python
pw_errors = validate_password(password)
if pw_errors:
    items = "".join(f"<li class=err>missing: {e}</li>" for e in pw_errors)
    body = f"<p class=err>Password rejected by policy:</p><ul>{items}</ul><a href='/register'>back</a>"
    return render_template_string(BASE, title="register", body=body)
```

Called *before* `random_base32()` (`app.py:151`) and *before* the DB `INSERT` (`app.py:155-159`) — a weak password never produces a TOTP secret, never touches SQLite, never hashes. Pure early return: no secret, no row, no session.

**Piece 4 — live checklist, cosmetic only (`app.py:192-200`):**

```javascript
function checkPw(){
  var v=document.getElementById('pw').value;
  var t=[v.length>=12,/[A-Z]/.test(v),/[a-z]/.test(v),/\d/.test(v),
         /[^A-Za-z0-9]/.test(v),(new Set(v)).size>=5];
  document.querySelectorAll('#pwrules li').forEach(function(li,i){
    li.style.color=t[i]?'#15803d':'#b91c1c';
  });
}
```

Rules turn green as the user types. This is UX only — an attacker can delete the `<script>` tag, which is why Piece 3 on the server is the security boundary.

**Measured behavior** (executed against the validator):

| Password | Result |
|---|---|
| `short1!A` | REJECT — under 12 chars |
| `alllowercase123!x` | REJECT — no uppercase |
| `password123` | REJECT — common list (+ other rules) |
| `Aaaaaaaaaaaa1!` | REJECT — < 5 unique characters |
| `Str0ng&Demo!2026` | **ACCEPT** |

### 3.2 Rest of enrollment

After the policy gate passes (`app.py:139-174`):

1. **Username ≥ 3 chars** (`app.py:143-145`).
2. **Secret generation** — `pyotp.random_base32()` produces a random Base32 string (160 bits of entropy). This is the shared key both sides will use (`app.py:151`).
3. **Backup codes** — five one-time codes are generated in case the phone is lost (`app.py:152`).
4. **Password is hashed, never stored raw** — `generate_password_hash(password)` (Werkzeug, PBKDF2-SHA256 with per-user salt) is what goes into the database (`app.py:157`).
5. **Row insert** — `INSERT INTO users ...` with hash + secret + backup codes (`app.py:155-159`). Duplicate usernames are rejected by the `UNIQUE` constraint (`app.py:160-162`).
6. **QR provisioning** — the secret is wrapped into a standard URI:

   ```
   otpauth://totp/SchoolMFA:alice?secret=MVUFB...&issuer=SchoolMFA
   ```

   `qrcode` renders it to PNG, base64-inlined so no image files hit disk (`app.py:164-165`). The phone app decodes the QR and now holds the identical secret.

**Security property:** after this stage the server knows `hash(password)` and `secret`; the phone knows `secret`. The plaintext password exists only in transit and in memory for a moment — and it was strong when it arrived.

---

## 4. Stage 2 — Factor 1: password (`POST /login`)

`app.py:206-240`:

1. **Throttle check** — an in-memory counter per IP: after 5 consecutive failures the IP is locked out for 30 seconds (`app.py:209-212`). This blunts online password brute force.
2. **Lookup** the user row by username (`app.py:218`).
3. **Verify** with `check_password_hash(stored_hash, candidate)` — constant-time comparison of the PBKDF2 digests (`app.py:219`).
4. **Failure** → increment counter, show `Bad login (n/5)` (`app.py:220-224`).
5. **Success** → *do not* log the user in yet. The session gets:

   ```python
   session.clear()               # wipe anything stale  (app.py:226)
   session["user"] = username
   session["mfa_pending"] = True  # step 2 required
   session["mfa_verified"] = False
   ```

   then redirect to `/verify` (`app.py:230`).

**Key design point:** password success alone never sets `mfa_verified`. The dashboard decorator checks both flags (`app.py:101-107`).

---

## 5. Stage 3 — Factor 2: TOTP (`POST /verify`)

### 5.1 How TOTP works (RFC 6238)

Both server and phone compute the same value from two inputs: the **shared secret** and the **current time**.

```
counter  = floor(unix_time / 30)          # 30-second time step
HMAC     = HMAC-SHA1(key=secret, msg=counter)   # 20-byte digest
truncate = dynamic truncation of HMAC → 31-bit integer
code     = truncate mod 10^6              # 6 decimal digits
```

### 5.2 Real computation (measured on this project)

Secret: `MVUFBTXLVLNNLQ5R2HGDPMZ72E4VRTPZ`

| unix time | counter `floor(t/30)` | 6-digit code |
|---|---|---|
| 1790070360 | 59669012 | 532100 |
| 1790070390 | 59669013 | 646666 |
| 1790070420 | 59669014 | 493421 |
| 1790070450 | 59669015 | 251754 |

Same secret, different 30-second window → completely different code. The code is a pure function of (secret, time), so both sides stay in sync with no communication.

Step-by-step for counter `59669013`:

```
HMAC-SHA1(key, pack(">Q", 59669013))
  = cdcf7c5cfb171335831fde0f8ab185e1463f3379
offset = last_nibble = 0x9 = 9
slice  = bytes 9..12 = 7c5cfb17 → 31-bit int, mod 10^6
  = 646666
```

This manual computation was run side-by-side with `pyotp.TOTP.at()` — outputs matched exactly.

### 5.3 Server-side verification (`app.py:243-278`)

1. **Gate:** if `session["mfa_pending"]` is not set, redirect to login — you cannot reach `/verify` by typing the URL (`app.py:245-246`).
2. **Load secret** for the session user (`app.py:250-251`).
3. **`totp.verify(code, valid_window=1)`** (`app.py:253`) — computes the expected code for the current window *and* the adjacent windows (−30s, 0, +30s). Accepting a ±1 window tolerates normal phone/PC clock skew without opening a large guessing window.
4. **Success** → `mfa_pending = False`, `mfa_verified = True`, redirect to dashboard (`app.py:254-256`).
5. **Backup path** — if the input matches an unused backup code, it is deleted from the DB (one-time use) and MFA is granted (`app.py:258-266`).
6. **Failure** → "Wrong code. Check time sync on phone." (`app.py:267`).

### 5.4 Why old codes cannot be replayed

A code is valid only while `floor(now/30)` equals the window it was generated for (±1). After ~60 seconds it fails verification forever. An attacker who captures a code on the wire has under a minute, and only if they can also complete the login in that window.

---

## 6. Stage 4 — Protected resource (`GET /dashboard`)

```python
@app.route("/dashboard")      # app.py:281
@login_required               # app.py:282
def dashboard(): ...
```

`login_required` (`app.py:101-107`) redirects to `/login` unless **both** `session["user"]` and `session["mfa_verified"]` are truthy:

```python
if not session.get("user") or not session.get("mfa_verified"):
    return redirect(url_for("login"))
```

The cookie itself is signed by `app.secret_key` (`app.py:29`), so the client cannot forge `mfa_verified=True`.

`/logout` clears the session (`app.py:292-295`), dropping both flags.

---

## 7. End-to-end sequence

```
User            Browser           Flask                DB              Phone
 |                |                |                   |                |
 |  register      |                |                   |                |
 |--------------->|  POST /register|                   |                |
 |                |--------------->| validate_password |                |
 |                |                |  FAIL weak pw ────|──► reject, stop|
 |                |                |  PASS: gen secret |                |
 |                |                | hash password     |                |
 |                |                |------------------>| INSERT row     |
 |                |  QR + secret   |                   |                |
 |                |<---------------|                   |                |
 |  scan QR       |                |                   |                |
 |---------------------------------------------------------------> secret
 |                |                |                   |                |
 |  login (pw)    |                |                   |                |
 |--------------->|  POST /login   |                   |                |
 |                |--------------->| check_password_hash                 |
 |                |                |------------------>| SELECT row     |
 |                |  302 /verify   | mfa_pending=True  |                |
 |                |<---------------|                   |                |
 |  enter 6-digit |                |          code = TOTP(secret, now)   |
 |--------------->|  POST /verify  |                   |       <--------|
 |                |--------------->| totp.verify(..., window=1)          |
 |                |  302 /dashboard| mfa_verified=True  |                |
 |                |<---------------|                   |                |
 |  open dashboard|                |                   |                |
 |--------------->|  GET /dashboard| login_required OK  |                |
 |                |<---------------|                   |                |
 |  "MFA success" |                |                   |                |
```

---

## 8. Security analysis

### 8.1 Threats mitigated

| Threat | Mitigation | Code |
|---|---|---|
| Weak / breached password chosen at signup | 12-char policy, complexity classes, blocklist, repetition guard — fail-closed before account creation | `app.py:44-61`, gate `146-150` |
| Password database leak | PBKDF2-SHA256 hashes, not plaintext | `app.py:157` |
| Password phishing / credential stuffing | Second factor required; stolen password useless alone | `app.py:228-229`, `104` |
| Online password brute force | 5 fails/IP → 30s lock | `app.py:209-222` |
| TOTP code replay | Codes expire each 30s window | RFC 6238, `verify()` `app.py:253` |
| Forged session cookie | Server-side `secret_key` signature | `app.py:29` |
| Direct URL access to dashboard | `login_required` checks both session flags | `app.py:101-107` |
| Phone lost | 5 one-time backup codes, consumed on use | `app.py:258-266` |
| Clock skew false rejects | `valid_window=1` (±30s) | `app.py:253` |
| Client-side policy bypass (edited HTML/JS) | Policy re-enforced server-side; JS checklist is cosmetic | server `146-150` vs JS `192-200` |

### 8.2 Residual risks (honest limitations)

1. **No HTTPS** — demo runs on localhost; on a real network the cookie and codes are sniffable.
2. **TOTP secret stored in plaintext** in SQLite — a full DB + file read yields factor-2 material. (Production: encrypt at rest with a KMS.)
3. **`/verify` has no rate limit** — 6 digits + ±1 window ≈ 3×10⁶ guesses; online guessing is slow but not formally throttled like `/login`.
4. **Hardcoded `secret_key`** — fine for demo, must be an env var / `os.urandom(32)` in production.
5. **Composition rules ≠ true strength** — policy blocks the worst choices but `Tr0ub4dor&3`-style passwords can still be memorable-guessable; a zxcvbn-style estimator would be the upgrade.
6. **TOTP is only partially phishing-resistant** — a live attacker can relay a code in real time. WebAuthn/passkeys remove this class of attack entirely (named as future work).
7. **No re-binding check on QR page** — anyone who sees the QR during enrollment enrolls their own phone.
8. **Blocklist is tiny** — 10 entries; production would load the full RockYou/HIBP corpus.

### 8.3 Why TOTP instead of SMS or email OTP

| | TOTP (chosen) | SMS OTP | Email OTP |
|---|---|---|---|
| Works offline | Yes | No | No |
| Delivery cost / delay | None | Carrier fees, delay | Inbox delay |
| SIM-swap attack | Immune | Vulnerable | N/A |
| Phishing relay risk | Medium | Medium | High |
| Standards | RFC 4226/6238 | — | — |
| Demo friendliness | QR scan, instant | Needs SMS gateway | Needs SMTP |

TOTP is the standard recommendation for a self-contained, offline, free-to-demo MFA implementation.

---

## 9. Live demonstration script (~3 minutes)

1. **Show the schema** — one `users` row: `password_hash` ≠ password (paste both side by side).
2. **Weak password live** — type `password123`, show the red rejection list; type a strong one, watch the checklist go green.
3. **Register** — audience sees the QR appear; scan it on camera.
4. **Password-only attempt** — stop at `/verify`, show dashboard is still unreachable: *"factor 1 alone is not enough."*
5. **Wrong TOTP** — enter `000000`, show rejection.
6. **Correct TOTP** — enter the phone's current code → "MFA success."
7. **Replay test** — wait 31+ seconds, re-enter the *same* code → rejected (time-step expired).

---

## 10. Conclusion

The system demonstrates working MFA with a clean two-step gate: the password policy rejects weak credentials before an account exists; password verification only sets `mfa_pending`; only a valid time-based code sets `mfa_verified`; the protected route demands both. Passwords are stored as salted PBKDF2 hashes, TOTP follows RFC 6238 with a measured, reproducible HMAC pipeline, and throttling plus one-time backup codes cover the practical attack paths. Remaining gaps (HTTPS, secret encryption at rest, `/verify` rate limit, stronger strength estimation, WebAuthn) are documented as production hardening steps rather than hidden.

---

## 11. References

1. RFC 4226 — HOTP: HMAC-based One-Time Password.
2. RFC 6238 — TOTP: Time-Based One-Time Password.
3. Werkzeug Security helpers — `generate_password_hash` / `check_password_hash`.
4. pyotp documentation — `pyotp.TOTP.verify(valid_window=...)`.
5. OWASP Multi-Factor Authentication Cheat Sheet.
6. OWASP Password Storage Cheat Sheet (PBKDF2, salting, work factor).
