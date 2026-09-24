"""
Flask MFA Demo - TOTP (Authenticator App)
School project: password (factor 1) + TOTP 6-digit code (factor 2)

Run:
  pip install -r requirements.txt
  python app.py
  open http://127.0.0.1:5000

Flow:
  1. Register -> get TOTP secret + QR -> scan in Google Authenticator / Authy / 1Password
  2. Login with password -> prompted for TOTP code
  3. Dashboard only after both factors pass
"""
import base64
import io
import json
import re
import sqlite3
import time
from functools import wraps

import pyotp
import qrcode
from flask import Flask, redirect, render_template_string, request, session, url_for, g
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "CHANGE-THIS-for-school-demo-only"  # in prod: os.urandom(32)
DB = "mfa.db"

# Simple in-memory login throttling: {ip: [fail_count, locked_until]}
login_attempts = {}

# Password policy — fails closed: every rule must pass.
PASSWORD_MIN_LENGTH = 12
COMMON_PASSWORDS = {
    "password", "password1", "password123", "123456789012",
    "qwertyuiop12", "letmein12345", "iloveyou1234", "admin1234567",
    "welcome12345", "changeme1234",
}


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


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc=None):
    db = g.pop("db", None)
    if db:
        db.close()


def init_db():
    db = get_db()
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            totp_secret TEXT NOT NULL,
            backup_codes TEXT NOT NULL DEFAULT '[]',
            created_at REAL NOT NULL
        )
    """)
    db.commit()


def qr_data_uri(otp_uri: str) -> str:
    img = qrcode.make(otp_uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    b64 = base64.b64encode(buf.getvalue()).decode()
    return f"data:image/png;base64,{b64}"


def login_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if not session.get("user") or not session.get("mfa_verified"):
            return redirect(url_for("login"))
        return f(*a, **kw)
    return wrapper


BASE = """
<!doctype html><html><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>{{title}}</title>
<style>
body{font-family:system-ui,sans-serif;max-width:640px;margin:40px auto;padding:0 16px}
.card{border:1px solid #ddd;border-radius:12px;padding:20px}
input,button{padding:10px;margin:6px 0;width:100%;box-sizing:border-box}
button{background:#111;color:#fff;border:0;border-radius:8px;cursor:pointer}
a{color:#2563eb}.err{color:#b91c1c}.ok{color:#15803d}code{background:#f3f4f6;padding:2px 6px;border-radius:6px}
</style></head><body>
<h2>🔐 Flask MFA Demo (TOTP)</h2>
<div class=card>{{body|safe}}</div>
<p><a href="/">home</a> · <a href="/register">register</a> · <a href="/login">login</a>
{% if session.user %} · <a href="/dashboard">dashboard</a> · <a href="/logout">logout</a>{% endif %}</p>
</body></html>
"""

@app.route("/")
def index():
    body = "<p>Factor 1: password. Factor 2: 6-digit TOTP from authenticator app.</p>"
    if session.get("user") and session.get("mfa_verified"):
        body += f"<p class=ok>Logged in as <b>{session['user']}</b></p><a href='/dashboard'><button>Go to dashboard</button></a>"
    else:
        body += "<a href='/register'><button>Create account</button></a><a href='/login'><button>Login</button></a>"
    return render_template_string(BASE, title="home", body=body)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        if len(username) < 3:
            body = "<p class=err>Username must be ≥3 characters.</p><a href='/register'>back</a>"
            return render_template_string(BASE, title="register", body=body)
        pw_errors = validate_password(password)
        if pw_errors:
            items = "".join(f"<li class=err>missing: {e}</li>" for e in pw_errors)
            body = f"<p class=err>Password rejected by policy:</p><ul>{items}</ul><a href='/register'>back</a>"
            return render_template_string(BASE, title="register", body=body)
        secret = pyotp.random_base32()
        backup = [pyotp.random_base32()[:8].lower() for _ in range(5)]
        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (username,password_hash,totp_secret,backup_codes,created_at) VALUES (?,?,?,?,?)",
                (username, generate_password_hash(password), secret, json.dumps(backup), time.time()),
            )
            db.commit()
        except sqlite3.IntegrityError:
            body = "<p class=err>Username taken.</p><a href='/register'>back</a>"
            return render_template_string(BASE, title="register", body=body)

        otp_uri = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name="SchoolMFA")
        qr = qr_data_uri(otp_uri)
        codes = "".join(f"<li><code>{c}</code></li>" for c in backup)
        body = f"""
        <p class=ok>Account created. Scan now — shown <b>once</b>:</p>
        <img src="{qr}" width=220><br>
        <p>Manual secret: <code>{secret}</code></p>
        <p>Backup codes (each one-time):</p><ul>{codes}</ul>
        <a href="/login"><button>Continue to login</button></a>
        """
        return render_template_string(BASE, title="setup MFA", body=body)

    body = """
    <h3>Register</h3>
    <form method=post>
      <input name=username placeholder="username" required>
      <input name=password id=pw type=password placeholder="password" oninput="checkPw()" required>
      <ul id=pwrules style="font-size:14px;padding-left:18px;margin:4px 0">
        <li>at least 12 characters</li>
        <li>one uppercase letter</li>
        <li>one lowercase letter</li>
        <li>one digit</li>
        <li>one symbol (!@#$...)</li>
        <li>5+ unique characters, not a common password</li>
      </ul>
      <button>Create + show QR</button>
    </form>
    <script>
    function checkPw(){
      var v=document.getElementById('pw').value;
      var t=[v.length>=12,/[A-Z]/.test(v),/[a-z]/.test(v),/\\d/.test(v),
             /[^A-Za-z0-9]/.test(v),(new Set(v)).size>=5];
      document.querySelectorAll('#pwrules li').forEach(function(li,i){
        li.style.color=t[i]?'#15803d':'#b91c1c';
        li.style.fontWeight=t[i]?'700':'400';
      });
    }
    </script>
    """
    return render_template_string(BASE, title="register", body=body)


@app.route("/login", methods=["GET", "POST"])
def login():
    ip = request.remote_addr or "local"
    fails, locked_until = login_attempts.get(ip, (0, 0))
    if time.time() < locked_until:
        body = f"<p class=err>Locked 30s after 5 fails. Wait {int(locked_until-time.time())}s.</p>"
        return render_template_string(BASE, title="login", body=body)

    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        db = get_db()
        u = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if not u or not check_password_hash(u["password_hash"], password):
            fails += 1
            lock = time.time() + 30 if fails >= 5 else 0
            login_attempts[ip] = (fails, lock)
            body = f"<p class=err>Bad login ({fails}/5).</p><a href='/login'>retry</a>"
            return render_template_string(BASE, title="login", body=body)
        login_attempts[ip] = (0, 0)
        session.clear()
        session["user"] = username
        session["mfa_pending"] = True
        session["mfa_verified"] = False
        return redirect(url_for("verify"))

    body = """
    <h3>Step 1 — Password</h3>
    <form method=post>
      <input name=username placeholder="username" required>
      <input name=password type=password placeholder="password" required>
      <button>Next: enter MFA code</button>
    </form>
    """
    return render_template_string(BASE, title="login", body=body)


@app.route("/verify", methods=["GET", "POST"])
def verify():
    if not session.get("mfa_pending"):
        return redirect(url_for("login"))
    if request.method == "POST":
        code = request.form.get("code", "").strip().replace(" ", "")
        db = get_db()
        u = db.execute("SELECT * FROM users WHERE username=?", (session["user"],)).fetchone()
        totp = pyotp.TOTP(u["totp_secret"])
        # window=1 tolerates ±30s clock skew
        if totp.verify(code, valid_window=1):
            session["mfa_pending"] = False
            session["mfa_verified"] = True
            return redirect(url_for("dashboard"))
        # backup code fallback (one-time)
        backups = json.loads(u["backup_codes"])
        if code.lower() in backups:
            backups.remove(code.lower())
            db.execute("UPDATE users SET backup_codes=? WHERE username=?",
                       (json.dumps(backups), session["user"]))
            db.commit()
            session["mfa_pending"] = False
            session["mfa_verified"] = True
            return redirect(url_for("dashboard"))
        body = "<p class=err>Wrong code. Check time sync on phone.</p><a href='/verify'>retry</a>"
        return render_template_string(BASE, title="verify", body=body)

    body = """
    <h3>Step 2 — Authenticator code</h3>
    <p>Open Google Authenticator / Authy, enter 6-digit code. Or use a backup code.</p>
    <form method=post>
      <input name=code inputmode=numeric maxlength=8 placeholder="123456" required autofocus>
      <button>Verify</button>
    </form>
    """
    return render_template_string(BASE, title="verify", body=body)


@app.route("/dashboard")
@login_required
def dashboard():
    body = f"""
    <p class=ok>✅ MFA success. Welcome <b>{session['user']}</b></p>
    <p>Both factors passed: password + TOTP.</p>
    <a href="/logout"><button>Logout</button></a>
    """
    return render_template_string(BASE, title="dashboard", body=body)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


with app.app_context():
    init_db()


def _open_browser(url: str) -> None:
    import threading
    import webbrowser

    threading.Timer(1.0, lambda: webbrowser.open(url)).start()


if __name__ == "__main__":
    import socket

    host = "127.0.0.1"
    port = 5000
    for candidate in (5000, 5001, 5002, 8000):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind((host, candidate))
                port = candidate
                break
            except OSError:
                continue
    url = f"http://{host}:{port}"
    print(f"MFA demo running on {url} (Ctrl+C to stop)")
    _open_browser(url)
    app.run(host=host, port=port, debug=True, use_reloader=False)
