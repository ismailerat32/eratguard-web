from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import os
import json
import random
import string
from datetime import datetime
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
from mailer import send_mail
from utils.reset_utils import cleanup_expired_tokens, create_reset_token, create_reset_code

load_dotenv()


def _ss_get_last_scan_time():
    try:
        import json as _j
        logs = _j.load(open("data/spam_logs.json", encoding="utf-8"))
        if logs:
            last = logs[-1]
            ts = last.get("timestamp", "")
            if ts:
                from datetime import datetime as _dt
                t = _dt.fromisoformat(ts.replace("Z",""))
                diff = (_dt.now() - t).seconds // 60
                if diff < 1: return "Az önce"
                if diff < 60: return f"{diff} dk önce"
                return f"{diff//60} saat önce"
    except: pass
    return "Henüz yok"

app = Flask(__name__)

# ===== ERATGUARD STABLE SESSION SECRET START =====
import os as _ss_os
from pathlib import Path as _ss_Path

_ss_secret_file = _ss_Path("data/.eratguard_secret_key")
try:
    _ss_secret_file.parent.mkdir(parents=True, exist_ok=True)
    if not _ss_secret_file.exists():
        _ss_secret_file.write_text("eratguard-stable-render-session-secret-2026-admin-mobile", encoding="utf-8")
    app.secret_key = (
        _ss_os.environ.get("FLASK_SECRET_KEY")
        or _ss_os.environ.get("SECRET_KEY")
        or _ss_os.environ.get("ERATGUARD_SECRET_KEY") or os.environ.get("SPAMSHIELD_SECRET_KEY")
        or _ss_secret_file.read_text(encoding="utf-8").strip()
    )
except Exception:
    app.secret_key = "eratguard-stable-render-session-secret-2026-admin-mobile"
# ===== ERATGUARD STABLE SESSION SECRET END =====

# app.secret_key already configured above with stable EratGuard/Render secret.

LOG_FILE = "logs/log.txt"
WATCHLIST_FILE = "data/watchlist.json"
BLOCKLIST_FILE = "data/blocklist.json"
USERS_FILE = "data/users.json"
SETTINGS_FILE = "data/settings.json"
LICENSE_FILE = "data/license.json"
LOCALES_DIR = "locales"


# ===== ERATGUARD SUPABASE KV START =====
def _eg_db_enabled():
    try:
        flag = str(os.getenv("ERATGUARD_DB_ENABLED", "")).strip().lower()
        return bool(os.getenv("SUPABASE_URL")) and bool(os.getenv("SUPABASE_SERVICE_ROLE_KEY")) and flag in {"1", "true", "yes", "on"}
    except Exception:
        return False

def _eg_supabase_url():
    return os.getenv("SUPABASE_URL", "").strip().rstrip("/")

def _eg_supabase_key():
    return os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip()

def _eg_supabase_headers(extra=None):
    headers = {
        "apikey": _eg_supabase_key(),
        "Authorization": "Bearer " + _eg_supabase_key(),
        "Content-Type": "application/json",
    }
    if extra:
        headers.update(extra)
    return headers

def _eg_kv_ensure_table():
    # Table was created from Supabase SQL Editor.
    # REST mode does not create schema automatically.
    return _eg_db_enabled()

def _eg_kv_get_json(key, default=None):
    if not _eg_db_enabled():
        return default
    try:
        import json as _eg_json
        import urllib.parse as _eg_parse
        import urllib.request as _eg_request

        encoded_key = _eg_parse.quote(str(key), safe="")
        url = f"{_eg_supabase_url()}/rest/v1/eratguard_kv?key=eq.{encoded_key}&select=value"

        req = _eg_request.Request(
            url,
            headers=_eg_supabase_headers({"Accept": "application/json"}),
            method="GET",
        )

        with _eg_request.urlopen(req, timeout=15) as resp:
            rows = _eg_json.loads(resp.read().decode("utf-8") or "[]")

        if not rows:
            return default

        value = rows[0].get("value", default)
        return value if value is not None else default

    except Exception as e:
        print("EG_DB_READ_WARN:", key, repr(e), flush=True)
        return default

def _eg_kv_set_json(key, value):
    if not _eg_db_enabled():
        return False
    try:
        import json as _eg_json
        import urllib.request as _eg_request

        url = f"{_eg_supabase_url()}/rest/v1/eratguard_kv?on_conflict=key"

        payload = _eg_json.dumps(
            [{
                "key": str(key),
                "value": value if value is not None else {},
            }],
            ensure_ascii=False,
        ).encode("utf-8")

        req = _eg_request.Request(
            url,
            data=payload,
            headers=_eg_supabase_headers({
                "Prefer": "resolution=merge-duplicates,return=minimal",
            }),
            method="POST",
        )

        with _eg_request.urlopen(req, timeout=15) as resp:
            return 200 <= resp.status < 300

    except Exception as e:
        print("EG_DB_WRITE_WARN:", key, repr(e), flush=True)
        return False
# ===== ERATGUARD SUPABASE KV END =====




def ensure_default_user():
    os.makedirs("data", exist_ok=True)
    if not os.path.exists(USERS_FILE):
        users = {
            "admin": {
                "password": generate_password_hash("admin123"),
                "role": "admin",
                "active": True,
                "license_key": "ADMIN-SYSTEM",
                "expires_at": "2099-12-31",
                "email": ""
            }
        }
        with open(USERS_FILE, "w", encoding="utf-8") as f:
            json.dump(users, f, ensure_ascii=False, indent=2)


def ensure_default_settings():
    os.makedirs("data", exist_ok=True)
    if not os.path.exists(SETTINGS_FILE):
        settings = {
            "notifications_enabled": True,
            "notify_spam": True,
            "notify_supheli": True,
            "min_notify_score": 35
        }
        with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
            json.dump(settings, f, ensure_ascii=False, indent=2)


def load_settings():
    ensure_default_settings()
    try:
        with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {
            "notifications_enabled": True,
            "notify_spam": True,
            "notify_supheli": True,
            "min_notify_score": 35
        }


def save_settings(settings):
    os.makedirs("data", exist_ok=True)
    with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
        json.dump(settings, f, ensure_ascii=False, indent=2)


def load_mail_settings():
    return {
        "smtp_host": os.getenv("SMTP_HOST", "smtp.gmail.com"),
        "smtp_port": int(os.getenv("SMTP_PORT", "587")),
        "smtp_user": os.getenv("SMTP_USER", ""),
        "smtp_pass": os.getenv("SMTP_PASS", "")
    }


def load_locale(lang):
    path = os.path.join(LOCALES_DIR, f"{lang}.json")
    fallback = os.path.join(LOCALES_DIR, "tr.json")

    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        try:
            with open(fallback, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}


def get_lang():
    lang = session.get("lang", "tr")
    return lang if lang in ["tr", "en"] else "tr"


def load_users():
    os.makedirs("data", exist_ok=True)

    local_users = {}
    try:
        if not os.path.exists(USERS_FILE):
            ensure_default_user()
        if os.path.exists(USERS_FILE):
            with open(USERS_FILE, "r", encoding="utf-8") as f:
                loaded = json.load(f)
                if isinstance(loaded, dict):
                    local_users = loaded
    except Exception as e:
        print("LOCAL_USERS_READ_WARN:", repr(e), flush=True)
        local_users = {}

    if _eg_db_enabled():
        db_users = _eg_kv_get_json("users", None)

        if isinstance(db_users, dict) and db_users:
            try:
                with open(USERS_FILE, "w", encoding="utf-8") as f:
                    json.dump(db_users, f, ensure_ascii=False, indent=2)
            except Exception:
                pass
            return db_users

        if isinstance(local_users, dict) and local_users:
            _eg_kv_set_json("users", local_users)
            return local_users

    return local_users if isinstance(local_users, dict) else {}


def save_users(users):
    os.makedirs("data", exist_ok=True)

    if not isinstance(users, dict):
        users = {}

    if _eg_db_enabled():
        _eg_kv_set_json("users", users)

    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, ensure_ascii=False, indent=2)


def read_logs():
    logs = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            for line in f.readlines():
                line = line.strip()
                if not line or "From:" not in line:
                    continue
                logs.append(line)
    return logs[-300:]


def parse_logs():
    parsed = []
    for line in read_logs():
        item = {
            "raw": line,
            "sender": "",
            "status": "",
            "score": "",
            "category": "",
            "message": line
        }

        parts = [p.strip() for p in line.split("|")]
        for p in parts:
            if p.startswith("From:"):
                item["sender"] = p.replace("From:", "").strip()
            elif p.startswith("Status:"):
                item["status"] = p.replace("Status:", "").strip()
            elif p.startswith("Score:"):
                item["score"] = p.replace("Score:", "").strip()
            elif p.startswith("Category:"):
                item["category"] = p.replace("Category:", "").strip()
            elif p.startswith("Message:"):
                item["message"] = p.replace("Message:", "").strip()

        parsed.append(item)

    return parsed


def load_json_dict(path):
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_json_dict(path, data):
    os.makedirs("data", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def load_license():
    if not os.path.exists(LICENSE_FILE):
        return {"active": False, "key": ""}
    try:
        with open(LICENSE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"active": False, "key": ""}


def save_license(data):
    os.makedirs("data", exist_ok=True)
    with open(LICENSE_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def login_required():
    return session.get("logged_in") is True


def _eg_password_policy_error(password):
    password = password or ""

    if len(password) < 8:
        return "Şifre en az 8 karakter olmalı."

    if not any(c.isupper() for c in password):
        return "Şifre en az 1 büyük harf içermeli."

    if not any(c.islower() for c in password):
        return "Şifre en az 1 küçük harf içermeli."

    if not any(c.isdigit() for c in password):
        return "Şifre en az 1 rakam içermeli."

    special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?/~`"
    if not any(c in special_chars for c in password):
        return "Şifre en az 1 özel karakter içermeli. Örnek: ! @ # ?"

    return None


def _eg_password_policy_text():
    return "Şifre en az 8 karakter, 1 büyük harf, 1 küçük harf, 1 rakam ve 1 özel karakter içermeli."



def admin_required():
    return session.get("role") == "admin"


def get_last_blocked(blocklist):
    if not blocklist:
        return None
    try:
        return list(blocklist.keys())[-1]
    except Exception:
        return None


def is_date_expired(date_str):
    try:
        expiry = datetime.strptime(date_str, "%Y-%m-%d").date()
        return datetime.now().date() > expiry
    except Exception:
        return False


def generate_license_key():
    parts = []
    for _ in range(4):
        part = "".join(random.choices(string.ascii_uppercase + string.digits, k=4))
        parts.append(part)
    return "SPAM-" + "-".join(parts)


def get_all_used_license_keys(users):
    used = set()
    for info in users.values():
        key = info.get("license_key", "").strip().upper()
        if key and key != "NONE":
            used.add(key)
    return used


def generate_unique_license_key(users):
    used = get_all_used_license_keys(users)
    while True:
        new_key = generate_license_key()
        if new_key not in used:
            return new_key


@app.route("/api/push-log", methods=["POST"])
def api_push_log():
    api_key = request.headers.get("X-API-KEY", "").strip()
    expected_key = os.getenv("API_PUSH_KEY", "").strip()

    if not expected_key or api_key != expected_key:
        return jsonify({"ok": False, "error": "unauthorized"}), 401

    data = request.get_json(silent=True) or {}

    sender = str(data.get("sender", "BİLİNMİYOR")).strip()
    status = str(data.get("status", "TEMİZ")).strip()
    score = str(data.get("score", "0")).strip()
    category = str(data.get("category", "GENEL")).strip()
    message = str(data.get("message", "")).strip()

    if not message:
        return jsonify({"ok": False, "error": "message missing"}), 400

    os.makedirs("logs", exist_ok=True)

    line = (
        f"From: {sender} | Status: {status} | Score: {score} | "
        f"Category: {category} | Message: {message[:160]}"
    )

    print("PUSH_LOG:", line, flush=True)

    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")

    return jsonify({"ok": True})


@app.route("/set-language/<lang>")
def set_language(lang):
    if lang in ["tr", "en"]:
        session["lang"] = lang
    return redirect(request.referrer or url_for("landing"))



# ===== SPAMSHIELD RENDER KEEPALIVE HEALTH START =====
@app.route("/health")
@app.route("/ping")
@app.route("/status")
def ss_health_ping():
    return {
        "ok": True,
        "service": "EratGuard PRO",
        "status": "alive"
    }, 200
# ===== SPAMSHIELD RENDER KEEPALIVE HEALTH END =====

@app.route("/landing")
def landing():
    return render_template("landing.html")


@app.route("/activate", methods=["GET", "POST"])
def activate():
    error = None
    success = None
    t = load_locale(get_lang())

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        license_key = request.form.get("license_key", "").strip().upper()

        users = load_users()

        if username not in users:
            error = "Kullanıcı bulunamadı" if get_lang() == "tr" else "User not found"
        else:
            user = users[username]
            saved_key = user.get("license_key", "").strip().upper()

            if not saved_key or saved_key == "NONE":
                error = "Bu kullanıcı için lisans tanımlı değil." if get_lang() == "tr" else "No license assigned for this user."
            elif license_key != saved_key:
                error = "Geçersiz lisans" if get_lang() == "tr" else "Invalid license"
            else:
                users[username]["active"] = True
                if not users[username].get("expires_at"):
                    users[username]["expires_at"] = "2026-12-31"
                save_users(users)
                success = "Hesap aktif edildi!" if get_lang() == "tr" else "Account activated!"

    return render_template("activate.html", error=error, success=success, t=t, lang=get_lang())


@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    success = None
    t = load_locale(get_lang())

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        users = load_users()

        if not username:
            error = "Kullanıcı adı boş olamaz." if get_lang() == "tr" else "Username cannot be empty."
        elif not email:
            error = "Mail adresi gerekli." if get_lang() == "tr" else "Email is required."
        elif username in users:
            error = "Bu kullanıcı zaten var." if get_lang() == "tr" else "This user already exists."
        elif _eg_password_policy_error(password):
            error = _eg_password_policy_error(password) if get_lang() == "tr" else "Password must be at least 8 characters and include uppercase, lowercase, number and special character."
        else:
            from datetime import datetime
            now = datetime.now().isoformat(timespec="seconds")

            users[username] = {
                "password": generate_password_hash(password),
                "role": "user",
                "active": True,
                "license_key": "NONE",
                "expires_at": "2099-01-01",
                "email": email,
                "created_at": now,
                "last_seen": now
            }
            save_users(users)

            # Güvenlik: kayıt sonrası otomatik giriş yok.
            # Kullanıcı hesabını oluşturduktan sonra şifresiyle login olmalı.
            try:
                _eg_touch_user_session(username, "register")
            except Exception:
                pass

            session.clear()
            return redirect(url_for("login") + "?registered=1")

    return render_template("register.html", error=error, success=success, t=t, lang=get_lang())


@app.route("/send-license/<target_username>", methods=["POST"])
def send_license(target_username):
    if not login_required():
        return redirect(url_for("login"))
    if not admin_required():
        return redirect(url_for("index"))

    users = load_users()
    mail_cfg = load_mail_settings()

    if target_username not in users:
        print("MAIL_ERROR: kullanıcı bulunamadı ->", target_username, flush=True)
        return redirect(url_for("users"))

    user = users[target_username]
    email = user.get("email", "").strip()

    if not email:
        print("MAIL_ERROR: kullanıcı email yok", flush=True)
        return redirect(url_for("users"))

    current_license = user.get("license_key", "").strip().upper()
    generated_new_license = False

    if not current_license or current_license == "NONE":
        license_key = generate_unique_license_key(users)
        generated_new_license = True
    else:
        license_key = current_license

    expires_at = user.get("expires_at", "").strip() or "2026-12-31"
    base_url = os.getenv("APP_BASE_URL", "http://127.0.0.1:8080")

    subject = "EratGuard Lisans Kodunuz"
    body = f"""Merhaba {target_username},

EratGuard lisans kodunuz aşağıdadır:

{license_key}

Aktivasyon için:
- Kullanıcı adınız: {target_username}
- Lisans kodunuz: {license_key}

Aktivasyon sayfası:
{base_url}/activate

EratGuard
"""

    try:
        print("MAIL_DEBUG smtp_host:", mail_cfg["smtp_host"], flush=True)
        print("MAIL_DEBUG smtp_port:", mail_cfg["smtp_port"], flush=True)
        print("MAIL_DEBUG smtp_user:", mail_cfg["smtp_user"], flush=True)
        print("MAIL_DEBUG smtp_pass_set:", bool(mail_cfg["smtp_pass"]), flush=True)
        print("MAIL_DEBUG target_email:", email, flush=True)
        print("MAIL_DEBUG target_username:", target_username, flush=True)
        print("MAIL_DEBUG license_key:", license_key, flush=True)

        send_mail(
            mail_cfg["smtp_host"],
            mail_cfg["smtp_port"],
            mail_cfg["smtp_user"],
            mail_cfg["smtp_pass"],
            email,
            subject,
            body
        )

        if generated_new_license:
            users[target_username]["license_key"] = license_key
            users[target_username]["expires_at"] = expires_at
            save_users(users)

        print("MAIL_SUCCESS gönderildi", flush=True)

    except Exception as e:
        print("MAIL_ERROR:", repr(e), flush=True)

    return redirect(url_for("users"))


    user = users[target_username]
    email = user.get("email", "").strip()

    if not email:
        print("MAIL_ERROR: kullanıcı email yok", flush=True)
        return redirect(url_for("users"))

    license_key = user.get("license_key", "").strip().upper()

    if not license_key or license_key == "NONE":
        license_key = generate_unique_license_key(users)
        users[target_username]["license_key"] = license_key
        if not users[target_username].get("expires_at"):
            users[target_username]["expires_at"] = "2026-12-31"
        save_users(users)

    base_url = os.getenv("APP_BASE_URL", "http://127.0.0.1:8080")

    subject = "EratGuard Lisans Kodunuz"
    body = f"""Merhaba {target_username},

EratGuard lisans kodunuz aşağıdadır:

{license_key}

Aktivasyon için:
- Kullanıcı adınız: {target_username}
- Lisans kodunuz: {license_key}

Aktivasyon sayfası:
{base_url}/activate

EratGuard
"""

    try:
        print("MAIL_DEBUG smtp_host:", mail_cfg["smtp_host"], flush=True)
        print("MAIL_DEBUG smtp_port:", mail_cfg["smtp_port"], flush=True)
        print("MAIL_DEBUG smtp_user:", mail_cfg["smtp_user"], flush=True)
        print("MAIL_DEBUG smtp_pass_set:", bool(mail_cfg["smtp_pass"]), flush=True)
        print("MAIL_DEBUG target_email:", email, flush=True)
        print("MAIL_DEBUG target_username:", target_username, flush=True)
        print("MAIL_DEBUG license_key:", license_key, flush=True)

        send_mail(
            mail_cfg["smtp_host"],
            mail_cfg["smtp_port"],
            mail_cfg["smtp_user"],
            mail_cfg["smtp_pass"],
            email,
            subject,
            body
        )

        print("MAIL_SUCCESS gönderildi", flush=True)

    except Exception as e:
        print("MAIL_ERROR:", repr(e), flush=True)

    return redirect(url_for("users"))


@app.route("/login", methods=["GET", "POST"])
def login():
    ensure_default_user()

    error = None
    t = load_locale(get_lang())

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        users = load_users()
        user = users.get(username)

        if not user:
            error = "Kullanıcı adı veya şifre yanlış." if get_lang() == "tr" else "Username or password is incorrect."
        elif not user.get("active", True):
            error = "Bu kullanıcı pasif durumda." if get_lang() == "tr" else "This user is inactive."
        elif is_date_expired(user.get("expires_at", "2099-12-31")):
            error = "Kullanıcı lisans süresi dolmuş." if get_lang() == "tr" else "User license has expired."
        elif check_password_hash(user["password"], password):
            session["logged_in"] = True
            session["onboarding_done"] = True
            session["username"] = username
            session["role"] = user.get("role", "user")

            try:
                from datetime import datetime
                users[username]["last_login"] = datetime.now().isoformat(timespec="seconds")
                users[username]["last_seen"] = users[username]["last_login"]
                save_users(users)
                _eg_touch_user_session(username, "login")
            except Exception:
                pass

            users = load_users()
            udata = users.get(username, {})
            if not udata.get("notif_asked"):
                return redirect("/notification-permission")
            return redirect(url_for("radial"))
        else:
            error = "Kullanıcı adı veya şifre yanlış." if get_lang() == "tr" else "Username or password is incorrect."

    return render_template("login.html", error=error, t=t, lang=get_lang())


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/change-password", methods=["GET", "POST"])
def change_password():
    if not login_required():
        return redirect(url_for("login"))

    error = None
    success = None
    username = session.get("username")
    t = load_locale(get_lang())

    if request.method == "POST":
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        users = load_users()
        user = users.get(username)

        if not user or not check_password_hash(user["password"], current_password):
            error = "Mevcut şifre yanlış." if get_lang() == "tr" else "Current password is incorrect."
        elif _eg_password_policy_error(new_password):
            error = _eg_password_policy_error(new_password) if get_lang() == "tr" else "Password must be at least 8 characters and include uppercase, lowercase, number and special character."
        elif new_password != confirm_password:
            error = "Yeni şifreler eşleşmiyor." if get_lang() == "tr" else "New passwords do not match."
        else:
            users[username]["password"] = generate_password_hash(new_password)
            save_users(users)
            success = "Şifre başarıyla değiştirildi." if get_lang() == "tr" else "Password changed successfully."

    return render_template(
        "change_password.html",
        error=error,
        success=success,
        username=username,
        t=t,
        lang=get_lang()
    )


@app.route("/add-user", methods=["GET", "POST"])
def add_user():
    if not login_required():
        return redirect(url_for("login"))
    if not admin_required():
        return redirect(url_for("index"))

    error = None
    success = None
    t = load_locale(get_lang())

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        role = request.form.get("role", "user").strip()
        expires_at = request.form.get("expires_at", "").strip()
        active = request.form.get("active") == "on"

        users = load_users()

        if not username:
            error = "Kullanıcı adı boş olamaz." if get_lang() == "tr" else "Username cannot be empty."
        elif username in users:
            error = "Bu kullanıcı zaten var." if get_lang() == "tr" else "This user already exists."
        elif _eg_password_policy_error(password):
            error = _eg_password_policy_error(password) if get_lang() == "tr" else "Password must be at least 8 characters and include uppercase, lowercase, number and special character."
        elif password != confirm_password:
            error = "Şifreler eşleşmiyor." if get_lang() == "tr" else "Passwords do not match."
        elif role not in ["admin", "user"]:
            error = "Geçersiz rol." if get_lang() == "tr" else "Invalid role."
        elif not expires_at:
            error = "Bitiş tarihi gerekli." if get_lang() == "tr" else "Expiry date is required."
        else:
            users[username] = {
                "password": generate_password_hash(password),
                "role": role,
                "active": active,
                "license_key": "NONE",
                "expires_at": expires_at,
                "email": email
            }
            save_users(users)
            success = f"{username} kullanıcısı eklendi." if get_lang() == "tr" else f"User {username} added."

    return render_template(
        "add_user.html",
        error=error,
        success=success,
        username=session.get("username", "admin"),
        t=t,
        lang=get_lang()
    )


@app.route("/users")
def users():
    if not login_required():
        return redirect(url_for("login"))
    if not admin_required():
        return redirect(url_for("index"))

    return render_template(
        "users.html",
        users=load_users(),
        username=session.get("username", "admin"),
        t=load_locale(get_lang()),
        lang=get_lang()
    )


@app.route("/toggle-user/<target_username>", methods=["POST"])
def toggle_user(target_username):
    if not login_required():
        return redirect(url_for("login"))
    if not admin_required():
        return redirect(url_for("index"))

    users = load_users()
    if target_username in users and target_username != "admin":
        users[target_username]["active"] = not users[target_username].get("active", True)
        save_users(users)

    return redirect(url_for("users"))


@app.route("/delete-user/<target_username>", methods=["POST"])
def delete_user(target_username):
    if not login_required():
        return redirect(url_for("login"))
    if not admin_required():
        return redirect(url_for("index"))

    current_user = session.get("username")
    users = load_users()

    if target_username != current_user and target_username in users:
        del users[target_username]
        save_users(users)

    return redirect(url_for("users"))


@app.route("/settings", methods=["GET", "POST"])
def settings():
    if not login_required():
        return redirect(url_for("login"))
    if not admin_required():
        return redirect(url_for("index"))

    error = None
    success = None
    settings_data = load_settings()
    t = load_locale(get_lang())

    if request.method == "POST":
        try:
            settings_data["notifications_enabled"] = request.form.get("notifications_enabled") == "on"
            settings_data["notify_spam"] = request.form.get("notify_spam") == "on"
            settings_data["notify_supheli"] = request.form.get("notify_supheli") == "on"
            settings_data["min_notify_score"] = int(request.form.get("min_notify_score", "35"))
            save_settings(settings_data)
            success = "Bildirim ayarları kaydedildi." if get_lang() == "tr" else "Notification settings saved."
        except Exception:
            error = "Ayarlar kaydedilemedi." if get_lang() == "tr" else "Settings could not be saved."

    return render_template(
        "settings.html",
        settings=settings_data,
        error=error,
        success=success,
        username=session.get("username", "admin"),
        t=t,
        lang=get_lang()
    )




@app.route("/set-lang/<lang>")
def set_lang(lang):
    if lang in ["tr", "en"]:
        session["lang"] = lang
    return redirect(request.referrer or "/radial")

@app.route("/splash")
def splash():
    return render_template("splash.html")

@app.route("/splash_admin")
def splash_admin():
    return render_template("splash_admin.html")

@app.route("/")
def index():
    if not login_required():
        return redirect(url_for("login"))

    logs = parse_logs()
    status_filter = request.args.get("status", "").strip().upper()
    category_filter = request.args.get("category", "").strip().upper()
    sender_filter = request.args.get("sender", "").strip().lower()

    filtered = []
    for log in logs:
        if status_filter and log["status"].upper() != status_filter:
            continue
        if category_filter and log["category"].upper() != category_filter:
            continue
        if sender_filter and sender_filter not in log["sender"].lower():
            continue
        filtered.append(log)

    watchlist = load_json_dict(WATCHLIST_FILE)
    blocklist = load_json_dict(BLOCKLIST_FILE)

    summary = {
        "watchlist_count": len(watchlist),
        "blocklist_count": len(blocklist),
        "last_blocked": get_last_blocked(blocklist)
    }

    return render_template(
        "dashboard.html",
        logs=filtered,
        watchlist=watchlist,
        blocklist=blocklist,
        summary=summary,
        status_filter=status_filter,
        category_filter=category_filter,
        sender_filter=sender_filter,
        username=session.get("username", "admin"),
        role=session.get("role", "user"),
        t=load_locale(get_lang()),
        lang=get_lang()
    )


@app.route("/unblock/<sender>", methods=["POST"])
def unblock(sender):
    if not login_required():
        return redirect(url_for("login"))
    if not admin_required():
        return redirect(url_for("index"))

    blocklist = load_json_dict(BLOCKLIST_FILE)
    if sender in blocklist:
        del blocklist[sender]
        save_json_dict(BLOCKLIST_FILE, blocklist)

    return redirect(url_for("index"))


@app.route("/watch-remove/<sender>", methods=["POST"])
def watch_remove(sender):
    if not login_required():
        return redirect(url_for("login"))
    if not admin_required():
        return redirect(url_for("index"))

    watchlist = load_json_dict(WATCHLIST_FILE)
    if sender in watchlist:
        del watchlist[sender]
        save_json_dict(WATCHLIST_FILE, watchlist)

    return redirect(url_for("index"))


@app.route("/watch-block/<sender>", methods=["POST"])
def watch_block(sender):
    if not login_required():
        return redirect(url_for("login"))
    if not admin_required():
        return redirect(url_for("index"))

    watchlist = load_json_dict(WATCHLIST_FILE)
    blocklist = load_json_dict(BLOCKLIST_FILE)

    if sender in watchlist:
        info = watchlist[sender]
        blocklist[sender] = {
            "category": info.get("category", "MANUAL_BLOCK"),
            "score": max(info.get("score", 0), 60),
            "blocked": True
        }
        del watchlist[sender]
        save_json_dict(WATCHLIST_FILE, watchlist)
        save_json_dict(BLOCKLIST_FILE, blocklist)

    return redirect(url_for("index"))



# ===== ERATGUARD FINAL SECURITY HEADERS + LICENSE ALIASES START =====
# Play Store öncesi final hardening:
# - Güvenlik header'ları
# - Lisans/abonelik alias route'ları
# - 404 görünen eski/alternatif lisans yollarını aktif sayfalara yönlendirme

from flask import redirect as _eg_final_redirect
from flask import request as _eg_final_request

@app.after_request
def _eg_final_security_headers(response):
    # Render HTTPS arkasında çalıştığı için HSTS güvenli.
    response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault(
        "Permissions-Policy",
        "geolocation=(), microphone=(), camera=(), payment=(), usb=(), bluetooth=()"
    )

    # Uygulamada inline CSS/JS bulunduğu için CSP güvenli ama kırmayacak seviyede tutuldu.
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self' https: data: blob:; "
        "script-src 'self' https: 'unsafe-inline' 'unsafe-eval'; "
        "style-src 'self' https: 'unsafe-inline'; "
        "img-src 'self' https: data: blob:; "
        "font-src 'self' https: data:; "
        "connect-src 'self' https:; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self' https:;"
    )
    return response


@app.route("/licenses", methods=["GET", "POST"])
@app.route("/generated-licenses", methods=["GET", "POST"])
@app.route("/license-manager", methods=["GET", "POST"])
@app.route("/activation", methods=["GET", "POST"])
@app.route("/activate-license", methods=["GET", "POST"])
@app.route("/u/lisans", methods=["GET", "POST"])
def _eg_final_user_license_aliases():
    return _eg_final_redirect("/u/license")


@app.route("/subscription", methods=["GET", "POST"])
@app.route("/abonelik", methods=["GET", "POST"])
def _eg_final_subscription_aliases():
    return _eg_final_redirect("/u/pricing")


@app.route("/manage-license/admin", methods=["GET", "POST"])
@app.route("/admin/generated-licenses", methods=["GET", "POST"])
@app.route("/admin/license-manager", methods=["GET", "POST"])
def _eg_final_admin_license_aliases():
    return _eg_final_redirect("/admin/licenses")

# ===== ERATGUARD FINAL SECURITY HEADERS + LICENSE ALIASES END =====



# ===== ERATGUARD FINAL USER AUTH BOUNDARY GUARD START =====
# Amaç:
# Login olmadan kullanıcı paneli alt sayfaları görünmesin.
# /app-start, /login, /privacy, /terms gibi public akışlar etkilenmez.

from flask import session as _eg_auth_session
from flask import redirect as _eg_auth_redirect
from flask import request as _eg_auth_request

def _eg_final_has_user_session():
    keys = [
        "username",
        "user",
        "user_id",
        "email",
        "logged_in",
        "authenticated",
        "admin_username",
        "is_admin",
    ]
    for k in keys:
        if _eg_auth_session.get(k):
            return True
    return False

@app.before_request
def _eg_final_user_auth_boundary_guard():
    path = (_eg_auth_request.path or "").rstrip("/") or "/"

    protected_exact = {
        "/u",
        "/u/home",
        "/u/blocked",
        "/u/analysis",
    }

    protected_prefixes = (
        "/u/blocked/",
        "/u/analysis/",
    )

    if path in protected_exact or any(path.startswith(prefix) for prefix in protected_prefixes):
        if not _eg_final_has_user_session():
            return _eg_auth_redirect("/login")

# ===== ERATGUARD FINAL USER AUTH BOUNDARY GUARD END =====



# ===== ERATGUARD FINAL PASSWORD RESET ROUTES START =====
from flask import render_template_string as _eg_reset_render_template_string
from flask import request as _eg_reset_request
from flask import redirect as _eg_reset_redirect
from werkzeug.security import generate_password_hash as _eg_reset_generate_password_hash

def _eg_reset_page(error=None, message=None, token="", code_mode=False):
    action = "/reset-password-code" if code_mode else ("/reset-password/" + token)

    if code_mode:
        code_input = """
        <label>Sıfırlama kodu</label>
        <input name="code" inputmode="numeric" maxlength="6" placeholder="6 haneli kod">
        """
    else:
        code_input = ""

    html = f"""
<!doctype html>
<html lang="tr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>EratGuard PRO • Şifre Sıfırla</title>
  <style>
    body {{
      margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center;
      background:radial-gradient(circle at top,#07351f 0,#010805 48%,#000 100%);
      color:#eefaf2; font-family:Arial,sans-serif;
    }}
    .card {{
      width:min(88vw,480px); padding:34px 28px; border:1px solid rgba(120,255,150,.18);
      border-radius:28px; background:rgba(0,20,12,.72); box-shadow:0 24px 80px rgba(0,0,0,.45);
    }}
    h1 {{ margin:0 0 14px; font-size:30px; }}
    p {{ color:rgba(238,250,242,.72); line-height:1.55; }}
    label {{ display:block; margin:18px 0 8px; font-weight:700; }}
    input {{
      width:100%; box-sizing:border-box; padding:15px 16px; border-radius:16px;
      border:1px solid rgba(255,255,255,.14); background:rgba(0,0,0,.28);
      color:white; font-size:16px; outline:none;
    }}
    button {{
      width:100%; margin-top:22px; padding:16px; border:0; border-radius:18px;
      color:white; font-weight:800; font-size:16px;
      background:linear-gradient(90deg,#00d66f,#18c6e8);
    }}
    .msg {{ margin-top:14px; color:#8dffb0; }}
    .err {{ margin-top:14px; color:#ff7b7b; }}
    a {{ color:#a9c8ff; text-decoration:none; display:block; margin-top:18px; text-align:center; }}
  </style>
</head>
<body>
  <form class="card" method="post" action="{action}">
    <h1>Yeni Şifre Oluştur</h1>
    <p>EratGuard hesabın için yeni ve güçlü bir şifre belirle.</p>
    {code_input}
    <label>Yeni şifre</label>
    <input name="new_password" type="password" minlength="8" required placeholder="En az 8 karakter, büyük/küçük harf, rakam ve özel karakter">
    <label>Yeni şifre tekrar</label>
    <input name="confirm_password" type="password" minlength="8" required placeholder="Güçlü şifreyi tekrar gir">
    <button type="submit">Şifreyi Güncelle</button>
    {f'<div class="msg">{message}</div>' if message else ''}
    {f'<div class="err">{error}</div>' if error else ''}
    <a href="/login">← Giriş sayfasına dön</a>
  </form>
</body>
</html>
"""
    return _eg_reset_render_template_string(html)

def _eg_reset_update_password(username, new_password):
    users = load_users()
    if username not in users:
        return False
    users[username]["password"] = _eg_reset_generate_password_hash(new_password)
    users[username].pop("password_hash", None)
    save_users(users)
    return True

def _eg_reset_validate_passwords(new_password, confirm_password):
    if not new_password:
        return "Yeni şifre boş olamaz."

    pw_error = _eg_password_policy_error(new_password)
    if pw_error:
        return pw_error

    if new_password != confirm_password:
        return "Şifreler eşleşmiyor."

    return None


def eg_final_reset_password_token(token):
    from utils.reset_utils import find_valid_token_record, mark_token_used

    record = find_valid_token_record(token)
    if not record:
        return _eg_reset_page(error="Sıfırlama bağlantısı geçersiz veya süresi dolmuş.", token=token)

    if _eg_reset_request.method == "POST":
        new_password = _eg_reset_request.form.get("new_password", "")
        confirm_password = _eg_reset_request.form.get("confirm_password", "")
        err = _eg_reset_validate_passwords(new_password, confirm_password)
        if err:
            return _eg_reset_page(error=err, token=token)

        username = record.get("username", "")
        if _eg_reset_update_password(username, new_password):
            mark_token_used(token)
            return _eg_reset_redirect("/login?reset=success")

        return _eg_reset_page(error="Şifre güncellenemedi. Lütfen destek ile iletişime geçin.", token=token)

    return _eg_reset_page(token=token)

@app.route("/reset-password-code", methods=["GET", "POST"])
def eg_final_reset_password_code():
    from utils.reset_utils import find_valid_code_record, mark_token_used

    if _eg_reset_request.method == "POST":
        code = (_eg_reset_request.form.get("code") or "").strip()
        record = find_valid_code_record(code)
        if not record:
            return _eg_reset_page(error="Sıfırlama kodu geçersiz veya süresi dolmuş.", code_mode=True)

        new_password = _eg_reset_request.form.get("new_password", "")
        confirm_password = _eg_reset_request.form.get("confirm_password", "")
        err = _eg_reset_validate_passwords(new_password, confirm_password)
        if err:
            return _eg_reset_page(error=err, code_mode=True)

        username = record.get("username", "")
        if _eg_reset_update_password(username, new_password):
            mark_token_used(code)
            return _eg_reset_redirect("/login?reset=success")

        return _eg_reset_page(error="Şifre güncellenemedi. Lütfen destek ile iletişime geçin.", code_mode=True)

    return _eg_reset_page(code_mode=True)

# ===== ERATGUARD FINAL PASSWORD RESET ROUTES END =====



# ===== ERATGUARD ADMIN FORGOT MAIL DIAGNOSTIC START =====
# Admin-only diagnostic. Public kullanıcıya account var/yok bilgisi sızdırmaz.
@app.route("/admin/forgot-mail-diagnostic", methods=["GET", "POST"])
@app.route("/admin-mail-diagnostic", methods=["GET", "POST"])
def eg_admin_forgot_mail_diagnostic():
    admin_ok_func = globals().get("_ss_admin_ok")
    is_admin_ok = admin_ok_func() if callable(admin_ok_func) else bool(
        session.get("logged_in") and (
            session.get("is_admin")
            or session.get("role") == "admin"
            or session.get("username") == "admin"
        )
    )

    if not is_admin_ok:
        return redirect("/ss-admin-access")

    def _mask_email(v):
        v = str(v or "").strip()
        if "@" not in v:
            return "EMPTY"
        left, right = v.split("@", 1)
        return left[:2] + "***@" + right

    result = None
    identity = ""

    if request.method == "POST":
        identity = (
            request.form.get("identity")
            or request.form.get("username_or_email")
            or request.form.get("email")
            or request.form.get("username")
            or ""
        ).strip()

        users = load_users()
        found_username = None
        found_user = None

        for uname, udata in users.items():
            email = str(udata.get("email", "") or "").strip().lower()
            if str(uname).strip().lower() == identity.lower() or email == identity.lower():
                found_username = uname
                found_user = udata
                break

        if found_username and found_user:
            target_email = str(found_user.get("email", "") or "").strip()
            ok, msg = send_mail(
                to_email=target_email,
                subject="EratGuard Forgot Diagnostic",
                body="Bu mesaj geldiyse EratGuard canlı SMTP sistemi bu kullanıcı e-postasına gönderebiliyor."
            ) if target_email else (False, "Kullanıcı email alanı boş")

            result = {
                "account_found": True,
                "matched_user": found_username,
                "target_email_masked": _mask_email(target_email),
                "mail_ok": ok,
                "mail_msg": msg,
            }
        else:
            result = {
                "account_found": False,
                "matched_user": "NONE",
                "target_email_masked": "NONE",
                "mail_ok": False,
                "mail_msg": "Bu identity canlı kullanıcı datasında bulunamadı.",
            }

    html = f"""
<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>EratGuard Admin Forgot Diagnostic</title>
<style>
body{{font-family:Arial,sans-serif;background:#010805;color:#eefaf2;padding:24px}}
.card{{max-width:680px;margin:auto;background:#06170f;border:1px solid rgba(120,255,150,.22);border-radius:22px;padding:24px}}
input,button{{width:100%;box-sizing:border-box;padding:14px;border-radius:14px;margin-top:10px;font-size:16px}}
input{{background:#000;color:#fff;border:1px solid #284}}
button{{border:0;background:linear-gradient(90deg,#00d66f,#18c6e8);color:white;font-weight:800}}
pre{{white-space:pre-wrap;background:#000;padding:16px;border-radius:14px;color:#9f9}}
a{{color:#a9c8ff}}
</style>
</head>
<body>
<div class="card">
<h1>Forgot Mail Diagnostic</h1>
<p>Admin-only canlı teşhis. Kullanıcıya bilgi sızdırmaz.</p>
<form method="post">
<input name="identity" placeholder="Kullanıcı adı veya e-posta" value="{identity}">
<button type="submit">Kontrol Et ve Test Maili Gönder</button>
</form>
<pre>{result if result else "Henüz test yapılmadı."}</pre>
<a href="/admin">← Admin paneline dön</a>
</div>
</body>
</html>
"""
    return html

# ===== ERATGUARD ADMIN FORGOT MAIL DIAGNOSTIC END =====


if __name__ == "__main__":
    ensure_default_user()
    ensure_default_settings()
    port = int(os.getenv("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=False)

@app.route("/activate-license/<target_username>", methods=["POST"])
def activate_license(target_username):
    if not login_required():
        return redirect(url_for("login"))
    if not admin_required():
        return redirect(url_for("index"))

    users = load_users()

    if target_username not in users:
        print("LICENSE_ERROR: kullanıcı yok", target_username, flush=True)
        return redirect(url_for("users"))

    user = users[target_username]

    license_key = generate_unique_license_key(users)

    users[target_username]["license_key"] = license_key
    users[target_username]["expires_at"] = "2026-12-31"
    users[target_username]["active"] = True

    save_users(users)

    print("LICENSE_SUCCESS:", target_username, license_key, flush=True)

    return redirect(url_for("users"))



@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password_live():
    t = load_locale(get_lang())
    cleanup_expired_tokens()

    if request.method == "POST":
        identity = (
            request.form.get("identity")
            or request.form.get("username_or_email")
            or request.form.get("email")
            or request.form.get("username")
            or ""
        ).strip()

        if not identity:
            return render_template(
                "forgot.html",
                success=False,
                message=None,
                reset_link=None,
                reset_code=None,
                error="Lütfen kullanıcı adı veya e-posta girin.",
                t=t,
                lang=get_lang()
            )

        users = load_users()
        username = None
        user = None

        for uname, udata in users.items():
            email = str(udata.get("email", "") or "").strip().lower()
            if str(uname).strip().lower() == identity.lower() or email == identity.lower():
                username = uname
                user = udata
                break

        reset_link = None
        reset_code = None

        def _eg_mask_email(v):
            v = str(v or "").strip()
            if "@" not in v:
                return "EMPTY"
            left, right = v.split("@", 1)
            return (left[:2] + "***@" + right)

        print(
            "FORGOT_DEBUG:",
            "identity_has_at=", ("@" in identity),
            "account_found=", bool(username and user),
            "matched_user=", (str(username)[:2] + "***" if username else "NONE"),
            flush=True
        )

        if username and user:
            raw_token = create_reset_token(username)
            reset_link = url_for("eg_final_reset_password_token", token=raw_token, _external=True)
            reset_code = create_reset_code(username)

            try:
                _ss_titanium_event_for_user(username, "password_reset_requested", {
                    "channel": "e-posta",
                    "status": "created",
                    "source": "forgot_password",
                    "identity_type": "email" if "@" in identity else "username"
                })
            except Exception as e:
                print("PASSWORD_RESET_NOTIFICATION_ERROR:", e, flush=True)

            target_email = str(user.get("email", "") or "").strip()
            if not target_email and "@" in str(username):
                target_email = str(username)

            print("FORGOT_DEBUG_TARGET:", _eg_mask_email(target_email), flush=True)

            if target_email:
                subject = "EratGuard Şifre Sıfırlama"
                body = (
                    f"Merhaba {username}\n\n"
                    f"EratGuard hesabın için şifre sıfırlama isteği oluşturuldu.\n\n"
                    f"Aşağıdaki bağlantı ile yeni şifre oluşturabilirsin:\n"
                    f"{reset_link}\n\n"
                    f"Alternatif olarak 6 haneli kodun: {reset_code}\n"
                    f"Kod ekranı: {url_for('eg_final_reset_password_code', _external=True)}\n\n"
                    f"Bu işlemi sen yapmadıysan bu mesajı yok sayabilirsin.\n"
                )

                try:
                    ok, msg = send_mail(
                        to_email=target_email,
                        subject=subject,
                        body=body
                    )
                    print("Password reset mail:", ok, msg, flush=True)
                except Exception as e:
                    print("Password reset mail error:", e, flush=True)

        # Security: never reveal whether the account exists.
        # Reset code/link must not be displayed on the web page.
        # If an account exists, reset details are sent by email only.
        return render_template(
            "forgot.html",
            success=True,
            message="Bu bilgilere sahip bir hesap varsa sıfırlama bilgileri e-posta ile gönderilecektir.",
            reset_link=None,
            reset_code=None,
            error=None,
            t=t,
            lang=get_lang()
        )

    return render_template(
        "forgot.html",
        success=False,
        message=None,
        reset_link=None,
        reset_code=None,
        error=None,
        t=t,
        lang=get_lang()
    )



@app.route("/radial")
def radial():
    if not login_required():
        return redirect(url_for("login"))

    return render_template("radial_menu.html")


USER_MODULES = {
    "protection": {
        "icon": "🛡️",
        "title": "Koruma Merkezi",
        "description": "SMS tarama, spam filtreleme ve gerçek zamanlı güvenlik motoru tek ekranda.",
        "stats": [
            {"value": "7/24", "label": "Aktif Koruma"},
            {"value": _ss_get_last_scan_time(), "label": "Son Tarama"},
            {"value": "92", "label": "Güven Skoru"},
            {"value": "AI", "label": "Analiz Motoru"}
        ],
        "cards": [
            {
                "title": "Anlık SMS Taraması",
                "text": "Gelen mesajlar risk sinyallerine göre değerlendirilir ve şüpheli içerikler işaretlenir.",
                "features": [
                    {"name": "Gerçek zamanlı tarama", "value": "Açık"},
                    {"name": "Şüpheli içerik işaretleme", "value": "Aktif"},
                    {"name": "Son tarama", "value": "Az önce"},
                    {"name": "Tarama modu", "value": "Otomatik"}
                ]
            },
            {
                "title": "Akıllı Spam Filtresi",
                "text": "Kampanya, oltalama, sahte ödül ve tehlikeli bağlantı içerikleri ayrıştırılır.",
                "features": [
                    {"name": "Oltalama koruması", "value": "Aktif"},
                    {"name": "Sahte ödül filtresi", "value": "Açık"},
                    {"name": "Tehlikeli bağlantı kontrolü", "value": "Hazır"},
                    {"name": "Spam algılama", "value": "Yüksek"}
                ]
            },
            {
                "title": "Koruma Katmanı",
                "text": "Kullanıcı deneyimini bozmadan sessiz ve güçlü bir güvenlik katmanı sağlar.",
                "features": [
                    {"name": "Sessiz koruma", "value": "Açık"},
                    {"name": "Arka plan güvenliği", "value": "Aktif"},
                    {"name": "Risk eşiği", "value": "Yüksek"},
                    {"name": "AI güvenlik modu", "value": "Hazır"}
                ]
            },
            {
                "title": "Güvenli Liste",
                "text": "Güvendiğin kişiler ve servisler için esnek yönetim alanı hazırlanır.",
                "features": [
                    {"name": "Güvenilir kişiler", "value": "Yönet", "href": "/u/safe-list"},
                    {"name": "Beyaz liste", "value": "Hazır", "href": "/u/safe-list"},
                    {"name": "Sistem servisleri", "value": "Korunur"},
                    {"name": "Manuel ekleme", "value": "Aç", "href": "/u/safe-list"}
                ]
            }
        ],
        "rows": [
            {"name": "Koruma Durumu", "value": "Aktif", "detail": "EratGuard koruma motoru açık ve kullanıcı hesabı için güvenlik kontrolü aktif."},
            {"name": "AI Motoru", "value": "Hazır", "detail": "AI analiz katmanı riskli kelime, bağlantı ve dolandırıcılık sinyallerini değerlendirmeye hazır."},
            {"name": "Spam Hassasiyeti", "value": "Yüksek", "detail": "Yüksek hassasiyet modu şüpheli kampanya, sahte ödül ve oltalama içeriklerini daha sıkı kontrol eder."},
            {"name": "Son Kontrol", "value": "Az önce", "detail": "Koruma durumu son oturumda kontrol edildi ve aktif görünüyor."}
        ],
        "primary_label": "",
        "primary_href": ""
    },
    "reports": {
        "icon": "📈",
        "title": "Raporlar",
        "description": "Günlük, haftalık ve aylık güvenlik özetlerini sade grafiklerle takip et.",
        "stats": [
            {"value": "125", "label": "Toplam SMS"},
            {"value": "24", "label": "Engellenen"},
            {"value": "%98.5", "label": "Koruma Oranı"}
        ],
        "cards": [
            {
                "title": "Haftalık Özet",
                "text": "Spam ve güvenli SMS dağılımını tek bakışta gösterir.",
                "features": [
                    {"name": "Toplam SMS", "value": "125"},
                    {"name": "Güvenli SMS", "value": "101"},
                    {"name": "Spam SMS", "value": "24"},
                    {"name": "Koruma oranı", "value": "%98.5"}
                ]
            },
            {
                "title": "Risk Eğilimi",
                "text": "Şüpheli mesaj oranındaki artış veya düşüşleri izler.",
                "features": [
                    {"name": "Bu haftaki risk", "value": "Orta"},
                    {"name": "Geçen haftaya göre", "value": "-%7"},
                    {"name": "Şüpheli bağlantı", "value": "4"},
                    {"name": "Sahte ödül denemesi", "value": "6"}
                ]
            },
            {
                "title": "Engelleme Performansı",
                "text": "EratGuard motorunun kaç mesajı yakaladığını gösterir.",
                "features": [
                    {"name": "Engellenen spam", "value": "24"},
                    {"name": "Şüpheli işaretlenen", "value": "9"},
                    {"name": "Güvenli geçen", "value": "101"},
                    {"name": "Yanlış alarm", "value": "0"}
                ]
            },
            {
                "title": "Premium Raporlama",
                "text": "Gelişmiş rapor alanı için grafik ve dışa aktarma altyapısı hazırlanır.",
                "features": [
                    {"name": "Haftalık rapor", "value": "Hazır"},
                    {"name": "PDF dışa aktar", "value": "Yakında"},
                    {"name": "CSV kayıt", "value": "Yakında"},
                    {"name": "Otomatik özet", "value": "Aktif"}
                ]
            }
        ],
        "rows": [
            {"name": "Güvenli SMS", "value": "%80", "detail": "Bu hafta alınan mesajların büyük bölümü güvenli olarak sınıflandırıldı."},
            {"name": "Spam SMS", "value": "%20", "detail": "EratGuard bu hafta 24 mesajı spam veya riskli içerik olarak işaretledi."},
            {"name": "Rapor Periyodu", "value": "Haftalık", "detail": "Rapor ekranı haftalık özet mantığıyla çalışır. Günlük ve aylık seçenekler sonradan eklenebilir."},
            {"name": "Son Rapor", "value": "1 saat önce", "detail": "Son rapor kısa süre önce oluşturuldu ve güvenlik özeti güncellendi."}
        ],
        "primary_label": "Haftalık Özeti Gör",
        "primary_href": "/u/reports"
    },
    "blocked": {
        "icon": "⛔",
        "title": "Engellenenler",
        "description": "Spam olarak işaretlenen numaraları ve mesajları güvenli şekilde yönet.",
        "stats": [
            {"value": "24", "label": "Engellendi"},
            {"value": "17", "label": "Blok Listesi"},
            {"value": "5", "label": "Yeni Kayıt"}
        ],
        "cards": [
            {
                "title": "Blok Listesi",
                "text": "Engellenen numaralar ve riskli kaynaklar burada toplanır.",
                "features": [
                    {"name": "Engellenen numaralar", "value": "17", "href": "/u/block-list"},
                    {"name": "Riskli göndericiler", "value": "5"},
                    {"name": "Firma adı engelleme", "value": "Hazır"},
                    {"name": "Listeyi yönet", "value": "Aç", "href": "/u/block-list"}
                ]
            },
            {
                "title": "Son Engellenen SMS",
                "text": "En güncel spam denemeleri hızlıca görüntülenir.",
                "features": [
                    {"name": "+90 555 123 45 67", "value": "10 dk önce"},
                    {"name": "Kazandınız kampanyası", "value": "Spam"},
                    {"name": "+90 532 987 65 43", "value": "25 dk önce"},
                    {"name": "Ödül kazandınız", "value": "Riskli"}
                ]
            },
            {
                "title": "Yanlış Pozitif Kontrol",
                "text": "Güvenli mesajlar yanlışlıkla engellendiyse geri alma alanı hazırlanır.",
                "features": [
                    {"name": "Güvenli olarak işaretle", "value": "Hazır"},
                    {"name": "Güvenli listeye taşı", "value": "Aç", "href": "/u/safe-list"},
                    {"name": "Yanlış alarm sayısı", "value": "0"},
                    {"name": "Geri alma modu", "value": "Yakında"}
                ]
            },
            {
                "title": "Kara Liste Yönetimi",
                "text": "Manuel numara ekleme ve kaldırma modülü için temel hazırdır.",
                "features": [
                    {"name": "Manuel numara ekle", "value": "Aç", "href": "/u/block-list"},
                    {"name": "Numara kaldır", "value": "Aç", "href": "/u/block-list"},
                    {"name": "Otomatik kara liste", "value": "Aktif"},
                    {"name": "Kalıcı engel", "value": "Hazır"}
                ]
            }
        ],
        "rows": [
            {"name": "Son Engelleme", "value": "5 dk önce", "detail": "EratGuard son engellemeyi kısa süre önce yaptı. Riskli mesaj blok listesine işlendi."},
            {"name": "Risk Seviyesi", "value": "Orta", "detail": "Son engellenen mesajlarda sahte ödül, kampanya ve şüpheli bağlantı sinyalleri görüldü."},
            {"name": "Liste Durumu", "value": "Aktif", "detail": "Blok listesi aktif. Eklenen numaralar ve riskli göndericiler koruma motoru tarafından dikkate alınır."},
            {"name": "Otomatik Engelleme", "value": "Açık", "detail": "Otomatik engelleme açıkken yüksek riskli mesajlar kullanıcıya düşmeden işaretlenir."}
        ],
        "primary_label": "Blok Listesini Yönet",
        "primary_href": "/u/block-list"
    },
    "analysis": {
        "icon": "🔍",
        "title": "AI Analiz",
        "description": "Mesaj içeriğini risk, dil, bağlantı ve dolandırıcılık sinyallerine göre analiz eder.",
        "stats": [
            {"value": "AI", "label": "Aktif"},
            {"value": "92", "label": "Skor"},
            {"value": "4", "label": "Risk Sinyali"}
        ],
        "cards": [
            {
                "title": "Metin Analizi",
                "text": "SMS içindeki vaat, tehdit, sahte ödül ve aciliyet ifadelerini inceler.",
                "features": [
                    {"name": "SMS analiz ekranı", "value": "Aç", "href": "/u/analysis/check"},
                    {"name": "Aciliyet baskısı", "value": "Kontrol"},
                    {"name": "Sahte ödül dili", "value": "Kontrol"},
                    {"name": "Bilgi isteme riski", "value": "Kontrol"}
                ]
            },
            {
                "title": "Bağlantı Kontrolü",
                "text": "Şüpheli URL ve yönlendirme işaretlerini yakalamaya hazırlanır.",
                "features": [
                    {"name": "Link algılama", "value": "Aktif"},
                    {"name": "Kısa link kontrolü", "value": "Hazır"},
                    {"name": "Şüpheli domain", "value": "Kontrol"},
                    {"name": "Analiz ekranı", "value": "Aç", "href": "/u/analysis/check"}
                ]
            },
            {
                "title": "Risk Skoru",
                "text": "Her mesaja anlaşılır bir güvenlik skoru üretir.",
                "features": [
                    {"name": "0-30", "value": "Güvenli"},
                    {"name": "31-70", "value": "Şüpheli"},
                    {"name": "71-100", "value": "Yüksek Risk"},
                    {"name": "Skor hesaplama", "value": "Aktif"}
                ]
            },
            {
                "title": "AI Geliştirme Alanı",
                "text": "Gelecekte daha gelişmiş model tabanlı analiz için genişletilebilir yapı sağlar.",
                "features": [
                    {"name": "Risk nedeni açıklama", "value": "Hazır"},
                    {"name": "Kelime sinyalleri", "value": "Aktif"},
                    {"name": "Link sinyalleri", "value": "Aktif"},
                    {"name": "Model tabanlı analiz", "value": "Yakında"}
                ]
            }
        ],
        "rows": [
            {"name": "Analiz Motoru", "value": "Çevrim içi", "detail": "SMS metinleri risk kelimeleri, linkler ve dolandırıcılık sinyallerine göre analiz edilir."},
            {"name": "Hassasiyet", "value": "Yüksek", "detail": "Yüksek hassasiyet modu sahte ödül, aciliyet ve bilgi isteme ifadelerini daha sıkı değerlendirir."},
            {"name": "Son Analiz", "value": "Hazır", "detail": "Bir SMS metni girerek anlık risk analizi başlatabilirsin."},
            {"name": "Güven Skoru", "value": "0-100", "detail": "Her analiz sonucunda kullanıcıya anlaşılır bir risk skoru gösterilir."}
        ],
        "primary_label": "SMS Analizi Yap",
        "primary_href": "/u/analysis/check"
    },
    "notifications": {
        "icon": "🔔",
        "title": "Bildirimler",
        "description": "Uyarılar, spam yakalamaları ve önemli sistem bildirimlerini takip et.",
        "stats": [
            {"value": "3", "label": "Bildirim"},
            {"value": "2", "label": "Yeni"},
            {"value": "Açık", "label": "Uyarılar"}
        ],
        "cards": [
            {
                "title": "Anlık Uyarılar",
                "text": "Önemli güvenlik olayları hızlı şekilde gösterilir.",
                "features": [
                    {"name": "Bildirim merkezi", "value": "Aç", "href": "/u/notifications/manage"},
                    {"name": "Güvenlik olayı", "value": "Aktif"},
                    {"name": "Yeni spam alarmı", "value": "Açık"},
                    {"name": "Lisans uyarısı", "value": "Hazır"}
                ]
            },
            {
                "title": "Spam Alarmı",
                "text": "Riskli SMS yakalandığında kullanıcıyı bilgilendirmek için hazırdır.",
                "features": [
                    {"name": "Spam yakalanınca uyar", "value": "Açık", "href": "/u/notifications/manage"},
                    {"name": "Yüksek risk alarmı", "value": "Aktif"},
                    {"name": "Şüpheli SMS bildirimi", "value": "Açık"},
                    {"name": "Alarm hassasiyeti", "value": "Yüksek"}
                ]
            },
            {
                "title": "Sistem Durumu",
                "text": "Koruma motoru ve lisans durumu bildirimleri buradan izlenir.",
                "features": [
                    {"name": "Koruma motoru", "value": "İzleniyor"},
                    {"name": "Lisans durumu", "value": "Aktif"},
                    {"name": "AI motoru", "value": "Hazır"},
                    {"name": "Sistem bildirimi", "value": "Açık"}
                ]
            },
            {
                "title": "Sessiz Mod",
                "text": "Kullanıcı tercihine göre bildirim yoğunluğu ayarlanabilir.",
                "features": [
                    {"name": "Sessiz mod", "value": "Yönet", "href": "/u/notifications/manage"},
                    {"name": "Sadece yüksek risk", "value": "Seçilebilir"},
                    {"name": "Günlük özet", "value": "Hazır"},
                    {"name": "Bildirim yoğunluğu", "value": "Orta"}
                ]
            }
        ],
        "rows": [
            {"name": "Bildirim Durumu", "value": "Açık", "detail": "Bildirimler açıkken EratGuard önemli güvenlik olaylarını kullanıcıya gösterir."},
            {"name": "Yeni Uyarı", "value": "2 adet", "detail": "Okunmamış güvenlik uyarıları ve son spam alarmı burada takip edilir."},
            {"name": "Spam Uyarısı", "value": "Aktif", "detail": "Riskli SMS yakalandığında kullanıcıya anlık uyarı gösterilir."},
            {"name": "Son Bildirim", "value": "15 dk önce", "detail": "Son bildirim kısa süre önce oluşturuldu. Bildirim geçmişi yönetim sayfasından izlenebilir."}
        ],
        "primary_label": "Bildirimleri Yönet",
        "primary_href": "/u/notifications/manage"
    },
    "license": {
        "icon": "🔑",
        "title": "Lisans Merkezi",
        "description": "Premium üyelik, lisans durumu ve hesap yetkilerini tek ekranda yönet.",
        "stats": [
            {"value": "PRO", "label": "Plan"},
            {"value": "Aktif", "label": "Durum"},
            {"value": "2099", "label": "Bitiş"}
        ],
        "cards": [
            {"title": "Premium Durumu", "text": "Hesabın premium özelliklere erişim durumunu gösterir."},
            {"title": "Lisans Anahtarı", "text": "Kullanıcıya özel lisans bilgisi burada yönetilebilir."},
            {"title": "Hesap Yetkisi", "text": "Aktif, pasif veya deneme kullanıcı ayrımı için hazırdır."},
            {"title": "Satın Alma Akışı", "text": "Ödeme ve yükseltme ekranlarına bağlanacak ana merkezdir."}
        ],
        "rows": [
            {"name": "Lisans", "value": "Aktif"},
            {"name": "Plan", "value": "PRO"},
            {"name": "Hesap Tipi", "value": "Kullanıcı"},
            {"name": "Koruma Yetkisi", "value": "Açık"}
        ],
        "primary_label": "Lisansı Kontrol Et",
        "primary_href": "/u/license"
    },
    "settings": {
        "icon": "⚙️",
        "title": "Ayarlar",
        "description": "Koruma hassasiyeti, bildirimler ve hesap tercihlerini düzenle.",
        "stats": [
            {"value": "Açık", "label": "Koruma"},
            {"value": "Yüksek", "label": "Hassasiyet"},
            {"value": "TR", "label": "Dil"}
        ],
        "cards": [
            {
                "title": "Koruma Ayarı",
                "text": "Spam filtre hassasiyetini kullanıcının tercihine göre ayarlama alanı.",
                "features": [
                    {"name": "Koruma ayarları", "value": "Aç", "href": "/u/settings/manage"},
                    {"name": "Koruma durumu", "value": "Yönet"},
                    {"name": "Hassasiyet", "value": "Yüksek"},
                    {"name": "AI koruma modu", "value": "Aktif"}
                ]
            },
            {
                "title": "Bildirim Tercihleri",
                "text": "Hangi olaylarda uyarı gösterileceği buradan yönetilebilir.",
                "features": [
                    {"name": "Bildirim ayarları", "value": "Aç", "href": "/u/notifications/manage"},
                    {"name": "Spam alarmı", "value": "Açık"},
                    {"name": "Sessiz mod", "value": "Yönet"},
                    {"name": "Uyarı seviyesi", "value": "Orta"}
                ]
            },
            {
                "title": "Dil ve Görünüm",
                "text": "Türkçe/İngilizce ve tema tercihleri için altyapı hazırdır.",
                "features": [
                    {"name": "Dil seçimi", "value": "Aç", "href": "/u/settings/manage"},
                    {"name": "Varsayılan dil", "value": "Türkçe"},
                    {"name": "Tema", "value": "Premium Koyu"},
                    {"name": "Mobil görünüm", "value": "Aktif"}
                ]
            },
            {
                "title": "Hesap Güvenliği",
                "text": "Şifre değişimi ve oturum kontrolü için yönlendirme alanıdır.",
                "features": [
                    {"name": "Şifre değiştir", "value": "Aç", "href": "/change-password"},
                    {"name": "Oturumu kapat", "value": "Çık", "href": "/logout"},
                    {"name": "Hesap durumu", "value": "Aktif"},
                    {"name": "Güvenli oturum", "value": "Açık"}
                ]
            }
        ],
        "rows": [
            {"name": "Koruma", "value": "Açık", "detail": "Koruma motoru kullanıcının tercihine göre açık veya kapalı tutulabilir."},
            {"name": "Bildirim", "value": "Açık", "detail": "Bildirimler güvenlik olayları, spam alarmı ve sistem durumu için kullanılabilir."},
            {"name": "Dil", "value": "Türkçe", "detail": "Arayüz dili kullanıcı tercihine göre yönetilebilir."},
            {"name": "Tema", "value": "Premium Koyu", "detail": "EratGuard PRO için koyu premium tema aktif olarak kullanılır."}
        ],
        "primary_label": "Ayarları Aç",
        "primary_href": "/u/settings/manage"
    },
    "community": {
        "icon": "👥",
        "title": "Topluluk",
        "description": "Spam kaynakları, güvenli numaralar ve topluluk katkıları için merkez.",
        "stats": [
            {"value": "Beta", "label": "Durum"},
            {"value": "0", "label": "Katkı"},
            {"value": "Yakında", "label": "Paylaşım"}
        ],
        "cards": [
            {"title": "Topluluk Bildirimi", "text": "Kullanıcıların spam numaraları bildirebileceği alan hazırlanır."},
            {"title": "Güvenli Kaynaklar", "text": "Güvenilir servis numaralarının listelenmesi için uygundur."},
            {"title": "Spam Haritası", "text": "Yoğun spam kaynakları için ileride istatistik alanı eklenebilir."},
            {"title": "Beta Programı", "text": "İlk kullanıcı geri bildirimlerini toplamak için kullanılabilir."}
        ],
        "rows": [
            {"name": "Topluluk Modu", "value": "Beta"},
            {"name": "Paylaşım", "value": "Kapalı"},
            {"name": "Geri Bildirim", "value": "Hazır"},
            {"name": "Durum", "value": "Geliştiriliyor"}
        ],
        "primary_label": "Topluluğu Aç",
        "primary_href": "/u/community"
    },
    "legal": {
        "icon": "⚖️",
        "title": "Telif ve Yasal Bildirim",
        "description": "EratGuard PRO kullanım koşulları, telif bildirimi ve yasal bilgilendirme alanı.",
        "stats": [
            {"value": "2026", "label": "Telif"},
            {"value": "PRO", "label": "Ürün"},
            {"value": "TR", "label": "Bölge"}
        ],
        "cards": [
            {"title": "Telif Hakkı", "text": "EratGuard PRO arayüzü, adı, tasarımı ve yazılım yapısı izinsiz kopyalanamaz."},
            {"title": "Kullanım Sorumluluğu", "text": "Uygulama güvenlik desteği sağlar; kullanıcı kararlarını tamamen devralmaz."},
            {"title": "Veri Güvenliği", "text": "Kullanıcı verilerinin korunması için güvenli akışlar hedeflenir."},
            {"title": "Yasal Bildirim", "text": "Ticari kullanım, dağıtım ve lisanslama sahibinin iznine bağlıdır."}
        ],
        "rows": [
            {"name": "Ürün", "value": "EratGuard PRO"},
            {"name": "Telif", "value": "Tüm hakları saklıdır"},
            {"name": "Sürüm", "value": "Beta"},
            {"name": "Kapsam", "value": "SMS güvenliği"}
        ],
        "primary_label": "Ana Ekrana Dön",
        "primary_href": "/radial"
    }
}


def render_user_module_page(module_key):
    if module_key != "legal" and not login_required():
        return redirect(url_for("login"))

    page = USER_MODULES.get(module_key)
    if not page:
        return redirect(url_for("radial"))

    user_settings = {}
    protection_enabled = True

    if module_key == "protection":
        try:
            username = session.get("username", "user")
            all_settings = load_user_settings_data()
            user_settings = all_settings.get(username, {})
            protection_enabled = user_settings.get("protection_enabled", True)

            page = dict(page)
            page["rows"] = [dict(row) for row in page.get("rows", [])]

            for row in page["rows"]:
                if row.get("name") == "Koruma Durumu":
                    row["value"] = "Açık" if protection_enabled else "Kapalı"
                    row["detail"] = "Koruma açıkken EratGuard gelen mesajları aktif olarak değerlendirir. Kapalıyken sadece kayıt ve görüntüleme yapılır."
                    row["control"] = "protection_toggle"
                    row["enabled"] = protection_enabled
        except Exception:
            protection_enabled = True

    return render_template(
        "user_module.html",
        page=page,
        user_settings=user_settings,
        protection_enabled=protection_enabled
    )


@app.route("/u/protection")
def user_protection():
    return render_user_module_page("protection")


@app.route("/u/reports")
def user_reports():
    if not login_required():
        return redirect(url_for("login"))
    username = session.get("username", "")
    try:
        import json as _j
        logs = _j.load(open("data/spam_logs.json", encoding="utf-8"))
        total_analyzed = len(logs)
        total_spam = sum(1 for r in logs if r.get("status") == "SPAM")
        high_risk = sum(1 for r in logs if r.get("risk", 0) >= 80)
        catch_rate = int(total_spam / total_analyzed * 100) if total_analyzed > 0 else 0
        spam_score = max(0, 100 - catch_rate)
    except:
        total_analyzed = total_spam = high_risk = catch_rate = 0
        spam_score = 92
    return render_template("reports.html",
        username=username,
        total_analyzed=total_analyzed,
        total_spam=total_spam,
        high_risk=high_risk,
        catch_rate=catch_rate,
        spam_score=spam_score
    )


@app.route("/u/blocked")
def user_blocked():
    return render_user_module_page("blocked")


@app.route("/u/analysis")
def user_analysis():
    return render_user_module_page("analysis")


@app.route("/u/notifications")
def user_notifications():
    return render_user_module_page("notifications")


@app.route("/u/license", methods=["GET", "POST"])
def user_license():
    if not login_required():
        return redirect(url_for("login"))

    username = session.get("username", "user")
    users = load_users()
    user = users.get(username, {}) if isinstance(users, dict) else {}

    message = None
    error = None

    if request.method == "POST":
        license_key = (request.form.get("license_key") or "").strip().upper()

        if not license_key:
            error = "Lütfen lisans kodu girin."
        elif len(license_key) < 8:
            error = "Lisans kodu çok kısa görünüyor."
        else:
            user["license_key"] = license_key
            user["license_type"] = "pro"
            user["plan"] = "pro"
            user["active"] = True
            user["expires_at"] = user.get("expires_at") or "2099-12-31"
            users[username] = user
            save_users(users)
            message = "Lisans başarıyla aktifleştirildi."

    license_key = user.get("license_key") or "Yok"
    plan = user.get("license_type") or user.get("plan") or "trial"
    expires_at = user.get("expires_at") or "Belirtilmedi"
    active = user.get("active", True)

    plan_label = "PRO" if str(plan).lower() in ["pro", "premium", "lifetime"] else "Deneme"
    license_status_label = "AKTİF" if active else "PASİF"
    premium_access = "Açık" if active else "Kapalı"

    days_left = "∞"
    if expires_at and expires_at not in ["Belirtilmedi", "2099-12-31", "2099-01-01"]:
        try:
            from datetime import datetime
            exp = datetime.strptime(expires_at[:10], "%Y-%m-%d")
            days_left = max(0, (exp - datetime.now()).days)
        except Exception:
            days_left = "∞"

    return render_template(
        "license_center.html",
        username=username,
        user=user,
        license_key=license_key,
        plan_label=plan_label,
        license_status_label=license_status_label,
        expires_at=expires_at,
        premium_access=premium_access,
        days_left=days_left,
        message=message,
        error=error
    )


@app.route("/u/settings")
def user_settings():
    return render_user_module_page("settings")



@app.route("/u/profile")
def user_profile():
    if not login_required():
        return redirect("/login")
    username = session.get("username", "")
    users = load_users()
    user = users.get(username, {})
    return render_template("profile.html",
        username=username,
        email=user.get("email", ""),
        role=user.get("role", "user"),
        license_key=user.get("license_key", "—"),
        expires_at=user.get("expires_at", "—")
    )

@app.route("/u/community")
def user_community():
    return render_user_module_page("community")

@app.route("/u/community/spam_report", methods=["POST"])
def spam_report():
    if not login_required():
        return redirect("/login")
    import pickle
    from sklearn.feature_extraction.text import CountVectorizer
    from sklearn.naive_bayes import MultinomialNB
    data = request.get_json() or request.form
    number = str(data.get("number", "")).strip()
    body = str(data.get("body", "")).strip()
    if not number or not body:
        return jsonify({"success": False, "error": "Numara ve mesaj gerekli"})
    entry = {
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "number": number,
        "body": body,
        "status": "SPAM",
        "score": 10,
        "reasons": ["community_report"],
        "reported_by": session.get("username", "unknown")
    }
    logs = []
    if os.path.exists("data/spam_logs.json"):
        with open("data/spam_logs.json", "r", encoding="utf-8") as f:
            logs = json.load(f)
    logs.append(entry)
    with open("data/spam_logs.json", "w", encoding="utf-8") as f:
        json.dump(logs, f, ensure_ascii=False, indent=2)
    try:
        texts = [r["body"] for r in logs if "body" in r and r["body"]]
        labels = [1 if r["status"] == "SPAM" else 0 for r in logs if "body" in r and r["body"]]
        if len(texts) >= 10:
            vec = CountVectorizer(ngram_range=(1,2), min_df=1)
            X = vec.fit_transform(texts)
            model = MultinomialNB()
            model.fit(X, labels)
            pickle.dump((vec, model), open("spam_model.pkl", "wb"))
    except Exception:
        pass
    return jsonify({"success": True, "message": "Spam bildirimi alindi, model guncellendi"})




@app.route("/u/legal")
def user_legal():
    return render_user_module_page("legal")



SAFE_LIST_FILE = "data/safe_list.json"


def load_safe_list_data():
    os.makedirs("data", exist_ok=True)
    if not os.path.exists(SAFE_LIST_FILE):
        with open(SAFE_LIST_FILE, "w", encoding="utf-8") as f:
            json.dump({}, f, ensure_ascii=False, indent=2)

    try:
        with open(SAFE_LIST_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_safe_list_data(data):
    os.makedirs("data", exist_ok=True)
    with open(SAFE_LIST_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


@app.route("/u/safe-list", methods=["GET", "POST"])
def user_safe_list():
    if not login_required():
        return redirect(url_for("login"))

    username = session.get("username", "user")
    data = load_safe_list_data()
    items = data.get(username, [])

    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        phone = (request.form.get("phone") or "").strip()

        if name and phone:
            items.append({
                "name": name,
                "phone": phone,
                "created_at": datetime.now().strftime("%Y-%m-%d %H:%M")
            })
            data[username] = items
            save_safe_list_data(data)

        return redirect(url_for("user_safe_list"))

    return render_template("safe_list.html", items=items)


@app.route("/u/safe-list/delete", methods=["POST"])
def user_safe_list_delete():
    if not login_required():
        return redirect(url_for("login"))

    username = session.get("username", "user")
    data = load_safe_list_data()
    items = data.get(username, [])

    try:
        idx = int(request.form.get("idx", "-1"))
    except Exception:
        idx = -1

    if 0 <= idx < len(items):
        items.pop(idx)
        data[username] = items
        save_safe_list_data(data)

    return redirect(url_for("user_safe_list"))


USER_SETTINGS_FILE = "data/user_settings.json"


def load_user_settings_data():
    os.makedirs("data", exist_ok=True)
    if not os.path.exists(USER_SETTINGS_FILE):
        with open(USER_SETTINGS_FILE, "w", encoding="utf-8") as f:
            json.dump({}, f, ensure_ascii=False, indent=2)

    try:
        with open(USER_SETTINGS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_user_settings_data(data):
    os.makedirs("data", exist_ok=True)
    with open(USER_SETTINGS_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


@app.route("/u/protection/toggle", methods=["POST"])
def user_protection_toggle():
    if not login_required():
        return redirect(url_for("login"))

    username = session.get("username", "user")
    enabled = request.form.get("protection_enabled") == "on"

    data = load_user_settings_data()
    user_settings = data.get(username, {})
    user_settings["protection_enabled"] = enabled
    data[username] = user_settings
    save_user_settings_data(data)

    return redirect(url_for("user_protection"))


USER_BLOCK_LIST_FILE = "data/user_block_list.json"


def load_user_block_list_data():
    os.makedirs("data", exist_ok=True)
    if not os.path.exists(USER_BLOCK_LIST_FILE):
        with open(USER_BLOCK_LIST_FILE, "w", encoding="utf-8") as f:
            json.dump({}, f, ensure_ascii=False, indent=2)

    try:
        with open(USER_BLOCK_LIST_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_user_block_list_data(data):
    os.makedirs("data", exist_ok=True)
    with open(USER_BLOCK_LIST_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


@app.route("/u/block-list", methods=["GET", "POST"])
def user_block_list():
    if not login_required():
        return redirect(url_for("login"))

    username = session.get("username", "user")
    data = load_user_block_list_data()
    items = data.get(username, [])

    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        phone = (request.form.get("phone") or "").strip()

        if name and phone:
            items.append({
                "name": name,
                "phone": phone,
                "created_at": datetime.now().strftime("%Y-%m-%d %H:%M")
            })
            data[username] = items
            save_user_block_list_data(data)

        return redirect(url_for("user_block_list"))

    return render_template("block_list.html", items=items)


@app.route("/u/block-list/delete", methods=["POST"])
def user_block_list_delete():
    if not login_required():
        return redirect(url_for("login"))

    username = session.get("username", "user")
    data = load_user_block_list_data()
    items = data.get(username, [])

    try:
        idx = int(request.form.get("idx", "-1"))
    except Exception:
        idx = -1

    if 0 <= idx < len(items):
        items.pop(idx)
        data[username] = items
        save_user_block_list_data(data)

    return redirect(url_for("user_block_list"))


def analyze_sms_text(message):
    text = (message or "").lower()
    score = 10
    reasons = []

    risky_words = [
        "ödül", "kazandınız", "tebrikler", "hemen", "acil", "tıkla",
        "link", "şifre", "kart", "iban", "kampanya", "ücretsiz",
        "onayla", "giriş yap", "hesap", "kargo", "teslimat"
    ]

    high_risk_words = [
        "şifrenizi", "kart bilgisi", "kimlik", "banka", "hesabınız askıya",
        "ödeme başarısız", "para iadesi", "doğrulama kodu"
    ]

    url_signals = ["http://", "https://", "www.", ".com", ".net", ".xyz", "bit.ly", "tinyurl"]

    hit_count = sum(1 for w in risky_words if w in text)
    high_count = sum(1 for w in high_risk_words if w in text)
    has_url = any(u in text for u in url_signals)
    has_urgency = any(w in text for w in ["hemen", "acil", "son gün", "kaçırma", "bugün"])
    has_reward = any(w in text for w in ["ödül", "kazandınız", "tebrikler", "hediye", "kampanya"])
    has_info = any(w in text for w in ["şifre", "kart", "kimlik", "iban", "doğrulama", "giriş yap"])

    score += hit_count * 8
    score += high_count * 14

    if has_url:
        score += 18
        reasons.append("Mesaj içinde bağlantı veya domain benzeri ifade bulundu.")

    if has_urgency:
        score += 12
        reasons.append("Mesaj kullanıcıyı hızlı karar vermeye zorlayan aciliyet dili içeriyor.")

    if has_reward:
        score += 12
        reasons.append("Mesaj ödül, kampanya veya kazanç vaadi içeriyor.")

    if has_info:
        score += 18
        reasons.append("Mesaj kişisel bilgi, şifre, kart veya hesap bilgisi isteme riski taşıyor.")

    if hit_count:
        reasons.append(f"Mesajda {hit_count} adet riskli kelime/sinyal tespit edildi.")

    if not reasons:
        reasons.append("Belirgin bir spam sinyali bulunmadı. Yine de bilinmeyen linklere dikkat edilmelidir.")

    score = max(0, min(100, score))

    if score >= 71:
        label = "Yüksek Risk"
        risk_class = "risk-high"
    elif score >= 31:
        label = "Şüpheli"
        risk_class = "risk-mid"
    else:
        label = "Güvenli Görünüyor"
        risk_class = "risk-low"

    return {
        "score": score,
        "label": label,
        "risk_class": risk_class,
        "link_status": "Şüpheli" if has_url else "Link yok",
        "urgency": "Var" if has_urgency else "Yok",
        "reward": "Var" if has_reward else "Yok",
        "info_request": "Riskli" if has_info else "Yok",
        "reasons": reasons
    }


@app.route("/u/analysis/check", methods=["GET", "POST"])
def user_analysis_check():
    if not login_required():
        return redirect(url_for("login"))

    message = ""
    result = None

    if request.method == "POST":
        message = request.form.get("message", "")
        result = analyze_sms_text(message)

    return render_template("analysis_check.html", message=message, result=result)


USER_NOTIFICATION_SETTINGS_FILE = "data/user_notification_settings.json"


def load_user_notification_settings():
    os.makedirs("data", exist_ok=True)
    if not os.path.exists(USER_NOTIFICATION_SETTINGS_FILE):
        with open(USER_NOTIFICATION_SETTINGS_FILE, "w", encoding="utf-8") as f:
            json.dump({}, f, ensure_ascii=False, indent=2)

    try:
        with open(USER_NOTIFICATION_SETTINGS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_user_notification_settings(data):
    os.makedirs("data", exist_ok=True)
    with open(USER_NOTIFICATION_SETTINGS_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def get_user_notification_settings(username):
    data = load_user_notification_settings()
    default_settings = {
        "notifications_enabled": True,
        "spam_alerts": True,
        "quiet_mode": False,
        "min_risk": "medium"
    }
    user_settings = data.get(username, {})
    default_settings.update(user_settings)
    return default_settings


@app.route("/u/notifications/manage", methods=["GET", "POST"])
def user_notifications_manage():
    if not login_required():
        return redirect(url_for("login"))

    username = session.get("username", "user")
    data = load_user_notification_settings()

    if request.method == "POST":
        data[username] = {
            "notifications_enabled": request.form.get("notifications_enabled") == "on",
            "spam_alerts": request.form.get("spam_alerts") == "on",
            "quiet_mode": request.form.get("quiet_mode") == "on",
            "min_risk": request.form.get("min_risk", "medium")
        }
        save_user_notification_settings(data)
        return redirect(url_for("user_notifications_manage"))

    settings = get_user_notification_settings(username)
    return render_template("notifications_manage.html", settings=settings)


@app.route("/u/settings/manage", methods=["GET", "POST"])
def user_settings_manage():
    if not login_required():
        return redirect(url_for("login"))

    username = session.get("username", "user")
    saved = False

    protection_data = load_user_settings_data()
    notification_data = load_user_notification_settings()

    default_settings = {
        "protection_enabled": True,
        "sensitivity": "high",
        "notifications_enabled": True,
        "spam_alerts": True,
        "quiet_mode": False,
        "language": get_lang(),
        "theme": "premium_dark"
    }

    current = {}
    current.update(default_settings)
    current.update(protection_data.get(username, {}))
    current.update(notification_data.get(username, {}))

    if request.method == "POST":
        current["protection_enabled"] = request.form.get("protection_enabled") == "on"
        current["sensitivity"] = request.form.get("sensitivity", "high")
        current["notifications_enabled"] = request.form.get("notifications_enabled") == "on"
        current["spam_alerts"] = request.form.get("spam_alerts") == "on"
        current["quiet_mode"] = request.form.get("quiet_mode") == "on"
        current["language"] = request.form.get("language", "tr")
        current["theme"] = request.form.get("theme", "premium_dark")

        protection_data[username] = {
            "protection_enabled": current["protection_enabled"],
            "sensitivity": current["sensitivity"],
            "language": current["language"],
            "theme": current["theme"]
        }

        notification_data[username] = {
            "notifications_enabled": current["notifications_enabled"],
            "spam_alerts": current["spam_alerts"],
            "quiet_mode": current["quiet_mode"],
            "min_risk": notification_data.get(username, {}).get("min_risk", "medium")
        }

        save_user_settings_data(protection_data)
        save_user_notification_settings(notification_data)

        session["lang"] = current["language"]
        saved = True

    return render_template(
        "settings_manage.html",
        settings=current,
        username=username,
        saved=saved
    )


@app.route("/u/pricing")
def user_pricing():
    if not login_required():
        return redirect(url_for("login"))
    return render_template("pricing.html")


def get_plan_info(plan):
    plans = {
        "starter_monthly": {
            "label": "Starter Shield",
            "period": "Aylık",
            "price": "150 TL / ay"
        },
        "pro_yearly": {
            "label": "Shield Pro+",
            "period": "Yıllık",
            "price": "1000 TL / yıl"
        },
        "lifetime": {
            "label": "Lifetime Shield",
            "period": "Tek sefer",
            "price": "2000 TL"
        },
        "pro_monthly": {
            "label": "Starter Shield",
            "period": "Aylık",
            "price": "150 TL / ay"
        }
    }
    return plans.get(plan, plans["pro_yearly"])


def _eg_payment_requests_path():
    from pathlib import Path
    data_dir = Path("data")
    data_dir.mkdir(exist_ok=True)
    return data_dir / "payment_requests.json"


def _eg_load_payment_requests():
    import json
    path = _eg_payment_requests_path()
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8") or "[]")
        return data if isinstance(data, list) else []
    except Exception:
        return []


def _eg_save_payment_requests(items):
    import json
    path = _eg_payment_requests_path()
    path.write_text(json.dumps(items, ensure_ascii=False, indent=2), encoding="utf-8")


def _eg_next_order_no():
    from datetime import datetime
    import random
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return f"EG-{stamp}-{random.randint(100,999)}"


@app.route("/u/checkout", methods=["GET", "POST"])
def user_checkout():
    if not login_required():
        return redirect(url_for("login"))

    from datetime import datetime

    username = session.get("username", "user")
    plan = request.values.get("plan", "pro_yearly")
    plan_info = get_plan_info(plan)

    if request.method == "POST":
        email = (request.form.get("email") or "").strip()
        note = (request.form.get("note") or "").strip()
        payment_method = (request.form.get("payment_method") or "manual_transfer").strip()

        requests_data = _eg_load_payment_requests()
        order_no = _eg_next_order_no()

        item = {
            "order_no": order_no,
            "created_at": datetime.now().isoformat(timespec="seconds"),
            "username": username,
            "email": email,
            "plan": plan,
            "plan_label": plan_info["label"],
            "plan_period": plan_info["period"],
            "plan_price": plan_info["price"],
            "payment_method": payment_method,
            "provider": "manual_license_review",
            "status": "payment_waiting",
            "note": note,
            "admin_note": "",
            "license_key": ""
        }

        requests_data.append(item)
        _eg_save_payment_requests(requests_data)

        return redirect(url_for("user_payment_success", order_no=order_no))

    return render_template(
        "checkout.html",
        plan=plan,
        plan_label=plan_info["label"],
        plan_period=plan_info["period"],
        plan_price=plan_info["price"],
        payment_provider="manual_license_review",
        payment_ready=True,
        message="EratGuard PRO lisans talebi oluşturun. Talebiniz için benzersiz sipariş numarası üretilecek ve ödeme onayı sonrası lisansınız hesabınıza tanımlanacaktır."
    )


@app.route("/u/payment-success", methods=["GET", "POST"])
def user_payment_success():
    if not login_required():
        return redirect(url_for("login"))

    username = session.get("username", "user")
    order_no = request.values.get("order_no", "").strip()

    request_item = None
    for item in _eg_load_payment_requests():
        if str(item.get("order_no", "")) == order_no and str(item.get("username", "")) == str(username):
            request_item = item
            break

    if not request_item:
        plan = request.values.get("plan", "pro_yearly")
        plan_info = get_plan_info(plan)
        request_item = {
            "order_no": "Henüz oluşturulmadı",
            "username": username,
            "plan": plan,
            "plan_label": plan_info["label"],
            "plan_price": plan_info["price"],
            "status": "not_created"
        }

    return render_template(
        "payment_success.html",
        saved=True,
        username=username,
        order_no=request_item.get("order_no", ""),
        status=request_item.get("status", "payment_waiting"),
        plan=request_item.get("plan", "pro_yearly"),
        plan_label=request_item.get("plan_label", "EratGuard PRO"),
        plan_price=request_item.get("plan_price", ""),
        license_key=request_item.get("license_key", ""),
        message="Lisans talebiniz kayda alındı. Ödeme bildiriminiz kontrol edildikten sonra lisansınız hesabınıza tanımlanacaktır. Kart bilgileriniz EratGuard tarafından saklanmaz."
    )


@app.route("/u/pay", methods=["GET", "POST"])
def user_pay():
    if not login_required():
        return redirect(url_for("login"))

    plan = request.args.get("plan", "pro_yearly")
    return redirect(url_for("user_checkout", plan=plan))

# ===== SPAMSHIELD LIVE ADMIN APK ROUTES START =====
@app.route("/ss-admin-access", methods=["GET", "POST"])
def ss_live_admin_access():
    from pathlib import Path
    import json
    import os
    import hashlib

    def _read_users():
        p = Path("data/users.json")
        try:
            if p.exists():
                data = json.loads(p.read_text(encoding="utf-8"))
                return data if isinstance(data, dict) else {}
        except Exception:
            pass
        return {}

    def _check_password(raw, stored):
        raw = str(raw or "")
        stored = str(stored or "")

        if not stored:
            return False

        if raw == stored:
            return True

        try:
            from werkzeug.security import check_password_hash
            if stored.startswith(("pbkdf2:", "scrypt:", "sha256:")):
                return check_password_hash(stored, raw)
        except Exception:
            pass

        try:
            if hashlib.sha256(raw.encode()).hexdigest() == stored:
                return True
        except Exception:
            pass

        return False

    if request.method == "POST":
        username = (request.form.get("username") or request.form.get("email") or "").strip()
        password = request.form.get("password") or ""

        users = _read_users()
        user = users.get(username) or users.get(username.lower()) or {}

        env_admin_passwords = [
            os.environ.get("ERATGUARD_ADMIN_PASSWORD", ""),
            os.environ.get("SPAMSHIELD_ADMIN_PASSWORD", ""),
            os.environ.get("ADMIN_PASSWORD", ""),
        ]
        env_admin_passwords = [x for x in env_admin_passwords if x]

        is_admin_name = username.lower() == "admin" or str(user.get("role", "")).lower() == "admin" or user.get("is_admin") is True
        fallback_admin_sha256 = "11b2d8d98c0a8ed79080d388420deb3b3168e5631667cad074d09ee0e26c86fb"
        ok_env = username.lower() == "admin" and password in env_admin_passwords
        ok_fallback = username.lower() == "admin" and hashlib.sha256(password.encode()).hexdigest() == fallback_admin_sha256
        ok_user = is_admin_name and _check_password(password, user.get("password") or user.get("password_hash") or "")

        if ok_env or ok_fallback or ok_user:
            session["logged_in"] = True
            session["username"] = username or "admin"
            session["role"] = "admin"
            session["is_admin"] = True
            return redirect("/admin")

        try:
            return render_template("admin_login.html", error="Admin girişi başarısız.")
        except Exception:
            return "<h2>EratGuard Admin</h2><p>Admin girişi başarısız.</p>", 401

    try:
        return render_template("admin_login.html", error="")
    except Exception:
        return """
        <html><head><meta charset="UTF-8"><title>EratGuard Admin</title></head>
        <body style="background:#020806;color:white;font-family:Arial;padding:24px;">
          <h2>EratGuard ADMIN</h2>
          <form method="post">
            <input name="username" placeholder="admin" style="display:block;margin:10px 0;padding:12px;">
            <input name="password" type="password" placeholder="şifre" style="display:block;margin:10px 0;padding:12px;">
            <button style="padding:12px 18px;">Giriş</button>
          
              <div style="margin-top:14px;text-align:center;">
                <a href="/admin/forgot-mail-diagnostic" style="color:#8cff5a;text-decoration:none;font-weight:800;">Admin şifremi unuttum</a>
                <span style="opacity:.45;margin:0 8px;">|</span>
                <a href="/forgot-password" style="color:#8cff5a;text-decoration:none;">Kullanıcı şifremi unuttum</a>
              </div>
            </form>
        </body></html>
        """




@app.route("/notification-permission")
def notification_permission():
    if not login_required():
        return redirect("/login")
    session["notif_asked"] = True
    username = session.get("username", "")
    if username:
        users = load_users()
        if username in users:
            users[username]["notif_asked"] = True
            import json as _j
            with open(USERS_FILE, "w", encoding="utf-8") as _f:
                _j.dump(users, _f, ensure_ascii=False, indent=2)
    return render_template("notification_permission.html")

@app.route("/onboarding")
def onboarding():
    return render_template("onboarding.html")

@app.route("/app-start")
def user_app_start():
    if session.get("logged_in"):
        return redirect("/radial")
    if not session.get("onboarding_done"):
        return render_template("onboarding.html")
    return render_template("splash_user_app.html")

@app.route("/ss-admin-app-start")
def ss_live_admin_app_start():
    if session.get("logged_in") and (
        session.get("is_admin") or session.get("role") == "admin" or session.get("username") == "admin"
    ):
        return redirect("/admin")
    return redirect("/ss-admin-access")

@app.route("/admin")
@app.route("/admin/")
def ss_live_admin_home():
    if not (
        session.get("logged_in") and (
            session.get("is_admin") or session.get("role") == "admin" or session.get("username") == "admin"
        )
    ):
        return redirect("/ss-admin-access")
    return redirect("/admin/dashboard")

@app.route("/admin/dashboard")
def ss_live_admin_dashboard():
    if not (
        session.get("logged_in") and (
            session.get("is_admin") or session.get("role") == "admin" or session.get("username") == "admin"
        )
    ):
        return redirect("/ss-admin-access")
    try:
        return render_template("admin_dashboard.html")
    except Exception as e:
        return f"<h2>EratGuard ADMIN</h2><p>Dashboard yüklenemedi: {e}</p>", 500

@app.route("/__spamshield_live_version")
def ss_live_version_probe():
    return "EratGuard live: dashboard_web admin routes active 2026-05-05", 200
# ===== SPAMSHIELD LIVE ADMIN APK ROUTES END =====

# ===== SPAMSHIELD ADMIN ALL SLICE SAFE CATCHALL START =====
@app.route("/admin/<path:anything>", methods=["GET", "POST"])
def ss_live_admin_all_slice_catchall(anything):
    # Admin session yoksa admin girişe dön
    if not (
        session.get("logged_in") and (
            session.get("is_admin")
            or session.get("role") == "admin"
            or session.get("username") == "admin"
        )
    ):
        return redirect("/ss-admin-access")

    slug = str(anything or "").strip().lower()

    template_map = {
        "dashboard": ("admin_dashboard.html", {}),
        "panel": ("admin_panel.html", {"users": [], "upgrade_requests": []}),
        "users": ("admin_panel.html", {"users": [], "upgrade_requests": []}),
        "licenses": ("admin_licenses.html", {}),
        "license": ("admin_licenses.html", {}),
        "payment-requests": ("admin_payment_requests.html", {"requests": []}),
        "payments": ("admin_payment_requests.html", {"requests": []}),
        "spam-logs": ("admin_spam_logs.html", {"spam_logs": []}),
        "security": ("admin_spam_logs.html", {"spam_logs": []}),
        "overview": ("admin_overview.html", {"stats": {}, "recent_logs": []}),
        "reports": ("admin_overview.html", {"stats": {}, "recent_logs": []}),
        "whitelist": ("whitelist.html", {"whitelist": []}),
        "notifications": ("whitelist.html", {"whitelist": []}),
        "settings": ("admin_settings.html", {"settings": {}}),
        "system": ("admin_system.html", {}),
    }

    tpl, ctx = template_map.get(slug, ("admin_dashboard.html", {}))

    try:
        return render_template(tpl, **ctx)
    except Exception as e:
        return f"""
        <html><head><meta charset="UTF-8"><title>EratGuard ADMIN</title></head>
        <body style="background:#020806;color:white;font-family:Arial;padding:24px;">
          <h2>EratGuard ADMIN</h2>
          <p>Bu admin bölümü hazırlanıyor: <b>{slug}</b></p>
          <p style="opacity:.7">Detay: {e}</p>
          <p><a style="color:#8cff5a" href="/admin/dashboard">Admin Dashboard'a dön</a></p>
        </body></html>
        """, 200
# ===== SPAMSHIELD ADMIN ALL SLICE SAFE CATCHALL END =====

# ===== SPAMSHIELD FAST ADMIN SLICE PAGES START =====
# DISABLED FINAL:
# Bu blok hafif/placeholder admin ekranlarını aktif ediyordu.
# Gerçek admin template'leri için kapatıldı.
# ===== SPAMSHIELD FAST ADMIN SLICE PAGES END =====


# ===== ERATGUARD USER SESSION TRACKING START =====
def _eg_user_sessions_path():
    from pathlib import Path as _eg_Path
    p = _eg_Path("data/user_sessions.json")
    p.parent.mkdir(parents=True, exist_ok=True)
    return p

def _eg_load_user_sessions():
    local_data = {}
    try:
        import json as _eg_json
        p = _eg_user_sessions_path()
        if p.exists():
            data = _eg_json.loads(p.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                local_data = data
    except Exception:
        local_data = {}

    if _eg_db_enabled():
        db_data = _eg_kv_get_json("user_sessions", None)
        if isinstance(db_data, dict) and db_data:
            return db_data
        if local_data:
            _eg_kv_set_json("user_sessions", local_data)
            return local_data

    return local_data


def _eg_save_user_sessions(data):
    if not isinstance(data, dict):
        data = {}

    if _eg_db_enabled():
        _eg_kv_set_json("user_sessions", data)

    try:
        import json as _eg_json
        p = _eg_user_sessions_path()
        p.write_text(_eg_json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception:
        pass


def _eg_touch_user_session(username, event="activity"):
    try:
        from datetime import datetime as _eg_datetime
        username = str(username or "").strip()
        if not username:
            return

        data = _eg_load_user_sessions()
        now = _eg_datetime.now().isoformat(timespec="seconds")
        item = data.get(username, {}) if isinstance(data.get(username, {}), dict) else {}

        item["username"] = username
        item["last_seen"] = now
        item["last_event"] = event

        try:
            item["last_ip"] = request.headers.get("X-Forwarded-For", request.remote_addr or "").split(",")[0].strip()
            item["user_agent"] = request.headers.get("User-Agent", "")[:180]
        except Exception:
            pass

        if event in ("login", "register"):
            item["last_login"] = now

        data[username] = item
        _eg_save_user_sessions(data)
    except Exception:
        pass

@app.before_request
def _eg_track_logged_user_activity_final():
    try:
        username = session.get("username")
        if not username:
            return None

        path = request.path or ""
        if path.startswith("/static/") or path.startswith("/api/system-resources"):
            return None

        _eg_touch_user_session(username, "activity")
    except Exception:
        pass
    return None
# ===== ERATGUARD USER SESSION TRACKING END =====



# ===== ERATGUARD STRICT USER AUTH GUARD START =====
@app.before_request
def _eg_strict_user_auth_guard_final():
    try:
        path = request.path or ""

        public_paths = {
            "/",
            "/landing",
            "/login",
            "/register",
            "/logout",
            "/forgot-password",
            "/forgot",
            "/reset-password-code",
            "/privacy",
            "/gizlilik",
            "/terms",
            "/mesafeli-satis",
            "/refund",
            "/iade",
            "/contact",
            "/iletisim",
            "/health",
            "/ping",
            "/status",
            "/splash",
            "/app-start",
            "/ss-admin-access",
            "/favicon.ico",
        }

        if path in public_paths:
            return None

        if path.startswith("/static/"):
            return None

        # Public/legal/API health tarafını bozmayalım.
        if path.startswith("/api/system-resources"):
            return None

        # Admin giriş sistemi kendi guard'ını kullansın.
        if path.startswith("/admin") or path.startswith("/ss-admin"):
            return None

        protected_prefixes = (
            "/u",
            "/dashboard",
            "/home",
            "/user",
            "/main",
            "/radial",
            "/protection",
            "/koruma",
            "/reports",
            "/report",
            "/rapor",
            "/blocked",
            "/block",
            "/analysis",
            "/analyze",
            "/analiz",
            "/notifications",
            "/notification",
            "/bildirim",
            "/settings",
            "/ayarlar",
            "/community",
            "/topluluk",
            "/license",
            "/lisans",
            "/pricing",
            "/checkout",
            "/payment",
            "/odeme",
            "/satin-al",
        )

        if path.startswith(protected_prefixes):
            if not session.get("logged_in") or not session.get("username"):
                session.clear()
                return redirect("/login?auth_required=1")

    except Exception as e:
        try:
            print("AUTH_GUARD_WARN:", repr(e), flush=True)
        except Exception:
            pass

    return None
# ===== ERATGUARD STRICT USER AUTH GUARD END =====


# ===== ERATGUARD REAL ADMIN TEMPLATE RESTORE START =====
# Final override: FAST/Hafif admin ekranlarını gerçek admin template'lerine geri bağlar.
try:
    from flask import render_template as _eg_real_render_template
    from flask import redirect as _eg_real_redirect
    from flask import session as _eg_real_session

    def _eg_real_admin_ok():
        try:
            cookie_ok = False
            try:
                cookie_ok = bool(_ss_admin_cookie_ok_final())
            except Exception:
                cookie_ok = False

            return bool(
                cookie_ok or (
                    _eg_real_session.get("logged_in") and (
                        _eg_real_session.get("is_admin")
                        or _eg_real_session.get("role") == "admin"
                        or _eg_real_session.get("username") == "admin"
                    )
                )
            )
        except Exception:
            return False

    def _eg_real_users_list():
        data = globals().get("users", {})
        try:
            loader = globals().get("load_users")
            if callable(loader):
                loaded = loader()
                if loaded:
                    data = loaded
        except Exception:
            pass

        sessions = {}
        try:
            sessions = _eg_load_user_sessions()
        except Exception:
            sessions = {}

        def _is_online(last_seen):
            try:
                from datetime import datetime
                if not last_seen:
                    return False
                dt = datetime.fromisoformat(str(last_seen))
                return (datetime.now() - dt).total_seconds() <= 600
            except Exception:
                return False

        out = []
        if isinstance(data, dict):
            for username, info in data.items():
                item = dict(info) if isinstance(info, dict) else {"value": info}
                sess = sessions.get(username, {}) if isinstance(sessions.get(username, {}), dict) else {}

                item.setdefault("username", username)
                item.setdefault("email", item.get("email", ""))
                item.setdefault("role", item.get("role", "user"))

                item["last_seen"] = sess.get("last_seen") or item.get("last_seen") or "-"
                item["last_login"] = sess.get("last_login") or item.get("last_login") or "-"
                item["last_ip"] = sess.get("last_ip") or item.get("last_ip") or "-"
                item["online"] = _is_online(item.get("last_seen"))

                out.append(item)
        elif isinstance(data, list):
            out = data
        return out

    def _eg_real_render(tpl, **ctx):
        if not _eg_real_admin_ok():
            return _eg_real_redirect("/ss-admin-access")
        return _eg_real_render_template(tpl, **ctx)

    def _eg_real_admin_home():
        if not _eg_real_admin_ok():
            return _eg_real_redirect("/ss-admin-access")
        return _eg_real_redirect("/admin/dashboard")

    def _eg_real_admin_dashboard():
        return _eg_real_render("admin_dashboard.html")

    def _eg_real_admin_panel():
        return _eg_real_render(
            "admin_panel.html",
            users=_eg_real_users_list(),
            upgrade_requests=globals().get("upgrade_requests", []),
        )

    def _eg_real_admin_licenses():
        import json as _eg_json
        from pathlib import Path as _eg_Path

        def _eg_load_json_dict(*paths):
            for raw in paths:
                try:
                    fp = _eg_Path(raw)
                    if fp.exists():
                        data = _eg_json.loads(fp.read_text(encoding="utf-8"))
                        return data if isinstance(data, dict) else {}
                except Exception:
                    pass
            return {}

        users = _eg_load_json_dict(
            "data/users.json",
            "users.json",
        )

        licenses = _eg_load_json_dict(
            "data/generated_licenses.json",
            "data/licenses.json",
            "generated_licenses.json",
            "licenses.json",
        )

        return _eg_real_render(
            "admin_licenses.html",
            users=users,
            licenses=licenses,
            error="",
            success="",
            new_license_key="",
        )

    def _eg_real_load_json(default, *paths):
        import json as _eg_json
        from pathlib import Path as _eg_Path

        for raw in paths:
            try:
                fp = _eg_Path(raw)
                if fp.exists():
                    data = _eg_json.loads(fp.read_text(encoding="utf-8"))
                    return data
            except Exception:
                pass
        return default

    def _eg_real_list_from_json(*paths):
        data = _eg_real_load_json([], *paths)
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            out = []
            for key, value in data.items():
                if isinstance(value, dict):
                    item = dict(value)
                    item.setdefault("id", key)
                    item.setdefault("key", key)
                    out.append(item)
                else:
                    out.append({"id": key, "value": value})
            return out
        return []

    def _eg_real_dict_from_json(*paths):
        data = _eg_real_load_json({}, *paths)
        return data if isinstance(data, dict) else {}

    def _eg_real_admin_payments():
        requests_data = _eg_real_load_json(
            [],
            "data/payment_requests.json",
            "payment_requests.json",
        )
        if isinstance(requests_data, dict):
            requests_data = list(requests_data.values())
        if not isinstance(requests_data, list):
            requests_data = []

        return _eg_real_render(
            "admin_payment_requests.html",
            requests=requests_data,
        )

    def _eg_real_admin_spam_logs():
        spam_logs = _eg_real_load_json(
            [],
            "data/spam_logs.json",
            "data/logs.json",
            "spam_logs.json",
            "logs.json",
        )
        if isinstance(spam_logs, dict):
            spam_logs = list(spam_logs.values())
        if not isinstance(spam_logs, list):
            spam_logs = []

        return _eg_real_render(
            "admin_spam_logs.html",
            spam_logs=spam_logs,
        )

    def _eg_real_settings_dict():
        settings = _eg_real_dict_from_json(
            "data/settings.json",
            "settings.json",
        )

        defaults = {
            "enable_notifications": True,
            "enable_vibration": True,
            "enable_auto_delete": False,
            "sms_limit": 100,
            "poll_interval": 15,
            "spam_threshold": 70,
        }

        for key, value in defaults.items():
            settings.setdefault(key, value)

        return settings

    def _eg_real_admin_overview():
        users_dict = _eg_real_dict_from_json("data/users.json", "users.json")
        spam_logs = _eg_real_load_json([], "data/spam_logs.json", "data/logs.json", "spam_logs.json", "logs.json")
        if isinstance(spam_logs, dict):
            spam_logs = list(spam_logs.values())
        if not isinstance(spam_logs, list):
            spam_logs = []

        settings = _eg_real_settings_dict()

        stats = {
            "total_users": len(users_dict) if isinstance(users_dict, dict) else 0,
            "spam_log_count": len(spam_logs),
            "spam_threshold": settings.get("spam_threshold", 70),
            "sms_limit": settings.get("sms_limit", 100),
            "notifications": bool(settings.get("enable_notifications", True)),
            "vibration": bool(settings.get("enable_vibration", True)),
            "auto_delete": bool(settings.get("enable_auto_delete", False)),
            "poll_interval": settings.get("poll_interval", 15),
        }

        return _eg_real_render(
            "admin_overview.html",
            stats=stats,
            recent_logs=spam_logs[:10],
        )

    def _eg_real_admin_whitelist():
        whitelist_data = _eg_real_load_json(
            [],
            "data/whitelist.json",
            "data/safe_list.json",
            "whitelist.json",
            "safe_list.json",
        )

        if isinstance(whitelist_data, dict):
            whitelist = list(whitelist_data.keys())
        elif isinstance(whitelist_data, list):
            whitelist = whitelist_data
        else:
            whitelist = []

        return _eg_real_render(
            "whitelist.html",
            whitelist=whitelist,
        )

    def _eg_real_admin_settings():
        return _eg_real_render(
            "admin_settings.html",
            settings=_eg_real_settings_dict(),
        )

    def _eg_real_admin_system():
        import sys as _eg_sys
        from pathlib import Path as _eg_Path

        def _state(path):
            try:
                return "OK" if _eg_Path(path).exists() else "YOK"
            except Exception:
                return "YOK"

        return _eg_real_render(
            "admin_system.html",
            mode="PRODUCTION",
            debug_state="KAPALI",
            users_state=_state("data/users.json"),
            licenses_state=_state("data/licenses.json"),
            settings_state=_state("data/settings.json"),
            python_version=_eg_sys.version.split()[0],
        )

    def _eg_real_admin_catchall(anything):
        slug = str(anything or "").strip().lower()
        if slug in ("", "dashboard"):
            return _eg_real_admin_dashboard()
        if slug in ("panel", "users", "user"):
            return _eg_real_admin_panel()
        if slug in ("licenses", "license", "generated-licenses"):
            return _eg_real_admin_licenses()
        if slug in ("payment-requests", "payments", "payment"):
            return _eg_real_admin_payments()
        if slug in ("spam-logs", "security"):
            return _eg_real_admin_spam_logs()
        if slug in ("overview", "reports"):
            return _eg_real_admin_overview()
        if slug in ("whitelist", "notifications"):
            return _eg_real_admin_whitelist()
        if slug == "settings":
            return _eg_real_admin_settings()
        if slug == "system":
            return _eg_real_admin_system()
        return _eg_real_admin_dashboard()

    _real_override_map = {
        "ss_live_admin_home": _eg_real_admin_home,
        "ss_live_admin_dashboard": _eg_real_admin_dashboard,
        "ss_live_admin_panel_alias": _eg_real_admin_panel,
        "ss_live_admin_licenses_alias": _eg_real_admin_licenses,
        "ss_live_admin_payment_requests_alias": _eg_real_admin_payments,
        "ss_live_admin_spam_logs_alias": _eg_real_admin_spam_logs,
        "ss_live_admin_overview_alias": _eg_real_admin_overview,
        "ss_live_admin_whitelist_alias": _eg_real_admin_whitelist,
        "ss_live_admin_settings_alias": _eg_real_admin_settings,
        "ss_live_admin_system_alias": _eg_real_admin_system,
        "ss_live_admin_all_slice_catchall": _eg_real_admin_catchall,
    }

    for _ep, _fn in _real_override_map.items():
        if _ep in app.view_functions:
            app.view_functions[_ep] = _fn

except Exception as _eg_real_admin_restore_error:
    print("REAL ADMIN TEMPLATE RESTORE ERROR:", _eg_real_admin_restore_error, flush=True)
# ===== ERATGUARD REAL ADMIN TEMPLATE RESTORE END =====


# ===== ERATGUARD FINAL SESSION SECRET LOCK START =====
try:
    import os as _ss_final_os
    from pathlib import Path as _ss_final_Path

    _ss_final_secret_file = _ss_final_Path("data/.eratguard_secret_key")
    _ss_final_secret_file.parent.mkdir(parents=True, exist_ok=True)

    if not _ss_final_secret_file.exists():
        _ss_final_secret_file.write_text(
            "eratguard-final-stable-session-secret-2026-admin-mobile",
            encoding="utf-8"
        )

    app.secret_key = (
        _ss_final_os.environ.get("FLASK_SECRET_KEY")
        or _ss_final_os.environ.get("SECRET_KEY")
        or _ss_final_os.environ.get("ERATGUARD_SECRET_KEY") or os.environ.get("SPAMSHIELD_SECRET_KEY")
        or _ss_final_secret_file.read_text(encoding="utf-8").strip()
        or "eratguard-final-stable-session-secret-2026-admin-mobile"
    )
    app.config["SECRET_KEY"] = app.secret_key
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
except Exception:
    app.secret_key = "eratguard-final-stable-session-secret-2026-admin-mobile"
    app.config["SECRET_KEY"] = app.secret_key
# ===== ERATGUARD FINAL SESSION SECRET LOCK END =====


# ===== ERATGUARD ADMIN SIGNED COOKIE FALLBACK START =====
def _ss_admin_cookie_secret_final():
    try:
        import os
        return (
            os.environ.get("FLASK_SECRET_KEY")
            or os.environ.get("SECRET_KEY")
            or os.environ.get("ERATGUARD_SECRET_KEY") or os.environ.get("SPAMSHIELD_SECRET_KEY")
            or "eratguard-final-stable-session-secret-2026-admin-mobile"
        )
    except Exception:
        return "eratguard-final-stable-session-secret-2026-admin-mobile"

def _ss_admin_cookie_token_final():
    import hmac
    import hashlib
    secret = _ss_admin_cookie_secret_final().encode("utf-8")
    return hmac.new(secret, b"eratguard-admin-mobile-ok", hashlib.sha256).hexdigest()

def _ss_admin_cookie_ok_final():
    try:
        return request.cookies.get("ss_admin_mobile") == _ss_admin_cookie_token_final()
    except Exception:
        return False

# Eski admin kontrol fonksiyonlarını cookie fallback ile güçlendir
def _ss_admin_ok():
    return bool(
        _ss_admin_cookie_ok_final()
        or (
            session.get("logged_in") and (
                session.get("is_admin")
                or session.get("role") == "admin"
                or session.get("username") == "admin"
            )
        )
    )

def _ss_admin_logged_in_final():
    return _ss_admin_ok()

# Admin login endpointini imzalı cookie basacak şekilde override et
def _ss_admin_access_cookie_override():
    from pathlib import Path
    import json
    import os
    import hashlib

    def _read_users():
        p = Path("data/users.json")
        try:
            if p.exists():
                data = json.loads(p.read_text(encoding="utf-8"))
                return data if isinstance(data, dict) else {}
        except Exception:
            pass
        return {}

    def _check_password(raw, stored):
        raw = str(raw or "")
        stored = str(stored or "")

        if not stored:
            return False

        if raw == stored:
            return True

        try:
            from werkzeug.security import check_password_hash
            if stored.startswith(("pbkdf2:", "scrypt:", "sha256:")):
                return check_password_hash(stored, raw)
        except Exception:
            pass

        try:
            if hashlib.sha256(raw.encode()).hexdigest() == stored:
                return True
        except Exception:
            pass

        return False

    if request.method == "POST":
        username = (request.form.get("username") or request.form.get("email") or "").strip()
        password = request.form.get("password") or ""

        users = _read_users()
        user = users.get(username) or users.get(username.lower()) or {}

        env_admin_passwords = [
            os.environ.get("ERATGUARD_ADMIN_PASSWORD", ""),
            os.environ.get("SPAMSHIELD_ADMIN_PASSWORD", ""),
            os.environ.get("ADMIN_PASSWORD", ""),
        ]
        env_admin_passwords = [x for x in env_admin_passwords if x]
        fallback_admin_sha256 = "11b2d8d98c0a8ed79080d388420deb3b3168e5631667cad074d09ee0e26c86fb"

        is_admin_name = (
            username.lower() == "admin"
            or str(user.get("role", "")).lower() == "admin"
            or user.get("is_admin") is True
        )

        ok_env = username.lower() == "admin" and password in env_admin_passwords
        ok_fallback = username.lower() == "admin" and hashlib.sha256(password.encode()).hexdigest() == fallback_admin_sha256
        ok_user = is_admin_name and _check_password(password, user.get("password") or user.get("password_hash") or "")

        if ok_env or ok_fallback or ok_user:
            session["logged_in"] = True
            session["username"] = username or "admin"
            session["role"] = "admin"
            session["is_admin"] = True

            resp = redirect("/admin")
            resp.set_cookie(
                "ss_admin_mobile",
                _ss_admin_cookie_token_final(),
                max_age=60 * 60 * 24 * 30,
                httponly=True,
                secure=True,
                samesite="Lax",
                path="/"
            )
            return resp

        try:
            return render_template("admin_login.html", error="Admin girişi başarısız.")
        except Exception:
            return "<h2>EratGuard Admin</h2><p>Admin girişi başarısız.</p>", 401

    try:
        return render_template("admin_login.html", error="")
    except Exception:
        return """
        <html><head><meta charset="UTF-8"><title>EratGuard Admin</title></head>
        <body style="background:#020806;color:white;font-family:Arial;padding:24px;">
          <h2>EratGuard ADMIN</h2>
          <form method="post">
            <input name="username" placeholder="admin" style="display:block;margin:10px 0;padding:12px;">
            <input name="password" type="password" placeholder="şifre" style="display:block;margin:10px 0;padding:12px;">
            <button style="padding:12px 18px;">Giriş</button>
          
              <div style="margin-top:14px;text-align:center;">
                <a href="/admin/forgot-mail-diagnostic" style="color:#8cff5a;text-decoration:none;font-weight:800;">Admin şifremi unuttum</a>
                <span style="opacity:.45;margin:0 8px;">|</span>
                <a href="/forgot-password" style="color:#8cff5a;text-decoration:none;">Kullanıcı şifremi unuttum</a>
              </div>
</form>
        </body></html>
        """

if "ss_live_admin_access" in app.view_functions:
    app.view_functions["ss_live_admin_access"] = _ss_admin_access_cookie_override
# ===== ERATGUARD ADMIN SIGNED COOKIE FALLBACK END =====

# ===== SPAMSHIELD USER FINAL ROUTE ALIAS + HOME LOCK START =====
from flask import render_template_string as _ss_user_render_template_string

def _ss_user_logged_in_final():
    return bool(session.get("logged_in") and session.get("username"))

def _ss_user_require_login_redirect():
    if not _ss_user_logged_in_final():
        return redirect("/login")
    return None

def _ss_user_home_final():
    need = _ss_user_require_login_redirect()
    if need:
        return need

    username = session.get("username", "kullanıcı")

    # Gerçek veriler
    try:
        import json as _j
        _logs = _j.load(open("data/spam_logs.json", encoding="utf-8"))
        spam_count = sum(1 for r in _logs if r.get("status") == "SPAM")
    except:
        spam_count = 0
    try:
        _block = _j.load(open("data/blocklist.json", encoding="utf-8"))
        blocked_count = len(_block)
    except:
        blocked_count = 0

    return _ss_user_render_template_string("""
<!doctype html>
<html lang="tr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
  <title>EratGuard PRO</title>
  <style>
    :root{
      --bg:#020806;
      --panel:#06170f;
      --panel2:#092519;
      --line:rgba(35,255,137,.24);
      --green:#20ff88;
      --green2:#8cff5a;
      --text:#f5fff8;
      --muted:rgba(245,255,248,.68);
    }
    *{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
    body{
      margin:0;
      min-height:100vh;
      background:
        radial-gradient(circle at 50% 10%,rgba(32,255,136,.18),transparent 30%),
        radial-gradient(circle at 80% 80%,rgba(140,255,90,.12),transparent 28%),
        linear-gradient(180deg,#010403,#03150d 55%,#010403);
      color:var(--text);
      font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",Arial,sans-serif;
      padding:12px;
      overflow-x:hidden;
    }
    .top{
      display:flex;
      align-items:center;
      justify-content:space-between;
      gap:10px;
      margin-bottom:12px;
    }
    .brand{
      display:flex;
      align-items:center;
      gap:10px;
    }
    .logo{
      width:48px;
      height:48px;
      border-radius:15px;
      display:grid;
      place-items:center;
      background:linear-gradient(145deg,rgba(32,255,136,.2),rgba(32,255,136,.04));
      border:1px solid var(--line);
      box-shadow:0 0 24px rgba(32,255,136,.16);
      font-size:17px;
    }
    h1{
      margin:0;
      font-size:27px;
      line-height:1;
      letter-spacing:-1px;
    }
    h1 span{color:var(--green2)}
    .sub{
      margin-top:6px;
      color:var(--muted);
      font-weight:700;
      font-size:11px;
    }
    .badge{
      color:var(--green);
      border:1px solid var(--line);
      background:rgba(32,255,136,.08);
      border-radius:999px;
      padding:8px 10px;
      font-weight:900;
      white-space:nowrap; max-width:118px; overflow:hidden; text-overflow:ellipsis; text-align:center;
    }
    .hero{
      border:1px solid var(--line);
      background:linear-gradient(145deg,rgba(7,31,20,.94),rgba(3,14,9,.88));
      border-radius:21px;
      padding:16px;
      box-shadow:0 20px 50px rgba(0,0,0,.35), inset 0 0 45px rgba(32,255,136,.04);
      margin-bottom:22px;
    }
    .hero h2{
      margin:0 0 10px;
      font-size:19px;
      line-height:1.08;
      letter-spacing:-1px;
    }
    .hero h2 span{color:var(--green)}
    .hero p{
      margin:0;
      color:var(--muted);
      font-size:14px;
      line-height:1.45;
      font-weight:700;
    }
    .stats{
      display:grid;
      grid-template-columns:repeat(3,1fr);
      gap:10px;
      margin-top:13px;
    }
    .stat{
      border:1px solid rgba(32,255,136,.16);
      background:rgba(0,0,0,.18);
      border-radius:19px;
      padding:10px 7px;
      text-align:center;
    }
    .stat b{
      color:var(--green);
      display:block;
      font-size:17px;
      line-height:1;
    }
    .stat span{
      color:var(--muted);
      display:block;
      margin-top:6px;
      font-weight:800;
      font-size:11px;
    }
    .section{
      margin:15px 0 8px;
      letter-spacing:6px;
      font-weight:1000;
      font-size:17px;
    }
    .bar{
      width:84px;
      height:5px;
      border-radius:999px;
      background:linear-gradient(90deg,var(--green),var(--green2));
      margin-bottom:12px;
    }
    .grid{
      display:grid;
      grid-template-columns:1fr 1fr;
      gap:10px;
    }
    .card{
      min-height:108px;
      display:flex;
      flex-direction:column;
      justify-content:space-between;
      text-decoration:none;
      color:var(--text);
      border:1px solid var(--line);
      background:linear-gradient(145deg,rgba(8,35,23,.96),rgba(2,13,8,.9));
      border-radius:19px;
      padding:12px;
      box-shadow:0 14px 34px rgba(0,0,0,.25);
    }
    .icon{
      width:40px;
      height:40px;
      border-radius:15px;
      display:grid;
      place-items:center;
      background:rgba(32,255,136,.10);
      border:1px solid rgba(32,255,136,.18);
      font-size:19px;
    }
    .pill{
      align-self:flex-end;
      margin-top:-40px;
      color:#8affb1;
      border:1px solid rgba(32,255,136,.24);
      background:rgba(32,255,136,.10);
      border-radius:999px;
      padding:5px 9px;
      font-size:11px;
      font-weight:900;
    }
    .card h3{
      margin:10px 0 2px;
      font-size:19px;
      line-height:1.05;
    }
    .card p{
      margin:0;
      color:var(--muted);
      font-weight:800;
      font-size:11px;
      line-height:1.35;
    }
    .foot{
      text-align:center;
      color:rgba(245,255,248,.42);
      font-weight:700;
      padding:20px 0 8px;
      font-size:11px;
    }
  </style>
</head>
<body>
  <div class="top">
    <div class="brand">
      <div class="logo">🛡️</div>
      <div>
        <h1>Erat<span>Guard</span></h1>
        <div class="sub">AI Spam Koruma Sistemi</div>
      </div>
    </div>
    <a href="/u/profile" class="badge" style="text-decoration:none;cursor:pointer;">👑 {{ username }}</a>
  </div>

  <section class="hero">
    <h2>Kontrol sende,<br><span>koruma aktif.</span></h2>
    <p>AI spam analizi, lisans ve güvenlik modülleri tek ekranda.</p>
    <div class="stats">
      <div class="stat"><b>{{ spam_count }}</b><span>Spam</span></div>
      <div class="stat"><b>{{ blocked_count }}</b><span>Engellenen</span></div>
      <div class="stat"><b>AI</b><span>Aktif</span></div>
    </div>
  </section>

  <div class="section">MODÜLLER</div>
  <div class="bar"></div>

  <main class="grid">
    <a class="card" href="/u/protection">
      <div class="icon">🛡️</div><div class="pill">Aktif</div>
      <h3>Koruma</h3><p>SMS güvenlik motoru</p>
    </a>

    <a class="card" href="/u/reports">
      <div class="icon">📈</div><div class="pill">Hazır</div>
      <h3>Rapor</h3><p>Güvenlik özetleri</p>
    </a>

    <a class="card" href="/u/blocked">
      <div class="icon">⛔</div><div class="pill">17</div>
      <h3>Engel</h3><p>Blok listesi</p>
    </a>

    <a class="card" href="/u/analysis">
      <div class="icon">🔍</div><div class="pill">AI</div>
      <h3>Analiz</h3><p>AI risk analizi</p>
    </a>

    <a class="card" href="/u/notifications">
      <div class="icon">🔔</div><div class="pill">Açık</div>
      <h3>Bildirim</h3><p>Uyarılar</p>
    </a>

    <a class="card" href="/u/license">
      <div class="icon">🔑</div><div class="pill">Pro</div>
      <h3>Lisans</h3><p>Hesap durumu</p>
    </a>

    <a class="card" href="/u/settings">
      <div class="icon">⚙️</div><div class="pill">Ayar</div>
      <h3>Ayarlar</h3><p>Tercihler</p>
    </a>

    <a class="card" href="/u/community">
      <div class="icon">👥</div><div class="pill">Beta</div>
      <h3>Topluluk</h3><p>Geri bildirim</p>
    </a>
  </main>

  <div class="foot">EratGuard PRO · {{ username }} · © 2026</div>
</body>
</html>
""", username=username, spam_count=spam_count, blocked_count=blocked_count)

# /radial endpointini temiz kartlı kullanıcı ana ekranına kilitle
try:
    for _rule in list(app.url_map.iter_rules()):
        if str(_rule) == "/radial":
            pass  # serbest birakild
except Exception:
    pass

# Eski / çıplak kullanıcı yolları doğru /u/... sayfalarına yönlendir
@app.route("/dashboard")
@app.route("/home")
@app.route("/user")
@app.route("/main")
def ss_user_alias_home_final():
    return _ss_user_home_final()

@app.route("/protection")
@app.route("/koruma")
def ss_user_alias_protection_final():
    return redirect("/u/protection")

@app.route("/reports")
@app.route("/report")
@app.route("/rapor")
@app.route("/raporlar")
def ss_user_alias_reports_final():
    return redirect("/u/reports")

@app.route("/blocked")
@app.route("/block")
@app.route("/engel")
@app.route("/engellenenler")
def ss_user_alias_blocked_final():
    return redirect("/u/blocked")

@app.route("/analysis")
@app.route("/analyze")
@app.route("/analiz")
def ss_user_alias_analysis_final():
    return redirect("/u/analysis")

@app.route("/notifications")
@app.route("/notification")
@app.route("/bildirim")
@app.route("/bildirimler")
def ss_user_alias_notifications_final():
    return redirect("/u/notifications")

@app.route("/settings")
@app.route("/ayarlar")
@app.route("/ayar")
def ss_user_alias_settings_final():
    return redirect("/u/settings")

@app.route("/community")
@app.route("/topluluk")
def ss_user_alias_community_final():
    return redirect("/u/community")

@app.route("/license")
@app.route("/lisans")
def ss_user_alias_license_final():
    return redirect("/u/license")

@app.route("/pricing")
@app.route("/packages")
@app.route("/paketler")
@app.route("/fiyatlandirma")
def ss_user_alias_pricing_final():
    return render_template("pricing.html")

@app.route("/checkout", methods=["GET", "POST"])
@app.route("/payment", methods=["GET", "POST"])
@app.route("/odeme", methods=["GET", "POST"])
@app.route("/satin-al", methods=["GET", "POST"])
def ss_public_checkout_final():
    plan = request.args.get("plan", "pro_yearly")

    plan_aliases = {
        "monthly": "pro_monthly",
        "aylik": "pro_monthly",
        "yearly": "pro_yearly",
        "yillik": "pro_yearly",
        "annual": "pro_yearly",
        "lifetime": "lifetime",
        "omurluk": "lifetime",
    }

    plan = plan_aliases.get(plan, plan)
    plan_info = get_plan_info(plan)

    payment_link = "/u/pay?plan=" + plan

    return render_template(
        "checkout.html",
        plan=plan,
        plan_label=plan_info["label"],
        plan_period=plan_info["period"],
        plan_price=plan_info["price"],
        payment_link=payment_link
    )
# ===== SPAMSHIELD USER FINAL ROUTE ALIAS + HOME LOCK END =====

# ===== SPAMSHIELD USER SETTINGS OVERRIDE FINAL START =====
def _ss_user_settings_redirect_final():
    return redirect("/u/settings")

try:
    for _rule in list(app.url_map.iter_rules()):
        if str(_rule) in ["/settings", "/ayarlar", "/ayar"]:
            app.view_functions[_rule.endpoint] = _ss_user_settings_redirect_final
except Exception:
    pass
# ===== SPAMSHIELD USER SETTINGS OVERRIDE FINAL END =====

# ===== SPAMSHIELD REMOVE USER RADIAL KEEP CARD HOME START =====
def _ss_user_card_home_locked_response():
    resp = _ss_user_home_final()
    try:
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        resp.headers["Pragma"] = "no-cache"
        resp.headers["Expires"] = "0"
    except Exception:
        pass
    return resp

# User tarafında radial/radial-menu/radial-demo dahil tüm eski kullanıcı ana ekranlarını kartlı ekrana kilitle.
try:
    for _rule in list(app.url_map.iter_rules()):
        if str(_rule) in [
            "/radial",
            "/radial-menu",
            "/radial-demo",
            "/dashboard",
            "/home",
            "/user",
            "/main",
            "/u/home",
            "/u/dashboard"
        ]:
            app.view_functions[_rule.endpoint] = _ss_user_card_home_locked_response
except Exception:
    pass

# Bazı route'lar hiç yoksa burada da garanti alias ver.
@app.route("/u/home-final")
def ss_user_card_home_final_alias():
    return _ss_user_card_home_locked_response()
# ===== SPAMSHIELD REMOVE USER RADIAL KEEP CARD HOME END =====

# ===== SPAMSHIELD RESTORE ADMIN RADIAL HOME FINAL START =====
def _ss_admin_radial_home_final():
    if not _ss_admin_ok():
        return redirect("/ss-admin-access")

    try:
        resp = render_template("admin_dashboard.html")
    except Exception as e:
        return f"""
        <html><head><meta charset="UTF-8"><title>EratGuard ADMIN</title></head>
        <body style="background:#020806;color:white;font-family:Arial;padding:24px;">
          <h2>EratGuard ADMIN</h2>
          <p>Admin radial dashboard yüklenemedi.</p>
          <p style="opacity:.7">Detay: {e}</p>
        </body></html>
        """, 200

    try:
        response = make_response(resp)
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        return response
    except Exception:
        return resp

# Admin ana ekranı tekrar radial dashboard olsun.
try:
    for _rule in list(app.url_map.iter_rules()):
        if str(_rule) in ["/admin", "/admin/", "/admin/dashboard"]:
            app.view_functions[_rule.endpoint] = _ss_admin_radial_home_final
except Exception:
    pass

# Catchall içinde sadece dashboard/admin ana sayfa radial olsun, diğer dilimler hızlı kalabilir.
try:
    if "ss_live_admin_all_slice_catchall" in app.view_functions:
        _old_admin_catchall_final = app.view_functions["ss_live_admin_all_slice_catchall"]

        def _ss_admin_catchall_radial_dashboard_final(anything):
            slug = str(anything or "").strip().lower()
            if slug in ("", "dashboard", "home", "main"):
                return _ss_admin_radial_home_final()
            return _old_admin_catchall_final(anything)

        app.view_functions["ss_live_admin_all_slice_catchall"] = _ss_admin_catchall_radial_dashboard_final
except Exception:
    pass
# ===== SPAMSHIELD RESTORE ADMIN RADIAL HOME FINAL END =====

# ===== SPAMSHIELD USER PROTECTION COMPACT FINAL START =====
from flask import render_template_string as _ss_protection_render_template_string
from flask import make_response as _ss_protection_make_response

def _ss_user_protection_compact_final():
    if not (session.get("logged_in") and session.get("username")):
        return redirect("/login")

    username = session.get("username", "kullanıcı")

    html = """
<!doctype html>
<html lang="tr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
  <title>EratGuard PRO • Koruma</title>
  <style>
    :root{
      --bg:#020806;
      --panel:#06170f;
      --panel2:#0a2418;
      --line:rgba(35,255,137,.22);
      --green:#20ff88;
      --green2:#8cff5a;
      --text:#f5fff8;
      --muted:rgba(245,255,248,.66);
    }
    *{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
    body{
      margin:0;
      min-height:100vh;
      background:
        radial-gradient(circle at 50% 0%,rgba(32,255,136,.14),transparent 32%),
        radial-gradient(circle at 88% 76%,rgba(140,255,90,.10),transparent 28%),
        linear-gradient(180deg,#010403,#03150d 58%,#010403);
      color:var(--text);
      font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",Arial,sans-serif;
      padding:14px;
      overflow-x:hidden;
    }
    .top{
      display:flex;
      align-items:center;
      justify-content:space-between;
      gap:10px;
      margin-bottom:14px;
    }
    .brand{display:flex;align-items:center;gap:10px;min-width:0}
    .logo{
      width:46px;height:46px;border-radius:16px;
      display:grid;place-items:center;
      background:linear-gradient(145deg,rgba(32,255,136,.18),rgba(32,255,136,.04));
      border:1px solid var(--line);
      box-shadow:0 0 20px rgba(32,255,136,.14);
      font-size:24px;
      flex:0 0 auto;
    }
    h1{margin:0;font-size:27px;line-height:1;letter-spacing:-1px}
    h1 span{color:var(--green2)}
    .sub{margin-top:5px;color:var(--muted);font-weight:800;font-size:12px}
    .badge{
      color:var(--green);
      border:1px solid var(--line);
      background:rgba(32,255,136,.08);
      border-radius:999px;
      padding:8px 10px;
      font-weight:950;
      font-size:12px;
      white-space:nowrap;
    }

    .hero{
      position:relative;
      overflow:hidden;
      border:1px solid var(--line);
      background:linear-gradient(145deg,rgba(8,35,23,.94),rgba(2,13,8,.92));
      border-radius:22px;
      padding:16px;
      box-shadow:0 18px 44px rgba(0,0,0,.34), inset 0 0 42px rgba(32,255,136,.04);
      margin-bottom:18px;
    }
    .hero:after{
      content:"";
      position:absolute;
      right:-55px;
      top:-60px;
      width:170px;
      height:170px;
      border-radius:50%;
      background:rgba(32,255,136,.08);
      filter:blur(1px);
    }
    .hero-icon{
      width:48px;height:48px;border-radius:16px;
      display:grid;place-items:center;
      background:rgba(32,255,136,.10);
      border:1px solid rgba(32,255,136,.18);
      font-size:25px;
      margin-bottom:13px;
      position:relative;
      z-index:1;
    }
    .hero h2{
      margin:0 0 9px;
      font-size:28px;
      line-height:1.05;
      letter-spacing:-1px;
      position:relative;
      z-index:1;
    }
    .hero p{
      margin:0;
      color:var(--muted);
      font-size:14px;
      line-height:1.42;
      font-weight:800;
      position:relative;
      z-index:1;
    }
    .stats{
      display:grid;
      grid-template-columns:repeat(3,1fr);
      gap:9px;
      margin-top:15px;
      position:relative;
      z-index:1;
    }
    .stat{
      border:1px solid rgba(32,255,136,.15);
      background:rgba(0,0,0,.17);
      border-radius:17px;
      padding:10px 7px;
      text-align:center;
    }
    .stat b{display:block;color:var(--green);font-size:20px;line-height:1}
    .stat span{display:block;margin-top:6px;color:var(--muted);font-weight:900;font-size:10px}

    .section{
      margin:17px 0 8px;
      letter-spacing:6px;
      font-weight:1000;
      font-size:16px;
    }
    .bar{
      width:82px;height:5px;border-radius:999px;
      background:linear-gradient(90deg,var(--green),var(--green2));
      margin-bottom:11px;
    }

    .list{display:grid;gap:10px}
    .info-card{
      display:grid;
      grid-template-columns:1fr auto;
      align-items:center;
      gap:10px;
      text-decoration:none;
      color:var(--text);
      border:1px solid var(--line);
      background:linear-gradient(145deg,rgba(8,35,23,.92),rgba(2,13,8,.9));
      border-radius:19px;
      padding:14px;
      min-height:88px;
    }
    .info-card h3{
      margin:0 0 6px;
      font-size:20px;
      line-height:1.05;
    }
    .info-card p{
      margin:0;
      color:var(--muted);
      font-weight:800;
      font-size:12px;
      line-height:1.35;
    }
    .plus{
      width:38px;height:38px;border-radius:999px;
      display:grid;place-items:center;
      color:#9affb9;
      border:1px solid rgba(32,255,136,.22);
      background:rgba(32,255,136,.09);
      font-size:22px;
      font-weight:900;
    }

    .status{
      border:1px solid var(--line);
      background:linear-gradient(145deg,rgba(8,35,23,.92),rgba(2,13,8,.9));
      border-radius:21px;
      padding:6px 14px;
    }
    .row{
      display:grid;
      grid-template-columns:1fr auto auto;
      align-items:center;
      gap:10px;
      padding:13px 0;
      border-bottom:1px solid rgba(245,255,248,.07);
    }
    .row:last-child{border-bottom:0}
    .row b{font-size:15px}
    .row span{color:#98ffb8;font-weight:950;font-size:13px}
    .mini-plus{
      width:30px;height:30px;border-radius:999px;
      display:grid;place-items:center;
      color:#9affb9;
      border:1px solid rgba(32,255,136,.22);
      background:rgba(32,255,136,.09);
      font-weight:950;
    }

    .back{
      display:flex;
      align-items:center;
      justify-content:center;
      min-height:52px;
      margin-top:14px;
      border-radius:18px;
      color:var(--text);
      text-decoration:none;
      font-weight:950;
      font-size:16px;
      background:rgba(255,255,255,.07);
      border:1px solid rgba(255,255,255,.12);
    }
    .foot{
      text-align:center;
      color:rgba(245,255,248,.38);
      font-weight:800;
      padding:22px 0 8px;
      font-size:12px;
    }
  </style>
</head>
<body>
  <div class="top">
    <div class="brand">
      <div class="logo">🛡️</div>
      <div>
        <h1>Erat<span>Guard</span></h1>
        <div class="sub">PRO güvenlik merkezi</div>
      </div>
    </div>
    <div class="badge">👑 PRO AKTİF</div>
  </div>

  <section class="hero">
    <div class="hero-icon">🛡️</div>
    <h2>Koruma Merkezi</h2>
    <p>SMS tarama, spam filtreleme ve AI güvenlik motoru tek ekranda.</p>

    <div class="stats">
      <div class="stat"><b>7/24</b><span>Koruma</span></div>
      <div class="stat"><b>92</b><span>Skor</span></div>
      <div class="stat"><b>AI</b><span>Hazır</span></div>
    </div>

    <a class="back" href="/radial">← Ana ekrana dön</a>
  </section>

  <div class="section">DETAYLAR</div>
  <div class="bar"></div>

  <main class="list">
    <div class="info-card">
      <div>
        <h3>Anlık SMS Taraması</h3>
        <p>Gelen mesajlar risk sinyallerine göre değerlendirilir.</p>
      </div>
    </div>

    <div class="info-card">
      <div>
        <h3>Akıllı Spam Filtresi</h3>
        <p>Kampanya, oltalama ve tehlikeli bağlantılar ayrıştırılır.</p>
      </div>
    </div>

    <div class="info-card">
      <div>
        <h3>Koruma Katmanı</h3>
        <p>Kullanıcı deneyimini bozmadan sessiz güvenlik sağlar.</p>
      </div>
    </div>

    <div class="info-card">
      <div>
        <h3>Güvenli Liste</h3>
        <p>Güvendiğin kişiler ve servisler esnek şekilde yönetilir.</p>
      </div>
    </div>
  </main>

  <div class="section">DURUM</div>
  <div class="bar"></div>

  <section class="status">
    <div class="row"><b>Koruma Durumu</b><span>Açık</span><div class="mini-plus">+</div></div>
    <div class="row"><b>AI Motoru</b><span>Hazır</span><div class="mini-plus">+</div></div>
    <div class="row"><b>Spam Hassasiyeti</b><span>Yüksek</span><div class="mini-plus">+</div></div>
    <div class="row"><b>Son Kontrol</b><span>Az önce</span><div class="mini-plus">+</div></div>
  </section>

  <div class="foot">EratGuard PRO · {{ username }} · © 2026</div>
</body>
</html>
"""
    resp = _ss_protection_make_response(_ss_protection_render_template_string(html, username=username))
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp

try:
    for _rule in list(app.url_map.iter_rules()):
        if str(_rule) == "/u/protection":
            app.view_functions[_rule.endpoint] = _ss_user_protection_compact_final
except Exception:
    pass
# ===== SPAMSHIELD USER PROTECTION COMPACT FINAL END =====

# ===== SPAMSHIELD USER ANALYSIS COMPACT FINAL START =====
from flask import render_template_string as _ss_analysis_render_template_string
from flask import make_response as _ss_analysis_make_response

def _ss_user_analysis_compact_final():
    if not (session.get("logged_in") and session.get("username")):
        return redirect("/login")

    username = session.get("username", "kullanıcı")

    html = """
<!doctype html>
<html lang="tr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
  <title>EratGuard PRO • AI Analiz</title>
  <style>
    :root{
      --bg:#020806;
      --line:rgba(35,255,137,.22);
      --green:#20ff88;
      --green2:#8cff5a;
      --text:#f5fff8;
      --muted:rgba(245,255,248,.66);
    }
    *{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
    body{
      margin:0;
      min-height:100vh;
      background:
        radial-gradient(circle at 50% 0%,rgba(32,255,136,.14),transparent 32%),
        radial-gradient(circle at 88% 76%,rgba(140,255,90,.10),transparent 28%),
        linear-gradient(180deg,#010403,#03150d 58%,#010403);
      color:var(--text);
      font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",Arial,sans-serif;
      padding:14px;
      overflow-x:hidden;
    }
    .top{
      display:flex;
      align-items:center;
      justify-content:space-between;
      gap:10px;
      margin-bottom:14px;
    }
    .brand{display:flex;align-items:center;gap:10px;min-width:0}
    .logo{
      width:46px;height:46px;border-radius:16px;
      display:grid;place-items:center;
      background:linear-gradient(145deg,rgba(32,255,136,.18),rgba(32,255,136,.04));
      border:1px solid var(--line);
      box-shadow:0 0 20px rgba(32,255,136,.14);
      font-size:24px;
      flex:0 0 auto;
    }
    h1{margin:0;font-size:27px;line-height:1;letter-spacing:-1px}
    h1 span{color:var(--green2)}
    .sub{margin-top:5px;color:var(--muted);font-weight:800;font-size:12px}
    .badge{
      color:var(--green);
      border:1px solid var(--line);
      background:rgba(32,255,136,.08);
      border-radius:999px;
      padding:8px 10px;
      font-weight:950;
      font-size:12px;
      white-space:nowrap;
    }

    .hero{
      position:relative;
      overflow:hidden;
      border:1px solid var(--line);
      background:linear-gradient(145deg,rgba(8,35,23,.94),rgba(2,13,8,.92));
      border-radius:22px;
      padding:16px;
      box-shadow:0 18px 44px rgba(0,0,0,.34), inset 0 0 42px rgba(32,255,136,.04);
      margin-bottom:18px;
    }
    .hero:after{
      content:"";
      position:absolute;
      right:-55px;
      top:-60px;
      width:170px;
      height:170px;
      border-radius:50%;
      background:rgba(32,255,136,.08);
    }
    .hero-icon{
      width:48px;height:48px;border-radius:16px;
      display:grid;place-items:center;
      background:rgba(32,255,136,.10);
      border:1px solid rgba(32,255,136,.18);
      font-size:25px;
      margin-bottom:13px;
      position:relative;
      z-index:1;
    }
    .hero h2{
      margin:0 0 9px;
      font-size:28px;
      line-height:1.05;
      letter-spacing:-1px;
      position:relative;
      z-index:1;
    }
    .hero p{
      margin:0;
      color:var(--muted);
      font-size:14px;
      line-height:1.42;
      font-weight:800;
      position:relative;
      z-index:1;
    }
    .stats{
      display:grid;
      grid-template-columns:repeat(3,1fr);
      gap:9px;
      margin-top:15px;
      position:relative;
      z-index:1;
    }
    .stat{
      border:1px solid rgba(32,255,136,.15);
      background:rgba(0,0,0,.17);
      border-radius:17px;
      padding:10px 7px;
      text-align:center;
    }
    .stat b{display:block;color:var(--green);font-size:20px;line-height:1}
    .stat span{display:block;margin-top:6px;color:var(--muted);font-weight:900;font-size:10px}

    .primary{
      display:flex;
      align-items:center;
      justify-content:center;
      min-height:50px;
      margin-top:14px;
      border-radius:18px;
      color:#02120b;
      text-decoration:none;
      font-weight:1000;
      font-size:16px;
      background:linear-gradient(135deg,#00c860,#00e676);
      position:relative;
      z-index:1;
    }
    .back{
      display:flex;
      align-items:center;
      justify-content:center;
      min-height:48px;
      margin-top:10px;
      border-radius:17px;
      color:var(--text);
      text-decoration:none;
      font-weight:950;
      font-size:15px;
      background:rgba(255,255,255,.07);
      border:1px solid rgba(255,255,255,.12);
      position:relative;
      z-index:1;
    }

    .section{
      margin:17px 0 8px;
      letter-spacing:6px;
      font-weight:1000;
      font-size:16px;
    }
    .bar{
      width:82px;height:5px;border-radius:999px;
      background:linear-gradient(90deg,var(--green),var(--green2));
      margin-bottom:11px;
    }

    .list{display:grid;gap:10px}
    .info-card{
      display:grid;
      grid-template-columns:1fr auto;
      align-items:center;
      gap:10px;
      text-decoration:none;
      color:var(--text);
      border:1px solid var(--line);
      background:linear-gradient(145deg,rgba(8,35,23,.92),rgba(2,13,8,.9));
      border-radius:19px;
      padding:14px;
      min-height:88px;
    }
    .info-card h3{
      margin:0 0 6px;
      font-size:20px;
      line-height:1.05;
    }
    .info-card p{
      margin:0;
      color:var(--muted);
      font-weight:800;
      font-size:12px;
      line-height:1.35;
    }
    .plus{
      width:38px;height:38px;border-radius:999px;
      display:grid;place-items:center;
      color:#9affb9;
      border:1px solid rgba(32,255,136,.22);
      background:rgba(32,255,136,.09);
      font-size:22px;
      font-weight:900;
    }

    .status{
      border:1px solid var(--line);
      background:linear-gradient(145deg,rgba(8,35,23,.92),rgba(2,13,8,.9));
      border-radius:21px;
      padding:6px 14px;
    }
    .row{
      display:grid;
      grid-template-columns:1fr auto auto;
      align-items:center;
      gap:10px;
      padding:13px 0;
      border-bottom:1px solid rgba(245,255,248,.07);
    }
    .row:last-child{border-bottom:0}
    .row b{font-size:15px}
    .row span{color:#98ffb8;font-weight:950;font-size:13px}
    .mini-plus{
      width:30px;height:30px;border-radius:999px;
      display:grid;place-items:center;
      color:#9affb9;
      border:1px solid rgba(32,255,136,.22);
      background:rgba(32,255,136,.09);
      font-weight:950;
    }
    .foot{
      text-align:center;
      color:rgba(245,255,248,.38);
      font-weight:800;
      padding:22px 0 8px;
      font-size:12px;
    }
  </style>
</head>
<body>
  <div class="top">
    <div class="brand">
      <div class="logo">🛡️</div>
      <div>
        <h1>Erat<span>Guard</span></h1>
        <div class="sub">PRO güvenlik merkezi</div>
      </div>
    </div>
    <div class="badge">👑 PRO AKTİF</div>
  </div>

  <section class="hero">
    <div class="hero-icon">🔍</div>
    <h2>AI Analiz</h2>
    <p>Mesaj içeriğini risk, dil, bağlantı ve dolandırıcılık sinyallerine göre analiz eder.</p>

    <div class="stats">
      <div class="stat"><b>AI</b><span>Aktif</span></div>
      <div class="stat"><b>92</b><span>Skor</span></div>
      <div class="stat"><b>4</b><span>Risk</span></div>
    </div>

    <a class="primary" href="/u/analysis/check">SMS Analizi Yap</a>
    <a class="back" href="/radial">← Ana ekrana dön</a>
  </section>

  <div class="section">DETAYLAR</div>
  <div class="bar"></div>

  <main class="list">
    <div class="info-card">
      <div>
        <h3>Metin Analizi</h3>
        <p>Vaat, tehdit, sahte ödül ve aciliyet ifadelerini inceler.</p>
      </div>
    </div>

    <div class="info-card">
      <div>
        <h3>Bağlantı Kontrolü</h3>
        <p>Şüpheli URL ve yönlendirme işaretlerini yakalamaya hazırlanır.</p>
      </div>
    </div>

    <div class="info-card">
      <div>
        <h3>Risk Skoru</h3>
        <p>Her mesaja anlaşılır bir güvenlik skoru üretir.</p>
      </div>
    </div>

    <div class="info-card">
      <div>
        <h3>AI Geliştirme Alanı</h3>
        <p>Gelecekte daha gelişmiş analiz modeli için hazır yapı sağlar.</p>
      </div>
    </div>
  </main>

  <div class="section">DURUM</div>
  <div class="bar"></div>

  <section class="status">
    <div class="row"><b>Analiz Motoru</b><span>Çevrim içi</span><div class="mini-plus">+</div></div>
    <div class="row"><b>Hassasiyet</b><span>Yüksek</span><div class="mini-plus">+</div></div>
    <div class="row"><b>Son Analiz</b><span>Hazır</span><div class="mini-plus">+</div></div>
    <div class="row"><b>Güven Skoru</b><span>0-100</span><div class="mini-plus">+</div></div>
  </section>

  <div class="foot">EratGuard PRO · {{ username }} · © 2026</div>
</body>
</html>
"""
    resp = _ss_analysis_make_response(_ss_analysis_render_template_string(html, username=username))
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp

try:
    for _rule in list(app.url_map.iter_rules()):
        if str(_rule) == "/u/analysis":
            app.view_functions[_rule.endpoint] = _ss_user_analysis_compact_final
except Exception:
    pass
# ===== SPAMSHIELD USER ANALYSIS COMPACT FINAL END =====

# ===== SPAMSHIELD USER BLOCKED COMPACT FINAL START =====
from flask import render_template_string as _ss_blocked_render_template_string
from flask import make_response as _ss_blocked_make_response

def _ss_user_blocked_compact_final():
    if not (session.get("logged_in") and session.get("username")):
        return redirect("/login")

    username = session.get("username", "kullanıcı")

    html = """
<!doctype html>
<html lang="tr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
  <title>EratGuard PRO • Engellenenler</title>
  <style>
    :root{
      --bg:#020806;
      --line:rgba(35,255,137,.22);
      --green:#20ff88;
      --green2:#8cff5a;
      --text:#f5fff8;
      --muted:rgba(245,255,248,.66);
    }
    *{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
    body{
      margin:0;
      min-height:100vh;
      background:
        radial-gradient(circle at 50% 0%,rgba(32,255,136,.14),transparent 32%),
        radial-gradient(circle at 88% 76%,rgba(140,255,90,.10),transparent 28%),
        linear-gradient(180deg,#010403,#03150d 58%,#010403);
      color:var(--text);
      font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",Arial,sans-serif;
      padding:14px;
      overflow-x:hidden;
    }
    .top{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:14px}
    .brand{display:flex;align-items:center;gap:10px;min-width:0}
    .logo{
      width:46px;height:46px;border-radius:16px;
      display:grid;place-items:center;
      background:linear-gradient(145deg,rgba(32,255,136,.18),rgba(32,255,136,.04));
      border:1px solid var(--line);
      box-shadow:0 0 20px rgba(32,255,136,.14);
      font-size:24px;
      flex:0 0 auto;
    }
    h1{margin:0;font-size:27px;line-height:1;letter-spacing:-1px}
    h1 span{color:var(--green2)}
    .sub{margin-top:5px;color:var(--muted);font-weight:800;font-size:12px}
    .badge{
      color:var(--green);
      border:1px solid var(--line);
      background:rgba(32,255,136,.08);
      border-radius:999px;
      padding:8px 10px;
      font-weight:950;
      font-size:12px;
      white-space:nowrap;
    }

    .hero{
      position:relative;
      overflow:hidden;
      border:1px solid var(--line);
      background:linear-gradient(145deg,rgba(8,35,23,.94),rgba(2,13,8,.92));
      border-radius:22px;
      padding:16px;
      box-shadow:0 18px 44px rgba(0,0,0,.34), inset 0 0 42px rgba(32,255,136,.04);
      margin-bottom:18px;
    }
    .hero:after{
      content:"";
      position:absolute;
      right:-55px;
      top:-60px;
      width:170px;
      height:170px;
      border-radius:50%;
      background:rgba(32,255,136,.08);
    }
    .hero-icon{
      width:48px;height:48px;border-radius:16px;
      display:grid;place-items:center;
      background:rgba(32,255,136,.10);
      border:1px solid rgba(32,255,136,.18);
      font-size:25px;
      margin-bottom:13px;
      position:relative;
      z-index:1;
    }
    .hero h2{
      margin:0 0 9px;
      font-size:28px;
      line-height:1.05;
      letter-spacing:-1px;
      position:relative;
      z-index:1;
    }
    .hero p{
      margin:0;
      color:var(--muted);
      font-size:14px;
      line-height:1.42;
      font-weight:800;
      position:relative;
      z-index:1;
    }
    .stats{
      display:grid;
      grid-template-columns:repeat(3,1fr);
      gap:9px;
      margin-top:15px;
      position:relative;
      z-index:1;
    }
    .stat{
      border:1px solid rgba(32,255,136,.15);
      background:rgba(0,0,0,.17);
      border-radius:17px;
      padding:10px 7px;
      text-align:center;
    }
    .stat b{display:block;color:var(--green);font-size:20px;line-height:1}
    .stat span{display:block;margin-top:6px;color:var(--muted);font-weight:900;font-size:10px}

    .primary{
      display:flex;
      align-items:center;
      justify-content:center;
      min-height:50px;
      margin-top:14px;
      border-radius:18px;
      color:#02120b;
      text-decoration:none;
      font-weight:1000;
      font-size:16px;
      background:linear-gradient(135deg,#00c860,#00e676);
      position:relative;
      z-index:1;
    }
    .back{
      display:flex;
      align-items:center;
      justify-content:center;
      min-height:48px;
      margin-top:10px;
      border-radius:17px;
      color:var(--text);
      text-decoration:none;
      font-weight:950;
      font-size:15px;
      background:rgba(255,255,255,.07);
      border:1px solid rgba(255,255,255,.12);
      position:relative;
      z-index:1;
    }

    .section{margin:17px 0 8px;letter-spacing:6px;font-weight:1000;font-size:16px}
    .bar{
      width:82px;height:5px;border-radius:999px;
      background:linear-gradient(90deg,var(--green),var(--green2));
      margin-bottom:11px;
    }
    .list{display:grid;gap:10px}
    .info-card{
      display:grid;
      grid-template-columns:1fr auto;
      align-items:center;
      gap:10px;
      text-decoration:none;
      color:var(--text);
      border:1px solid var(--line);
      background:linear-gradient(145deg,rgba(8,35,23,.92),rgba(2,13,8,.9));
      border-radius:19px;
      padding:14px;
      min-height:88px;
    }
    .info-card h3{margin:0 0 6px;font-size:20px;line-height:1.05}
    .info-card p{margin:0;color:var(--muted);font-weight:800;font-size:12px;line-height:1.35}
    .plus{
      width:38px;height:38px;border-radius:999px;
      display:grid;place-items:center;
      color:#9affb9;
      border:1px solid rgba(32,255,136,.22);
      background:rgba(32,255,136,.09);
      font-size:22px;
      font-weight:900;
    }

    .status{
      border:1px solid var(--line);
      background:linear-gradient(145deg,rgba(8,35,23,.92),rgba(2,13,8,.9));
      border-radius:21px;
      padding:6px 14px;
    }
    .row{
      display:grid;
      grid-template-columns:1fr auto auto;
      align-items:center;
      gap:10px;
      padding:13px 0;
      border-bottom:1px solid rgba(245,255,248,.07);
    }
    .row:last-child{border-bottom:0}
    .row b{font-size:15px}
    .row span{color:#98ffb8;font-weight:950;font-size:13px}
    .mini-plus{
      width:30px;height:30px;border-radius:999px;
      display:grid;place-items:center;
      color:#9affb9;
      border:1px solid rgba(32,255,136,.22);
      background:rgba(32,255,136,.09);
      font-weight:950;
    }
    .foot{text-align:center;color:rgba(245,255,248,.38);font-weight:800;padding:22px 0 8px;font-size:12px}
  </style>
</head>
<body>
  <div class="top">
    <div class="brand">
      <div class="logo">🛡️</div>
      <div>
        <h1>Erat<span>Guard</span></h1>
        <div class="sub">PRO güvenlik merkezi</div>
      </div>
    </div>
    <div class="badge">👑 PRO AKTİF</div>
  </div>

  <section class="hero">
    <div class="hero-icon">⛔</div>
    <h2>Engellenenler</h2>
    <p>Spam olarak işaretlenen numara ve mesajları güvenli şekilde yönet.</p>

    <div class="stats">
      <div class="stat"><b>24</b><span>Engelli</span></div>
      <div class="stat"><b>17</b><span>Liste</span></div>
      <div class="stat"><b>5</b><span>Yeni</span></div>
    </div>

    <a class="primary" href="/u/block-list">Blok Listesini Yönet</a>
    <a class="back" href="/radial">← Ana ekrana dön</a>
  </section>

  <div class="section">DETAYLAR</div>
  <div class="bar"></div>

  <main class="list">
    <div class="info-card">
      <div>
        <h3>Blok Listesi</h3>
        <p>Spam gönderen numara ve servisleri tek ekrandan yönet.</p>
      </div>
    </div>

    <div class="info-card">
      <div>
        <h3>Riskli İçerik</h3>
        <p>Şüpheli mesajlar analiz edilip engel listesine hazırlanır.</p>
      </div>
    </div>

    <div class="info-card">
      <div>
        <h3>Güvenli Liste</h3>
        <p>Güvendiğin kişiler yanlışlıkla engellenmesin.</p>
      </div>
    </div>

    <div class="info-card">
      <div>
        <h3>Engel Raporları</h3>
        <p>Engellenen mesajlar ve son hareketler özetlenir.</p>
      </div>
    </div>
  </main>

  <div class="section">DURUM</div>
  <div class="bar"></div>

  <section class="status">
    <div class="row"><b>Blok Sistemi</b><span>Aktif</span><div class="mini-plus">+</div></div>
    <div class="row"><b>Yeni Kayıt</b><span>5</span><div class="mini-plus">+</div></div>
    <div class="row"><b>Spam Hassasiyeti</b><span>Yüksek</span><div class="mini-plus">+</div></div>
    <div class="row"><b>Son Güncelleme</b><span>Az önce</span><div class="mini-plus">+</div></div>
  </section>

  <div class="foot">EratGuard PRO · {{ username }} · © 2026</div>
</body>
</html>
"""
    resp = _ss_blocked_make_response(_ss_blocked_render_template_string(html, username=username))
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp

try:
    for _rule in list(app.url_map.iter_rules()):
        if str(_rule) == "/u/blocked":
            app.view_functions[_rule.endpoint] = _ss_user_blocked_compact_final
except Exception:
    pass
# ===== SPAMSHIELD USER BLOCKED COMPACT FINAL END =====



# ===== SPAMSHIELD USER TITANIUM CORE START =====
from flask import request as _ss_titanium_request
from flask import jsonify as _ss_titanium_jsonify
from datetime import datetime as _ss_titanium_datetime
from pathlib import Path as _ss_titanium_Path
import json as _ss_titanium_json
import re as _ss_titanium_re

_SS_TITANIUM_DATA = _ss_titanium_Path("data")
_SS_TITANIUM_DATA.mkdir(exist_ok=True)

_SS_QUARANTINE_FILE = _SS_TITANIUM_DATA / "user_quarantine.json"
_SS_ANALYSIS_HISTORY_FILE = _SS_TITANIUM_DATA / "user_analysis_history.json"
_SS_TITANIUM_EVENTS_FILE = _SS_TITANIUM_DATA / "user_titanium_events.json"

def _ss_titanium_now():
    return _ss_titanium_datetime.now().isoformat(timespec="seconds")

def _ss_titanium_read_json(path, default):
    try:
        if not path.exists():
            return default
        return _ss_titanium_json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default

def _ss_titanium_write_json(path, data):
    path.parent.mkdir(exist_ok=True)
    path.write_text(
        _ss_titanium_json.dumps(data, ensure_ascii=False, indent=2),
        encoding="utf-8"
    )

def _ss_titanium_user_ok():
    return bool(session.get("logged_in") and session.get("username"))

def _ss_titanium_username():
    return str(session.get("username") or "kullanıcı")

def _ss_titanium_event(event_type, payload=None):
    events = _ss_titanium_read_json(_SS_TITANIUM_EVENTS_FILE, [])
    events.append({
        "created_at": _ss_titanium_now(),
        "username": _ss_titanium_username(),
        "event_type": event_type,
        "payload": payload or {}
    })
    _ss_titanium_write_json(_SS_TITANIUM_EVENTS_FILE, events[-300:])

def _ss_titanium_event_for_user(username, event_type, payload=None):
    try:
        target_username = str(username or "").strip()
        if not target_username:
            return False

        events = _ss_titanium_read_json(_SS_TITANIUM_EVENTS_FILE, [])
        events.append({
            "created_at": _ss_titanium_now(),
            "username": target_username,
            "event_type": event_type,
            "payload": payload or {}
        })
        _ss_titanium_write_json(_SS_TITANIUM_EVENTS_FILE, events[-300:])
        return True
    except Exception as e:
        print("TITANIUM_EVENT_FOR_USER_ERROR:", e, flush=True)
        return False

def _ss_titanium_analyze_sms(text):
    raw = str(text or "").strip()
    lowered = raw.lower()

    # EratGuard hardened analyzer bridge:
    # Kullanıcı paneli, APK WebView ve Titanium scan aynı güçlendirilmiş motoru kullansın.
    if not raw:
        return {
            "text": raw,
            "score": 0,
            "status": "empty",
            "label": "Boş mesaj",
            "recommended_action": "none",
            "summary": "Analiz için SMS metni gerekli.",
            "signals": ["SMS metni girilmedi."],
        }

    try:
        from analyzer import analyze_sms as _eg_hardened_analyze_sms

        hardened = _eg_hardened_analyze_sms("USER", raw)
        h_status = str(hardened.get("status", "")).upper()
        h_score = int(hardened.get("score", 0) or 0)
        h_category = str(hardened.get("category", "GENEL") or "GENEL")
        h_reason = str(hardened.get("reason", "") or "")

        if h_status == "SPAM":
            if h_score >= 60:
                status = "riskli"
                label = "Riskli"
                action = "quarantine"
                summary = "Mesaj yüksek riskli görünüyor. Karantinaya alınması önerilir."
            else:
                status = "supheli"
                label = "Şüpheli"
                action = "review"
                summary = "Mesaj şüpheli sinyaller taşıyor. Kullanıcı onayıyla incelenmelidir."
        else:
            status = "guvenli"
            label = "Güvenli"
            action = "safe"
            summary = "Belirgin spam/dolandırıcılık sinyali düşük görünüyor."

        signals = []
        if h_category:
            signals.append("Kategori: " + h_category)

        if h_reason and h_reason != "CLEAN":
            for part in h_reason.split(" + "):
                part = part.strip()
                if part:
                    signals.append("Sinyal: " + part)

        if not signals:
            signals.append("Belirgin risk sinyali bulunamadı")

        return {
            "text": raw,
            "score": max(0, min(h_score, 100)),
            "status": status,
            "label": label,
            "recommended_action": action,
            "summary": summary,
            "signals": signals[:8],
        }

    except Exception as _eg_hardened_err:
        print("HARDENED_ANALYZER_BRIDGE_ERROR:", _eg_hardened_err, flush=True)

    signals = []
    score = 0

    risky_keywords = {
        "ödül": 18,
        "kazandınız": 24,
        "kazandin": 24,
        "kazandiniz": 24,
        "hediye": 15,
        "ücretsiz": 12,
        "ucretsiz": 12,
        "tıkla": 18,
        "tikla": 18,
        "link": 12,
        "http": 24,
        "https": 24,
        "bit.ly": 30,
        "acil": 16,
        "hemen": 12,
        "son gün": 18,
        "son gun": 18,
        "şifre": 22,
        "sifre": 22,
        "kod": 12,
        "banka": 16,
        "kart": 16,
        "iban": 20,
        "hesap": 12,
        "onayla": 18,
        "doğrula": 18,
        "dogrula": 18,
        "kargo": 10,
        "teslimat": 10,
        "borç": 16,
        "borc": 16,
        "icra": 24,
        "ceza": 20,
        "abonelik": 10,
        "iptal": 8
    }

    for word, pts in risky_keywords.items():
        if word in lowered:
            score += pts
            signals.append(f"Riskli ifade: {word}")

    if _ss_titanium_re.search(r'https?://|www\.', lowered):
        score += 25
        signals.append("Bağlantı tespit edildi")

    if _ss_titanium_re.search(r'\b\d{4,8}\b', lowered):
        score += 8
        signals.append("Kod/numara benzeri ifade tespit edildi")

    if len(raw) < 12:
        score += 4
        signals.append("Mesaj çok kısa, bağlam sınırlı")

    if len(raw) > 180:
        score += 8
        signals.append("Uzun mesaj, oltalama kalıbı olabilir")

    if raw.count("!") >= 2:
        score += 8
        signals.append("Aşırı vurgu işareti tespit edildi")

    score = max(0, min(score, 100))

    if score >= 70:
        status = "riskli"
        label = "Riskli"
        action = "quarantine"
        summary = "Mesaj yüksek riskli görünüyor. Karantinaya alınması önerilir."
    elif score >= 40:
        status = "supheli"
        label = "Şüpheli"
        action = "review"
        summary = "Mesaj şüpheli sinyaller taşıyor. Kullanıcı onayıyla karantinaya alınabilir."
    else:
        status = "guvenli"
        label = "Güvenli"
        action = "safe"
        summary = "Belirgin spam/dolandırıcılık sinyali düşük görünüyor."

    if not signals:
        signals.append("Belirgin risk sinyali bulunamadı")

    return {
        "text": raw,
        "score": score,
        "status": status,
        "label": label,
        "recommended_action": action,
        "summary": summary,
        "signals": signals[:8],
    }

def _ss_titanium_save_analysis(result):
    history = _ss_titanium_read_json(_SS_ANALYSIS_HISTORY_FILE, [])
    item = {
        "created_at": _ss_titanium_now(),
        "username": _ss_titanium_username(),
        "score": result.get("score"),
        "status": result.get("status"),
        "label": result.get("label"),
        "summary": result.get("summary"),
        "signals": result.get("signals", []),
        "text": result.get("text", "")
    }
    history.append(item)
    _ss_titanium_write_json(_SS_ANALYSIS_HISTORY_FILE, history[-300:])
    return item

def _ss_titanium_save_quarantine(result, source="scan"):
    quarantine = _ss_titanium_read_json(_SS_QUARANTINE_FILE, [])
    item = {
        "created_at": _ss_titanium_now(),
        "username": _ss_titanium_username(),
        "source": source,
        "score": result.get("score"),
        "status": result.get("status"),
        "label": result.get("label"),
        "summary": result.get("summary"),
        "signals": result.get("signals", []),
        "text": result.get("text", "")
    }
    quarantine.append(item)
    _ss_titanium_write_json(_SS_QUARANTINE_FILE, quarantine[-300:])
    return item

def ss_user_titanium_scan_final():
    if not _ss_titanium_user_ok():
        return _ss_titanium_jsonify({"ok": False, "error": "login_required"}), 401

    if _ss_titanium_request.is_json:
        text = (_ss_titanium_request.get_json(silent=True) or {}).get("text", "")
    else:
        text = _ss_titanium_request.form.get("text", "")

    result = _ss_titanium_analyze_sms(text)

    if not result["text"]:
        return _ss_titanium_jsonify({
            "ok": False,
            "error": "empty_text",
            "message": "Analiz için SMS metni gerekli."
        }), 400

    saved_analysis = _ss_titanium_save_analysis(result)

    quarantined = None
    if result["score"] >= 70:
        quarantined = _ss_titanium_save_quarantine(result, source="auto_high_risk")

    _ss_titanium_event("sms_scan", {
        "score": result["score"],
        "status": result["status"],
        "auto_quarantine": bool(quarantined)
    })

    return _ss_titanium_jsonify({
        "ok": True,
        "result": result,
        "analysis_saved": saved_analysis,
        "auto_quarantine": bool(quarantined),
        "quarantine_item": quarantined
    })

def ss_user_titanium_quarantine_final():
    if not _ss_titanium_user_ok():
        return _ss_titanium_jsonify({"ok": False, "error": "login_required"}), 401

    username = _ss_titanium_username()
    items = _ss_titanium_read_json(_SS_QUARANTINE_FILE, [])
    items = [x for x in items if x.get("username") == username]
    return _ss_titanium_jsonify({
        "ok": True,
        "count": len(items),
        "items": list(reversed(items[-50:]))
    })

def ss_user_titanium_history_final():
    if not _ss_titanium_user_ok():
        return _ss_titanium_jsonify({"ok": False, "error": "login_required"}), 401

    username = _ss_titanium_username()
    items = _ss_titanium_read_json(_SS_ANALYSIS_HISTORY_FILE, [])
    items = [x for x in items if x.get("username") == username]
    return _ss_titanium_jsonify({
        "ok": True,
        "count": len(items),
        "items": list(reversed(items[-50:]))
    })

def ss_user_titanium_summary_final():
    if not _ss_titanium_user_ok():
        return _ss_titanium_jsonify({"ok": False, "error": "login_required"}), 401

    username = _ss_titanium_username()
    history = [x for x in _ss_titanium_read_json(_SS_ANALYSIS_HISTORY_FILE, []) if x.get("username") == username]
    quarantine = [x for x in _ss_titanium_read_json(_SS_QUARANTINE_FILE, []) if x.get("username") == username]

    riskli = sum(1 for x in history if x.get("status") == "riskli")
    supheli = sum(1 for x in history if x.get("status") == "supheli")
    guvenli = sum(1 for x in history if x.get("status") == "guvenli")

    return _ss_titanium_jsonify({
        "ok": True,
        "username": username,
        "analysis_count": len(history),
        "quarantine_count": len(quarantine),
        "riskli": riskli,
        "supheli": supheli,
        "guvenli": guvenli,
        "last_analysis": history[-1] if history else None
    })

try:
    app.add_url_rule("/u/titanium/scan", endpoint="ss_user_titanium_scan_final", view_func=ss_user_titanium_scan_final, methods=["POST"])
    app.add_url_rule("/u/titanium/quarantine", endpoint="ss_user_titanium_quarantine_final", view_func=ss_user_titanium_quarantine_final, methods=["GET"])
    app.add_url_rule("/u/titanium/history", endpoint="ss_user_titanium_history_final", view_func=ss_user_titanium_history_final, methods=["GET"])
    app.add_url_rule("/u/titanium/summary", endpoint="ss_user_titanium_summary_final", view_func=ss_user_titanium_summary_final, methods=["GET"])
except Exception as e:
    print("Titanium route register skipped:", e)
# ===== SPAMSHIELD USER TITANIUM CORE END =====

# ===== SPAMSHIELD USER PROTECTION TITANIUM SCANNER UI START =====
from flask import redirect as _ss_protect_redirect
from flask import session as _ss_protect_session
from flask import request as _ss_protect_request
from flask import make_response as _ss_protect_make_response

@app.route("/u/protection/scan", methods=["POST"])
def ss_user_protection_scan_ui_final():
    if not (session.get("logged_in") and session.get("username")):
        return redirect("/login")

    sms_text = (_ss_protect_request.form.get("sms_text") or "").strip()

    if not sms_text:
        _ss_protect_session["ss_protection_scan_result"] = {
            "ok": False,
            "label": "Boş mesaj",
            "score": 0,
            "status": "empty",
            "summary": "Analiz için SMS metni gerekli.",
            "signals": ["SMS metni girilmedi."],
            "auto_quarantine": False
        }
        return _ss_protect_redirect("/u/protection")

    result = _ss_titanium_analyze_sms(sms_text)
    _ss_titanium_save_analysis(result)

    quarantined = None
    if result.get("score", 0) >= 60:
        quarantined = _ss_titanium_save_quarantine(result, source="protection_page_scan")

    _ss_titanium_event("protection_page_scan", {
        "score": result.get("score"),
        "status": result.get("status"),
        "auto_quarantine": bool(quarantined)
    })

    _ss_protect_session["ss_protection_scan_result"] = {
        "ok": True,
        "label": result.get("label"),
        "score": result.get("score"),
        "status": result.get("status"),
        "summary": result.get("summary"),
        "signals": result.get("signals", []),
        "auto_quarantine": bool(quarantined)
    }

    return _ss_protect_redirect("/u/protection")


try:
    _ss_old_protection_titanium_page = app.view_functions.get("user_protection")

    def _ss_user_protection_titanium_scanner_page_final():
        resp = _ss_user_protection_compact_final()

        try:
            html = resp.get_data(as_text=True)
        except Exception:
            return resp

        result = _ss_protect_session.pop("ss_protection_scan_result", None)

        result_html = ""
        if result:
            signal_rows = ""
            for sig in result.get("signals", [])[:6]:
                signal_rows += f'<div class="row"><b>Sinyal</b><span>{sig}</span></div>'

            quarantine_text = "Otomatik karantinaya alındı" if result.get("auto_quarantine") else "Karantinaya alınmadı"
            score = result.get("score", 0)
            label = result.get("label", "Bilinmiyor")
            summary = result.get("summary", "")

            result_html = f'''
  <section class="status" style="margin:0 0 14px;">
    <div class="row"><b>Son Tarama</b><span>{label}</span></div>
    <div class="row"><b>Risk Skoru</b><span>{score}/100</span></div>
    <div class="row"><b>İşlem</b><span>{quarantine_text}</span></div>
    <div class="row"><b>Özet</b><span>{summary}</span></div>
    {signal_rows}
  </section>
'''

        scanner_html = f'''
  <div class="section">ANLIK TARAMA</div>
  <div class="bar"></div>

  <section class="status" style="margin-bottom:14px;">
    <form method="post" action="/u/protection/scan">
      <label style="display:block;font-weight:950;margin:8px 0 8px;color:#f5fff8;">
        SMS metnini analiz et
      </label>

      <textarea name="sms_text" rows="5" placeholder="Şüpheli SMS metnini buraya yapıştır..."
        style="width:100%;resize:vertical;border-radius:17px;border:1px solid rgba(35,255,137,.22);background:rgba(0,0,0,.22);color:#f5fff8;padding:12px;font:800 13px system-ui;outline:none;"></textarea>

      <button type="submit"
        style="width:100%;margin-top:10px;min-height:48px;border:0;border-radius:17px;background:linear-gradient(135deg,#00c860,#00e676);color:#02120b;font-weight:1000;font-size:15px;">
        SMS'i Tara
      </button>

      <div style="margin-top:10px;color:rgba(245,255,248,.58);font-size:11px;font-weight:800;line-height:1.35;">
        Riskli mesajlar Titanium motor tarafından otomatik karantinaya alınır.
      </div>
    </form>
  </section>

  {result_html}
'''

        if '<div class="section">DETAYLAR</div>' in html:
            html = html.replace('<div class="section">DETAYLAR</div>', scanner_html + '\n  <div class="section">DETAYLAR</div>', 1)
        else:
            html = html.replace('</section>', '</section>\n' + scanner_html, 1)

        new_resp = _ss_protect_make_response(html)
        new_resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        new_resp.headers["Pragma"] = "no-cache"
        new_resp.headers["Expires"] = "0"
        return new_resp

    for _rule in list(app.url_map.iter_rules()):
        if str(_rule) == "/u/protection":
            app.view_functions[_rule.endpoint] = _ss_user_protection_titanium_scanner_page_final

except Exception as e:
    print("Protection titanium scanner page override skipped:", e)
# ===== SPAMSHIELD USER PROTECTION TITANIUM SCANNER UI END =====

# ===== SPAMSHIELD USER ANALYSIS TITANIUM SCANNER UI START =====
from flask import redirect as _ss_analysis_redirect
from flask import session as _ss_analysis_session
from flask import request as _ss_analysis_request
from flask import make_response as _ss_analysis_make_response
import html as _ss_analysis_html_escape

def _ss_analysis_safe(v):
    try:
        if v is None:
            return ""
        return _ss_analysis_html_escape.escape(str(v))
    except Exception:
        return ""

def _ss_user_analysis_check_titanium_final():
    if not (session.get("logged_in") and session.get("username")):
        return redirect("/login")

    if _ss_analysis_request.method == "GET":
        return _ss_analysis_redirect("/u/analysis")

    sms_text = (_ss_analysis_request.form.get("sms_text") or "").strip()

    if not sms_text:
        _ss_analysis_session["ss_analysis_scan_result"] = {
            "ok": False,
            "label": "Boş mesaj",
            "score": 0,
            "status": "empty",
            "summary": "Analiz için SMS metni gerekli.",
            "signals": ["SMS metni girilmedi."],
            "auto_quarantine": False
        }
        return _ss_analysis_redirect("/u/analysis")

    result = _ss_titanium_analyze_sms(sms_text)
    _ss_titanium_save_analysis(result)

    quarantined = None
    if result.get("score", 0) >= 60:
        quarantined = _ss_titanium_save_quarantine(result, source="analysis_page_scan")

    _ss_titanium_event("analysis_page_scan", {
        "score": result.get("score"),
        "status": result.get("status"),
        "auto_quarantine": bool(quarantined)
    })

    _ss_analysis_session["ss_analysis_scan_result"] = {
        "ok": True,
        "label": result.get("label"),
        "score": result.get("score"),
        "status": result.get("status"),
        "summary": result.get("summary"),
        "signals": result.get("signals", []),
        "auto_quarantine": bool(quarantined)
    }

    return _ss_analysis_redirect("/u/analysis")


try:
    def _ss_user_analysis_titanium_scanner_page_final():
        resp = _ss_user_analysis_compact_final()

        try:
            html = resp.get_data(as_text=True)
        except Exception:
            return resp

        result = _ss_analysis_session.pop("ss_analysis_scan_result", None)

        result_html = ""
        if result:
            label = _ss_analysis_safe(result.get("label", "Bilinmiyor"))
            score = _ss_analysis_safe(result.get("score", 0))
            summary = _ss_analysis_safe(result.get("summary", ""))
            quarantine_text = "Otomatik karantinaya alındı" if result.get("auto_quarantine") else "Karantinaya alınmadı"

            signal_rows = ""
            for sig in result.get("signals", [])[:8]:
                signal_rows += f'''
    <div class="row">
      <b>Risk Sinyali</b>
      <span>{_ss_analysis_safe(sig)}</span>
      <div class="mini-plus">✓</div>
    </div>
'''

            result_html = f'''
  <section class="status" style="margin:0 0 14px;">
    <div class="row"><b>Analiz Sonucu</b><span>{label}</span><div class="mini-plus">✓</div></div>
    <div class="row"><b>Risk Skoru</b><span>{score}/100</span><div class="mini-plus">✓</div></div>
    <div class="row"><b>Karantina</b><span>{quarantine_text}</span><div class="mini-plus">✓</div></div>
    <div class="row"><b>AI Özeti</b><span>{summary}</span><div class="mini-plus">✓</div></div>
    {signal_rows}
  </section>
'''

        scanner_html = f'''
  <div class="section">AI TARAMA</div>
  <div class="bar"></div>

  <section class="status" style="margin-bottom:14px;">
    <form method="post" action="/u/analysis/check">
      <label style="display:block;font-weight:950;margin:8px 0 8px;color:#f5fff8;">
        SMS / mesaj metnini detaylı analiz et
      </label>

      <textarea name="sms_text" rows="6" placeholder="Analiz etmek istediğin SMS veya mesaj metnini buraya yapıştır..."
        style="width:100%;resize:vertical;border-radius:17px;border:1px solid rgba(35,255,137,.22);background:rgba(0,0,0,.22);color:#f5fff8;padding:12px;font:800 13px system-ui;outline:none;"></textarea>

      <button type="submit"
        style="width:100%;margin-top:10px;min-height:48px;border:0;border-radius:17px;background:linear-gradient(135deg,#00c860,#00e676);color:#02120b;font-weight:1000;font-size:15px;">
        AI Analizi Başlat
      </button>

      <div style="margin-top:10px;color:rgba(245,255,248,.58);font-size:11px;font-weight:800;line-height:1.35;">
        Titanium AI motoru mesajı risk skoru, sinyal ve karantina durumuna göre değerlendirir.
      </div>
    </form>
  </section>

  {result_html}
'''

        if '<div class="section">DETAYLAR</div>' in html:
            html = html.replace('<div class="section">DETAYLAR</div>', scanner_html + '\n  <div class="section">DETAYLAR</div>', 1)
        else:
            html = html.replace('</section>', '</section>\n' + scanner_html, 1)

        new_resp = _ss_analysis_make_response(html)
        new_resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        new_resp.headers["Pragma"] = "no-cache"
        new_resp.headers["Expires"] = "0"
        return new_resp

    for _rule in list(app.url_map.iter_rules()):
        if str(_rule) == "/u/analysis":
            app.view_functions[_rule.endpoint] = _ss_user_analysis_titanium_scanner_page_final
        if str(_rule) == "/u/analysis/check":
            app.view_functions[_rule.endpoint] = _ss_user_analysis_check_titanium_final

except Exception as e:
    print("Analysis titanium scanner page override skipped:", e)
# ===== SPAMSHIELD USER ANALYSIS TITANIUM SCANNER UI END =====

# ===== SPAMSHIELD USER ANALYSIS TITANIUM SCANNER UI START =====
from flask import redirect as _ss_analysis_redirect
from flask import session as _ss_analysis_session
from flask import request as _ss_analysis_request
from flask import make_response as _ss_analysis_make_response
import html as _ss_analysis_html_escape

def _ss_analysis_safe(v):
    try:
        if v is None:
            return ""
        return _ss_analysis_html_escape.escape(str(v))
    except Exception:
        return ""

def _ss_user_analysis_check_titanium_final():
    if not (session.get("logged_in") and session.get("username")):
        return redirect("/login")

    if _ss_analysis_request.method == "GET":
        return _ss_analysis_redirect("/u/analysis")

    sms_text = (_ss_analysis_request.form.get("sms_text") or "").strip()

    if not sms_text:
        _ss_analysis_session["ss_analysis_scan_result"] = {
            "ok": False,
            "label": "Boş mesaj",
            "score": 0,
            "status": "empty",
            "summary": "Analiz için SMS metni gerekli.",
            "signals": ["SMS metni girilmedi."],
            "auto_quarantine": False
        }
        return _ss_analysis_redirect("/u/analysis")

    result = _ss_titanium_analyze_sms(sms_text)
    _ss_titanium_save_analysis(result)

    quarantined = None
    if result.get("score", 0) >= 60:
        quarantined = _ss_titanium_save_quarantine(result, source="analysis_page_scan")

    _ss_titanium_event("analysis_page_scan", {
        "score": result.get("score"),
        "status": result.get("status"),
        "auto_quarantine": bool(quarantined)
    })

    _ss_analysis_session["ss_analysis_scan_result"] = {
        "ok": True,
        "label": result.get("label"),
        "score": result.get("score"),
        "status": result.get("status"),
        "summary": result.get("summary"),
        "signals": result.get("signals", []),
        "auto_quarantine": bool(quarantined)
    }

    return _ss_analysis_redirect("/u/analysis")


try:
    def _ss_user_analysis_titanium_scanner_page_final():
        resp = _ss_user_analysis_compact_final()

        try:
            html = resp.get_data(as_text=True)
        except Exception:
            return resp

        result = _ss_analysis_session.pop("ss_analysis_scan_result", None)

        result_html = ""
        if result:
            label = _ss_analysis_safe(result.get("label", "Bilinmiyor"))
            score = _ss_analysis_safe(result.get("score", 0))
            summary = _ss_analysis_safe(result.get("summary", ""))
            quarantine_text = "Otomatik karantinaya alındı" if result.get("auto_quarantine") else "Karantinaya alınmadı"

            signal_rows = ""
            for sig in result.get("signals", [])[:8]:
                signal_rows += f'''
    <div class="row">
      <b>Risk Sinyali</b>
      <span>{_ss_analysis_safe(sig)}</span>
      <div class="mini-plus">✓</div>
    </div>
'''

            result_html = f'''
  <section class="status" style="margin:0 0 14px;">
    <div class="row"><b>Analiz Sonucu</b><span>{label}</span><div class="mini-plus">✓</div></div>
    <div class="row"><b>Risk Skoru</b><span>{score}/100</span><div class="mini-plus">✓</div></div>
    <div class="row"><b>Karantina</b><span>{quarantine_text}</span><div class="mini-plus">✓</div></div>
    <div class="row"><b>AI Özeti</b><span>{summary}</span><div class="mini-plus">✓</div></div>
    {signal_rows}
  </section>
'''

        scanner_html = f'''
  <div class="section">AI TARAMA</div>
  <div class="bar"></div>

  <section class="status" style="margin-bottom:14px;">
    <form method="post" action="/u/analysis/check">
      <label style="display:block;font-weight:950;margin:8px 0 8px;color:#f5fff8;">
        SMS / mesaj metnini detaylı analiz et
      </label>

      <textarea name="sms_text" rows="6" placeholder="Analiz etmek istediğin SMS veya mesaj metnini buraya yapıştır..."
        style="width:100%;resize:vertical;border-radius:17px;border:1px solid rgba(35,255,137,.22);background:rgba(0,0,0,.22);color:#f5fff8;padding:12px;font:800 13px system-ui;outline:none;"></textarea>

      <button type="submit"
        style="width:100%;margin-top:10px;min-height:48px;border:0;border-radius:17px;background:linear-gradient(135deg,#00c860,#00e676);color:#02120b;font-weight:1000;font-size:15px;">
        AI Analizi Başlat
      </button>

      <div style="margin-top:10px;color:rgba(245,255,248,.58);font-size:11px;font-weight:800;line-height:1.35;">
        Titanium AI motoru mesajı risk skoru, sinyal ve karantina durumuna göre değerlendirir.
      </div>
    </form>
  </section>

  {result_html}
'''

        if '<div class="section">DETAYLAR</div>' in html:
            html = html.replace('<div class="section">DETAYLAR</div>', scanner_html + '\n  <div class="section">DETAYLAR</div>', 1)
        else:
            html = html.replace('</section>', '</section>\n' + scanner_html, 1)

        new_resp = _ss_analysis_make_response(html)
        new_resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        new_resp.headers["Pragma"] = "no-cache"
        new_resp.headers["Expires"] = "0"
        return new_resp

    for _rule in list(app.url_map.iter_rules()):
        if str(_rule) == "/u/analysis":
            app.view_functions[_rule.endpoint] = _ss_user_analysis_titanium_scanner_page_final
        if str(_rule) == "/u/analysis/check":
            app.view_functions[_rule.endpoint] = _ss_user_analysis_check_titanium_final

except Exception as e:
    print("Analysis titanium scanner page override skipped:", e)
# ===== SPAMSHIELD USER ANALYSIS TITANIUM SCANNER UI END =====

# ===== SPAMSHIELD USER BLOCKED TITANIUM QUARANTINE UI START =====
from flask import make_response as _ss_blocked_titanium_make_response
from flask import session as _ss_blocked_titanium_session
import html as _ss_blocked_titanium_html_escape

def _ss_blocked_titanium_safe(v):
    try:
        return _ss_blocked_titanium_html_escape.escape(str(v or ""))
    except Exception:
        return ""

def _ss_blocked_titanium_source_label(src):
    src = str(src or "").strip()
    if src == "protection_page_scan":
        return "Koruma"
    if src == "analysis_page_scan":
        return "AI Analiz"
    if src == "auto_high_risk":
        return "Otomatik"
    return "Tarama"

try:
    def _ss_user_blocked_titanium_quarantine_page_final():
        resp = _ss_user_blocked_compact_final()

        try:
            html = resp.get_data(as_text=True)
        except Exception:
            return resp

        username = str(session.get("username") or "kullanıcı")
        quarantine = _ss_titanium_read_json(_SS_QUARANTINE_FILE, [])
        items = [x for x in quarantine if x.get("username") == username]
        items = list(reversed(items[-8:]))

        total_count = len([x for x in quarantine if x.get("username") == username])
        high_count = sum(1 for x in quarantine if x.get("username") == username and int(x.get("score") or 0) >= 70)

        cards = ""
        if items:
            for item in items:
                text = _ss_blocked_titanium_safe(item.get("text", ""))
                if len(text) > 120:
                    text = text[:120] + "..."

                score = _ss_blocked_titanium_safe(item.get("score", 0))
                label = _ss_blocked_titanium_safe(item.get("label", "Riskli"))
                source = _ss_blocked_titanium_safe(_ss_blocked_titanium_source_label(item.get("source")))
                created = _ss_blocked_titanium_safe(item.get("created_at", ""))

                signal_text = ""
                for sig in (item.get("signals") or [])[:3]:
                    signal_text += f'<span class="q-chip">{_ss_blocked_titanium_safe(sig)}</span>'

                cards += f'''
  <article class="q-card">
    <div class="q-top">
      <div>
        <h3>{label} Mesaj</h3>
        <p>{text}</p>
      </div>
      <div class="q-score">{score}</div>
    </div>

    <div class="q-meta">
      <span>Kaynak: {source}</span>
      <span>{created}</span>
    </div>

    <div class="q-signals">
      {signal_text}
    </div>
  </article>
'''
        else:
            cards = '''
  <article class="q-empty">
    <h3>Karantina temiz</h3>
    <p>Henüz karantinaya alınmış riskli mesaj yok. Koruma veya AI Analiz sayfasından tarama yaptığında riskli mesajlar burada görünür.</p>
  </article>
'''

        quarantine_html = f'''
  <style>
    .q-grid{{display:grid;gap:10px;margin-bottom:16px}}
    .q-card{{
      border:1px solid rgba(35,255,137,.22);
      background:linear-gradient(145deg,rgba(8,35,23,.92),rgba(2,13,8,.9));
      border-radius:19px;
      padding:14px;
      box-shadow:0 14px 34px rgba(0,0,0,.22);
    }}
    .q-top{{
      display:grid;
      grid-template-columns:1fr auto;
      gap:10px;
      align-items:start;
    }}
    .q-card h3{{
      margin:0 0 6px;
      font-size:19px;
      line-height:1.05;
      color:#f5fff8;
    }}
    .q-card p{{
      margin:0;
      color:rgba(245,255,248,.66);
      font-weight:800;
      font-size:12px;
      line-height:1.38;
      word-break:break-word;
    }}
    .q-score{{
      width:44px;
      height:44px;
      border-radius:15px;
      display:grid;
      place-items:center;
      color:#02120b;
      background:linear-gradient(135deg,#00c860,#00e676);
      font-weight:1000;
      font-size:18px;
      box-shadow:0 0 18px rgba(32,255,136,.18);
    }}
    .q-meta{{
      display:flex;
      justify-content:space-between;
      gap:8px;
      margin-top:11px;
      color:rgba(245,255,248,.52);
      font-size:10px;
      font-weight:900;
      flex-wrap:wrap;
    }}
    .q-signals{{
      display:flex;
      gap:6px;
      flex-wrap:wrap;
      margin-top:10px;
    }}
    .q-chip{{
      border:1px solid rgba(32,255,136,.18);
      background:rgba(32,255,136,.07);
      color:#98ffb8;
      border-radius:999px;
      padding:5px 8px;
      font-size:10px;
      font-weight:900;
    }}
    .q-empty{{
      border:1px solid rgba(35,255,137,.22);
      background:linear-gradient(145deg,rgba(8,35,23,.92),rgba(2,13,8,.9));
      border-radius:19px;
      padding:15px;
      margin-bottom:16px;
    }}
    .q-empty h3{{margin:0 0 7px;font-size:19px}}
    .q-empty p{{margin:0;color:rgba(245,255,248,.66);font-weight:800;font-size:12px;line-height:1.4}}
  </style>

  <div class="section">KARANTİNA</div>
  <div class="bar"></div>

  <section class="status" style="margin-bottom:14px;">
    <div class="row"><b>Toplam Karantina</b><span>{total_count}</span><div class="mini-plus">✓</div></div>
    <div class="row"><b>Yüksek Risk</b><span>{high_count}</span><div class="mini-plus">✓</div></div>
    <div class="row"><b>Durum</b><span>Aktif İzleme</span><div class="mini-plus">✓</div></div>
  </section>

  <div class="q-grid">
    {cards}
  </div>
'''

        if '<div class="section">DETAYLAR</div>' in html:
            html = html.replace('<div class="section">DETAYLAR</div>', quarantine_html + '\n  <div class="section">DETAYLAR</div>', 1)
        else:
            html = html.replace('</section>', '</section>\n' + quarantine_html, 1)

        new_resp = _ss_blocked_titanium_make_response(html)
        new_resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        new_resp.headers["Pragma"] = "no-cache"
        new_resp.headers["Expires"] = "0"
        return new_resp

    for _rule in list(app.url_map.iter_rules()):
        if str(_rule) == "/u/blocked":
            app.view_functions[_rule.endpoint] = _ss_user_blocked_titanium_quarantine_page_final

except Exception as e:
    print("Blocked titanium quarantine page override skipped:", e)
# ===== SPAMSHIELD USER BLOCKED TITANIUM QUARANTINE UI END =====

# ===== SPAMSHIELD USER REPORTS TITANIUM SUMMARY UI START =====
from flask import render_template_string as _ss_reports_render_template_string
from flask import make_response as _ss_reports_make_response
import html as _ss_reports_html_escape

def _ss_reports_safe(v):
    try:
        return _ss_reports_html_escape.escape(str(v or ""))
    except Exception:
        return ""

def _ss_reports_source_label(src):
    src = str(src or "").strip()
    if src == "protection_page_scan":
        return "Koruma"
    if src == "analysis_page_scan":
        return "AI Analiz"
    if src == "auto_high_risk":
        return "Otomatik"
    return "Tarama"

def _ss_user_reports_titanium_summary_page_final():
    if not (session.get("logged_in") and session.get("username")):
        return redirect("/login")

    username = str(session.get("username") or "kullanıcı")

    history_all = _ss_titanium_read_json(_SS_ANALYSIS_HISTORY_FILE, [])
    quarantine_all = _ss_titanium_read_json(_SS_QUARANTINE_FILE, [])

    history = [x for x in history_all if x.get("username") == username]
    quarantine = [x for x in quarantine_all if x.get("username") == username]

    total = len(history)
    quarantine_count = len(quarantine)
    riskli = sum(1 for x in history if x.get("status") == "riskli")
    supheli = sum(1 for x in history if x.get("status") == "supheli")
    guvenli = sum(1 for x in history if x.get("status") == "guvenli")

    last_items = list(reversed(history[-6:]))

    if total:
        risk_percent = round((riskli / total) * 100)
        safe_percent = round((guvenli / total) * 100)
    else:
        risk_percent = 0
        safe_percent = 0

    if riskli >= 5:
        security_note = "Yoğun risk trafiği algılandı. Karantina ve analiz takibi aktif tutulmalı."
        mode = "Yüksek İzleme"
    elif riskli >= 1:
        security_note = "Riskli mesajlar tespit edildi. Titanium motor aktif şekilde çalışıyor."
        mode = "Aktif Koruma"
    else:
        security_note = "Belirgin risk yoğunluğu yok. Sistem temiz görünüyor."
        mode = "Temiz Durum"

    rows = ""
    if last_items:
        for item in last_items:
            label = _ss_reports_safe(item.get("label", "Bilinmiyor"))
            score = _ss_reports_safe(item.get("score", 0))
            created = _ss_reports_safe(item.get("created_at", ""))
            summary = _ss_reports_safe(item.get("summary", ""))
            text = _ss_reports_safe(item.get("text", ""))
            if len(text) > 95:
                text = text[:95] + "..."

            rows += f'''
    <article class="report-item">
      <div class="report-top">
        <div>
          <h3>{label} Analiz</h3>
          <p>{text}</p>
        </div>
        <div class="score">{score}</div>
      </div>
      <div class="report-meta">
        <span>{created}</span>
        <span>{summary}</span>
      </div>
    </article>
'''
    else:
        rows = '''
    <article class="report-empty">
      <h3>Henüz analiz yok</h3>
      <p>Koruma veya AI Analiz sayfasında SMS taraması yaptığında raporlar burada oluşur.</p>
    </article>
'''

    q_rows = ""
    for item in list(reversed(quarantine[-4:])):
        source = _ss_reports_safe(_ss_reports_source_label(item.get("source")))
        score = _ss_reports_safe(item.get("score", 0))
        label = _ss_reports_safe(item.get("label", "Riskli"))
        q_rows += f'''
      <div class="row"><b>{label}</b><span>{source} · {score}/100</span><div class="mini-plus">✓</div></div>
'''

    if not q_rows:
        q_rows = '<div class="row"><b>Karantina</b><span>Temiz</span><div class="mini-plus">✓</div></div>'

    html = f"""
<!doctype html>
<html lang="tr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
  <title>EratGuard PRO • Raporlar</title>
  <style>
    :root{{
      --bg:#020806;
      --line:rgba(35,255,137,.22);
      --green:#20ff88;
      --green2:#8cff5a;
      --text:#f5fff8;
      --muted:rgba(245,255,248,.66);
    }}
    *{{box-sizing:border-box;-webkit-tap-highlight-color:transparent}}
    body{{
      margin:0;
      min-height:100vh;
      background:
        radial-gradient(circle at 50% 0%,rgba(32,255,136,.14),transparent 32%),
        radial-gradient(circle at 88% 76%,rgba(140,255,90,.10),transparent 28%),
        linear-gradient(180deg,#010403,#03150d 58%,#010403);
      color:var(--text);
      font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",Arial,sans-serif;
      padding:14px;
      overflow-x:hidden;
    }}
    .top{{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:14px}}
    .brand{{display:flex;align-items:center;gap:10px;min-width:0}}
    .logo{{
      width:46px;height:46px;border-radius:16px;
      display:grid;place-items:center;
      background:linear-gradient(145deg,rgba(32,255,136,.18),rgba(32,255,136,.04));
      border:1px solid var(--line);
      box-shadow:0 0 20px rgba(32,255,136,.14);
      font-size:24px;
      flex:0 0 auto;
    }}
    h1{{margin:0;font-size:27px;line-height:1;letter-spacing:-1px}}
    h1 span{{color:var(--green2)}}
    .sub{{margin-top:5px;color:var(--muted);font-weight:800;font-size:12px}}
    .badge{{
      color:var(--green);
      border:1px solid var(--line);
      background:rgba(32,255,136,.08);
      border-radius:999px;
      padding:8px 10px;
      font-weight:950;
      font-size:12px;
      white-space:nowrap;
    }}
    .hero{{
      position:relative;
      overflow:hidden;
      border:1px solid var(--line);
      background:linear-gradient(145deg,rgba(8,35,23,.94),rgba(2,13,8,.92));
      border-radius:22px;
      padding:16px;
      box-shadow:0 18px 44px rgba(0,0,0,.34), inset 0 0 42px rgba(32,255,136,.04);
      margin-bottom:18px;
    }}
    .hero-icon{{
      width:48px;height:48px;border-radius:16px;
      display:grid;place-items:center;
      background:rgba(32,255,136,.10);
      border:1px solid rgba(32,255,136,.18);
      font-size:25px;
      margin-bottom:13px;
    }}
    .hero h2{{margin:0 0 9px;font-size:28px;line-height:1.05;letter-spacing:-1px}}
    .hero p{{margin:0;color:var(--muted);font-size:14px;line-height:1.42;font-weight:800}}
    .stats{{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-top:15px}}
    .stat{{
      border:1px solid rgba(32,255,136,.15);
      background:rgba(0,0,0,.17);
      border-radius:17px;
      padding:10px 6px;
      text-align:center;
    }}
    .stat b{{display:block;color:var(--green);font-size:18px;line-height:1}}
    .stat span{{display:block;margin-top:6px;color:var(--muted);font-weight:900;font-size:9px}}
    .back{{
      display:flex;
      align-items:center;
      justify-content:center;
      min-height:48px;
      margin-top:14px;
      border-radius:17px;
      color:var(--text);
      text-decoration:none;
      font-weight:950;
      font-size:15px;
      background:rgba(255,255,255,.07);
      border:1px solid rgba(255,255,255,.12);
    }}
    .section{{margin:17px 0 8px;letter-spacing:6px;font-weight:1000;font-size:16px}}
    .bar{{width:82px;height:5px;border-radius:999px;background:linear-gradient(90deg,var(--green),var(--green2));margin-bottom:11px}}
    .status{{
      border:1px solid var(--line);
      background:linear-gradient(145deg,rgba(8,35,23,.92),rgba(2,13,8,.9));
      border-radius:21px;
      padding:6px 14px;
      margin-bottom:14px;
    }}
    .row{{
      display:grid;
      grid-template-columns:1fr auto auto;
      align-items:center;
      gap:10px;
      padding:13px 0;
      border-bottom:1px solid rgba(245,255,248,.07);
    }}
    .row:last-child{{border-bottom:0}}
    .row b{{font-size:15px}}
    .row span{{color:#98ffb8;font-weight:950;font-size:13px;text-align:right}}
    .mini-plus{{
      width:30px;height:30px;border-radius:999px;
      display:grid;place-items:center;
      color:#9affb9;
      border:1px solid rgba(32,255,136,.22);
      background:rgba(32,255,136,.09);
      font-weight:950;
    }}
    .report-list{{display:grid;gap:10px}}
    .report-item{{
      border:1px solid rgba(35,255,137,.22);
      background:linear-gradient(145deg,rgba(8,35,23,.92),rgba(2,13,8,.9));
      border-radius:19px;
      padding:14px;
    }}
    .report-top{{display:grid;grid-template-columns:1fr auto;gap:10px;align-items:start}}
    .report-item h3{{margin:0 0 6px;font-size:19px;line-height:1.05}}
    .report-item p{{margin:0;color:rgba(245,255,248,.66);font-weight:800;font-size:12px;line-height:1.38;word-break:break-word}}
    .score{{
      width:44px;height:44px;border-radius:15px;
      display:grid;place-items:center;
      color:#02120b;
      background:linear-gradient(135deg,#00c860,#00e676);
      font-weight:1000;
      font-size:18px;
    }}
    .report-meta{{
      display:grid;
      gap:5px;
      margin-top:11px;
      color:rgba(245,255,248,.52);
      font-size:10px;
      font-weight:900;
    }}
    .report-empty{{
      border:1px solid rgba(35,255,137,.22);
      background:linear-gradient(145deg,rgba(8,35,23,.92),rgba(2,13,8,.9));
      border-radius:19px;
      padding:15px;
    }}
    .report-empty h3{{margin:0 0 7px;font-size:19px}}
    .report-empty p{{margin:0;color:rgba(245,255,248,.66);font-weight:800;font-size:12px;line-height:1.4}}
    .foot{{text-align:center;color:rgba(245,255,248,.38);font-weight:800;padding:22px 0 8px;font-size:12px}}
  </style>
</head>
<body>
  <div class="top">
    <div class="brand">
      <div class="logo">🛡️</div>
      <div>
        <h1>Erat<span>Guard</span></h1>
        <div class="sub">Titanium rapor merkezi</div>
      </div>
    </div>
    <div class="badge">👑 PRO AKTİF</div>
  </div>

  <section class="hero">
    <div class="hero-icon">📊</div>
    <h2>Raporlar</h2>
    <p>{_ss_reports_safe(security_note)}</p>

    <div class="stats">
      <div class="stat"><b>{total}</b><span>Analiz</span></div>
      <div class="stat"><b>{riskli}</b><span>Riskli</span></div>
      <div class="stat"><b>{guvenli}</b><span>Güvenli</span></div>
      <div class="stat"><b>{quarantine_count}</b><span>Karantina</span></div>
    </div>

    <a class="back" href="/radial">← Ana ekrana dön</a>
  </section>

  <div class="section">ÖZET</div>
  <div class="bar"></div>

  <section class="status">
    <div class="row"><b>Koruma Modu</b><span>{_ss_reports_safe(mode)}</span><div class="mini-plus">✓</div></div>
    <div class="row"><b>Risk Oranı</b><span>%{risk_percent}</span><div class="mini-plus">✓</div></div>
    <div class="row"><b>Güvenli Oran</b><span>%{safe_percent}</span><div class="mini-plus">✓</div></div>
    <div class="row"><b>İzleme</b><span>Aktif</span><div class="mini-plus">✓</div></div>
  </section>

  <div class="section">KARANTİNA</div>
  <div class="bar"></div>

  <section class="status">
    {q_rows}
  </section>

  <div class="section">SON ANALİZLER</div>
  <div class="bar"></div>

  <main class="report-list">
    {rows}
  </main>

  <div class="foot">EratGuard PRO · {username} · © 2026</div>
</body>
</html>
"""

    resp = _ss_reports_make_response(_ss_reports_render_template_string(html))
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp

try:
    for _rule in list(app.url_map.iter_rules()):
        if str(_rule) == "/u/reports":
            app.view_functions[_rule.endpoint] = _ss_user_reports_titanium_summary_page_final
except Exception as e:
    print("Reports titanium summary page override skipped:", e)
# ===== SPAMSHIELD USER REPORTS TITANIUM SUMMARY UI END =====

# ===== SPAMSHIELD USER NOTIFICATIONS TITANIUM EVENTS UI START =====
from flask import render_template_string as _ss_notify_render_template_string
from flask import make_response as _ss_notify_make_response
import html as _ss_notify_html_escape

def _ss_notify_safe(v):
    try:
        return _ss_notify_html_escape.escape(str(v or ""))
    except Exception:
        return ""

def _ss_notify_event_title(event_type, payload):
    event_type = str(event_type or "")
    payload = payload or {}

    if event_type == "protection_page_scan":
        if payload.get("auto_quarantine"):
            return "Koruma taraması: riskli SMS karantinaya alındı"
        return "Koruma taraması tamamlandı"

    if event_type == "analysis_page_scan":
        if payload.get("auto_quarantine"):
            return "AI analiz: yüksek risk karantinaya alındı"
        return "AI analiz tamamlandı"

    if event_type == "sms_scan":
        if payload.get("auto_quarantine"):
            return "Titanium motor riskli mesajı karantinaya aldı"
        return "Titanium SMS taraması tamamlandı"

    if event_type == "password_reset_requested":
        return "Şifre sıfırlama talebi oluşturuldu"

    return "Güvenlik olayı kaydedildi"

def _ss_notify_event_detail(event_type, payload):
    payload = payload or {}

    if str(event_type or "") == "password_reset_requested":
        channel = payload.get("channel", "e-posta")
        return f"Hesabın için şifre sıfırlama talebi oluşturuldu. Kod {channel} üzerinden gönderildi. Bu işlemi sen yapmadıysan şifreni değiştir."

    score = payload.get("score", "-")
    status = payload.get("status", "bilinmiyor")

    if payload.get("auto_quarantine"):
        return f"Risk skoru {score}. Durum: {status}. Mesaj otomatik karantinaya alındı."

    return f"Risk skoru {score}. Durum: {status}. İzleme kaydı oluşturuldu."

def _ss_user_notifications_titanium_events_page_final():
    if not (session.get("logged_in") and session.get("username")):
        return redirect("/login")

    username = str(session.get("username") or "kullanıcı")

    events_all = _ss_titanium_read_json(_SS_TITANIUM_EVENTS_FILE, [])
    events = [x for x in events_all if x.get("username") == username]
    events = list(reversed(events[-12:]))

    quarantine_all = _ss_titanium_read_json(_SS_QUARANTINE_FILE, [])
    quarantine = [x for x in quarantine_all if x.get("username") == username]

    history_all = _ss_titanium_read_json(_SS_ANALYSIS_HISTORY_FILE, [])
    history = [x for x in history_all if x.get("username") == username]

    riskli = sum(1 for x in history if x.get("status") == "riskli")
    auto_q = sum(1 for x in events if (x.get("payload") or {}).get("auto_quarantine"))

    if events:
        event_cards = ""
        for ev in events:
            payload = ev.get("payload") or {}
            event_type = ev.get("event_type")
            created = _ss_notify_safe(ev.get("created_at", ""))
            title = _ss_notify_safe(_ss_notify_event_title(event_type, payload))
            detail = _ss_notify_safe(_ss_notify_event_detail(event_type, payload))

            score = _ss_notify_safe(payload.get("score", "-"))

            if payload.get("auto_quarantine"):
                badge = "Karantina"
            elif str(payload.get("status")) == "riskli":
                badge = "Riskli"
            else:
                badge = "Bilgi"

            event_cards += f'''
    <article class="notify-card">
      <div class="notify-top">
        <div>
          <h3>{title}</h3>
          <p>{detail}</p>
        </div>
        <div class="notify-score">{score}</div>
      </div>
      <div class="notify-meta">
        <span>{created}</span>
        <span>{badge}</span>
      </div>
    </article>
'''
    else:
        event_cards = '''
    <article class="notify-empty">
      <h3>Henüz bildirim yok</h3>
      <p>Koruma veya AI Analiz sayfasında tarama yaptığında güvenlik bildirimleri burada oluşur.</p>
    </article>
'''

    html = f"""
<!doctype html>
<html lang="tr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
  <title>EratGuard PRO • Bildirimler</title>
  <style>
    :root{{
      --bg:#020806;
      --line:rgba(35,255,137,.22);
      --green:#20ff88;
      --green2:#8cff5a;
      --text:#f5fff8;
      --muted:rgba(245,255,248,.66);
    }}
    *{{box-sizing:border-box;-webkit-tap-highlight-color:transparent}}
    body{{
      margin:0;
      min-height:100vh;
      background:
        radial-gradient(circle at 50% 0%,rgba(32,255,136,.14),transparent 32%),
        radial-gradient(circle at 88% 76%,rgba(140,255,90,.10),transparent 28%),
        linear-gradient(180deg,#010403,#03150d 58%,#010403);
      color:var(--text);
      font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",Arial,sans-serif;
      padding:14px;
      overflow-x:hidden;
    }}
    .top{{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:14px}}
    .brand{{display:flex;align-items:center;gap:10px;min-width:0}}
    .logo{{
      width:46px;height:46px;border-radius:16px;
      display:grid;place-items:center;
      background:linear-gradient(145deg,rgba(32,255,136,.18),rgba(32,255,136,.04));
      border:1px solid var(--line);
      box-shadow:0 0 20px rgba(32,255,136,.14);
      font-size:24px;
      flex:0 0 auto;
    }}
    h1{{margin:0;font-size:27px;line-height:1;letter-spacing:-1px}}
    h1 span{{color:var(--green2)}}
    .sub{{margin-top:5px;color:var(--muted);font-weight:800;font-size:12px}}
    .badge{{
      color:var(--green);
      border:1px solid var(--line);
      background:rgba(32,255,136,.08);
      border-radius:999px;
      padding:8px 10px;
      font-weight:950;
      font-size:12px;
      white-space:nowrap;
    }}
    .hero{{
      border:1px solid var(--line);
      background:linear-gradient(145deg,rgba(8,35,23,.94),rgba(2,13,8,.92));
      border-radius:22px;
      padding:16px;
      box-shadow:0 18px 44px rgba(0,0,0,.34), inset 0 0 42px rgba(32,255,136,.04);
      margin-bottom:18px;
    }}
    .hero-icon{{
      width:48px;height:48px;border-radius:16px;
      display:grid;place-items:center;
      background:rgba(32,255,136,.10);
      border:1px solid rgba(32,255,136,.18);
      font-size:25px;
      margin-bottom:13px;
    }}
    .hero h2{{margin:0 0 9px;font-size:28px;line-height:1.05;letter-spacing:-1px}}
    .hero p{{margin:0;color:var(--muted);font-size:14px;line-height:1.42;font-weight:800}}
    .stats{{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-top:15px}}
    .stat{{
      border:1px solid rgba(32,255,136,.15);
      background:rgba(0,0,0,.17);
      border-radius:17px;
      padding:10px 6px;
      text-align:center;
    }}
    .stat b{{display:block;color:var(--green);font-size:18px;line-height:1}}
    .stat span{{display:block;margin-top:6px;color:var(--muted);font-weight:900;font-size:9px}}
    .back{{
      display:flex;
      align-items:center;
      justify-content:center;
      min-height:48px;
      margin-top:14px;
      border-radius:17px;
      color:var(--text);
      text-decoration:none;
      font-weight:950;
      font-size:15px;
      background:rgba(255,255,255,.07);
      border:1px solid rgba(255,255,255,.12);
    }}
    .section{{margin:17px 0 8px;letter-spacing:6px;font-weight:1000;font-size:16px}}
    .bar{{width:82px;height:5px;border-radius:999px;background:linear-gradient(90deg,var(--green),var(--green2));margin-bottom:11px}}
    .notify-list{{display:grid;gap:10px}}
    .notify-card{{
      border:1px solid rgba(35,255,137,.22);
      background:linear-gradient(145deg,rgba(8,35,23,.92),rgba(2,13,8,.9));
      border-radius:19px;
      padding:14px;
      box-shadow:0 14px 34px rgba(0,0,0,.22);
    }}
    .notify-top{{display:grid;grid-template-columns:1fr auto;gap:10px;align-items:start}}
    .notify-card h3{{margin:0 0 6px;font-size:18px;line-height:1.08}}
    .notify-card p{{margin:0;color:rgba(245,255,248,.66);font-weight:800;font-size:12px;line-height:1.38}}
    .notify-score{{
      width:42px;height:42px;border-radius:15px;
      display:grid;place-items:center;
      color:#02120b;
      background:linear-gradient(135deg,#00c860,#00e676);
      font-weight:1000;
      font-size:17px;
    }}
    .notify-meta{{
      display:flex;
      justify-content:space-between;
      gap:8px;
      margin-top:11px;
      color:rgba(245,255,248,.52);
      font-size:10px;
      font-weight:900;
      flex-wrap:wrap;
    }}
    .notify-empty{{
      border:1px solid rgba(35,255,137,.22);
      background:linear-gradient(145deg,rgba(8,35,23,.92),rgba(2,13,8,.9));
      border-radius:19px;
      padding:15px;
    }}
    .notify-empty h3{{margin:0 0 7px;font-size:19px}}
    .notify-empty p{{margin:0;color:rgba(245,255,248,.66);font-weight:800;font-size:12px;line-height:1.4}}
    .foot{{text-align:center;color:rgba(245,255,248,.38);font-weight:800;padding:22px 0 8px;font-size:12px}}
  </style>
</head>
<body>
  <div class="top">
    <div class="brand">
      <div class="logo">🛡️</div>
      <div>
        <h1>Erat<span>Guard</span></h1>
        <div class="sub">Titanium bildirim merkezi</div>
      </div>
    </div>
    <div class="badge">👑 PRO AKTİF</div>
  </div>

  <section class="hero">
    <div class="hero-icon">🔔</div>
    <h2>Bildirimler</h2>
    <p>Koruma, AI analiz ve karantina olayları burada güvenlik akışı olarak görünür.</p>

    <div class="stats">
      <div class="stat"><b>{len(events)}</b><span>Olay</span></div>
      <div class="stat"><b>{riskli}</b><span>Riskli</span></div>
      <div class="stat"><b>{len(quarantine)}</b><span>Karantina</span></div>
    </div>

    <a class="back" href="/radial">← Ana ekrana dön</a>
  </section>

  <div class="section">AKIŞ</div>
  <div class="bar"></div>

  <main class="notify-list">
    {event_cards}
  </main>

  <div class="foot">EratGuard PRO · {username} · © 2026</div>
</body>
</html>
"""

    resp = _ss_notify_make_response(_ss_notify_render_template_string(html))
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp

try:
    for _rule in list(app.url_map.iter_rules()):
        if str(_rule) == "/u/notifications":
            app.view_functions[_rule.endpoint] = _ss_user_notifications_titanium_events_page_final
except Exception as e:
    print("Notifications titanium events page override skipped:", e)
# ===== SPAMSHIELD USER NOTIFICATIONS TITANIUM EVENTS UI END =====

# ===== SPAMSHIELD USER SETTINGS TITANIUM PREFERENCES UI START =====
from flask import render_template_string as _ss_settings_render_template_string
from flask import make_response as _ss_settings_make_response
from flask import request as _ss_settings_request
from flask import redirect as _ss_settings_redirect
from flask import session as _ss_settings_session
from pathlib import Path as _ss_settings_Path
import json as _ss_settings_json
import html as _ss_settings_html_escape

_SS_USER_SETTINGS_FILE = _ss_settings_Path("data") / "user_settings.json"

def _ss_settings_safe(v):
    try:
        return _ss_settings_html_escape.escape(str(v or ""))
    except Exception:
        return ""

def _ss_settings_read_all():
    try:
        if not _SS_USER_SETTINGS_FILE.exists():
            return {}
        return _ss_settings_json.loads(_SS_USER_SETTINGS_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}

def _ss_settings_write_all(data):
    _SS_USER_SETTINGS_FILE.parent.mkdir(exist_ok=True)
    _SS_USER_SETTINGS_FILE.write_text(
        _ss_settings_json.dumps(data, ensure_ascii=False, indent=2),
        encoding="utf-8"
    )

def _ss_settings_default():
    return {
        "protection_enabled": True,
        "ai_sensitivity": "high",
        "auto_quarantine": True,
        "notifications_enabled": True,
    }

def _ss_settings_get(username):
    data = _ss_settings_read_all()
    user_settings = data.get(username) or {}
    merged = _ss_settings_default()
    merged.update(user_settings)
    return merged

def _ss_settings_set(username, settings):
    data = _ss_settings_read_all()
    data[username] = settings
    _ss_settings_write_all(data)

def _ss_settings_label(value):
    if value == "low":
        return "Düşük"
    if value == "medium":
        return "Orta"
    if value == "high":
        return "Yüksek"
    if value == "titanium":
        return "Titanium"
    return "Yüksek"

def _ss_user_settings_manage_titanium_final():
    if not (session.get("logged_in") and session.get("username")):
        return redirect("/login")

    if _ss_settings_request.method == "GET":
        return _ss_settings_redirect("/u/settings")

    username = str(session.get("username") or "kullanıcı")

    protection_enabled = _ss_settings_request.form.get("protection_enabled") == "on"
    auto_quarantine = _ss_settings_request.form.get("auto_quarantine") == "on"
    notifications_enabled = _ss_settings_request.form.get("notifications_enabled") == "on"

    ai_sensitivity = (_ss_settings_request.form.get("ai_sensitivity") or "high").strip()
    if ai_sensitivity not in {"low", "medium", "high", "titanium"}:
        ai_sensitivity = "high"

    new_settings = {
        "protection_enabled": protection_enabled,
        "ai_sensitivity": ai_sensitivity,
        "auto_quarantine": auto_quarantine,
        "notifications_enabled": notifications_enabled,
        "updated_at": _ss_titanium_now() if "_ss_titanium_now" in globals() else "",
    }

    _ss_settings_set(username, new_settings)

    try:
        _ss_titanium_event("settings_update", {
            "protection_enabled": protection_enabled,
            "ai_sensitivity": ai_sensitivity,
            "auto_quarantine": auto_quarantine,
            "notifications_enabled": notifications_enabled
        })
    except Exception:
        pass

    _ss_settings_session["ss_settings_saved"] = True
    return _ss_settings_redirect("/u/settings")

def _ss_user_settings_titanium_preferences_page_final():
    if not (session.get("logged_in") and session.get("username")):
        return redirect("/login")

    username = str(session.get("username") or "kullanıcı")
    settings = _ss_settings_get(username)

    saved = bool(_ss_settings_session.pop("ss_settings_saved", False))

    protection_checked = "checked" if settings.get("protection_enabled") else ""
    quarantine_checked = "checked" if settings.get("auto_quarantine") else ""
    notifications_checked = "checked" if settings.get("notifications_enabled") else ""

    sensitivity = settings.get("ai_sensitivity", "high")
    sensitivity_label = _ss_settings_label(sensitivity)

    opt_low = "selected" if sensitivity == "low" else ""
    opt_medium = "selected" if sensitivity == "medium" else ""
    opt_high = "selected" if sensitivity == "high" else ""
    opt_titanium = "selected" if sensitivity == "titanium" else ""

    saved_html = ""
    if saved:
        saved_html = '''
  <section class="saved">
    <b>Ayarlar kaydedildi</b>
    <span>Titanium tercihlerin güncellendi.</span>
  </section>
'''

    html = f"""
<!doctype html>
<html lang="tr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
  <title>EratGuard PRO • Ayarlar</title>
  <style>
    :root{{
      --bg:#020806;
      --line:rgba(35,255,137,.22);
      --green:#20ff88;
      --green2:#8cff5a;
      --text:#f5fff8;
      --muted:rgba(245,255,248,.66);
    }}
    *{{box-sizing:border-box;-webkit-tap-highlight-color:transparent}}
    body{{
      margin:0;
      min-height:100vh;
      background:
        radial-gradient(circle at 50% 0%,rgba(32,255,136,.14),transparent 32%),
        radial-gradient(circle at 88% 76%,rgba(140,255,90,.10),transparent 28%),
        linear-gradient(180deg,#010403,#03150d 58%,#010403);
      color:var(--text);
      font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",Arial,sans-serif;
      padding:14px;
      overflow-x:hidden;
    }}
    .top{{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:14px}}
    .brand{{display:flex;align-items:center;gap:10px;min-width:0}}
    .logo{{
      width:46px;height:46px;border-radius:16px;
      display:grid;place-items:center;
      background:linear-gradient(145deg,rgba(32,255,136,.18),rgba(32,255,136,.04));
      border:1px solid var(--line);
      box-shadow:0 0 20px rgba(32,255,136,.14);
      font-size:24px;
      flex:0 0 auto;
    }}
    h1{{margin:0;font-size:27px;line-height:1;letter-spacing:-1px}}
    h1 span{{color:var(--green2)}}
    .sub{{margin-top:5px;color:var(--muted);font-weight:800;font-size:12px}}
    .badge{{
      color:var(--green);
      border:1px solid var(--line);
      background:rgba(32,255,136,.08);
      border-radius:999px;
      padding:8px 10px;
      font-weight:950;
      font-size:12px;
      white-space:nowrap;
    }}
    .hero{{
      border:1px solid var(--line);
      background:linear-gradient(145deg,rgba(8,35,23,.94),rgba(2,13,8,.92));
      border-radius:22px;
      padding:16px;
      box-shadow:0 18px 44px rgba(0,0,0,.34), inset 0 0 42px rgba(32,255,136,.04);
      margin-bottom:18px;
    }}
    .hero-icon{{
      width:48px;height:48px;border-radius:16px;
      display:grid;place-items:center;
      background:rgba(32,255,136,.10);
      border:1px solid rgba(32,255,136,.18);
      font-size:25px;
      margin-bottom:13px;
    }}
    .hero h2{{margin:0 0 9px;font-size:28px;line-height:1.05;letter-spacing:-1px}}
    .hero p{{margin:0;color:var(--muted);font-size:14px;line-height:1.42;font-weight:800}}
    .stats{{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-top:15px}}
    .stat{{
      border:1px solid rgba(32,255,136,.15);
      background:rgba(0,0,0,.17);
      border-radius:17px;
      padding:10px 6px;
      text-align:center;
    }}
    .stat b{{display:block;color:var(--green);font-size:18px;line-height:1}}
    .stat span{{display:block;margin-top:6px;color:var(--muted);font-weight:900;font-size:9px}}
    .back{{
      display:flex;
      align-items:center;
      justify-content:center;
      min-height:48px;
      margin-top:14px;
      border-radius:17px;
      color:var(--text);
      text-decoration:none;
      font-weight:950;
      font-size:15px;
      background:rgba(255,255,255,.07);
      border:1px solid rgba(255,255,255,.12);
    }}
    .section{{margin:17px 0 8px;letter-spacing:6px;font-weight:1000;font-size:16px}}
    .bar{{width:82px;height:5px;border-radius:999px;background:linear-gradient(90deg,var(--green),var(--green2));margin-bottom:11px}}
    .panel{{
      border:1px solid var(--line);
      background:linear-gradient(145deg,rgba(8,35,23,.92),rgba(2,13,8,.9));
      border-radius:21px;
      padding:14px;
      margin-bottom:14px;
    }}
    .setting-row{{
      display:grid;
      grid-template-columns:1fr auto;
      align-items:center;
      gap:12px;
      padding:14px 0;
      border-bottom:1px solid rgba(245,255,248,.07);
    }}
    .setting-row:last-child{{border-bottom:0}}
    .setting-row b{{display:block;font-size:16px;margin-bottom:5px}}
    .setting-row span{{display:block;color:var(--muted);font-size:12px;font-weight:800;line-height:1.35}}
    .switch input{{display:none}}
    .slider{{
      width:54px;
      height:32px;
      border-radius:999px;
      display:block;
      position:relative;
      background:rgba(255,255,255,.13);
      border:1px solid rgba(255,255,255,.12);
      transition:.2s;
    }}
    .slider:before{{
      content:"";
      position:absolute;
      width:24px;
      height:24px;
      left:4px;
      top:3px;
      border-radius:50%;
      background:rgba(255,255,255,.75);
      transition:.2s;
    }}
    .switch input:checked + .slider{{
      background:linear-gradient(135deg,#00c860,#00e676);
      border-color:rgba(32,255,136,.35);
    }}
    .switch input:checked + .slider:before{{
      transform:translateX(21px);
      background:#02120b;
    }}
    select{{
      width:150px;
      border-radius:15px;
      border:1px solid rgba(35,255,137,.22);
      background:rgba(0,0,0,.25);
      color:#f5fff8;
      padding:10px;
      font-weight:900;
      outline:none;
    }}
    .save-btn{{
      width:100%;
      min-height:50px;
      border:0;
      border-radius:18px;
      color:#02120b;
      background:linear-gradient(135deg,#00c860,#00e676);
      font-weight:1000;
      font-size:16px;
      margin-top:10px;
    }}
    .saved{{
      border:1px solid rgba(32,255,136,.35);
      background:rgba(32,255,136,.10);
      border-radius:18px;
      padding:13px 14px;
      margin-bottom:14px;
    }}
    .saved b{{display:block;color:#98ffb8;font-size:15px}}
    .saved span{{display:block;color:rgba(245,255,248,.68);font-weight:800;font-size:12px;margin-top:4px}}
    .foot{{text-align:center;color:rgba(245,255,248,.38);font-weight:800;padding:22px 0 8px;font-size:12px}}
  </style>
</head>
<body>
  <div class="top">
    <div class="brand">
      <div class="logo">🛡️</div>
      <div>
        <h1>Erat<span>Guard</span></h1>
        <div class="sub">Titanium ayar merkezi</div>
      </div>
    </div>
    <div class="badge">👑 PRO AKTİF</div>
  </div>

  <section class="hero">
    <div class="hero-icon">⚙️</div>
    <h2>Ayarlar</h2>
    <p>Koruma davranışını, AI hassasiyetini, karantina ve bildirim tercihlerini yönet.</p>

    <div class="stats">
      <div class="stat"><b>{"Açık" if settings.get("protection_enabled") else "Kapalı"}</b><span>Koruma</span></div>
      <div class="stat"><b>{_ss_settings_safe(sensitivity_label)}</b><span>AI</span></div>
      <div class="stat"><b>{"Açık" if settings.get("auto_quarantine") else "Kapalı"}</b><span>Karantina</span></div>
    </div>

    <a class="back" href="/radial">← Ana ekrana dön</a>
  </section>

  {saved_html}

  <div class="section">TERCİHLER</div>
  <div class="bar"></div>

  <form method="post" action="/u/settings/manage" class="panel">
    <div class="setting-row">
      <div>
        <b>Koruma Motoru</b>
        <span>SMS ve mesaj tarama sistemini aktif tutar.</span>
      </div>
      <label class="switch">
        <input type="checkbox" name="protection_enabled" {protection_checked}>
        <span class="slider"></span>
      </label>
    </div>

    <div class="setting-row">
      <div>
        <b>AI Hassasiyeti</b>
        <span>Risk tespit seviyesini belirler.</span>
      </div>
      <select name="ai_sensitivity">
        <option value="low" {opt_low}>Düşük</option>
        <option value="medium" {opt_medium}>Orta</option>
        <option value="high" {opt_high}>Yüksek</option>
        <option value="titanium" {opt_titanium}>Titanium</option>
      </select>
    </div>

    <div class="setting-row">
      <div>
        <b>Otomatik Karantina</b>
        <span>Yüksek riskli mesajları otomatik karantinaya alır.</span>
      </div>
      <label class="switch">
        <input type="checkbox" name="auto_quarantine" {quarantine_checked}>
        <span class="slider"></span>
      </label>
    </div>

    <div class="setting-row">
      <div>
        <b>Güvenlik Bildirimleri</b>
        <span>Tarama, risk ve karantina olaylarını bildirim akışına taşır.</span>
      </div>
      <label class="switch">
        <input type="checkbox" name="notifications_enabled" {notifications_checked}>
        <span class="slider"></span>
      </label>
    </div>

    <button class="save-btn" type="submit">Ayarları Kaydet</button>
  </form>

  <div class="foot">EratGuard PRO · {username} · © 2026</div>
</body>
</html>
"""

    resp = _ss_settings_make_response(_ss_settings_render_template_string(html))
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp

try:
    for _rule in list(app.url_map.iter_rules()):
        if str(_rule) == "/u/settings":
            app.view_functions[_rule.endpoint] = _ss_user_settings_titanium_preferences_page_final
        if str(_rule) == "/u/settings/manage":
            app.view_functions[_rule.endpoint] = _ss_user_settings_manage_titanium_final
except Exception as e:
    print("Settings titanium preferences page override skipped:", e)
# ===== SPAMSHIELD USER SETTINGS TITANIUM PREFERENCES UI END =====

# ===== SPAMSHIELD USER LICENSE TITANIUM CENTER UI START =====
from flask import render_template_string as _ss_license_render_template_string
from flask import make_response as _ss_license_make_response
import html as _ss_license_html_escape
from pathlib import Path as _ss_license_Path
import json as _ss_license_json

_SS_LICENSE_FILE = _ss_license_Path("data") / "licenses.json"

def _ss_license_safe(v):
    try:
        return _ss_license_html_escape.escape(str(v or ""))
    except Exception:
        return ""

def _ss_license_read_all():
    try:
        if not _SS_LICENSE_FILE.exists():
            return {}
        return _ss_license_json.loads(_SS_LICENSE_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}

def _ss_license_find_user(username):
    data = _ss_license_read_all()

    if isinstance(data, dict):
        if username in data and isinstance(data.get(username), dict):
            return data.get(username)

        for _, item in data.items():
            if isinstance(item, dict) and str(item.get("username", "")).lower() == str(username).lower():
                return item

    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict) and str(item.get("username", "")).lower() == str(username).lower():
                return item

    return {}

def _ss_license_plan_label(plan):
    plan = str(plan or "").lower()
    if "lifetime" in plan:
        return "Lifetime Shield"
    if "year" in plan or "pro_yearly" in plan:
        return "Shield Pro+"
    if "month" in plan or "starter" in plan:
        return "Starter Shield"
    if "pro" in plan:
        return "Shield Pro"
    return "PRO Aktif"

def _ss_user_license_titanium_center_page_final():
    if not (session.get("logged_in") and session.get("username")):
        return redirect("/login")

    username = str(session.get("username") or "kullanıcı")
    lic = _ss_license_find_user(username)

    plan_raw = lic.get("plan") or lic.get("plan_key") or lic.get("license_type") or "pro_active"
    plan_label = lic.get("plan_label") or _ss_license_plan_label(plan_raw)
    expiry = lic.get("expires_at") or lic.get("expiry") or lic.get("license_expiry") or "Aktif"
    status = lic.get("status") or "active"

    if str(status).lower() in {"active", "aktif", "valid", "ok"}:
        status_label = "Aktif"
        status_note = "PRO lisansın aktif görünüyor. Titanium özellikleri kullanılabilir."
    else:
        status_label = "Kontrol"
        status_note = "Lisans durumu kontrol edilmeli. Gerekirse fiyatlandırma sayfasından yenileyebilirsin."

    if not lic:
        plan_label = "PRO Aktif"
        expiry = "Aktif"
        status_label = "Aktif"
        status_note = "Kullanıcı oturumu PRO erişimde. Lisans merkezi Titanium modda hazır."

    html = f"""
<!doctype html>
<html lang="tr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
  <title>EratGuard PRO • Lisans</title>
  <style>
    :root{{
      --bg:#020806;
      --line:rgba(35,255,137,.22);
      --green:#20ff88;
      --green2:#8cff5a;
      --text:#f5fff8;
      --muted:rgba(245,255,248,.66);
    }}
    *{{box-sizing:border-box;-webkit-tap-highlight-color:transparent}}
    body{{
      margin:0;
      min-height:100vh;
      background:
        radial-gradient(circle at 50% 0%,rgba(32,255,136,.14),transparent 32%),
        radial-gradient(circle at 88% 76%,rgba(140,255,90,.10),transparent 28%),
        linear-gradient(180deg,#010403,#03150d 58%,#010403);
      color:var(--text);
      font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",Arial,sans-serif;
      padding:14px;
      overflow-x:hidden;
    }}
    .top{{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:14px}}
    .brand{{display:flex;align-items:center;gap:10px;min-width:0}}
    .logo{{
      width:46px;height:46px;border-radius:16px;
      display:grid;place-items:center;
      background:linear-gradient(145deg,rgba(32,255,136,.18),rgba(32,255,136,.04));
      border:1px solid var(--line);
      box-shadow:0 0 20px rgba(32,255,136,.14);
      font-size:24px;
      flex:0 0 auto;
    }}
    h1{{margin:0;font-size:27px;line-height:1;letter-spacing:-1px}}
    h1 span{{color:var(--green2)}}
    .sub{{margin-top:5px;color:var(--muted);font-weight:800;font-size:12px}}
    .badge{{
      color:var(--green);
      border:1px solid var(--line);
      background:rgba(32,255,136,.08);
      border-radius:999px;
      padding:8px 10px;
      font-weight:950;
      font-size:12px;
      white-space:nowrap;
    }}
    .hero{{
      border:1px solid var(--line);
      background:linear-gradient(145deg,rgba(8,35,23,.94),rgba(2,13,8,.92));
      border-radius:22px;
      padding:16px;
      box-shadow:0 18px 44px rgba(0,0,0,.34), inset 0 0 42px rgba(32,255,136,.04);
      margin-bottom:18px;
    }}
    .hero-icon{{
      width:52px;height:52px;border-radius:17px;
      display:grid;place-items:center;
      background:rgba(32,255,136,.10);
      border:1px solid rgba(32,255,136,.18);
      font-size:27px;
      margin-bottom:13px;
    }}
    .hero h2{{margin:0 0 9px;font-size:29px;line-height:1.05;letter-spacing:-1px}}
    .hero p{{margin:0;color:var(--muted);font-size:14px;line-height:1.42;font-weight:800}}
    .stats{{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-top:15px}}
    .stat{{
      border:1px solid rgba(32,255,136,.15);
      background:rgba(0,0,0,.17);
      border-radius:17px;
      padding:10px 6px;
      text-align:center;
    }}
    .stat b{{display:block;color:var(--green);font-size:17px;line-height:1;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}}
    .stat span{{display:block;margin-top:6px;color:var(--muted);font-weight:900;font-size:9px}}
    .actions{{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:14px}}
    .btn{{
      display:flex;
      align-items:center;
      justify-content:center;
      min-height:48px;
      border-radius:17px;
      text-decoration:none;
      font-weight:1000;
      font-size:14px;
    }}
    .btn.primary{{color:#02120b;background:linear-gradient(135deg,#00c860,#00e676)}}
    .btn.ghost{{color:var(--text);background:rgba(255,255,255,.07);border:1px solid rgba(255,255,255,.12)}}
    .section{{margin:17px 0 8px;letter-spacing:6px;font-weight:1000;font-size:16px}}
    .bar{{width:82px;height:5px;border-radius:999px;background:linear-gradient(90deg,var(--green),var(--green2));margin-bottom:11px}}
    .panel{{
      border:1px solid var(--line);
      background:linear-gradient(145deg,rgba(8,35,23,.92),rgba(2,13,8,.9));
      border-radius:21px;
      padding:6px 14px;
      margin-bottom:14px;
    }}
    .row{{
      display:grid;
      grid-template-columns:1fr auto auto;
      align-items:center;
      gap:10px;
      padding:13px 0;
      border-bottom:1px solid rgba(245,255,248,.07);
    }}
    .row:last-child{{border-bottom:0}}
    .row b{{font-size:15px}}
    .row span{{color:#98ffb8;font-weight:950;font-size:13px;text-align:right}}
    .tick{{
      width:30px;height:30px;border-radius:999px;
      display:grid;place-items:center;
      color:#9affb9;
      border:1px solid rgba(32,255,136,.22);
      background:rgba(32,255,136,.09);
      font-weight:950;
    }}
    .feature-grid{{display:grid;gap:10px}}
    .feature{{
      border:1px solid rgba(35,255,137,.22);
      background:linear-gradient(145deg,rgba(8,35,23,.92),rgba(2,13,8,.9));
      border-radius:19px;
      padding:14px;
    }}
    .feature h3{{margin:0 0 6px;font-size:19px;line-height:1.05}}
    .feature p{{margin:0;color:rgba(245,255,248,.66);font-weight:800;font-size:12px;line-height:1.38}}
    .foot{{text-align:center;color:rgba(245,255,248,.38);font-weight:800;padding:22px 0 8px;font-size:12px}}
  </style>
</head>
<body>
  <div class="top">
    <div class="brand">
      <div class="logo">🛡️</div>
      <div>
        <h1>Erat<span>Guard</span></h1>
        <div class="sub">Titanium lisans merkezi</div>
      </div>
    </div>
    <div class="badge">👑 PRO AKTİF</div>
  </div>

  <section class="hero">
    <div class="hero-icon">👑</div>
    <h2>Lisans</h2>
    <p>{_ss_license_safe(status_note)}</p>

    <div class="stats">
      <div class="stat"><b>{_ss_license_safe(status_label)}</b><span>Durum</span></div>
      <div class="stat"><b>{_ss_license_safe(plan_label)}</b><span>Plan</span></div>
      <div class="stat"><b>{_ss_license_safe(expiry)}</b><span>Süre</span></div>
    </div>

    <div class="actions">
      <a class="btn ghost" href="/radial">← Ana ekran</a>
      <a class="btn primary" href="/u/pricing">Planları Gör</a>
    </div>
  </section>

  <div class="section">LİSANS</div>
  <div class="bar"></div>

  <section class="panel">
    <div class="row"><b>Kullanıcı</b><span>{_ss_license_safe(username)}</span><div class="tick">✓</div></div>
    <div class="row"><b>Plan</b><span>{_ss_license_safe(plan_label)}</span><div class="tick">✓</div></div>
    <div class="row"><b>Lisans Durumu</b><span>{_ss_license_safe(status_label)}</span><div class="tick">✓</div></div>
    <div class="row"><b>PRO Erişim</b><span>Aktif</span><div class="tick">✓</div></div>
  </section>

  <div class="section">ÖZELLİKLER</div>
  <div class="bar"></div>

  <main class="feature-grid">
    <article class="feature">
      <h3>Titanium Tarama</h3>
      <p>Koruma ve AI Analiz sayfalarında SMS risk skoru çıkarılır.</p>
    </article>

    <article class="feature">
      <h3>Otomatik Karantina</h3>
      <p>Yüksek riskli mesajlar Engellenenler merkezinde güvenli alana alınır.</p>
    </article>

    <article class="feature">
      <h3>Rapor ve Bildirim</h3>
      <p>Analiz, karantina ve güvenlik olayları raporlanır ve bildirim akışına düşer.</p>
    </article>

    <article class="feature">
      <h3>Premium Güvenlik Akışı</h3>
      <p>Tara, analiz et, karantinaya al, raporla ve kullanıcıya bildir.</p>
    </article>
  </main>

  <div class="foot">EratGuard PRO · {username} · © 2026</div>
</body>
</html>
"""

    resp = _ss_license_make_response(_ss_license_render_template_string(html))
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp

try:
    for _rule in list(app.url_map.iter_rules()):
        if str(_rule) == "/u/license":
            app.view_functions[_rule.endpoint] = _ss_user_license_titanium_center_page_final
except Exception as e:
    print("License titanium center page override skipped:", e)
# ===== SPAMSHIELD USER LICENSE TITANIUM CENTER UI END =====

# ===== SPAMSHIELD USER COMMUNITY TITANIUM FEEDBACK UI START =====
from flask import render_template_string as _ss_comm_render_template_string
from flask import make_response as _ss_comm_make_response
from flask import request as _ss_comm_request
from flask import redirect as _ss_comm_redirect
from flask import session as _ss_comm_session
from pathlib import Path as _ss_comm_Path
import json as _ss_comm_json
import html as _ss_comm_html_escape

_SS_COMMUNITY_FILE = _ss_comm_Path("data") / "user_community_feedback.json"

def _ss_comm_safe(v):
    try:
        return _ss_comm_html_escape.escape(str(v or ""))
    except Exception:
        return ""

def _ss_comm_read_all():
    try:
        if not _SS_COMMUNITY_FILE.exists():
            return []
        data = _ss_comm_json.loads(_SS_COMMUNITY_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except Exception:
        return []

def _ss_comm_write_all(data):
    _SS_COMMUNITY_FILE.parent.mkdir(exist_ok=True)
    _SS_COMMUNITY_FILE.write_text(
        _ss_comm_json.dumps(data[-300:], ensure_ascii=False, indent=2),
        encoding="utf-8"
    )

def _ss_user_community_feedback_post_final():
    if not (session.get("logged_in") and session.get("username")):
        return redirect("/login")

    username = str(session.get("username") or "kullanıcı")
    category = (_ss_comm_request.form.get("category") or "suggestion").strip()
    message = (_ss_comm_request.form.get("message") or "").strip()

    if category not in {"suggestion", "bug", "experience", "security"}:
        category = "suggestion"

    if not message:
        _ss_comm_session["ss_community_feedback_status"] = {
            "ok": False,
            "message": "Geri bildirim için kısa bir not yazmalısın."
        }
        return _ss_comm_redirect("/u/community")

    all_items = _ss_comm_read_all()
    item = {
        "created_at": _ss_titanium_now() if "_ss_titanium_now" in globals() else "",
        "username": username,
        "category": category,
        "message": message[:800],
        "status": "received"
    }
    all_items.append(item)
    _ss_comm_write_all(all_items)

    try:
        _ss_titanium_event("community_feedback", {
            "category": category,
            "status": "received"
        })
    except Exception:
        pass

    _ss_comm_session["ss_community_feedback_status"] = {
        "ok": True,
        "message": "Geri bildirimin alındı. EratGuard PRO gelişim havuzuna eklendi."
    }
    return _ss_comm_redirect("/u/community")

def _ss_comm_category_label(category):
    category = str(category or "")
    if category == "bug":
        return "Hata"
    if category == "experience":
        return "Deneyim"
    if category == "security":
        return "Güvenlik"
    return "Öneri"

def _ss_user_community_titanium_feedback_page_final():
    if not (session.get("logged_in") and session.get("username")):
        return redirect("/login")

    username = str(session.get("username") or "kullanıcı")
    status = _ss_comm_session.pop("ss_community_feedback_status", None)

    all_items = _ss_comm_read_all()
    user_items = [x for x in all_items if x.get("username") == username]
    last_items = list(reversed(user_items[-6:]))

    total_feedback = len(user_items)
    security_feedback = sum(1 for x in user_items if x.get("category") == "security")
    bug_feedback = sum(1 for x in user_items if x.get("category") == "bug")

    status_html = ""
    if status:
        ok = bool(status.get("ok"))
        title = "Gönderildi" if ok else "Eksik bilgi"
        status_html = f'''
  <section class="notice {'ok' if ok else 'warn'}">
    <b>{title}</b>
    <span>{_ss_comm_safe(status.get("message"))}</span>
  </section>
'''

    if last_items:
        feedback_cards = ""
        for item in last_items:
            label = _ss_comm_safe(_ss_comm_category_label(item.get("category")))
            created = _ss_comm_safe(item.get("created_at"))
            msg = _ss_comm_safe(item.get("message"))
            if len(msg) > 120:
                msg = msg[:120] + "..."

            feedback_cards += f'''
    <article class="feedback-card">
      <div class="feedback-top">
        <div>
          <h3>{label}</h3>
          <p>{msg}</p>
        </div>
        <div class="feedback-badge">✓</div>
      </div>
      <div class="feedback-meta">
        <span>{created}</span>
        <span>Alındı</span>
      </div>
    </article>
'''
    else:
        feedback_cards = '''
    <article class="feedback-empty">
      <h3>Henüz geri bildirim yok</h3>
      <p>Öneri, hata, güvenlik fikri veya deneyimini buradan gönderebilirsin.</p>
    </article>
'''

    html = f"""
<!doctype html>
<html lang="tr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
  <title>EratGuard PRO • Topluluk</title>
  <style>
    :root{{
      --bg:#020806;
      --line:rgba(35,255,137,.22);
      --green:#20ff88;
      --green2:#8cff5a;
      --text:#f5fff8;
      --muted:rgba(245,255,248,.66);
    }}
    *{{box-sizing:border-box;-webkit-tap-highlight-color:transparent}}
    body{{
      margin:0;
      min-height:100vh;
      background:
        radial-gradient(circle at 50% 0%,rgba(32,255,136,.14),transparent 32%),
        radial-gradient(circle at 88% 76%,rgba(140,255,90,.10),transparent 28%),
        linear-gradient(180deg,#010403,#03150d 58%,#010403);
      color:var(--text);
      font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",Arial,sans-serif;
      padding:14px;
      overflow-x:hidden;
    }}
    .top{{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:14px}}
    .brand{{display:flex;align-items:center;gap:10px;min-width:0}}
    .logo{{
      width:46px;height:46px;border-radius:16px;
      display:grid;place-items:center;
      background:linear-gradient(145deg,rgba(32,255,136,.18),rgba(32,255,136,.04));
      border:1px solid var(--line);
      box-shadow:0 0 20px rgba(32,255,136,.14);
      font-size:24px;
      flex:0 0 auto;
    }}
    h1{{margin:0;font-size:27px;line-height:1;letter-spacing:-1px}}
    h1 span{{color:var(--green2)}}
    .sub{{margin-top:5px;color:var(--muted);font-weight:800;font-size:12px}}
    .badge{{
      color:var(--green);
      border:1px solid var(--line);
      background:rgba(32,255,136,.08);
      border-radius:999px;
      padding:8px 10px;
      font-weight:950;
      font-size:12px;
      white-space:nowrap;
    }}
    .hero{{
      border:1px solid var(--line);
      background:linear-gradient(145deg,rgba(8,35,23,.94),rgba(2,13,8,.92));
      border-radius:22px;
      padding:16px;
      box-shadow:0 18px 44px rgba(0,0,0,.34), inset 0 0 42px rgba(32,255,136,.04);
      margin-bottom:18px;
    }}
    .hero-icon{{
      width:52px;height:52px;border-radius:17px;
      display:grid;place-items:center;
      background:rgba(32,255,136,.10);
      border:1px solid rgba(32,255,136,.18);
      font-size:27px;
      margin-bottom:13px;
    }}
    .hero h2{{margin:0 0 9px;font-size:29px;line-height:1.05;letter-spacing:-1px}}
    .hero p{{margin:0;color:var(--muted);font-size:14px;line-height:1.42;font-weight:800}}
    .stats{{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-top:15px}}
    .stat{{
      border:1px solid rgba(32,255,136,.15);
      background:rgba(0,0,0,.17);
      border-radius:17px;
      padding:10px 6px;
      text-align:center;
    }}
    .stat b{{display:block;color:var(--green);font-size:18px;line-height:1}}
    .stat span{{display:block;margin-top:6px;color:var(--muted);font-weight:900;font-size:9px}}
    .back{{
      display:flex;
      align-items:center;
      justify-content:center;
      min-height:48px;
      margin-top:14px;
      border-radius:17px;
      color:var(--text);
      text-decoration:none;
      font-weight:950;
      font-size:15px;
      background:rgba(255,255,255,.07);
      border:1px solid rgba(255,255,255,.12);
    }}
    .section{{margin:17px 0 8px;letter-spacing:6px;font-weight:1000;font-size:16px}}
    .bar{{width:82px;height:5px;border-radius:999px;background:linear-gradient(90deg,var(--green),var(--green2));margin-bottom:11px}}
    .panel{{
      border:1px solid var(--line);
      background:linear-gradient(145deg,rgba(8,35,23,.92),rgba(2,13,8,.9));
      border-radius:21px;
      padding:14px;
      margin-bottom:14px;
    }}
    label{{display:block;font-weight:950;margin:0 0 8px;color:#f5fff8;font-size:14px}}
    select, textarea{{
      width:100%;
      border-radius:17px;
      border:1px solid rgba(35,255,137,.22);
      background:rgba(0,0,0,.22);
      color:#f5fff8;
      padding:12px;
      font:800 13px system-ui;
      outline:none;
      margin-bottom:10px;
    }}
    textarea{{resize:vertical;min-height:112px}}
    .send-btn{{
      width:100%;
      min-height:50px;
      border:0;
      border-radius:18px;
      color:#02120b;
      background:linear-gradient(135deg,#00c860,#00e676);
      font-weight:1000;
      font-size:16px;
    }}
    .notice{{
      border-radius:18px;
      padding:13px 14px;
      margin-bottom:14px;
      border:1px solid rgba(32,255,136,.35);
      background:rgba(32,255,136,.10);
    }}
    .notice.warn{{
      border-color:rgba(255,190,90,.34);
      background:rgba(255,190,90,.10);
    }}
    .notice b{{display:block;color:#98ffb8;font-size:15px}}
    .notice.warn b{{color:#ffd18a}}
    .notice span{{display:block;color:rgba(245,255,248,.68);font-weight:800;font-size:12px;margin-top:4px}}
    .feedback-list{{display:grid;gap:10px}}
    .feedback-card{{
      border:1px solid rgba(35,255,137,.22);
      background:linear-gradient(145deg,rgba(8,35,23,.92),rgba(2,13,8,.9));
      border-radius:19px;
      padding:14px;
    }}
    .feedback-top{{display:grid;grid-template-columns:1fr auto;gap:10px;align-items:start}}
    .feedback-card h3{{margin:0 0 6px;font-size:19px;line-height:1.05}}
    .feedback-card p{{margin:0;color:rgba(245,255,248,.66);font-weight:800;font-size:12px;line-height:1.38;word-break:break-word}}
    .feedback-badge{{
      width:38px;height:38px;border-radius:15px;
      display:grid;place-items:center;
      color:#02120b;
      background:linear-gradient(135deg,#00c860,#00e676);
      font-weight:1000;
      font-size:18px;
    }}
    .feedback-meta{{
      display:flex;
      justify-content:space-between;
      gap:8px;
      margin-top:11px;
      color:rgba(245,255,248,.52);
      font-size:10px;
      font-weight:900;
      flex-wrap:wrap;
    }}
    .feedback-empty{{
      border:1px solid rgba(35,255,137,.22);
      background:linear-gradient(145deg,rgba(8,35,23,.92),rgba(2,13,8,.9));
      border-radius:19px;
      padding:15px;
    }}
    .feedback-empty h3{{margin:0 0 7px;font-size:19px}}
    .feedback-empty p{{margin:0;color:rgba(245,255,248,.66);font-weight:800;font-size:12px;line-height:1.4}}
    .foot{{text-align:center;color:rgba(245,255,248,.38);font-weight:800;padding:22px 0 8px;font-size:12px}}
  </style>
</head>
<body>
  <div class="top">
    <div class="brand">
      <div class="logo">🛡️</div>
      <div>
        <h1>Erat<span>Guard</span></h1>
        <div class="sub">Titanium topluluk merkezi</div>
      </div>
    </div>
    <div class="badge">👑 PRO AKTİF</div>
  </div>

  <section class="hero">
    <div class="hero-icon">🌐</div>
    <h2>Topluluk</h2>
    <p>EratGuard PRO’yu birlikte daha güçlü hale getirmek için öneri, hata ve güvenlik geri bildirimi gönder.</p>

    <div class="stats">
      <div class="stat"><b>{total_feedback}</b><span>Geri Bildirim</span></div>
      <div class="stat"><b>{security_feedback}</b><span>Güvenlik</span></div>
      <div class="stat"><b>{bug_feedback}</b><span>Hata</span></div>
    </div>

    <a class="back" href="/radial">← Ana ekrana dön</a>
  </section>

  {status_html}

  <div class="section">GÖNDER</div>
  <div class="bar"></div>

  <form method="post" action="/u/community/feedback" class="panel">
    <label>Geri bildirim türü</label>
    <select name="category">
      <option value="suggestion">Öneri</option>
      <option value="bug">Hata bildirimi</option>
      <option value="experience">Kullanıcı deneyimi</option>
      <option value="security">Güvenlik fikri</option>
    </select>

    <label>Mesajın</label>
    <textarea name="message" placeholder="EratGuard PRO için önerini, hatanı veya geliştirme fikrini yaz..."></textarea>

    <button class="send-btn" type="submit">Geri Bildirim Gönder</button>
  </form>

  <div class="section">SON KAYITLAR</div>
  <div class="bar"></div>

  <main class="feedback-list">
    {feedback_cards}
  </main>

  <div class="foot">EratGuard PRO · {username} · © 2026</div>
</body>
</html>
"""

    resp = _ss_comm_make_response(_ss_comm_render_template_string(html))
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp

try:
    app.add_url_rule(
        "/u/community/feedback",
        endpoint="ss_user_community_feedback_post_final",
        view_func=_ss_user_community_feedback_post_final,
        methods=["POST"]
    )
except Exception as e:
    print("Community feedback route register skipped:", e)

try:
    for _rule in list(app.url_map.iter_rules()):
        if str(_rule) == "/u/community":
            app.view_functions[_rule.endpoint] = _ss_user_community_titanium_feedback_page_final
except Exception as e:
    print("Community titanium feedback page override skipped:", e)
# ===== SPAMSHIELD USER COMMUNITY TITANIUM FEEDBACK UI END =====

# ===== ERATGUARD PUBLIC LEGAL PAGES START =====
from flask import render_template_string as _ss_legal_public_render_template_string
from flask import make_response as _ss_legal_public_make_response

def _ss_public_legal_page(title, subtitle, body_html):
    html = f"""
<!doctype html>
<html lang="tr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
  <title>{title} - EratGuard PRO</title>
  <style>
    :root{{
      --bg:#020806;
      --line:rgba(35,255,137,.22);
      --green:#20ff88;
      --green2:#8cff5a;
      --text:#f5fff8;
      --muted:rgba(245,255,248,.68);
    }}
    *{{box-sizing:border-box}}
    body{{
      margin:0;
      min-height:100vh;
      background:
        radial-gradient(circle at 50% 0%,rgba(32,255,136,.14),transparent 32%),
        linear-gradient(180deg,#010403,#03150d 58%,#010403);
      color:var(--text);
      font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",Arial,sans-serif;
      padding:16px;
    }}
    .wrap{{max-width:860px;margin:0 auto}}
    .top{{
      display:flex;
      align-items:center;
      justify-content:space-between;
      gap:12px;
      margin-bottom:16px;
    }}
    .brand{{display:flex;align-items:center;gap:10px}}
    .logo{{
      width:46px;height:46px;border-radius:16px;
      display:grid;place-items:center;
      background:linear-gradient(145deg,rgba(32,255,136,.18),rgba(32,255,136,.04));
      border:1px solid var(--line);
      font-size:24px;
    }}
    h1{{margin:0;font-size:26px;letter-spacing:-1px}}
    h1 span{{color:var(--green2)}}
    .nav a{{
      color:#98ffb8;
      text-decoration:none;
      font-weight:900;
      font-size:13px;
      margin-left:10px;
    }}
    .hero{{
      border:1px solid var(--line);
      background:linear-gradient(145deg,rgba(8,35,23,.94),rgba(2,13,8,.92));
      border-radius:24px;
      padding:20px;
      margin-bottom:14px;
      box-shadow:0 18px 44px rgba(0,0,0,.34);
    }}
    .hero h2{{margin:0 0 8px;font-size:30px;line-height:1.05}}
    .hero p{{margin:0;color:var(--muted);font-weight:800;line-height:1.45}}
    .panel{{
      border:1px solid var(--line);
      background:linear-gradient(145deg,rgba(8,35,23,.92),rgba(2,13,8,.9));
      border-radius:22px;
      padding:18px;
      margin-bottom:14px;
    }}
    h3{{margin:18px 0 8px;font-size:20px;color:#f5fff8}}
    h3:first-child{{margin-top:0}}
    p, li{{color:var(--muted);font-weight:750;line-height:1.55;font-size:14px}}
    ul{{padding-left:20px}}
    .notice{{
      border:1px solid rgba(32,255,136,.28);
      background:rgba(32,255,136,.08);
      border-radius:18px;
      padding:13px;
      color:#98ffb8;
      font-weight:900;
      margin-top:12px;
    }}
    .foot{{
      text-align:center;
      color:rgba(245,255,248,.42);
      font-weight:800;
      font-size:12px;
      padding:18px 0 8px;
    }}
    @media(max-width:560px){{
      .top{{align-items:flex-start;flex-direction:column}}
      .nav a{{margin-left:0;margin-right:10px;display:inline-block;margin-top:6px}}
    }}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="top">
      <div class="brand">
        <div class="logo">🛡️</div>
        <div>
          <h1>Spam<span>Shield</span> PRO</h1>
          <div style="color:rgba(245,255,248,.55);font-weight:800;font-size:12px">Yasal ve bilgilendirme merkezi</div>
        </div>
      </div>
      <div class="nav">
        <a href="/pricing">Fiyatlandırma</a>
        <a href="/privacy">Gizlilik</a>
        <a href="/terms">Şartlar</a>
        <a href="/refund">İade</a>
        <a href="/contact">İletişim</a>
      </div>
    </div>

    <section class="hero">
      <h2>{title}</h2>
      <p>{subtitle}</p>
    </section>

    <section class="panel">
      {body_html}
    </section>

    <div class="foot">© 2026 EratGuard PRO · Tüm hakları saklıdır.</div>
  </div>
</body>
</html>
"""
    resp = _ss_legal_public_make_response(_ss_legal_public_render_template_string(html))
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp


@app.route("/privacy")
@app.route("/gizlilik")
def ss_public_privacy_page():
    return _ss_public_legal_page(
        "Gizlilik ve KVKK Politikası",
        "EratGuard PRO kullanıcı verilerinin korunması, gizlilik ve kişisel veri işleme ilkeleri.",
        """
        <h3>Gizlilik İlkesi</h3>
        <p>EratGuard PRO, kullanıcı güvenliğini artırmak için tasarlanmış dijital bir güvenlik ve spam analiz hizmetidir. Kullanıcı verileri yalnızca hizmetin çalışması, lisans yönetimi, güvenlik analizi ve destek süreçleri için kullanılır.</p>

        <h3>İşlenen Veriler</h3>
        <ul>
          <li>Kullanıcı adı ve oturum bilgileri</li>
          <li>Lisans ve plan bilgileri</li>
          <li>Kullanıcının analiz için manuel olarak girdiği SMS/metin örnekleri</li>
          <li>Risk skoru, karantina ve güvenlik olay kayıtları</li>
          <li>Topluluk geri bildirimleri</li>
        </ul>

        <h3>Ödeme Bilgileri</h3>
        <p>Kart bilgileri EratGuard PRO içinde saklanmaz. Satın alma süreci lisans talebi ve ödeme onayı üzerinden yürütülür.</p>

        <h3>KVKK Bilgilendirmesi</h3>
        <p>Kişisel veriler; hizmet sunumu, kullanıcı güvenliği, lisans aktivasyonu, destek ve yasal yükümlülükler kapsamında işlenebilir. Kullanıcılar kişisel verileriyle ilgili bilgi alma, düzeltme ve silme taleplerini iletişim kanalları üzerinden iletebilir.</p>

        <h3>Saklama ve Güvenlik</h3>
        <p>Veriler, hizmetin gerektirdiği süre boyunca saklanır. EratGuard PRO, yetkisiz erişime karşı makul teknik ve idari önlemler almayı hedefler.</p>

        <div class="notice">Bu sayfa kullanıcı bilgilendirmesi ve yayın incelemesi için kamusal bilgilendirme amacıyla hazırlanmıştır.</div>
        """
    )


@app.route("/terms")
@app.route("/mesafeli-satis")
def ss_public_terms_page():
    return _ss_public_legal_page(
        "Kullanım Şartları ve Mesafeli Satış Bilgilendirmesi",
        "EratGuard PRO dijital lisans hizmetinin kullanım, satış ve aktivasyon koşulları.",
        """
        <h3>Hizmet Tanımı</h3>
        <p>EratGuard PRO; SMS/metin spam analizi, risk skoru, otomatik karantina, raporlama, bildirim ve lisans tabanlı kullanıcı paneli özellikleri sunan dijital bir yazılım hizmetidir.</p>

        <h3>Dijital Ürün ve Lisans</h3>
        <p>Satın alma işlemi sonrasında kullanıcıya dijital hizmet/lisans erişimi sağlanır. Lisans aktif edildiğinde kullanıcı premium özelliklerden yararlanabilir.</p>

        <h3>Kullanıcı Sorumluluğu</h3>
        <ul>
          <li>Kullanıcı, hesap bilgilerini güvenli tutmakla sorumludur.</li>
          <li>Hizmet kötüye kullanım, yasa dışı faaliyet veya üçüncü kişilerin haklarını ihlal edecek şekilde kullanılamaz.</li>
          <li>EratGuard PRO analiz sonuçları bilgilendirme amaçlıdır; nihai karar kullanıcı sorumluluğundadır.</li>
        </ul>

        <h3>Ödeme ve Aktivasyon</h3>
        <p>Satın alma süreci lisans talebi ve ödeme onayı üzerinden yürütülür. Ödeme onayı sonrası lisans aktivasyonu EratGuard PRO lisans merkezi üzerinden yapılır.</p>

        <h3>Hizmet Değişiklikleri</h3>
        <p>EratGuard PRO, güvenlik ve performans gerekçeleriyle özelliklerde iyileştirme, güncelleme veya değişiklik yapabilir.</p>

        <div class="notice">Mesafeli satış ve kullanım şartları yayın öncesi firma bilgileriyle son kez kontrol edilmelidir.</div>
        """
    )


@app.route("/refund")
@app.route("/iade")
def ss_public_refund_page():
    return _ss_public_legal_page(
        "İptal ve İade Politikası",
        "EratGuard PRO dijital lisans satın alımlarında iptal, iade ve aktivasyon bilgilendirmesi.",
        """
        <h3>Dijital Ürün Niteliği</h3>
        <p>EratGuard PRO dijital yazılım/lisans hizmetidir. Lisans aktif edildikten ve premium erişim kullanıma açıldıktan sonra dijital ürün niteliği gereği iade koşulları sınırlı olabilir.</p>

        <h3>Aktivasyon Öncesi Talepler</h3>
        <p>Ödeme yapılmış ancak lisans aktivasyonu tamamlanmamışsa kullanıcı destek kanalı üzerinden iptal veya iade talebi oluşturabilir.</p>

        <h3>Teknik Sorunlar</h3>
        <p>Kullanıcı, hizmete erişememe veya lisans aktivasyon sorunu yaşarsa destek ekibiyle iletişime geçebilir. Öncelik, sorunun giderilmesi ve hizmetin kullanılabilir hale getirilmesidir.</p>

        <h3>İade Değerlendirmesi</h3>
        <p>İade talepleri; ödeme durumu, lisans aktivasyonu, kullanım durumu ve ilgili mevzuat dikkate alınarak değerlendirilir.</p>

        <h3>Ödeme Güvenliği</h3>
        <p>Kart bilgileri EratGuard PRO tarafından saklanmaz. Ödeme işlemleri güvenli ödeme altyapısı üzerinden gerçekleştirilir.</p>

        <div class="notice">İade politikası dijital lisans mantığına göre hazırlanmıştır; yayın öncesi firma bilgileri ve süreçler netleştirilmelidir.</div>
        """
    )


@app.route("/contact")
@app.route("/iletisim")
def ss_public_contact_page():
    return _ss_public_legal_page(
        "İletişim",
        "EratGuard PRO destek, lisans, ödeme ve güvenlik bildirimleri için iletişim bilgileri.",
        """
        <h3>Destek ve İletişim</h3>
        <p>EratGuard PRO ile ilgili lisans, ödeme, teknik destek, güvenlik bildirimi ve geri bildirim talepleri için aşağıdaki iletişim kanalları kullanılabilir.</p>

        <h3>E-posta</h3>
        <p>Destek e-posta adresi: <strong>eratguardprotr@gmail.com</strong></p>

        <h3>Firma / Yayıncı Bilgileri</h3>
        <ul>
          <li>Yayıncı / Hizmet Sağlayıcı: İsmail Erat</li>
          <li>Ürün / Marka: EratGuard PRO</li>
          <li>Hizmet türü: Dijital yazılım / lisans tabanlı güvenlik hizmeti</li>
          <li>Adres: Isparta / Türkiye</li>
          <li>Destek e-posta: eratguardprotr@gmail.com</li>
          <li>Ödeme altyapısı: EratGuard lisans talebi ve ödeme onayı süreci</li>
        </ul>

        <h3>Vergi / Kimlik Bilgisi</h3>
        <p>Vergi ve kimlik bilgileri güvenlik nedeniyle herkese açık sitede yayınlanmaz; yalnızca resmi başvuru ve ödeme sağlayıcı panelinde paylaşılır.</p>

        <h3>Önemli Not</h3>
        <p>EratGuard PRO bireysel yayıncı tarafından geliştirilen dijital yazılım/lisans hizmetidir. Resmi başvuru süreçlerinde gerekli bilgiler ilgili ödeme sağlayıcı panelinden paylaşılır.</p>

        <div class="notice">İletişim ve yayıncı bilgileri kullanıcı bilgilendirmesine uygun şekilde güncellenmiştir.</div>
        """
    )
# ===== ERATGUARD PUBLIC LEGAL PAGES END =====

# ===== ERATGUARD BETA PUBLIC/USER ALIAS FIX START =====
# v1.0.0-beta probe fix:
# These aliases prevent old/short links from returning 404 during beta testing.

@app.route("/u")
def eratguard_alias_u_root():
    return redirect("/app-start")

@app.route("/u/home")
def eratguard_alias_u_home():
    return redirect("/app-start")

@app.route("/legal")
def eratguard_alias_public_legal():
    return redirect("/u/legal")

@app.route("/forgot")
def eratguard_alias_forgot():
    return redirect("/forgot-password")
# ===== ERATGUARD BETA PUBLIC/USER ALIAS FIX END =====

# ===== ERATGUARD BETA SECURITY HARDENING START =====
# Defensive hardening for v1.0.0-beta:
# - Security headers
# - Lightweight in-memory rate limit for login/admin/forgot-password POST requests

from collections import defaultdict as _eg_defaultdict
import time as _eg_time

_eg_rate_buckets = _eg_defaultdict(list)

def _eg_client_ip():
    try:
        xff = request.headers.get("X-Forwarded-For", "")
        if xff:
            return xff.split(",")[0].strip()
        return request.headers.get("CF-Connecting-IP") or request.remote_addr or "unknown"
    except Exception:
        return "unknown"

def _eg_rate_limit_check(bucket_name, limit, window_seconds):
    now = _eg_time.time()
    ip = _eg_client_ip()
    key = f"{bucket_name}:{ip}"

    bucket = _eg_rate_buckets[key]
    bucket[:] = [t for t in bucket if now - t < window_seconds]

    if len(bucket) >= limit:
        return False, int(window_seconds - (now - bucket[0]))

    bucket.append(now)
    return True, 0

@app.before_request
def eratguard_beta_rate_limit_guard():
    try:
        path = request.path
        method = request.method.upper()

        if method != "POST":
            return None

        rules = {
            "/ss-admin-access": ("admin-login", 8, 15 * 60),
            "/login": ("user-login", 12, 15 * 60),
            "/forgot-password": ("forgot-password", 5, 15 * 60),
            "/forgot": ("forgot-password-alias", 5, 15 * 60),
        }

        if path not in rules:
            return None

        bucket, limit, window = rules[path]
        ok, retry_after = _eg_rate_limit_check(bucket, limit, window)

        if ok:
            return None

        resp = app.response_class(
            "<h2>EratGuard PRO</h2><p>Çok fazla deneme yapıldı. Lütfen biraz sonra tekrar deneyin.</p>",
            status=429,
            mimetype="text/html",
        )
        resp.headers["Retry-After"] = str(max(retry_after, 60))
        return resp

    except Exception:
        return None

@app.after_request
def eratguard_beta_security_headers(resp):
    try:
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        resp.headers.setdefault(
            "Permissions-Policy",
            "geolocation=(), microphone=(), camera=(), payment=()"
        )

        resp.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self' https: data: blob:; "
            "script-src 'self' 'unsafe-inline' https:; "
            "style-src 'self' 'unsafe-inline' https:; "
            "img-src 'self' data: https:; "
            "font-src 'self' data: https:; "
            "connect-src 'self' https:; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )

        if request.scheme == "https" or request.headers.get("X-Forwarded-Proto") == "https":
            resp.headers.setdefault(
                "Strict-Transport-Security",
                "max-age=31536000; includeSubDomains"
            )

    except Exception:
        pass

    return resp
# ===== ERATGUARD BETA SECURITY HARDENING END =====

# ===== ERATGUARD SESSION COOKIE HARDENING START =====
# Ensure Flask session cookies are protected in production.
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
# ===== ERATGUARD SESSION COOKIE HARDENING END =====

# ===== ERATGUARD MANUAL LICENSE ADMIN FLOW START =====
def _eg_admin_payment_requests_for_template():
    try:
        return _eg_load_payment_requests()
    except Exception:
        return []


@app.route("/admin/payment-requests-live")
@app.route("/admin/license-requests")
def eg_admin_license_requests_live():
    if not session.get("admin_logged_in"):
        return redirect("/ss-admin-access")

    requests_data = _eg_admin_payment_requests_for_template()
    requests_data = sorted(
        requests_data,
        key=lambda x: str(x.get("created_at", "")),
        reverse=True
    )

    return render_template(
        "admin_payment_requests.html",
        requests=requests_data
    )


@app.route("/admin/license-request/approve/<order_no>", methods=["POST", "GET"])
def eg_admin_approve_license_request(order_no):
    if not session.get("admin_logged_in"):
        return redirect("/ss-admin-access")

    requests_data = _eg_load_payment_requests()
    users = load_users()

    changed = False
    approved_license = ""

    for item in requests_data:
        if str(item.get("order_no", "")) == str(order_no):
            username = str(item.get("username", "") or "").strip()
            if not username:
                continue

            user = users.get(username, {}) if isinstance(users, dict) else {}

            license_key = str(item.get("license_key", "") or "").strip().upper()
            if not license_key:
                license_key = generate_unique_license_key(users)

            user["active"] = True
            user["license_key"] = license_key
            user["license_type"] = "lifetime" if item.get("plan") == "lifetime" else "pro"
            user["plan"] = item.get("plan", "pro_yearly")
            user["expires_at"] = "2099-12-31" if item.get("plan") == "lifetime" else "2027-12-31"

            users[username] = user

            item["status"] = "approved_license_assigned"
            item["license_key"] = license_key
            item["admin_note"] = "Admin onayıyla lisans kullanıcı hesabına tanımlandı."
            changed = True
            approved_license = license_key
            break

    if changed:
        save_users(users)
        _eg_save_payment_requests(requests_data)

    return redirect("/admin/license-requests")


@app.route("/admin/license-request/reject/<order_no>", methods=["POST", "GET"])
def eg_admin_reject_license_request(order_no):
    if not session.get("admin_logged_in"):
        return redirect("/ss-admin-access")

    requests_data = _eg_load_payment_requests()
    changed = False

    for item in requests_data:
        if str(item.get("order_no", "")) == str(order_no):
            item["status"] = "rejected_or_cancelled"
            item["admin_note"] = "Talep admin tarafından iptal edildi."
            changed = True
            break

    if changed:
        _eg_save_payment_requests(requests_data)

    return redirect("/admin/license-requests")


@app.route("/admin/payment-requests")
def eg_admin_payment_requests_redirect_final():
    return redirect("/admin/license-requests")
# ===== ERATGUARD MANUAL LICENSE ADMIN FLOW END =====

# ===== ERATGUARD ONE-TIME LICENSE VALIDATION START =====
def _eg_norm_license_key(value):
    return str(value or "").strip().upper()


def _eg_mark_payment_request_license_used(license_key, username):
    items = _eg_load_payment_requests()
    changed = False
    found = False

    for item in items:
        item_key = _eg_norm_license_key(item.get("license_key"))
        item_user = str(item.get("username", "") or "").strip()
        status = str(item.get("status", "") or "")

        if item_key == license_key:
            found = True

            if item_user and item_user != username:
                return False, "Bu lisans başka bir kullanıcı hesabına atanmış."

            if "approved" not in status:
                return False, "Bu lisans henüz admin tarafından onaylanmamış."

            if item.get("used") is True and item.get("activated_by") != username:
                return False, "Bu lisans daha önce kullanılmış."

            item["used"] = True
            item["activated_by"] = username
            item["activated_at"] = __import__("datetime").datetime.now().isoformat(timespec="seconds")
            changed = True
            break

    if changed:
        _eg_save_payment_requests(items)

    return found, ""


def _eg_check_generated_license_once(license_key, username):
    import json
    from pathlib import Path
    from datetime import datetime

    p = Path("data/generated_licenses.json")
    if not p.exists():
        return False, "not_found"

    try:
        data = json.loads(p.read_text(encoding="utf-8") or "[]")
    except Exception:
        return False, "not_found"

    if not isinstance(data, list):
        return False, "not_found"

    changed = False
    for item in data:
        if _eg_norm_license_key(item.get("key")) != license_key:
            continue

        if item.get("used") is True:
            if str(item.get("activated_by", "")) == str(username):
                return True, "already_owned"
            return False, "Bu lisans daha önce kullanılmış."

        item["used"] = True
        item["activated_by"] = username
        item["activated_at"] = datetime.now().isoformat(timespec="seconds")
        changed = True

        if changed:
            p.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

        return True, ""

    return False, "not_found"


def _eg_check_legacy_license_once(license_key, username):
    import json
    from pathlib import Path
    from datetime import datetime

    p = Path("data/licenses.json")
    if not p.exists():
        return False, "not_found"

    try:
        data = json.loads(p.read_text(encoding="utf-8") or "{}")
    except Exception:
        return False, "not_found"

    if not isinstance(data, dict):
        return False, "not_found"

    item = data.get(license_key)
    if not isinstance(item, dict):
        return False, "not_found"

    assigned_user = str(item.get("username", "") or item.get("activated_by", "") or "").strip()
    used = bool(item.get("used")) or str(item.get("status", "")).lower() in ("used", "active")

    if assigned_user and assigned_user != username:
        return False, "Bu lisans başka bir kullanıcı hesabına atanmış."

    if used and assigned_user != username:
        return False, "Bu lisans daha önce kullanılmış."

    item["used"] = True
    item["status"] = "active"
    item["username"] = username
    item["activated_by"] = username
    item["activated_at"] = datetime.now().isoformat(timespec="seconds")

    data[license_key] = item
    p.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

    return True, ""


def _eg_validate_one_time_license(license_key, username):
    license_key = _eg_norm_license_key(license_key)

    if not license_key:
        return False, "Lütfen lisans kodu girin."

    if len(license_key) < 8:
        return False, "Lisans kodu çok kısa görünüyor."

    found, msg = _eg_mark_payment_request_license_used(license_key, username)
    if found:
        if msg:
            return False, msg
        return True, ""

    ok, msg = _eg_check_generated_license_once(license_key, username)
    if ok:
        return True, ""
    if msg != "not_found":
        return False, msg

    ok, msg = _eg_check_legacy_license_once(license_key, username)
    if ok:
        return True, ""
    if msg != "not_found":
        return False, msg

    return False, "Bu lisans kodu sistemde onaylı veya kullanılabilir durumda değil."


def _eg_final_one_time_user_license():
    if not login_required():
        return redirect(url_for("login"))

    username = session.get("username", "user")
    users = load_users()
    user = users.get(username, {}) if isinstance(users, dict) else {}

    message = None
    error = None

    if request.method == "POST":
        license_key = _eg_norm_license_key(request.form.get("license_key"))

        ok, err = _eg_validate_one_time_license(license_key, username)

        if not ok:
            error = err
        else:
            user["license_key"] = license_key
            user["license_type"] = "pro"
            user["plan"] = "pro"
            user["active"] = True
            user["expires_at"] = user.get("expires_at") or "2099-12-31"
            users[username] = user
            save_users(users)
            message = "Lisans başarıyla aktifleştirildi. Bu lisans artık bu kullanıcı hesabına kilitlendi."

    license_key = user.get("license_key") or "Yok"
    plan = user.get("license_type") or user.get("plan") or "trial"
    expires_at = user.get("expires_at") or "Belirtilmedi"
    active = user.get("active", True)

    plan_label = "PRO" if str(plan).lower() in ["pro", "premium", "lifetime"] else "Deneme"
    license_status_label = "AKTİF" if active else "PASİF"
    premium_access = "Açık" if active else "Kapalı"

    days_left = "∞"
    if expires_at and expires_at not in ["Belirtilmedi", "2099-12-31", "2099-01-01"]:
        try:
            from datetime import datetime
            exp = datetime.strptime(expires_at[:10], "%Y-%m-%d")
            days_left = max(0, (exp - datetime.now()).days)
        except Exception:
            days_left = "∞"

    return render_template(
        "license_center.html",
        username=username,
        user=user,
        license_key=license_key,
        plan_label=plan_label,
        license_status_label=license_status_label,
        expires_at=expires_at,
        premium_access=premium_access,
        days_left=days_left,
        message=message,
        error=error
    )


# Final route override: daha önce /u/license başka fonksiyona bağlandıysa bunu tekrar güvenli tek-kullanımlık akışa bağla.
try:
    for _rule in list(app.url_map.iter_rules()):
        if str(_rule) == "/u/license":
            app.view_functions[_rule.endpoint] = _eg_final_one_time_user_license
except Exception as _eg_license_override_error:
    print("ONE_TIME_LICENSE_OVERRIDE_WARN:", _eg_license_override_error, flush=True)
# ===== ERATGUARD ONE-TIME LICENSE VALIDATION END =====

# ===== ERATGUARD ADMIN SYSTEM RESOURCES API START =====
@app.route("/api/system-resources")
def _eg_admin_system_resources_api_final():
    try:
        import os
        import time

        cpu_percent = 0
        memory_percent = 0
        disk_percent = 0

        try:
            import psutil
            cpu_percent = float(psutil.cpu_percent(interval=0.15))
            memory_percent = float(psutil.virtual_memory().percent)
            disk_percent = float(psutil.disk_usage(".").percent)
        except Exception:
            # CPU fallback from /proc/stat
            try:
                def _read_cpu():
                    with open("/proc/stat", "r", encoding="utf-8") as f:
                        parts = f.readline().split()[1:]
                    nums = [int(x) for x in parts[:8]]
                    idle = nums[3] + (nums[4] if len(nums) > 4 else 0)
                    total = sum(nums)
                    return idle, total

                idle1, total1 = _read_cpu()
                time.sleep(0.12)
                idle2, total2 = _read_cpu()
                total_delta = max(total2 - total1, 1)
                idle_delta = max(idle2 - idle1, 0)
                cpu_percent = round(100.0 * (1.0 - idle_delta / total_delta), 1)
            except Exception:
                cpu_percent = 0

            # Memory fallback from /proc/meminfo
            try:
                mem = {}
                with open("/proc/meminfo", "r", encoding="utf-8") as f:
                    for line in f:
                        key, val = line.split(":", 1)
                        mem[key] = int(val.strip().split()[0])
                total = float(mem.get("MemTotal", 0))
                available = float(mem.get("MemAvailable", mem.get("MemFree", 0)))
                if total > 0:
                    memory_percent = round(100.0 * (total - available) / total, 1)
            except Exception:
                memory_percent = 0

            # Disk fallback
            try:
                st = os.statvfs(".")
                total = float(st.f_blocks * st.f_frsize)
                free = float(st.f_bavail * st.f_frsize)
                if total > 0:
                    disk_percent = round(100.0 * (total - free) / total, 1)
            except Exception:
                disk_percent = 0

        return jsonify({
            "ok": True,
            "cpu_percent": round(float(cpu_percent), 1),
            "memory_percent": round(float(memory_percent), 1),
            "disk_percent": round(float(disk_percent), 1),
            "network": "LIVE",
        })
    except Exception as e:
        return jsonify({
            "ok": False,
            "cpu_percent": 0,
            "memory_percent": 0,
            "disk_percent": 0,
            "network": "LIVE",
            "error": str(e),
        }), 200
# ===== ERATGUARD ADMIN SYSTEM RESOURCES API END =====
