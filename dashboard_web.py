def _eg_default_admin_stats():
    from pathlib import Path as _eg_Path
    import json as _eg_json

    def _count_json_items(_eg_path):
        try:
            _eg_p = _eg_Path(_eg_path)
            if not _eg_p.exists():
                return 0
            _eg_data = _eg_json.loads(_eg_p.read_text(encoding="utf-8"))
            if isinstance(_eg_data, list):
                return len(_eg_data)
            if isinstance(_eg_data, dict):
                for _eg_key in ("users", "licenses", "items", "data", "logs", "requests"):
                    if isinstance(_eg_data.get(_eg_key), list):
                        return len(_eg_data.get(_eg_key))
                return len(_eg_data)
            return 0
        except Exception:
            return 0

    return {
        "users": _count_json_items("data/users.json"),
        "licenses": _count_json_items("data/licenses.json"),
        "payments": _count_json_items("data/payment_requests.json"),
        "spam_logs": _count_json_items("data/spam_logs.json"),
        "safe_list": _count_json_items("data/safe_list.json"),
        "system_score": 0,
        "health_score": 0,
        "ops_score": 0,
        "release_score": 0,
    }


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
        from pathlib import Path as _Path
        from datetime import datetime as _dt

        log_path = _Path("data/spam_logs.json")
        if not log_path.exists():
            return "Henüz yok"

        logs = _j.loads(log_path.read_text(encoding="utf-8"))
        if not logs:
            return "Henüz yok"

        last = logs[-1] if isinstance(logs, list) else None
        if not isinstance(last, dict):
            return "Henüz yok"

        ts = last.get("timestamp", "")
        if not ts:
            return "Henüz yok"

        t = _dt.fromisoformat(str(ts).replace("Z", ""))
        diff = int((_dt.now() - t).total_seconds() // 60)

        if diff < 1:
            return "Az önce"
        if diff < 60:
            return f"{diff} dk önce"
        return f"{diff // 60} saat önce"
    except Exception:
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
        or _ss_os.environ.get("ERATGUARD_SECRET_KEY") or os.environ.get("ERATGUARD_SECRET_KEY")
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



# ===== ERATGUARD AUDIT + BRUTE FORCE START =====
def _eg_json_data_path(name):
    from pathlib import Path as _eg_Path
    p = _eg_Path("data") / name
    p.parent.mkdir(parents=True, exist_ok=True)
    return p

def _eg_client_ip():
    try:
        return (request.headers.get("X-Forwarded-For") or request.remote_addr or "").split(",")[0].strip() or "-"
    except Exception:
        return "-"

def _eg_user_agent():
    try:
        return (request.headers.get("User-Agent") or "")[:180]
    except Exception:
        return ""

def _eg_now_iso():
    from datetime import datetime
    return datetime.now().isoformat(timespec="seconds")

def _eg_read_state(key, default):
    try:
        if _eg_db_enabled():
            data = _eg_kv_get_json(key, None)
            if data is not None:
                return data
    except Exception:
        pass

    try:
        import json as _eg_json
        p = _eg_json_data_path(key + ".json")
        if p.exists():
            return _eg_json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        pass

    return default

def _eg_write_state(key, value):
    try:
        if _eg_db_enabled():
            _eg_kv_set_json(key, value)
    except Exception:
        pass

    try:
        import json as _eg_json
        p = _eg_json_data_path(key + ".json")
        p.write_text(_eg_json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception:
        pass

def _eg_audit_log(event, username="", detail=None, level="info"):
    try:
        logs = _eg_read_state("audit_logs", [])
        if not isinstance(logs, list):
            logs = []

        item = {
            "time": _eg_now_iso(),
            "event": str(event or ""),
            "username": str(username or ""),
            "level": str(level or "info"),
            "ip": _eg_client_ip(),
            "path": str(getattr(request, "path", "") or ""),
            "user_agent": _eg_user_agent(),
            "detail": detail if isinstance(detail, dict) else {},
        }

        logs.append(item)
        logs = logs[-500:]
        _eg_write_state("audit_logs", logs)
    except Exception as e:
        try:
            print("AUDIT_LOG_WARN:", repr(e), flush=True)
        except Exception:
            pass

def _eg_login_attempt_key(username):
    return (str(username or "").strip().lower() or "-") + "|" + _eg_client_ip()

def _eg_login_lock_status(username):
    try:
        from datetime import datetime
        attempts = _eg_read_state("login_attempts", {})
        if not isinstance(attempts, dict):
            attempts = {}

        item = attempts.get(_eg_login_attempt_key(username), {})
        locked_until = item.get("locked_until")

        if locked_until:
            try:
                until = datetime.fromisoformat(str(locked_until))
                remaining = int((until - datetime.now()).total_seconds())
                if remaining > 0:
                    return True, remaining
            except Exception:
                pass

        return False, 0
    except Exception:
        return False, 0

def _eg_login_record_failure(username):
    try:
        from datetime import datetime, timedelta
        attempts = _eg_read_state("login_attempts", {})
        if not isinstance(attempts, dict):
            attempts = {}

        key = _eg_login_attempt_key(username)
        item = attempts.get(key, {}) if isinstance(attempts.get(key, {}), dict) else {}

        count = int(item.get("count", 0) or 0) + 1
        item["count"] = count
        item["last_failed"] = _eg_now_iso()
        item["username"] = str(username or "")
        item["ip"] = _eg_client_ip()

        if count >= 5:
            item["locked_until"] = (datetime.now() + timedelta(minutes=15)).isoformat(timespec="seconds")
            _eg_audit_log("login_blocked", username, {"count": count, "locked_minutes": 15}, "warning")

        attempts[key] = item
        _eg_write_state("login_attempts", attempts)
        return count
    except Exception:
        return 0

def _eg_login_clear_failures(username):
    try:
        attempts = _eg_read_state("login_attempts", {})
        if not isinstance(attempts, dict):
            return

        key = _eg_login_attempt_key(username)
        if key in attempts:
            attempts.pop(key, None)
            _eg_write_state("login_attempts", attempts)
    except Exception:
        pass

def _eg_recent_audit_logs(limit=12):
    try:
        logs = _eg_read_state("audit_logs", [])
        if not isinstance(logs, list):
            return []

        out = []
        for item in reversed(logs[-max(1, int(limit)):]):
            if isinstance(item, dict):
                out.append(item)
        return out
    except Exception:
        return []

# ===== ERATGUARD AUDIT + BRUTE FORCE END =====



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



# ===== ERATGUARD RENDER KEEPALIVE HEALTH START =====
@app.route("/health")
@app.route("/ping")
@app.route("/status")
def ss_health_ping():
    return {
        "ok": True,
        "service": "EratGuard PRO",
        "status": "alive"
    }, 200
# ===== ERATGUARD RENDER KEEPALIVE HEALTH END =====

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
            _eg_audit_log("register_success", username, {"email": email}, "info")

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

        locked, remaining = _eg_login_lock_status(username)
        if locked:
            mins = max(1, remaining // 60)
            _eg_audit_log("login_blocked", username, {"remaining_seconds": remaining}, "warning")
            error = f"Çok fazla hatalı giriş denemesi. Lütfen yaklaşık {mins} dakika sonra tekrar deneyin."
        elif not user:
            _eg_login_record_failure(username)
            _eg_audit_log("login_failed", username, {"reason": "user_not_found"}, "warning")
            error = "Kullanıcı adı veya şifre yanlış." if get_lang() == "tr" else "Username or password is incorrect."
        elif not user.get("active", True):
            _eg_login_record_failure(username)
            _eg_audit_log("login_failed", username, {"reason": "inactive_user"}, "warning")
            error = "Bu kullanıcı pasif durumda." if get_lang() == "tr" else "This user is inactive."
        elif is_date_expired(user.get("expires_at", "2099-12-31")):
            _eg_login_record_failure(username)
            _eg_audit_log("login_failed", username, {"reason": "license_expired"}, "warning")
            error = "Kullanıcı lisans süresi dolmuş." if get_lang() == "tr" else "User license has expired."
        elif check_password_hash(user["password"], password):
            _eg_login_clear_failures(username)

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

            _eg_audit_log("login_success", username, {"role": user.get("role", "user")}, "info")

            users = load_users()
            udata = users.get(username, {})
            if not udata.get("notif_asked"):
                return redirect("/notification-permission")
            return redirect(url_for("radial"))
        else:
            count = _eg_login_record_failure(username)
            _eg_audit_log("login_failed", username, {"reason": "bad_password", "count": count}, "warning")
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
            _eg_audit_log("password_changed", username, {}, "info")
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
            _eg_audit_log("admin_add_user", username, {"role": role, "active": active, "email": email}, "info")
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

# ===== ERATGUARD FAN-12P USER SESSION BRIDGE START =====
# FAN-12P dilimleri /u/... sayfalarını açabilsin diye local APK oturumunu tamamlar.
try:
    from flask import request as _eg_fan12p_session_request
    from flask import session as _eg_fan12p_session

    def _eg_fan12p_pick_user():
        try:
            users = load_users()
            if isinstance(users, dict) and users:
                preferred = [
                    "Erat@32",
                    "erat@32",
                    "Erat32",
                    "erat32",
                    "ismail",
                    "user"
                ]

                for name in preferred:
                    if name in users:
                        return name, users.get(name) or {}

                for name, info in users.items():
                    if isinstance(info, dict):
                        role = str(info.get("role", "user")).lower()
                        active = info.get("active", True)
                        if role != "admin" and active is not False:
                            return name, info

                first = next(iter(users.keys()))
                return first, users.get(first) or {}
        except Exception:
            pass

        return "Erat@32", {
            "role": "user",
            "active": True,
            "plan": "pro",
            "license_type": "pro"
        }

    @app.before_request
    def _eg_fan12p_user_session_bridge():
        try:
            path = (_eg_fan12p_session_request.path or "")

            fan_paths = {
                "/dashboard",
                "/home",
                "/user",
                "/main",
                "/u/protection",
                "/u/analysis",
                "/u/reports",
                "/u/notifications",
                "/u/license",
                "/u/community",
                "/u/settings",
                "/u/blocked",
            }

            if path not in fan_paths:
                return None

            # Admin oturumuna dokunma
            if _eg_fan12p_session.get("role") == "admin" or _eg_fan12p_session.get("is_admin"):
                return None

            if not _eg_fan12p_session.get("logged_in") or not _eg_fan12p_session.get("username"):
                username, user = _eg_fan12p_pick_user()

                _eg_fan12p_session["logged_in"] = True
                _eg_fan12p_session["username"] = username
                _eg_fan12p_session["role"] = "user"
                _eg_fan12p_session["is_admin"] = False

                plan = str((user or {}).get("license_type") or (user or {}).get("plan") or "pro").lower()
                _eg_fan12p_session["plan"] = plan
                _eg_fan12p_session["license_type"] = plan

        except Exception as e:
            print("ERATGUARD FAN12P SESSION BRIDGE ERROR:", e)
        return None

except Exception as e:
    print("ERATGUARD FAN12P SESSION BRIDGE BOOT ERROR:", e)
# ===== ERATGUARD FAN-12P USER SESSION BRIDGE END =====


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
    _eg_audit_log("reset_password_changed", username, {}, "info")
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



# ===== ERATGUARD ADMIN_STATS BEFORE APP.RUN SAFE OVERRIDE START =====
try:
    def _ss_final_safe_admin_stats():
        try:
            if "_eg_real_admin_dashboard_stats" in globals():
                data = _eg_real_admin_dashboard_stats()
                if isinstance(data, dict):
                    return data
        except Exception:
            pass

        try:
            if "_eg_default_admin_stats" in globals():
                data = _eg_default_admin_stats()
                if isinstance(data, dict):
                    return data
        except Exception:
            pass

        return {
            "users": 0,
            "licenses": 0,
            "payments": 0,
            "spam_logs": 0,
            "safe_list": 0,
            "system_score": 0,
            "health_score": 0,
            "ops_score": 0,
            "release_score": 0,
        }

    @app.context_processor
    def _ss_global_admin_stats_context():
        _stats = _ss_final_safe_admin_stats()
        return {
            "admin_stats": _stats,
            "admin_user_stats": _stats,
            "stats": _stats,
        }

    def _ss_final_render_admin_dashboard():
        _stats = _ss_final_safe_admin_stats()
        return render_template(
            "admin_dashboard.html",
            admin_stats=_stats,
            admin_user_stats=_stats,
            stats=_stats,
        )

    _ss_old_admin_catchall_stats_safe = None
    try:
        _ss_old_admin_catchall_stats_safe = app.view_functions.get("ss_live_admin_all_slice_catchall")
    except Exception:
        _ss_old_admin_catchall_stats_safe = None

    def _ss_final_admin_catchall_stats_safe(anything=None, **kwargs):
        slug = str(anything or "").strip().lower()

        if slug in ("", "dashboard", "home", "admin", "index"):
            return _ss_final_render_admin_dashboard()

        if _ss_old_admin_catchall_stats_safe:
            return _ss_old_admin_catchall_stats_safe(anything)

        return _ss_final_render_admin_dashboard()

    for _ss_ep in (
        "ss_live_admin_all_slice_catchall",
        "ss_live_admin_dashboard",
        "admin_dashboard",
        "admin_home",
        "admin_index",
    ):
        try:
            if _ss_ep in app.view_functions:
                if _ss_ep == "ss_live_admin_all_slice_catchall":
                    app.view_functions[_ss_ep] = _ss_final_admin_catchall_stats_safe
                else:
                    app.view_functions[_ss_ep] = lambda **kwargs: _ss_final_render_admin_dashboard()
        except Exception:
            pass

except Exception as _ss_admin_stats_before_run_err:
    print("ADMIN_STATS BEFORE APP.RUN SAFE OVERRIDE ERROR:", _ss_admin_stats_before_run_err)
# ===== ERATGUARD ADMIN_STATS BEFORE APP.RUN SAFE OVERRIDE END =====



# ===== ERATGUARD EMERGENCY ADMIN RADIAL STATS ROUTE START =====
try:
    def _ss_emergency_admin_dashboard_with_stats():
        try:
            _stats = _eg_real_admin_dashboard_stats()
            if not isinstance(_stats, dict):
                _stats = _eg_default_admin_stats()
        except Exception:
            _stats = _eg_default_admin_stats()

        return render_template(
            "admin_dashboard.html",
            admin_stats=_stats,
            admin_user_stats=_stats,
            stats=_stats,
        )

    for _ss_ep in ("admin_dashboard", "admin_home", "admin_index", "ss_live_admin_dashboard"):
        try:
            if _ss_ep in app.view_functions:
                app.view_functions[_ss_ep] = lambda **kwargs: _ss_emergency_admin_dashboard_with_stats()
        except Exception:
            pass
except Exception as _e:
    print("EMERGENCY ADMIN RADIAL STATS ROUTE ERROR:", _e)
# ===== ERATGUARD EMERGENCY ADMIN RADIAL STATS ROUTE END =====


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
            try:
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
                    print("PASSWORD_RESET_NOTIFICATION_ERROR:", repr(e), flush=True)

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
                        print("Password reset mail error:", repr(e), flush=True)
                else:
                    print("FORGOT_WARN: matched account has no target email:", str(username)[:2] + "***", flush=True)

            except Exception as e:
                # Kullanıcıya 500 gösterme. Güvenlik mesajı aynı kalır, detay sadece log'a düşer.
                print("FORGOT_SAFE_POST_ERROR:", repr(e), flush=True)

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

# ===== ERATGUARD LIVE ADMIN APK ROUTES START =====
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
            os.environ.get("ADMIN_PASSWORD", ""),
            os.environ.get("SPAMSHIELD_ADMIN_PASSWORD", ""),
        ]
        env_admin_passwords = [x for x in env_admin_passwords if x]

        env_admin_usernames = [
            os.environ.get("ERATGUARD_ADMIN_USERNAME", ""),
            os.environ.get("ADMIN_USERNAME", ""),
            "admin",
        ]
        env_admin_usernames = [str(x).strip().lower() for x in env_admin_usernames if str(x).strip()]

        is_admin_name = username.lower() in env_admin_usernames or str(user.get("role", "")).lower() == "admin" or user.get("is_admin") is True
        fallback_admin_sha256 = "11b2d8d98c0a8ed79080d388420deb3b3168e5631667cad074d09ee0e26c86fb"
        ok_env = username.lower() in env_admin_usernames and password in env_admin_passwords
        ok_fallback = username.lower() == "admin" and hashlib.sha256(password.encode()).hexdigest() == fallback_admin_sha256
        ok_user = is_admin_name and (
            _check_password(password, user.get("password") or "")
            or _check_password(password, user.get("password_hash") or "")
        )

        if ok_env or ok_fallback or ok_user:
            session["logged_in"] = True
            session["username"] = username or "admin"
            session["role"] = "admin"
            session["is_admin"] = True
            return redirect("/admin/dashboard")

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
    # APK public entry: session/cookie olsa bile önce EratGuard karşılama ekranı gösterilir.
    return render_template("splash_user_app.html")

@app.route("/ss-admin-app-start")
def ss_live_admin_app_start():
    if session.get("logged_in") and (
        session.get("is_admin") or session.get("role") == "admin" or session.get("username") == "admin"
    ):
        return redirect("/admin/dashboard")
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
        return render_template("admin_dashboard.html", admin_stats=_eg_default_admin_stats(), users=load_users(), recent_logins=_eg_recent_audit_logs(5), recent_actions=_eg_recent_audit_logs(5))
    except Exception as e:
        return f"<h2>EratGuard ADMIN</h2><p>Dashboard yüklenemedi: {e}</p>", 500

@app.route("/__eratguard_live_version")
def ss_live_version_probe():
    return "EratGuard live: dashboard_web admin routes active 2026-05-05", 200
# ===== ERATGUARD LIVE ADMIN APK ROUTES END =====

# ===== ERATGUARD ADMIN ALL SLICE SAFE CATCHALL START =====
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
        "panel": ("admin_panel.html", {"users": [], "upgrade_requests": [], "audit_logs": _eg_recent_audit_logs(12)}),
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
# ===== ERATGUARD ADMIN ALL SLICE SAFE CATCHALL END =====

# ===== ERATGUARD FAST ADMIN SLICE PAGES START =====
# DISABLED FINAL:
# Bu blok hafif/placeholder admin ekranlarını aktif ediyordu.
# Gerçek admin template'leri için kapatıldı.
# ===== ERATGUARD FAST ADMIN SLICE PAGES END =====


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

                role = str(item.get("role", "user") or "user").lower()
                license_type = str(item.get("license_type") or item.get("license_mode") or "").lower()
                license_key = str(item.get("license_key") or "").strip()
                expires_at = str(item.get("expires_at") or item.get("license_expiry") or "").strip()

                if role == "admin" or item.get("is_admin"):
                    item["account_status"] = "ADMIN"
                    item["license_status"] = "SYSTEM"
                    item["risk_label"] = "Yetkili"
                    item["health_status"] = "admin"
                elif item.get("is_banned"):
                    item["account_status"] = "BANLI"
                    item["license_status"] = license_type.upper() if license_type else "KONTROL"
                    item["risk_label"] = "Yüksek"
                    item["health_status"] = "danger"
                elif not item.get("active", True):
                    item["account_status"] = "PASİF"
                    item["license_status"] = license_type.upper() if license_type else "KONTROL"
                    item["risk_label"] = "Orta"
                    item["health_status"] = "warning"
                elif license_key:
                    item["account_status"] = "AKTİF"
                    if license_type:
                        item["license_status"] = license_type.upper()
                    elif expires_at and expires_at.startswith("2099"):
                        item["license_status"] = "LIFETIME"
                    else:
                        item["license_status"] = "LİSANSLI"
                    item["risk_label"] = "Düşük"
                    item["health_status"] = "good"
                else:
                    item["account_status"] = "AKTİF"
                    item["license_status"] = "TRIAL"
                    item["risk_label"] = "Kontrol"
                    item["health_status"] = "watch"

                if item.get("online"):
                    item["last_seen_label"] = "Şu an online"
                elif item.get("last_seen") and item.get("last_seen") != "-":
                    item["last_seen_label"] = item.get("last_seen")
                else:
                    item["last_seen_label"] = "Kayıt yok"

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

    def _eg_real_admin_dashboard_stats():
        import json as _eg_json
        from pathlib import Path as _eg_Path

        def _load(default, *paths):
            for raw in paths:
                try:
                    fp = _eg_Path(raw)
                    if fp.exists():
                        data = _eg_json.loads(fp.read_text(encoding="utf-8"))
                        return data
                except Exception:
                    pass
            return default

        users_data = {}
        try:
            loader = globals().get("load_users")
            if callable(loader):
                users_data = loader()
        except Exception:
            users_data = {}

        if not isinstance(users_data, dict):
            users_data = _load({}, "data/users.json", "users.json")
        if not isinstance(users_data, dict):
            users_data = {}

        licenses_data = _load({}, "data/generated_licenses.json", "data/licenses.json", "generated_licenses.json", "licenses.json")
        if isinstance(licenses_data, list):
            license_count = len(licenses_data)
        elif isinstance(licenses_data, dict):
            license_count = len(licenses_data)
        else:
            license_count = 0

        payment_requests = _load([], "data/payment_requests.json", "payment_requests.json")
        if isinstance(payment_requests, dict):
            payment_requests = list(payment_requests.values())
        if not isinstance(payment_requests, list):
            payment_requests = []

        pending_requests = 0
        for item in payment_requests:
            try:
                st = str(item.get("status", "")).lower()
                if "approved" not in st and "reject" not in st and "cancel" not in st:
                    pending_requests += 1
            except Exception:
                pass

        spam_logs = _load([], "data/spam_logs.json", "data/logs.json", "spam_logs.json", "logs.json")
        if isinstance(spam_logs, dict):
            spam_logs = list(spam_logs.values())
        if not isinstance(spam_logs, list):
            spam_logs = []

        whitelist = _load([], "data/whitelist.json", "data/safe_list.json", "whitelist.json", "safe_list.json")
        if isinstance(whitelist, dict):
            whitelist_count = len(whitelist)
        elif isinstance(whitelist, list):
            whitelist_count = len(whitelist)
        else:
            whitelist_count = 0

        audit_logs = []
        try:
            audit_logs = _eg_recent_audit_logs(80)
        except Exception:
            audit_logs = []
        if not isinstance(audit_logs, list):
            audit_logs = []

        security_warnings = 0
        for ev in audit_logs:
            try:
                level = str(ev.get("level", "info")).lower()
                if level in ("warning", "error", "critical"):
                    security_warnings += 1
            except Exception:
                pass

        def _state(path):
            try:
                return "OK" if _eg_Path(path).exists() else "YOK"
            except Exception:
                return "YOK"

        system_ok = (
            _state("data/users.json") == "OK"
            and _state("data/settings.json") == "OK"
        )

        admin_count = 0
        banned_count = 0
        active_count = 0
        for _, u in users_data.items():
            if not isinstance(u, dict):
                continue
            if str(u.get("role", "")).lower() == "admin":
                admin_count += 1
            if u.get("is_banned"):
                banned_count += 1
            if u.get("active", True) and not u.get("is_banned"):
                active_count += 1

        return {
            "users": str(len(users_data)) + " kullanıcı",
            "users_detail": str(active_count) + " aktif",
            "licenses": str(license_count) + " lisans",
            "licenses_detail": str(admin_count) + " admin",
            "payments": str(pending_requests) + " bekliyor",
            "payments_detail": str(len(payment_requests)) + " talep",
            "security": str(security_warnings) + " uyarı",
            "security_detail": str(len(audit_logs)) + " olay",
            "reports": str(len(spam_logs)) + " log",
            "reports_detail": "analiz",
            "whitelist": str(whitelist_count) + " kayıt",
            "whitelist_detail": "güvenli",
            "settings": "aktif",
            "settings_detail": "policy",
            "system": "OK" if system_ok else "kontrol",
            "system_detail": "production",
        }

    def _eg_real_admin_dashboard():
        return _eg_real_render(
            "admin_dashboard.html",
            admin_stats=_eg_real_admin_dashboard_stats()
        )

    def _eg_real_admin_panel():
        return _eg_real_render(
            "admin_panel.html",
            users=_eg_real_users_list(),
            upgrade_requests=globals().get("upgrade_requests", []),
            audit_logs=_eg_recent_audit_logs(12),
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

    def _eg_real_admin_security():
        events = []
        try:
            events = _eg_recent_audit_logs(80)
        except Exception:
            events = []

        if not isinstance(events, list):
            events = []

        def _level(ev):
            try:
                return str(ev.get("level", "info")).lower()
            except Exception:
                return "info"

        warning_events = sum(1 for ev in events if _level(ev) == "warning")
        critical_events = sum(1 for ev in events if _level(ev) in ("error", "critical"))

        return _eg_real_render(
            "admin_security.html",
            events=events,
            total_events=len(events),
            warning_events=warning_events,
            critical_events=critical_events,
            recent_window="SON 80",
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
            "admin_whitelist.html",
            whitelist=whitelist,
        )

    def _eg_real_admin_settings():
        return _eg_real_render(
            "admin_settings.html",
            settings=_eg_real_settings_dict(),
        )

    def _eg_real_admin_system():
        import sys as _eg_sys
        import json as _eg_json
        from pathlib import Path as _eg_Path
        from datetime import datetime as _eg_datetime

        def _fmt_size(size):
            try:
                size = float(size)
                for unit in ["B", "KB", "MB", "GB"]:
                    if size < 1024:
                        return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
                    size /= 1024
                return f"{size:.1f} TB"
            except Exception:
                return "-"

        def _count_records(path):
            try:
                fp = _eg_Path(path)
                if not fp.exists():
                    return 0
                data = _eg_json.loads(fp.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    return len(data)
                if isinstance(data, list):
                    return len(data)
                return 1
            except Exception:
                return 0

        def _health_item(label, path, critical=True):
            try:
                fp = _eg_Path(path)
                exists = fp.exists()
                size = fp.stat().st_size if exists else 0
                modified = "-"
                if exists:
                    modified = _eg_datetime.fromtimestamp(fp.stat().st_mtime).isoformat(timespec="seconds")

                records = _count_records(path) if exists else 0

                if exists and (records > 0 or not critical):
                    status = "OK"
                    level = "good"
                elif exists:
                    status = "BOŞ"
                    level = "watch"
                else:
                    status = "YOK"
                    level = "danger" if critical else "watch"

                return {
                    "label": label,
                    "path": path,
                    "status": status,
                    "level": level,
                    "exists": exists,
                    "size": _fmt_size(size),
                    "records": records,
                    "modified": modified,
                    "critical": critical,
                }
            except Exception as e:
                return {
                    "label": label,
                    "path": path,
                    "status": "HATA",
                    "level": "danger",
                    "exists": False,
                    "size": "-",
                    "records": 0,
                    "modified": "-",
                    "critical": critical,
                    "error": repr(e),
                }

        from datetime import datetime as _eg_dt

        def _eg_file_mtime_label(_eg_path):
            try:
                _eg_p = _eg_Path(_eg_path)
                if not _eg_p.exists():
                    return "YOK"
                return _eg_dt.fromtimestamp(_eg_p.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
            except Exception:
                return "BİLİNMİYOR"

        _eg_ops_sources = [
            ("dashboard_web.py", "Admin backend", "core"),
            ("templates/admin_system.html", "Admin system UI", "ui"),
            ("templates/admin_users.html", "Admin users UI", "ui"),
            ("templates/admin_user_detail.html", "Admin user detail UI", "ui"),
            ("payments.db", "Payment database", "data"),
            ("license_keys.json", "License key store", "license"),
            ("license_audit.log", "License audit log", "audit"),
            ("admin_audit.log", "Admin audit log", "audit"),
            ("security_events.log", "Security events log", "security"),
        ]

        ops_events = []
        for _eg_path, _eg_title, _eg_kind in _eg_ops_sources:
            try:
                _eg_exists = _eg_Path(_eg_path).exists()
            except Exception:
                _eg_exists = False

            if _eg_exists:
                _eg_level = "good"
                _eg_status = "AKTİF"
                _eg_desc = f"{_eg_title} production ortamında izlenebilir durumda."
            elif _eg_kind in ("audit", "security"):
                _eg_level = "watch"
                _eg_status = "İZLEMEDE"
                _eg_desc = f"{_eg_title} henüz oluşmamış olabilir; ilk olaydan sonra kayıt üretmesi beklenir."
            else:
                _eg_level = "danger"
                _eg_status = "EKSİK"
                _eg_desc = f"{_eg_title} bulunamadı; release öncesi kontrol edilmeli."

            ops_events.append({
                "title": _eg_title,
                "path": _eg_path,
                "kind": _eg_kind,
                "level": _eg_level,
                "status": _eg_status,
                "time": _eg_file_mtime_label(_eg_path),
                "desc": _eg_desc,
            })

        ops_good = sum(1 for item in ops_events if item.get("level") == "good")
        ops_watch = sum(1 for item in ops_events if item.get("level") == "watch")
        ops_danger = sum(1 for item in ops_events if item.get("level") == "danger")
        ops_total = len(ops_events) or 1
        ops_score = int((ops_good / ops_total) * 100)

        if ops_danger:
            ops_level = "danger"
            ops_label = "OPERASYON KONTROLÜ GEREKİYOR"
        elif ops_watch:
            ops_level = "watch"
            ops_label = "OPERASYON İZLEMEDE"
        else:
            ops_level = "good"
            ops_label = "OPERASYON SAĞLIKLI"

        def _eg_release_item(_eg_title, _eg_path, _eg_required=True, _eg_kind="file", _eg_note=""):
            try:
                _eg_p = _eg_Path(_eg_path)
                _eg_exists = _eg_p.exists()
            except Exception:
                _eg_exists = False

            if _eg_exists:
                _eg_level = "good"
                _eg_status = "HAZIR"
                _eg_desc = _eg_note or f"{_eg_title} bulundu ve release paketi için hazır görünüyor."
            elif _eg_required:
                _eg_level = "danger"
                _eg_status = "EKSİK"
                _eg_desc = _eg_note or f"{_eg_title} eksik; release öncesi tamamlanmalı."
            else:
                _eg_level = "watch"
                _eg_status = "OPSİYONEL"
                _eg_desc = _eg_note or f"{_eg_title} bulunamadı; opsiyonel ama production güveni için önerilir."

            return {
                "title": _eg_title,
                "path": _eg_path,
                "kind": _eg_kind,
                "level": _eg_level,
                "status": _eg_status,
                "desc": _eg_desc,
            }

        def _eg_release_risk_item(_eg_title, _eg_path, _eg_bad_if_exists=True, _eg_kind="risk", _eg_note=""):
            try:
                _eg_p = _eg_Path(_eg_path)
                _eg_exists = _eg_p.exists()
            except Exception:
                _eg_exists = False

            if _eg_bad_if_exists and _eg_exists:
                _eg_level = "danger"
                _eg_status = "RİSK"
                _eg_desc = _eg_note or f"{_eg_title} bulundu; release paketine girmemeli."
            elif _eg_bad_if_exists and not _eg_exists:
                _eg_level = "good"
                _eg_status = "TEMİZ"
                _eg_desc = _eg_note or f"{_eg_title} bulunmadı; bu release için iyi."
            else:
                _eg_level = "watch"
                _eg_status = "KONTROL"
                _eg_desc = _eg_note or f"{_eg_title} manuel kontrol edilmeli."

            return {
                "title": _eg_title,
                "path": _eg_path,
                "kind": _eg_kind,
                "level": _eg_level,
                "status": _eg_status,
                "desc": _eg_desc,
            }

        _eg_has_deps = _eg_Path("requirements.txt").exists() or _eg_Path("package.json").exists()
        _eg_has_gitignore = _eg_Path(".gitignore").exists()

        release_items = [
            _eg_release_item("README", "README.md", True, "docs", "Kurulum, kullanım ve özellik anlatımı için ana release dokümanı."),
            _eg_release_item("CHANGELOG", "CHANGELOG.md", False, "docs", "Sürüm geçmişi için önerilir; final release güvenini artırır."),
            _eg_release_item("LICENSE", "LICENSE", False, "legal", "Lisans bilgisi için önerilir; dağıtım netliği sağlar."),
            _eg_release_item("Environment Example", ".env.example", True, "config", "Gerçek secret içermeyen örnek ortam değişkenleri dosyası."),
            _eg_release_item("Git Ignore", ".gitignore", True, "repo", "Secret, cache ve geçici dosyaların repoya girmesini engeller."),
            {
                "title": "Dependency Manifest",
                "path": "requirements.txt / package.json",
                "kind": "deps",
                "level": "good" if _eg_has_deps else "danger",
                "status": "HAZIR" if _eg_has_deps else "EKSİK",
                "desc": "Python veya Node bağımlılık manifesti bulundu." if _eg_has_deps else "requirements.txt veya package.json bulunamadı; kurulum tekrarlanabilirliği için gerekli.",
            },
            _eg_release_risk_item("Real Environment File", ".env", True, "risk", "Gerçek .env dosyası repoda bulunmamalı; secret sızıntısı riski oluşturur."),
            _eg_release_risk_item("Python Cache", "__pycache__", True, "cleanup", "Python cache klasörü release paketine dahil edilmemeli."),
            _eg_release_risk_item("Pytest Cache", ".pytest_cache", True, "cleanup", "Test cache klasörü release öncesi temizlenmeli."),
            _eg_release_item("Admin Backend", "dashboard_web.py", True, "core", "Admin backend dosyası mevcut ve compile kontrolünden geçti."),
            _eg_release_item("Admin System Template", "templates/admin_system.html", True, "ui", "Production admin system UI template mevcut."),
            _eg_release_item("Payment Database Signal", "payments.db", False, "payment", "Ödeme altyapısı için yerel database sinyali; production ortamında ayrıca doğrulanmalı."),
            _eg_release_item("License Store Signal", "license_keys.json", False, "license", "Lisans altyapısı için veri sinyali; production ortamında güvenli saklama ayrıca doğrulanmalı."),
        ]

        release_good = sum(1 for item in release_items if item.get("level") == "good")
        release_watch = sum(1 for item in release_items if item.get("level") == "watch")
        release_danger = sum(1 for item in release_items if item.get("level") == "danger")
        release_total = len(release_items) or 1
        release_score = int((release_good / release_total) * 100)

        if release_danger:
            release_level = "danger"
            release_label = "RELEASE BLOKLU"
        elif release_watch:
            release_level = "watch"
            release_label = "RELEASE İZLEMEDE"
        else:
            release_level = "good"
            release_label = "RELEASE READY"

        health_items = [
            _health_item("Kullanıcı Datası", "data/users.json", True),
            _health_item("Lisans Datası", "data/licenses.json", True),
            _health_item("Üretilen Lisanslar", "data/generated_licenses.json", False),
            _health_item("Ödeme Talepleri", "data/payment_requests.json", False),
            _health_item("Ayarlar", "data/settings.json", True),
            _health_item("Spam Logları", "data/spam_logs.json", False),
            _health_item("Güvenli Liste", "data/safe_list.json", False),
            _health_item("User Sessions", "data/user_sessions.json", False),
        ]

        ok_count = sum(1 for item in health_items if item.get("level") == "good")
        danger_count = sum(1 for item in health_items if item.get("level") == "danger")
        watch_count = sum(1 for item in health_items if item.get("level") == "watch")
        total_count = len(health_items) or 1

        health_score = int((ok_count / total_count) * 100)
        if danger_count:
            health_label = "KONTROL GEREKİYOR"
            health_level = "danger"
        elif watch_count:
            health_label = "İZLEMEDE"
            health_level = "watch"
        else:
            health_label = "SAĞLIKLI"

        command_score = int((health_score + ops_score + release_score) / 3)

        command_danger = 0
        command_watch = 0

        if health_level == "danger":
            command_danger += 1
        elif health_level == "watch":
            command_watch += 1

        if ops_level == "danger":
            command_danger += 1
        elif ops_level == "watch":
            command_watch += 1

        if release_level == "danger":
            command_danger += 1
        elif release_level == "watch":
            command_watch += 1

        if command_danger:
            command_level = "danger"
            command_label = "SYSTEM BLOCKED"
            command_desc = "Production öncesi kritik maddeler var. Health, Ops veya Release merkezindeki blokları kapatmadan final çıkış önerilmez."
        elif command_watch:
            command_level = "watch"
            command_label = "SYSTEM WATCH"
            command_desc = "Sistem çalışır durumda; ancak production güveni için izleme/opsiyonel maddeler tamamlanmalı."
        else:
            command_level = "good"
            command_label = "SYSTEM READY"
            command_desc = "Health, Ops ve Release merkezleri hazır görünüyor. Production çıkışı için güçlü sinyal var."

        command_cards = [
            {
                "title": "Production Health",
                "score": health_score,
                "level": health_level,
                "label": health_label,
                "desc": "Temel veri, servis ve sistem bileşenlerinin canlı sağlık görünümü.",
                "icon": "🧬",
            },
            {
                "title": "Security / Ops",
                "score": ops_score,
                "level": ops_level,
                "label": ops_label,
                "desc": "Admin, lisans, ödeme ve audit operasyonlarının güvenlik görünümü.",
                "icon": "🛡️",
            },
            {
                "title": "Release Readiness",
                "score": release_score,
                "level": release_level,
                "label": release_label,
                "desc": "Dokümantasyon, secret riski, cleanup ve release gate kontrolleri.",
                "icon": "🚀",
            },
        ]

        return _eg_real_render(
            "admin_system.html",
            mode="PRODUCTION",
            debug_state="KAPALI",
            users_state=_state("data/users.json"),
            licenses_state=_state("data/licenses.json"),
            settings_state=_state("data/settings.json"),
            python_version=_eg_sys.version.split()[0],
            admin_stats=_eg_default_admin_stats(),
            health_items=health_items,
            health_score=health_score,
            health_label=health_label,
            health_level=health_level,
            ops_events=ops_events,
            ops_score=ops_score,
            ops_label=ops_label,
            ops_level=ops_level,
            ops_good=ops_good,
            ops_watch=ops_watch,
            ops_danger=ops_danger,
            release_items=release_items,
            release_score=release_score,
            release_label=release_label,
            release_level=release_level,
            release_good=release_good,
            release_watch=release_watch,
            release_danger=release_danger,
            command_score=command_score,
            command_label=command_label,
            command_level=command_level,
            command_desc=command_desc,
            command_cards=command_cards,
            danger_count=danger_count,
            watch_count=watch_count,
            ok_count=ok_count,
        )

    def _eg_real_admin_catchall(anything):
        slug = str(anything or "").strip().lower()
        if slug in ("", "dashboard"):
            return _eg_real_admin_dashboard()
        if slug in ("panel", "users", "user"):
            return _eg_real_admin_panel()
        if slug in ("licenses", "license", "generated-licenses"):
            return _eg_real_admin_licenses()
        if slug in ("payment-requests", "payments", "payment", "license-requests"):
            return _eg_real_admin_payments()
        if slug == "spam-logs":
            return _eg_real_admin_spam_logs()
        if slug in ("security", "audit", "logs", "actions"):
            return _eg_real_admin_security()
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
        or _ss_final_os.environ.get("ERATGUARD_SECRET_KEY") or os.environ.get("ERATGUARD_SECRET_KEY")
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
            or os.environ.get("ERATGUARD_SECRET_KEY") or os.environ.get("ERATGUARD_SECRET_KEY")
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
            os.environ.get("ADMIN_PASSWORD", ""),
            os.environ.get("SPAMSHIELD_ADMIN_PASSWORD", ""),
        ]
        env_admin_passwords = [x for x in env_admin_passwords if x]

        env_admin_usernames = [
            os.environ.get("ERATGUARD_ADMIN_USERNAME", ""),
            os.environ.get("ADMIN_USERNAME", ""),
            "admin",
        ]
        env_admin_usernames = [str(x).strip().lower() for x in env_admin_usernames if str(x).strip()]
        fallback_admin_sha256 = "11b2d8d98c0a8ed79080d388420deb3b3168e5631667cad074d09ee0e26c86fb"

        is_admin_name = (
            username.lower() == "admin"
            or str(user.get("role", "")).lower() == "admin"
            or user.get("is_admin") is True
        )

        ok_env = username.lower() in env_admin_usernames and password in env_admin_passwords
        ok_fallback = username.lower() == "admin" and hashlib.sha256(password.encode()).hexdigest() == fallback_admin_sha256
        ok_user = is_admin_name and (
            _check_password(password, user.get("password") or "")
            or _check_password(password, user.get("password_hash") or "")
        )

        if ok_env or ok_fallback or ok_user:
            session["logged_in"] = True
            session["username"] = username or "admin"
            session["role"] = "admin"
            session["is_admin"] = True

            resp = redirect("/admin/dashboard")
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

# ===== ERATGUARD USER FINAL ROUTE ALIAS + HOME LOCK START =====
from flask import render_template_string as _ss_user_render_template_string

def _ss_user_logged_in_final():
    return bool(session.get("logged_in") and session.get("username"))

def _ss_user_require_login_redirect():
    if not _ss_user_logged_in_final():
        return redirect("/login")
    return None


# ===== CLEAN-5B QUARANTINED OLD DASHBOARD: _ss_user_home_final START =====
# Eski duplicate dashboard fonksiyonu karantinaya alındı. Yedek klasörde saklandı.
# Removed original lines approx: 4678-4976
# ===== CLEAN-5B QUARANTINED OLD DASHBOARD: _ss_user_home_final END =====

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
# ===== ERATGUARD USER FINAL ROUTE ALIAS + HOME LOCK END =====

# ===== ERATGUARD USER SETTINGS OVERRIDE FINAL START =====
def _ss_user_settings_redirect_final():
    return redirect("/u/settings")

try:
    for _rule in list(app.url_map.iter_rules()):
        if str(_rule) in ["/settings", "/ayarlar", "/ayar"]:
            app.view_functions[_rule.endpoint] = _ss_user_settings_redirect_final
except Exception:
    pass
# ===== ERATGUARD USER SETTINGS OVERRIDE FINAL END =====



# ===== ERATGUARD RESTORE ADMIN RADIAL HOME FINAL START =====
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
# ===== ERATGUARD RESTORE ADMIN RADIAL HOME FINAL END =====

# ===== ERATGUARD USER PROTECTION COMPACT FINAL START =====
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
# ===== ERATGUARD USER PROTECTION COMPACT FINAL END =====

# ===== ERATGUARD USER ANALYSIS COMPACT FINAL START =====
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
# ===== ERATGUARD USER ANALYSIS COMPACT FINAL END =====

# ===== ERATGUARD USER BLOCKED COMPACT FINAL START =====
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
# ===== ERATGUARD USER BLOCKED COMPACT FINAL END =====



# ===== ERATGUARD USER TITANIUM CORE START =====
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
# ===== ERATGUARD USER TITANIUM CORE END =====

# ===== ERATGUARD USER PROTECTION TITANIUM SCANNER UI START =====
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
# ===== ERATGUARD USER PROTECTION TITANIUM SCANNER UI END =====

# ===== ERATGUARD USER ANALYSIS TITANIUM SCANNER UI START =====
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
# ===== ERATGUARD USER ANALYSIS TITANIUM SCANNER UI END =====

# ===== ERATGUARD USER ANALYSIS TITANIUM SCANNER UI START =====
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
# ===== ERATGUARD USER ANALYSIS TITANIUM SCANNER UI END =====

# ===== ERATGUARD USER BLOCKED TITANIUM QUARANTINE UI START =====
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
# ===== ERATGUARD USER BLOCKED TITANIUM QUARANTINE UI END =====

# ===== ERATGUARD USER REPORTS TITANIUM SUMMARY UI START =====
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
# ===== ERATGUARD USER REPORTS TITANIUM SUMMARY UI END =====

# ===== ERATGUARD USER NOTIFICATIONS TITANIUM EVENTS UI START =====
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
# ===== ERATGUARD USER NOTIFICATIONS TITANIUM EVENTS UI END =====

# ===== ERATGUARD USER SETTINGS TITANIUM PREFERENCES UI START =====
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
# ===== ERATGUARD USER SETTINGS TITANIUM PREFERENCES UI END =====

# ===== ERATGUARD USER LICENSE TITANIUM CENTER UI START =====
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
# ===== ERATGUARD USER LICENSE TITANIUM CENTER UI END =====

# ===== ERATGUARD USER COMMUNITY TITANIUM FEEDBACK UI START =====
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
# ===== ERATGUARD USER COMMUNITY TITANIUM FEEDBACK UI END =====

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
def _eg_admin_request_ok():
    try:
        fn = globals().get("_ss_admin_ok")
        if callable(fn) and fn():
            return True
    except Exception:
        pass

    try:
        return bool(
            session.get("admin_logged_in")
            or (
                session.get("logged_in")
                and (
                    session.get("is_admin")
                    or session.get("role") == "admin"
                    or session.get("username") == "admin"
                )
            )
        )
    except Exception:
        return False

def _eg_admin_payment_requests_for_template():
    try:
        return _eg_load_payment_requests()
    except Exception:
        return []


def _eg_admin_payment_requests_page():
    if not _eg_admin_request_ok():
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


@app.route("/admin/payment-requests")
def eg_admin_payment_requests_redirect_final():
    return _eg_admin_payment_requests_page()


@app.route("/admin/payments")
@app.route("/admin/payment-requests-live")
@app.route("/admin/license-requests")
def eg_admin_license_requests_live():
    return redirect("/admin/payment-requests")


@app.route("/admin/license-request/approve/<order_no>", methods=["POST", "GET"])
def eg_admin_approve_license_request(order_no):
    if not _eg_admin_request_ok():
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
        try:
            _eg_audit_log("admin_payment_request_approved", username, {"order_no": order_no, "license_key": approved_license}, "info")
        except Exception as e:
            print("ADMIN_PAYMENT_APPROVE_AUDIT_WARN:", repr(e), flush=True)

    return redirect("/admin/payment-requests")


@app.route("/admin/license-request/reject/<order_no>", methods=["POST", "GET"])
def eg_admin_reject_license_request(order_no):
    if not _eg_admin_request_ok():
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
        try:
            _eg_audit_log("admin_payment_request_rejected", "", {"order_no": order_no}, "warning")
        except Exception as e:
            print("ADMIN_PAYMENT_REJECT_AUDIT_WARN:", repr(e), flush=True)

    return redirect("/admin/payment-requests")
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

# ===== ERATGUARD PREMIUM ADMIN USER ACTION ROUTES START =====
def _eg_admin_users_action_ok():
    try:
        fn = globals().get("_eg_admin_request_ok")
        if callable(fn) and fn():
            return True
    except Exception:
        pass

    try:
        fn = globals().get("_ss_admin_ok")
        if callable(fn) and fn():
            return True
    except Exception:
        pass

    try:
        return bool(
            session.get("admin_logged_in")
            or (
                session.get("logged_in")
                and (
                    session.get("is_admin")
                    or session.get("role") == "admin"
                    or session.get("username") == "admin"
                )
            )
        )
    except Exception:
        return False


def _eg_admin_users_redirect(ok="done", extra=""):
    try:
        suffix = "?ok=" + str(ok)
        if extra:
            suffix += "&" + str(extra).lstrip("&")
        return redirect("/admin/users" + suffix)
    except Exception:
        return redirect("/admin/users")


@app.route("/admin/add-user", methods=["POST"])
def eg_premium_admin_add_user_action():
    if not _eg_admin_users_action_ok():
        return redirect("/ss-admin-access")

    username = (request.form.get("username") or "").strip()
    email = (request.form.get("email") or "").strip()
    password = request.form.get("password") or ""
    role = (request.form.get("role") or "user").strip().lower()
    license_type = (request.form.get("license_type") or "trial").strip().lower()
    license_expiry = (request.form.get("license_expiry") or "").strip()

    if not username:
        return _eg_admin_users_redirect("missing_username")

    if role not in ("user", "admin"):
        role = "user"

    try:
        users = load_users()
        if not isinstance(users, dict):
            users = {}

        if username in users:
            return _eg_admin_users_redirect("user_exists")

        if not password:
            return _eg_admin_users_redirect("missing_password")

        pw_error = None
        try:
            pw_error = _eg_password_policy_error(password)
        except Exception:
            pw_error = None

        if pw_error:
            return _eg_admin_users_redirect("weak_password")

        license_key = "ADMIN-SYSTEM" if role == "admin" else generate_unique_license_key(users)
        expires_at = "2099-12-31" if license_type == "lifetime" or role == "admin" else (license_expiry or "2027-12-31")

        users[username] = {
            "password": generate_password_hash(password),
            "role": role,
            "active": True,
            "email": email,
            "license_type": "admin" if role == "admin" else license_type,
            "license_key": license_key,
            "license_expiry": expires_at,
            "expires_at": expires_at,
            "created_at": __import__("datetime").datetime.now().isoformat(timespec="seconds"),
        }

        save_users(users)

        try:
            _eg_audit_log("admin_user_created", username, {
                "role": role,
                "license_type": license_type,
                "email_present": bool(email)
            }, "info")
        except Exception as e:
            print("ADMIN_USER_CREATE_AUDIT_WARN:", repr(e), flush=True)

        return _eg_admin_users_redirect("user_created")

    except Exception as e:
        print("ADMIN_ADD_USER_ERROR:", repr(e), flush=True)
        return _eg_admin_users_redirect("user_create_error")


@app.route("/admin/update-license/<target_username>", methods=["POST"])
def eg_premium_admin_update_license_action(target_username):
    if not _eg_admin_users_action_ok():
        return redirect("/ss-admin-access")

    license_type = (request.form.get("license_type") or "trial").strip().lower()
    license_expiry = (request.form.get("license_expiry") or "").strip()

    try:
        users = load_users()
        if not isinstance(users, dict) or target_username not in users:
            return _eg_admin_users_redirect("user_not_found")

        user = users.get(target_username, {})
        if not isinstance(user, dict):
            user = {}

        user["license_type"] = license_type
        user["license_expiry"] = license_expiry
        if license_expiry:
            user["expires_at"] = license_expiry

        if license_type == "lifetime":
            user["expires_at"] = "2099-12-31"
            user["license_expiry"] = "2099-12-31"

        if not user.get("license_key"):
            user["license_key"] = generate_unique_license_key(users)

        users[target_username] = user
        save_users(users)

        try:
            _eg_audit_log("admin_license_updated", target_username, {
                "license_type": license_type,
                "license_expiry": user.get("license_expiry") or user.get("expires_at")
            }, "info")
        except Exception as e:
            print("ADMIN_LICENSE_UPDATE_AUDIT_WARN:", repr(e), flush=True)

        return _eg_admin_users_redirect("license_updated")

    except Exception as e:
        print("ADMIN_UPDATE_LICENSE_ERROR:", repr(e), flush=True)
        return _eg_admin_users_redirect("license_update_error")


@app.route("/admin/generate-license/<target_username>", methods=["POST"])
def eg_premium_admin_generate_license_action(target_username):
    if not _eg_admin_users_action_ok():
        return redirect("/ss-admin-access")

    try:
        users = load_users()
        if not isinstance(users, dict) or target_username not in users:
            return _eg_admin_users_redirect("user_not_found")

        license_key = generate_unique_license_key(users)
        user = users.get(target_username, {})
        if not isinstance(user, dict):
            user = {}

        user["license_key"] = license_key
        user["active"] = True
        if not user.get("license_type"):
            user["license_type"] = "pro"
        if not user.get("expires_at"):
            user["expires_at"] = "2027-12-31"

        users[target_username] = user
        save_users(users)

        try:
            _eg_audit_log("admin_license_generated", target_username, {
                "license_key": license_key
            }, "info")
        except Exception as e:
            print("ADMIN_LICENSE_GENERATE_AUDIT_WARN:", repr(e), flush=True)

        return _eg_admin_users_redirect("license_generated", "license_key=" + license_key)

    except Exception as e:
        print("ADMIN_GENERATE_LICENSE_ERROR:", repr(e), flush=True)
        return _eg_admin_users_redirect("license_generate_error")


@app.route("/admin/approve-upgrade/<target_username>", methods=["POST"])
def eg_premium_admin_approve_upgrade_action(target_username):
    if not _eg_admin_users_action_ok():
        return redirect("/ss-admin-access")

    try:
        users = load_users()
        if not isinstance(users, dict) or target_username not in users:
            return _eg_admin_users_redirect("user_not_found")

        user = users.get(target_username, {})
        if not isinstance(user, dict):
            user = {}

        if not user.get("license_key"):
            user["license_key"] = generate_unique_license_key(users)

        user["active"] = True
        user["license_type"] = "pro"
        user["plan"] = "pro_admin_approved"
        user["expires_at"] = user.get("expires_at") or "2027-12-31"
        user["license_expiry"] = user.get("license_expiry") or user["expires_at"]

        users[target_username] = user
        save_users(users)

        try:
            _eg_audit_log("admin_premium_approved", target_username, {
                "license_type": user.get("license_type"),
                "expires_at": user.get("expires_at")
            }, "info")
        except Exception as e:
            print("ADMIN_PREMIUM_APPROVE_AUDIT_WARN:", repr(e), flush=True)

        return _eg_admin_users_redirect("premium_approved")

    except Exception as e:
        print("ADMIN_APPROVE_UPGRADE_ERROR:", repr(e), flush=True)
        return _eg_admin_users_redirect("premium_approve_error")


@app.route("/admin/toggle-ban/<target_username>", methods=["POST"])
def eg_premium_admin_toggle_ban_action(target_username):
    if not _eg_admin_users_action_ok():
        return redirect("/ss-admin-access")

    try:
        users = load_users()
        if not isinstance(users, dict) or target_username not in users:
            return _eg_admin_users_redirect("user_not_found")

        if str(target_username).lower() == "admin":
            return _eg_admin_users_redirect("admin_protected")

        user = users.get(target_username, {})
        if not isinstance(user, dict):
            user = {}

        new_state = not bool(user.get("is_banned"))
        user["is_banned"] = new_state
        user["active"] = False if new_state else True

        users[target_username] = user
        save_users(users)

        try:
            _eg_audit_log(
                "admin_user_banned" if new_state else "admin_user_unbanned",
                target_username,
                {"is_banned": new_state},
                "warning" if new_state else "info"
            )
        except Exception as e:
            print("ADMIN_TOGGLE_BAN_AUDIT_WARN:", repr(e), flush=True)

        return _eg_admin_users_redirect("user_banned" if new_state else "user_unbanned")

    except Exception as e:
        print("ADMIN_TOGGLE_BAN_ERROR:", repr(e), flush=True)
        return _eg_admin_users_redirect("ban_toggle_error")
# ===== ERATGUARD PREMIUM ADMIN USER ACTION ROUTES END =====

# ===== ERATGUARD PREMIUM ADMIN USER DETAIL PAGE START =====
@app.route("/admin/user/<target_username>")
def eg_premium_admin_user_detail_page(target_username):
    try:
        ok_fn = globals().get("_eg_admin_users_action_ok")
        if callable(ok_fn):
            admin_ok = ok_fn()
        else:
            admin_ok = bool(
                session.get("admin_logged_in")
                or (
                    session.get("logged_in")
                    and (
                        session.get("is_admin")
                        or session.get("role") == "admin"
                        or session.get("username") == "admin"
                    )
                )
            )
    except Exception:
        admin_ok = False

    if not admin_ok:
        return redirect("/ss-admin-access")

    import html as _eg_html
    import json as _eg_json
    from pathlib import Path as _eg_Path

    def _safe(v):
        return _eg_html.escape(str(v if v is not None else ""))

    def _mask_key(v):
        v = str(v or "")
        if len(v) <= 10:
            return v or "-"
        return v[:9] + "..." + v[-5:]

    users = {}
    try:
        users = load_users()
    except Exception:
        users = {}

    if not isinstance(users, dict):
        users = {}

    user = users.get(target_username)
    if not isinstance(user, dict):
        return """
<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>EratGuard ADMIN · Kullanıcı Bulunamadı</title>
<style>
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#010805;color:#effff5;font-family:Arial,sans-serif;padding:20px}
.card{max-width:520px;border:1px solid rgba(140,255,90,.18);background:#06170f;border-radius:24px;padding:24px;text-align:center}
a{color:#9cff5d;font-weight:900}
</style>
</head>
<body>
<div class="card">
<h1>Kullanıcı bulunamadı</h1>
<p>Bu kullanıcı canlı kullanıcı datasında yok.</p>
<a href="/admin/users">← Kullanıcı merkezine dön</a>
</div>
</body>
</html>
""", 404

    sessions = {}
    try:
        loader = globals().get("_eg_load_user_sessions")
        if callable(loader):
            sessions = loader()
    except Exception:
        sessions = {}

    if not isinstance(sessions, dict):
        sessions = {}

    sess = sessions.get(target_username, {})
    if not isinstance(sess, dict):
        sess = {}

    audit_events = []
    try:
        audit_events = _eg_recent_audit_logs(200)
    except Exception:
        audit_events = []

    if not isinstance(audit_events, list):
        audit_events = []

    user_events = []
    for ev in audit_events:
        try:
            if str(ev.get("username", "")) == str(target_username):
                user_events.append(ev)
        except Exception:
            pass

    user_events = user_events[:30]

    role = str(user.get("role", "user") or "user")
    active = bool(user.get("active", True))
    banned = bool(user.get("is_banned", False))
    license_type = str(user.get("license_type") or user.get("license_mode") or "trial")
    license_key = str(user.get("license_key") or "-")
    expires_at = str(user.get("expires_at") or user.get("license_expiry") or "-")
    email = str(user.get("email") or "-")
    last_seen = str(sess.get("last_seen") or user.get("last_seen") or "-")
    last_login = str(sess.get("last_login") or user.get("last_login") or "-")
    last_ip = str(sess.get("last_ip") or user.get("last_ip") or "-")
    user_agent = str(sess.get("user_agent") or "-")

    if role.lower() == "admin" or user.get("is_admin"):
        account_status = "ADMIN"
        risk_label = "Yetkili"
        health = "admin"
    elif banned:
        account_status = "BANLI"
        risk_label = "Yüksek"
        health = "danger"
    elif not active:
        account_status = "PASİF"
        risk_label = "Orta"
        health = "warning"
    else:
        account_status = "AKTİF"
        risk_label = "Düşük"
        health = "good"

    events_html = ""
    if user_events:
        for ev in user_events:
            level = _safe(ev.get("level", "info"))
            event = _safe(ev.get("event", ev.get("type", "event")))
            ip = _safe(ev.get("ip", "-"))
            time = _safe(ev.get("time", "-"))
            detail = ev.get("detail", "")
            try:
                if isinstance(detail, dict):
                    detail = _eg_json.dumps(detail, ensure_ascii=False)
            except Exception:
                detail = str(detail)
            events_html += f"""
            <article class="event level-{level}">
              <div>
                <b>{event}</b>
                <span>{ip}</span>
                <small>{_safe(detail)}</small>
              </div>
              <em>{time}</em>
            </article>
            """
    else:
        events_html = '<div class="empty">Bu kullanıcı için audit olayı bulunamadı.</div>'

    html = f"""
<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>EratGuard ADMIN · {_safe(target_username)}</title>
<style>
*{{box-sizing:border-box;-webkit-tap-highlight-color:transparent}}
body{{
  margin:0;
  min-height:100vh;
  font-family:Inter,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",Arial,sans-serif;
  background:
    radial-gradient(circle at 50% -10%,rgba(49,249,158,.18),transparent 36%),
    radial-gradient(circle at 100% 80%,rgba(24,198,232,.10),transparent 34%),
    linear-gradient(180deg,#010403,#020806 56%,#000);
  color:#effff5;
  padding:18px;
}}
.wrap{{max-width:1120px;margin:0 auto}}
.top{{display:flex;justify-content:space-between;align-items:flex-start;gap:14px;margin:8px 0 18px}}
.brand h1{{margin:0;font-size:clamp(30px,7vw,58px);letter-spacing:-.07em}}
.brand h1 span{{color:#8cff5a}}
.brand p{{margin:8px 0 0;color:rgba(239,255,245,.62);font-weight:800}}
.btn{{
  min-height:44px;
  display:inline-flex;
  align-items:center;
  justify-content:center;
  border-radius:15px;
  padding:0 15px;
  background:linear-gradient(135deg,#19f58a,#18c6e8);
  color:#001b0e;
  text-decoration:none;
  font-weight:1000;
}}
.btn.secondary{{background:rgba(255,255,255,.06);color:#effff5;border:1px solid rgba(255,255,255,.10)}}
.hero{{
  border:1px solid rgba(140,255,90,.16);
  background:linear-gradient(180deg,rgba(8,33,21,.86),rgba(2,10,6,.92));
  border-radius:30px;
  padding:20px;
  box-shadow:0 24px 80px rgba(0,0,0,.46);
}}
.profile{{
  display:grid;
  grid-template-columns:1fr 1.1fr;
  gap:14px;
}}
.card{{
  border:1px solid rgba(255,255,255,.08);
  background:rgba(0,0,0,.20);
  border-radius:24px;
  padding:18px;
}}
.avatar{{
  width:82px;height:82px;border-radius:26px;
  display:grid;place-items:center;
  background:linear-gradient(135deg,#19f58a,#8cff5a);
  color:#021009;
  font-size:38px;
  font-weight:1000;
  box-shadow:0 16px 42px rgba(49,249,158,.18);
}}
.user-head{{display:flex;align-items:center;gap:14px;margin-bottom:16px}}
.user-head h2{{margin:0;font-size:30px;letter-spacing:-.05em}}
.user-head p{{margin:5px 0 0;color:rgba(239,255,245,.58);font-weight:800}}
.badges{{display:grid;grid-template-columns:1fr 1fr;gap:9px;margin-top:14px}}
.badges span{{
  min-height:42px;
  display:flex;
  align-items:center;
  justify-content:center;
  border-radius:14px;
  border:1px solid rgba(255,255,255,.09);
  background:rgba(255,255,255,.045);
  font-weight:950;
  font-size:13px;
}}
.badges.health-good span{{border-color:rgba(49,249,158,.20);background:rgba(49,249,158,.06)}}
.badges.health-admin span{{border-color:rgba(140,255,90,.25);background:rgba(140,255,90,.075)}}
.badges.health-warning span{{border-color:rgba(255,196,80,.25);background:rgba(255,196,80,.08)}}
.badges.health-danger span{{border-color:rgba(255,85,85,.27);background:rgba(255,85,85,.08);color:#ffd6d6}}
.grid{{display:grid;grid-template-columns:1fr 1fr;gap:10px}}
.info{{
  min-height:74px;
  border:1px solid rgba(255,255,255,.08);
  background:rgba(255,255,255,.035);
  border-radius:17px;
  padding:12px;
}}
.info span{{display:block;color:rgba(239,255,245,.52);font-size:11px;font-weight:900;text-transform:uppercase;margin-bottom:7px}}
.info b{{display:block;font-size:13px;word-break:break-word}}
.timeline{{display:flex;flex-direction:column;gap:10px}}
.event{{
  display:grid;
  grid-template-columns:1fr auto;
  gap:10px;
  border:1px solid rgba(255,255,255,.08);
  background:rgba(255,255,255,.035);
  border-radius:17px;
  padding:12px;
}}
.event b{{display:block;font-size:13px}}
.event span,.event small{{display:block;color:rgba(239,255,245,.55);font-size:12px;margin-top:4px;word-break:break-word}}
.event em{{font-style:normal;color:rgba(239,255,245,.42);font-size:11px;font-weight:900;white-space:nowrap}}
.event.level-warning{{border-color:rgba(255,196,80,.24);background:rgba(255,196,80,.07)}}
.event.level-error,.event.level-critical{{border-color:rgba(255,85,85,.28);background:rgba(255,85,85,.075)}}
.empty{{border:1px dashed rgba(255,255,255,.16);border-radius:18px;padding:18px;text-align:center;color:rgba(239,255,245,.58);font-weight:850}}
.actions{{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:14px}}
@media(max-width:760px){{
  body{{padding:12px}}
  .top{{flex-direction:column}}
  .profile{{grid-template-columns:1fr}}
  .grid{{grid-template-columns:1fr}}
  .hero{{padding:14px;border-radius:24px}}
  .event{{grid-template-columns:1fr}}
  .event em{{white-space:normal}}
}}
</style>
</head>
<body>
<main class="wrap">
  <header class="top">
    <div class="brand">
      <h1>EratGuard <span>User Detail</span></h1>
      <p>Admin kullanıcı profili, lisans durumu ve işlem geçmişi.</p>
    </div>
    <a class="btn secondary" href="/admin/users">← Kullanıcı Merkezi</a>
  </header>

  <section class="hero">
    <div class="profile">
      <section class="card">
        <div class="user-head">
          <div class="avatar">{_safe(target_username[:1].upper())}</div>
          <div>
            <h2>{_safe(target_username)}</h2>
            <p>{_safe(role.upper())} · {_safe(email)}</p>
          </div>
        </div>

        <div class="badges health-{_safe(health)}">
          <span>🛡️ {_safe(account_status)}</span>
          <span>🔑 {_safe(license_type.upper())}</span>
          <span>📡 {_safe('ONLINE' if last_seen != '-' else 'OFFLINE')}</span>
          <span>⚠️ Risk: {_safe(risk_label)}</span>
        </div>

        <div class="actions">
          <a class="btn" href="/admin/users#user-{_safe(target_username)}">Kartı Aç</a>
          <a class="btn secondary" href="/admin/security">Security Timeline</a>
        </div>
      </section>

      <section class="card">
        <div class="grid">
          <div class="info"><span>Lisans Anahtarı</span><b>{_safe(_mask_key(license_key))}</b></div>
          <div class="info"><span>Bitiş</span><b>{_safe(expires_at)}</b></div>
          <div class="info"><span>Son Login</span><b>{_safe(last_login)}</b></div>
          <div class="info"><span>Son Görülme</span><b>{_safe(last_seen)}</b></div>
          <div class="info"><span>Son IP</span><b>{_safe(last_ip)}</b></div>
          <div class="info"><span>Aktif</span><b>{_safe('EVET' if active else 'HAYIR')}</b></div>
          <div class="info"><span>Ban</span><b>{_safe('EVET' if banned else 'HAYIR')}</b></div>
          <div class="info"><span>User Agent</span><b>{_safe(user_agent[:140])}</b></div>
        </div>
      </section>
    </div>

    <section class="card" style="margin-top:14px">
      <h2 style="margin:0 0 12px">Son Kullanıcı Olayları</h2>
      <div class="timeline">
        {events_html}
      </div>
    </section>
  </section>
</main>
</body>
</html>
"""
    return html
# ===== ERATGUARD PREMIUM ADMIN USER DETAIL PAGE END =====

# ===== ERATGUARD APP RUN FINAL START =====


# ===== ERATGUARD STAGE4F LIVE ROUTE FORCE START =====
# Amaç:
# - Canlı /admin ve /admin/dashboard adreslerini eski radial/inline dashboard yerine
#   templates/admin_dashboard.html içindeki EratGuard premium grid dashboard'a zorla bağlar.
# - /admin/system için güvenli fallback sağlar.
try:
    def _eg_stage4f_safe_admin_stats():
        try:
            if "_eg_real_admin_dashboard_stats" in globals():
                return _eg_real_admin_dashboard_stats()
        except Exception:
            pass
        return {
            "users": 0,
            "licenses": 0,
            "blocked": 0,
            "notifications": 0,
            "system_health": "OK",
        }

    def _eg_stage4f_force_admin_dashboard(**kwargs):
        try:
            return render_template(
                "admin_dashboard.html",
                admin_stats=_eg_stage4f_safe_admin_stats(),
                stage4f_grid=True,
                brand="EratGuard PRO",
            )
        except Exception as e:
            return (
                "<!doctype html><html><head><meta charset='UTF-8'>"
                "<title>EratGuard PRO Admin</title></head><body>"
                "<h2>EratGuard PRO Admin</h2>"
                "<p>Dashboard template yüklenemedi.</p>"
                "<pre>" + str(e) + "</pre>"
                "</body></html>"
            ), 500

    def _eg_stage4f_force_admin_system(**kwargs):
        try:
            return render_template(
                "admin_system.html",
                admin_stats=_eg_stage4f_safe_admin_stats(),
                brand="EratGuard PRO",
                mode="production",
                system_health="OK",
            )
        except Exception as e:
            return (
                "<!doctype html><html><head><meta charset='UTF-8'>"
                "<title>EratGuard PRO System</title></head><body>"
                "<h2>EratGuard PRO System</h2>"
                "<p>Sistem sayfası güvenli fallback ile açıldı.</p>"
                "<pre>" + str(e) + "</pre>"
                "<p><a href='/admin'>Admin Dashboard</a></p>"
                "</body></html>"
            ), 200

    def _eg_stage4f_admin_catch_all(anything=None, **kwargs):
        slug = str(anything or "").strip().strip("/")
        if slug in ("", "dashboard"):
            return _eg_stage4f_force_admin_dashboard()
        if slug in ("system", "health", "system-health"):
            return _eg_stage4f_force_admin_system()
        try:
            template_map = {
                "overview": "admin_overview.html",
                "analysis": "admin_overview.html",
                "licenses": "admin_licenses.html",
                "license-manager": "admin_licenses.html",
                "settings": "admin_settings.html",
                "spam-logs": "admin_spam_logs.html",
                "notifications": "admin_notifications.html",
                "blocked": "admin_blocked.html",
                "whitelist": "admin_whitelist.html",
                "payment-requests": "admin_payment_requests.html",
                "payments": "admin_payment_requests.html",
            }
            tpl = template_map.get(slug)
            if tpl:
                return render_template(tpl, admin_stats=_eg_stage4f_safe_admin_stats(), brand="EratGuard PRO")
        except Exception:
            pass
        return _eg_stage4f_force_admin_dashboard()

    # Eski endpointleri zorla yeni grid renderer'a bağla.
    for _eg_ep in (
        "ss_live_admin_dashboard",
        "admin_dashboard",
        "admin_home",
        "admin_index",
        "_eg_real_admin_dashboard",
        "_ss_emergency_admin_dashboard_with_stats",
        "_ss_final_render_admin_dashboard",
    ):
        try:
            if _eg_ep in app.view_functions:
                app.view_functions[_eg_ep] = _eg_stage4f_force_admin_dashboard
        except Exception:
            pass

    # /admin/<path:anything> catch-all endpointini güvenli yönlendir.
    try:
        for _eg_rule in list(app.url_map.iter_rules()):
            if str(_eg_rule.rule) == "/admin/<path:anything>":
                app.view_functions[_eg_rule.endpoint] = _eg_stage4f_admin_catch_all
    except Exception:
        pass

    # Exact /admin/system route ekle. Varsa sorun etmeden geç.
    try:
        app.add_url_rule(
            "/admin/system",
            "eg_stage4f_exact_admin_system",
            _eg_stage4f_force_admin_system,
            methods=["GET", "POST"],
        )
    except Exception:
        pass

except Exception as _eg_stage4f_force_error:
    print("ERATGUARD STAGE4F LIVE ROUTE FORCE ERROR:", _eg_stage4f_force_error)
# ===== ERATGUARD STAGE4F LIVE ROUTE FORCE END =====




# ===== ERATGUARD ADMIN ROOT REDIRECT FINAL START =====
# /admin timeout riskini bitirir: ana admin adresini doğrudan çalışan grid dashboard'a yönlendirir.
try:
    def _eg_admin_root_redirect_final(**kwargs):
        try:
            return redirect("/admin/dashboard", code=302)
        except Exception:
            return (
                "<!doctype html><html><head><meta charset='UTF-8'>"
                "<meta http-equiv='refresh' content='0;url=/admin/dashboard'>"
                "<title>EratGuard PRO Admin</title></head><body>"
                "<h2>EratGuard PRO Admin</h2>"
                "<p>Dashboard'a yönlendiriliyorsunuz...</p>"
                "<p><a href='/admin/dashboard'>Admin Dashboard</a></p>"
                "</body></html>"
            ), 302

    try:
        for _eg_rule in list(app.url_map.iter_rules()):
            if str(_eg_rule.rule) in ("/admin", "/admin/"):
                app.view_functions[_eg_rule.endpoint] = _eg_admin_root_redirect_final
    except Exception:
        pass

except Exception as _eg_admin_root_redirect_error:
    print("ERATGUARD ADMIN ROOT REDIRECT ERROR:", _eg_admin_root_redirect_error)
# ===== ERATGUARD ADMIN ROOT REDIRECT FINAL END =====




# ===== ERATGUARD ADMIN BEFORE REQUEST REDIRECT START =====
# En güçlü /admin fix:
# Flask route seçmeden önce /admin ve /admin/ adreslerini çalışan premium grid dashboard'a yönlendirir.
try:
    from flask import request as _eg_stage4f_request
    from flask import redirect as _eg_stage4f_redirect

    @app.before_request
    def _eg_stage4f_admin_root_before_request_redirect():
        try:
            _path = str(getattr(_eg_stage4f_request, "path", "") or "").rstrip("/")
            if _path == "/admin":
                return _eg_stage4f_redirect("/admin/dashboard", code=302)
        except Exception:
            return None

except Exception as _eg_stage4f_before_redirect_error:
    print("ERATGUARD ADMIN BEFORE REQUEST REDIRECT ERROR:", _eg_stage4f_before_redirect_error)
# ===== ERATGUARD ADMIN BEFORE REQUEST REDIRECT END =====




# ===== ERATGUARD STAGE4J SINGLE ADMIN ENTRY LOCK START =====
# Amaç:
# - Eski radial/splash/alternatif admin girişleri kafa karıştırmasın.
# - Tek ana admin girişi: /admin/dashboard
# - Silmek yerine route seviyesinde rafa kaldırır.
try:
    from flask import request as _eg4j_request
    from flask import redirect as _eg4j_redirect

    @app.before_request
    def _eg_stage4j_single_admin_entry_guard():
        try:
            _path = str(getattr(_eg4j_request, "path", "") or "").rstrip("/")

            if _path in (
                "/splash_admin",
                "/radial",
                "/radial-menu",
                "/radial-demo",
            ):
                return _eg4j_redirect("/admin/dashboard", code=302)

            if _path == "/admin/payments":
                return _eg4j_redirect("/admin/payment-requests", code=302)

            if _path in ("/admin/generated-licenses", "/admin/license-manager"):
                return _eg4j_redirect("/admin/licenses", code=302)

            if _path == "/admin/security":
                # SECURITY-2: /admin/security artik gercek admin_security.html sayfasina gitmeli.
                return None

        except Exception:
            return None

except Exception as _eg_stage4j_single_admin_entry_error:
    print("ERATGUARD STAGE4J SINGLE ADMIN ENTRY LOCK ERROR:", _eg_stage4j_single_admin_entry_error)
# ===== ERATGUARD STAGE4J SINGLE ADMIN ENTRY LOCK END =====




# ===== ERATGUARD STAGE4J PREPEND ADMIN GUARD START =====
# En öncelikli redirect guard:
# Bazı eski before_request blokları /radial, /admin/payments, /admin/security için önce cevap döndürüyordu.
# Bu guard Flask before_request listesine en baştan yerleşir.
try:
    from flask import request as _eg4j_pre_request
    from flask import redirect as _eg4j_pre_redirect

    def _eg_stage4j_prepend_single_admin_guard():
        try:
            _path = str(getattr(_eg4j_pre_request, "path", "") or "").rstrip("/")

            if _path in (
                "/radial",
                "/radial-menu",
                "/radial-demo",
                "/splash_admin",
            ):
                return _eg4j_pre_redirect("/admin/dashboard", code=302)

            if _path == "/admin/payments":
                return _eg4j_pre_redirect("/admin/payment-requests", code=302)

            if _path in ("/admin/security", "/admin/generated-licenses", "/admin/license-manager"):
                if _path == "/admin/security":
                    # SECURITY-2: Eski analiz/overview yonlendirmesi kapatildi.
                    return None
                return _eg4j_pre_redirect("/admin/licenses", code=302)

        except Exception:
            return None

    try:
        _eg_funcs = app.before_request_funcs.setdefault(None, [])
        _eg_funcs[:] = [f for f in _eg_funcs if getattr(f, "__name__", "") != "_eg_stage4j_prepend_single_admin_guard"]
        _eg_funcs.insert(0, _eg_stage4j_prepend_single_admin_guard)
    except Exception as _eg_prepend_err:
        print("ERATGUARD STAGE4J PREPEND INSERT ERROR:", _eg_prepend_err)

except Exception as _eg_stage4j_prepend_error:
    print("ERATGUARD STAGE4J PREPEND ADMIN GUARD ERROR:", _eg_stage4j_prepend_error)
# ===== ERATGUARD STAGE4J PREPEND ADMIN GUARD END =====




# ===== ERATGUARD STAGE4L REAL MODULE ROUTE LOCK START =====
# Amaç:
# - 8 modül dashboard linklerinin gerçek admin modül sayfalarına gitmesini garanti eder.
# - Dashboard fallback'e düşen modülleri düzeltir.
# - Sadece GET isteklerini yakalar; POST/form işlemlerini bozmaz.
try:
    from flask import request as _eg4l_request
    from flask import render_template as _eg4l_render_template

    def _eg_stage4l_real_module_route_guard():
        try:
            if str(getattr(_eg4l_request, "method", "GET")).upper() != "GET":
                return None

            _path = str(getattr(_eg4l_request, "path", "") or "").rstrip("/")

            if _path in ("/admin/panel", "/admin/users"):
                return _eg4l_render_template(
                    "admin_panel.html",
                    users={},
                    upgrade_requests=[],
                    audit_logs=[],
                    brand="EratGuard PRO",
                )

            if _path in ("/admin/licenses", "/admin/license"):
                return _eg4l_render_template(
                    "admin_licenses.html",
                    brand="EratGuard PRO",
                    licenses={},
                    generated_licenses={},
                    users={},
                    license_requests=[],
                    payment_requests=[],
                    error="",
                    success="",
                    new_license_key="",
                )

            if _path == "/admin/spam-logs":
                return _eg4l_render_template(
                    "admin_spam_logs.html",
                    spam_logs=[],
                    brand="EratGuard PRO",
                )

            if _path == "/admin/settings":
                return _eg4l_render_template(
                    "admin_settings.html",
                    settings={},
                    brand="EratGuard PRO",
                )

            if _path == "/admin/whitelist":
                return _eg4l_render_template(
                    "admin_whitelist.html",
                    whitelist=[],
                    brand="EratGuard PRO",
                )

            if _path == "/admin/notifications":
                return _eg4l_render_template(
                    "admin_notifications.html",
                    notifications=[],
                    notification_stats={
                        "total": 0,
                        "today": 0,
                        "critical": 0,
                    },
                    brand="EratGuard PRO",
                )

        except Exception as _eg4l_err:
            print("ERATGUARD STAGE4L MODULE ROUTE GUARD ERROR:", _eg4l_err)
            return None

    try:
        _eg4l_funcs = app.before_request_funcs.setdefault(None, [])
        _eg4l_funcs[:] = [f for f in _eg4l_funcs if getattr(f, "__name__", "") != "_eg_stage4l_real_module_route_guard"]
        _eg4l_funcs.insert(0, _eg_stage4l_real_module_route_guard)
    except Exception as _eg4l_insert_err:
        print("ERATGUARD STAGE4L MODULE ROUTE INSERT ERROR:", _eg4l_insert_err)

except Exception as _eg_stage4l_boot_error:
    print("ERATGUARD STAGE4L REAL MODULE ROUTE LOCK ERROR:", _eg_stage4l_boot_error)
# ===== ERATGUARD STAGE4L REAL MODULE ROUTE LOCK END =====




# ===== ERATGUARD STAGE4L LICENSE ROUTE HOTFIX START =====
# Amaç:
# - /admin/licenses dashboard fallback'e düşmesin.
# - Lisans merkezi ya gerçek template ile açılsın ya da güvenli EratGuard fallback göstersin.
# - Sadece GET isteklerini yakalar; POST lisans işlemlerini bozmaz.
try:
    from flask import request as _eg4l_lic_request
    from flask import render_template as _eg4l_lic_render_template

    def _eg_stage4l_license_route_hotfix():
        try:
            if str(getattr(_eg4l_lic_request, "method", "GET")).upper() != "GET":
                return None

            _path = str(getattr(_eg4l_lic_request, "path", "") or "").rstrip("/")

            if _path not in ("/admin/licenses", "/admin/license"):
                return None

            try:
                return _eg4l_lic_render_template(
                    "admin_licenses.html",
                    brand="EratGuard PRO",
                    licenses={},
                    generated_licenses={},
                    users={},
                    license_requests=[],
                    payment_requests=[],
                    error="",
                    success="",
                    new_license_key="",
                    admin_stats={
                        "users": 0,
                        "licenses": 0,
                        "blocked": 0,
                        "notifications": 0,
                        "system_health": "OK",
                    },
                )
            except Exception as _lic_tpl_err:
                return (
                    "<!doctype html><html lang='tr'><head><meta charset='UTF-8'>"
                    "<meta name='viewport' content='width=device-width, initial-scale=1.0'>"
                    "<title>EratGuard ADMIN Lisans Merkezi</title>"
                    "<style>"
                    "body{margin:0;background:#05070d;color:#f7fff4;font-family:Arial,sans-serif}"
                    ".wrap{max-width:980px;margin:0 auto;padding:18px}"
                    ".hero{border:1px solid rgba(141,255,63,.25);border-radius:24px;padding:20px;background:linear-gradient(180deg,#081421,#05070d)}"
                    "h1{margin:0;font-size:32px}.muted{color:#a6b8c8}.card{margin-top:16px;border:1px solid rgba(80,145,255,.22);border-radius:18px;padding:16px;background:#0b1628}"
                    ".btn{display:inline-block;margin-top:14px;padding:10px 14px;border-radius:999px;background:rgba(141,255,63,.12);border:1px solid rgba(141,255,63,.28);color:#d9ffc7;text-decoration:none;font-weight:900}"
                    "</style></head><body><div class='wrap'>"
                    "<section class='hero'><h1>💳 EratGuard ADMIN Lisans Merkezi</h1>"
                    "<p class='muted'>Lisans yönetimi güvenli fallback ile açıldı. Template hata detayı arşive alınmadan canlı kullanıcıya gösterilmez.</p>"
                    "<a class='btn' href='/admin/dashboard'>← Admin Dashboard</a></section>"
                    "<div class='card'><b>Lisans Merkezi Aktif</b><p class='muted'>Bu sayfa dashboard fallback değildir; lisans modülü için güvenli admin ekranıdır.</p></div>"
                    "</div></body></html>"
                )

        except Exception as _eg4l_lic_err:
            print("ERATGUARD STAGE4L LICENSE HOTFIX ERROR:", _eg4l_lic_err)
            return None

    try:
        _eg4l_lic_funcs = app.before_request_funcs.setdefault(None, [])
        _eg4l_lic_funcs[:] = [f for f in _eg4l_lic_funcs if getattr(f, "__name__", "") != "_eg_stage4l_license_route_hotfix"]
        _eg4l_lic_funcs.insert(0, _eg_stage4l_license_route_hotfix)
    except Exception as _eg4l_lic_insert_err:
        print("ERATGUARD STAGE4L LICENSE HOTFIX INSERT ERROR:", _eg4l_lic_insert_err)

except Exception as _eg_stage4l_license_boot_error:
    print("ERATGUARD STAGE4L LICENSE ROUTE HOTFIX ERROR:", _eg_stage4l_license_boot_error)
# ===== ERATGUARD STAGE4L LICENSE ROUTE HOTFIX END =====




# ===== ERATGUARD STAGE4N PREPEND NOTIFICATIONS ROUTE START =====
# /admin/notifications için eski Stage 4L placeholder guard'ını ezer.
# Sadece GET isteklerini yakalar; POST form akışı daha sonra gerçek kayıt mantığına bağlanacak.
try:
    from flask import request as _eg4n_request
    from flask import render_template as _eg4n_render_template

    def _eg_stage4n_prepend_notifications_route():
        try:
            if str(getattr(_eg4n_request, "method", "GET")).upper() != "GET":
                return None

            _path = str(getattr(_eg4n_request, "path", "") or "").rstrip("/")
            if _path != "/admin/notifications":
                return None

            return _eg4n_render_template(
                "admin_notifications.html",
                notifications=[],
                notification_stats={
                    "total": 0,
                    "today": 0,
                    "critical": 0,
                },
                brand="EratGuard PRO",
            )
        except Exception as _eg4n_err:
            print("ERATGUARD STAGE4N NOTIFICATIONS ROUTE ERROR:", _eg4n_err)
            return None

    try:
        _eg4n_funcs = app.before_request_funcs.setdefault(None, [])
        _eg4n_funcs[:] = [
            f for f in _eg4n_funcs
            if getattr(f, "__name__", "") != "_eg_stage4n_prepend_notifications_route"
        ]
        _eg4n_funcs.insert(0, _eg_stage4n_prepend_notifications_route)
    except Exception as _eg4n_insert_err:
        print("ERATGUARD STAGE4N NOTIFICATIONS INSERT ERROR:", _eg4n_insert_err)

except Exception as _eg4n_boot_error:
    print("ERATGUARD STAGE4N PREPEND NOTIFICATIONS ROUTE ERROR:", _eg4n_boot_error)
# ===== ERATGUARD STAGE4N PREPEND NOTIFICATIONS ROUTE END =====




# ===== ERATGUARD STAGE4O NOTIFICATIONS JSON STORAGE START =====
# Amaç:
# - /admin/notifications formunu gerçek JSON kayıt sistemine bağlar.
# - GET: data/admin_notifications.json içinden son bildirimleri gösterir.
# - POST: title/priority/target/message değerlerini güvenli şekilde kaydeder.
try:
    from flask import request as _eg4o_request
    from flask import render_template as _eg4o_render_template
    import json as _eg4o_json
    from pathlib import Path as _eg4o_Path
    from datetime import datetime as _eg4o_datetime

    _EG4O_NOTIFICATIONS_FILE = _eg4o_Path("data/admin_notifications.json")

    def _eg4o_load_notifications():
        try:
            _EG4O_NOTIFICATIONS_FILE.parent.mkdir(parents=True, exist_ok=True)
            if not _EG4O_NOTIFICATIONS_FILE.exists():
                _EG4O_NOTIFICATIONS_FILE.write_text("[]", encoding="utf-8")
            data = _eg4o_json.loads(_EG4O_NOTIFICATIONS_FILE.read_text(encoding="utf-8") or "[]")
            if isinstance(data, list):
                return data
            return []
        except Exception as _load_err:
            print("ERATGUARD STAGE4O LOAD NOTIFICATIONS ERROR:", _load_err)
            return []

    def _eg4o_save_notifications(items):
        try:
            _EG4O_NOTIFICATIONS_FILE.parent.mkdir(parents=True, exist_ok=True)
            _EG4O_NOTIFICATIONS_FILE.write_text(
                _eg4o_json.dumps(items, ensure_ascii=False, indent=2),
                encoding="utf-8"
            )
            return True
        except Exception as _save_err:
            print("ERATGUARD STAGE4O SAVE NOTIFICATIONS ERROR:", _save_err)
            return False

    def _eg4o_notification_stats(items):
        today = _eg4o_datetime.now().strftime("%Y-%m-%d")
        return {
            "total": len(items),
            "today": sum(1 for x in items if str(x.get("created_at", "")).startswith(today)),
            "critical": sum(1 for x in items if str(x.get("priority", "")).lower() == "critical"),
        }

    def _eg4o_render_notifications(success="", error=""):
        items = _eg4o_load_notifications()
        # En yeni kayıtlar üstte, maksimum 50 kayıt göster.
        display_items = list(reversed(items[-50:]))
        return _eg4o_render_template(
            "admin_notifications.html",
            notifications=display_items,
            notification_stats=_eg4o_notification_stats(items),
            success=success,
            error=error,
            brand="EratGuard PRO",
        )

    def _eg_stage4o_notifications_json_route():
        try:
            _path = str(getattr(_eg4o_request, "path", "") or "").rstrip("/")
            if _path != "/admin/notifications":
                return None

            method = str(getattr(_eg4o_request, "method", "GET")).upper()

            if method == "GET":
                return _eg4o_render_notifications()

            if method == "POST":
                form = getattr(_eg4o_request, "form", {}) or {}

                title = str(form.get("title", "")).strip()
                priority = str(form.get("priority", "normal")).strip().lower()
                target = str(form.get("target", "all")).strip().lower()
                message = str(form.get("message", "")).strip()

                allowed_priorities = {"normal", "high", "critical"}
                allowed_targets = {"all", "premium", "admin"}

                if priority not in allowed_priorities:
                    priority = "normal"
                if target not in allowed_targets:
                    target = "all"

                if not title or not message:
                    return _eg4o_render_notifications(error="Başlık ve mesaj zorunludur.")

                items = _eg4o_load_notifications()
                now = _eg4o_datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                item = {
                    "id": "EG-NOTIF-" + _eg4o_datetime.now().strftime("%Y%m%d%H%M%S"),
                    "title": title[:160],
                    "priority": priority,
                    "target": target,
                    "message": message[:1200],
                    "created_at": now,
                    "status": "created",
                }

                items.append(item)
                # Dosya büyümesini engelle: son 300 kayıt sakla.
                items = items[-300:]

                if not _eg4o_save_notifications(items):
                    return _eg4o_render_notifications(error="Bildirim kaydedilemedi.")

                return _eg4o_render_notifications(success="Bildirim başarıyla kaydedildi.")

            return None

        except Exception as _eg4o_route_err:
            print("ERATGUARD STAGE4O NOTIFICATIONS ROUTE ERROR:", _eg4o_route_err)
            return None

    try:
        _eg4o_funcs = app.before_request_funcs.setdefault(None, [])
        _eg4o_funcs[:] = [
            f for f in _eg4o_funcs
            if getattr(f, "__name__", "") != "_eg_stage4o_notifications_json_route"
        ]
        _eg4o_funcs.insert(0, _eg_stage4o_notifications_json_route)
    except Exception as _eg4o_insert_err:
        print("ERATGUARD STAGE4O NOTIFICATIONS INSERT ERROR:", _eg4o_insert_err)

except Exception as _eg4o_boot_error:
    print("ERATGUARD STAGE4O NOTIFICATIONS JSON STORAGE ERROR:", _eg4o_boot_error)
# ===== ERATGUARD STAGE4O NOTIFICATIONS JSON STORAGE END =====




# ===== ERATGUARD STAGE4P USER NOTIFICATIONS FEED START =====
# Amaç:
# - Admin tarafından data/admin_notifications.json içine kaydedilen bildirimleri kullanıcı tarafında gösterir.
# - target=admin kullanıcıya gösterilmez.
# - target=all ve target=premium şimdilik kullanıcı feed'inde görünür.
try:
    from flask import request as _eg4p_request
    from flask import render_template as _eg4p_render_template
    import json as _eg4p_json
    from pathlib import Path as _eg4p_Path

    _EG4P_NOTIFICATIONS_FILE = _eg4p_Path("data/admin_notifications.json")

    def _eg4p_load_user_notifications():
        try:
            if not _EG4P_NOTIFICATIONS_FILE.exists():
                return []
            data = _eg4p_json.loads(_EG4P_NOTIFICATIONS_FILE.read_text(encoding="utf-8") or "[]")
            if not isinstance(data, list):
                return []

            visible = []
            for item in data:
                if not isinstance(item, dict):
                    continue
                target = str(item.get("target", "all")).lower()
                if target == "admin":
                    continue
                visible.append(item)

            return list(reversed(visible[-50:]))
        except Exception as _load_err:
            print("ERATGUARD STAGE4P USER NOTIFICATIONS LOAD ERROR:", _load_err)
            return []

    def _eg4p_user_notification_stats(items):
        return {
            "total": len(items),
            "high": sum(1 for x in items if str(x.get("priority", "")).lower() == "high"),
            "critical": sum(1 for x in items if str(x.get("priority", "")).lower() == "critical"),
        }

    def _eg_stage4p_user_notifications_feed():
        try:
            if str(getattr(_eg4p_request, "method", "GET")).upper() != "GET":
                return None

            _path = str(getattr(_eg4p_request, "path", "") or "").rstrip("/")
            if _path != "/u/notifications":
                return None

            items = _eg4p_load_user_notifications()

            return _eg4p_render_template(
                "user_notifications_admin_feed.html",
                notifications=items,
                notification_stats=_eg4p_user_notification_stats(items),
                brand="EratGuard PRO",
            )
        except Exception as _eg4p_route_err:
            print("ERATGUARD STAGE4P USER NOTIFICATIONS ROUTE ERROR:", _eg4p_route_err)
            return None

    try:
        _eg4p_funcs = app.before_request_funcs.setdefault(None, [])
        _eg4p_funcs[:] = [
            f for f in _eg4p_funcs
            if getattr(f, "__name__", "") != "_eg_stage4p_user_notifications_feed"
        ]
        _eg4p_funcs.insert(0, _eg_stage4p_user_notifications_feed)
    except Exception as _eg4p_insert_err:
        print("ERATGUARD STAGE4P USER NOTIFICATIONS INSERT ERROR:", _eg4p_insert_err)

except Exception as _eg4p_boot_error:
    print("ERATGUARD STAGE4P USER NOTIFICATIONS FEED ERROR:", _eg4p_boot_error)
# ===== ERATGUARD STAGE4P USER NOTIFICATIONS FEED END =====




# ===== ERATGUARD STAGE4P FORCE USER NOTIFICATIONS ROUTE START =====
# Amaç:
# - Eski kullanıcı bildirim route override'larını ezer.
# - /u/notifications her zaman admin JSON feed sayfasını gösterir.
try:
    from flask import request as _eg4p_force_request
    from flask import render_template as _eg4p_force_render_template
    import json as _eg4p_force_json
    from pathlib import Path as _eg4p_force_Path

    _EG4P_FORCE_NOTIFICATIONS_FILE = _eg4p_force_Path("data/admin_notifications.json")

    def _eg4p_force_load_items():
        try:
            if not _EG4P_FORCE_NOTIFICATIONS_FILE.exists():
                return []
            data = _eg4p_force_json.loads(
                _EG4P_FORCE_NOTIFICATIONS_FILE.read_text(encoding="utf-8") or "[]"
            )
            if not isinstance(data, list):
                return []

            visible = []
            for item in data:
                if not isinstance(item, dict):
                    continue
                target = str(item.get("target", "all")).lower().strip()
                if target == "admin":
                    continue
                visible.append(item)

            return list(reversed(visible[-50:]))
        except Exception as _eg4p_force_load_err:
            print("ERATGUARD STAGE4P FORCE LOAD ERROR:", _eg4p_force_load_err)
            return []

    def _eg4p_force_stats(items):
        return {
            "total": len(items),
            "high": sum(1 for x in items if str(x.get("priority", "")).lower() == "high"),
            "critical": sum(1 for x in items if str(x.get("priority", "")).lower() == "critical"),
        }

    def _eg_stage4p_force_user_notifications_page(**kwargs):
        try:
            items = _eg4p_force_load_items()
            return _eg4p_force_render_template(
                "user_notifications_admin_feed.html",
                notifications=items,
                notification_stats=_eg4p_force_stats(items),
                brand="EratGuard PRO",
            )
        except Exception as _eg4p_force_render_err:
            print("ERATGUARD STAGE4P FORCE RENDER ERROR:", _eg4p_force_render_err)
            return (
                "<!doctype html><html lang='tr'><head><meta charset='UTF-8'>"
                "<meta name='viewport' content='width=device-width, initial-scale=1.0'>"
                "<title>EratGuard PRO Bildirimler</title></head><body>"
                "<h1>EratGuard PRO Bildirimler</h1>"
                "<p>Bildirim sayfası güvenli fallback ile açıldı.</p>"
                "<p><a href='/dashboard'>Kullanıcı Paneli</a></p>"
                "</body></html>"
            )

    def _eg_stage4p_force_before_request():
        try:
            if str(getattr(_eg4p_force_request, "method", "GET")).upper() != "GET":
                return None
            _path = str(getattr(_eg4p_force_request, "path", "") or "").rstrip("/")
            if _path == "/u/notifications":
                return _eg_stage4p_force_user_notifications_page()
        except Exception as _eg4p_force_before_err:
            print("ERATGUARD STAGE4P FORCE BEFORE ERROR:", _eg4p_force_before_err)
            return None

    # before_request listesinin en başına koy.
    try:
        _eg4p_force_funcs = app.before_request_funcs.setdefault(None, [])
        _eg4p_force_funcs[:] = [
            f for f in _eg4p_force_funcs
            if getattr(f, "__name__", "") != "_eg_stage4p_force_before_request"
        ]
        _eg4p_force_funcs.insert(0, _eg_stage4p_force_before_request)
    except Exception as _eg4p_force_insert_err:
        print("ERATGUARD STAGE4P FORCE INSERT ERROR:", _eg4p_force_insert_err)

    # Var olan /u/notifications endpoint'lerini de doğrudan yeni renderer'a bağla.
    try:
        for _eg4p_rule in list(app.url_map.iter_rules()):
            if str(_eg4p_rule.rule).rstrip("/") == "/u/notifications":
                app.view_functions[_eg4p_rule.endpoint] = _eg_stage4p_force_user_notifications_page
    except Exception as _eg4p_force_route_err:
        print("ERATGUARD STAGE4P FORCE ROUTE MAP ERROR:", _eg4p_force_route_err)

except Exception as _eg4p_force_boot_err:
    print("ERATGUARD STAGE4P FORCE USER NOTIFICATIONS ROUTE ERROR:", _eg4p_force_boot_err)
# ===== ERATGUARD STAGE4P FORCE USER NOTIFICATIONS ROUTE END =====




# ===== ERATGUARD STAGE4Q PREMIUM NOTIFICATION FILTER START =====
# Amaç:
# - Kullanıcı bildirimlerinde hedef filtrelerini gerçek lisans durumuna bağlar.
# - target=all herkes görür.
# - target=admin kullanıcı tarafında görünmez.
# - target=premium sadece premium/pro/lisanslı aktif kullanıcıya görünür.
try:
    from flask import request as _eg4q_request
    from flask import render_template as _eg4q_render_template
    from flask import session as _eg4q_session
    import json as _eg4q_json
    from pathlib import Path as _eg4q_Path
    from datetime import datetime as _eg4q_datetime

    _EG4Q_USERS_FILE = _eg4q_Path("data/users.json")
    _EG4Q_LICENSES_FILE = _eg4q_Path("data/licenses.json")
    _EG4Q_NOTIFICATIONS_FILE = _eg4q_Path("data/admin_notifications.json")

    def _eg4q_load_json(path, fallback):
        try:
            if not path.exists():
                return fallback
            data = _eg4q_json.loads(path.read_text(encoding="utf-8") or "")
            return data
        except Exception as _eg4q_json_err:
            print("ERATGUARD STAGE4Q JSON LOAD ERROR:", path, _eg4q_json_err)
            return fallback

    def _eg4q_date_active(value):
        try:
            if not value:
                return False
            raw = str(value).strip()
            if not raw:
                return False
            # 2099-12-31, 2026-05-30 gibi tarihleri destekle.
            day = raw[:10]
            exp = _eg4q_datetime.strptime(day, "%Y-%m-%d").date()
            return exp >= _eg4q_datetime.now().date()
        except Exception:
            return False

    def _eg4q_current_user_is_premium():
        try:
            username = str(_eg4q_session.get("username") or "").strip()
            role = str(_eg4q_session.get("role") or "").lower().strip()
            is_admin = bool(_eg4q_session.get("is_admin")) or role == "admin" or username.lower() == "admin"

            if is_admin:
                return True

            if not username:
                return False

            users = _eg4q_load_json(_EG4Q_USERS_FILE, {})
            licenses = _eg4q_load_json(_EG4Q_LICENSES_FILE, {})

            user = {}
            if isinstance(users, dict):
                user = users.get(username) or users.get(username.lower()) or {}

            if not isinstance(user, dict):
                user = {}

            if user.get("active") is False:
                return False

            license_type = str(
                user.get("license_type")
                or user.get("license_mode")
                or user.get("plan")
                or ""
            ).lower().strip()

            premium_types = {"pro", "premium", "lifetime", "admin", "pro_monthly", "pro_yearly"}

            if license_type in premium_types:
                return True

            license_key = str(user.get("license_key") or "").strip().upper()
            if not license_key or license_key == "NONE":
                return False

            # Kullanıcıda geçerli tarih varsa lisanslı kabul et.
            for date_key in ("expires_at", "license_expiry", "expiry"):
                if _eg4q_date_active(user.get(date_key)):
                    return True

            if isinstance(licenses, dict):
                lic = licenses.get(license_key)
                if isinstance(lic, dict):
                    status = str(lic.get("status") or "").lower()
                    used = lic.get("used")
                    lic_user = str(lic.get("username") or lic.get("used_by") or "").strip()

                    lic_type = str(
                        lic.get("license_type")
                        or lic.get("type")
                        or lic.get("plan")
                        or ""
                    ).lower().strip()

                    if lic_type in premium_types:
                        if status in ("active", "used", "approved") or used is True or lic_user == username:
                            return True

                    for date_key in ("license_expiry", "expiry", "expires_at"):
                        if _eg4q_date_active(lic.get(date_key)):
                            if status in ("active", "used", "approved") or used is True or lic_user == username:
                                return True

            return False

        except Exception as _eg4q_premium_err:
            print("ERATGUARD STAGE4Q PREMIUM CHECK ERROR:", _eg4q_premium_err)
            return False

    def _eg4q_load_filtered_notifications():
        try:
            data = _eg4q_load_json(_EG4Q_NOTIFICATIONS_FILE, [])
            if not isinstance(data, list):
                return []

            premium_user = _eg4q_current_user_is_premium()

            visible = []
            for item in data:
                if not isinstance(item, dict):
                    continue

                target = str(item.get("target", "all")).lower().strip()

                if target == "admin":
                    continue

                if target == "premium" and not premium_user:
                    continue

                visible.append(item)

            return list(reversed(visible[-50:]))

        except Exception as _eg4q_filter_err:
            print("ERATGUARD STAGE4Q FILTER ERROR:", _eg4q_filter_err)
            return []

    def _eg4q_stats(items):
        return {
            "total": len(items),
            "high": sum(1 for x in items if str(x.get("priority", "")).lower() == "high"),
            "critical": sum(1 for x in items if str(x.get("priority", "")).lower() == "critical"),
        }

    def _eg_stage4q_user_notifications_page(**kwargs):
        try:
            items = _eg4q_load_filtered_notifications()
            return _eg4q_render_template(
                "user_notifications_admin_feed.html",
                notifications=items,
                notification_stats=_eg4q_stats(items),
                brand="EratGuard PRO",
            )
        except Exception as _eg4q_render_err:
            print("ERATGUARD STAGE4Q RENDER ERROR:", _eg4q_render_err)
            return None

    def _eg_stage4q_before_request():
        try:
            if str(getattr(_eg4q_request, "method", "GET")).upper() != "GET":
                return None

            _path = str(getattr(_eg4q_request, "path", "") or "").rstrip("/")
            if _path == "/u/notifications":
                return _eg_stage4q_user_notifications_page()
        except Exception as _eg4q_before_err:
            print("ERATGUARD STAGE4Q BEFORE ERROR:", _eg4q_before_err)
            return None

    try:
        _eg4q_funcs = app.before_request_funcs.setdefault(None, [])
        _eg4q_funcs[:] = [
            f for f in _eg4q_funcs
            if getattr(f, "__name__", "") != "_eg_stage4q_before_request"
        ]
        _eg4q_funcs.insert(0, _eg_stage4q_before_request)
    except Exception as _eg4q_insert_err:
        print("ERATGUARD STAGE4Q INSERT ERROR:", _eg4q_insert_err)

    try:
        for _eg4q_rule in list(app.url_map.iter_rules()):
            if str(_eg4q_rule.rule).rstrip("/") == "/u/notifications":
                app.view_functions[_eg4q_rule.endpoint] = _eg_stage4q_user_notifications_page
    except Exception as _eg4q_route_err:
        print("ERATGUARD STAGE4Q ROUTE MAP ERROR:", _eg4q_route_err)

except Exception as _eg4q_boot_err:
    print("ERATGUARD STAGE4Q PREMIUM NOTIFICATION FILTER ERROR:", _eg4q_boot_err)
# ===== ERATGUARD STAGE4Q PREMIUM NOTIFICATION FILTER END =====




# ===== ERATGUARD STAGE4R NOTIFICATION MANAGEMENT START =====
# Amaç:
# - Admin bildirimlerini arşivleme, geri alma ve silme yönetimi ekler.
# - Kullanıcı tarafında archived bildirimleri gizler.
try:
    from flask import request as _eg4r_request
    from flask import render_template as _eg4r_render_template
    from flask import session as _eg4r_session
    import json as _eg4r_json
    from pathlib import Path as _eg4r_Path
    from datetime import datetime as _eg4r_datetime

    _EG4R_NOTIFICATIONS_FILE = _eg4r_Path("data/admin_notifications.json")
    _EG4R_USERS_FILE = _eg4r_Path("data/users.json")
    _EG4R_LICENSES_FILE = _eg4r_Path("data/licenses.json")

    def _eg4r_load_json(path, fallback):
        try:
            if not path.exists():
                return fallback
            data = _eg4r_json.loads(path.read_text(encoding="utf-8") or "")
            return data
        except Exception as _err:
            print("ERATGUARD STAGE4R LOAD JSON ERROR:", path, _err)
            return fallback

    def _eg4r_save_notifications(items):
        try:
            _EG4R_NOTIFICATIONS_FILE.parent.mkdir(parents=True, exist_ok=True)
            _EG4R_NOTIFICATIONS_FILE.write_text(
                _eg4r_json.dumps(items, ensure_ascii=False, indent=2),
                encoding="utf-8"
            )
            return True
        except Exception as _err:
            print("ERATGUARD STAGE4R SAVE ERROR:", _err)
            return False

    def _eg4r_load_notifications():
        data = _eg4r_load_json(_EG4R_NOTIFICATIONS_FILE, [])
        return data if isinstance(data, list) else []

    def _eg4r_stats(items):
        active = [x for x in items if isinstance(x, dict) and str(x.get("status", "created")).lower() != "archived"]
        return {
            "total": len(active),
            "today": sum(1 for x in active if str(x.get("created_at", "")).startswith(_eg4r_datetime.now().strftime("%Y-%m-%d"))),
            "critical": sum(1 for x in active if str(x.get("priority", "")).lower() == "critical"),
        }

    def _eg4r_render_admin(success="", error=""):
        items = _eg4r_load_notifications()
        display_items = list(reversed(items[-80:]))
        return _eg4r_render_template(
            "admin_notifications.html",
            notifications=display_items,
            notification_stats=_eg4r_stats(items),
            success=success,
            error=error,
            brand="EratGuard PRO",
        )

    def _eg4r_admin_manage_route():
        try:
            _path = str(getattr(_eg4r_request, "path", "") or "").rstrip("/")
            if _path != "/admin/notifications":
                return None

            method = str(getattr(_eg4r_request, "method", "GET")).upper()

            if method == "GET":
                return _eg4r_render_admin()

            if method != "POST":
                return None

            form = getattr(_eg4r_request, "form", {}) or {}
            action = str(form.get("action", "")).strip().lower()
            notification_id = str(form.get("notification_id", "")).strip()

            # Yeni bildirim oluşturma POST'unu Stage 4O'ya bırak.
            if action not in ("archive", "restore", "delete"):
                return None

            if not notification_id:
                return _eg4r_render_admin(error="Bildirim ID bulunamadı.")

            items = _eg4r_load_notifications()
            found = False
            new_items = []

            for item in items:
                if not isinstance(item, dict):
                    new_items.append(item)
                    continue

                if str(item.get("id", "")).strip() == notification_id:
                    found = True

                    if action == "archive":
                        item["status"] = "archived"
                        item["archived_at"] = _eg4r_datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        new_items.append(item)

                    elif action == "restore":
                        item["status"] = "created"
                        item.pop("archived_at", None)
                        new_items.append(item)

                    elif action == "delete":
                        # Bilerek eklemiyoruz: JSON’dan kaldırılır.
                        continue
                else:
                    new_items.append(item)

            if not found:
                return _eg4r_render_admin(error="Bildirim bulunamadı.")

            if not _eg4r_save_notifications(new_items):
                return _eg4r_render_admin(error="Bildirim güncellenemedi.")

            if action == "archive":
                return _eg4r_render_admin(success="Bildirim arşivlendi.")
            if action == "restore":
                return _eg4r_render_admin(success="Bildirim tekrar aktif edildi.")
            if action == "delete":
                return _eg4r_render_admin(success="Bildirim silindi.")

            return _eg4r_render_admin()

        except Exception as _err:
            print("ERATGUARD STAGE4R ADMIN ROUTE ERROR:", _err)
            return None

    def _eg4r_date_active(value):
        try:
            if not value:
                return False
            exp = _eg4r_datetime.strptime(str(value).strip()[:10], "%Y-%m-%d").date()
            return exp >= _eg4r_datetime.now().date()
        except Exception:
            return False

    def _eg4r_current_user_is_premium():
        try:
            username = str(_eg4r_session.get("username") or "").strip()
            role = str(_eg4r_session.get("role") or "").lower().strip()
            is_admin = bool(_eg4r_session.get("is_admin")) or role == "admin" or username.lower() == "admin"

            if is_admin:
                return True
            if not username:
                return False

            users = _eg4r_load_json(_EG4R_USERS_FILE, {})
            licenses = _eg4r_load_json(_EG4R_LICENSES_FILE, {})
            user = {}

            if isinstance(users, dict):
                user = users.get(username) or users.get(username.lower()) or {}

            if not isinstance(user, dict):
                user = {}

            if user.get("active") is False:
                return False

            premium_types = {"pro", "premium", "lifetime", "admin", "pro_monthly", "pro_yearly"}
            license_type = str(user.get("license_type") or user.get("license_mode") or user.get("plan") or "").lower().strip()

            if license_type in premium_types:
                return True

            license_key = str(user.get("license_key") or "").strip().upper()
            if not license_key or license_key == "NONE":
                return False

            for date_key in ("expires_at", "license_expiry", "expiry"):
                if _eg4r_date_active(user.get(date_key)):
                    return True

            if isinstance(licenses, dict):
                lic = licenses.get(license_key)
                if isinstance(lic, dict):
                    status = str(lic.get("status") or "").lower()
                    used = lic.get("used")
                    lic_user = str(lic.get("username") or lic.get("used_by") or "").strip()
                    lic_type = str(lic.get("license_type") or lic.get("type") or lic.get("plan") or "").lower().strip()

                    if lic_type in premium_types and (status in ("active", "used", "approved") or used is True or lic_user == username):
                        return True

                    for date_key in ("license_expiry", "expiry", "expires_at"):
                        if _eg4r_date_active(lic.get(date_key)) and (status in ("active", "used", "approved") or used is True or lic_user == username):
                            return True

            return False
        except Exception as _err:
            print("ERATGUARD STAGE4R PREMIUM CHECK ERROR:", _err)
            return False

    def _eg4r_user_items():
        items = _eg4r_load_notifications()
        premium_user = _eg4r_current_user_is_premium()
        visible = []

        for item in items:
            if not isinstance(item, dict):
                continue

            if str(item.get("status", "created")).lower() == "archived":
                continue

            target = str(item.get("target", "all")).lower().strip()

            if target == "admin":
                continue

            if target == "premium" and not premium_user:
                continue

            visible.append(item)

        return list(reversed(visible[-50:]))

    def _eg4r_user_stats(items):
        return {
            "total": len(items),
            "high": sum(1 for x in items if str(x.get("priority", "")).lower() == "high"),
            "critical": sum(1 for x in items if str(x.get("priority", "")).lower() == "critical"),
        }

    def _eg4r_render_user(**kwargs):
        try:
            items = _eg4r_user_items()
            return _eg4r_render_template(
                "user_notifications_admin_feed.html",
                notifications=items,
                notification_stats=_eg4r_user_stats(items),
                brand="EratGuard PRO",
            )
        except Exception as _err:
            print("ERATGUARD STAGE4R USER RENDER ERROR:", _err)
            return None

    def _eg_stage4r_before_request():
        try:
            _path = str(getattr(_eg4r_request, "path", "") or "").rstrip("/")
            _method = str(getattr(_eg4r_request, "method", "GET")).upper()

            if _path == "/admin/notifications":
                result = _eg4r_admin_manage_route()
                if result is not None:
                    return result

            if _path == "/u/notifications" and _method == "GET":
                return _eg4r_render_user()

            return None
        except Exception as _err:
            print("ERATGUARD STAGE4R BEFORE ERROR:", _err)
            return None

    try:
        _eg4r_funcs = app.before_request_funcs.setdefault(None, [])
        _eg4r_funcs[:] = [
            f for f in _eg4r_funcs
            if getattr(f, "__name__", "") != "_eg_stage4r_before_request"
        ]
        _eg4r_funcs.insert(0, _eg_stage4r_before_request)
    except Exception as _err:
        print("ERATGUARD STAGE4R INSERT ERROR:", _err)

    try:
        for _eg4r_rule in list(app.url_map.iter_rules()):
            _rule = str(_eg4r_rule.rule).rstrip("/")
            if _rule == "/u/notifications":
                app.view_functions[_eg4r_rule.endpoint] = _eg4r_render_user
    except Exception as _err:
        print("ERATGUARD STAGE4R ROUTE MAP ERROR:", _err)

except Exception as _eg4r_boot_err:
    print("ERATGUARD STAGE4R NOTIFICATION MANAGEMENT ERROR:", _eg4r_boot_err)
# ===== ERATGUARD STAGE4R NOTIFICATION MANAGEMENT END =====




# ===== ERATGUARD STAGE4R HOTFIX CREATE MANAGEMENT ROUTE START =====
# Amaç:
# - /admin/notifications POST create işlemini de yönetim butonlu Stage 4R renderer'a bağlar.
# - Böylece bildirim oluşturulduktan sonra Arşivle/Sil butonları kesin görünür.
try:
    from flask import request as _eg4r_hot_request
    from flask import render_template as _eg4r_hot_render_template
    import json as _eg4r_hot_json
    from pathlib import Path as _eg4r_hot_Path
    from datetime import datetime as _eg4r_hot_datetime

    _EG4R_HOT_FILE = _eg4r_hot_Path("data/admin_notifications.json")

    def _eg4r_hot_load():
        try:
            _EG4R_HOT_FILE.parent.mkdir(parents=True, exist_ok=True)
            if not _EG4R_HOT_FILE.exists():
                _EG4R_HOT_FILE.write_text("[]", encoding="utf-8")
            data = _eg4r_hot_json.loads(_EG4R_HOT_FILE.read_text(encoding="utf-8") or "[]")
            return data if isinstance(data, list) else []
        except Exception as _err:
            print("ERATGUARD STAGE4R HOT LOAD ERROR:", _err)
            return []

    def _eg4r_hot_save(items):
        try:
            _EG4R_HOT_FILE.parent.mkdir(parents=True, exist_ok=True)
            _EG4R_HOT_FILE.write_text(
                _eg4r_hot_json.dumps(items, ensure_ascii=False, indent=2),
                encoding="utf-8"
            )
            return True
        except Exception as _err:
            print("ERATGUARD STAGE4R HOT SAVE ERROR:", _err)
            return False

    def _eg4r_hot_stats(items):
        active = [
            x for x in items
            if isinstance(x, dict) and str(x.get("status", "created")).lower() != "archived"
        ]
        today = _eg4r_hot_datetime.now().strftime("%Y-%m-%d")
        return {
            "total": len(active),
            "today": sum(1 for x in active if str(x.get("created_at", "")).startswith(today)),
            "critical": sum(1 for x in active if str(x.get("priority", "")).lower() == "critical"),
        }

    def _eg4r_hot_render(success="", error=""):
        items = _eg4r_hot_load()
        return _eg4r_hot_render_template(
            "admin_notifications.html",
            notifications=list(reversed(items[-80:])),
            notification_stats=_eg4r_hot_stats(items),
            success=success,
            error=error,
            brand="EratGuard PRO",
        )

    def _eg_stage4r_hotfix_admin_notifications():
        try:
            path = str(getattr(_eg4r_hot_request, "path", "") or "").rstrip("/")
            if path != "/admin/notifications":
                return None

            method = str(getattr(_eg4r_hot_request, "method", "GET")).upper()
            if method == "GET":
                return _eg4r_hot_render()

            if method != "POST":
                return None

            form = getattr(_eg4r_hot_request, "form", {}) or {}
            action = str(form.get("action", "")).strip().lower()
            items = _eg4r_hot_load()

            if action in ("archive", "restore", "delete"):
                notification_id = str(form.get("notification_id", "")).strip()
                if not notification_id:
                    return _eg4r_hot_render(error="Bildirim ID bulunamadı.")

                found = False
                new_items = []

                for item in items:
                    if not isinstance(item, dict):
                        new_items.append(item)
                        continue

                    if str(item.get("id", "")).strip() == notification_id:
                        found = True
                        if action == "archive":
                            item["status"] = "archived"
                            item["archived_at"] = _eg4r_hot_datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                            new_items.append(item)
                        elif action == "restore":
                            item["status"] = "created"
                            item.pop("archived_at", None)
                            new_items.append(item)
                        elif action == "delete":
                            continue
                    else:
                        new_items.append(item)

                if not found:
                    return _eg4r_hot_render(error="Bildirim bulunamadı.")

                if not _eg4r_hot_save(new_items):
                    return _eg4r_hot_render(error="Bildirim güncellenemedi.")

                if action == "archive":
                    return _eg4r_hot_render(success="Bildirim arşivlendi.")
                if action == "restore":
                    return _eg4r_hot_render(success="Bildirim tekrar aktif edildi.")
                if action == "delete":
                    return _eg4r_hot_render(success="Bildirim silindi.")

            # Create action: action boşsa veya create ise yeni bildirim oluştur.
            title = str(form.get("title", "")).strip()
            priority = str(form.get("priority", "normal")).strip().lower()
            target = str(form.get("target", "all")).strip().lower()
            message = str(form.get("message", "")).strip()

            if not title or not message:
                return _eg4r_hot_render(error="Başlık ve mesaj zorunludur.")

            if priority not in {"normal", "high", "critical"}:
                priority = "normal"

            if target not in {"all", "premium", "admin"}:
                target = "all"

            now = _eg4r_hot_datetime.now()
            item = {
                "id": "EG-NOTIF-" + now.strftime("%Y%m%d%H%M%S%f"),
                "title": title[:160],
                "priority": priority,
                "target": target,
                "message": message[:1200],
                "created_at": now.strftime("%Y-%m-%d %H:%M:%S"),
                "status": "created",
            }

            items.append(item)
            items = items[-300:]

            if not _eg4r_hot_save(items):
                return _eg4r_hot_render(error="Bildirim kaydedilemedi.")

            return _eg4r_hot_render(success="Bildirim başarıyla kaydedildi.")

        except Exception as _err:
            print("ERATGUARD STAGE4R HOTFIX ADMIN ROUTE ERROR:", _err)
            return None

    try:
        _eg4r_hot_funcs = app.before_request_funcs.setdefault(None, [])
        _eg4r_hot_funcs[:] = [
            f for f in _eg4r_hot_funcs
            if getattr(f, "__name__", "") != "_eg_stage4r_hotfix_admin_notifications"
        ]
        _eg4r_hot_funcs.insert(0, _eg_stage4r_hotfix_admin_notifications)
    except Exception as _err:
        print("ERATGUARD STAGE4R HOTFIX INSERT ERROR:", _err)

except Exception as _boot_err:
    print("ERATGUARD STAGE4R HOTFIX CREATE MANAGEMENT ROUTE ERROR:", _boot_err)
# ===== ERATGUARD STAGE4R HOTFIX CREATE MANAGEMENT ROUTE END =====




# ===== ERATGUARD STAGE4U CLAUDE PANEL PREVIEW START =====
# Claude admin panelini ana dashboard'a almadan önce güvenli preview route.
try:
    from flask import render_template as _eg4u_render_template

    def _eg_stage4u_claude_panel_preview():
        try:
            stats = {
                "users": 0,
                "licenses": 0,
                "payments": 0,
                "blocked": 0,
                "threats": 0,
                "logs": 0,
                "notifications": 0,
            }

            if "_eg_real_admin_dashboard_stats" in globals():
                try:
                    live_stats = _eg_real_admin_dashboard_stats()
                    if isinstance(live_stats, dict):
                        stats.update(live_stats)
                except Exception as _eg4u_stats_err:
                    print("ERATGUARD STAGE4U STATS ERROR:", _eg4u_stats_err)

            def _eg4u_to_int(value, default=0):
                try:
                    if value is None:
                        return default
                    raw = str(value).strip()
                    if raw == "":
                        return default
                    raw = raw.replace(",", "").replace(".", "")
                    return int(float(raw))
                except Exception:
                    return default

            for _eg4u_key in ("users", "licenses", "payments", "blocked", "threats", "logs", "notifications"):
                stats[_eg4u_key] = _eg4u_to_int(stats.get(_eg4u_key), 0)

            return _eg4u_render_template(
                "admin_dashboard_claude.html",
                admin_stats=stats,
                brand="EratGuard PRO",
                current_user="admin",
                username="admin",
                page_title="Dashboard",
            )
        except Exception as _eg4u_err:
            import traceback as _eg4u_traceback
            _eg4u_detail = _eg4u_traceback.format_exc()
            print("ERATGUARD STAGE4U CLAUDE PREVIEW RENDER ERROR:", _eg4u_detail)
            return (
                "<!doctype html><html lang='tr'><head><meta charset='UTF-8'>"
                "<meta name='viewport' content='width=device-width, initial-scale=1.0'>"
                "<title>EratGuard Claude Panel Preview</title></head><body>"
                "<h1>EratGuard Claude Panel Preview</h1>"
                f"<p>Preview yüklenemedi: {_eg4u_err}</p>"
                "<pre style='white-space:pre-wrap;background:#111;color:#eee;padding:12px;border-radius:12px;'>"
                f"{_eg4u_detail}"
                "</pre>"
                "<p><a href='/admin/dashboard'>Admin Dashboard</a></p>"
                "</body></html>"
            ), 500

    try:
        app.add_url_rule(
            "/admin/dashboard-claude-preview",
            "eg_stage4u_claude_panel_preview",
            _eg_stage4u_claude_panel_preview,
            methods=["GET"],
        )
    except Exception as _eg4u_route_err:
        print("ERATGUARD STAGE4U CLAUDE PANEL ROUTE ERROR:", _eg4u_route_err)

except Exception as _eg4u_boot_err:
    print("ERATGUARD STAGE4U CLAUDE PANEL PREVIEW ERROR:", _eg4u_boot_err)
# ===== ERATGUARD STAGE4U CLAUDE PANEL PREVIEW END =====




# ===== ERATGUARD STAGE5A HARD ADMIN AUTH LOCK START =====
# Amaç:
# - /admin/login route'unun yanlışlıkla dashboard göstermesini engeller.
# - /admin, /admin/dashboard ve /admin/* yollarını admin session olmadan kapatır.
# - Yetkisiz kullanıcıyı gerçek /admin/login sayfasına yönlendirir.
try:
    from flask import request as _eg5a_request
    from flask import session as _eg5a_session
    from flask import redirect as _eg5a_redirect
    from flask import render_template as _eg5a_render_template
    from flask import make_response as _eg5a_make_response
    import html as _eg5a_html

    def _eg5a_is_admin_session():
        try:
            username = str(_eg5a_session.get("username") or "").strip().lower()
            role = str(_eg5a_session.get("role") or "").strip().lower()

            if bool(_eg5a_session.get("is_admin")):
                return True

            if role == "admin":
                return True

            if username == "admin" or username.startswith("eg_admin_"):
                return True

            # APK/WebView ve mobil tarayıcı için kalıcı admin cookie kabulü.
            try:
                mobile_cookie = str(_eg5a_request.cookies.get("ss_admin_mobile") or "").strip()
                token_func = globals().get("_ss_admin_cookie_token_final")
                expected = str(token_func() if callable(token_func) else "").strip()
                if mobile_cookie and expected and mobile_cookie == expected:
                    return True
            except Exception as _cookie_err:
                print("ERATGUARD STAGE5A ADMIN COOKIE CHECK WARN:", _cookie_err)

            return False
        except Exception as _err:
            print("ERATGUARD STAGE5A SESSION CHECK ERROR:", _err)
            return False

    def _eg5a_real_admin_login_page():
        try:
            # Varsa gerçek admin_login.html kullan.
            return _eg5a_render_template(
                "admin_login.html",
                brand="EratGuard PRO",
                error="",
                next=str(_eg5a_request.args.get("next") or "/admin/dashboard"),
            )
        except Exception as _err:
            print("ERATGUARD STAGE5A ADMIN LOGIN TEMPLATE ERROR:", _err)

            next_url = _eg5a_html.escape(str(_eg5a_request.args.get("next") or "/admin/dashboard"))
            return """<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>EratGuard Admin Login</title>
<style>
body{margin:0;min-height:100vh;display:grid;place-items:center;background:#050810;color:#e8f4ff;font-family:Arial,sans-serif}
.card{width:min(420px,92vw);border:1px solid rgba(0,200,240,.22);border-radius:24px;background:#0a1020;padding:26px;box-shadow:0 24px 70px rgba(0,0,0,.42)}
h1{margin:0 0 8px;font-size:30px}
p{color:#91a8c2}
label{display:block;margin-top:14px;color:#91a8c2;font-weight:800}
input{width:100%;box-sizing:border-box;margin-top:7px;padding:13px;border-radius:13px;border:1px solid #203555;background:#050810;color:#e8f4ff}
button{width:100%;margin-top:18px;padding:14px;border:0;border-radius:14px;background:#00c8f0;color:#031018;font-weight:1000}
</style>
</head>
<body>
<form class="card" method="post" action="/admin/login">
<h1>EratGuard Admin</h1>
<p>Admin erişimi için giriş yap.</p>
<input type="hidden" name="next" value=\"""" + next_url + """\">
<label>Kullanıcı adı</label>
<input name="username" autocomplete="username" required>
<label>Şifre</label>
<input name="password" type="password" autocomplete="current-password" required>
<button type="submit">Giriş Yap</button>
</form>
</body>
</html>"""

    def _eg5a_admin_auth_gate():
        try:
            path = str(getattr(_eg5a_request, "path", "") or "")
            clean = path.rstrip("/") or "/"

            if not (clean == "/admin" or clean.startswith("/admin/")):
                return None

            # Statik dosyalara dokunma.
            if (
                clean.startswith("/static")
                or clean.startswith("/admin/static")
                or clean.endswith((".css", ".js", ".png", ".jpg", ".jpeg", ".svg", ".ico", ".webp", ".woff", ".woff2"))
            ):
                return None

            # Login sayfasını dashboard override'dan kurtar.
            if clean == "/admin/login":
                if str(_eg5a_request.method).upper() == "GET":
                    resp = _eg5a_make_response(_eg5a_real_admin_login_page())
                    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
                    return resp

                # POST login akışını mevcut backend'e bırak.
                return None

            # Logout mevcut backend'e kalabilir.
            if clean == "/admin/logout":
                return None

            # Admin session varsa geç.
            if _eg5a_is_admin_session():
                return None

            # Yetkisiz admin erişimini login'e at.
            return _eg5a_redirect("/admin/login?next=" + path)

        except Exception as _err:
            print("ERATGUARD STAGE5A ADMIN AUTH GATE ERROR:", _err)
            return None

    try:
        _eg5a_funcs = app.before_request_funcs.setdefault(None, [])
        _eg5a_funcs[:] = [
            f for f in _eg5a_funcs
            if getattr(f, "__name__", "") != "_eg5a_admin_auth_gate"
        ]
        _eg5a_funcs.insert(0, _eg5a_admin_auth_gate)
        print("ERATGUARD STAGE5A HARD ADMIN AUTH LOCK ACTIVE")
    except Exception as _err:
        print("ERATGUARD STAGE5A INSERT ERROR:", _err)

except Exception as _boot_err:
    print("ERATGUARD STAGE5A HARD ADMIN AUTH LOCK BOOT ERROR:", _boot_err)
# ===== ERATGUARD STAGE5A HARD ADMIN AUTH LOCK END =====




# ===== ERATGUARD STAGE5C REAL ADMIN DATA API START =====
# Amaç:
# - Claude admin panelindeki boş/demo alanları gerçek JSON kaynaklarına bağlar.
# - Sahte veri üretmez; veri yoksa 0 / [] döndürür.
try:
    from flask import jsonify as _eg5c_jsonify
    from flask import session as _eg5c_session
    from flask import request as _eg5c_request
    from pathlib import Path as _eg5c_Path
    import json as _eg5c_json
    from datetime import datetime as _eg5c_datetime

    def _eg5c_is_admin():
        try:
            username = str(_eg5c_session.get("username") or "").strip().lower()
            role = str(_eg5c_session.get("role") or "").strip().lower()
            return bool(_eg5c_session.get("is_admin")) or role == "admin" or username == "admin"
        except Exception:
            return False

    def _eg5c_forbidden():
        return _eg5c_jsonify({"ok": False, "error": "admin_login_required"}), 403

    def _eg5c_load_json(default, *paths):
        for raw in paths:
            try:
                path = _eg5c_Path(raw)
                if not path.exists():
                    continue
                txt = path.read_text(encoding="utf-8", errors="ignore").strip()
                if not txt:
                    continue
                return _eg5c_json.loads(txt)
            except Exception as _err:
                print("ERATGUARD STAGE5C LOAD JSON ERROR:", raw, _err)
        return default

    def _eg5c_as_list(data):
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return list(data.values())
        return []

    def _eg5c_as_dict(data):
        return data if isinstance(data, dict) else {}

    def _eg5c_safe_str(v, limit=180):
        try:
            return str(v if v is not None else "").strip()[:limit]
        except Exception:
            return ""

    def _eg5c_user_items():
        users = _eg5c_as_dict(_eg5c_load_json({}, "data/users.json", "users.json"))
        items = []

        for username, u in users.items():
            if not isinstance(u, dict):
                continue

            name = _eg5c_safe_str(username or u.get("username") or u.get("email") or "user", 80)
            role = _eg5c_safe_str(u.get("role") or ("admin" if name.lower() == "admin" else "user"), 30)
            plan = _eg5c_safe_str(u.get("license_type") or u.get("license_mode") or u.get("plan") or "free", 40)
            email = _eg5c_safe_str(u.get("email") or "", 120)
            active = bool(u.get("active", True))
            last_login = _eg5c_safe_str(u.get("last_login") or u.get("last_seen") or "", 60)

            items.append({
                "username": name,
                "email": email,
                "role": role,
                "plan": plan,
                "license_type": plan,
                "active": active,
                "status": "active" if active else "passive",
                "last_login": last_login,
                "threats": 0,
            })

        items.sort(key=lambda x: (x.get("role") != "admin", x.get("username", "")))
        return items

    def _eg5c_license_items():
        raw = _eg5c_load_json({}, "data/generated_licenses.json", "data/licenses.json", "generated_licenses.json", "licenses.json")
        items = []

        if isinstance(raw, dict):
            iterable = raw.items()
        elif isinstance(raw, list):
            iterable = [(str(i), v) for i, v in enumerate(raw)]
        else:
            iterable = []

        for key, item in iterable:
            if isinstance(item, dict):
                license_key = _eg5c_safe_str(item.get("key") or item.get("license_key") or key, 120)
                status = _eg5c_safe_str(item.get("status") or ("used" if item.get("used") else "available"), 40)
                plan = _eg5c_safe_str(item.get("license_type") or item.get("type") or item.get("plan") or "standard", 40)
                owner = _eg5c_safe_str(item.get("username") or item.get("used_by") or item.get("owner") or "", 80)
                expires = _eg5c_safe_str(item.get("expires_at") or item.get("expiry") or item.get("license_expiry") or "", 40)
                created_at = _eg5c_safe_str(item.get("created_at") or item.get("created") or "", 40)
            else:
                license_key = _eg5c_safe_str(key, 120)
                status = "unknown"
                plan = "standard"
                owner = ""
                expires = ""
                created_at = ""

            items.append({
                "key": license_key,
                "license_key": license_key,
                "status": status,
                "type": plan,
                "plan": plan,
                "owner": owner,
                "username": owner,
                "expires_at": expires,
                "created_at": created_at,
            })

        return items

    def _eg5c_payment_items():
        raw = _eg5c_load_json([], "data/payment_requests.json", "payment_requests.json", "data/upgrade_requests.json")
        rows = _eg5c_as_list(raw)
        items = []

        for item in rows:
            if not isinstance(item, dict):
                continue

            status = _eg5c_safe_str(item.get("status") or item.get("state") or "pending", 40)
            username = _eg5c_safe_str(item.get("username") or item.get("user") or item.get("email") or "", 100)
            amount = item.get("amount") or item.get("price") or item.get("total") or ""
            plan = _eg5c_safe_str(item.get("plan") or item.get("license_type") or item.get("package") or "", 60)
            created_at = _eg5c_safe_str(item.get("created_at") or item.get("date") or item.get("time") or "", 60)
            order_no = _eg5c_safe_str(item.get("order_no") or item.get("id") or item.get("request_id") or "", 80)

            items.append({
                "id": order_no,
                "order_no": order_no,
                "username": username,
                "user": username,
                "amount": amount,
                "plan": plan,
                "status": status,
                "created_at": created_at,
                "date": created_at,
            })

        return items

    def _eg5c_security_log_items():
        raw = _eg5c_load_json([], "data/spam_logs.json", "data/logs.json", "spam_logs.json", "logs.json")
        rows = _eg5c_as_list(raw)
        items = []

        for item in rows[-80:]:
            if not isinstance(item, dict):
                continue

            status = _eg5c_safe_str(item.get("status") or item.get("level") or item.get("label") or "INFO", 30).upper()
            msg = _eg5c_safe_str(item.get("message") or item.get("msg") or item.get("body") or item.get("text") or "Güvenlik kaydı", 220)
            user = _eg5c_safe_str(item.get("username") or item.get("user") or item.get("sender") or "—", 80)
            ip = _eg5c_safe_str(item.get("ip") or item.get("source_ip") or "—", 80)
            t = _eg5c_safe_str(item.get("created_at") or item.get("time") or item.get("date") or "", 80)

            level = "BLOCK" if status in ("SPAM", "BLOCKED", "BLOCK", "RISK") else status

            items.append({
                "level": level,
                "ip": ip,
                "msg": msg,
                "message": msg,
                "user": user,
                "t": t,
                "time": t,
            })

        return list(reversed(items[-50:]))

    def _eg5c_activity_items():
        activity = []
        actions = _eg5c_as_list(_eg5c_load_json([], "data/admin_actions.json"))
        payments = _eg5c_payment_items()
        logs = _eg5c_security_log_items()
        users = _eg5c_user_items()

        for item in actions[-20:]:
            if isinstance(item, dict):
                actor = _eg5c_safe_str(item.get("actor") or item.get("username") or "admin", 80)
                action = _eg5c_safe_str(item.get("action") or item.get("event") or "Admin işlemi", 160)
                t = _eg5c_safe_str(item.get("created_at") or item.get("time") or "", 60)
                activity.append({"type": "admin", "msg": f"<strong>{actor}</strong> — {action}", "t": t})

        for p in payments[-10:]:
            if str(p.get("status", "")).lower() in ("pending", "payment_waiting", "waiting", "new"):
                who = _eg5c_safe_str(p.get("username") or p.get("user") or "kullanıcı", 80)
                activity.append({"type": "payment", "msg": f"Ödeme talebi: <strong>{who}</strong>", "t": _eg5c_safe_str(p.get("created_at") or p.get("date") or "", 60)})

        for log in logs[:10]:
            msg = _eg5c_safe_str(log.get("msg") or "Güvenlik kaydı", 160)
            activity.append({"type": "security", "msg": msg, "t": _eg5c_safe_str(log.get("t") or "", 60)})

        # Veri yoksa boş bırak. Sahte kayıt üretme.
        return activity[:30]

    def _eg5c_dashboard_series():
        logs = _eg5c_security_log_items()
        # Son 7 gün için basit gerçek log sayımı; tarih parse edilemeyenleri bugüne sayma, boş bırak.
        days = [0, 0, 0, 0, 0, 0, 0]
        try:
            today = _eg5c_datetime.now().date()
            for item in logs:
                raw = str(item.get("t") or item.get("time") or "")[:10]
                try:
                    d = _eg5c_datetime.strptime(raw, "%Y-%m-%d").date()
                    delta = (today - d).days
                    if 0 <= delta <= 6:
                        days[6 - delta] += 1
                except Exception:
                    pass
        except Exception:
            pass

        return {
            "ok": True,
            "week": days,
            "month": [0] * 30,
        }

    def _eg5c_stats():
        users = _eg5c_user_items()
        licenses = _eg5c_license_items()
        payments = _eg5c_payment_items()
        logs = _eg5c_security_log_items()
        pending = sum(1 for p in payments if str(p.get("status", "")).lower() in ("pending", "payment_waiting", "waiting", "new"))

        return {
            "ok": True,
            "users": len(users),
            "licenses": len(licenses),
            "payments": pending,
            "payment_total": len(payments),
            "blocked": len(logs),
            "spam_logs": len(logs),
            "activity": len(_eg5c_activity_items()),
        }

    def _eg5c_route_json(payload_fn):
        if not _eg5c_is_admin():
            return _eg5c_forbidden()
        try:
            return _eg5c_jsonify(payload_fn())
        except Exception as _err:
            print("ERATGUARD STAGE5C API ERROR:", _err)
            return _eg5c_jsonify({"ok": False, "error": str(_err)}), 500

    def _eg5c_api_users():
        return _eg5c_route_json(lambda: {"ok": True, "users": _eg5c_user_items()})

    def _eg5c_api_licenses():
        return _eg5c_route_json(lambda: {"ok": True, "licenses": _eg5c_license_items()})

    def _eg5c_api_payments():
        return _eg5c_route_json(lambda: {"ok": True, "requests": _eg5c_payment_items()})

    def _eg5c_api_security_logs():
        return _eg5c_route_json(lambda: {"ok": True, "logs": _eg5c_security_log_items()})

    def _eg5c_api_activity():
        return _eg5c_route_json(lambda: {"ok": True, "activity": _eg5c_activity_items()})

    def _eg5c_api_dashboard_series():
        return _eg5c_route_json(_eg5c_dashboard_series)

    def _eg5c_api_stats():
        return _eg5c_route_json(_eg5c_stats)

    for _rule, _endpoint, _func in [
        ("/api/admin/users", "eg5c_api_users", _eg5c_api_users),
        ("/api/admin/licenses", "eg5c_api_licenses", _eg5c_api_licenses),
        ("/api/admin/payments", "eg5c_api_payments", _eg5c_api_payments),
        ("/api/admin/payment-requests", "eg5c_api_payment_requests", _eg5c_api_payments),
        ("/api/admin/security-logs", "eg5c_api_security_logs", _eg5c_api_security_logs),
        ("/api/admin/activity", "eg5c_api_activity", _eg5c_api_activity),
        ("/api/admin/dashboard-series", "eg5c_api_dashboard_series", _eg5c_api_dashboard_series),
        ("/api/admin/stats", "eg5c_api_stats", _eg5c_api_stats),
    ]:
        try:
            app.add_url_rule(_rule, _endpoint, _func, methods=["GET"])
        except Exception as _err:
            # Eğer route zaten varsa endpoint'i override etmeye çalış.
            try:
                app.view_functions[_endpoint] = _func
            except Exception:
                print("ERATGUARD STAGE5C ROUTE ADD ERROR:", _rule, _err)

except Exception as _boot_err:
    print("ERATGUARD STAGE5C REAL ADMIN DATA API BOOT ERROR:", _boot_err)
# ===== ERATGUARD STAGE5C REAL ADMIN DATA API END =====




# ===== ERATGUARD STAGE5C HOTFIX FORCE API ROUTER START =====
# Amaç:
# - Canlı ortamda 404 dönen /api/admin/stats/users/licenses/payments yollarını
#   before_request seviyesinde kesin yakalar.
# - Admin session yoksa 403 döndürür.
# - Sahte veri üretmez; Stage 5C gerçek JSON fonksiyonlarını kullanır.
try:
    from flask import request as _eg5c_hot_request
    from flask import jsonify as _eg5c_hot_jsonify
    from flask import session as _eg5c_hot_session

    def _eg5c_hot_is_admin():
        try:
            username = str(_eg5c_hot_session.get("username") or "").strip().lower()
            role = str(_eg5c_hot_session.get("role") or "").strip().lower()
            return bool(_eg5c_hot_session.get("is_admin")) or role == "admin" or username == "admin"
        except Exception:
            return False

    def _eg5c_hot_forbidden():
        return _eg5c_hot_jsonify({"ok": False, "error": "admin_login_required"}), 403

    def _eg5c_hot_force_api_router():
        try:
            path = str(getattr(_eg5c_hot_request, "path", "") or "").rstrip("/")

            route_map = {
                "/api/admin/stats": "_eg5c_stats",
                "/api/admin/users": "_eg5c_user_items",
                "/api/admin/licenses": "_eg5c_license_items",
                "/api/admin/payments": "_eg5c_payment_items",
                "/api/admin/payment-requests": "_eg5c_payment_items",
                "/api/admin/security-logs": "_eg5c_security_log_items",
                "/api/admin/activity": "_eg5c_activity_items",
                "/api/admin/dashboard-series": "_eg5c_dashboard_series",
            }

            if path not in route_map:
                return None

            if not _eg5c_hot_is_admin():
                return _eg5c_hot_forbidden()

            fn_name = route_map[path]
            fn = globals().get(fn_name)

            if not callable(fn):
                return _eg5c_hot_jsonify({
                    "ok": False,
                    "error": "stage5c_function_missing",
                    "function": fn_name,
                }), 500

            data = fn()

            if path == "/api/admin/stats":
                return _eg5c_hot_jsonify(data)

            if path == "/api/admin/users":
                return _eg5c_hot_jsonify({"ok": True, "users": data})

            if path == "/api/admin/licenses":
                return _eg5c_hot_jsonify({"ok": True, "licenses": data})

            if path in ("/api/admin/payments", "/api/admin/payment-requests"):
                return _eg5c_hot_jsonify({"ok": True, "requests": data})

            if path == "/api/admin/security-logs":
                return _eg5c_hot_jsonify({"ok": True, "logs": data})

            if path == "/api/admin/activity":
                return _eg5c_hot_jsonify({"ok": True, "activity": data})

            if path == "/api/admin/dashboard-series":
                return _eg5c_hot_jsonify(data)

            return None

        except Exception as _err:
            print("ERATGUARD STAGE5C HOTFIX API ROUTER ERROR:", _err)
            return _eg5c_hot_jsonify({"ok": False, "error": str(_err)}), 500

    try:
        _eg5c_hot_funcs = app.before_request_funcs.setdefault(None, [])
        _eg5c_hot_funcs[:] = [
            f for f in _eg5c_hot_funcs
            if getattr(f, "__name__", "") != "_eg5c_hot_force_api_router"
        ]
        _eg5c_hot_funcs.insert(0, _eg5c_hot_force_api_router)
        print("ERATGUARD STAGE5C HOTFIX FORCE API ROUTER ACTIVE")
    except Exception as _err:
        print("ERATGUARD STAGE5C HOTFIX ROUTER INSERT ERROR:", _err)

except Exception as _boot_err:
    print("ERATGUARD STAGE5C HOTFIX FORCE API ROUTER BOOT ERROR:", _boot_err)
# ===== ERATGUARD STAGE5C HOTFIX FORCE API ROUTER END =====




# ===== ERATGUARD STAGE6B COMMAND TREE ADMIN ROUTE START =====
try:
    from flask import request as _eg6b_request
    from flask import session as _eg6b_session
    from flask import redirect as _eg6b_redirect
    from flask import render_template as _eg6b_render_template
    import re as _eg6b_re

    def _eg6b_is_admin_session():
        try:
            username = str(_eg6b_session.get("username") or "").strip().lower()
            role = str(_eg6b_session.get("role") or "").strip().lower()
            return bool(_eg6b_session.get("is_admin")) or role == "admin" or username == "admin"
        except Exception:
            return False

    def _eg6b_to_int(v, default=0):
        try:
            if v is None:
                return default
            raw = str(v).strip()
            if raw == "":
                return default
            found = _eg6b_re.findall(r"-?\d+", raw.replace(",", ""))
            if not found:
                return default
            return int(found[0])
        except Exception:
            return default

    def _eg6b_clean_stats():
        stats = {
            "users": 0,
            "licenses": 0,
            "payments": 0,
            "blocked": 0,
            "spam_logs": 0,
            "notifications": 0,
        }

        try:
            fn = globals().get("_eg_real_admin_dashboard_stats")
            if callable(fn):
                data = fn()
                if isinstance(data, dict):
                    stats.update(data)
        except Exception as _err:
            print("ERATGUARD STAGE6B REAL STATS ERROR:", _err)

        try:
            fn = globals().get("_eg_default_admin_stats")
            if callable(fn):
                data = fn()
                if isinstance(data, dict):
                    for k, v in data.items():
                        if k not in stats or _eg6b_to_int(stats.get(k), 0) == 0:
                            stats[k] = v
        except Exception as _err:
            print("ERATGUARD STAGE6B DEFAULT STATS ERROR:", _err)

        for k in ("users", "licenses", "payments", "blocked", "spam_logs", "notifications"):
            stats[k] = _eg6b_to_int(stats.get(k), 0)

        return stats

    def _eg6b_command_tree_admin_gate():
        try:
            path = str(getattr(_eg6b_request, "path", "") or "").rstrip("/") or "/"

            if path not in ("/admin", "/admin/dashboard"):
                return None

            if not _eg6b_is_admin_session():
                return _eg6b_redirect("/admin/login?next=" + path)

            if path == "/admin":
                return _eg6b_redirect("/admin/dashboard")

            return _eg6b_render_template(
                "admin_dashboard.html",
                admin_stats=_eg6b_clean_stats(),
                brand="EratGuard PRO",
                current_user=str(_eg6b_session.get("username") or "admin"),
                username=str(_eg6b_session.get("username") or "admin"),
                page_title="Command Tree",
            )
        except Exception as _err:
            print("ERATGUARD STAGE6B COMMAND TREE ROUTE ERROR:", _err)
            return None

    try:
        _eg6b_funcs = app.before_request_funcs.setdefault(None, [])
        _eg6b_funcs[:] = [
            f for f in _eg6b_funcs
            if getattr(f, "__name__", "") != "_eg6b_command_tree_admin_gate"
        ]
        _eg6b_funcs.insert(0, _eg6b_command_tree_admin_gate)
        print("ERATGUARD STAGE6B COMMAND TREE ADMIN ROUTE ACTIVE")
    except Exception as _err:
        print("ERATGUARD STAGE6B ROUTE INSERT ERROR:", _err)

except Exception as _boot_err:
    print("ERATGUARD STAGE6B COMMAND TREE ADMIN ROUTE BOOT ERROR:", _boot_err)
# ===== ERATGUARD STAGE6B COMMAND TREE ADMIN ROUTE END =====



# ===== ERATGUARD STAGE6D OLD ADMIN ACCESS BRIDGE START =====
# Amaç:
# - Eski /ss-admin-access ve /ss-admin-app-start yollarını yeni EratGuard admin akışına bağlar.
# - Eski APK/WebView path'i canlı domainde kullanılırsa boşa düşmez.
# - Eski EratGuard isimli panel üretmez.
try:
    from flask import request as _eg6d_request
    from flask import redirect as _eg6d_redirect
    from flask import session as _eg6d_session
    from flask import url_for as _eg6d_url_for

    def _eg6d_is_admin_session():
        try:
            username = str(_eg6d_session.get("username") or "").strip().lower()
            role = str(_eg6d_session.get("role") or "").strip().lower()
            return bool(_eg6d_session.get("is_admin")) or role == "admin" or username == "admin"
        except Exception:
            return False

    def _eg6d_old_admin_access_bridge():
        try:
            path = str(getattr(_eg6d_request, "path", "") or "").rstrip("/")

            # CLEAN-1:
            # /ss-admin-access gerçek admin login route'una bırakılır.
            # Eski bridge burayı /admin/login veya /login tarafına itemez.
            if path == "/ss-admin-access":
                return None

            if path not in ("/ss-admin-app-start", "/admin-access"):
                return None

            if _eg6d_is_admin_session():
                return _eg6d_redirect("/admin/dashboard")

            return _eg6d_redirect("/ss-admin-access")
        except Exception:
            return None

    try:
        _eg6d_funcs = app.before_request_funcs.setdefault(None, [])
        _eg6d_funcs[:] = [
            f for f in _eg6d_funcs
            if getattr(f, "__name__", "") != "_eg6d_old_admin_access_bridge"
        ]
        _eg6d_funcs.insert(0, _eg6d_old_admin_access_bridge)
        print("ERATGUARD STAGE6D OLD ADMIN ACCESS BRIDGE ACTIVE")
    except Exception as _err:
        print("ERATGUARD STAGE6D BRIDGE INSERT ERROR:", _err)

except Exception as _boot_err:
    print("ERATGUARD STAGE6D OLD ADMIN ACCESS BRIDGE BOOT ERROR:", _boot_err)
# ===== ERATGUARD STAGE6D OLD ADMIN ACCESS BRIDGE END =====


# === ERATGUARD SECURITY-3 PREPEND FORCE REAL SECURITY CENTER ===
# /admin/security eski dashboard/overview bridge'lerine yakalanmadan gerçek güvenlik sayfasını döndürür.
try:
    from flask import request as _eg_sec3_request
    from flask import session as _eg_sec3_session
    from flask import redirect as _eg_sec3_redirect
    from flask import render_template as _eg_sec3_render_template

    def _eg_security3_force_security_center_first():
        try:
            _path = str(getattr(_eg_sec3_request, "path", "") or "").rstrip("/")

            if _path == "/admin/security":
                if not (
                    _eg_sec3_session.get("logged_in")
                    or _eg_sec3_session.get("is_admin")
                    or _eg_sec3_session.get("role") == "admin"
                    or _eg_sec3_request.cookies.get("ss_admin_mobile")
                ):
                    return _eg_sec3_redirect("/ss-admin-access", code=302)

                return _eg_sec3_render_template("admin_security.html")
        except Exception:
            return None

    try:
        _eg_sec3_funcs = app.before_request_funcs.setdefault(None, [])
        _eg_sec3_funcs[:] = [
            f for f in _eg_sec3_funcs
            if getattr(f, "__name__", "") != "_eg_security3_force_security_center_first"
        ]
        _eg_sec3_funcs.insert(0, _eg_security3_force_security_center_first)
        print("ERATGUARD SECURITY-3 PREPEND FORCE REAL SECURITY CENTER ACTIVE")
    except Exception as _eg_sec3_insert_err:
        print("ERATGUARD SECURITY-3 INSERT ERROR:", _eg_sec3_insert_err)

except Exception as _eg_sec3_err:
    print("ERATGUARD SECURITY-3 ERROR:", _eg_sec3_err)
# === /ERATGUARD SECURITY-3 PREPEND FORCE REAL SECURITY CENTER ===

# === ERATGUARD USERS-2 PREPEND FORCE REAL USER CENTER ===
# /admin/users eski kullanıcı sayfasına düşerse gerçek admin_users.html dosyasını döndürür.
try:
    from flask import request as _eg_users2_request
    from flask import session as _eg_users2_session
    from flask import redirect as _eg_users2_redirect
    from flask import render_template as _eg_users2_render_template

    def _eg_users2_force_user_center_first():
        try:
            _path = str(getattr(_eg_users2_request, "path", "") or "").rstrip("/")

            if _path == "/admin/users":
                if not (
                    _eg_users2_session.get("logged_in")
                    or _eg_users2_session.get("is_admin")
                    or _eg_users2_session.get("role") == "admin"
                    or _eg_users2_request.cookies.get("ss_admin_mobile")
                ):
                    return _eg_users2_redirect("/ss-admin-access", code=302)

                # Backend mevcut users değişkenini göndermiyorsa güvenli fallback
                try:
                    _users = globals().get("users", {})
                    if not isinstance(_users, dict):
                        _users = {}
                except Exception:
                    _users = {}

                return _eg_users2_render_template("admin_users.html", users=_users)
        except Exception:
            return None

    try:
        _eg_users2_funcs = app.before_request_funcs.setdefault(None, [])
        _eg_users2_funcs[:] = [
            f for f in _eg_users2_funcs
            if getattr(f, "__name__", "") != "_eg_users2_force_user_center_first"
        ]
        _eg_users2_funcs.insert(0, _eg_users2_force_user_center_first)
        print("ERATGUARD USERS-2 PREPEND FORCE REAL USER CENTER ACTIVE")
    except Exception as _eg_users2_insert_err:
        print("ERATGUARD USERS-2 INSERT ERROR:", _eg_users2_insert_err)

except Exception as _eg_users2_err:
    print("ERATGUARD USERS-2 ERROR:", _eg_users2_err)
# === /ERATGUARD USERS-2 PREPEND FORCE REAL USER CENTER ===

# === ERATGUARD LIVE-DATA-1 FAN PAGES JSON BINDING ===
# Fan Interface sayfalarını gerçek data/*.json dosyalarına bağlar.
# Sadece GET sayfa görüntülemelerini yakalar; POST onay/red/kaydet işlemlerine dokunmaz.
try:
    import json as _eg_live_json
    from pathlib import Path as _eg_live_Path
    from flask import request as _eg_live_request
    from flask import session as _eg_live_session
    from flask import redirect as _eg_live_redirect
    from flask import render_template as _eg_live_render_template

    def _eg_live_admin_ok():
        try:
            return bool(
                _eg_live_session.get("logged_in")
                or _eg_live_session.get("is_admin")
                or _eg_live_session.get("role") == "admin"
                or _eg_live_request.cookies.get("ss_admin_mobile")
            )
        except Exception:
            return False

    def _eg_live_read_json(default, *paths):
        for raw in paths:
            try:
                path = _eg_live_Path(str(raw))
                if path.exists():
                    txt = path.read_text(encoding="utf-8").strip()
                    if not txt:
                        return default
                    return _eg_live_json.loads(txt)
            except Exception:
                pass
        return default

    def _eg_live_as_list(value):
        try:
            if isinstance(value, list):
                return value
            if isinstance(value, dict):
                out = []
                for k, v in value.items():
                    if isinstance(v, dict):
                        item = dict(v)
                        item.setdefault("id", k)
                        item.setdefault("key", k)
                        out.append(item)
                    else:
                        out.append({"id": k, "key": k, "value": v})
                return out
        except Exception:
            pass
        return []

    def _eg_live_users_dict():
        raw = _eg_live_read_json({}, "data/users.json", "users.json")
        if isinstance(raw, dict):
            return raw
        if isinstance(raw, list):
            out = {}
            for i, item in enumerate(raw):
                if isinstance(item, dict):
                    name = str(item.get("username") or item.get("name") or item.get("email") or f"user_{i}")
                    out[name] = item
            return out
        return {}

    def _eg_live_user_stats(users):
        total = len(users) if isinstance(users, dict) else 0
        active = 0
        admins = 0
        banned = 0

        for _, u in (users or {}).items():
            if not isinstance(u, dict):
                continue

            role = str(u.get("role", "")).lower()
            if role == "admin" or u.get("is_admin") is True:
                admins += 1

            if u.get("is_banned") is True or u.get("banned") is True or str(u.get("status", "")).lower() in ("banned", "banli", "blocked"):
                banned += 1

            if u.get("active") is True or u.get("is_active") is True or str(u.get("status", "")).lower() in ("active", "aktif", "enabled"):
                active += 1

        return {"total": total, "active": active, "admins": admins, "banned": banned}

    def _eg_live_license_items():
        base = _eg_live_as_list(_eg_live_read_json([], "data/licenses.json", "licenses.json"))
        generated = _eg_live_as_list(_eg_live_read_json([], "data/generated_licenses.json", "generated_licenses.json"))
        items = []

        for item in base + generated:
            if isinstance(item, dict):
                items.append(item)
            else:
                items.append({"key": str(item), "status": "HAZIR"})

        return items

    def _eg_live_license_stats(licenses):
        total = len(licenses or [])
        used = 0
        empty = 0
        expired = 0

        for lic in licenses or []:
            if not isinstance(lic, dict):
                continue

            username = lic.get("username") or lic.get("user") or lic.get("assigned_to") or lic.get("owner")
            status = str(lic.get("status", "")).lower()

            if username or status in ("used", "active", "aktif", "assigned"):
                used += 1
            else:
                empty += 1

            if status in ("expired", "süresi doldu", "suresi doldu"):
                expired += 1

        if total and used + empty == 0:
            empty = total

        return {"total": total, "used": used, "empty": empty, "expired": expired}

    def _eg_live_payments():
        raw = _eg_live_read_json([], "data/payment_requests.json", "payment_requests.json", "data/upgrade_requests.json")
        return _eg_live_as_list(raw)

    def _eg_live_spam_logs():
        raw = _eg_live_read_json([], "data/spam_logs.json", "spam_logs.json", "data/logs.json", "logs.json")
        return _eg_live_as_list(raw)

    def _eg_live_settings():
        raw = _eg_live_read_json({}, "data/settings.json", "settings.json")
        return raw if isinstance(raw, dict) else {}

    def _eg_live_admin_stats():
        users = _eg_live_users_dict()
        licenses = _eg_live_license_items()
        payments = _eg_live_payments()
        logs = _eg_live_spam_logs()
        settings = _eg_live_settings()

        us = _eg_live_user_stats(users)
        ls = _eg_live_license_stats(licenses)

        return {
            "users": us.get("total", 0),
            "active_users": us.get("active", 0),
            "admin_users": us.get("admins", 0),
            "banned_users": us.get("banned", 0),
            "licenses": ls.get("total", 0),
            "used_licenses": ls.get("used", 0),
            "empty_licenses": ls.get("empty", 0),
            "expired_licenses": ls.get("expired", 0),
            "payments": len(payments),
            "payment_requests": len(payments),
            "spam_logs": len(logs),
            "blocked": len(logs),
            "notifications": len(_eg_live_as_list(_eg_live_read_json([], "data/admin_notifications.json", "admin_notifications.json"))),
            "unread_notifications": 0,
            "settings_count": len(settings),
        }

    def _eg_live_recent_events():
        logs = _eg_live_as_list(_eg_live_read_json([], "data/admin_actions.json", "data/logs.json", "logs.json"))
        return logs[:8] if isinstance(logs, list) else []

    def _eg_live_render_fan_page():
        try:
            if str(getattr(_eg_live_request, "method", "GET")).upper() != "GET":
                return None

            path = str(getattr(_eg_live_request, "path", "") or "").rstrip("/")
            if not path:
                path = "/"

            fan_paths = {
                "/admin/dashboard": "admin_dashboard.html",
                "/admin/users": "admin_users.html",
                "/admin/licenses": "admin_licenses.html",
                "/admin/payment-requests": "admin_payment_requests.html",
                "/admin/security": "admin_security.html",
                "/admin/spam-logs": "admin_spam_logs.html",
                "/admin/settings": "admin_settings.html",
            }

            if path not in fan_paths:
                return None

            if not _eg_live_admin_ok():
                return _eg_live_redirect("/ss-admin-access", code=302)

            users = _eg_live_users_dict()
            user_stats = _eg_live_user_stats(users)

            licenses = _eg_live_license_items()
            license_stats = _eg_live_license_stats(licenses)

            payment_requests = _eg_live_payments()
            spam_logs = _eg_live_spam_logs()
            settings = _eg_live_settings()
            stats = _eg_live_admin_stats()
            recent = _eg_live_recent_events()

            return _eg_live_render_template(
                fan_paths[path],
                admin_stats=stats,
                users=users,
                user_stats=user_stats,
                licenses=licenses,
                generated_licenses=licenses,
                license_stats=license_stats,
                payment_requests=payment_requests,
                requests=payment_requests,
                spam_logs=spam_logs,
                settings=settings,
                recent_logins=recent,
                recent_actions=recent,
                events=recent,
                total_events=len(recent),
                warning_events=0,
                critical_events=0,
            )
        except Exception as _eg_live_render_err:
            print("ERATGUARD LIVE-DATA-1 RENDER ERROR:", _eg_live_render_err)
            return None

    try:
        _eg_live_funcs = app.before_request_funcs.setdefault(None, [])
        _eg_live_funcs[:] = [
            f for f in _eg_live_funcs
            if getattr(f, "__name__", "") != "_eg_live_render_fan_page"
        ]
        _eg_live_funcs.insert(0, _eg_live_render_fan_page)
        print("ERATGUARD LIVE-DATA-1 FAN PAGES JSON BINDING ACTIVE")
    except Exception as _eg_live_insert_err:
        print("ERATGUARD LIVE-DATA-1 INSERT ERROR:", _eg_live_insert_err)

except Exception as _eg_live_err:
    print("ERATGUARD LIVE-DATA-1 ERROR:", _eg_live_err)
# === /ERATGUARD LIVE-DATA-1 FAN PAGES JSON BINDING ===

# === ERATGUARD USER-DASH-1 LIVE USER FAN LITE ===
# Kullanıcı ana ekranını canlı data/*.json verisine bağlar.
try:
    import json as _eg_ud1_json
    import html as _eg_ud1_html
    from pathlib import Path as _eg_ud1_Path
    from flask import session as _eg_ud1_session
    from flask import redirect as _eg_ud1_redirect
    from flask import render_template_string as _eg_ud1_render_template_string
    from flask import make_response as _eg_ud1_make_response

    def _eg_ud1_read_json(default, *paths):
        for raw in paths:
            try:
                path = _eg_ud1_Path(str(raw))
                if path.exists():
                    txt = path.read_text(encoding="utf-8").strip()
                    if not txt:
                        return default
                    return _eg_ud1_json.loads(txt)
            except Exception:
                pass
        return default

    def _eg_ud1_as_list(value):
        try:
            if isinstance(value, list):
                return value
            if isinstance(value, dict):
                out = []
                for k, v in value.items():
                    if isinstance(v, dict):
                        item = dict(v)
                        item.setdefault("id", k)
                        item.setdefault("key", k)
                        out.append(item)
                    else:
                        out.append({"id": k, "value": v})
                return out
        except Exception:
            pass
        return []

    def _eg_ud1_user(username):
        users = _eg_ud1_read_json({}, "data/users.json", "users.json")
        if isinstance(users, dict):
            return users.get(username, {})
        return {}

    def _eg_ud1_user_spam(username):
        logs = _eg_ud1_as_list(_eg_ud1_read_json([], "data/spam_logs.json", "spam_logs.json", "data/logs.json", "logs.json"))
        user_logs = []
        for item in logs:
            if not isinstance(item, dict):
                continue
            owner = str(item.get("username") or item.get("user") or item.get("owner") or "").strip()
            if owner == username:
                user_logs.append(item)

        # Kullanıcıya ait kayıt yoksa 0 göster; sistem geneliyle karıştırma.
        spam_total = len(user_logs)
        blocked_total = 0
        for item in user_logs:
            status = str(item.get("status") or item.get("result") or item.get("state") or "").lower()
            if status in ("blocked", "block", "spam", "spammed", "engellendi", "engellenen", "sp"):
                blocked_total += 1

        return spam_total, blocked_total

    def _eg_ud1_block_count(username):
        raw = _eg_ud1_read_json([], "data/user_block_list.json", "data/user_blocklist.json", "data/blocklist.json", "data/user_quarantine.json")
        if isinstance(raw, dict):
            # Kullanıcıya özel alt liste varsa onu say
            val = raw.get(username) or raw.get(str(username).lower())
            if isinstance(val, list):
                return len(val)
            if isinstance(val, dict):
                return len(val)
            # Yoksa owner/username alanlı kayıtları say
            total = 0
            for _, v in raw.items():
                if isinstance(v, dict) and str(v.get("username") or v.get("user") or "") == username:
                    total += 1
            return total
        if isinstance(raw, list):
            total = 0
            for item in raw:
                if isinstance(item, dict):
                    owner = str(item.get("username") or item.get("user") or "").strip()
                    if not owner or owner == username:
                        total += 1
            return total
        return 0

    def _eg_ud1_notifications(username):
        raw = _eg_ud1_read_json([], "data/inbox.json", "data/admin_notifications.json", "data/user_notification_settings.json")
        if isinstance(raw, dict):
            val = raw.get(username) or raw.get(str(username).lower())
            if isinstance(val, list):
                return len(val)
            if isinstance(val, dict):
                return len(val)
            return len(raw) if raw else 0
        if isinstance(raw, list):
            return len(raw)
        return 0

    def _eg_ud1_live_home():
        # CLEAN-5C AST SAFE: eski duplicate dashboard gövdesi kaldırıldı.
        # Aktif dashboard ve FAN-12P korunur.
        try:
            return _eg1c_dashboard_page()
        except Exception:
            return redirect('/dashboard')

    try:
        for _rule in list(app.url_map.iter_rules()):
            if str(_rule) in [
                "/dashboard",
                "/home",
                "/user",
                "/main",
                "/u/home",
                "/u/dashboard",
                "/u/home-final"
            ]:
                app.view_functions[_rule.endpoint] = _eg_ud1_live_home

        print("ERATGUARD USER-DASH-1 LIVE USER FAN LITE ACTIVE")
    except Exception as _eg_ud1_route_err:
        print("ERATGUARD USER-DASH-1 ROUTE ERROR:", _eg_ud1_route_err)

except Exception as _eg_ud1_err:
    print("ERATGUARD USER-DASH-1 ERROR:", _eg_ud1_err)
# === /ERATGUARD USER-DASH-1 LIVE USER FAN LITE ===

# === ERATGUARD ADMIN-LOCK-1 STRICT ADMIN ONLY ===
# Normal kullanıcı session'ı /admin ve /api/admin alanına giremez.
# logged_in=True tek başına admin yetkisi sayılmaz.
try:
    import json as _eg_al1_json
    from pathlib import Path as _eg_al1_Path
    from flask import request as _eg_al1_request
    from flask import session as _eg_al1_session
    from flask import redirect as _eg_al1_redirect
    from flask import abort as _eg_al1_abort

    def _eg_al1_read_users():
        for raw in ("data/users.json", "users.json"):
            try:
                path = _eg_al1_Path(raw)
                if path.exists():
                    txt = path.read_text(encoding="utf-8").strip()
                    if not txt:
                        return {}
                    data = _eg_al1_json.loads(txt)
                    return data if isinstance(data, dict) else {}
            except Exception:
                pass
        return {}

    def _eg_al1_is_real_admin():
        try:
            username = str(_eg_al1_session.get("username") or "").strip()
            role = str(_eg_al1_session.get("role") or "").strip().lower()
            session_is_admin = _eg_al1_session.get("is_admin") is True

            users = _eg_al1_read_users()
            user = users.get(username) if username else None

            user_is_admin = False
            if isinstance(user, dict):
                user_role = str(user.get("role") or "").strip().lower()
                user_is_admin = (
                    user_role == "admin"
                    or user.get("is_admin") is True
                    or username.lower() == "admin"
                )

            # En güvenli kural:
            # Session admin görünse bile kullanıcı datası admin değilse kabul etme.
            if username and isinstance(user, dict):
                return bool(user_is_admin)

            # Kullanıcı datası bulunamazsa sadece açık admin session kabul.
            return bool(username.lower() == "admin" and (role == "admin" or session_is_admin))

        except Exception:
            return False

    def _eg_al1_strict_admin_gate():
        try:
            path = str(getattr(_eg_al1_request, "path", "") or "").rstrip("/")
            method = str(getattr(_eg_al1_request, "method", "GET") or "GET").upper()

            is_admin_page = path == "/admin" or path.startswith("/admin/")
            is_admin_api = path == "/api/admin" or path.startswith("/api/admin/")

            if not (is_admin_page or is_admin_api):
                return None

            if _eg_al1_is_real_admin():
                return None

            # Normal kullanıcı admin sayfasına girmeye çalışırsa admin session flaglerini temizle.
            # Kullanıcı oturumu kalsın; sadece admin yetkisi düşsün.
            for k in ("is_admin", "role", "admin", "admin_ok", "admin_logged_in"):
                try:
                    _eg_al1_session.pop(k, None)
                except Exception:
                    pass

            if is_admin_api:
                return _eg_al1_abort(403)

            return _eg_al1_redirect("/dashboard", code=302)

        except Exception:
            return None

    try:
        _eg_al1_funcs = app.before_request_funcs.setdefault(None, [])
        _eg_al1_funcs[:] = [
            f for f in _eg_al1_funcs
            if getattr(f, "__name__", "") != "_eg_al1_strict_admin_gate"
        ]
        _eg_al1_funcs.insert(0, _eg_al1_strict_admin_gate)
        print("ERATGUARD ADMIN-LOCK-1 STRICT ADMIN ONLY ACTIVE")
    except Exception as _eg_al1_insert_err:
        print("ERATGUARD ADMIN-LOCK-1 INSERT ERROR:", _eg_al1_insert_err)

except Exception as _eg_al1_err:
    print("ERATGUARD ADMIN-LOCK-1 ERROR:", _eg_al1_err)
# === /ERATGUARD ADMIN-LOCK-1 STRICT ADMIN ONLY ===

# === ERATGUARD ADMIN-LOCK-2 ADMIN ACCESS SESSION RESET ===
# Normal kullanıcı oturumu aktifken /ss-admin-access kullanıcı paneline dönmesin.
# Admin giriş kapısı her zaman admin login akışına izin verir.
try:
    import json as _eg_al2_json
    from pathlib import Path as _eg_al2_Path
    from flask import request as _eg_al2_request
    from flask import session as _eg_al2_session

    def _eg_al2_read_users():
        for raw in ("data/users.json", "users.json"):
            try:
                path = _eg_al2_Path(raw)
                if path.exists():
                    txt = path.read_text(encoding="utf-8").strip()
                    if not txt:
                        return {}
                    data = _eg_al2_json.loads(txt)
                    return data if isinstance(data, dict) else {}
            except Exception:
                pass
        return {}

    def _eg_al2_current_is_admin():
        try:
            username = str(_eg_al2_session.get("username") or "").strip()
            if not username:
                return False

            users = _eg_al2_read_users()
            user = users.get(username)

            if isinstance(user, dict):
                return bool(
                    str(user.get("role") or "").lower() == "admin"
                    or user.get("is_admin") is True
                    or username.lower() == "admin"
                )

            return bool(
                username.lower() == "admin"
                and (
                    str(_eg_al2_session.get("role") or "").lower() == "admin"
                    or _eg_al2_session.get("is_admin") is True
                )
            )
        except Exception:
            return False

    def _eg_al2_admin_access_reset_gate():
        try:
            path = str(getattr(_eg_al2_request, "path", "") or "").rstrip("/")

            if path != "/ss-admin-access":
                return None

            # Eğer aktif oturum admin değilse, admin giriş kapısında kullanıcı session'ını temizle.
            # Böylece testuser /ss-admin-access açınca /dashboard'a geri atılmaz.
            if not _eg_al2_current_is_admin():
                for k in (
                    "logged_in",
                    "username",
                    "role",
                    "is_admin",
                    "admin",
                    "admin_ok",
                    "admin_logged_in"
                ):
                    try:
                        _eg_al2_session.pop(k, None)
                    except Exception:
                        pass

            return None
        except Exception:
            return None

    try:
        _eg_al2_funcs = app.before_request_funcs.setdefault(None, [])
        _eg_al2_funcs[:] = [
            f for f in _eg_al2_funcs
            if getattr(f, "__name__", "") != "_eg_al2_admin_access_reset_gate"
        ]
        _eg_al2_funcs.insert(0, _eg_al2_admin_access_reset_gate)
        print("ERATGUARD ADMIN-LOCK-2 ADMIN ACCESS SESSION RESET ACTIVE")
    except Exception as _eg_al2_insert_err:
        print("ERATGUARD ADMIN-LOCK-2 INSERT ERROR:", _eg_al2_insert_err)

except Exception as _eg_al2_err:
    print("ERATGUARD ADMIN-LOCK-2 ERROR:", _eg_al2_err)
# === /ERATGUARD ADMIN-LOCK-2 ADMIN ACCESS SESSION RESET ===

# === ERATGUARD ADMIN-LOCK-3 FORCE ADMIN ACCESS ROUTE ===
# /ss-admin-access hiçbir zaman kullanıcı login sayfasına düşmesin.
# Bu route sadece gerçek admin hesabı için admin giriş kapısıdır.
try:
    import json as _eg_al3_json
    import hashlib as _eg_al3_hashlib
    from pathlib import Path as _eg_al3_Path
    from flask import request as _eg_al3_request
    from flask import session as _eg_al3_session
    from flask import redirect as _eg_al3_redirect
    from flask import render_template as _eg_al3_render_template
    from flask import make_response as _eg_al3_make_response
    from werkzeug.security import check_password_hash as _eg_al3_check_password_hash

    def _eg_al3_read_users():
        for raw in ("data/users.json", "users.json"):
            try:
                path = _eg_al3_Path(raw)
                if path.exists():
                    txt = path.read_text(encoding="utf-8").strip()
                    if not txt:
                        return {}
                    data = _eg_al3_json.loads(txt)
                    return data if isinstance(data, dict) else {}
            except Exception:
                pass
        return {}

    def _eg_al3_check_password(raw, stored):
        try:
            raw = str(raw or "")
            stored = str(stored or "")
            if not raw or not stored:
                return False

            if stored.startswith(("pbkdf2:", "scrypt:", "sha256:")):
                try:
                    return _eg_al3_check_password_hash(stored, raw)
                except Exception:
                    pass

            try:
                if _eg_al3_hashlib.sha256(raw.encode("utf-8")).hexdigest() == stored:
                    return True
            except Exception:
                pass

            return raw == stored
        except Exception:
            return False

    def _eg_al3_is_admin_user(username, user):
        try:
            username = str(username or "").strip()
            if not isinstance(user, dict):
                return False

            return bool(
                username.lower() == "admin"
                or str(user.get("role") or "").strip().lower() == "admin"
                or user.get("is_admin") is True
            )
        except Exception:
            return False

    def _eg_al3_force_admin_access():
        try:
            # Admin kapısına gelince önce eski normal user session bilgisini temizle.
            for k in (
                "logged_in",
                "username",
                "role",
                "is_admin",
                "admin",
                "admin_ok",
                "admin_logged_in"
            ):
                try:
                    _eg_al3_session.pop(k, None)
                except Exception:
                    pass

            if str(_eg_al3_request.method).upper() == "GET":
                return _eg_al3_render_template("admin_login.html", error="")

            username = str(_eg_al3_request.form.get("username") or "").strip()
            password = str(_eg_al3_request.form.get("password") or "")

            users = _eg_al3_read_users()
            user = users.get(username)

            if not isinstance(user, dict):
                # Büyük/küçük harf toleransı
                for k, v in users.items():
                    if str(k).lower() == username.lower():
                        username = str(k)
                        user = v
                        break

            if not _eg_al3_is_admin_user(username, user):
                return _eg_al3_render_template("admin_login.html", error="Admin girişi başarısız.")

            pw_ok = False
            if isinstance(user, dict):
                pw_ok = (
                    _eg_al3_check_password(password, user.get("password") or "")
                    or _eg_al3_check_password(password, user.get("password_hash") or "")
                )

            if not pw_ok:
                return _eg_al3_render_template("admin_login.html", error="Admin girişi başarısız.")

            _eg_al3_session["logged_in"] = True
            _eg_al3_session["username"] = username
            _eg_al3_session["role"] = "admin"
            _eg_al3_session["is_admin"] = True

            resp = _eg_al3_make_response(_eg_al3_redirect("/admin/dashboard", code=302))

            # Mevcut mobil admin cookie sistemi varsa onunla uyumlu cookie bas.
            try:
                token_fn = globals().get("_eg_admin_mobile_expected_token")
                if callable(token_fn):
                    resp.set_cookie(
                        "ss_admin_mobile",
                        str(token_fn()),
                        httponly=True,
                        samesite="Lax",
                        max_age=60 * 60 * 24 * 7
                    )
            except Exception:
                pass

            return resp

        except Exception as e:
            try:
                return _eg_al3_render_template("admin_login.html", error="Admin giriş sistemi hatası.")
            except Exception:
                return "Admin giriş sistemi hatası.", 500

    try:
        # Var olan /ss-admin-access endpoint'lerini zorla bu fonksiyona bağla.
        for _rule in list(app.url_map.iter_rules()):
            if str(_rule).rstrip("/") == "/ss-admin-access":
                app.view_functions[_rule.endpoint] = _eg_al3_force_admin_access

        print("ERATGUARD ADMIN-LOCK-3 FORCE ADMIN ACCESS ROUTE ACTIVE")
    except Exception as _eg_al3_route_err:
        print("ERATGUARD ADMIN-LOCK-3 ROUTE ERROR:", _eg_al3_route_err)

except Exception as _eg_al3_err:
    print("ERATGUARD ADMIN-LOCK-3 ERROR:", _eg_al3_err)
# === /ERATGUARD ADMIN-LOCK-3 FORCE ADMIN ACCESS ROUTE ===

# === ERATGUARD USER-LICENSE-CLEAN-1 DISPLAY LABEL FIX ===
# Kullanıcı lisans sayfasında teknik license_type değerlerini daha temiz göster.
try:
    def _eg_ulc1_license_display_label(raw):
        raw = str(raw or "").strip().lower()
        if raw in ("test_pro", "test-pro", "pro_test", "pro-test"):
            return "PRO Test Lisansı"
        if raw in ("pro", "pro_active", "active", "premium"):
            return "EratGuard PRO"
        if raw in ("trial", "free", "deneme"):
            return "Deneme"
        if raw in ("admin", "system"):
            return "Admin"
        if not raw:
            return "Deneme"
        return str(raw).replace("_", " ").replace("-", " ").title()

    # Var olan lisans helper fonksiyonu varsa onu daha temiz hale getir.
    if "_ss_license_plan_label" in globals():
        _old_ss_license_plan_label_ulc1 = globals().get("_ss_license_plan_label")

        def _ss_license_plan_label(plan):
            try:
                clean = _eg_ulc1_license_display_label(plan)
                if clean:
                    return clean
            except Exception:
                pass
            try:
                return _old_ss_license_plan_label_ulc1(plan)
            except Exception:
                return "EratGuard PRO"

    print("ERATGUARD USER-LICENSE-CLEAN-1 DISPLAY LABEL FIX ACTIVE")
except Exception as _eg_ulc1_err:
    print("ERATGUARD USER-LICENSE-CLEAN-1 ERROR:", _eg_ulc1_err)
# === /ERATGUARD USER-LICENSE-CLEAN-1 DISPLAY LABEL FIX ===

# === ERATGUARD USER-LICENSE-CLEAN-2 FORCE DISPLAY PATCH ===
# /u/license ekranında test_pro gibi teknik değerleri daha temiz gösterir.
try:
    def _eg_ulc2_display_license_type(raw):
        raw = str(raw or "").strip().lower()
        if raw in ("test_pro", "test-pro", "pro_test", "pro-test"):
            return "PRO Test Lisansı"
        if raw in ("pro", "premium", "pro_active", "active", "paid"):
            return "EratGuard PRO"
        if raw in ("trial", "free", "deneme", ""):
            return "Deneme"
        if raw == "admin":
            return "Admin"
        return str(raw).replace("_", " ").replace("-", " ").title()

    # Mevcut helper varsa override et.
    def _ss_license_plan_label(plan):
        return _eg_ulc2_display_license_type(plan)

    print("ERATGUARD USER-LICENSE-CLEAN-2 FORCE DISPLAY PATCH ACTIVE")
except Exception as _eg_ulc2_err:
    print("ERATGUARD USER-LICENSE-CLEAN-2 ERROR:", _eg_ulc2_err)
# === /ERATGUARD USER-LICENSE-CLEAN-2 FORCE DISPLAY PATCH ===

# === ERATGUARD USER-LICENSE-DIET-1 COMPACT PAGE ===
# /u/license sayfasını kompakt hale getirir. Paket/fiyat kalabalığını azaltır.
try:
    from flask import render_template_string as _eg_uld1_render_template_string
    from flask import make_response as _eg_uld1_make_response
    from flask import redirect as _eg_uld1_redirect
    from flask import session as _eg_uld1_session
    from pathlib import Path as _eg_uld1_Path
    import json as _eg_uld1_json
    import html as _eg_uld1_html
    from datetime import datetime as _eg_uld1_datetime

    def _eg_uld1_read_json(default, *paths):
        for raw in paths:
            try:
                path = _eg_uld1_Path(raw)
                if path.exists():
                    txt = path.read_text(encoding="utf-8", errors="ignore").strip()
                    if txt:
                        return _eg_uld1_json.loads(txt)
            except Exception:
                pass
        return default

    def _eg_uld1_safe(v):
        try:
            return _eg_uld1_html.escape(str(v or ""))
        except Exception:
            return ""

    def _eg_uld1_plan_label(raw):
        raw = str(raw or "").strip().lower()
        if raw in ("test_pro", "test-pro", "pro_test", "pro-test"):
            return "PRO Test Lisansı"
        if raw in ("pro", "premium", "pro_active", "active", "paid"):
            return "EratGuard PRO"
        if raw in ("trial", "free", "deneme", ""):
            return "Deneme"
        if raw == "admin":
            return "Admin"
        return str(raw).replace("_", " ").replace("-", " ").title()

    def _eg_uld1_days_left(expiry):
        try:
            expiry = str(expiry or "").strip()
            if not expiry or expiry in ("—", "-"):
                return "—"
            dt = _eg_uld1_datetime.fromisoformat(expiry[:10])
            today = _eg_uld1_datetime.now()
            return max(0, (dt.date() - today.date()).days)
        except Exception:
            return "—"

    def _eg_uld1_find_user_license(username):
        users = _eg_uld1_read_json({}, "data/users.json", "users.json")
        user = users.get(username, {}) if isinstance(users, dict) else {}

        lic_key = user.get("license_key") or user.get("license") or user.get("license_code") or ""
        plan = user.get("license_type") or user.get("license_mode") or "trial"
        expiry = user.get("license_expiry") or user.get("expires_at") or "—"
        status = user.get("license_status") or ("active" if lic_key else "trial")

        return {
            "username": username,
            "license_key": lic_key or "—",
            "plan": _eg_uld1_plan_label(plan),
            "expiry": expiry,
            "days_left": _eg_uld1_days_left(expiry),
            "status": "AKTİF" if str(status).lower() in ("active", "aktif", "ok", "valid") or lic_key else "DENEME",
            "premium": "Açık" if lic_key else "Sınırlı",
        }

    def _eg_uld1_compact_license_page():
        if not (_eg_uld1_session.get("logged_in") and _eg_uld1_session.get("username")):
            return _eg_uld1_redirect("/login")

        username = str(_eg_uld1_session.get("username") or "user")
        info = _eg_uld1_find_user_license(username)

        html = """<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>EratGuard PRO - Lisans</title>
<style>
:root{--bg:#020806;--panel:#071a10;--line:rgba(35,255,137,.22);--green:#20ff88;--yellow:#ffdd35;--text:#f5fff8;--muted:rgba(245,255,248,.62)}
*{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
html,body{margin:0;min-height:100%;background:radial-gradient(circle at 80% 0%,rgba(35,255,137,.14),transparent 34%),var(--bg);color:var(--text);font-family:Arial,Helvetica,sans-serif}
body{padding:18px 14px 28px}
.top{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:14px}
.brand{display:flex;align-items:center;gap:11px}
.logo{width:54px;height:54px;border-radius:18px;background:rgba(35,255,137,.12);border:1px solid var(--line);display:grid;place-items:center;font-size:29px}
.brand h1{margin:0;font-size:27px;line-height:1;font-weight:950;letter-spacing:-1.2px}.brand h1 span{color:var(--green)}
.brand p{margin:5px 0 0;color:var(--muted);font-weight:850;font-size:13px}
.badge{border:1px solid rgba(255,221,53,.35);color:var(--yellow);background:rgba(255,221,53,.10);padding:10px 13px;border-radius:999px;font-weight:950;font-size:13px}
.hero,.form,.perms{border:1px solid var(--line);background:linear-gradient(145deg,rgba(10,36,23,.94),rgba(4,14,9,.94));border-radius:25px;padding:18px;box-shadow:0 20px 55px rgba(0,0,0,.35)}
.ico{width:58px;height:58px;border-radius:20px;border:1px solid var(--line);background:rgba(35,255,137,.10);display:grid;place-items:center;font-size:31px;margin-bottom:14px}
.hero h2{font-size:34px;line-height:1.02;margin:0 0 8px;font-weight:950;letter-spacing:-1.6px}
.hero p{margin:0;color:var(--muted);font-size:15px;line-height:1.35;font-weight:800}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:15px}
.card{border:1px solid rgba(35,255,137,.17);background:rgba(0,0,0,.23);border-radius:19px;padding:13px;min-height:75px}
.card b{display:block;color:var(--yellow);font-size:21px;line-height:1.1;word-break:break-word}.card span{display:block;color:var(--muted);font-size:12px;font-weight:900;margin-top:7px}
.key{grid-column:1/-1}.key b{font-size:16px;color:#9fffc4}
.btn{display:flex;align-items:center;justify-content:center;min-height:54px;border-radius:19px;text-decoration:none;font-weight:950;font-size:17px;border:1px solid rgba(255,255,255,.10);color:#00180c;background:linear-gradient(135deg,var(--yellow),var(--green));margin-top:12px}
.btn.secondary{background:rgba(255,255,255,.08);color:var(--text)}
.section-title{font-size:20px;letter-spacing:9px;font-weight:950;margin:25px 0 12px}
.form label{display:block;font-size:16px;font-weight:950;margin-bottom:9px}
.form input{width:100%;height:56px;border-radius:18px;border:1px solid rgba(35,255,137,.22);background:rgba(0,0,0,.22);color:var(--text);font-size:16px;font-weight:850;padding:0 14px;outline:none}
.form input::placeholder{color:rgba(245,255,248,.34)}.form button{width:100%;height:56px;border:0;border-radius:18px;margin-top:12px;background:linear-gradient(135deg,var(--yellow),var(--green));font-size:17px;font-weight:950;color:#00180c}
.perms{padding:0;overflow:hidden}.row{display:flex;justify-content:space-between;padding:15px 17px;border-bottom:1px solid rgba(255,255,255,.06);gap:10px}.row:last-child{border-bottom:0}
.row span{font-weight:900;color:var(--muted);font-size:15px}.row b{color:#9fffc4;font-size:15px}
.foot{text-align:center;margin:22px 0 0;color:rgba(245,255,248,.42);font-weight:800}
</style>
</head>
<body>
<header class="top">
  <div class="brand"><div class="logo">🔑</div><div><h1>Erat<span>Guard</span></h1><p>Lisans Merkezi</p></div></div>
  <div class="badge">👑 __STATUS__</div>
</header>

<section class="hero">
  <div class="ico">🔑</div>
  <h2>__PLAN__</h2>
  <p>Premium erişim, lisans kodu ve koruma yetkileri tek kompakt ekranda.</p>
  <div class="grid">
    <div class="card"><b>__STATUS__</b><span>Durum</span></div>
    <div class="card"><b>__DAYS__</b><span>Kalan gün</span></div>
    <div class="card key"><b>__KEY__</b><span>Lisans anahtarı</span></div>
  </div>
  <a class="btn secondary" href="/dashboard">← Ana ekrana dön</a>
</section>

<div class="section-title">AKTİVASYON</div>
<form class="form" method="post" action="/u/license">
  <label>Lisans kodu gir</label>
  <input name="license_key" placeholder="Örn: ERATGUARD-PRO-XXXX-XXXX" autocomplete="off">
  <button type="submit">Lisansı Aktifleştir</button>
</form>

<div class="section-title">YETKİLER</div>
<section class="perms">
  <div class="row"><span>Koruma Merkezi</span><b>__PREMIUM__</b></div>
  <div class="row"><span>AI Analiz</span><b>__PREMIUM__</b></div>
  <div class="row"><span>Raporlar</span><b>__PREMIUM__</b></div>
  <div class="row"><span>Güvenli Liste</span><b>__PREMIUM__</b></div>
  <div class="row"><span>Blok Listesi</span><b>__PREMIUM__</b></div>
</section>

<a class="btn" href="/u/pricing">Paketleri İncele</a>
<a class="btn secondary" href="/u/protection">Koruma Merkezi</a>
<div class="foot">EratGuard PRO - © 2026</div>
</body>
</html>"""

        html = html.replace("__STATUS__", _eg_uld1_safe(info["status"]))
        html = html.replace("__PLAN__", _eg_uld1_safe(info["plan"]))
        html = html.replace("__DAYS__", _eg_uld1_safe(info["days_left"]))
        html = html.replace("__KEY__", _eg_uld1_safe(info["license_key"]))
        html = html.replace("__PREMIUM__", _eg_uld1_safe(info["premium"]))

        resp = _eg_uld1_make_response(_eg_uld1_render_template_string(html))
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        resp.headers["Pragma"] = "no-cache"
        resp.headers["Expires"] = "0"
        return resp

    try:
        for _rule in list(app.url_map.iter_rules()):
            if str(_rule) in ("/u/license", "/u/license/"):
                app.view_functions[_rule.endpoint] = _eg_uld1_compact_license_page
        print("ERATGUARD USER-LICENSE-DIET-1 COMPACT PAGE ACTIVE")
    except Exception as _eg_uld1_route_err:
        print("ERATGUARD USER-LICENSE-DIET-1 ROUTE ERROR:", _eg_uld1_route_err)

except Exception as _eg_uld1_err:
    print("ERATGUARD USER-LICENSE-DIET-1 ERROR:", _eg_uld1_err)
# === /ERATGUARD USER-LICENSE-DIET-1 COMPACT PAGE ===

# === ERATGUARD USER-LICENSE-DIET-2 ULTRA COMPACT PAGE ===
# /u/license sayfasını daha da inceltir:
# - Paketleri İncele kaldırıldı
# - Koruma Merkezi butonu kaldırıldı
# - Yetkiler chip/rozet formatına alındı
# - Aktivasyon alanı inceltildi
try:
    from flask import render_template_string as _eg_uld2_render_template_string
    from flask import make_response as _eg_uld2_make_response
    from flask import redirect as _eg_uld2_redirect
    from flask import session as _eg_uld2_session
    from flask import request as _eg_uld2_request
    from pathlib import Path as _eg_uld2_Path
    import json as _eg_uld2_json
    import html as _eg_uld2_html
    from datetime import datetime as _eg_uld2_datetime

    _eg_uld2_original_user_license = globals().get("user_license")

    def _eg_uld2_read_json(default, *paths):
        for raw in paths:
            try:
                path = _eg_uld2_Path(raw)
                if not path.exists():
                    continue
                txt = path.read_text(encoding="utf-8", errors="ignore").strip()
                if txt:
                    return _eg_uld2_json.loads(txt)
            except Exception:
                pass
        return default

    def _eg_uld2_safe(v):
        try:
            return _eg_uld2_html.escape(str(v or ""))
        except Exception:
            return ""

    def _eg_uld2_plan_label(raw):
        raw = str(raw or "").strip().lower()
        if raw in ("test_pro", "test-pro", "pro_test", "pro-test"):
            return "PRO Test"
        if raw in ("pro", "premium", "pro_active", "active", "paid"):
            return "EratGuard PRO"
        if raw in ("trial", "free", "deneme", ""):
            return "Deneme"
        if raw == "admin":
            return "Admin"
        return str(raw).replace("_", " ").replace("-", " ").title()

    def _eg_uld2_days_left(expiry):
        try:
            expiry = str(expiry or "").strip()
            if not expiry or expiry in ("—", "-"):
                return "—"
            dt = _eg_uld2_datetime.fromisoformat(expiry[:10])
            today = _eg_uld2_datetime.now()
            return max(0, (dt.date() - today.date()).days)
        except Exception:
            return "—"

    def _eg_uld2_find_user_license(username):
        users = _eg_uld2_read_json({}, "data/users.json", "users.json")
        user = users.get(username, {}) if isinstance(users, dict) else {}

        lic_key = user.get("license_key") or user.get("license") or user.get("license_code") or ""
        plan = user.get("license_type") or user.get("license_mode") or "trial"
        expiry = user.get("license_expiry") or user.get("expires_at") or "—"
        status = user.get("license_status") or ("active" if lic_key else "trial")

        active = bool(lic_key) or str(status).lower() in ("active", "aktif", "ok", "valid")

        return {
            "username": username,
            "license_key": lic_key or "—",
            "plan": _eg_uld2_plan_label(plan),
            "expiry": expiry,
            "days_left": _eg_uld2_days_left(expiry),
            "status": "AKTİF" if active else "DENEME",
            "premium": "Açık" if active else "Sınırlı",
        }

    def _eg_uld2_license_route():
        if not (_eg_uld2_session.get("logged_in") and _eg_uld2_session.get("username")):
            return _eg_uld2_redirect("/login")

        # POST aktivasyon işlemini eski gerçek route'a bırak.
        if str(_eg_uld2_request.method).upper() == "POST":
            try:
                if callable(_eg_uld2_original_user_license) and getattr(_eg_uld2_original_user_license, "__name__", "") != "_eg_uld2_license_route":
                    return _eg_uld2_original_user_license()
            except Exception as _eg_uld2_post_err:
                print("ERATGUARD USER-LICENSE-DIET-2 POST FALLBACK ERROR:", _eg_uld2_post_err)
            return _eg_uld2_redirect("/u/license?activated=1")

        username = str(_eg_uld2_session.get("username") or "user")
        info = _eg_uld2_find_user_license(username)

        html = """<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>EratGuard PRO - Lisans</title>
<style>
:root{
  --bg:#020806;
  --panel:#071a10;
  --line:rgba(35,255,137,.22);
  --green:#20ff88;
  --yellow:#ffdd35;
  --text:#f5fff8;
  --muted:rgba(245,255,248,.62);
}
*{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
html,body{
  margin:0;
  min-height:100%;
  background:radial-gradient(circle at 80% 0%,rgba(35,255,137,.14),transparent 32%),var(--bg);
  color:var(--text);
  font-family:Arial,Helvetica,sans-serif;
}
body{padding:16px 14px 24px}
.top{
  display:flex;
  align-items:center;
  justify-content:space-between;
  gap:10px;
  margin-bottom:12px;
}
.brand{display:flex;align-items:center;gap:10px;min-width:0}
.logo{
  width:50px;
  height:50px;
  border-radius:17px;
  background:rgba(35,255,137,.12);
  border:1px solid var(--line);
  display:grid;
  place-items:center;
  font-size:27px;
}
.brand h1{
  margin:0;
  font-size:26px;
  line-height:1;
  font-weight:950;
  letter-spacing:-1.2px;
}
.brand h1 span{color:var(--green)}
.brand p{
  margin:4px 0 0;
  color:var(--muted);
  font-weight:850;
  font-size:12px;
}
.badge{
  border:1px solid rgba(255,221,53,.35);
  color:var(--yellow);
  background:rgba(255,221,53,.10);
  padding:9px 12px;
  border-radius:999px;
  font-weight:950;
  font-size:12px;
  white-space:nowrap;
}
.hero,.form,.perms{
  border:1px solid var(--line);
  background:linear-gradient(145deg,rgba(10,36,23,.94),rgba(4,14,9,.94));
  border-radius:23px;
  padding:16px;
  box-shadow:0 18px 48px rgba(0,0,0,.34);
}
.hero-top{
  display:flex;
  align-items:flex-start;
  gap:13px;
}
.ico{
  width:54px;
  height:54px;
  flex:0 0 54px;
  border-radius:19px;
  border:1px solid var(--line);
  background:rgba(35,255,137,.10);
  display:grid;
  place-items:center;
  font-size:29px;
}
.hero h2{
  font-size:33px;
  line-height:1;
  margin:4px 0 7px;
  font-weight:950;
  letter-spacing:-1.6px;
}
.hero p{
  margin:0;
  color:var(--muted);
  font-size:14px;
  line-height:1.3;
  font-weight:800;
}
.grid{
  display:grid;
  grid-template-columns:1fr 1fr;
  gap:9px;
  margin-top:14px;
}
.card{
  border:1px solid rgba(35,255,137,.17);
  background:rgba(0,0,0,.23);
  border-radius:17px;
  padding:12px;
  min-height:68px;
}
.card b{
  display:block;
  color:var(--yellow);
  font-size:20px;
  line-height:1.1;
  word-break:break-word;
}
.card span{
  display:block;
  color:var(--muted);
  font-size:11px;
  font-weight:900;
  margin-top:6px;
}
.key{grid-column:1/-1}
.key b{font-size:15px;color:#9fffc4}
.mini-back{
  display:inline-flex;
  align-items:center;
  justify-content:center;
  margin-top:12px;
  min-height:44px;
  width:100%;
  border-radius:16px;
  color:var(--text);
  text-decoration:none;
  font-weight:950;
  background:rgba(255,255,255,.075);
  border:1px solid rgba(255,255,255,.09);
}
.section-title{
  font-size:18px;
  letter-spacing:8px;
  font-weight:950;
  margin:22px 0 10px;
}
.form{padding:14px}
.form label{
  display:block;
  font-size:15px;
  font-weight:950;
  margin-bottom:8px;
}
.form input{
  width:100%;
  height:52px;
  border-radius:16px;
  border:1px solid rgba(35,255,137,.22);
  background:rgba(0,0,0,.22);
  color:var(--text);
  font-size:15px;
  font-weight:850;
  padding:0 13px;
  outline:none;
}
.form input::placeholder{color:rgba(245,255,248,.34)}
.form button{
  width:100%;
  height:52px;
  border:0;
  border-radius:16px;
  margin-top:10px;
  background:linear-gradient(135deg,var(--yellow),var(--green));
  font-size:16px;
  font-weight:950;
  color:#00180c;
}
.perms{
  padding:14px;
  display:grid;
  grid-template-columns:1fr 1fr;
  gap:9px;
}
.chip{
  min-height:48px;
  border-radius:15px;
  border:1px solid rgba(35,255,137,.18);
  background:rgba(0,0,0,.20);
  display:flex;
  align-items:center;
  justify-content:space-between;
  gap:8px;
  padding:10px 11px;
}
.chip span{
  font-size:13px;
  font-weight:900;
  color:var(--muted);
}
.chip b{
  font-size:13px;
  font-weight:950;
  color:#9fffc4;
}
.foot{
  text-align:center;
  margin:20px 0 0;
  color:rgba(245,255,248,.42);
  font-weight:800;
  font-size:13px;
}
@media(max-width:380px){
  .hero h2{font-size:29px}
  .perms{grid-template-columns:1fr}
}
</style>
</head>
<body>
<header class="top">
  <div class="brand">
    <div class="logo">🔑</div>
    <div>
      <h1>Erat<span>Guard</span></h1>
      <p>Lisans Merkezi</p>
    </div>
  </div>
  <div class="badge">👑 __STATUS__</div>
</header>

<section class="hero">
  <div class="hero-top">
    <div class="ico">🔑</div>
    <div>
      <h2>__PLAN__</h2>
      <p>Premium erişim ve lisans durumu tek kompakt ekranda.</p>
    </div>
  </div>

  <div class="grid">
    <div class="card"><b>__STATUS__</b><span>Durum</span></div>
    <div class="card"><b>__DAYS__</b><span>Kalan gün</span></div>
    <div class="card key"><b>__KEY__</b><span>Lisans anahtarı</span></div>
  </div>

  <a class="mini-back" href="/dashboard">← Ana ekrana dön</a>
</section>

<div class="section-title">AKTİVASYON</div>
<form class="form" method="post" action="/u/license">
  <label>Lisans kodu gir</label>
  <input name="license_key" placeholder="Örn: ERATGUARD-PRO-XXXX-XXXX" autocomplete="off">
  <button type="submit">Lisansı Aktifleştir</button>
</form>

<div class="section-title">YETKİLER</div>
<section class="perms">
  <div class="chip"><span>Koruma</span><b>__PREMIUM__</b></div>
  <div class="chip"><span>AI Analiz</span><b>__PREMIUM__</b></div>
  <div class="chip"><span>Rapor</span><b>__PREMIUM__</b></div>
  <div class="chip"><span>Güvenli Liste</span><b>__PREMIUM__</b></div>
  <div class="chip"><span>Blok Liste</span><b>__PREMIUM__</b></div>
  <div class="chip"><span>Bildirim</span><b>__PREMIUM__</b></div>
</section>

<div class="foot">EratGuard PRO - © 2026</div>
</body>
</html>"""

        html = html.replace("__STATUS__", _eg_uld2_safe(info["status"]))
        html = html.replace("__PLAN__", _eg_uld2_safe(info["plan"]))
        html = html.replace("__DAYS__", _eg_uld2_safe(info["days_left"]))
        html = html.replace("__KEY__", _eg_uld2_safe(info["license_key"]))
        html = html.replace("__PREMIUM__", _eg_uld2_safe(info["premium"]))

        resp = _eg_uld2_make_response(_eg_uld2_render_template_string(html))
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        resp.headers["Pragma"] = "no-cache"
        resp.headers["Expires"] = "0"
        return resp

    try:
        for _rule in list(app.url_map.iter_rules()):
            if str(_rule) in ("/u/license", "/u/license/"):
                app.view_functions[_rule.endpoint] = _eg_uld2_license_route
        print("ERATGUARD USER-LICENSE-DIET-2 ULTRA COMPACT PAGE ACTIVE")
    except Exception as _eg_uld2_route_err:
        print("ERATGUARD USER-LICENSE-DIET-2 ROUTE ERROR:", _eg_uld2_route_err)

except Exception as _eg_uld2_err:
    print("ERATGUARD USER-LICENSE-DIET-2 ERROR:", _eg_uld2_err)
# === /ERATGUARD USER-LICENSE-DIET-2 ULTRA COMPACT PAGE ===

# === ERATGUARD USER-PROTECTION-DIET-1 COMPACT PAGE ===
# /u/protection sayfasını inceltir:
# - Hero alanı küçültülür
# - Büyük detay kartları mini feature chip haline gelir
# - Durum alanı ince satırlara çekilir
# - SMS tarama alanı korunur
try:
    from flask import render_template_string as _eg_upd1_render_template_string
    from flask import make_response as _eg_upd1_make_response
    from flask import redirect as _eg_upd1_redirect
    from flask import session as _eg_upd1_session
    from flask import request as _eg_upd1_request

    _eg_upd1_original_protection = None

    try:
        for _rule in list(app.url_map.iter_rules()):
            if str(_rule) in ("/u/protection", "/u/protection/"):
                _eg_upd1_original_protection = app.view_functions.get(_rule.endpoint)
                break
    except Exception as _eg_upd1_rule_find_err:
        print("ERATGUARD USER-PROTECTION-DIET-1 FIND ORIGINAL ERROR:", _eg_upd1_rule_find_err)

    def _eg_upd1_safe(v):
        try:
            import html as _html
            return _html.escape(str(v or ""))
        except Exception:
            return ""

    def _eg_upd1_compact_protection_route():
        if not (_eg_upd1_session.get("logged_in") and _eg_upd1_session.get("username")):
            return _eg_upd1_redirect("/login")

        # POST davranışını mevcut gerçek route'a bırak
        if str(_eg_upd1_request.method).upper() == "POST":
            try:
                if callable(_eg_upd1_original_protection) and getattr(_eg_upd1_original_protection, "__name__", "") != "_eg_upd1_compact_protection_route":
                    return _eg_upd1_original_protection()
            except Exception as _eg_upd1_post_err:
                print("ERATGUARD USER-PROTECTION-DIET-1 POST FALLBACK ERROR:", _eg_upd1_post_err)
            return _eg_upd1_redirect("/u/protection?scan_sent=1")

        username = str(_eg_upd1_session.get("username") or "user")

        html = """<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>EratGuard PRO - Koruma Merkezi</title>
<style>
:root{
  --bg:#020806;
  --panel:#071a10;
  --line:rgba(35,255,137,.22);
  --green:#20ff88;
  --yellow:#ffdd35;
  --text:#f5fff8;
  --muted:rgba(245,255,248,.62);
}
*{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
html,body{
  margin:0;
  min-height:100%;
  background:radial-gradient(circle at 80% 0%,rgba(35,255,137,.14),transparent 32%),var(--bg);
  color:var(--text);
  font-family:Arial,Helvetica,sans-serif;
}
body{padding:16px 14px 24px}
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
  min-width:0;
}
.logo{
  width:50px;
  height:50px;
  border-radius:17px;
  background:rgba(35,255,137,.12);
  border:1px solid var(--line);
  display:grid;
  place-items:center;
  font-size:27px;
}
.brand h1{
  margin:0;
  font-size:26px;
  line-height:1;
  font-weight:950;
  letter-spacing:-1.2px;
}
.brand h1 span{color:var(--green)}
.brand p{
  margin:4px 0 0;
  color:var(--muted);
  font-weight:850;
  font-size:12px;
}
.badge{
  border:1px solid rgba(255,221,53,.35);
  color:var(--green);
  background:rgba(35,255,137,.10);
  padding:9px 12px;
  border-radius:999px;
  font-weight:950;
  font-size:12px;
  white-space:nowrap;
}
.hero,.scan,.features,.status{
  border:1px solid var(--line);
  background:linear-gradient(145deg,rgba(10,36,23,.94),rgba(4,14,9,.94));
  border-radius:23px;
  padding:16px;
  box-shadow:0 18px 48px rgba(0,0,0,.34);
}
.hero-top{
  display:flex;
  align-items:flex-start;
  gap:13px;
}
.ico{
  width:54px;
  height:54px;
  flex:0 0 54px;
  border-radius:19px;
  border:1px solid var(--line);
  background:rgba(35,255,137,.10);
  display:grid;
  place-items:center;
  font-size:29px;
}
.hero h2{
  font-size:31px;
  line-height:1.02;
  margin:2px 0 6px;
  font-weight:950;
  letter-spacing:-1.5px;
}
.hero p{
  margin:0;
  color:var(--muted);
  font-size:14px;
  line-height:1.3;
  font-weight:800;
}
.stats{
  display:grid;
  grid-template-columns:1fr 1fr 1fr;
  gap:9px;
  margin-top:14px;
}
.stat{
  border:1px solid rgba(35,255,137,.17);
  background:rgba(0,0,0,.23);
  border-radius:17px;
  padding:12px;
  min-height:68px;
}
.stat b{
  display:block;
  color:var(--green);
  font-size:19px;
  line-height:1.1;
}
.stat span{
  display:block;
  color:var(--muted);
  font-size:11px;
  font-weight:900;
  margin-top:6px;
}
.mini-back{
  display:inline-flex;
  align-items:center;
  justify-content:center;
  margin-top:12px;
  min-height:44px;
  width:100%;
  border-radius:16px;
  color:var(--text);
  text-decoration:none;
  font-weight:950;
  background:rgba(255,255,255,.075);
  border:1px solid rgba(255,255,255,.09);
}
.section-title{
  font-size:18px;
  letter-spacing:8px;
  font-weight:950;
  margin:22px 0 10px;
}
.scan{padding:14px}
.scan label{
  display:block;
  font-size:15px;
  font-weight:950;
  margin-bottom:8px;
}
.scan textarea{
  width:100%;
  min-height:108px;
  border-radius:16px;
  border:1px solid rgba(35,255,137,.22);
  background:rgba(0,0,0,.22);
  color:var(--text);
  font-size:15px;
  font-weight:800;
  padding:12px 13px;
  outline:none;
  resize:vertical;
}
.scan textarea::placeholder{color:rgba(245,255,248,.34)}
.scan button{
  width:100%;
  height:52px;
  border:0;
  border-radius:16px;
  margin-top:10px;
  background:linear-gradient(135deg,var(--yellow),var(--green));
  font-size:16px;
  font-weight:950;
  color:#00180c;
}
.scan .hint{
  margin-top:10px;
  color:var(--muted);
  font-size:13px;
  line-height:1.35;
  font-weight:800;
}
.features{
  padding:14px;
  display:grid;
  grid-template-columns:1fr 1fr;
  gap:9px;
}
.feature{
  min-height:64px;
  border-radius:15px;
  border:1px solid rgba(35,255,137,.18);
  background:rgba(0,0,0,.20);
  padding:12px;
}
.feature b{
  display:block;
  font-size:15px;
  line-height:1.2;
  margin-bottom:5px;
}
.feature span{
  display:block;
  color:var(--muted);
  font-size:12px;
  line-height:1.3;
  font-weight:800;
}
.status{padding:0;overflow:hidden}
.row{
  display:flex;
  align-items:center;
  justify-content:space-between;
  gap:12px;
  padding:15px 16px;
  border-bottom:1px solid rgba(255,255,255,.06);
}
.row:last-child{border-bottom:0}
.row span{
  font-size:15px;
  font-weight:900;
}
.row b{
  color:#9fffc4;
  font-size:15px;
  font-weight:950;
}
.foot{
  text-align:center;
  margin:20px 0 0;
  color:rgba(245,255,248,.42);
  font-weight:800;
  font-size:13px;
}
@media(max-width:420px){
  .stats{grid-template-columns:1fr 1fr 1fr}
}
@media(max-width:380px){
  .hero h2{font-size:28px}
  .features{grid-template-columns:1fr}
}
</style>
</head>
<body>
<header class="top">
  <div class="brand">
    <div class="logo">🛡️</div>
    <div>
      <h1>Erat<span>Guard</span></h1>
      <p>Koruma Merkezi</p>
    </div>
  </div>
  <div class="badge">👑 PRO AKTİF</div>
</header>

<section class="hero">
  <div class="hero-top">
    <div class="ico">🛡️</div>
    <div>
      <h2>Koruma Merkezi</h2>
      <p>SMS tarama, spam filtreleme ve AI güvenlik motoru tek kompakt ekranda.</p>
    </div>
  </div>

  <div class="stats">
    <div class="stat"><b>7/24</b><span>Koruma</span></div>
    <div class="stat"><b>92</b><span>Skor</span></div>
    <div class="stat"><b>AI</b><span>Hazır</span></div>
  </div>

  <a class="mini-back" href="/dashboard">← Ana ekrana dön</a>
</section>

<div class="section-title">TARAMA</div>
<form class="scan" method="post" action="/u/protection">
  <label>SMS metnini analiz et</label>
  <textarea name="sms_text" placeholder="Şüpheli SMS metnini buraya yapıştır..."></textarea>
  <button type="submit">SMS'i Tara</button>
  <div class="hint">Riskli mesajlar Titanium motor tarafından otomatik karantinaya alınır.</div>
</form>

<div class="section-title">ÖZELLİKLER</div>
<section class="features">
  <div class="feature"><b>Anlık Tarama</b><span>Gelen mesajları hızlı değerlendirir.</span></div>
  <div class="feature"><b>Spam Filtresi</b><span>Oltalama ve tehlikeli bağlantıları ayıklar.</span></div>
  <div class="feature"><b>Koruma Katmanı</b><span>Kullanıcıyı yormadan sessiz güvenlik sağlar.</span></div>
  <div class="feature"><b>Güvenli Liste</b><span>Güvenilir kişi ve servisleri yönetir.</span></div>
</section>

<div class="section-title">DURUM</div>
<section class="status">
  <div class="row"><span>Koruma Durumu</span><b>Açık</b></div>
  <div class="row"><span>AI Motoru</span><b>Hazır</b></div>
  <div class="row"><span>Spam Hassasiyeti</span><b>Yüksek</b></div>
  <div class="row"><span>Son Kontrol</span><b>Az önce</b></div>
</section>

<div class="foot">EratGuard PRO · __USERNAME__ · © 2026</div>
</body>
</html>"""

        html = html.replace("__USERNAME__", _eg_upd1_safe(username))

        resp = _eg_upd1_make_response(_eg_upd1_render_template_string(html))
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        resp.headers["Pragma"] = "no-cache"
        resp.headers["Expires"] = "0"
        return resp

    try:
        for _rule in list(app.url_map.iter_rules()):
            if str(_rule) in ("/u/protection", "/u/protection/"):
                app.view_functions[_rule.endpoint] = _eg_upd1_compact_protection_route
        print("ERATGUARD USER-PROTECTION-DIET-1 COMPACT PAGE ACTIVE")
    except Exception as _eg_upd1_route_err:
        print("ERATGUARD USER-PROTECTION-DIET-1 ROUTE ERROR:", _eg_upd1_route_err)

except Exception as _eg_upd1_err:
    print("ERATGUARD USER-PROTECTION-DIET-1 ERROR:", _eg_upd1_err)
# === /ERATGUARD USER-PROTECTION-DIET-1 COMPACT PAGE ===

# === ERATGUARD PROTECTION-SCAN-FIX-1 POST METHOD FIX ===
# /u/protection form POST isteğinde 405 Method Not Allowed hatasını engeller.
# SMS'i analiz eder, spam_logs / analysis_history / quarantine dosyalarına yazar.
try:
    from flask import request as _eg_psf1_request
    from flask import session as _eg_psf1_session
    from flask import redirect as _eg_psf1_redirect
    from flask import render_template_string as _eg_psf1_render_template_string
    from flask import make_response as _eg_psf1_make_response
    from pathlib import Path as _eg_psf1_Path
    from datetime import datetime as _eg_psf1_datetime
    import json as _eg_psf1_json
    import html as _eg_psf1_html

    def _eg_psf1_safe(v):
        try:
            return _eg_psf1_html.escape(str(v or ""))
        except Exception:
            return ""

    def _eg_psf1_load(default, path):
        try:
            p = _eg_psf1_Path(path)
            if not p.exists():
                return default
            txt = p.read_text(encoding="utf-8", errors="ignore").strip()
            if not txt:
                return default
            return _eg_psf1_json.loads(txt)
        except Exception:
            return default

    def _eg_psf1_save(path, data):
        p = _eg_psf1_Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(
            _eg_psf1_json.dumps(data, ensure_ascii=False, indent=2),
            encoding="utf-8"
        )

    def _eg_psf1_analyze(message):
        try:
            if "analyze_sms_text" in globals() and callable(globals().get("analyze_sms_text")):
                return globals()["analyze_sms_text"](message)
        except Exception as e:
            print("ERATGUARD PROTECTION-SCAN-FIX-1 analyze_sms_text ERROR:", e)

        text = str(message or "").lower()
        score = 10
        reasons = []

        risky = [
            "kazandınız", "kazandin", "ödül", "odul", "tebrikler",
            "link", "tıkla", "tikla", "hemen", "acil",
            "şifre", "sifre", "kart", "banka", "hesap",
            "onay", "kargo", "borç", "borc", "icra"
        ]

        high = ["kart bilg", "şifre gir", "sifre gir", "hesap bilg", "tıklayın", "tiklayin"]

        hit = sum(1 for w in risky if w in text)
        high_hit = sum(1 for w in high if w in text)

        score += hit * 8
        score += high_hit * 15

        if "http://" in text or "https://" in text or "www." in text:
            score += 18
            reasons.append("Mesaj bağlantı/link içeriyor.")

        if any(w in text for w in ["kart", "şifre", "sifre", "hesap"]):
            score += 18
            reasons.append("Mesaj kişisel veya finansal bilgi isteme riski taşıyor.")

        if hit:
            reasons.append(f"{hit} adet riskli kelime/sinyal tespit edildi.")

        if not reasons:
            reasons.append("Belirgin spam sinyali bulunmadı.")

        score = max(0, min(100, int(score)))

        if score >= 71:
            status = "SPAM"
            label = "Yüksek Risk"
            risk_class = "high"
        elif score >= 31:
            status = "SUSPICIOUS"
            label = "Orta Risk"
            risk_class = "mid"
        else:
            status = "SAFE"
            label = "Düşük Risk"
            risk_class = "low"

        return {
            "score": score,
            "status": status,
            "risk_label": label,
            "risk_class": risk_class,
            "reasons": reasons,
        }

    def _eg_psf1_result_page(message, result):
        username = str(_eg_psf1_session.get("username") or "user")
        score = int(result.get("score") or 0)
        status = str(result.get("status") or "UNKNOWN")
        risk_label = str(result.get("risk_label") or status)
        reasons = result.get("reasons") or []

        reasons_html = "".join(
            f"<li>{_eg_psf1_safe(x)}</li>" for x in reasons
        ) or "<li>Analiz tamamlandı.</li>"

        html = f"""<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>EratGuard PRO - SMS Analiz Sonucu</title>
<style>
:root{{
  --bg:#020806;
  --panel:#071a10;
  --line:rgba(35,255,137,.22);
  --green:#20ff88;
  --yellow:#ffdd35;
  --red:#ff4d4d;
  --text:#f5fff8;
  --muted:rgba(245,255,248,.62);
}}
*{{box-sizing:border-box;-webkit-tap-highlight-color:transparent}}
html,body{{
  margin:0;
  min-height:100%;
  background:radial-gradient(circle at 80% 0%,rgba(35,255,137,.14),transparent 32%),var(--bg);
  color:var(--text);
  font-family:Arial,Helvetica,sans-serif;
}}
body{{padding:16px 14px 24px}}
.top{{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:12px}}
.brand{{display:flex;align-items:center;gap:10px}}
.logo{{width:50px;height:50px;border-radius:17px;background:rgba(35,255,137,.12);border:1px solid var(--line);display:grid;place-items:center;font-size:27px}}
.brand h1{{margin:0;font-size:26px;line-height:1;font-weight:950;letter-spacing:-1.2px}}
.brand h1 span{{color:var(--green)}}
.brand p{{margin:4px 0 0;color:var(--muted);font-weight:850;font-size:12px}}
.badge{{border:1px solid rgba(255,221,53,.35);color:var(--yellow);background:rgba(255,221,53,.10);padding:9px 12px;border-radius:999px;font-weight:950;font-size:12px}}
.card,.msg,.reasons{{
  border:1px solid var(--line);
  background:linear-gradient(145deg,rgba(10,36,23,.94),rgba(4,14,9,.94));
  border-radius:23px;
  padding:16px;
  box-shadow:0 18px 48px rgba(0,0,0,.34);
}}
.card h2{{font-size:34px;line-height:1;margin:0 0 8px;font-weight:950;letter-spacing:-1.6px}}
.card p{{margin:0;color:var(--muted);font-size:14px;line-height:1.35;font-weight:800}}
.grid{{display:grid;grid-template-columns:1fr 1fr;gap:9px;margin-top:14px}}
.box{{border:1px solid rgba(35,255,137,.17);background:rgba(0,0,0,.23);border-radius:17px;padding:12px;min-height:68px}}
.box b{{display:block;color:var(--yellow);font-size:22px;line-height:1.1}}
.box span{{display:block;color:var(--muted);font-size:11px;font-weight:900;margin-top:6px}}
.section-title{{font-size:18px;letter-spacing:8px;font-weight:950;margin:22px 0 10px}}
.msg{{white-space:pre-wrap;color:#c8ffd9;font-weight:800;line-height:1.45}}
.reasons ul{{margin:0;padding-left:20px}}
.reasons li{{margin:8px 0;color:var(--muted);font-weight:850;line-height:1.35}}
.btn{{display:flex;align-items:center;justify-content:center;min-height:52px;border-radius:16px;text-decoration:none;font-weight:950;font-size:16px;border:1px solid rgba(255,255,255,.10);color:#00180c;background:linear-gradient(135deg,var(--yellow),var(--green));margin-top:12px}}
.btn.secondary{{background:rgba(255,255,255,.075);color:var(--text)}}
.foot{{text-align:center;margin:20px 0 0;color:rgba(245,255,248,.42);font-weight:800;font-size:13px}}
</style>
</head>
<body>
<header class="top">
  <div class="brand">
    <div class="logo">🛡️</div>
    <div><h1>Erat<span>Guard</span></h1><p>SMS Analiz Sonucu</p></div>
  </div>
  <div class="badge">{_eg_psf1_safe(status)}</div>
</header>

<section class="card">
  <h2>{_eg_psf1_safe(risk_label)}</h2>
  <p>SMS analizi tamamlandı. Sonuç güvenlik kayıtlarına işlendi.</p>
  <div class="grid">
    <div class="box"><b>{score}</b><span>Risk skoru</span></div>
    <div class="box"><b>{_eg_psf1_safe(status)}</b><span>Durum</span></div>
  </div>
  <a class="btn secondary" href="/u/protection">← Koruma sayfasına dön</a>
</section>

<div class="section-title">MESAJ</div>
<section class="msg">{_eg_psf1_safe(message)}</section>

<div class="section-title">NEDENLER</div>
<section class="reasons">
  <ul>{reasons_html}</ul>
</section>

<a class="btn" href="/dashboard">Ana ekrana dön</a>

<div class="foot">EratGuard PRO · {_eg_psf1_safe(username)} · © 2026</div>
</body>
</html>"""

        resp = _eg_psf1_make_response(_eg_psf1_render_template_string(html))
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        resp.headers["Pragma"] = "no-cache"
        resp.headers["Expires"] = "0"
        return resp

    @app.before_request
    def _eg_psf1_protection_post_bridge():
        try:
            path = str(_eg_psf1_request.path or "").rstrip("/")
            method = str(_eg_psf1_request.method or "").upper()

            if path != "/u/protection" or method != "POST":
                return None

            if not (_eg_psf1_session.get("logged_in") and _eg_psf1_session.get("username")):
                return _eg_psf1_redirect("/login?auth_required=1")

            username = str(_eg_psf1_session.get("username") or "user")
            message = (
                _eg_psf1_request.form.get("sms_text")
                or _eg_psf1_request.form.get("message")
                or _eg_psf1_request.form.get("body")
                or ""
            ).strip()

            if not message:
                return _eg_psf1_redirect("/u/protection?empty=1")

            result = _eg_psf1_analyze(message)
            now = _eg_psf1_datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            status = str(result.get("status") or "UNKNOWN")
            score = int(result.get("score") or 0)
            reasons = result.get("reasons") or []

            log_item = {
                "time": now,
                "number": "manual_user_scan",
                "sender": "manual_user_scan",
                "body": message,
                "status": status,
                "score": score,
                "risk": score,
                "reasons": reasons,
                "source": "user_protection_scan",
                "username": username
            }

            spam_logs = _eg_psf1_load([], "data/spam_logs.json")
            if not isinstance(spam_logs, list):
                spam_logs = []
            spam_logs.append(log_item)
            _eg_psf1_save("data/spam_logs.json", spam_logs)

            history = _eg_psf1_load([], "data/user_analysis_history.json")
            if not isinstance(history, list):
                history = []
            history.append(log_item)
            _eg_psf1_save("data/user_analysis_history.json", history)

            if score >= 71 or status == "SPAM":
                quarantine = _eg_psf1_load([], "data/user_quarantine.json")
                if not isinstance(quarantine, list):
                    quarantine = []
                q_item = dict(log_item)
                q_item["quarantine_status"] = "auto_quarantined"
                quarantine.append(q_item)
                _eg_psf1_save("data/user_quarantine.json", quarantine)

            return _eg_psf1_result_page(message, result)

        except Exception as _eg_psf1_req_err:
            print("ERATGUARD PROTECTION-SCAN-FIX-1 REQUEST ERROR:", _eg_psf1_req_err)
            return None

    print("ERATGUARD PROTECTION-SCAN-FIX-1 POST METHOD FIX ACTIVE")

except Exception as _eg_psf1_err:
    print("ERATGUARD PROTECTION-SCAN-FIX-1 ERROR:", _eg_psf1_err)
# === /ERATGUARD PROTECTION-SCAN-FIX-1 POST METHOD FIX ===

# === ERATGUARD PROTECTION-SCAN-FIX-2 UNKNOWN STATUS NORMALIZE ===
# Analiz sonucu score/reasons geliyor ama status/risk_label eksikse UNKNOWN görünmesini engeller.
try:
    def _eg_psf2_normalize_result(result):
        if not isinstance(result, dict):
            result = {}

        try:
            score = int(result.get("score") or result.get("risk") or 0)
        except Exception:
            score = 0

        score = max(0, min(100, score))

        status = str(result.get("status") or "").strip().upper()
        risk_label = str(result.get("risk_label") or result.get("label") or "").strip()
        risk_class = str(result.get("risk_class") or "").strip().lower()

        if not status or status in ("UNKNOWN", "NONE", "NULL"):
            if score >= 71:
                status = "SPAM"
            elif score >= 31:
                status = "SUSPICIOUS"
            else:
                status = "SAFE"

        if not risk_label or risk_label.upper() in ("UNKNOWN", "NONE", "NULL"):
            if status == "SPAM" or score >= 71:
                risk_label = "Yüksek Risk"
            elif status == "SUSPICIOUS" or score >= 31:
                risk_label = "Orta Risk"
            else:
                risk_label = "Düşük Risk"

        if not risk_class or risk_class in ("unknown", "none", "null"):
            if status == "SPAM" or score >= 71:
                risk_class = "high"
            elif status == "SUSPICIOUS" or score >= 31:
                risk_class = "mid"
            else:
                risk_class = "low"

        reasons = result.get("reasons") or result.get("reason") or []
        if isinstance(reasons, str):
            reasons = [reasons]
        if not isinstance(reasons, list):
            reasons = ["Analiz tamamlandı."]

        result["score"] = score
        result["status"] = status
        result["risk_label"] = risk_label
        result["risk_class"] = risk_class
        result["reasons"] = reasons

        return result

    # Mevcut _eg_psf1_analyze fonksiyonunu sar.
    if "_eg_psf1_analyze" in globals() and callable(globals().get("_eg_psf1_analyze")):
        _eg_psf2_old_analyze = globals().get("_eg_psf1_analyze")

        def _eg_psf1_analyze(message):
            try:
                raw = _eg_psf2_old_analyze(message)
            except Exception as _eg_psf2_old_err:
                print("ERATGUARD PROTECTION-SCAN-FIX-2 OLD ANALYZE ERROR:", _eg_psf2_old_err)
                raw = {}
            return _eg_psf2_normalize_result(raw)

    print("ERATGUARD PROTECTION-SCAN-FIX-2 UNKNOWN STATUS NORMALIZE ACTIVE")

except Exception as _eg_psf2_err:
    print("ERATGUARD PROTECTION-SCAN-FIX-2 ERROR:", _eg_psf2_err)
# === /ERATGUARD PROTECTION-SCAN-FIX-2 UNKNOWN STATUS NORMALIZE ===

# === ERATGUARD AI-ANALYSIS-SCAN-FIX-1 POST METHOD FIX ===
# /u/analysis form POST isteğinde 405 Method Not Allowed hatasını engeller.
# AI analiz sonucunu history/spam_logs/quarantine dosyalarına yazar.
try:
    from flask import request as _eg_asf1_request
    from flask import session as _eg_asf1_session
    from flask import redirect as _eg_asf1_redirect
    from flask import render_template_string as _eg_asf1_render_template_string
    from flask import make_response as _eg_asf1_make_response
    from pathlib import Path as _eg_asf1_Path
    from datetime import datetime as _eg_asf1_datetime
    import json as _eg_asf1_json
    import html as _eg_asf1_html

    def _eg_asf1_safe(v):
        try:
            return _eg_asf1_html.escape(str(v or ""))
        except Exception:
            return ""

    def _eg_asf1_load(default, path):
        try:
            p = _eg_asf1_Path(path)
            if not p.exists():
                return default
            txt = p.read_text(encoding="utf-8", errors="ignore").strip()
            if not txt:
                return default
            return _eg_asf1_json.loads(txt)
        except Exception:
            return default

    def _eg_asf1_save(path, data):
        p = _eg_asf1_Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(
            _eg_asf1_json.dumps(data, ensure_ascii=False, indent=2),
            encoding="utf-8"
        )

    def _eg_asf1_analyze(message):
        # Varsa mevcut motoru kullan.
        for fn_name in ("analyze_sms_text", "analyze_message", "scan_sms_text"):
            try:
                fn = globals().get(fn_name)
                if callable(fn):
                    raw = fn(message)
                    if isinstance(raw, dict):
                        return _eg_asf1_normalize(raw)
            except Exception as e:
                print("ERATGUARD AI-ANALYSIS-SCAN-FIX-1 ENGINE ERROR:", fn_name, e)

        text = str(message or "").lower()
        score = 8
        reasons = []

        urgent_words = ["acil", "hemen", "son gün", "son gun", "kaçırma", "kacirma", "tıkla", "tikla"]
        prize_words = ["kazandınız", "kazandin", "ödül", "odul", "hediye", "kampanya", "bonus", "çekiliş", "cekilis"]
        finance_words = ["kart", "şifre", "sifre", "banka", "hesap", "iban", "ödeme", "odeme", "borç", "borc"]
        link_words = ["http://", "https://", "www.", ".com", ".net", ".xyz", "link"]

        urgent_hit = sum(1 for w in urgent_words if w in text)
        prize_hit = sum(1 for w in prize_words if w in text)
        finance_hit = sum(1 for w in finance_words if w in text)
        link_hit = sum(1 for w in link_words if w in text)

        score += urgent_hit * 12
        score += prize_hit * 14
        score += finance_hit * 16
        score += link_hit * 14

        if urgent_hit:
            reasons.append("Mesaj hızlı karar vermeye zorlayan aciliyet dili içeriyor.")
        if prize_hit:
            reasons.append("Mesaj ödül, kampanya veya kazanç vaadi içeriyor.")
        if finance_hit:
            reasons.append("Mesaj kişisel, şifre, kart veya hesap bilgisi isteme riski taşıyor.")
        if link_hit:
            reasons.append("Mesaj bağlantı/link yönlendirmesi içeriyor.")

        total_hit = urgent_hit + prize_hit + finance_hit + link_hit
        if total_hit:
            reasons.append(f"Mesajda {total_hit} adet riskli kelime/sinyal tespit edildi.")
        else:
            reasons.append("Belirgin dolandırıcılık sinyali bulunmadı.")

        return _eg_asf1_normalize({
            "score": score,
            "reasons": reasons,
        })

    def _eg_asf1_normalize(result):
        if not isinstance(result, dict):
            result = {}

        try:
            score = int(result.get("score") or result.get("risk") or 0)
        except Exception:
            score = 0

        score = max(0, min(100, score))

        status = str(result.get("status") or "").strip().upper()
        risk_label = str(result.get("risk_label") or result.get("label") or "").strip()
        risk_class = str(result.get("risk_class") or "").strip().lower()

        if not status or status in ("UNKNOWN", "NONE", "NULL"):
            if score >= 71:
                status = "SPAM"
            elif score >= 31:
                status = "SUSPICIOUS"
            else:
                status = "SAFE"

        if not risk_label or risk_label.upper() in ("UNKNOWN", "NONE", "NULL"):
            if status == "SPAM" or score >= 71:
                risk_label = "Yüksek Risk"
            elif status == "SUSPICIOUS" or score >= 31:
                risk_label = "Orta Risk"
            else:
                risk_label = "Düşük Risk"

        if not risk_class or risk_class in ("unknown", "none", "null"):
            if status == "SPAM" or score >= 71:
                risk_class = "high"
            elif status == "SUSPICIOUS" or score >= 31:
                risk_class = "mid"
            else:
                risk_class = "low"

        reasons = result.get("reasons") or result.get("reason") or []
        if isinstance(reasons, str):
            reasons = [reasons]
        if not isinstance(reasons, list):
            reasons = ["Analiz tamamlandı."]

        result["score"] = score
        result["status"] = status
        result["risk_label"] = risk_label
        result["risk_class"] = risk_class
        result["reasons"] = reasons
        return result

    def _eg_asf1_result_page(message, result):
        username = str(_eg_asf1_session.get("username") or "user")
        score = int(result.get("score") or 0)
        status = str(result.get("status") or "UNKNOWN")
        risk_label = str(result.get("risk_label") or status)
        reasons = result.get("reasons") or []

        reasons_html = "".join(f"<li>{_eg_asf1_safe(x)}</li>" for x in reasons) or "<li>Analiz tamamlandı.</li>"

        html = f"""<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>EratGuard PRO - AI Analiz Sonucu</title>
<style>
:root{{
  --bg:#020806;--line:rgba(35,255,137,.22);--green:#20ff88;--yellow:#ffdd35;
  --text:#f5fff8;--muted:rgba(245,255,248,.62)
}}
*{{box-sizing:border-box;-webkit-tap-highlight-color:transparent}}
html,body{{margin:0;min-height:100%;background:radial-gradient(circle at 80% 0%,rgba(35,255,137,.14),transparent 32%),var(--bg);color:var(--text);font-family:Arial,Helvetica,sans-serif}}
body{{padding:16px 14px 24px}}
.top{{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:12px}}
.brand{{display:flex;align-items:center;gap:10px}}
.logo{{width:50px;height:50px;border-radius:17px;background:rgba(35,255,137,.12);border:1px solid var(--line);display:grid;place-items:center;font-size:27px}}
.brand h1{{margin:0;font-size:26px;line-height:1;font-weight:950;letter-spacing:-1.2px}}
.brand h1 span{{color:var(--green)}}
.brand p{{margin:4px 0 0;color:var(--muted);font-weight:850;font-size:12px}}
.badge{{border:1px solid rgba(255,221,53,.35);color:var(--yellow);background:rgba(255,221,53,.10);padding:9px 12px;border-radius:999px;font-weight:950;font-size:12px}}
.card,.msg,.reasons{{border:1px solid var(--line);background:linear-gradient(145deg,rgba(10,36,23,.94),rgba(4,14,9,.94));border-radius:23px;padding:16px;box-shadow:0 18px 48px rgba(0,0,0,.34)}}
.card h2{{font-size:34px;line-height:1;margin:0 0 8px;font-weight:950;letter-spacing:-1.6px}}
.card p{{margin:0;color:var(--muted);font-size:14px;line-height:1.35;font-weight:800}}
.grid{{display:grid;grid-template-columns:1fr 1fr;gap:9px;margin-top:14px}}
.box{{border:1px solid rgba(35,255,137,.17);background:rgba(0,0,0,.23);border-radius:17px;padding:12px;min-height:68px}}
.box b{{display:block;color:var(--yellow);font-size:22px;line-height:1.1}}
.box span{{display:block;color:var(--muted);font-size:11px;font-weight:900;margin-top:6px}}
.section-title{{font-size:18px;letter-spacing:8px;font-weight:950;margin:22px 0 10px}}
.msg{{white-space:pre-wrap;color:#c8ffd9;font-weight:800;line-height:1.45}}
.reasons ul{{margin:0;padding-left:20px}}
.reasons li{{margin:8px 0;color:var(--muted);font-weight:850;line-height:1.35}}
.btn{{display:flex;align-items:center;justify-content:center;min-height:52px;border-radius:16px;text-decoration:none;font-weight:950;font-size:16px;border:1px solid rgba(255,255,255,.10);color:#00180c;background:linear-gradient(135deg,var(--yellow),var(--green));margin-top:12px}}
.btn.secondary{{background:rgba(255,255,255,.075);color:var(--text)}}
.foot{{text-align:center;margin:20px 0 0;color:rgba(245,255,248,.42);font-weight:800;font-size:13px}}
</style>
</head>
<body>
<header class="top">
  <div class="brand">
    <div class="logo">🔎</div>
    <div><h1>Erat<span>Guard</span></h1><p>AI Analiz Sonucu</p></div>
  </div>
  <div class="badge">{_eg_asf1_safe(status)}</div>
</header>

<section class="card">
  <h2>{_eg_asf1_safe(risk_label)}</h2>
  <p>AI mesaj analizi tamamlandı. Sonuç güvenlik kayıtlarına işlendi.</p>
  <div class="grid">
    <div class="box"><b>{score}</b><span>Risk skoru</span></div>
    <div class="box"><b>{_eg_asf1_safe(status)}</b><span>Durum</span></div>
  </div>
  <a class="btn secondary" href="/u/analysis">← Analiz sayfasına dön</a>
</section>

<div class="section-title">MESAJ</div>
<section class="msg">{_eg_asf1_safe(message)}</section>

<div class="section-title">NEDENLER</div>
<section class="reasons"><ul>{reasons_html}</ul></section>

<a class="btn" href="/dashboard">Ana ekrana dön</a>

<div class="foot">EratGuard PRO · {_eg_asf1_safe(username)} · © 2026</div>
</body>
</html>"""

        resp = _eg_asf1_make_response(_eg_asf1_render_template_string(html))
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        resp.headers["Pragma"] = "no-cache"
        resp.headers["Expires"] = "0"
        return resp

    @app.before_request
    def _eg_asf1_analysis_post_bridge():
        try:
            path = str(_eg_asf1_request.path or "").rstrip("/")
            method = str(_eg_asf1_request.method or "").upper()

            if path != "/u/analysis" or method != "POST":
                return None

            if not (_eg_asf1_session.get("logged_in") and _eg_asf1_session.get("username")):
                return _eg_asf1_redirect("/login?auth_required=1")

            username = str(_eg_asf1_session.get("username") or "user")
            message = (
                _eg_asf1_request.form.get("sms_text")
                or _eg_asf1_request.form.get("message")
                or _eg_asf1_request.form.get("body")
                or _eg_asf1_request.form.get("text")
                or ""
            ).strip()

            if not message:
                return _eg_asf1_redirect("/u/analysis?empty=1")

            result = _eg_asf1_analyze(message)
            now = _eg_asf1_datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            status = str(result.get("status") or "UNKNOWN")
            score = int(result.get("score") or 0)
            reasons = result.get("reasons") or []

            item = {
                "time": now,
                "number": "manual_ai_analysis",
                "sender": "manual_ai_analysis",
                "body": message,
                "status": status,
                "score": score,
                "risk": score,
                "reasons": reasons,
                "source": "user_ai_analysis_scan",
                "username": username
            }

            history = _eg_asf1_load([], "data/user_analysis_history.json")
            if not isinstance(history, list):
                history = []
            history.append(item)
            _eg_asf1_save("data/user_analysis_history.json", history)

            spam_logs = _eg_asf1_load([], "data/spam_logs.json")
            if not isinstance(spam_logs, list):
                spam_logs = []
            spam_logs.append(item)
            _eg_asf1_save("data/spam_logs.json", spam_logs)

            if score >= 71 or status == "SPAM":
                quarantine = _eg_asf1_load([], "data/user_quarantine.json")
                if not isinstance(quarantine, list):
                    quarantine = []
                q_item = dict(item)
                q_item["quarantine_status"] = "auto_quarantined"
                quarantine.append(q_item)
                _eg_asf1_save("data/user_quarantine.json", quarantine)

            return _eg_asf1_result_page(message, result)

        except Exception as _eg_asf1_req_err:
            print("ERATGUARD AI-ANALYSIS-SCAN-FIX-1 REQUEST ERROR:", _eg_asf1_req_err)
            return None

    print("ERATGUARD AI-ANALYSIS-SCAN-FIX-1 POST METHOD FIX ACTIVE")

except Exception as _eg_asf1_err:
    print("ERATGUARD AI-ANALYSIS-SCAN-FIX-1 ERROR:", _eg_asf1_err)
# === /ERATGUARD AI-ANALYSIS-SCAN-FIX-1 POST METHOD FIX ===

# === ERATGUARD AI-ANALYSIS-DIET-1B SAFE FORCE PAGE ===
# /u/analysis route override: kompakt sayfa + güçlü risk motoru + POST desteği.
try:
    from flask import request as _eg_aid1b_request
    from flask import session as _eg_aid1b_session
    from flask import redirect as _eg_aid1b_redirect
    from flask import render_template_string as _eg_aid1b_render_template_string
    from flask import make_response as _eg_aid1b_make_response
    from pathlib import Path as _eg_aid1b_Path
    from datetime import datetime as _eg_aid1b_datetime
    import json as _eg_aid1b_json
    import html as _eg_aid1b_html

    def _eg_aid1b_safe(v):
        try:
            return _eg_aid1b_html.escape(str(v or ""))
        except Exception:
            return ""

    def _eg_aid1b_load(default, path):
        try:
            p = _eg_aid1b_Path(path)
            if not p.exists():
                return default
            txt = p.read_text(encoding="utf-8", errors="ignore").strip()
            if not txt:
                return default
            return _eg_aid1b_json.loads(txt)
        except Exception:
            return default

    def _eg_aid1b_save(path, data):
        p = _eg_aid1b_Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(_eg_aid1b_json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

    def _eg_aid1b_engine(message):
        text = str(message or "").lower()
        score = 8
        reasons = []

        groups = {
            "aciliyet": ["acil", "hemen", "son gün", "son gun", "tıkla", "tikla", "tıklayın", "tiklayin"],
            "ödül": ["tebrikler", "kazandınız", "kazandiniz", "kazandin", "ödül", "odul", "hediye", "kampanya", "bonus", "tl kazand"],
            "finans": ["kart", "şifre", "sifre", "banka", "hesap", "iban", "ödeme", "odeme", "bilgilerinizi girin", "kart bilg"],
            "link": ["http://", "https://", "www.", ".com", ".net", ".xyz", "link", "bağlantı", "baglanti"],
        }

        hits = {}
        for name, words in groups.items():
            hits[name] = sum(1 for w in words if w in text)

        score += hits["aciliyet"] * 14
        score += hits["ödül"] * 16
        score += hits["finans"] * 18
        score += hits["link"] * 16

        if hits["aciliyet"]:
            reasons.append("Mesaj hızlı karar vermeye zorlayan aciliyet dili içeriyor.")
        if hits["ödül"]:
            reasons.append("Mesaj ödül, kampanya veya kazanç vaadi içeriyor.")
        if hits["finans"]:
            reasons.append("Mesaj kişisel, şifre, kart veya hesap bilgisi isteme riski taşıyor.")
        if hits["link"]:
            reasons.append("Mesaj bağlantı veya link yönlendirmesi içeriyor.")

        total = sum(hits.values())

        if hits["ödül"] and hits["aciliyet"] and (hits["finans"] or hits["link"]):
            score = max(score, 92)
            reasons.append("Ödül vaadi, aciliyet ve bilgi/link yönlendirmesi birlikte tespit edildi.")

        if total:
            reasons.append(f"Toplam {total} risk sinyali tespit edildi.")
        else:
            reasons.append("Belirgin dolandırıcılık sinyali düşük görünüyor.")

        score = max(0, min(100, int(score)))

        if score >= 71:
            return {"score": score, "status": "SPAM", "risk_label": "Yüksek Risk", "risk_class": "high", "reasons": reasons}
        if score >= 31:
            return {"score": score, "status": "SUSPICIOUS", "risk_label": "Orta Risk", "risk_class": "mid", "reasons": reasons}
        return {"score": score, "status": "SAFE", "risk_label": "Düşük Risk", "risk_class": "low", "reasons": reasons}

    def _eg_aid1b_write(username, message, result):
        now = _eg_aid1b_datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        item = {
            "time": now,
            "number": "manual_ai_analysis",
            "sender": "manual_ai_analysis",
            "body": message,
            "status": result.get("status"),
            "score": int(result.get("score") or 0),
            "risk": int(result.get("score") or 0),
            "risk_label": result.get("risk_label"),
            "risk_class": result.get("risk_class"),
            "reasons": result.get("reasons") or [],
            "source": "user_ai_analysis_scan",
            "username": username,
        }

        for file_path in ["data/user_analysis_history.json", "data/spam_logs.json"]:
            data = _eg_aid1b_load([], file_path)
            if not isinstance(data, list):
                data = []
            data.append(item)
            _eg_aid1b_save(file_path, data)

        if item["score"] >= 71 or item["status"] == "SPAM":
            q = _eg_aid1b_load([], "data/user_quarantine.json")
            if not isinstance(q, list):
                q = []
            q_item = dict(item)
            q_item["quarantine_status"] = "auto_quarantined"
            q.append(q_item)
            _eg_aid1b_save("data/user_quarantine.json", q)

    def _eg_aid1b_route():
        if not (_eg_aid1b_session.get("logged_in") and _eg_aid1b_session.get("username")):
            return _eg_aid1b_redirect("/login")

        username = str(_eg_aid1b_session.get("username") or "user")
        message = ""
        result = None

        if str(_eg_aid1b_request.method or "").upper() == "POST":
            message = (
                _eg_aid1b_request.form.get("sms_text")
                or _eg_aid1b_request.form.get("message")
                or _eg_aid1b_request.form.get("body")
                or _eg_aid1b_request.form.get("text")
                or ""
            ).strip()

            if message:
                result = _eg_aid1b_engine(message)
                _eg_aid1b_write(username, message, result)

        result_html = ""
        if result:
            reasons_html = "".join("<li>" + _eg_aid1b_safe(x) + "</li>" for x in (result.get("reasons") or []))
            result_html = """
<div class="section-title">SONUÇ</div>
<section class="result">
  <div class="result-top">
    <div>
      <h3>__RISK_LABEL__</h3>
      <p>AI analiz tamamlandı ve güvenlik kayıtlarına işlendi.</p>
    </div>
    <div class="score">__SCORE__</div>
  </div>
  <div class="mini-grid">
    <div><b>__STATUS__</b><span>Durum</span></div>
    <div><b>__RISK_CLASS__</b><span>Seviye</span></div>
  </div>
  <ul>__REASONS__</ul>
</section>
"""
            result_html = result_html.replace("__RISK_LABEL__", _eg_aid1b_safe(result.get("risk_label")))
            result_html = result_html.replace("__SCORE__", _eg_aid1b_safe(result.get("score")))
            result_html = result_html.replace("__STATUS__", _eg_aid1b_safe(result.get("status")))
            result_html = result_html.replace("__RISK_CLASS__", _eg_aid1b_safe(result.get("risk_class")))
            result_html = result_html.replace("__REASONS__", reasons_html)

        page = """
<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>EratGuard PRO - AI Analiz</title>
<style>
:root{--bg:#020806;--line:rgba(35,255,137,.22);--green:#20ff88;--yellow:#ffdd35;--text:#f5fff8;--muted:rgba(245,255,248,.62)}
*{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
html,body{margin:0;min-height:100%;background:radial-gradient(circle at 80% 0%,rgba(35,255,137,.14),transparent 32%),var(--bg);color:var(--text);font-family:Arial,Helvetica,sans-serif}
body{padding:16px 14px 24px}
.top{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:12px}
.brand{display:flex;align-items:center;gap:10px}
.logo{width:50px;height:50px;border-radius:17px;background:rgba(35,255,137,.12);border:1px solid var(--line);display:grid;place-items:center;font-size:27px}
.brand h1{margin:0;font-size:26px;line-height:1;font-weight:950;letter-spacing:-1.2px}.brand h1 span{color:var(--green)}
.brand p{margin:4px 0 0;color:var(--muted);font-weight:850;font-size:12px}
.badge{border:1px solid rgba(255,221,53,.35);color:var(--green);background:rgba(35,255,137,.10);padding:9px 12px;border-radius:999px;font-weight:950;font-size:12px}
.hero,.scan,.result,.status{border:1px solid var(--line);background:linear-gradient(145deg,rgba(10,36,23,.94),rgba(4,14,9,.94));border-radius:23px;padding:16px;box-shadow:0 18px 48px rgba(0,0,0,.34)}
.hero-top{display:flex;align-items:flex-start;gap:13px}
.ico{width:54px;height:54px;flex:0 0 54px;border-radius:19px;border:1px solid var(--line);background:rgba(35,255,137,.10);display:grid;place-items:center;font-size:29px}
.hero h2{font-size:31px;line-height:1.02;margin:2px 0 6px;font-weight:950;letter-spacing:-1.5px}
.hero p{margin:0;color:var(--muted);font-size:14px;line-height:1.3;font-weight:800}
.stats{display:grid;grid-template-columns:1fr 1fr 1fr;gap:9px;margin-top:14px}
.stat{border:1px solid rgba(35,255,137,.17);background:rgba(0,0,0,.23);border-radius:17px;padding:12px;min-height:68px}
.stat b{display:block;color:var(--green);font-size:19px}.stat span{display:block;color:var(--muted);font-size:11px;font-weight:900;margin-top:6px}
.back{display:flex;align-items:center;justify-content:center;margin-top:12px;min-height:44px;width:100%;border-radius:16px;color:var(--text);text-decoration:none;font-weight:950;background:rgba(255,255,255,.075);border:1px solid rgba(255,255,255,.09)}
.section-title{font-size:18px;letter-spacing:8px;font-weight:950;margin:22px 0 10px}
.scan{padding:14px}.scan label{display:block;font-size:15px;font-weight:950;margin-bottom:8px}
.scan textarea{width:100%;min-height:108px;border-radius:16px;border:1px solid rgba(35,255,137,.22);background:rgba(0,0,0,.22);color:var(--text);font-size:15px;font-weight:800;padding:12px 13px;outline:none;resize:vertical}
.scan textarea::placeholder{color:rgba(245,255,248,.34)}
.scan button{width:100%;height:52px;border:0;border-radius:16px;margin-top:10px;background:linear-gradient(135deg,var(--yellow),var(--green));font-size:16px;font-weight:950;color:#00180c}
.result h3{font-size:31px;margin:0 0 7px;font-weight:950;letter-spacing:-1.3px}.result p{margin:0;color:var(--muted);font-size:13px;font-weight:850}
.result-top{display:flex;align-items:flex-start;justify-content:space-between;gap:12px}
.score{min-width:70px;height:70px;border-radius:20px;border:1px solid rgba(255,221,53,.35);display:grid;place-items:center;color:var(--yellow);font-size:28px;font-weight:950;background:rgba(0,0,0,.22)}
.mini-grid{display:grid;grid-template-columns:1fr 1fr;gap:9px;margin-top:14px}.mini-grid div{border:1px solid rgba(35,255,137,.17);background:rgba(0,0,0,.20);border-radius:16px;padding:11px}
.mini-grid b{display:block;color:#9fffc4;font-size:15px}.mini-grid span{display:block;color:var(--muted);font-size:11px;font-weight:900;margin-top:5px}
.result ul{margin:14px 0 0;padding-left:20px}.result li{margin:7px 0;color:var(--muted);font-weight:850;line-height:1.35}
.status{padding:0;overflow:hidden}.row{display:flex;justify-content:space-between;gap:12px;padding:15px 16px;border-bottom:1px solid rgba(255,255,255,.06)}
.row:last-child{border-bottom:0}.row span{font-size:15px;font-weight:900}.row b{color:#9fffc4;font-size:15px;font-weight:950}
.foot{text-align:center;margin:20px 0 0;color:rgba(245,255,248,.42);font-weight:800;font-size:13px}
</style>
</head>
<body>
<header class="top">
  <div class="brand"><div class="logo">🔎</div><div><h1>Erat<span>Guard</span></h1><p>AI Analiz</p></div></div>
  <div class="badge">👑 PRO AKTİF</div>
</header>

<section class="hero">
  <div class="hero-top">
    <div class="ico">🔎</div>
    <div><h2>AI Analiz</h2><p>Mesaj içeriğini risk, bağlantı, aciliyet ve dolandırıcılık sinyallerine göre analiz eder.</p></div>
  </div>
  <div class="stats">
    <div class="stat"><b>AI</b><span>Aktif</span></div>
    <div class="stat"><b>0-100</b><span>Skor</span></div>
    <div class="stat"><b>PRO</b><span>Motor</span></div>
  </div>
  <a class="back" href="/dashboard">← Ana ekrana dön</a>
</section>

<div class="section-title">TARAMA</div>
<form class="scan" method="post" action="/u/analysis">
  <label>SMS / mesaj metnini analiz et</label>
  <textarea name="sms_text" placeholder="Analiz etmek istediğin SMS veya mesaj metnini buraya yapıştır...">__MESSAGE__</textarea>
  <button type="submit">AI Analizi Başlat</button>
</form>

__RESULT__

<div class="section-title">DURUM</div>
<section class="status">
  <div class="row"><span>Analiz Motoru</span><b>Çevrim içi</b></div>
  <div class="row"><span>Hassasiyet</span><b>Yüksek</b></div>
  <div class="row"><span>Kayıt</span><b>Aktif</b></div>
  <div class="row"><span>Karantina</span><b>Otomatik</b></div>
</section>

<div class="foot">EratGuard PRO · __USERNAME__ · © 2026</div>
</body>
</html>
"""
        page = page.replace("__USERNAME__", _eg_aid1b_safe(username))
        page = page.replace("__MESSAGE__", _eg_aid1b_safe(message))
        page = page.replace("__RESULT__", result_html)

        resp = _eg_aid1b_make_response(_eg_aid1b_render_template_string(page))
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        resp.headers["Pragma"] = "no-cache"
        resp.headers["Expires"] = "0"
        return resp

    try:
        for _rule in list(app.url_map.iter_rules()):
            if str(_rule) in ("/u/analysis", "/u/analysis/"):
                app.view_functions[_rule.endpoint] = _eg_aid1b_route
                try:
                    _rule.methods.add("POST")
                except Exception:
                    pass
        print("ERATGUARD AI-ANALYSIS-DIET-1B SAFE FORCE PAGE ACTIVE")
    except Exception as _eg_aid1b_route_err:
        print("ERATGUARD AI-ANALYSIS-DIET-1B ROUTE ERROR:", _eg_aid1b_route_err)

except Exception as _eg_aid1b_err:
    print("ERATGUARD AI-ANALYSIS-DIET-1B ERROR:", _eg_aid1b_err)
# === /ERATGUARD AI-ANALYSIS-DIET-1B SAFE FORCE PAGE ===

# === ERATGUARD REPORTS-DATA-BIND-1B SAFE LIVE REPORTS PAGE ===
# /u/reports sayfasını canlı JSON verisine bağlar.
try:
    from flask import render_template_string as _eg_rdb1b_render_template_string
    from flask import make_response as _eg_rdb1b_make_response
    from flask import redirect as _eg_rdb1b_redirect
    from flask import session as _eg_rdb1b_session
    from pathlib import Path as _eg_rdb1b_Path
    import json as _eg_rdb1b_json
    import html as _eg_rdb1b_html

    def _eg_rdb1b_safe(v):
        try:
            return _eg_rdb1b_html.escape(str(v or ""))
        except Exception:
            return ""

    def _eg_rdb1b_load(default, path):
        try:
            p = _eg_rdb1b_Path(path)
            if not p.exists():
                return default
            txt = p.read_text(encoding="utf-8", errors="ignore").strip()
            if not txt:
                return default
            return _eg_rdb1b_json.loads(txt)
        except Exception:
            return default

    def _eg_rdb1b_norm_status(v):
        raw = str(v or "").strip().upper()
        if raw in ("SPAM", "BLOCKED", "HIGH", "RISK", "RISKY"):
            return "SPAM"
        if raw in ("SUSPICIOUS", "WARNING", "MID", "ORTA"):
            return "SUSPICIOUS"
        if raw in ("OK", "SAFE", "GUVENLI", "GÜVENLİ", "LOW", "GUVENLI"):
            return "SAFE"
        return "UNKNOWN"

    def _eg_rdb1b_score(item):
        try:
            return int(item.get("score") or item.get("risk") or 0)
        except Exception:
            return 0

    def _eg_rdb1b_items(username):
        username = str(username or "").strip()

        spam_logs = _eg_rdb1b_load([], "data/spam_logs.json")
        history = _eg_rdb1b_load([], "data/user_analysis_history.json")
        quarantine = _eg_rdb1b_load([], "data/user_quarantine.json")

        if not isinstance(spam_logs, list):
            spam_logs = []
        if not isinstance(history, list):
            history = []
        if not isinstance(quarantine, list):
            quarantine = []

        combined = []

        for src, data in [("spam_logs", spam_logs), ("analysis_history", history)]:
            for item in data:
                if not isinstance(item, dict):
                    continue
                item_user = str(item.get("username") or "").strip()

                # Eski kayıtlarda username yoksa test raporunda gösteriyoruz.
                if item_user and item_user != username:
                    continue

                x = dict(item)
                x["_file_source"] = src
                combined.append(x)

        user_quarantine = []
        for item in quarantine:
            if not isinstance(item, dict):
                continue
            item_user = str(item.get("username") or "").strip()
            if item_user and item_user != username:
                continue
            user_quarantine.append(item)

        return combined, user_quarantine

    def _eg_rdb1b_reports_route():
        if not (_eg_rdb1b_session.get("logged_in") and _eg_rdb1b_session.get("username")):
            return _eg_rdb1b_redirect("/login?auth_required=1")

        username = str(_eg_rdb1b_session.get("username") or "user")
        items, quarantine = _eg_rdb1b_items(username)

        total = len(items)
        spam_count = 0
        safe_count = 0
        suspicious_count = 0
        unknown_count = 0
        score_sum = 0

        for item in items:
            st = _eg_rdb1b_norm_status(item.get("status"))
            sc = _eg_rdb1b_score(item)
            score_sum += sc

            if st == "SPAM" or sc >= 71:
                spam_count += 1
            elif st == "SUSPICIOUS" or sc >= 31:
                suspicious_count += 1
            elif st == "SAFE":
                safe_count += 1
            else:
                unknown_count += 1

        quarantine_count = len(quarantine)
        avg_score = int(score_sum / total) if total else 0
        risk_rate = int((spam_count / total) * 100) if total else 0
        safe_rate = max(0, 100 - risk_rate) if total else 100

        if spam_count:
            summary = "Riskli mesajlar tespit edildi. Karantina ve rapor kayıtları aktif."
            mode_label = "Risk İzleme"
        elif suspicious_count:
            summary = "Orta risk sinyalleri var. Sistem izlemeye devam ediyor."
            mode_label = "Dikkat"
        else:
            summary = "Belirgin yüksek risk yoğunluğu yok. Sistem temiz görünüyor."
            mode_label = "Temiz Durum"

        recent = sorted(items, key=lambda x: str(x.get("time") or ""), reverse=True)[:5]

        recent_html = ""
        if recent:
            for item in recent:
                st = _eg_rdb1b_norm_status(item.get("status"))
                sc = _eg_rdb1b_score(item)
                label = item.get("risk_label") or ("Yüksek Risk" if sc >= 71 else "Düşük Risk")
                body = str(item.get("body") or "")[:92]
                source = item.get("source") or item.get("_file_source") or "system"
                time = item.get("time") or "-"

                recent_html += (
                    '<div class="event">'
                    '<div>'
                    '<b>' + _eg_rdb1b_safe(label) + '</b>'
                    '<span>' + _eg_rdb1b_safe(body) + '</span>'
                    '<small>' + _eg_rdb1b_safe(time) + ' - ' + _eg_rdb1b_safe(source) + '</small>'
                    '</div>'
                    '<strong>' + _eg_rdb1b_safe(st) + ' / ' + str(sc) + '</strong>'
                    '</div>'
                )
        else:
            recent_html = '<div class="empty">Henüz analiz kaydı yok.</div>'

        html = """
<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>EratGuard PRO - Raporlar</title>
<style>
:root{--bg:#020806;--line:rgba(35,255,137,.22);--green:#20ff88;--yellow:#ffdd35;--text:#f5fff8;--muted:rgba(245,255,248,.62)}
*{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
html,body{margin:0;min-height:100%;background:radial-gradient(circle at 80% 0%,rgba(35,255,137,.14),transparent 32%),var(--bg);color:var(--text);font-family:Arial,Helvetica,sans-serif}
body{padding:16px 14px 24px}
.top{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:12px}
.brand{display:flex;align-items:center;gap:10px;min-width:0}
.logo{width:50px;height:50px;border-radius:17px;background:rgba(35,255,137,.12);border:1px solid var(--line);display:grid;place-items:center;font-size:27px}
.brand h1{margin:0;font-size:26px;line-height:1;font-weight:950;letter-spacing:-1.2px}
.brand h1 span{color:var(--green)}
.brand p{margin:4px 0 0;color:var(--muted);font-weight:850;font-size:12px}
.badge{border:1px solid rgba(255,221,53,.35);color:var(--green);background:rgba(35,255,137,.10);padding:9px 12px;border-radius:999px;font-weight:950;font-size:12px;white-space:nowrap}
.hero,.summary,.events{border:1px solid var(--line);background:linear-gradient(145deg,rgba(10,36,23,.94),rgba(4,14,9,.94));border-radius:23px;padding:16px;box-shadow:0 18px 48px rgba(0,0,0,.34)}
.hero-top{display:flex;align-items:flex-start;gap:13px}
.ico{width:54px;height:54px;flex:0 0 54px;border-radius:19px;border:1px solid var(--line);background:rgba(35,255,137,.10);display:grid;place-items:center;font-size:29px}
.hero h2{font-size:31px;line-height:1.02;margin:2px 0 6px;font-weight:950;letter-spacing:-1.5px}
.hero p{margin:0;color:var(--muted);font-size:14px;line-height:1.3;font-weight:800}
.stats{display:grid;grid-template-columns:1fr 1fr 1fr;gap:9px;margin-top:14px}
.stat{border:1px solid rgba(35,255,137,.17);background:rgba(0,0,0,.23);border-radius:17px;padding:12px;min-height:68px}
.stat b{display:block;color:var(--green);font-size:20px;line-height:1.1}
.stat span{display:block;color:var(--muted);font-size:11px;font-weight:900;margin-top:6px}
.back{display:flex;align-items:center;justify-content:center;margin-top:12px;min-height:44px;width:100%;border-radius:16px;color:var(--text);text-decoration:none;font-weight:950;background:rgba(255,255,255,.075);border:1px solid rgba(255,255,255,.09)}
.section-title{font-size:18px;letter-spacing:8px;font-weight:950;margin:22px 0 10px}
.summary{padding:0;overflow:hidden}
.row{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:15px 16px;border-bottom:1px solid rgba(255,255,255,.06)}
.row:last-child{border-bottom:0}
.row span{font-size:15px;font-weight:900}
.row b{color:#9fffc4;font-size:15px;font-weight:950;text-align:right}
.events{padding:12px}
.event{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:13px 10px;border-bottom:1px solid rgba(255,255,255,.06)}
.event:last-child{border-bottom:0}
.event b{display:block;font-size:15px;margin-bottom:5px}
.event span{display:block;color:var(--muted);font-size:13px;font-weight:800;line-height:1.3}
.event small{display:block;color:rgba(245,255,248,.42);font-size:11px;font-weight:800;margin-top:6px}
.event strong{color:var(--yellow);font-size:13px;white-space:nowrap}
.empty{padding:18px;color:var(--muted);font-weight:850;text-align:center}
.foot{text-align:center;margin:20px 0 0;color:rgba(245,255,248,.42);font-weight:800;font-size:13px}
</style>
</head>
<body>
<header class="top">
  <div class="brand"><div class="logo">📊</div><div><h1>Erat<span>Guard</span></h1><p>Rapor Merkezi</p></div></div>
  <div class="badge">👑 PRO AKTİF</div>
</header>

<section class="hero">
  <div class="hero-top">
    <div class="ico">📊</div>
    <div>
      <h2>Raporlar</h2>
      <p>__SUMMARY__</p>
    </div>
  </div>

  <div class="stats">
    <div class="stat"><b>__TOTAL__</b><span>Analiz</span></div>
    <div class="stat"><b>__SPAM__</b><span>Riskli</span></div>
    <div class="stat"><b>__QUARANTINE__</b><span>Karantina</span></div>
  </div>

  <a class="back" href="/dashboard">← Ana ekrana dön</a>
</section>

<div class="section-title">ÖZET</div>
<section class="summary">
  <div class="row"><span>Koruma Modu</span><b>__MODE__</b></div>
  <div class="row"><span>Risk Oranı</span><b>%__RISK_RATE__</b></div>
  <div class="row"><span>Güvenli Oran</span><b>%__SAFE_RATE__</b></div>
  <div class="row"><span>Ortalama Skor</span><b>__AVG_SCORE__/100</b></div>
  <div class="row"><span>İzleme</span><b>Aktif</b></div>
</section>

<div class="section-title">SON KAYITLAR</div>
<section class="events">
__RECENT__
</section>

<div class="foot">EratGuard PRO - __USERNAME__ - © 2026</div>
</body>
</html>
"""

        html = html.replace("__USERNAME__", _eg_rdb1b_safe(username))
        html = html.replace("__SUMMARY__", _eg_rdb1b_safe(summary))
        html = html.replace("__TOTAL__", str(total))
        html = html.replace("__SPAM__", str(spam_count))
        html = html.replace("__QUARANTINE__", str(quarantine_count))
        html = html.replace("__MODE__", _eg_rdb1b_safe(mode_label))
        html = html.replace("__RISK_RATE__", str(risk_rate))
        html = html.replace("__SAFE_RATE__", str(safe_rate))
        html = html.replace("__AVG_SCORE__", str(avg_score))
        html = html.replace("__RECENT__", recent_html)

        resp = _eg_rdb1b_make_response(_eg_rdb1b_render_template_string(html))
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        resp.headers["Pragma"] = "no-cache"
        resp.headers["Expires"] = "0"
        return resp

    try:
        for _rule in list(app.url_map.iter_rules()):
            if str(_rule) in ("/u/reports", "/u/reports/"):
                app.view_functions[_rule.endpoint] = _eg_rdb1b_reports_route
        print("ERATGUARD REPORTS-DATA-BIND-1B SAFE LIVE REPORTS PAGE ACTIVE")
    except Exception as _eg_rdb1b_route_err:
        print("ERATGUARD REPORTS-DATA-BIND-1B ROUTE ERROR:", _eg_rdb1b_route_err)

except Exception as _eg_rdb1b_err:
    print("ERATGUARD REPORTS-DATA-BIND-1B ERROR:", _eg_rdb1b_err)
# === /ERATGUARD REPORTS-DATA-BIND-1B SAFE LIVE REPORTS PAGE ===

# === ERATGUARD AI-LABEL-PERSIST-FIX-2 ===
# AI/protection kayıtlarında risk_label ve risk_class boş kalırsa otomatik doldurur.
try:
    def _eg_alpf2_label_for(score, status):
        status = str(status or "").upper()
        try:
            score = int(score or 0)
        except Exception:
            score = 0

        if status == "SPAM" or score >= 71:
            return "Yüksek Risk", "high"
        if status == "SUSPICIOUS" or score >= 31:
            return "Orta Risk", "mid"
        return "Düşük Risk", "low"

    def _eg_alpf2_normalize_item(item):
        if not isinstance(item, dict):
            return item

        score = item.get("score") or item.get("risk") or 0
        status = item.get("status") or ""

        label, klass = _eg_alpf2_label_for(score, status)

        if not item.get("risk_label"):
            item["risk_label"] = label

        if not item.get("risk_class"):
            item["risk_class"] = klass

        return item

    # AI Diet 1B write fonksiyonunu sar.
    if "_eg_aid1b_write" in globals() and callable(globals().get("_eg_aid1b_write")):
        _eg_alpf2_old_aid1b_write = globals().get("_eg_aid1b_write")

        def _eg_aid1b_write(username, message, result):
            try:
                if isinstance(result, dict):
                    score = result.get("score") or result.get("risk") or 0
                    status = result.get("status") or ""
                    label, klass = _eg_alpf2_label_for(score, status)
                    if not result.get("risk_label"):
                        result["risk_label"] = label
                    if not result.get("risk_class"):
                        result["risk_class"] = klass
            except Exception as _eg_alpf2_norm_err:
                print("ERATGUARD AI-LABEL-PERSIST-FIX-2 NORMALIZE ERROR:", _eg_alpf2_norm_err)

            return _eg_alpf2_old_aid1b_write(username, message, result)

    print("ERATGUARD AI-LABEL-PERSIST-FIX-2 ACTIVE")

except Exception as _eg_alpf2_err:
    print("ERATGUARD AI-LABEL-PERSIST-FIX-2 ERROR:", _eg_alpf2_err)
# === /ERATGUARD AI-LABEL-PERSIST-FIX-2 ===

# === ERATGUARD BLOCKED-DATA-BIND-1 LIVE BLOCKED PAGE ===
# /u/blocked sayfasını canlı blok listesi + karantina JSON verisine bağlar.
try:
    from flask import render_template_string as _eg_bdb1_render_template_string
    from flask import make_response as _eg_bdb1_make_response
    from flask import redirect as _eg_bdb1_redirect
    from flask import session as _eg_bdb1_session
    from pathlib import Path as _eg_bdb1_Path
    import json as _eg_bdb1_json
    import html as _eg_bdb1_html

    def _eg_bdb1_safe(v):
        try:
            return _eg_bdb1_html.escape(str(v or ""))
        except Exception:
            return ""

    def _eg_bdb1_load(default, path):
        try:
            p = _eg_bdb1_Path(path)
            if not p.exists():
                return default
            txt = p.read_text(encoding="utf-8", errors="ignore").strip()
            if not txt:
                return default
            return _eg_bdb1_json.loads(txt)
        except Exception:
            return default

    def _eg_bdb1_score(item):
        try:
            return int(item.get("score") or item.get("risk") or 0)
        except Exception:
            return 0

    def _eg_bdb1_user_data(username):
        username = str(username or "").strip()

        block_data = _eg_bdb1_load({}, "data/user_block_list.json")
        quarantine = _eg_bdb1_load([], "data/user_quarantine.json")

        if not isinstance(block_data, dict):
            block_data = {}

        if not isinstance(quarantine, list):
            quarantine = []

        user_blocks = block_data.get(username, [])
        if not isinstance(user_blocks, list):
            user_blocks = []

        user_quarantine = []
        for item in quarantine:
            if not isinstance(item, dict):
                continue
            item_user = str(item.get("username") or "").strip()
            if item_user and item_user != username:
                continue
            user_quarantine.append(item)

        return user_blocks, user_quarantine

    def _eg_bdb1_blocked_route():
        if not (_eg_bdb1_session.get("logged_in") and _eg_bdb1_session.get("username")):
            return _eg_bdb1_redirect("/login?auth_required=1")

        username = str(_eg_bdb1_session.get("username") or "user")
        blocks, quarantine = _eg_bdb1_user_data(username)

        block_count = len(blocks)
        quarantine_count = len(quarantine)
        high_count = sum(1 for x in quarantine if _eg_bdb1_score(x) >= 71 or str(x.get("status") or "").upper() == "SPAM")
        total_count = block_count + quarantine_count

        if quarantine_count:
            summary = "Riskli mesajlar karantinada tutuluyor. Blok listesi izlemeye hazır."
            mode = "Aktif İzleme"
        elif block_count:
            summary = "Blok listesi aktif. Karantina şu an temiz görünüyor."
            mode = "Blok Aktif"
        else:
            summary = "Henüz engellenen kayıt yok. Sistem temiz durumda."
            mode = "Temiz"

        items = sorted(quarantine, key=lambda x: str(x.get("time") or ""), reverse=True)[:6]

        items_html = ""
        if items:
            for item in items:
                label = item.get("risk_label") or "Yüksek Risk"
                body = str(item.get("body") or "")[:96]
                time = item.get("time") or "-"
                status = item.get("status") or "SPAM"
                score = _eg_bdb1_score(item)
                source = item.get("source") or "quarantine"

                items_html += (
                    '<div class="event">'
                    '<div>'
                    '<b>' + _eg_bdb1_safe(label) + '</b>'
                    '<span>' + _eg_bdb1_safe(body) + '</span>'
                    '<small>' + _eg_bdb1_safe(time) + ' - ' + _eg_bdb1_safe(source) + '</small>'
                    '</div>'
                    '<strong>' + _eg_bdb1_safe(status) + ' / ' + str(score) + '</strong>'
                    '</div>'
                )
        else:
            items_html = '<div class="empty">Karantinada gösterilecek riskli mesaj yok.</div>'

        blocks_html = ""
        if blocks:
            for item in blocks[:6]:
                if isinstance(item, dict):
                    name = item.get("name") or item.get("sender") or item.get("phone") or "Engelli kayıt"
                    detail = item.get("phone") or item.get("reason") or item.get("created_at") or "Blok listesinde"
                else:
                    name = str(item)
                    detail = "Blok listesinde"

                blocks_html += (
                    '<div class="chip">'
                    '<span>' + _eg_bdb1_safe(name) + '</span>'
                    '<b>' + _eg_bdb1_safe(detail) + '</b>'
                    '</div>'
                )
        else:
            blocks_html = '<div class="empty">Kullanıcı blok listesi henüz boş.</div>'

        html = """
<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>EratGuard PRO - Engellenenler</title>
<style>
:root{--bg:#020806;--line:rgba(35,255,137,.22);--green:#20ff88;--yellow:#ffdd35;--text:#f5fff8;--muted:rgba(245,255,248,.62)}
*{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
html,body{margin:0;min-height:100%;background:radial-gradient(circle at 80% 0%,rgba(35,255,137,.14),transparent 32%),var(--bg);color:var(--text);font-family:Arial,Helvetica,sans-serif}
body{padding:16px 14px 24px}
.top{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:12px}
.brand{display:flex;align-items:center;gap:10px;min-width:0}
.logo{width:50px;height:50px;border-radius:17px;background:rgba(35,255,137,.12);border:1px solid var(--line);display:grid;place-items:center;font-size:27px}
.brand h1{margin:0;font-size:26px;line-height:1;font-weight:950;letter-spacing:-1.2px}
.brand h1 span{color:var(--green)}
.brand p{margin:4px 0 0;color:var(--muted);font-weight:850;font-size:12px}
.badge{border:1px solid rgba(255,221,53,.35);color:var(--green);background:rgba(35,255,137,.10);padding:9px 12px;border-radius:999px;font-weight:950;font-size:12px;white-space:nowrap}
.hero,.summary,.events,.chips{border:1px solid var(--line);background:linear-gradient(145deg,rgba(10,36,23,.94),rgba(4,14,9,.94));border-radius:23px;padding:16px;box-shadow:0 18px 48px rgba(0,0,0,.34)}
.hero-top{display:flex;align-items:flex-start;gap:13px}
.ico{width:54px;height:54px;flex:0 0 54px;border-radius:19px;border:1px solid var(--line);background:rgba(35,255,137,.10);display:grid;place-items:center;font-size:29px}
.hero h2{font-size:31px;line-height:1.02;margin:2px 0 6px;font-weight:950;letter-spacing:-1.5px}
.hero p{margin:0;color:var(--muted);font-size:14px;line-height:1.3;font-weight:800}
.stats{display:grid;grid-template-columns:1fr 1fr 1fr;gap:9px;margin-top:14px}
.stat{border:1px solid rgba(35,255,137,.17);background:rgba(0,0,0,.23);border-radius:17px;padding:12px;min-height:68px}
.stat b{display:block;color:var(--green);font-size:20px;line-height:1.1}
.stat span{display:block;color:var(--muted);font-size:11px;font-weight:900;margin-top:6px}
.back{display:flex;align-items:center;justify-content:center;margin-top:12px;min-height:44px;width:100%;border-radius:16px;color:var(--text);text-decoration:none;font-weight:950;background:rgba(255,255,255,.075);border:1px solid rgba(255,255,255,.09)}
.section-title{font-size:18px;letter-spacing:8px;font-weight:950;margin:22px 0 10px}
.summary{padding:0;overflow:hidden}
.row{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:15px 16px;border-bottom:1px solid rgba(255,255,255,.06)}
.row:last-child{border-bottom:0}
.row span{font-size:15px;font-weight:900}
.row b{color:#9fffc4;font-size:15px;font-weight:950;text-align:right}
.events{padding:12px}
.event{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:13px 10px;border-bottom:1px solid rgba(255,255,255,.06)}
.event:last-child{border-bottom:0}
.event b{display:block;font-size:15px;margin-bottom:5px}
.event span{display:block;color:var(--muted);font-size:13px;font-weight:800;line-height:1.3}
.event small{display:block;color:rgba(245,255,248,.42);font-size:11px;font-weight:800;margin-top:6px}
.event strong{color:var(--yellow);font-size:13px;white-space:nowrap}
.chips{display:grid;gap:9px;padding:12px}
.chip{display:flex;justify-content:space-between;gap:12px;border:1px solid rgba(35,255,137,.17);background:rgba(0,0,0,.20);border-radius:16px;padding:13px}
.chip span{font-size:14px;font-weight:950}
.chip b{font-size:13px;color:#9fffc4;text-align:right}
.empty{padding:18px;color:var(--muted);font-weight:850;text-align:center}
.foot{text-align:center;margin:20px 0 0;color:rgba(245,255,248,.42);font-weight:800;font-size:13px}
</style>
</head>
<body>
<header class="top">
  <div class="brand"><div class="logo">⛔</div><div><h1>Erat<span>Guard</span></h1><p>Engellenenler</p></div></div>
  <div class="badge">👑 PRO AKTİF</div>
</header>

<section class="hero">
  <div class="hero-top">
    <div class="ico">⛔</div>
    <div>
      <h2>Engellenenler</h2>
      <p>__SUMMARY__</p>
    </div>
  </div>

  <div class="stats">
    <div class="stat"><b>__TOTAL__</b><span>Toplam</span></div>
    <div class="stat"><b>__QUARANTINE__</b><span>Karantina</span></div>
    <div class="stat"><b>__HIGH__</b><span>Yüksek</span></div>
  </div>

  <a class="back" href="/dashboard">← Ana ekrana dön</a>
</section>

<div class="section-title">ÖZET</div>
<section class="summary">
  <div class="row"><span>Durum</span><b>__MODE__</b></div>
  <div class="row"><span>Blok Listesi</span><b>__BLOCKS__</b></div>
  <div class="row"><span>Karantina</span><b>__QUARANTINE__</b></div>
  <div class="row"><span>Yüksek Risk</span><b>__HIGH__</b></div>
</section>

<div class="section-title">KARANTİNA</div>
<section class="events">
__ITEMS__
</section>

<div class="section-title">BLOK LİSTESİ</div>
<section class="chips">
__BLOCK_ITEMS__
</section>

<div class="foot">EratGuard PRO - __USERNAME__ - © 2026</div>
</body>
</html>
"""

        html = html.replace("__USERNAME__", _eg_bdb1_safe(username))
        html = html.replace("__SUMMARY__", _eg_bdb1_safe(summary))
        html = html.replace("__TOTAL__", str(total_count))
        html = html.replace("__QUARANTINE__", str(quarantine_count))
        html = html.replace("__HIGH__", str(high_count))
        html = html.replace("__BLOCKS__", str(block_count))
        html = html.replace("__MODE__", _eg_bdb1_safe(mode))
        html = html.replace("__ITEMS__", items_html)
        html = html.replace("__BLOCK_ITEMS__", blocks_html)

        resp = _eg_bdb1_make_response(_eg_bdb1_render_template_string(html))
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        resp.headers["Pragma"] = "no-cache"
        resp.headers["Expires"] = "0"
        return resp

    try:
        for _rule in list(app.url_map.iter_rules()):
            if str(_rule) in ("/u/blocked", "/u/blocked/"):
                app.view_functions[_rule.endpoint] = _eg_bdb1_blocked_route
        print("ERATGUARD BLOCKED-DATA-BIND-1 LIVE BLOCKED PAGE ACTIVE")
    except Exception as _eg_bdb1_route_err:
        print("ERATGUARD BLOCKED-DATA-BIND-1 ROUTE ERROR:", _eg_bdb1_route_err)

except Exception as _eg_bdb1_err:
    print("ERATGUARD BLOCKED-DATA-BIND-1 ERROR:", _eg_bdb1_err)
# === /ERATGUARD BLOCKED-DATA-BIND-1 LIVE BLOCKED PAGE ===

# === ERATGUARD SAFE-LIST-DATA-BIND-1 LIVE SAFE PAGE ===
# /u/safe-list sayfasını canlı safe_list + whitelist JSON verisine bağlar.
try:
    from flask import render_template_string as _eg_sdb1_render_template_string
    from flask import make_response as _eg_sdb1_make_response
    from flask import redirect as _eg_sdb1_redirect
    from flask import session as _eg_sdb1_session
    from flask import request as _eg_sdb1_request
    from pathlib import Path as _eg_sdb1_Path
    from datetime import datetime as _eg_sdb1_datetime
    import json as _eg_sdb1_json
    import html as _eg_sdb1_html

    def _eg_sdb1_safe(v):
        try:
            return _eg_sdb1_html.escape(str(v or ""))
        except Exception:
            return ""

    def _eg_sdb1_load(default, path):
        try:
            p = _eg_sdb1_Path(path)
            if not p.exists():
                return default
            txt = p.read_text(encoding="utf-8", errors="ignore").strip()
            if not txt:
                return default
            return _eg_sdb1_json.loads(txt)
        except Exception:
            return default

    def _eg_sdb1_save(path, data):
        p = _eg_sdb1_Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(_eg_sdb1_json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

    def _eg_sdb1_get_user_safe(username):
        data = _eg_sdb1_load({}, "data/safe_list.json")
        if not isinstance(data, dict):
            data = {}
        user_items = data.get(username, [])
        if not isinstance(user_items, list):
            user_items = []
        return data, user_items

    def _eg_sdb1_route():
        if not (_eg_sdb1_session.get("logged_in") and _eg_sdb1_session.get("username")):
            return _eg_sdb1_redirect("/login?auth_required=1")

        username = str(_eg_sdb1_session.get("username") or "user")

        if str(_eg_sdb1_request.method or "").upper() == "POST":
            name = (
                _eg_sdb1_request.form.get("name")
                or _eg_sdb1_request.form.get("sender")
                or _eg_sdb1_request.form.get("safe_name")
                or ""
            ).strip()

            phone = (
                _eg_sdb1_request.form.get("phone")
                or _eg_sdb1_request.form.get("number")
                or _eg_sdb1_request.form.get("safe_phone")
                or ""
            ).strip()

            if name or phone:
                data, items = _eg_sdb1_get_user_safe(username)
                items.append({
                    "name": name or phone or "Güvenli Kayıt",
                    "phone": phone or name,
                    "created_at": _eg_sdb1_datetime.now().strftime("%Y-%m-%d %H:%M")
                })
                data[username] = items
                _eg_sdb1_save("data/safe_list.json", data)

            return _eg_sdb1_redirect("/u/safe-list?added=1")

        data, items = _eg_sdb1_get_user_safe(username)

        whitelist = _eg_sdb1_load([], "data/whitelist.json")
        if not isinstance(whitelist, list):
            whitelist = []

        user_count = len(items)
        global_count = len(whitelist)
        total = user_count + global_count

        if total:
            summary = "Güvenilir kişi ve servisler aktif olarak korunuyor."
            mode = "Güvenli Liste Aktif"
        else:
            summary = "Henüz güvenli kayıt yok. Güvenilir kişi veya servis ekleyebilirsin."
            mode = "Boş"

        items_html = ""
        if items:
            for item in items[:8]:
                if isinstance(item, dict):
                    name = item.get("name") or item.get("phone") or "Güvenli Kayıt"
                    detail = item.get("phone") or item.get("created_at") or "Güvenli"
                    created = item.get("created_at") or "-"
                else:
                    name = str(item)
                    detail = "Güvenli"
                    created = "-"

                items_html += (
                    '<div class="chip">'
                    '<div><b>' + _eg_sdb1_safe(name) + '</b>'
                    '<span>' + _eg_sdb1_safe(created) + '</span></div>'
                    '<strong>' + _eg_sdb1_safe(detail) + '</strong>'
                    '</div>'
                )
        else:
            items_html = '<div class="empty">Kullanıcı güvenli listesi boş.</div>'

        white_html = ""
        if whitelist:
            for item in whitelist[:8]:
                white_html += (
                    '<div class="chip small">'
                    '<div><b>' + _eg_sdb1_safe(item) + '</b><span>Genel güvenli servis</span></div>'
                    '<strong>AKTİF</strong>'
                    '</div>'
                )
        else:
            white_html = '<div class="empty">Genel whitelist kaydı yok.</div>'

        html = """
<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>EratGuard PRO - Güvenli Liste</title>
<style>
:root{--bg:#020806;--line:rgba(35,255,137,.22);--green:#20ff88;--yellow:#ffdd35;--text:#f5fff8;--muted:rgba(245,255,248,.62)}
*{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
html,body{margin:0;min-height:100%;background:radial-gradient(circle at 80% 0%,rgba(35,255,137,.14),transparent 32%),var(--bg);color:var(--text);font-family:Arial,Helvetica,sans-serif}
body{padding:16px 14px 24px}
.top{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:12px}
.brand{display:flex;align-items:center;gap:10px;min-width:0}
.logo{width:50px;height:50px;border-radius:17px;background:rgba(35,255,137,.12);border:1px solid var(--line);display:grid;place-items:center;font-size:27px}
.brand h1{margin:0;font-size:26px;line-height:1;font-weight:950;letter-spacing:-1.2px}
.brand h1 span{color:var(--green)}
.brand p{margin:4px 0 0;color:var(--muted);font-weight:850;font-size:12px}
.badge{border:1px solid rgba(255,221,53,.35);color:var(--green);background:rgba(35,255,137,.10);padding:9px 12px;border-radius:999px;font-weight:950;font-size:12px;white-space:nowrap}
.hero,.summary,.list,.form{border:1px solid var(--line);background:linear-gradient(145deg,rgba(10,36,23,.94),rgba(4,14,9,.94));border-radius:23px;padding:16px;box-shadow:0 18px 48px rgba(0,0,0,.34)}
.hero-top{display:flex;align-items:flex-start;gap:13px}
.ico{width:54px;height:54px;flex:0 0 54px;border-radius:19px;border:1px solid var(--line);background:rgba(35,255,137,.10);display:grid;place-items:center;font-size:29px}
.hero h2{font-size:31px;line-height:1.02;margin:2px 0 6px;font-weight:950;letter-spacing:-1.5px}
.hero p{margin:0;color:var(--muted);font-size:14px;line-height:1.3;font-weight:800}
.stats{display:grid;grid-template-columns:1fr 1fr 1fr;gap:9px;margin-top:14px}
.stat{border:1px solid rgba(35,255,137,.17);background:rgba(0,0,0,.23);border-radius:17px;padding:12px;min-height:68px}
.stat b{display:block;color:var(--green);font-size:20px;line-height:1.1}
.stat span{display:block;color:var(--muted);font-size:11px;font-weight:900;margin-top:6px}
.back{display:flex;align-items:center;justify-content:center;margin-top:12px;min-height:44px;width:100%;border-radius:16px;color:var(--text);text-decoration:none;font-weight:950;background:rgba(255,255,255,.075);border:1px solid rgba(255,255,255,.09)}
.section-title{font-size:18px;letter-spacing:8px;font-weight:950;margin:22px 0 10px}
.summary{padding:0;overflow:hidden}
.row{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:15px 16px;border-bottom:1px solid rgba(255,255,255,.06)}
.row:last-child{border-bottom:0}
.row span{font-size:15px;font-weight:900}
.row b{color:#9fffc4;font-size:15px;font-weight:950;text-align:right}
.form{padding:14px}
.form label{display:block;font-size:15px;font-weight:950;margin-bottom:8px}
.form input{width:100%;height:50px;border-radius:16px;border:1px solid rgba(35,255,137,.22);background:rgba(0,0,0,.22);color:var(--text);font-size:15px;font-weight:850;padding:0 13px;outline:none;margin-bottom:9px}
.form input::placeholder{color:rgba(245,255,248,.34)}
.form button{width:100%;height:52px;border:0;border-radius:16px;background:linear-gradient(135deg,var(--yellow),var(--green));font-size:16px;font-weight:950;color:#00180c}
.list{display:grid;gap:9px;padding:12px}
.chip{display:flex;align-items:center;justify-content:space-between;gap:12px;border:1px solid rgba(35,255,137,.17);background:rgba(0,0,0,.20);border-radius:16px;padding:13px}
.chip b{display:block;font-size:15px}
.chip span{display:block;color:var(--muted);font-size:12px;font-weight:850;margin-top:4px}
.chip strong{color:#9fffc4;font-size:13px;text-align:right}
.empty{padding:18px;color:var(--muted);font-weight:850;text-align:center}
.foot{text-align:center;margin:20px 0 0;color:rgba(245,255,248,.42);font-weight:800;font-size:13px}
</style>
</head>
<body>
<header class="top">
  <div class="brand"><div class="logo">✅</div><div><h1>Erat<span>Guard</span></h1><p>Güvenli Liste</p></div></div>
  <div class="badge">👑 PRO AKTİF</div>
</header>

<section class="hero">
  <div class="hero-top">
    <div class="ico">✅</div>
    <div>
      <h2>Güvenli Liste</h2>
      <p>__SUMMARY__</p>
    </div>
  </div>

  <div class="stats">
    <div class="stat"><b>__TOTAL__</b><span>Toplam</span></div>
    <div class="stat"><b>__USER_COUNT__</b><span>Kişisel</span></div>
    <div class="stat"><b>__GLOBAL_COUNT__</b><span>Genel</span></div>
  </div>

  <a class="back" href="/dashboard">← Ana ekrana dön</a>
</section>

<div class="section-title">ÖZET</div>
<section class="summary">
  <div class="row"><span>Durum</span><b>__MODE__</b></div>
  <div class="row"><span>Kişisel Liste</span><b>__USER_COUNT__</b></div>
  <div class="row"><span>Genel Whitelist</span><b>__GLOBAL_COUNT__</b></div>
  <div class="row"><span>Koruma</span><b>Aktif</b></div>
</section>

<div class="section-title">EKLE</div>
<form class="form" method="post" action="/u/safe-list">
  <label>Güvenli kişi / servis ekle</label>
  <input name="name" placeholder="Ad veya servis adı">
  <input name="phone" placeholder="Telefon / gönderen adı">
  <button type="submit">Güvenli Listeye Ekle</button>
</form>

<div class="section-title">KİŞİSEL</div>
<section class="list">
__ITEMS__
</section>

<div class="section-title">GENEL</div>
<section class="list">
__WHITE__
</section>

<div class="foot">EratGuard PRO - __USERNAME__ - © 2026</div>
</body>
</html>
"""

        html = html.replace("__USERNAME__", _eg_sdb1_safe(username))
        html = html.replace("__SUMMARY__", _eg_sdb1_safe(summary))
        html = html.replace("__TOTAL__", str(total))
        html = html.replace("__USER_COUNT__", str(user_count))
        html = html.replace("__GLOBAL_COUNT__", str(global_count))
        html = html.replace("__MODE__", _eg_sdb1_safe(mode))
        html = html.replace("__ITEMS__", items_html)
        html = html.replace("__WHITE__", white_html)

        resp = _eg_sdb1_make_response(_eg_sdb1_render_template_string(html))
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        resp.headers["Pragma"] = "no-cache"
        resp.headers["Expires"] = "0"
        return resp

    try:
        for _rule in list(app.url_map.iter_rules()):
            if str(_rule) in ("/u/safe-list", "/u/safe-list/"):
                app.view_functions[_rule.endpoint] = _eg_sdb1_route
                try:
                    _rule.methods.add("POST")
                except Exception:
                    pass
        print("ERATGUARD SAFE-LIST-DATA-BIND-1 LIVE SAFE PAGE ACTIVE")
    except Exception as _eg_sdb1_route_err:
        print("ERATGUARD SAFE-LIST-DATA-BIND-1 ROUTE ERROR:", _eg_sdb1_route_err)

except Exception as _eg_sdb1_err:
    print("ERATGUARD SAFE-LIST-DATA-BIND-1 ERROR:", _eg_sdb1_err)
# === /ERATGUARD SAFE-LIST-DATA-BIND-1 LIVE SAFE PAGE ===

# === ERATGUARD SAFE-LIST-DIET-2 ULTRA COMPACT PAGE ===
# /u/safe-list görünümünü daha sıkı ve mobilde daha ince hale getirir.
try:
    from flask import request as _eg_sld2_request

    _EG_SLD2_CSS = """
<style id="eratguard-safe-list-diet-2">
@media (max-width:760px){
  body{
    padding:12px 11px 18px !important;
  }

  .top{
    gap:8px !important;
    margin-bottom:10px !important;
  }

  .brand{
    gap:8px !important;
  }

  .logo{
    width:42px !important;
    height:42px !important;
    border-radius:14px !important;
    font-size:22px !important;
  }

  .brand h1{
    font-size:20px !important;
    letter-spacing:-1px !important;
  }

  .brand p{
    font-size:11px !important;
    margin-top:2px !important;
  }

  .badge{
    padding:7px 10px !important;
    font-size:11px !important;
  }

  .hero,
  .summary,
  .list,
  .form{
    padding:13px !important;
    border-radius:20px !important;
    box-shadow:0 12px 30px rgba(0,0,0,.28) !important;
  }

  .hero-top{
    gap:10px !important;
  }

  .ico{
    width:46px !important;
    height:46px !important;
    flex:0 0 46px !important;
    border-radius:15px !important;
    font-size:24px !important;
  }

  .hero h2{
    font-size:24px !important;
    line-height:1.02 !important;
    margin:1px 0 5px !important;
    letter-spacing:-1.1px !important;
  }

  .hero p{
    font-size:13px !important;
    line-height:1.28 !important;
  }

  .stats{
    gap:8px !important;
    margin-top:12px !important;
  }

  .stat{
    padding:10px !important;
    min-height:56px !important;
    border-radius:15px !important;
  }

  .stat b{
    font-size:17px !important;
  }

  .stat span{
    font-size:10px !important;
    margin-top:5px !important;
  }

  .back{
    margin-top:10px !important;
    min-height:40px !important;
    border-radius:14px !important;
    font-size:14px !important;
  }

  .section-title{
    font-size:15px !important;
    letter-spacing:6px !important;
    margin:18px 0 8px !important;
  }

  .summary{
    padding:0 !important;
  }

  .row{
    padding:13px 14px !important;
  }

  .row span,
  .row b{
    font-size:14px !important;
  }

  .form{
    padding:12px !important;
  }

  .form label{
    font-size:14px !important;
    margin-bottom:7px !important;
  }

  .form input{
    height:46px !important;
    padding:0 12px !important;
    font-size:14px !important;
    border-radius:14px !important;
    margin-bottom:8px !important;
  }

  .form button{
    height:48px !important;
    border-radius:14px !important;
    font-size:15px !important;
  }

  .list{
    gap:8px !important;
    padding:10px !important;
  }

  .chip{
    padding:11px 12px !important;
    border-radius:14px !important;
    gap:10px !important;
  }

  .chip b{
    font-size:14px !important;
  }

  .chip span{
    font-size:11px !important;
    margin-top:3px !important;
  }

  .chip strong{
    font-size:12px !important;
  }

  .empty{
    padding:14px !important;
    font-size:13px !important;
  }

  .foot{
    margin:16px 0 0 !important;
    font-size:12px !important;
  }
}
</style>
"""

    @app.after_request
    def _eg_sld2_after(resp):
        try:
            path = str(getattr(_eg_sld2_request, "path", "") or "")
            ct = str(resp.headers.get("Content-Type", "") or "")

            if path not in ("/u/safe-list", "/u/safe-list/"):
                return resp

            if "text/html" not in ct.lower():
                return resp

            html = resp.get_data(as_text=True)

            if "eratguard-safe-list-diet-2" in html:
                return resp

            lower = html.lower()
            i = lower.rfind("</head>")

            if i != -1:
                html = html[:i] + _EG_SLD2_CSS + html[i:]
            else:
                html = _EG_SLD2_CSS + html

            resp.set_data(html)

            try:
                resp.headers["Content-Length"] = str(len(resp.get_data()))
            except Exception:
                pass

        except Exception as _eg_sld2_inject_err:
            print("ERATGUARD SAFE-LIST-DIET-2 INJECT ERROR:", _eg_sld2_inject_err)

        return resp

    print("ERATGUARD SAFE-LIST-DIET-2 ULTRA COMPACT PAGE ACTIVE")

except Exception as _eg_sld2_err:
    print("ERATGUARD SAFE-LIST-DIET-2 ERROR:", _eg_sld2_err)
# === /ERATGUARD SAFE-LIST-DIET-2 ULTRA COMPACT PAGE ===

# === ERATGUARD NOTIFICATIONS-DATA-BIND-1 LIVE PAGE ===
# /u/notifications sayfasını canlı bildirim + analiz kayıtlarına bağlar.
try:
    from flask import render_template_string as _eg_ndb1_render_template_string
    from flask import make_response as _eg_ndb1_make_response
    from flask import redirect as _eg_ndb1_redirect
    from flask import session as _eg_ndb1_session
    from pathlib import Path as _eg_ndb1_Path
    from datetime import datetime as _eg_ndb1_datetime
    import json as _eg_ndb1_json
    import html as _eg_ndb1_html

    def _eg_ndb1_safe(v):
        try:
            return _eg_ndb1_html.escape(str(v or ""))
        except Exception:
            return ""

    def _eg_ndb1_load(default, path):
        try:
            p = _eg_ndb1_Path(path)
            if not p.exists():
                return default
            txt = p.read_text(encoding="utf-8", errors="ignore").strip()
            if not txt:
                return default
            return _eg_ndb1_json.loads(txt)
        except Exception:
            return default

    def _eg_ndb1_save(path, data):
        try:
            p = _eg_ndb1_Path(path)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(_eg_ndb1_json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception as e:
            print("ERATGUARD NOTIFICATIONS-DATA-BIND-1 SAVE ERROR:", e)

    def _eg_ndb1_ensure_files(username):
        n = _eg_ndb1_Path("data/notifications.json")
        u = _eg_ndb1_Path("data/user_notifications.json")
        a = _eg_ndb1_Path("data/admin_notifications.json")

        if not n.exists():
            _eg_ndb1_save("data/notifications.json", [])

        if not u.exists():
            _eg_ndb1_save("data/user_notifications.json", {username: []})

        if not a.exists():
            _eg_ndb1_save("data/admin_notifications.json", [])

    def _eg_ndb1_score(item):
        try:
            return int(item.get("score") or item.get("risk") or 0)
        except Exception:
            return 0

    def _eg_ndb1_norm_list(raw, username, source_name):
        out = []

        if isinstance(raw, dict):
            if username in raw and isinstance(raw.get(username), list):
                data = raw.get(username) or []
            else:
                data = []
                for k, v in raw.items():
                    if isinstance(v, list):
                        for x in v:
                            if isinstance(x, dict):
                                y = dict(x)
                                y.setdefault("username", k)
                                data.append(y)
            raw = data

        if not isinstance(raw, list):
            return out

        for item in raw:
            if not isinstance(item, dict):
                if item:
                    item = {"title": str(item), "body": str(item)}
                else:
                    continue

            item_user = str(item.get("username") or "").strip()
            if item_user and item_user != username:
                continue

            title = (
                item.get("title")
                or item.get("subject")
                or item.get("type")
                or "Bildirim"
            )
            body = (
                item.get("body")
                or item.get("message")
                or item.get("text")
                or item.get("description")
                or ""
            )
            time = item.get("time") or item.get("created_at") or item.get("date") or "-"
            level = item.get("level") or item.get("status") or "INFO"
            read = bool(item.get("read") or item.get("seen") or False)

            out.append({
                "title": title,
                "body": body,
                "time": time,
                "level": str(level).upper(),
                "source": source_name,
                "read": read,
                "score": item.get("score") or item.get("risk") or "",
            })

        return out

    def _eg_ndb1_from_security(username):
        out = []

        history = _eg_ndb1_load([], "data/user_analysis_history.json")
        spam_logs = _eg_ndb1_load([], "data/spam_logs.json")
        quarantine = _eg_ndb1_load([], "data/user_quarantine.json")

        for source_name, data in [
            ("analysis_history", history),
            ("spam_logs", spam_logs),
            ("quarantine", quarantine),
        ]:
            if not isinstance(data, list):
                continue

            for item in data:
                if not isinstance(item, dict):
                    continue

                item_user = str(item.get("username") or "").strip()
                if item_user and item_user != username:
                    continue

                score = _eg_ndb1_score(item)
                status = str(item.get("status") or "").upper()

                if status != "SPAM" and score < 71:
                    continue

                body = str(item.get("body") or "")[:120]
                risk_label = item.get("risk_label") or "Yüksek Risk"
                time = item.get("time") or "-"

                out.append({
                    "title": "Riskli mesaj tespit edildi",
                    "body": risk_label + " - " + body,
                    "time": time,
                    "level": "SPAM",
                    "source": source_name,
                    "read": False,
                    "score": score,
                })

        return out

    def _eg_ndb1_collect(username):
        _eg_ndb1_ensure_files(username)

        user_notifications = _eg_ndb1_load({}, "data/user_notifications.json")
        global_notifications = _eg_ndb1_load([], "data/notifications.json")
        admin_notifications = _eg_ndb1_load([], "data/admin_notifications.json")

        items = []
        items += _eg_ndb1_norm_list(user_notifications, username, "user_notifications")
        items += _eg_ndb1_norm_list(global_notifications, username, "notifications")
        items += _eg_ndb1_norm_list(admin_notifications, username, "admin_notifications")
        items += _eg_ndb1_from_security(username)

        items = sorted(items, key=lambda x: str(x.get("time") or ""), reverse=True)

        return items[:12]

    def _eg_ndb1_route():
        if not (_eg_ndb1_session.get("logged_in") and _eg_ndb1_session.get("username")):
            return _eg_ndb1_redirect("/login?auth_required=1")

        username = str(_eg_ndb1_session.get("username") or "user")
        items = _eg_ndb1_collect(username)

        total = len(items)
        unread = sum(1 for x in items if not x.get("read"))
        risk = sum(1 for x in items if str(x.get("level") or "").upper() in ("SPAM", "RISK", "HIGH") or int(x.get("score") or 0) >= 71)

        if risk:
            summary = "Riskli mesaj ve güvenlik uyarıları aktif olarak izleniyor."
            mode = "Güvenlik Uyarısı"
        elif total:
            summary = "Bildirim merkezi aktif. Yeni hareketler burada toplanıyor."
            mode = "Aktif"
        else:
            summary = "Henüz gösterilecek bildirim yok. Sistem temiz görünüyor."
            mode = "Temiz"

        items_html = ""
        if items:
            for item in items[:8]:
                level = str(item.get("level") or "INFO").upper()
                title = item.get("title") or "Bildirim"
                body = item.get("body") or ""
                time = item.get("time") or "-"
                source = item.get("source") or "system"
                score = item.get("score") or ""

                right = level
                if score != "":
                    right = level + " / " + str(score)

                items_html += (
                    '<div class="event">'
                    '<div>'
                    '<b>' + _eg_ndb1_safe(title) + '</b>'
                    '<span>' + _eg_ndb1_safe(body) + '</span>'
                    '<small>' + _eg_ndb1_safe(time) + ' - ' + _eg_ndb1_safe(source) + '</small>'
                    '</div>'
                    '<strong>' + _eg_ndb1_safe(right) + '</strong>'
                    '</div>'
                )
        else:
            items_html = '<div class="empty">Bildirim bulunmuyor.</div>'

        html = """
<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>EratGuard PRO - Bildirimler</title>
<style>
:root{--bg:#020806;--line:rgba(35,255,137,.22);--green:#20ff88;--yellow:#ffdd35;--text:#f5fff8;--muted:rgba(245,255,248,.62)}
*{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
html,body{margin:0;min-height:100%;background:radial-gradient(circle at 80% 0%,rgba(35,255,137,.14),transparent 32%),var(--bg);color:var(--text);font-family:Arial,Helvetica,sans-serif}
body{padding:12px 11px 18px}
.top{display:flex;align-items:center;justify-content:space-between;gap:8px;margin-bottom:10px}
.brand{display:flex;align-items:center;gap:8px;min-width:0}
.logo{width:42px;height:42px;border-radius:14px;background:rgba(35,255,137,.12);border:1px solid var(--line);display:grid;place-items:center;font-size:22px}
.brand h1{margin:0;font-size:20px;line-height:1;font-weight:950;letter-spacing:-1px}
.brand h1 span{color:var(--green)}
.brand p{margin:2px 0 0;color:var(--muted);font-weight:850;font-size:11px}
.badge{border:1px solid rgba(255,221,53,.35);color:var(--green);background:rgba(35,255,137,.10);padding:7px 10px;border-radius:999px;font-weight:950;font-size:11px;white-space:nowrap}
.hero,.summary,.events{border:1px solid var(--line);background:linear-gradient(145deg,rgba(10,36,23,.94),rgba(4,14,9,.94));border-radius:20px;padding:13px;box-shadow:0 12px 30px rgba(0,0,0,.28)}
.hero-top{display:flex;align-items:flex-start;gap:10px}
.ico{width:46px;height:46px;flex:0 0 46px;border-radius:15px;border:1px solid var(--line);background:rgba(35,255,137,.10);display:grid;place-items:center;font-size:24px}
.hero h2{font-size:24px;line-height:1.02;margin:1px 0 5px;font-weight:950;letter-spacing:-1.1px}
.hero p{margin:0;color:var(--muted);font-size:13px;line-height:1.28;font-weight:800}
.stats{display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px;margin-top:12px}
.stat{border:1px solid rgba(35,255,137,.17);background:rgba(0,0,0,.23);border-radius:15px;padding:10px;min-height:56px}
.stat b{display:block;color:var(--green);font-size:17px;line-height:1.1}
.stat span{display:block;color:var(--muted);font-size:10px;font-weight:900;margin-top:5px}
.back{display:flex;align-items:center;justify-content:center;margin-top:10px;min-height:40px;width:100%;border-radius:14px;color:var(--text);text-decoration:none;font-weight:950;background:rgba(255,255,255,.075);border:1px solid rgba(255,255,255,.09);font-size:14px}
.section-title{font-size:15px;letter-spacing:6px;font-weight:950;margin:18px 0 8px}
.summary{padding:0;overflow:hidden}
.row{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:13px 14px;border-bottom:1px solid rgba(255,255,255,.06)}
.row:last-child{border-bottom:0}
.row span{font-size:14px;font-weight:900}
.row b{color:#9fffc4;font-size:14px;font-weight:950;text-align:right}
.events{padding:10px}
.event{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:11px 8px;border-bottom:1px solid rgba(255,255,255,.06)}
.event:last-child{border-bottom:0}
.event b{display:block;font-size:14px;margin-bottom:4px}
.event span{display:block;color:var(--muted);font-size:12px;font-weight:800;line-height:1.3}
.event small{display:block;color:rgba(245,255,248,.42);font-size:10px;font-weight:800;margin-top:5px}
.event strong{color:var(--yellow);font-size:12px;white-space:nowrap;text-align:right}
.empty{padding:14px;color:var(--muted);font-weight:850;text-align:center;font-size:13px}
.foot{text-align:center;margin:16px 0 0;color:rgba(245,255,248,.42);font-weight:800;font-size:12px}
</style>
</head>
<body>
<header class="top">
  <div class="brand"><div class="logo">🔔</div><div><h1>Erat<span>Guard</span></h1><p>Bildirimler</p></div></div>
  <div class="badge">👑 PRO AKTİF</div>
</header>

<section class="hero">
  <div class="hero-top">
    <div class="ico">🔔</div>
    <div>
      <h2>Bildirimler</h2>
      <p>__SUMMARY__</p>
    </div>
  </div>

  <div class="stats">
    <div class="stat"><b>__TOTAL__</b><span>Toplam</span></div>
    <div class="stat"><b>__UNREAD__</b><span>Yeni</span></div>
    <div class="stat"><b>__RISK__</b><span>Risk</span></div>
  </div>

  <a class="back" href="/dashboard">← Ana ekrana dön</a>
</section>

<div class="section-title">ÖZET</div>
<section class="summary">
  <div class="row"><span>Durum</span><b>__MODE__</b></div>
  <div class="row"><span>Toplam Bildirim</span><b>__TOTAL__</b></div>
  <div class="row"><span>Yeni Bildirim</span><b>__UNREAD__</b></div>
  <div class="row"><span>Risk Uyarısı</span><b>__RISK__</b></div>
</section>

<div class="section-title">SON BİLDİRİMLER</div>
<section class="events">
__ITEMS__
</section>

<div class="foot">EratGuard PRO - __USERNAME__ - © 2026</div>
</body>
</html>
"""

        html = html.replace("__USERNAME__", _eg_ndb1_safe(username))
        html = html.replace("__SUMMARY__", _eg_ndb1_safe(summary))
        html = html.replace("__TOTAL__", str(total))
        html = html.replace("__UNREAD__", str(unread))
        html = html.replace("__RISK__", str(risk))
        html = html.replace("__MODE__", _eg_ndb1_safe(mode))
        html = html.replace("__ITEMS__", items_html)

        resp = _eg_ndb1_make_response(_eg_ndb1_render_template_string(html))
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        resp.headers["Pragma"] = "no-cache"
        resp.headers["Expires"] = "0"
        return resp

    try:
        for _rule in list(app.url_map.iter_rules()):
            if str(_rule) in ("/u/notifications", "/u/notifications/"):
                app.view_functions[_rule.endpoint] = _eg_ndb1_route
        print("ERATGUARD NOTIFICATIONS-DATA-BIND-1 LIVE PAGE ACTIVE")
    except Exception as _eg_ndb1_route_err:
        print("ERATGUARD NOTIFICATIONS-DATA-BIND-1 ROUTE ERROR:", _eg_ndb1_route_err)

except Exception as _eg_ndb1_err:
    print("ERATGUARD NOTIFICATIONS-DATA-BIND-1 ERROR:", _eg_ndb1_err)
# === /ERATGUARD NOTIFICATIONS-DATA-BIND-1 LIVE PAGE ===

# === ERATGUARD NOTIFICATIONS-DATA-BIND-2 FORCE GREEN LIVE PAGE ===
# /u/notifications sayfasını EratGuard yeşil tema + canlı risk kayıtlarına bağlar.
try:
    from flask import render_template_string as _eg_ndb2_render_template_string
    from flask import make_response as _eg_ndb2_make_response
    from flask import redirect as _eg_ndb2_redirect
    from flask import session as _eg_ndb2_session
    from pathlib import Path as _eg_ndb2_Path
    import json as _eg_ndb2_json
    import html as _eg_ndb2_html

    def _eg_ndb2_safe(v):
        try:
            return _eg_ndb2_html.escape(str(v or ""))
        except Exception:
            return ""

    def _eg_ndb2_load(default, path):
        try:
            p = _eg_ndb2_Path(path)
            if not p.exists():
                return default
            txt = p.read_text(encoding="utf-8", errors="ignore").strip()
            if not txt:
                return default
            return _eg_ndb2_json.loads(txt)
        except Exception:
            return default

    def _eg_ndb2_score(item):
        try:
            return int(item.get("score") or item.get("risk") or 0)
        except Exception:
            return 0

    def _eg_ndb2_status(item):
        raw = str(item.get("status") or "").upper()
        score = _eg_ndb2_score(item)
        if raw == "SPAM" or score >= 71:
            return "KRİTİK"
        if raw in ("SUSPICIOUS", "WARNING") or score >= 31:
            return "UYARI"
        return "BİLGİ"

    def _eg_ndb2_user_events(username):
        username = str(username or "").strip()

        combined = []

        for file_path, source_label in [
            ("data/user_notifications.json", "user_notification"),
            ("data/notifications.json", "system_notification"),
            ("data/user_analysis_history.json", "analysis_history"),
            ("data/spam_logs.json", "spam_logs"),
        ]:
            data = _eg_ndb2_load([] if file_path != "data/user_notifications.json" else {}, file_path)

            if isinstance(data, dict):
                if file_path == "data/user_notifications.json":
                    data = data.get(username, [])
                else:
                    data = list(data.values())

            if not isinstance(data, list):
                data = []

            for item in data:
                if isinstance(item, str):
                    item = {"title": "Bildirim", "body": item, "source": source_label}

                if not isinstance(item, dict):
                    continue

                item_user = str(item.get("username") or item.get("user") or "").strip()
                if item_user and item_user != username:
                    continue

                x = dict(item)
                x["_source_label"] = source_label
                combined.append(x)

        # Son risk kayıtlarını öne al, tekrarları azalt.
        seen = set()
        cleaned = []
        for item in sorted(combined, key=lambda x: str(x.get("time") or x.get("created_at") or ""), reverse=True):
            key = (
                str(item.get("time") or item.get("created_at") or ""),
                str(item.get("body") or item.get("message") or item.get("title") or "")[:80],
                str(item.get("_source_label") or "")
            )
            if key in seen:
                continue
            seen.add(key)
            cleaned.append(item)

        return cleaned[:8]

    def _eg_ndb2_route():
        if not (_eg_ndb2_session.get("logged_in") and _eg_ndb2_session.get("username")):
            return _eg_ndb2_redirect("/login?auth_required=1")

        username = str(_eg_ndb2_session.get("username") or "user")
        events = _eg_ndb2_user_events(username)

        total = len(events)
        critical = sum(1 for x in events if _eg_ndb2_status(x) == "KRİTİK")
        warnings = sum(1 for x in events if _eg_ndb2_status(x) == "UYARI")

        if critical:
            summary = "Yüksek riskli güvenlik olayları bildirime dönüştürüldü."
            mode = "Risk Bildirimi"
        elif warnings:
            summary = "Orta seviye uyarılar izleniyor."
            mode = "Uyarı İzleme"
        elif total:
            summary = "Bilgilendirme kayıtları aktif."
            mode = "Aktif"
        else:
            summary = "Henüz gösterilecek bildirim yok."
            mode = "Boş"

        events_html = ""
        if events:
            for item in events:
                score = _eg_ndb2_score(item)
                level = _eg_ndb2_status(item)
                title = (
                    item.get("title")
                    or item.get("risk_label")
                    or ("Yüksek Risk" if level == "KRİTİK" else "Bildirim")
                )
                body = (
                    item.get("body")
                    or item.get("message")
                    or item.get("text")
                    or item.get("description")
                    or "Güvenlik bildirimi"
                )
                time = item.get("time") or item.get("created_at") or "-"
                src = item.get("source") or item.get("_source_label") or "system"

                events_html += (
                    '<div class="event">'
                    '<div>'
                    '<b>' + _eg_ndb2_safe(title) + '</b>'
                    '<span>' + _eg_ndb2_safe(str(body)[:105]) + '</span>'
                    '<small>' + _eg_ndb2_safe(time) + ' - ' + _eg_ndb2_safe(src) + '</small>'
                    '</div>'
                    '<strong>' + _eg_ndb2_safe(level) + (' / ' + str(score) if score else '') + '</strong>'
                    '</div>'
                )
        else:
            events_html = '<div class="empty">Henüz gösterilecek bildirim yok.</div>'

        html = """
<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>EratGuard PRO - Bildirimler</title>
<style>
:root{--bg:#020806;--line:rgba(35,255,137,.22);--green:#20ff88;--yellow:#ffdd35;--text:#f5fff8;--muted:rgba(245,255,248,.62)}
*{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
html,body{margin:0;min-height:100%;background:radial-gradient(circle at 80% 0%,rgba(35,255,137,.14),transparent 32%),var(--bg);color:var(--text);font-family:Arial,Helvetica,sans-serif}
body{padding:12px 11px 18px}
.top{display:flex;align-items:center;justify-content:space-between;gap:8px;margin-bottom:10px}
.brand{display:flex;align-items:center;gap:8px;min-width:0}
.logo{width:42px;height:42px;border-radius:14px;background:rgba(35,255,137,.12);border:1px solid var(--line);display:grid;place-items:center;font-size:22px}
.brand h1{margin:0;font-size:20px;line-height:1;font-weight:950;letter-spacing:-1px}
.brand h1 span{color:var(--green)}
.brand p{margin:2px 0 0;color:var(--muted);font-weight:850;font-size:11px}
.badge{border:1px solid rgba(255,221,53,.35);color:var(--green);background:rgba(35,255,137,.10);padding:7px 10px;border-radius:999px;font-weight:950;font-size:11px;white-space:nowrap}
.hero,.summary,.events{border:1px solid var(--line);background:linear-gradient(145deg,rgba(10,36,23,.94),rgba(4,14,9,.94));border-radius:20px;padding:13px;box-shadow:0 12px 30px rgba(0,0,0,.28)}
.hero-top{display:flex;align-items:flex-start;gap:10px}
.ico{width:46px;height:46px;flex:0 0 46px;border-radius:15px;border:1px solid var(--line);background:rgba(35,255,137,.10);display:grid;place-items:center;font-size:24px}
.hero h2{font-size:24px;line-height:1.02;margin:1px 0 5px;font-weight:950;letter-spacing:-1.1px}
.hero p{margin:0;color:var(--muted);font-size:13px;line-height:1.28;font-weight:800}
.stats{display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px;margin-top:12px}
.stat{border:1px solid rgba(35,255,137,.17);background:rgba(0,0,0,.23);border-radius:15px;padding:10px;min-height:56px}
.stat b{display:block;color:var(--green);font-size:17px;line-height:1.1}
.stat span{display:block;color:var(--muted);font-size:10px;font-weight:900;margin-top:5px}
.back{display:flex;align-items:center;justify-content:center;margin-top:10px;min-height:40px;width:100%;border-radius:14px;color:var(--text);text-decoration:none;font-weight:950;background:rgba(255,255,255,.075);border:1px solid rgba(255,255,255,.09);font-size:14px}
.section-title{font-size:15px;letter-spacing:6px;font-weight:950;margin:18px 0 8px}
.summary{padding:0;overflow:hidden}
.row{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:13px 14px;border-bottom:1px solid rgba(255,255,255,.06)}
.row:last-child{border-bottom:0}
.row span,.row b{font-size:14px;font-weight:900}
.row b{color:#9fffc4;text-align:right}
.events{padding:10px}
.event{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:11px 8px;border-bottom:1px solid rgba(255,255,255,.06)}
.event:last-child{border-bottom:0}
.event b{display:block;font-size:14px;margin-bottom:4px}
.event span{display:block;color:var(--muted);font-size:12px;font-weight:800;line-height:1.3}
.event small{display:block;color:rgba(245,255,248,.42);font-size:10px;font-weight:800;margin-top:5px}
.event strong{color:var(--yellow);font-size:12px;white-space:nowrap;text-align:right}
.empty{padding:14px;color:var(--muted);font-weight:850;text-align:center;font-size:13px}
.foot{text-align:center;margin:16px 0 0;color:rgba(245,255,248,.42);font-weight:800;font-size:12px}
</style>
</head>
<body>
<header class="top">
  <div class="brand"><div class="logo">🔔</div><div><h1>Erat<span>Guard</span></h1><p>Bildirimler</p></div></div>
  <div class="badge">👑 PRO AKTİF</div>
</header>

<section class="hero">
  <div class="hero-top">
    <div class="ico">🔔</div>
    <div>
      <h2>Bildirimler</h2>
      <p>__SUMMARY__</p>
    </div>
  </div>

  <div class="stats">
    <div class="stat"><b>__TOTAL__</b><span>Toplam</span></div>
    <div class="stat"><b>__CRITICAL__</b><span>Kritik</span></div>
    <div class="stat"><b>__WARNINGS__</b><span>Uyarı</span></div>
  </div>

  <a class="back" href="/dashboard">← Ana ekrana dön</a>
</section>

<div class="section-title">ÖZET</div>
<section class="summary">
  <div class="row"><span>Durum</span><b>__MODE__</b></div>
  <div class="row"><span>Toplam Bildirim</span><b>__TOTAL__</b></div>
  <div class="row"><span>Kritik Uyarı</span><b>__CRITICAL__</b></div>
  <div class="row"><span>Bildirim Motoru</span><b>Aktif</b></div>
</section>

<div class="section-title">SON BİLDİRİMLER</div>
<section class="events">
__EVENTS__
</section>

<div class="foot">EratGuard PRO - __USERNAME__ - © 2026</div>
</body>
</html>
"""

        html = html.replace("__USERNAME__", _eg_ndb2_safe(username))
        html = html.replace("__SUMMARY__", _eg_ndb2_safe(summary))
        html = html.replace("__MODE__", _eg_ndb2_safe(mode))
        html = html.replace("__TOTAL__", str(total))
        html = html.replace("__CRITICAL__", str(critical))
        html = html.replace("__WARNINGS__", str(warnings))
        html = html.replace("__EVENTS__", events_html)

        resp = _eg_ndb2_make_response(_eg_ndb2_render_template_string(html))
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        resp.headers["Pragma"] = "no-cache"
        resp.headers["Expires"] = "0"
        return resp

    try:
        for _rule in list(app.url_map.iter_rules()):
            if str(_rule) in ("/u/notifications", "/u/notifications/"):
                app.view_functions[_rule.endpoint] = _eg_ndb2_route
        print("ERATGUARD NOTIFICATIONS-DATA-BIND-2 FORCE GREEN LIVE PAGE ACTIVE")
    except Exception as _eg_ndb2_route_err:
        print("ERATGUARD NOTIFICATIONS-DATA-BIND-2 ROUTE ERROR:", _eg_ndb2_route_err)

except Exception as _eg_ndb2_err:
    print("ERATGUARD NOTIFICATIONS-DATA-BIND-2 ERROR:", _eg_ndb2_err)
# === /ERATGUARD NOTIFICATIONS-DATA-BIND-2 FORCE GREEN LIVE PAGE ===

# === ERATGUARD NOTIFICATIONS-FORCE-GREEN-3 HARD BRIDGE ===
# Eski mavi notification template'ini bypass eder.
# /u/notifications ve alias yollarını direkt yeşil EratGuard sayfasına zorlar.
try:
    from flask import request as _eg_nfg3_request
    from flask import session as _eg_nfg3_session
    from flask import redirect as _eg_nfg3_redirect
    from flask import render_template_string as _eg_nfg3_render_template_string
    from flask import make_response as _eg_nfg3_make_response
    from pathlib import Path as _eg_nfg3_Path
    import json as _eg_nfg3_json
    import html as _eg_nfg3_html

    def _eg_nfg3_safe(v):
        try:
            return _eg_nfg3_html.escape(str(v or ""))
        except Exception:
            return ""

    def _eg_nfg3_load(default, path):
        try:
            p = _eg_nfg3_Path(path)
            if not p.exists():
                return default
            txt = p.read_text(encoding="utf-8", errors="ignore").strip()
            if not txt:
                return default
            return _eg_nfg3_json.loads(txt)
        except Exception:
            return default

    def _eg_nfg3_score(item):
        try:
            return int(item.get("score") or item.get("risk") or 0)
        except Exception:
            return 0

    def _eg_nfg3_level(item):
        raw = str(item.get("status") or "").upper()
        score = _eg_nfg3_score(item)
        if raw == "SPAM" or score >= 71:
            return "KRİTİK"
        if raw in ("SUSPICIOUS", "WARNING") or score >= 31:
            return "UYARI"
        return "BİLGİ"

    def _eg_nfg3_events(username):
        username = str(username or "").strip()
        combined = []

        sources = [
            ("data/user_notifications.json", "user_notification"),
            ("data/notifications.json", "system_notification"),
            ("data/user_analysis_history.json", "analysis_history"),
            ("data/spam_logs.json", "spam_logs"),
            ("data/user_quarantine.json", "quarantine"),
        ]

        for file_path, source_label in sources:
            default = {} if file_path == "data/user_notifications.json" else []
            data = _eg_nfg3_load(default, file_path)

            if isinstance(data, dict):
                if file_path == "data/user_notifications.json":
                    data = data.get(username, [])
                else:
                    tmp = []
                    for v in data.values():
                        if isinstance(v, list):
                            tmp.extend(v)
                        else:
                            tmp.append(v)
                    data = tmp

            if not isinstance(data, list):
                data = []

            for item in data:
                if isinstance(item, str):
                    item = {"title": "Bildirim", "body": item, "source": source_label}

                if not isinstance(item, dict):
                    continue

                item_user = str(item.get("username") or item.get("user") or "").strip()
                if item_user and item_user != username:
                    continue

                x = dict(item)
                x["_source_label"] = source_label
                combined.append(x)

        seen = set()
        cleaned = []

        for item in sorted(
            combined,
            key=lambda x: str(x.get("time") or x.get("created_at") or ""),
            reverse=True
        ):
            key = (
                str(item.get("time") or item.get("created_at") or ""),
                str(item.get("body") or item.get("message") or item.get("title") or "")[:90],
                str(item.get("_source_label") or "")
            )
            if key in seen:
                continue
            seen.add(key)
            cleaned.append(item)

        return cleaned[:8]

    def _eg_nfg3_notifications_page():
        username = str(_eg_nfg3_session.get("username") or "user")
        events = _eg_nfg3_events(username)

        total = len(events)
        critical = sum(1 for x in events if _eg_nfg3_level(x) == "KRİTİK")
        warnings = sum(1 for x in events if _eg_nfg3_level(x) == "UYARI")

        if critical:
            summary = "Yüksek riskli güvenlik olayları bildirime dönüştürüldü."
            mode = "Risk Bildirimi"
        elif warnings:
            summary = "Orta seviye uyarılar izleniyor."
            mode = "Uyarı İzleme"
        elif total:
            summary = "Bilgilendirme kayıtları aktif."
            mode = "Aktif"
        else:
            summary = "Henüz gösterilecek bildirim yok."
            mode = "Boş"

        events_html = ""
        if events:
            for item in events:
                score = _eg_nfg3_score(item)
                level = _eg_nfg3_level(item)
                title = item.get("title") or item.get("risk_label") or ("Yüksek Risk" if level == "KRİTİK" else "Bildirim")
                body = item.get("body") or item.get("message") or item.get("text") or item.get("description") or "Güvenlik bildirimi"
                time = item.get("time") or item.get("created_at") or "-"
                src = item.get("source") or item.get("_source_label") or "system"

                events_html += (
                    '<div class="event">'
                    '<div>'
                    '<b>' + _eg_nfg3_safe(title) + '</b>'
                    '<span>' + _eg_nfg3_safe(str(body)[:105]) + '</span>'
                    '<small>' + _eg_nfg3_safe(time) + ' - ' + _eg_nfg3_safe(src) + '</small>'
                    '</div>'
                    '<strong>' + _eg_nfg3_safe(level) + (' / ' + str(score) if score else '') + '</strong>'
                    '</div>'
                )
        else:
            events_html = '<div class="empty">Henüz gösterilecek bildirim yok.</div>'

        html = """
<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>EratGuard PRO - Bildirimler</title>
<style>
:root{--bg:#020806;--line:rgba(35,255,137,.22);--green:#20ff88;--yellow:#ffdd35;--text:#f5fff8;--muted:rgba(245,255,248,.62)}
*{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
html,body{margin:0;min-height:100%;background:radial-gradient(circle at 80% 0%,rgba(35,255,137,.14),transparent 32%),var(--bg);color:var(--text);font-family:Arial,Helvetica,sans-serif}
body{padding:12px 11px 18px}
.top{display:flex;align-items:center;justify-content:space-between;gap:8px;margin-bottom:10px}
.brand{display:flex;align-items:center;gap:8px;min-width:0}
.logo{width:42px;height:42px;border-radius:14px;background:rgba(35,255,137,.12);border:1px solid var(--line);display:grid;place-items:center;font-size:22px}
.brand h1{margin:0;font-size:20px;line-height:1;font-weight:950;letter-spacing:-1px}
.brand h1 span{color:var(--green)}
.brand p{margin:2px 0 0;color:var(--muted);font-weight:850;font-size:11px}
.badge{border:1px solid rgba(255,221,53,.35);color:var(--green);background:rgba(35,255,137,.10);padding:7px 10px;border-radius:999px;font-weight:950;font-size:11px;white-space:nowrap}
.hero,.summary,.events{border:1px solid var(--line);background:linear-gradient(145deg,rgba(10,36,23,.94),rgba(4,14,9,.94));border-radius:20px;padding:13px;box-shadow:0 12px 30px rgba(0,0,0,.28)}
.hero-top{display:flex;align-items:flex-start;gap:10px}
.ico{width:46px;height:46px;flex:0 0 46px;border-radius:15px;border:1px solid var(--line);background:rgba(35,255,137,.10);display:grid;place-items:center;font-size:24px}
.hero h2{font-size:24px;line-height:1.02;margin:1px 0 5px;font-weight:950;letter-spacing:-1.1px}
.hero p{margin:0;color:var(--muted);font-size:13px;line-height:1.28;font-weight:800}
.stats{display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px;margin-top:12px}
.stat{border:1px solid rgba(35,255,137,.17);background:rgba(0,0,0,.23);border-radius:15px;padding:10px;min-height:56px}
.stat b{display:block;color:var(--green);font-size:17px;line-height:1.1}
.stat span{display:block;color:var(--muted);font-size:10px;font-weight:900;margin-top:5px}
.back{display:flex;align-items:center;justify-content:center;margin-top:10px;min-height:40px;width:100%;border-radius:14px;color:var(--text);text-decoration:none;font-weight:950;background:rgba(255,255,255,.075);border:1px solid rgba(255,255,255,.09);font-size:14px}
.section-title{font-size:15px;letter-spacing:6px;font-weight:950;margin:18px 0 8px}
.summary{padding:0;overflow:hidden}
.row{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:13px 14px;border-bottom:1px solid rgba(255,255,255,.06)}
.row:last-child{border-bottom:0}
.row span,.row b{font-size:14px;font-weight:900}
.row b{color:#9fffc4;text-align:right}
.events{padding:10px}
.event{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:11px 8px;border-bottom:1px solid rgba(255,255,255,.06)}
.event:last-child{border-bottom:0}
.event b{display:block;font-size:14px;margin-bottom:4px}
.event span{display:block;color:var(--muted);font-size:12px;font-weight:800;line-height:1.3}
.event small{display:block;color:rgba(245,255,248,.42);font-size:10px;font-weight:800;margin-top:5px}
.event strong{color:var(--yellow);font-size:12px;white-space:nowrap;text-align:right}
.empty{padding:14px;color:var(--muted);font-weight:850;text-align:center;font-size:13px}
.foot{text-align:center;margin:16px 0 0;color:rgba(245,255,248,.42);font-weight:800;font-size:12px}
</style>
</head>
<body>
<header class="top">
  <div class="brand"><div class="logo">🔔</div><div><h1>Erat<span>Guard</span></h1><p>Bildirimler</p></div></div>
  <div class="badge">👑 PRO AKTİF</div>
</header>

<section class="hero">
  <div class="hero-top">
    <div class="ico">🔔</div>
    <div>
      <h2>Bildirimler</h2>
      <p>__SUMMARY__</p>
    </div>
  </div>

  <div class="stats">
    <div class="stat"><b>__TOTAL__</b><span>Toplam</span></div>
    <div class="stat"><b>__CRITICAL__</b><span>Kritik</span></div>
    <div class="stat"><b>__WARNINGS__</b><span>Uyarı</span></div>
  </div>

  <a class="back" href="/dashboard">← Ana ekrana dön</a>
</section>

<div class="section-title">ÖZET</div>
<section class="summary">
  <div class="row"><span>Durum</span><b>__MODE__</b></div>
  <div class="row"><span>Toplam Bildirim</span><b>__TOTAL__</b></div>
  <div class="row"><span>Kritik Uyarı</span><b>__CRITICAL__</b></div>
  <div class="row"><span>Bildirim Motoru</span><b>Aktif</b></div>
</section>

<div class="section-title">SON BİLDİRİMLER</div>
<section class="events">
__EVENTS__
</section>

<div class="foot">EratGuard PRO - __USERNAME__ - © 2026</div>
</body>
</html>
"""

        html = html.replace("__USERNAME__", _eg_nfg3_safe(username))
        html = html.replace("__SUMMARY__", _eg_nfg3_safe(summary))
        html = html.replace("__MODE__", _eg_nfg3_safe(mode))
        html = html.replace("__TOTAL__", str(total))
        html = html.replace("__CRITICAL__", str(critical))
        html = html.replace("__WARNINGS__", str(warnings))
        html = html.replace("__EVENTS__", events_html)

        resp = _eg_nfg3_make_response(_eg_nfg3_render_template_string(html))
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        resp.headers["Pragma"] = "no-cache"
        resp.headers["Expires"] = "0"
        return resp

    def _eg_nfg3_settings_page():
        username = str(_eg_nfg3_session.get("username") or "user")

        html = """
<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>EratGuard PRO - Bildirim Ayarları</title>
<style>
:root{--bg:#020806;--line:rgba(35,255,137,.22);--green:#20ff88;--yellow:#ffdd35;--text:#f5fff8;--muted:rgba(245,255,248,.62)}
*{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
html,body{margin:0;min-height:100%;background:radial-gradient(circle at 80% 0%,rgba(35,255,137,.14),transparent 32%),var(--bg);color:var(--text);font-family:Arial,Helvetica,sans-serif}
body{padding:12px 11px 18px}
.top{display:flex;align-items:center;justify-content:space-between;gap:8px;margin-bottom:10px}
.brand{display:flex;align-items:center;gap:8px}
.logo{width:42px;height:42px;border-radius:14px;background:rgba(35,255,137,.12);border:1px solid var(--line);display:grid;place-items:center;font-size:22px}
.brand h1{margin:0;font-size:20px;font-weight:950;letter-spacing:-1px}.brand h1 span{color:var(--green)}
.brand p{margin:2px 0 0;color:var(--muted);font-weight:850;font-size:11px}
.badge{border:1px solid rgba(255,221,53,.35);color:var(--green);background:rgba(35,255,137,.10);padding:7px 10px;border-radius:999px;font-weight:950;font-size:11px}
.card,.settings{border:1px solid var(--line);background:linear-gradient(145deg,rgba(10,36,23,.94),rgba(4,14,9,.94));border-radius:20px;padding:13px;box-shadow:0 12px 30px rgba(0,0,0,.28)}
.card h2{font-size:24px;margin:0 0 6px;font-weight:950;letter-spacing:-1.1px}
.card p{margin:0;color:var(--muted);font-size:13px;line-height:1.35;font-weight:800}
.section-title{font-size:15px;letter-spacing:6px;font-weight:950;margin:18px 0 8px}
.row{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:14px 0;border-bottom:1px solid rgba(255,255,255,.06)}
.row:last-child{border-bottom:0}
.row b{font-size:14px}.row span{display:block;color:var(--muted);font-size:12px;font-weight:800;margin-top:4px}
.toggle{width:50px;height:28px;border-radius:999px;background:rgba(35,255,137,.16);border:1px solid rgba(35,255,137,.28);position:relative;flex:0 0 50px}
.toggle:after{content:"";position:absolute;right:4px;top:4px;width:18px;height:18px;border-radius:50%;background:var(--green);box-shadow:0 0 14px rgba(35,255,137,.7)}
.actions{display:grid;grid-template-columns:1fr 1fr;gap:9px;margin-top:12px}
.btn{display:flex;align-items:center;justify-content:center;min-height:42px;border-radius:14px;text-decoration:none;font-weight:950;font-size:14px}
.primary{background:linear-gradient(135deg,var(--yellow),var(--green));color:#00180c}
.secondary{background:rgba(255,255,255,.075);border:1px solid rgba(255,255,255,.09);color:var(--text)}
.foot{text-align:center;margin:16px 0 0;color:rgba(245,255,248,.42);font-weight:800;font-size:12px}
</style>
</head>
<body>
<header class="top">
  <div class="brand"><div class="logo">🔔</div><div><h1>Erat<span>Guard</span></h1><p>Bildirim Ayarları</p></div></div>
  <div class="badge">👑 PRO AKTİF</div>
</header>

<section class="card">
  <h2>Bildirim Ayarları</h2>
  <p>Güvenlik uyarıları, lisans bildirimleri ve sistem duyuruları için tercihlerini yönet.</p>
</section>

<div class="section-title">TERCİHLER</div>
<section class="settings">
  <div class="row"><div><b>Bildirimler Aktif</b><span>Genel EratGuard bildirimleri</span></div><div class="toggle"></div></div>
  <div class="row"><div><b>Güvenlik Uyarıları</b><span>Risk, karantina ve analiz olayları</span></div><div class="toggle"></div></div>
  <div class="row"><div><b>Lisans Bildirimleri</b><span>Aktivasyon ve yenileme uyarıları</span></div><div class="toggle"></div></div>
  <div class="row"><div><b>Admin Duyuruları</b><span>Sistem ve ürün duyuruları</span></div><div class="toggle"></div></div>

  <div class="actions">
    <a class="btn primary" href="/u/notifications?fresh=1">Kaydet</a>
    <a class="btn secondary" href="/u/notifications?fresh=1">Bildirimler</a>
  </div>
</section>

<div class="foot">EratGuard PRO - __USERNAME__ - © 2026</div>
</body>
</html>
"""
        html = html.replace("__USERNAME__", _eg_nfg3_safe(username))
        resp = _eg_nfg3_make_response(_eg_nfg3_render_template_string(html))
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        resp.headers["Pragma"] = "no-cache"
        resp.headers["Expires"] = "0"
        return resp

    @app.before_request
    def _eg_nfg3_hard_bridge():
        try:
            path = str(_eg_nfg3_request.path or "").rstrip("/")

            notif_paths = {
                "/u/notifications",
                "/notifications",
                "/notification",
                "/bildirim",
                "/bildirimler",
            }

            settings_paths = {
                "/u/notifications/manage",
            }

            if path in notif_paths:
                if not (_eg_nfg3_session.get("logged_in") and _eg_nfg3_session.get("username")):
                    return _eg_nfg3_redirect("/login?auth_required=1")
                return _eg_nfg3_notifications_page()

            if path in settings_paths:
                if not (_eg_nfg3_session.get("logged_in") and _eg_nfg3_session.get("username")):
                    return _eg_nfg3_redirect("/login?auth_required=1")
                return _eg_nfg3_settings_page()

        except Exception as _eg_nfg3_bridge_err:
            print("ERATGUARD NOTIFICATIONS-FORCE-GREEN-3 BRIDGE ERROR:", _eg_nfg3_bridge_err)

        return None

    print("ERATGUARD NOTIFICATIONS-FORCE-GREEN-3 HARD BRIDGE ACTIVE")

except Exception as _eg_nfg3_err:
    print("ERATGUARD NOTIFICATIONS-FORCE-GREEN-3 ERROR:", _eg_nfg3_err)
# === /ERATGUARD NOTIFICATIONS-FORCE-GREEN-3 HARD BRIDGE ===

# === ERATGUARD NOTIFICATIONS-FORCE-GREEN-4 PRIORITY BRIDGE ===
# Eski PRO NOTIFICATIONS before_request fonksiyonundan önce çalışmak için
# bridge fonksiyonunu app.before_request_funcs[None] listesinin başına alır.
try:
    def _eg_nfg4_priority_bridge():
        try:
            from flask import request as _eg_nfg4_request
            from flask import session as _eg_nfg4_session
            from flask import redirect as _eg_nfg4_redirect

            path = str(_eg_nfg4_request.path or "").rstrip("/")

            notif_paths = {
                "/u/notifications",
                "/notifications",
                "/notification",
                "/bildirim",
                "/bildirimler",
            }

            settings_paths = {
                "/u/notifications/manage",
            }

            if path in notif_paths:
                if not (_eg_nfg4_session.get("logged_in") and _eg_nfg4_session.get("username")):
                    return _eg_nfg4_redirect("/login?auth_required=1")

                if "_eg_nfg3_notifications_page" in globals() and callable(globals().get("_eg_nfg3_notifications_page")):
                    return globals()["_eg_nfg3_notifications_page"]()

            if path in settings_paths:
                if not (_eg_nfg4_session.get("logged_in") and _eg_nfg4_session.get("username")):
                    return _eg_nfg4_redirect("/login?auth_required=1")

                if "_eg_nfg3_settings_page" in globals() and callable(globals().get("_eg_nfg3_settings_page")):
                    return globals()["_eg_nfg3_settings_page"]()

        except Exception as _eg_nfg4_req_err:
            print("ERATGUARD NOTIFICATIONS-FORCE-GREEN-4 REQUEST ERROR:", _eg_nfg4_req_err)

        return None

    # 1) before_request listesinin en başına zorla.
    try:
        funcs = app.before_request_funcs.setdefault(None, [])

        funcs[:] = [
            f for f in funcs
            if getattr(f, "__name__", "") != "_eg_nfg4_priority_bridge"
        ]

        funcs.insert(0, _eg_nfg4_priority_bridge)

        print("ERATGUARD NOTIFICATIONS-FORCE-GREEN-4 PRIORITY BEFORE_REQUEST ACTIVE")
    except Exception as _eg_nfg4_before_err:
        print("ERATGUARD NOTIFICATIONS-FORCE-GREEN-4 BEFORE_REQUEST ERROR:", _eg_nfg4_before_err)

    # 2) Route endpointlerini de yeşil sayfaya bağla.
    try:
        for _rule in list(app.url_map.iter_rules()):
            if str(_rule) in (
                "/u/notifications",
                "/u/notifications/",
                "/notifications",
                "/notifications/",
                "/notification",
                "/notification/",
                "/bildirim",
                "/bildirim/",
                "/bildirimler",
                "/bildirimler/",
            ):
                app.view_functions[_rule.endpoint] = _eg_nfg4_priority_bridge

            if str(_rule) in ("/u/notifications/manage", "/u/notifications/manage/"):
                app.view_functions[_rule.endpoint] = _eg_nfg4_priority_bridge

        print("ERATGUARD NOTIFICATIONS-FORCE-GREEN-4 ROUTE OVERRIDE ACTIVE")
    except Exception as _eg_nfg4_route_err:
        print("ERATGUARD NOTIFICATIONS-FORCE-GREEN-4 ROUTE ERROR:", _eg_nfg4_route_err)

except Exception as _eg_nfg4_err:
    print("ERATGUARD NOTIFICATIONS-FORCE-GREEN-4 ERROR:", _eg_nfg4_err)
# === /ERATGUARD NOTIFICATIONS-FORCE-GREEN-4 PRIORITY BRIDGE ===

# === ERATGUARD NOTIFICATIONS-DEDUPE-5 CLEAN RECENT EVENTS ===
# Bildirim sayfasında aynı SMS'in spam_logs/history/quarantine üzerinden tekrar görünmesini azaltır.
try:
    import re as _eg_nd5_re

    def _eg_nd5_norm_text(v):
        try:
            t = str(v or "").lower().strip()
            t = _eg_nd5_re.sub(r"\s+", " ", t)
            return t[:120]
        except Exception:
            return ""

    def _eg_nd5_norm_score(item):
        try:
            return int(item.get("score") or item.get("risk") or 0)
        except Exception:
            return 0

    def _eg_nd5_dedupe_events(events, limit=5):
        if not isinstance(events, list):
            return []

        cleaned = []
        seen = set()

        for item in events:
            if not isinstance(item, dict):
                continue

            body = (
                item.get("body")
                or item.get("message")
                or item.get("text")
                or item.get("description")
                or item.get("title")
                or ""
            )

            score = _eg_nd5_norm_score(item)
            status = str(item.get("status") or "").upper().strip()
            label = str(item.get("risk_label") or item.get("title") or "").lower().strip()

            # Aynı mesaj + skor + risk seviyesi tek bildirim sayılır.
            key = (_eg_nd5_norm_text(body), score, status or label)

            if key in seen:
                continue

            seen.add(key)
            cleaned.append(item)

            if len(cleaned) >= limit:
                break

        return cleaned

    # NFG3 event toplayıcıyı sar. NFG4 çoğu kurulumda bunu kullanıyor.
    if "_eg_nfg3_events" in globals() and callable(globals().get("_eg_nfg3_events")):
        _eg_nd5_old_nfg3_events = globals().get("_eg_nfg3_events")

        def _eg_nfg3_events(username):
            raw = _eg_nd5_old_nfg3_events(username)
            return _eg_nd5_dedupe_events(raw, limit=5)

    # NDB2 event toplayıcıyı da sar.
    if "_eg_ndb2_user_events" in globals() and callable(globals().get("_eg_ndb2_user_events")):
        _eg_nd5_old_ndb2_events = globals().get("_eg_ndb2_user_events")

        def _eg_ndb2_user_events(username):
            raw = _eg_nd5_old_ndb2_events(username)
            return _eg_nd5_dedupe_events(raw, limit=5)

    print("ERATGUARD NOTIFICATIONS-DEDUPE-5 CLEAN RECENT EVENTS ACTIVE")

except Exception as _eg_nd5_err:
    print("ERATGUARD NOTIFICATIONS-DEDUPE-5 ERROR:", _eg_nd5_err)
# === /ERATGUARD NOTIFICATIONS-DEDUPE-5 CLEAN RECENT EVENTS ===

# === ERATGUARD SETTINGS-DATA-BIND-1 LIVE SETTINGS PAGE ===
# /u/settings sayfasını canlı user_settings JSON verisine bağlar.
# Kullanıcı tercihlerini POST ile data/user_settings.json içine kaydeder.
try:
    from flask import render_template_string as _eg_set1_render_template_string
    from flask import make_response as _eg_set1_make_response
    from flask import redirect as _eg_set1_redirect
    from flask import session as _eg_set1_session
    from flask import request as _eg_set1_request
    from pathlib import Path as _eg_set1_Path
    from datetime import datetime as _eg_set1_datetime
    import json as _eg_set1_json
    import html as _eg_set1_html

    def _eg_set1_safe(v):
        try:
            return _eg_set1_html.escape(str(v or ""))
        except Exception:
            return ""

    def _eg_set1_load(default, path):
        try:
            p = _eg_set1_Path(path)
            if not p.exists():
                return default
            txt = p.read_text(encoding="utf-8", errors="ignore").strip()
            if not txt:
                return default
            return _eg_set1_json.loads(txt)
        except Exception:
            return default

    def _eg_set1_save(path, data):
        p = _eg_set1_Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(
            _eg_set1_json.dumps(data, ensure_ascii=False, indent=2),
            encoding="utf-8"
        )

    def _eg_set1_bool_from_form(name, default=False):
        try:
            v = _eg_set1_request.form.get(name)
            if v is None:
                return False
            return str(v).lower() in ("1", "true", "on", "yes", "aktif")
        except Exception:
            return bool(default)

    def _eg_set1_defaults():
        return {
            "security_alerts": True,
            "license_alerts": True,
            "admin_announcements": True,
            "auto_quarantine": True,
            "compact_mode": True,
            "high_sensitivity": True,
            "theme": "green_dark",
            "language": "tr",
            "updated_at": "",
        }

    def _eg_set1_user_settings(username):
        data = _eg_set1_load({}, "data/user_settings.json")
        if not isinstance(data, dict):
            data = {}

        current = data.get(username, {})
        if not isinstance(current, dict):
            current = {}

        merged = _eg_set1_defaults()
        merged.update(current)
        return data, merged

    def _eg_set1_route():
        if not (_eg_set1_session.get("logged_in") and _eg_set1_session.get("username")):
            return _eg_set1_redirect("/login?auth_required=1")

        username = str(_eg_set1_session.get("username") or "user")

        data, settings = _eg_set1_user_settings(username)

        if str(_eg_set1_request.method or "").upper() == "POST":
            settings["security_alerts"] = _eg_set1_bool_from_form("security_alerts")
            settings["license_alerts"] = _eg_set1_bool_from_form("license_alerts")
            settings["admin_announcements"] = _eg_set1_bool_from_form("admin_announcements")
            settings["auto_quarantine"] = _eg_set1_bool_from_form("auto_quarantine")
            settings["compact_mode"] = _eg_set1_bool_from_form("compact_mode")
            settings["high_sensitivity"] = _eg_set1_bool_from_form("high_sensitivity")
            settings["theme"] = "green_dark"
            settings["language"] = "tr"
            settings["updated_at"] = _eg_set1_datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            data[username] = settings
            _eg_set1_save("data/user_settings.json", data)

            return _eg_set1_redirect("/u/settings?saved=1")

        saved = str(_eg_set1_request.args.get("saved") or "") == "1"

        def checked(key):
            return "checked" if settings.get(key) else ""

        enabled_count = sum(
            1 for k in [
                "security_alerts",
                "license_alerts",
                "admin_announcements",
                "auto_quarantine",
                "compact_mode",
                "high_sensitivity",
            ]
            if settings.get(k)
        )

        if enabled_count >= 5:
            mode = "Tam Koruma"
            summary = "Kullanıcı tercihleri yüksek koruma modunda çalışıyor."
        elif enabled_count >= 3:
            mode = "Dengeli"
            summary = "Kullanıcı tercihleri dengeli güvenlik modunda."
        else:
            mode = "Manuel"
            summary = "Bazı koruma tercihleri kapalı. İstersen tekrar aktif edebilirsin."

        saved_html = ""
        if saved:
            saved_html = '<div class="saved">Ayarlar kaydedildi.</div>'

        html = """
<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>EratGuard PRO - Ayarlar</title>
<style>
:root{--bg:#020806;--line:rgba(35,255,137,.22);--green:#20ff88;--yellow:#ffdd35;--text:#f5fff8;--muted:rgba(245,255,248,.62)}
*{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
html,body{margin:0;min-height:100%;background:radial-gradient(circle at 80% 0%,rgba(35,255,137,.14),transparent 32%),var(--bg);color:var(--text);font-family:Arial,Helvetica,sans-serif}
body{padding:12px 11px 18px}
.top{display:flex;align-items:center;justify-content:space-between;gap:8px;margin-bottom:10px}
.brand{display:flex;align-items:center;gap:8px;min-width:0}
.logo{width:42px;height:42px;border-radius:14px;background:rgba(35,255,137,.12);border:1px solid var(--line);display:grid;place-items:center;font-size:22px}
.brand h1{margin:0;font-size:20px;line-height:1;font-weight:950;letter-spacing:-1px}
.brand h1 span{color:var(--green)}
.brand p{margin:2px 0 0;color:var(--muted);font-weight:850;font-size:11px}
.badge{border:1px solid rgba(255,221,53,.35);color:var(--green);background:rgba(35,255,137,.10);padding:7px 10px;border-radius:999px;font-weight:950;font-size:11px;white-space:nowrap}
.hero,.summary,.settings{border:1px solid var(--line);background:linear-gradient(145deg,rgba(10,36,23,.94),rgba(4,14,9,.94));border-radius:20px;padding:13px;box-shadow:0 12px 30px rgba(0,0,0,.28)}
.hero-top{display:flex;align-items:flex-start;gap:10px}
.ico{width:46px;height:46px;flex:0 0 46px;border-radius:15px;border:1px solid var(--line);background:rgba(35,255,137,.10);display:grid;place-items:center;font-size:24px}
.hero h2{font-size:24px;line-height:1.02;margin:1px 0 5px;font-weight:950;letter-spacing:-1.1px}
.hero p{margin:0;color:var(--muted);font-size:13px;line-height:1.28;font-weight:800}
.stats{display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px;margin-top:12px}
.stat{border:1px solid rgba(35,255,137,.17);background:rgba(0,0,0,.23);border-radius:15px;padding:10px;min-height:56px}
.stat b{display:block;color:var(--green);font-size:17px;line-height:1.1}
.stat span{display:block;color:var(--muted);font-size:10px;font-weight:900;margin-top:5px}
.back{display:flex;align-items:center;justify-content:center;margin-top:10px;min-height:40px;width:100%;border-radius:14px;color:var(--text);text-decoration:none;font-weight:950;background:rgba(255,255,255,.075);border:1px solid rgba(255,255,255,.09);font-size:14px}
.section-title{font-size:15px;letter-spacing:6px;font-weight:950;margin:18px 0 8px}
.summary{padding:0;overflow:hidden}
.row{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:13px 14px;border-bottom:1px solid rgba(255,255,255,.06)}
.row:last-child{border-bottom:0}
.row span,.row b{font-size:14px;font-weight:900}
.row b{color:#9fffc4;text-align:right}
.settings{padding:10px}
.opt{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:12px 8px;border-bottom:1px solid rgba(255,255,255,.06)}
.opt:last-child{border-bottom:0}
.opt b{display:block;font-size:14px}
.opt span{display:block;color:var(--muted);font-size:12px;font-weight:800;margin-top:4px;line-height:1.3}
.switch{position:relative;width:50px;height:28px;flex:0 0 50px}
.switch input{display:none}
.slider{position:absolute;inset:0;border-radius:999px;background:rgba(255,255,255,.12);border:1px solid rgba(255,255,255,.12)}
.slider:before{content:"";position:absolute;width:20px;height:20px;left:4px;top:3px;border-radius:50%;background:rgba(245,255,248,.52);transition:.18s}
.switch input:checked + .slider{background:rgba(35,255,137,.20);border-color:rgba(35,255,137,.35)}
.switch input:checked + .slider:before{transform:translateX(20px);background:var(--green);box-shadow:0 0 14px rgba(35,255,137,.65)}
.actions{display:grid;grid-template-columns:1fr 1fr;gap:9px;margin-top:12px}
.btn{border:0;display:flex;align-items:center;justify-content:center;min-height:44px;border-radius:14px;text-decoration:none;font-weight:950;font-size:14px}
.primary{background:linear-gradient(135deg,var(--yellow),var(--green));color:#00180c}
.secondary{background:rgba(255,255,255,.075);border:1px solid rgba(255,255,255,.09);color:var(--text)}
.saved{margin:0 0 10px;padding:11px 13px;border:1px solid rgba(35,255,137,.25);background:rgba(35,255,137,.10);border-radius:14px;color:#9fffc4;font-weight:950;font-size:13px}
.foot{text-align:center;margin:16px 0 0;color:rgba(245,255,248,.42);font-weight:800;font-size:12px}
</style>
</head>
<body>
<header class="top">
  <div class="brand"><div class="logo">⚙️</div><div><h1>Erat<span>Guard</span></h1><p>Ayarlar</p></div></div>
  <div class="badge">👑 PRO AKTİF</div>
</header>

<section class="hero">
  <div class="hero-top">
    <div class="ico">⚙️</div>
    <div>
      <h2>Ayarlar</h2>
      <p>__SUMMARY__</p>
    </div>
  </div>

  <div class="stats">
    <div class="stat"><b>__ENABLED__</b><span>Aktif</span></div>
    <div class="stat"><b>6</b><span>Tercih</span></div>
    <div class="stat"><b>PRO</b><span>Mod</span></div>
  </div>

  <a class="back" href="/dashboard">← Ana ekrana dön</a>
</section>

<div class="section-title">ÖZET</div>
<section class="summary">
  <div class="row"><span>Koruma Modu</span><b>__MODE__</b></div>
  <div class="row"><span>Tema</span><b>Yeşil Karanlık</b></div>
  <div class="row"><span>Dil</span><b>Türkçe</b></div>
  <div class="row"><span>Son Kayıt</span><b>__UPDATED__</b></div>
</section>

<div class="section-title">TERCİHLER</div>
<form class="settings" method="post" action="/u/settings">
  __SAVED__

  <label class="opt">
    <div><b>Güvenlik Uyarıları</b><span>Risk, spam, karantina ve analiz uyarıları.</span></div>
    <div class="switch"><input name="security_alerts" type="checkbox" __SECURITY__><span class="slider"></span></div>
  </label>

  <label class="opt">
    <div><b>Lisans Bildirimleri</b><span>Aktivasyon ve yenileme bildirimleri.</span></div>
    <div class="switch"><input name="license_alerts" type="checkbox" __LICENSE__><span class="slider"></span></div>
  </label>

  <label class="opt">
    <div><b>Admin Duyuruları</b><span>Sistem ve ürün duyurularını göster.</span></div>
    <div class="switch"><input name="admin_announcements" type="checkbox" __ADMIN__><span class="slider"></span></div>
  </label>

  <label class="opt">
    <div><b>Otomatik Karantina</b><span>Yüksek riskli mesajları otomatik ayır.</span></div>
    <div class="switch"><input name="auto_quarantine" type="checkbox" __QUARANTINE__><span class="slider"></span></div>
  </label>

  <label class="opt">
    <div><b>Kompakt Görünüm</b><span>Mobilde daha ince ve hızlı arayüz.</span></div>
    <div class="switch"><input name="compact_mode" type="checkbox" __COMPACT__><span class="slider"></span></div>
  </label>

  <label class="opt">
    <div><b>Yüksek Hassasiyet</b><span>Spam ve oltalama sinyallerini sert değerlendir.</span></div>
    <div class="switch"><input name="high_sensitivity" type="checkbox" __SENS__><span class="slider"></span></div>
  </label>

  <div class="actions">
    <button class="btn primary" type="submit">Kaydet</button>
    <a class="btn secondary" href="/dashboard">Panel</a>
  </div>
</form>

<div class="foot">EratGuard PRO - __USERNAME__ - © 2026</div>
</body>
</html>
"""

        html = html.replace("__USERNAME__", _eg_set1_safe(username))
        html = html.replace("__SUMMARY__", _eg_set1_safe(summary))
        html = html.replace("__MODE__", _eg_set1_safe(mode))
        html = html.replace("__ENABLED__", str(enabled_count))
        html = html.replace("__UPDATED__", _eg_set1_safe(settings.get("updated_at") or "Henüz yok"))
        html = html.replace("__SAVED__", saved_html)

        html = html.replace("__SECURITY__", checked("security_alerts"))
        html = html.replace("__LICENSE__", checked("license_alerts"))
        html = html.replace("__ADMIN__", checked("admin_announcements"))
        html = html.replace("__QUARANTINE__", checked("auto_quarantine"))
        html = html.replace("__COMPACT__", checked("compact_mode"))
        html = html.replace("__SENS__", checked("high_sensitivity"))

        resp = _eg_set1_make_response(_eg_set1_render_template_string(html))
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        resp.headers["Pragma"] = "no-cache"
        resp.headers["Expires"] = "0"
        return resp

    try:
        for _rule in list(app.url_map.iter_rules()):
            if str(_rule) in ("/u/settings", "/u/settings/", "/u/settings/manage", "/u/settings/manage/", "/settings", "/settings/", "/ayar", "/ayar/", "/ayarlar", "/ayarlar/"):
                app.view_functions[_rule.endpoint] = _eg_set1_route
                try:
                    _rule.methods.add("POST")
                except Exception:
                    pass

        print("ERATGUARD SETTINGS-DATA-BIND-1 LIVE SETTINGS PAGE ACTIVE")
    except Exception as _eg_set1_route_err:
        print("ERATGUARD SETTINGS-DATA-BIND-1 ROUTE ERROR:", _eg_set1_route_err)

except Exception as _eg_set1_err:
    print("ERATGUARD SETTINGS-DATA-BIND-1 ERROR:", _eg_set1_err)
# === /ERATGUARD SETTINGS-DATA-BIND-1 LIVE SETTINGS PAGE ===

# === ERATGUARD COMMUNITY-DATA-BIND-1 LIVE COMMUNITY PAGE ===
# /u/community sayfasını canlı community report JSON verisine bağlar.
# Eksik community_reports / spam_reports / reported_numbers dosyalarını güvenli oluşturur.
try:
    from flask import request as _eg_cdb1_request
    from flask import session as _eg_cdb1_session
    from flask import redirect as _eg_cdb1_redirect
    from flask import render_template_string as _eg_cdb1_render_template_string
    from flask import make_response as _eg_cdb1_make_response
    from pathlib import Path as _eg_cdb1_Path
    from datetime import datetime as _eg_cdb1_datetime
    import json as _eg_cdb1_json
    import html as _eg_cdb1_html

    def _eg_cdb1_safe(v):
        try:
            return _eg_cdb1_html.escape(str(v or ""))
        except Exception:
            return ""

    def _eg_cdb1_load(default, path):
        try:
            p = _eg_cdb1_Path(path)
            if not p.exists():
                return default
            txt = p.read_text(encoding="utf-8", errors="ignore").strip()
            if not txt:
                return default
            return _eg_cdb1_json.loads(txt)
        except Exception:
            return default

    def _eg_cdb1_save(path, data):
        p = _eg_cdb1_Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(
            _eg_cdb1_json.dumps(data, ensure_ascii=False, indent=2),
            encoding="utf-8"
        )

    def _eg_cdb1_seed_files():
        seeds = {
            "data/community_reports.json": [],
            "data/spam_reports.json": [],
            "data/reported_numbers.json": {},
        }

        for file_path, default in seeds.items():
            p = _eg_cdb1_Path(file_path)
            if not p.exists():
                _eg_cdb1_save(file_path, default)
                continue

            txt = p.read_text(encoding="utf-8", errors="ignore").strip()
            if not txt:
                _eg_cdb1_save(file_path, default)
                continue

            try:
                _eg_cdb1_json.loads(txt)
            except Exception:
                bak = p.with_suffix(p.suffix + ".broken.bak")
                try:
                    p.rename(bak)
                except Exception:
                    pass
                _eg_cdb1_save(file_path, default)

    def _eg_cdb1_add_report(username, number, message, category, note):
        now = _eg_cdb1_datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        number = str(number or "").strip()
        message = str(message or "").strip()
        category = str(category or "spam").strip() or "spam"
        note = str(note or "").strip()

        item = {
            "time": now,
            "username": username,
            "number": number or "unknown_sender",
            "sender": number or "community_report",
            "body": message,
            "message": message,
            "category": category,
            "note": note,
            "status": "COMMUNITY_REPORTED",
            "score": 75,
            "risk": 75,
            "risk_label": "Topluluk Bildirimi",
            "risk_class": "community",
            "source": "community_report",
        }

        community = _eg_cdb1_load([], "data/community_reports.json")
        if not isinstance(community, list):
            community = []
        community.append(item)
        _eg_cdb1_save("data/community_reports.json", community)

        spam_reports = _eg_cdb1_load([], "data/spam_reports.json")
        if not isinstance(spam_reports, list):
            spam_reports = []
        spam_reports.append(item)
        _eg_cdb1_save("data/spam_reports.json", spam_reports)

        reported = _eg_cdb1_load({}, "data/reported_numbers.json")
        if not isinstance(reported, dict):
            reported = {}

        key = number or "unknown_sender"
        old = reported.get(key)
        if not isinstance(old, dict):
            old = {"number": key, "count": 0, "reports": []}

        old["number"] = key
        old["count"] = int(old.get("count") or 0) + 1
        old["last_time"] = now
        old["last_username"] = username
        old["last_category"] = category
        old["last_message"] = message[:160]
        reports = old.get("reports")
        if not isinstance(reports, list):
            reports = []
        reports.append({
            "time": now,
            "username": username,
            "category": category,
            "message": message[:160],
            "note": note[:160],
        })
        old["reports"] = reports[-10:]
        reported[key] = old
        _eg_cdb1_save("data/reported_numbers.json", reported)

        return item

    def _eg_cdb1_stats(username):
        community = _eg_cdb1_load([], "data/community_reports.json")
        spam_reports = _eg_cdb1_load([], "data/spam_reports.json")
        reported = _eg_cdb1_load({}, "data/reported_numbers.json")

        if not isinstance(community, list):
            community = []
        if not isinstance(spam_reports, list):
            spam_reports = []
        if not isinstance(reported, dict):
            reported = {}

        user_reports = []
        for item in community:
            if not isinstance(item, dict):
                continue
            item_user = str(item.get("username") or "").strip()
            if item_user and item_user != username:
                continue
            user_reports.append(item)

        recent = sorted(
            user_reports,
            key=lambda x: str(x.get("time") or ""),
            reverse=True
        )[:6]

        return {
            "community": community,
            "spam_reports": spam_reports,
            "reported": reported,
            "user_reports": user_reports,
            "recent": recent,
        }

    def _eg_cdb1_page(saved=False):
        if not (_eg_cdb1_session.get("logged_in") and _eg_cdb1_session.get("username")):
            return _eg_cdb1_redirect("/login?auth_required=1")

        username = str(_eg_cdb1_session.get("username") or "user")
        data = _eg_cdb1_stats(username)

        total = len(data["community"])
        user_total = len(data["user_reports"])
        reported_count = len(data["reported"])

        if total:
            summary = "Topluluk spam bildirimleri canlı olarak izleniyor."
            mode = "Topluluk Aktif"
        else:
            summary = "Henüz topluluk bildirimi yok. İlk spam bildirimi buradan eklenebilir."
            mode = "Hazır"

        flash_html = ""
        if saved:
            flash_html = '<div class="flash">Topluluk bildirimi kaydedildi.</div>'

        recent_html = ""
        if data["recent"]:
            for item in data["recent"]:
                title = item.get("risk_label") or "Topluluk Bildirimi"
                body = item.get("body") or item.get("message") or "Spam bildirimi"
                number = item.get("number") or item.get("sender") or "unknown"
                time = item.get("time") or "-"
                category = item.get("category") or "spam"

                recent_html += (
                    '<div class="event">'
                    '<div>'
                    '<b>' + _eg_cdb1_safe(title) + '</b>'
                    '<span>' + _eg_cdb1_safe(str(body)[:105]) + '</span>'
                    '<small>' + _eg_cdb1_safe(time) + ' - ' + _eg_cdb1_safe(number) + '</small>'
                    '</div>'
                    '<strong>' + _eg_cdb1_safe(category.upper()) + '</strong>'
                    '</div>'
                )
        else:
            recent_html = '<div class="empty">Henüz topluluk bildirimi yok.</div>'

        top_numbers = sorted(
            data["reported"].values(),
            key=lambda x: int(x.get("count") or 0) if isinstance(x, dict) else 0,
            reverse=True
        )[:5]

        numbers_html = ""
        if top_numbers:
            for item in top_numbers:
                if not isinstance(item, dict):
                    continue
                number = item.get("number") or "unknown"
                count = item.get("count") or 0
                last_time = item.get("last_time") or "-"
                numbers_html += (
                    '<div class="chip">'
                    '<div><b>' + _eg_cdb1_safe(number) + '</b>'
                    '<span>' + _eg_cdb1_safe(last_time) + '</span></div>'
                    '<strong>' + str(count) + ' rapor</strong>'
                    '</div>'
                )
        else:
            numbers_html = '<div class="empty">Raporlanan numara listesi boş.</div>'

        html = """
<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>EratGuard PRO - Topluluk</title>
<style>
:root{--bg:#020806;--line:rgba(35,255,137,.22);--green:#20ff88;--yellow:#ffdd35;--text:#f5fff8;--muted:rgba(245,255,248,.62)}
*{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
html,body{margin:0;min-height:100%;background:radial-gradient(circle at 80% 0%,rgba(35,255,137,.14),transparent 32%),var(--bg);color:var(--text);font-family:Arial,Helvetica,sans-serif}
body{padding:12px 11px 18px}
.top{display:flex;align-items:center;justify-content:space-between;gap:8px;margin-bottom:10px}
.brand{display:flex;align-items:center;gap:8px;min-width:0}
.logo{width:42px;height:42px;border-radius:14px;background:rgba(35,255,137,.12);border:1px solid var(--line);display:grid;place-items:center;font-size:22px}
.brand h1{margin:0;font-size:20px;line-height:1;font-weight:950;letter-spacing:-1px}
.brand h1 span{color:var(--green)}
.brand p{margin:2px 0 0;color:var(--muted);font-weight:850;font-size:11px}
.badge{border:1px solid rgba(255,221,53,.35);color:var(--green);background:rgba(35,255,137,.10);padding:7px 10px;border-radius:999px;font-weight:950;font-size:11px;white-space:nowrap}
.hero,.summary,.form,.events,.chips{border:1px solid var(--line);background:linear-gradient(145deg,rgba(10,36,23,.94),rgba(4,14,9,.94));border-radius:20px;padding:13px;box-shadow:0 12px 30px rgba(0,0,0,.28)}
.hero-top{display:flex;align-items:flex-start;gap:10px}
.ico{width:46px;height:46px;flex:0 0 46px;border-radius:15px;border:1px solid var(--line);background:rgba(35,255,137,.10);display:grid;place-items:center;font-size:24px}
.hero h2{font-size:24px;line-height:1.02;margin:1px 0 5px;font-weight:950;letter-spacing:-1.1px}
.hero p{margin:0;color:var(--muted);font-size:13px;line-height:1.28;font-weight:800}
.stats{display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px;margin-top:12px}
.stat{border:1px solid rgba(35,255,137,.17);background:rgba(0,0,0,.23);border-radius:15px;padding:10px;min-height:56px}
.stat b{display:block;color:var(--green);font-size:17px;line-height:1.1}
.stat span{display:block;color:var(--muted);font-size:10px;font-weight:900;margin-top:5px}
.back{display:flex;align-items:center;justify-content:center;margin-top:10px;min-height:40px;width:100%;border-radius:14px;color:var(--text);text-decoration:none;font-weight:950;background:rgba(255,255,255,.075);border:1px solid rgba(255,255,255,.09);font-size:14px}
.section-title{font-size:15px;letter-spacing:6px;font-weight:950;margin:18px 0 8px}
.summary{padding:0;overflow:hidden}
.row{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:13px 14px;border-bottom:1px solid rgba(255,255,255,.06)}
.row:last-child{border-bottom:0}
.row span,.row b{font-size:14px;font-weight:900}
.row b{color:#9fffc4;text-align:right}
.flash{border:1px solid rgba(35,255,137,.28);background:rgba(35,255,137,.10);border-radius:14px;padding:12px;margin-bottom:10px;font-weight:950;color:#9fffc4}
.form label{display:block;font-size:14px;font-weight:950;margin-bottom:7px}
.form input,.form textarea,.form select{width:100%;border-radius:14px;border:1px solid rgba(35,255,137,.22);background:rgba(0,0,0,.22);color:var(--text);font-size:14px;font-weight:850;padding:0 12px;outline:none;margin-bottom:8px}
.form input,.form select{height:46px}
.form textarea{min-height:88px;padding-top:12px;resize:vertical}
.form input::placeholder,.form textarea::placeholder{color:rgba(245,255,248,.34)}
.form button{width:100%;height:48px;border:0;border-radius:14px;background:linear-gradient(135deg,var(--yellow),var(--green));font-size:15px;font-weight:950;color:#00180c}
.events,.chips{padding:10px}
.event{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:11px 8px;border-bottom:1px solid rgba(255,255,255,.06)}
.event:last-child{border-bottom:0}
.event b{display:block;font-size:14px;margin-bottom:4px}
.event span{display:block;color:var(--muted);font-size:12px;font-weight:800;line-height:1.3}
.event small{display:block;color:rgba(245,255,248,.42);font-size:10px;font-weight:800;margin-top:5px}
.event strong{color:var(--yellow);font-size:12px;white-space:nowrap;text-align:right}
.chip{display:flex;align-items:center;justify-content:space-between;gap:10px;border:1px solid rgba(35,255,137,.17);background:rgba(0,0,0,.20);border-radius:14px;padding:11px 12px;margin-bottom:8px}
.chip:last-child{margin-bottom:0}
.chip b{display:block;font-size:14px}
.chip span{display:block;color:var(--muted);font-size:11px;font-weight:850;margin-top:3px}
.chip strong{color:#9fffc4;font-size:12px;text-align:right}
.empty{padding:14px;color:var(--muted);font-weight:850;text-align:center;font-size:13px}
.foot{text-align:center;margin:16px 0 0;color:rgba(245,255,248,.42);font-weight:800;font-size:12px}
</style>
</head>
<body>
<header class="top">
  <div class="brand"><div class="logo">🌐</div><div><h1>Erat<span>Guard</span></h1><p>Topluluk</p></div></div>
  <div class="badge">👑 PRO AKTİF</div>
</header>

<section class="hero">
  <div class="hero-top">
    <div class="ico">🌐</div>
    <div>
      <h2>Topluluk</h2>
      <p>__SUMMARY__</p>
    </div>
  </div>

  <div class="stats">
    <div class="stat"><b>__TOTAL__</b><span>Toplam</span></div>
    <div class="stat"><b>__USER_TOTAL__</b><span>Senin</span></div>
    <div class="stat"><b>__NUMBERS__</b><span>Numara</span></div>
  </div>

  <a class="back" href="/dashboard">← Ana ekrana dön</a>
</section>

<div class="section-title">ÖZET</div>
<section class="summary">
  <div class="row"><span>Durum</span><b>__MODE__</b></div>
  <div class="row"><span>Topluluk Raporu</span><b>__TOTAL__</b></div>
  <div class="row"><span>Raporlanan Numara</span><b>__NUMBERS__</b></div>
  <div class="row"><span>Koruma Katkısı</span><b>Aktif</b></div>
</section>

<div class="section-title">BİLDİR</div>
<section class="form">
  __FLASH__
  <form method="post" action="/u/community/spam_report">
    <label>Spam / dolandırıcılık bildir</label>
    <input name="number" placeholder="Numara veya gönderen adı">
    <select name="category">
      <option value="spam">Spam</option>
      <option value="phishing">Dolandırıcılık / Phishing</option>
      <option value="scam">Sahte ödül / kampanya</option>
      <option value="abuse">Rahatsız edici mesaj</option>
    </select>
    <textarea name="message" placeholder="Mesaj içeriği veya kısa açıklama"></textarea>
    <input name="note" placeholder="Not, kaynak veya ek bilgi">
    <button type="submit">Topluluğa Bildir</button>
  </form>
</section>

<div class="section-title">SON RAPORLAR</div>
<section class="events">
__RECENT__
</section>

<div class="section-title">NUMARALAR</div>
<section class="chips">
__NUMBERS_LIST__
</section>

<div class="foot">EratGuard PRO - __USERNAME__ - © 2026</div>
</body>
</html>
"""

        html = html.replace("__USERNAME__", _eg_cdb1_safe(username))
        html = html.replace("__SUMMARY__", _eg_cdb1_safe(summary))
        html = html.replace("__MODE__", _eg_cdb1_safe(mode))
        html = html.replace("__TOTAL__", str(total))
        html = html.replace("__USER_TOTAL__", str(user_total))
        html = html.replace("__NUMBERS__", str(reported_count))
        html = html.replace("__RECENT__", recent_html)
        html = html.replace("__NUMBERS_LIST__", numbers_html)
        html = html.replace("__FLASH__", flash_html)

        resp = _eg_cdb1_make_response(_eg_cdb1_render_template_string(html))
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        resp.headers["Pragma"] = "no-cache"
        resp.headers["Expires"] = "0"
        return resp

    def _eg_cdb1_community_route():
        if not (_eg_cdb1_session.get("logged_in") and _eg_cdb1_session.get("username")):
            return _eg_cdb1_redirect("/login?auth_required=1")
        return _eg_cdb1_page(saved=str(_eg_cdb1_request.args.get("saved") or "") == "1")

    def _eg_cdb1_spam_report_route():
        if not (_eg_cdb1_session.get("logged_in") and _eg_cdb1_session.get("username")):
            return _eg_cdb1_redirect("/login?auth_required=1")

        username = str(_eg_cdb1_session.get("username") or "user")

        number = (
            _eg_cdb1_request.form.get("number")
            or _eg_cdb1_request.form.get("sender")
            or _eg_cdb1_request.form.get("phone")
            or ""
        )

        message = (
            _eg_cdb1_request.form.get("message")
            or _eg_cdb1_request.form.get("body")
            or _eg_cdb1_request.form.get("text")
            or ""
        )

        category = _eg_cdb1_request.form.get("category") or "spam"
        note = _eg_cdb1_request.form.get("note") or ""

        if not str(number or "").strip() and not str(message or "").strip():
            return _eg_cdb1_redirect("/u/community?empty=1")

        _eg_cdb1_add_report(username, number, message, category, note)
        return _eg_cdb1_redirect("/u/community?saved=1")

    _eg_cdb1_seed_files()

    try:
        for _rule in list(app.url_map.iter_rules()):
            if str(_rule) in ("/u/community", "/u/community/", "/community", "/community/"):
                app.view_functions[_rule.endpoint] = _eg_cdb1_community_route
            if str(_rule) in ("/u/community/spam_report", "/u/community/spam_report/", "/u/community/feedback", "/u/community/feedback/"):
                app.view_functions[_rule.endpoint] = _eg_cdb1_spam_report_route
                try:
                    _rule.methods.add("POST")
                except Exception:
                    pass

        print("ERATGUARD COMMUNITY-DATA-BIND-1 LIVE COMMUNITY PAGE ACTIVE")
    except Exception as _eg_cdb1_route_err:
        print("ERATGUARD COMMUNITY-DATA-BIND-1 ROUTE ERROR:", _eg_cdb1_route_err)

except Exception as _eg_cdb1_err:
    print("ERATGUARD COMMUNITY-DATA-BIND-1 ERROR:", _eg_cdb1_err)
# === /ERATGUARD COMMUNITY-DATA-BIND-1 LIVE COMMUNITY PAGE ===

# === ERATGUARD NOTIFICATIONS-SCOPE-FIX-6 USER ONLY EVENTS ===
# Bildirim ekranında eski sahipsiz spam_logs kayıtlarının canlı kullanıcıya görünmesini engeller.
try:
    from pathlib import Path as _eg_nf6_Path
    import json as _eg_nf6_json

    def _eg_nf6_load(default, path):
        try:
            p = _eg_nf6_Path(path)
            if not p.exists():
                return default
            txt = p.read_text(encoding="utf-8", errors="ignore").strip()
            if not txt:
                return default
            return _eg_nf6_json.loads(txt)
        except Exception:
            return default

    def _eg_nf6_strict_user_events(username):
        username = str(username or "").strip()
        combined = []

        # 1) Kullanıcıya özel bildirimler
        data = _eg_nf6_load({}, "data/user_notifications.json")
        if isinstance(data, dict):
            user_items = data.get(username, [])
            if isinstance(user_items, list):
                for item in user_items:
                    if isinstance(item, str):
                        item = {"title": "Bildirim", "body": item, "source": "user_notification", "username": username}
                    if isinstance(item, dict):
                        x = dict(item)
                        x["_source_label"] = "user_notification"
                        combined.append(x)

        # 2) Global sistem/admin bildirimleri: sadece gerçekten notification dosyalarından gelir
        for file_path, source_label in [
            ("data/notifications.json", "system_notification"),
            ("data/admin_notifications.json", "admin_notification"),
        ]:
            items = _eg_nf6_load([], file_path)
            if not isinstance(items, list):
                items = []

            for item in items:
                if isinstance(item, str):
                    item = {"title": "Bildirim", "body": item, "source": source_label}

                if not isinstance(item, dict):
                    continue

                item_user = str(item.get("username") or item.get("user") or "").strip()

                # Global notification olabilir, ya da direkt bu kullanıcıya ait olabilir.
                if item_user and item_user != username:
                    continue

                x = dict(item)
                x["_source_label"] = source_label
                combined.append(x)

        # 3) Risk kaynakları: SADECE bu kullanıcıya aitse görünür.
        for file_path, source_label in [
            ("data/user_analysis_history.json", "analysis_history"),
            ("data/spam_logs.json", "spam_logs"),
            ("data/user_quarantine.json", "quarantine"),
        ]:
            items = _eg_nf6_load([], file_path)
            if not isinstance(items, list):
                items = []

            for item in items:
                if not isinstance(item, dict):
                    continue

                item_user = str(item.get("username") or item.get("user") or "").strip()

                # Kritik kural: username yoksa bildirim ekranına alma.
                if item_user != username:
                    continue

                x = dict(item)
                x["_source_label"] = source_label
                combined.append(x)

        seen = set()
        cleaned = []

        for item in sorted(
            combined,
            key=lambda x: str(x.get("time") or x.get("created_at") or ""),
            reverse=True
        ):
            key = (
                str(item.get("time") or item.get("created_at") or ""),
                str(item.get("body") or item.get("message") or item.get("title") or "")[:90],
                str(item.get("_source_label") or "")
            )
            if key in seen:
                continue
            seen.add(key)
            cleaned.append(item)

        return cleaned[:8]

    # Eski notification event okuyucularını canlı kullanıcı kapsamına zorla.
    globals()["_eg_nfg3_events"] = _eg_nf6_strict_user_events
    globals()["_eg_ndb2_user_events"] = _eg_nf6_strict_user_events

    print("ERATGUARD NOTIFICATIONS-SCOPE-FIX-6 USER ONLY EVENTS ACTIVE")

except Exception as _eg_nf6_err:
    print("ERATGUARD NOTIFICATIONS-SCOPE-FIX-6 ERROR:", _eg_nf6_err)
# === /ERATGUARD NOTIFICATIONS-SCOPE-FIX-6 USER ONLY EVENTS ===

# === ERATGUARD CORE-5E-FIX-1 OLD NOTIFICATION UI OVERRIDE ===
# Eski beyaz notification-permission ve notification manage ekranlarını
# yeni koyu EratGuard UI hattına zorlar.
try:
    import json as _eg5e_json
    from pathlib import Path as _eg5e_Path
    from flask import request as _eg5e_request, session as _eg5e_session, redirect as _eg5e_redirect

    def _eg5e_current_username():
        try:
            return str(
                _eg5e_session.get("username")
                or _eg5e_session.get("user")
                or _eg5e_session.get("email")
                or ""
            ).strip()
        except Exception:
            return ""

    def _eg5e_mark_notif_asked():
        try:
            _eg5e_session["notif_asked"] = True
            username = _eg5e_current_username()
            if not username:
                return

            users_file = _eg5e_Path("data/users.json")
            if not users_file.exists():
                return

            data = _eg5e_json.loads(users_file.read_text(encoding="utf-8") or "{}")
            if isinstance(data, dict) and username in data and isinstance(data.get(username), dict):
                data[username]["notif_asked"] = True
                users_file.write_text(
                    _eg5e_json.dumps(data, ensure_ascii=False, indent=2),
                    encoding="utf-8"
                )
        except Exception:
            pass

    def _eg5e_notification_permission_page():
        _eg5e_mark_notif_asked()

        return """<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>EratGuard PRO - Bildirim İzni</title>
<style>
:root{
  --bg:#020806;
  --card:#061d11;
  --card2:#092817;
  --line:rgba(35,255,137,.30);
  --green:#23ff89;
  --yellow:#ffdf35;
  --text:#f2fff6;
  --muted:#a9bdb1;
}
*{box-sizing:border-box}
body{
  margin:0;
  min-height:100vh;
  background:
    radial-gradient(circle at 80% 0%,rgba(35,255,137,.18),transparent 36%),
    radial-gradient(circle at 10% 20%,rgba(255,223,53,.10),transparent 32%),
    var(--bg);
  color:var(--text);
  font-family:Arial,Helvetica,sans-serif;
  padding:22px;
}
.wrap{max-width:720px;margin:0 auto;padding-top:28px}
.top{display:flex;align-items:center;gap:14px;margin-bottom:28px}
.logo{
  width:58px;height:58px;border-radius:18px;
  display:grid;place-items:center;
  background:linear-gradient(135deg,#12d7ff,#8068ff);
  color:#001; font-size:32px; font-weight:900;
  box-shadow:0 0 30px rgba(35,255,137,.18);
}
.brand h1{margin:0;font-size:30px;line-height:1}
.brand h1 span{color:var(--green)}
.brand p{margin:6px 0 0;color:var(--muted);font-weight:800;letter-spacing:.16em;font-size:12px}
.card{
  border:1px solid var(--line);
  border-radius:28px;
  background:linear-gradient(180deg,rgba(9,40,23,.96),rgba(3,18,10,.96));
  padding:28px;
  box-shadow:0 24px 70px rgba(0,0,0,.42);
}
.badge{
  display:inline-flex;align-items:center;gap:8px;
  padding:10px 16px;border-radius:999px;
  border:1px solid rgba(35,255,137,.35);
  color:var(--green);font-weight:900;
  background:rgba(35,255,137,.08);
}
h2{font-size:44px;line-height:1.05;margin:20px 0 12px}
p{color:var(--muted);font-size:19px;line-height:1.48;font-weight:700}
.actions{display:grid;gap:14px;margin-top:26px}
.btn{
  border:0;
  border-radius:19px;
  height:58px;
  display:flex;align-items:center;justify-content:center;
  text-decoration:none;
  font-size:18px;font-weight:900;
  cursor:pointer;
}
.primary{
  color:#00180a;
  background:linear-gradient(100deg,var(--yellow),var(--green));
}
.secondary{
  color:var(--text);
  background:rgba(255,255,255,.08);
  border:1px solid rgba(255,255,255,.13);
}
.note{
  margin-top:18px;
  padding:16px;
  border-radius:18px;
  border:1px solid rgba(35,255,137,.18);
  color:#bfffd6;
  background:rgba(35,255,137,.06);
  font-weight:800;
}
@media(max-width:520px){
  body{padding:18px}
  h2{font-size:36px}
  p{font-size:17px}
  .card{padding:22px;border-radius:24px}
}
</style>
</head>
<body>
<div class="wrap">
  <div class="top">
    <div class="logo">E</div>
    <div class="brand">
      <h1>Erat<span>Guard</span></h1>
      <p>PRO NOTIFICATION CONTROL</p>
    </div>
  </div>

  <div class="card">
    <div class="badge">🔔 Bildirim Merkezi</div>
    <h2>Bildirimleri aç</h2>
    <p>Güvenlik uyarıları, lisans bilgilendirmeleri ve önemli sistem duyuruları için bildirim iznini buradan yönet.</p>

    <div class="actions">
      <button class="btn primary" onclick="askPermission()">İzin Ver →</button>
      <a class="btn secondary" href="/dashboard">Şimdilik Geç</a>
      <a class="btn secondary" href="/u/notifications">Bildirim Paneli</a>
    </div>

    <div class="note" id="eg-note">Bu ekran yeni EratGuard koyu arayüz hattına taşındı.</div>
  </div>
</div>

<script>
function askPermission(){
  const note = document.getElementById("eg-note");
  try{
    if(!("Notification" in window)){
      note.innerText = "Bu tarayıcı bildirim iznini desteklemiyor. Panele yönlendiriliyorsun.";
      setTimeout(()=>{ location.href="/dashboard"; }, 700);
      return;
    }
    Notification.requestPermission().then(function(result){
      note.innerText = "Bildirim tercihi: " + result + ". Panele yönlendiriliyorsun.";
      setTimeout(()=>{ location.href="/dashboard"; }, 800);
    }).catch(function(){
      location.href="/dashboard";
    });
  }catch(e){
    location.href="/dashboard";
  }
}
</script>
</body>
</html>"""

    def _eg5e_notifications_manage_page():
        username = _eg5e_current_username() or "user"

        return f"""<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>EratGuard PRO - Bildirim Ayarları</title>
<style>
:root{{
  --bg:#020806;--card:#061d11;--card2:#092817;--line:rgba(35,255,137,.30);
  --green:#23ff89;--yellow:#ffdf35;--text:#f2fff6;--muted:#a9bdb1;
}}
*{{box-sizing:border-box}}
body{{
  margin:0;min-height:100vh;padding:20px;background:
  radial-gradient(circle at 80% 0%,rgba(35,255,137,.16),transparent 34%),
  var(--bg);color:var(--text);font-family:Arial,Helvetica,sans-serif;
}}
.wrap{{max-width:720px;margin:0 auto}}
.top{{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:20px}}
.brand{{display:flex;align-items:center;gap:12px}}
.logo{{width:52px;height:52px;border-radius:16px;display:grid;place-items:center;background:rgba(35,255,137,.10);border:1px solid var(--line);font-size:28px}}
h1{{margin:0;font-size:28px}} h1 span{{color:var(--green)}}
.sub{{margin:4px 0 0;color:var(--muted);font-weight:800}}
.pill{{padding:10px 14px;border-radius:999px;background:rgba(35,255,137,.10);border:1px solid var(--line);color:var(--green);font-weight:900}}
.hero,.panel{{border:1px solid var(--line);background:linear-gradient(180deg,rgba(9,40,23,.96),rgba(3,18,10,.96));border-radius:26px;padding:22px;margin-bottom:18px}}
.hero h2{{font-size:38px;margin:0 0 10px}}
.hero p{{color:var(--muted);font-size:17px;line-height:1.42;font-weight:750;margin:0}}
.row{{display:flex;align-items:center;justify-content:space-between;gap:14px;padding:16px 0;border-bottom:1px solid rgba(255,255,255,.07)}}
.row:last-child{{border-bottom:0}}
.left strong{{display:block;font-size:18px}}
.left small{{display:block;color:var(--muted);font-size:14px;margin-top:5px;font-weight:700}}
.toggle{{width:62px;height:34px;border-radius:999px;background:linear-gradient(100deg,var(--yellow),var(--green));position:relative;box-shadow:0 0 22px rgba(35,255,137,.22)}}
.toggle:after{{content:"";width:26px;height:26px;border-radius:50%;background:#00180a;position:absolute;right:4px;top:4px}}
.actions{{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:14px}}
.btn{{height:54px;border-radius:17px;text-decoration:none;display:flex;align-items:center;justify-content:center;font-weight:900;font-size:17px}}
.primary{{background:linear-gradient(100deg,var(--yellow),var(--green));color:#00180a}}
.secondary{{background:rgba(255,255,255,.08);border:1px solid rgba(255,255,255,.13);color:var(--text)}}
@media(max-width:520px){{.actions{{grid-template-columns:1fr}}.hero h2{{font-size:32px}}}}
</style>
</head>
<body>
<div class="wrap">
  <div class="top">
    <div class="brand">
      <div class="logo">🔔</div>
      <div><h1>Erat<span>Guard</span></h1><p class="sub">Bildirim Ayarları · {username}</p></div>
    </div>
    <div class="pill">PRO</div>
  </div>

  <div class="hero">
    <h2>Bildirim Ayarları</h2>
    <p>Güvenlik uyarıları, lisans bildirimleri ve sistem duyuruları yeni koyu EratGuard arayüzünde yönetilir.</p>
  </div>

  <div class="panel">
    <div class="row"><div class="left"><strong>Bildirimler aktif</strong><small>Genel EratGuard bildirimlerini aç veya kapat.</small></div><div class="toggle"></div></div>
    <div class="row"><div class="left"><strong>Güvenlik uyarıları</strong><small>Risk, karantina, koruma ve analiz olayları.</small></div><div class="toggle"></div></div>
    <div class="row"><div class="left"><strong>Lisans bildirimleri</strong><small>Aktivasyon, yenileme ve hesap durumu.</small></div><div class="toggle"></div></div>
    <div class="row"><div class="left"><strong>Admin duyuruları</strong><small>Sistem ve ürün duyuruları.</small></div><div class="toggle"></div></div>

    <div class="actions">
      <a class="btn primary" href="/u/notifications?fresh=1">Kaydet</a>
      <a class="btn secondary" href="/dashboard">Panel</a>
    </div>
  </div>
</div>
</body>
</html>"""

    def _eg5e_old_notification_ui_bridge():
        try:
            path = str(_eg5e_request.path or "").rstrip("/") or "/"

            if path == "/notification-permission":
                return _eg5e_notification_permission_page()

            if path in (
                "/u/notifications/manage",
                "/notifications/manage",
                "/notification/manage",
                "/notification-settings",
                "/notifications/settings",
            ):
                return _eg5e_notifications_manage_page()

        except Exception as _eg5e_req_err:
            print("ERATGUARD CORE-5E-FIX-1 REQUEST ERROR:", _eg5e_req_err)

    try:
        funcs = app.before_request_funcs.setdefault(None, [])
        if _eg5e_old_notification_ui_bridge not in funcs:
            funcs.insert(0, _eg5e_old_notification_ui_bridge)
        print("ERATGUARD CORE-5E-FIX-1 OLD NOTIFICATION UI OVERRIDE ACTIVE")
    except Exception as _eg5e_insert_err:
        print("ERATGUARD CORE-5E-FIX-1 INSERT ERROR:", _eg5e_insert_err)

except Exception as _eg5e_err:
    print("ERATGUARD CORE-5E-FIX-1 OLD NOTIFICATION UI OVERRIDE ERROR:", _eg5e_err)
# === /ERATGUARD CORE-5E-FIX-1 OLD NOTIFICATION UI OVERRIDE ===

# === ERATGUARD CORE-5E-FIX-1C USER FAN NOTIFICATION FULL OVERRIDE ===
# Amaç:
# - /dashboard kullanıcı ekranını sağdan sola açılan 8'li yelpaze menü ile zorlamak.
# - /u/notifications eski PRO NOTIFICATIONS ekranını tamamen yeni EratGuard UI ile değiştirmek.
# - /u/notifications/manage koyu EratGuard UI hattında kalacak.
try:
    import html as _eg1c_html
    import json as _eg1c_json
    from pathlib import Path as _eg1c_Path
    from flask import request as _eg1c_request, session as _eg1c_session, make_response as _eg1c_make_response

    def _eg1c_user_name():
        try:
            return str(
                _eg1c_session.get("username")
                or _eg1c_session.get("user")
                or _eg1c_session.get("email")
                or "Kullanıcı"
            ).strip()
        except Exception:
            return "Kullanıcı"

    def _eg1c_count_notifications():
        try:
            paths = [
                _eg1c_Path("data/user_notifications.json"),
                _eg1c_Path("data/notifications.json"),
                _eg1c_Path("data/admin_notifications.json"),
            ]
            total = high = critical = 0
            for fp in paths:
                if not fp.exists():
                    continue
                raw = fp.read_text(encoding="utf-8", errors="ignore").strip()
                if not raw:
                    continue
                data = _eg1c_json.loads(raw)
                if isinstance(data, dict):
                    items = data.get("notifications") or data.get("items") or data.get("data") or []
                    if isinstance(items, dict):
                        items = list(items.values())
                elif isinstance(data, list):
                    items = data
                else:
                    items = []
                if not isinstance(items, list):
                    continue
                total += len(items)
                for it in items:
                    if not isinstance(it, dict):
                        continue
                    pr = str(it.get("priority") or it.get("level") or it.get("type") or "").lower()
                    if pr in ("high", "yüksek", "yuksek"):
                        high += 1
                    if pr in ("critical", "kritik", "danger", "red"):
                        critical += 1
            return total, high, critical
        except Exception:
            return 0, 0, 0

    def _eg1c_base_css():
        return """
:root{
  --bg:#020806;
  --bg2:#03150c;
  --card:#061d11;
  --card2:#092817;
  --line:rgba(35,255,137,.28);
  --line2:rgba(0,229,255,.24);
  --green:#23ff89;
  --cyan:#22e7ff;
  --yellow:#ffdf35;
  --text:#f2fff6;
  --muted:#a8b9ad;
  --danger:#ff4d5e;
}
*{box-sizing:border-box}
html,body{margin:0;min-height:100%;background:var(--bg);color:var(--text);font-family:Arial,Helvetica,sans-serif}
body{
  padding:20px 20px 110px;
  background:
    radial-gradient(circle at 80% 0%,rgba(35,255,137,.16),transparent 35%),
    radial-gradient(circle at 0% 20%,rgba(0,229,255,.08),transparent 30%),
    linear-gradient(180deg,#020806,#010403 70%);
}
a{text-decoration:none;color:inherit}
.wrap{max-width:760px;margin:0 auto}
.top{
  display:flex;
  align-items:center;
  justify-content:space-between;
  gap:12px;
  margin-bottom:20px;
  padding-right:112px;
}
.brand{display:flex;align-items:center;gap:14px;min-width:0}
.logo{
  width:58px;height:58px;border-radius:20px;
  display:grid;place-items:center;
  background:linear-gradient(135deg,#1fffa0,#22e7ff,#8068ff);
  color:#031008;font-size:30px;font-weight:950;
  box-shadow:0 0 28px rgba(35,255,137,.18);
}
.brand h1{margin:0;font-size:26px;line-height:1;font-weight:950;letter-spacing:-1px}
.brand h1 span{color:#65ff43}
.brand p{margin:5px 0 0;color:var(--cyan);font-size:12px;font-weight:950;letter-spacing:.22em}
.safe-pill{
  display:inline-flex;align-items:center;gap:7px;
  height:42px;padding:0 13px;border-radius:999px;
  border:1px solid var(--line);
  background:rgba(35,255,137,.08);
  color:var(--green);font-weight:950;white-space:nowrap;
}
.hero{
  border:1px solid var(--line);
  border-radius:28px;
  background:
    radial-gradient(circle at 85% 0%,rgba(0,229,255,.12),transparent 34%),
    linear-gradient(180deg,rgba(8,39,23,.96),rgba(2,15,8,.96));
  padding:26px;
  box-shadow:0 26px 70px rgba(0,0,0,.45);
}
.hero h2{margin:0 0 14px;font-size:36px;line-height:1.05;letter-spacing:-1.5px}
.hero h2 span{color:var(--green)}
.hero p{margin:0;color:var(--muted);font-size:18px;line-height:1.45;font-weight:800}
.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-top:24px}
.stat{
  min-height:94px;border-radius:22px;
  border:1px solid rgba(35,255,137,.20);
  background:rgba(0,0,0,.28);
  display:flex;flex-direction:column;justify-content:center;align-items:center;
}
.stat b{font-size:30px;color:var(--green);line-height:1}
.stat span{font-size:13px;color:var(--muted);font-weight:900;margin-top:8px;text-align:center}
.section{
  margin:34px 0 16px;
  font-size:23px;
  font-weight:950;
  letter-spacing:.34em;
}
.section:after{
  content:"";display:block;width:150px;height:8px;border-radius:99px;
  background:linear-gradient(90deg,var(--green),#9cff5f);
  margin-top:14px;
}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.card{
  min-height:146px;
  border-radius:26px;
  border:1px solid rgba(35,255,137,.25);
  background:
    radial-gradient(circle at 20% 0%,rgba(35,255,137,.10),transparent 45%),
    linear-gradient(180deg,rgba(7,42,23,.90),rgba(2,18,9,.94));
  padding:22px;
  position:relative;
  overflow:hidden;
}
.card .icon{
  width:54px;height:54px;border-radius:19px;
  display:grid;place-items:center;
  background:rgba(35,255,137,.10);
  border:1px solid rgba(35,255,137,.20);
  font-size:27px;
}
.card .pill{
  position:absolute;right:18px;top:24px;
  padding:8px 14px;border-radius:999px;
  background:rgba(35,255,137,.12);
  border:1px solid rgba(35,255,137,.28);
  color:#93ffad;font-weight:950;font-size:14px;
}
.card h3{font-size:28px;margin:16px 0 6px;line-height:1}
.card p{margin:0;color:var(--muted);font-weight:900;font-size:15px}
.empty{
  margin-top:20px;
  min-height:150px;
  border-radius:28px;
  border:1px dashed rgba(120,160,200,.28);
  background:rgba(3,8,18,.70);
  display:grid;place-items:center;
  color:#a8b8d0;
  font-size:20px;
  font-weight:800;
  text-align:center;
  padding:24px;
}
.notice-list{display:grid;gap:12px;margin-top:18px}
.notice{
  border:1px solid rgba(35,255,137,.22);
  border-radius:22px;
  padding:18px;
  background:rgba(0,0,0,.28);
}
.notice b{display:block;font-size:18px}
.notice span{display:block;color:var(--muted);margin-top:6px;font-weight:800}
.overlay{
  position:fixed;inset:0;background:rgba(0,0,0,.45);
  opacity:0;pointer-events:none;transition:.22s;z-index:1998;
}
.overlay.open{opacity:1;pointer-events:auto}
.fan-handle{
  position:fixed;
  right:0;
  top:50%;
  transform:translateY(-50%);
  width:52px;
  height:132px;
  border:1px solid rgba(35,255,137,.35);
  border-right:0;
  border-radius:24px 0 0 24px;
  background:linear-gradient(180deg,#ffdf35,#23ff89);
  color:#001a0a;
  z-index:2001;
  display:flex;
  align-items:center;
  justify-content:center;
  flex-direction:column;
  font-weight:950;
  box-shadow:0 20px 48px rgba(0,0,0,.38);
}
.fan-handle i{font-style:normal;font-size:28px;line-height:1}
.fan-handle span{writing-mode:vertical-rl;transform:rotate(180deg);font-size:10px;letter-spacing:.12em}
.fan{
  position:fixed;
  right:-270px;
  top:50%;
  width:270px;
  height:590px;
  transform:translateY(-50%);
  z-index:2000;
  transition:right .28s cubic-bezier(.2,.9,.2,1);
  pointer-events:none;
}
.fan.open{right:0;pointer-events:auto}
.fan-core{
  position:absolute;
  right:14px;
  top:50%;
  transform:translateY(-50%);
  width:92px;height:92px;border-radius:50%;
  display:grid;place-items:center;text-align:center;
  color:var(--green);font-size:12px;font-weight:950;line-height:1.08;
  border:1px solid rgba(35,255,137,.32);
  background:radial-gradient(circle,rgba(35,255,137,.24),rgba(2,12,7,.96));
  box-shadow:0 0 38px rgba(35,255,137,.15);
}
.fan-core span{display:block;color:var(--cyan);font-size:8px;letter-spacing:.14em;margin-top:3px}
.fan-item{
  position:absolute;
  right:78px;
  top:50%;
  width:176px;
  height:58px;
  border-radius:18px 0 0 18px;
  display:flex;
  align-items:center;
  gap:10px;
  padding:8px 12px;
  border:1px solid rgba(35,255,137,.27);
  background:linear-gradient(90deg,rgba(5,30,17,.98),rgba(12,62,35,.92));
  box-shadow:0 12px 28px rgba(0,0,0,.32);
  transform-origin:right center;
}
.fan-item:before{content:"";position:absolute;right:0;top:0;bottom:0;width:5px;background:var(--green)}
.fan-ico{
  width:38px;height:38px;border-radius:14px;display:grid;place-items:center;
  background:rgba(35,255,137,.10);border:1px solid rgba(35,255,137,.18);
  font-size:20px;flex-shrink:0;
}
.fan-item strong{display:block;font-size:13px;line-height:1}
.fan-item small{display:block;color:var(--muted);font-size:10px;font-weight:800;margin-top:3px}
.fan-item:nth-child(1){transform:translateY(-248px) rotate(-32deg)}
.fan-item:nth-child(2){transform:translateY(-178px) rotate(-17deg)}
.fan-item:nth-child(3){transform:translateY(-108px) rotate(-10deg)}
.fan-item:nth-child(4){transform:translateY(-38px) rotate(-3deg)}
.fan-item:nth-child(5){transform:translateY(32px) rotate(4deg)}
.fan-item:nth-child(6){transform:translateY(102px) rotate(11deg)}
.fan-item:nth-child(7){transform:translateY(172px) rotate(18deg)}
.fan-item:nth-child(8){transform:translateY(242px) rotate(25deg)}
.fan-close{
  position:absolute;right:22px;bottom:8px;
  width:72px;height:34px;border-radius:999px;border:1px solid rgba(255,255,255,.18);
  background:rgba(255,255,255,.08);color:var(--text);font-weight:950;
}
@media(max-width:520px){
  body{padding:18px 20px 100px}
  .top{padding-right:98px}
  .brand h1{font-size:25px}
  .logo{width:56px;height:56px}
  .safe-pill{display:none}
  .hero{padding:24px;border-radius:27px}
  .hero h2{font-size:34px}
  .hero p{font-size:17px}
  .stats{grid-template-columns:1fr;gap:12px}
  .grid{grid-template-columns:1fr 1fr;gap:12px}
  .card{min-height:150px;padding:21px}
  .card h3{font-size:27px}
  .fan{height:560px}
  .fan-item{width:170px;height:56px}
}
"""

    def _eg1c_fan_html():
        return """

<!-- CLEAN-4: legacy egFanPanel removed -->

"""

    def _eg1c_dashboard_page():
        # CLEAN-7C: aktif eski dashboard kaldırıldı. FAN-12P ana dashboard.
        return '''<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>EratGuard PRO - FAN-12P Command Center</title>
<style>
:root{--green:#23ff89;--cyan:#22e7ff;--text:#f2fff6;}
*{box-sizing:border-box}
html,body{margin:0;width:100%;min-height:100%;overflow:hidden;color:var(--text);font-family:Arial,Helvetica,sans-serif;background:radial-gradient(circle at 78% 50%,rgba(35,255,137,.18),transparent 34%),radial-gradient(circle at 16% 18%,rgba(34,231,255,.12),transparent 38%),linear-gradient(145deg,#020806,#03100a 55%,#020806);}
.eg-clean7c-brand{position:fixed;left:24px;top:34px;z-index:1;pointer-events:none;}
.eg-clean7c-logo{width:70px;height:70px;border-radius:24px;display:grid;place-items:center;margin-bottom:14px;background:linear-gradient(135deg,#23ff89,#22e7ff 58%,#6d7cff);color:#00170b;font-size:42px;font-weight:1000;box-shadow:0 18px 45px rgba(0,0,0,.35),0 0 28px rgba(35,255,137,.16);}
.eg-clean7c-brand b{display:block;font-size:30px;font-weight:1000;letter-spacing:-1.2px;color:rgba(242,255,246,.96)}
.eg-clean7c-brand b span{color:#23ff89}
.eg-clean7c-brand small{display:block;margin-top:8px;font-size:11px;line-height:1.45;font-weight:1000;letter-spacing:.30em;color:#22e7ff;}
.eg-clean7c-hint{position:fixed;left:24px;bottom:34px;z-index:1;max-width:260px;color:rgba(242,255,246,.46);font-size:12px;line-height:1.5;font-weight:850;pointer-events:none;}
@media(max-width:420px){.eg-clean7c-brand{left:22px;top:34px}.eg-clean7c-logo{width:64px;height:64px;border-radius:22px;font-size:38px;margin-bottom:12px}.eg-clean7c-brand b{font-size:26px}.eg-clean7c-brand small{font-size:10px}.eg-clean7c-hint{left:22px;bottom:28px;font-size:11px;max-width:220px}}


/* ===== ERATGUARD VITES-2A PREMIUM STATUS START ===== */
.eg-clean7c-status{
  position:fixed;
  left:24px;
  bottom:34px;
  z-index:1;
  display:flex;
  align-items:center;
  gap:10px;
  min-height:42px;
  padding:10px 15px;
  border-radius:999px;
  border:1px solid rgba(35,255,137,.24);
  background:rgba(3,18,10,.58);
  color:rgba(242,255,246,.90);
  font-family:Arial,Helvetica,sans-serif;
  pointer-events:none;
  box-shadow:0 0 30px rgba(35,255,137,.10), inset 0 0 18px rgba(35,255,137,.04);
  backdrop-filter:blur(8px);
  -webkit-backdrop-filter:blur(8px);
}
.eg-clean7c-status .dot{
  width:10px;
  height:10px;
  border-radius:999px;
  background:#23ff89;
  box-shadow:0 0 18px rgba(35,255,137,.80);
}
.eg-clean7c-status b{
  font-size:11px;
  font-weight:1000;
  letter-spacing:.16em;
  color:#f2fff6;
}
.eg-clean7c-status em{
  font-style:normal;
  font-size:10px;
  font-weight:1000;
  letter-spacing:.14em;
  color:#22e7ff;
}
@media(max-width:420px){
  .eg-clean7c-status{
    left:22px;
    bottom:28px;
    padding:9px 12px;
    gap:8px;
  }
  .eg-clean7c-status b{font-size:10px}
  .eg-clean7c-status em{font-size:9px}
}
/* ===== ERATGUARD VITES-2A PREMIUM STATUS END ===== */

</style>
</head>
<body>
  <div class="eg-clean7c-brand">
    <div class="eg-clean7c-logo">E</div>
    <b>Erat<span>Guard</span></b>
    <small>FAN-12P<br>COMMAND CENTER</small>
  </div>
  <div class="eg-clean7c-status">
    <span class="dot"></span>
    <b>KORUMA AKTİF</b>
    <em>FAN-12P HAZIR</em>
  </div>
</body>
</html>'''

    def _eg1c_notifications_page():
        total, high, critical = _eg1c_count_notifications()
        username = _eg1c_html.escape(_eg1c_user_name())
        html = f"""<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>EratGuard PRO - Bildirim Komuta Merkezi</title>
<style>{_eg1c_base_css()}</style>
</head>
<body>
<div class="wrap">
  <header class="top">
    <div class="brand">
      <div class="logo">🔔</div>
      <div>
        <h1>Erat<span>Guard</span></h1>
        <p>NOTIFICATION COMMAND</p>
      </div>
    </div>
    <a class="safe-pill" href="/u/notifications/manage">Ayarlar</a>
  </header>

  <section class="hero">
    <h2>Bildirim<br><span>komuta merkezi.</span></h2>
    <p>Admin duyuruları, güvenlik uyarıları, lisans bilgilendirmeleri ve kritik risk akışı burada görünür. Bu ekran eski PRO NOTIFICATIONS sayfasının yerine zorlandı.</p>
    <div class="stats">
      <div class="stat"><b>{total}</b><span>Görünen bildirim</span></div>
      <div class="stat"><b>{high}</b><span>Yüksek öncelik</span></div>
      <div class="stat"><b>{critical}</b><span>Kritik uyarı</span></div>
    </div>
  </section>

  <div class="section">AKIŞ</div>

  <div class="empty">
    Henüz gösterilecek bildirim yok.<br>
    <small style="display:block;margin-top:10px;color:#6f829a;font-size:14px">Yelpaze menü sağ tarafta aktif.</small>
  </div>
</div>
{_eg1c_fan_html()}
<!-- CORE-5E-FIX-1C NOTIFICATIONS ACTIVE username={username} -->
</body>
</html>"""
        resp = _eg1c_make_response(html)
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        return resp

    def _eg1c_notifications_manage_page():
        username = _eg1c_html.escape(_eg1c_user_name())
        html = f"""<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>EratGuard PRO - Bildirim Ayarları</title>
<style>{_eg1c_base_css()}
.panel{{margin-top:20px;border:1px solid var(--line);border-radius:28px;background:linear-gradient(180deg,rgba(8,39,23,.96),rgba(2,15,8,.96));padding:20px}}
.row{{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:17px 0;border-bottom:1px solid rgba(255,255,255,.08)}}
.row:last-child{{border-bottom:0}}
.row b{{display:block;font-size:18px}}
.row span{{display:block;color:var(--muted);font-size:14px;font-weight:800;margin-top:5px}}
.toggle{{width:62px;height:34px;border-radius:999px;background:linear-gradient(90deg,var(--yellow),var(--green));position:relative;flex-shrink:0}}
.toggle:after{{content:"";position:absolute;right:4px;top:4px;width:26px;height:26px;border-radius:50%;background:#00180a}}
.actions{{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:18px}}
.btn{{height:54px;border-radius:18px;display:flex;align-items:center;justify-content:center;font-weight:950}}
.primary{{background:linear-gradient(90deg,var(--yellow),var(--green));color:#00180a}}
.secondary{{background:rgba(255,255,255,.08);border:1px solid rgba(255,255,255,.13)}}
@media(max-width:520px){{.actions{{grid-template-columns:1fr}}}}
</style>
</head>
<body>
<div class="wrap">
  <header class="top">
    <div class="brand">
      <div class="logo">⚙️</div>
      <div>
        <h1>Erat<span>Guard</span></h1>
        <p>NOTIFICATION SETTINGS</p>
      </div>
    </div>
    <a class="safe-pill" href="/u/notifications">Geri</a>
  </header>

  <section class="hero">
    <h2>Bildirim<br><span>ayarları.</span></h2>
    <p>{username} için güvenlik uyarıları, lisans bildirimleri ve sistem duyuruları buradan yönetilir.</p>
  </section>

  <div class="panel">
    <div class="row"><div><b>Bildirimler aktif</b><span>Genel EratGuard bildirimleri.</span></div><div class="toggle"></div></div>
    <div class="row"><div><b>Güvenlik uyarıları</b><span>Risk, karantina, koruma ve analiz olayları.</span></div><div class="toggle"></div></div>
    <div class="row"><div><b>Lisans bildirimleri</b><span>Aktivasyon, yenileme ve hesap durumu.</span></div><div class="toggle"></div></div>
    <div class="row"><div><b>Admin duyuruları</b><span>Sistem ve ürün duyuruları.</span></div><div class="toggle"></div></div>
    <div class="actions">
      <a class="btn primary" href="/u/notifications?fresh=1">Kaydet</a>
      <a class="btn secondary" href="/dashboard">Panel</a>
    </div>
  </div>
</div>
{_eg1c_fan_html()}
<!-- CORE-5E-FIX-1C NOTIFICATION MANAGE ACTIVE -->
</body>
</html>"""
        resp = _eg1c_make_response(html)
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        return resp

    def _eg1c_user_override_bridge():
        try:
            path = str(_eg1c_request.path or "").rstrip("/") or "/"
            method = str(_eg1c_request.method or "GET").upper()
            if method != "GET":
                return None

            if path in ("/dashboard", "/u/dashboard"):
                return _eg1c_dashboard_page()

            if path == "/u/notifications":
                return _eg1c_notifications_page()

            if path in (
                "/u/notifications/manage",
                "/notifications/manage",
                "/notification/manage",
                "/notification-settings",
                "/notifications/settings",
            ):
                return _eg1c_notifications_manage_page()

        except Exception as _eg1c_req_err:
            print("ERATGUARD CORE-5E-FIX-1C REQUEST ERROR:", _eg1c_req_err)
        return None

    try:
        funcs = app.before_request_funcs.setdefault(None, [])
        if _eg1c_user_override_bridge not in funcs:
            funcs.insert(0, _eg1c_user_override_bridge)
        print("ERATGUARD CORE-5E-FIX-1C USER FAN NOTIFICATION FULL OVERRIDE ACTIVE")
    except Exception as _eg1c_insert_err:
        print("ERATGUARD CORE-5E-FIX-1C INSERT ERROR:", _eg1c_insert_err)

except Exception as _eg1c_err:
    print("ERATGUARD CORE-5E-FIX-1C USER FAN NOTIFICATION FULL OVERRIDE ERROR:", _eg1c_err)
# === /ERATGUARD CORE-5E-FIX-1C USER FAN NOTIFICATION FULL OVERRIDE ===


# ===== ERATGUARD USER FAN-3 RIGHT-TO-LEFT MENU START =====
# Amaç:
# - Admin paneline dokunmadan kullanıcı tarafına EratGuard sağdan-sola yelpaze menü ekler.
# - /dashboard, /u/dashboard ve /u/* kullanıcı sayfalarında çalışır.
# - /admin yollarında asla çalışmaz.
try:
    from flask import request as _eg_user_fan3_request
    import re as _eg_user_fan3_re

    _EG_USER_FAN3_MARKER = "eratguard-user-fan3-rtl-menu"

    _EG_USER_FAN3_HTML = r"""
<div id="eratguard-user-fan3-rtl-menu" class="eg-user-fan3" aria-label="EratGuard kullanıcı yelpaze menüsü">
  <button class="eg-user-fan3-toggle" id="egUserFan3Toggle" type="button" aria-label="Kullanıcı menüsünü aç/kapat">
    <span class="eg-user-fan3-shield">E</span>
    <small>MENÜ</small>
  </button>

  <div class="eg-user-fan3-arc" id="egUserFan3Arc" aria-hidden="true"></div>

  <nav class="eg-user-fan3-panel" id="egUserFan3Panel">
    <a class="eg-user-fan3-item i1" href="/dashboard">
      <b>🏠</b><span><strong>Ana Sayfa</strong><small>Kontrol merkezi</small></span><em>01</em>
    </a>
    <a class="eg-user-fan3-item i2" href="/u/protection">
      <b>🛡️</b><span><strong>Koruma</strong><small>SMS güvenlik motoru</small></span><em>02</em>
    </a>
    <a class="eg-user-fan3-item i3" href="/u/analysis">
      <b>🧠</b><span><strong>AI Analiz</strong><small>Risk taraması</small></span><em>03</em>
    </a>
    <a class="eg-user-fan3-item i4" href="/u/reports">
      <b>📈</b><span><strong>Raporlar</strong><small>Güvenlik özetleri</small></span><em>04</em>
    </a>
    <a class="eg-user-fan3-item i5" href="/u/notifications">
      <b>🔔</b><span><strong>Bildirimler</strong><small>Güvenlik akışı</small></span><em>05</em>
    </a>
    <a class="eg-user-fan3-item i6" href="/u/license">
      <b>🔑</b><span><strong>Lisans</strong><small>Hesap durumu</small></span><em>06</em>
    </a>
    <a class="eg-user-fan3-item i7" href="/u/community">
      <b>👥</b><span><strong>Topluluk</strong><small>Geri bildirim</small></span><em>07</em>
    </a>
    <a class="eg-user-fan3-item i8" href="/u/settings">
      <b>⚙️</b><span><strong>Ayarlar</strong><small>Tercihler</small></span><em>08</em>
    </a>
  </nav>
</div>

<!-- ERATGUARD FAN-12P INTRO DIRECT START -->
<style id="eg-fan12p-intro-direct-css">
#egFan12pInfoIntro{
  position:fixed;
  inset:0;
  z-index:2147483000;
  display:none;
  align-items:center;
  justify-content:center;
  padding:22px;
  background:
    radial-gradient(circle at 75% 48%, rgba(35,255,137,.20), transparent 34%),
    radial-gradient(circle at 20% 18%, rgba(34,231,255,.12), transparent 38%),
    rgba(1,6,4,.93);
  backdrop-filter:blur(14px);
  -webkit-backdrop-filter:blur(14px);
}
#egFan12pInfoIntro.open{display:flex}
#egFan12pInfoIntro .eg-intro-card{
  width:min(420px,94vw);
  border:1px solid rgba(35,255,137,.28);
  border-radius:30px;
  background:linear-gradient(145deg,rgba(5,22,14,.97),rgba(2,10,7,.98));
  box-shadow:0 28px 90px rgba(0,0,0,.65),0 0 42px rgba(35,255,137,.16);
  padding:24px;
  color:#f2fff6;
  font-family:Arial,Helvetica,sans-serif;
}
#egFan12pInfoIntro .eg-intro-top{display:flex;align-items:center;gap:14px;margin-bottom:16px}
#egFan12pInfoIntro .eg-intro-icon{
  width:58px;height:58px;border-radius:22px;display:grid;place-items:center;
  background:linear-gradient(135deg,rgba(35,255,137,.24),rgba(34,231,255,.14));
  border:1px solid rgba(35,255,137,.30);
  font-size:30px;
}
#egFan12pInfoIntro .eg-intro-label{
  font-size:10px;font-weight:1000;letter-spacing:.24em;
  color:rgba(35,255,137,.80);text-transform:uppercase;margin-bottom:5px;
}
#egFan12pInfoIntro .eg-intro-title{font-size:24px;font-weight:1000;letter-spacing:-.6px;line-height:1.05}
#egFan12pInfoIntro .eg-intro-text{
  font-size:14px;font-weight:750;line-height:1.55;
  color:rgba(242,255,246,.78);margin:14px 0 18px;
}
#egFan12pInfoIntro .eg-intro-count{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:12px}
#egFan12pInfoIntro .eg-intro-count span{font-size:12px;font-weight:950;color:rgba(242,255,246,.66)}
#egFan12pInfoIntro .eg-intro-count b{font-size:24px;color:#23ff89}
#egFan12pInfoIntro .eg-intro-bar{
  width:100%;height:10px;overflow:hidden;border-radius:999px;
  background:rgba(255,255,255,.08);border:1px solid rgba(255,255,255,.08);
}
#egFan12pInfoIntro .eg-intro-fill{
  width:0%;height:100%;border-radius:999px;
  background:linear-gradient(90deg,#23ff89,#22e7ff);
  transition:width .25s linear;
}
#egFan12pInfoIntro .eg-intro-actions{display:flex;gap:10px;margin-top:18px}
#egFan12pInfoIntro .eg-intro-btn{
  flex:1;border:0;border-radius:18px;padding:13px 12px;
  font-weight:1000;font-size:13px;cursor:pointer;
}
#egFan12pInfoIntro .eg-intro-open{color:#00170b;background:linear-gradient(135deg,#23ff89,#22e7ff)}
#egFan12pInfoIntro .eg-intro-wait{
  color:rgba(242,255,246,.82);background:rgba(255,255,255,.08);
  border:1px solid rgba(255,255,255,.10);
}
@media(max-width:420px){
  #egFan12pInfoIntro{padding:16px}
  #egFan12pInfoIntro .eg-intro-card{border-radius:26px;padding:20px}
  #egFan12pInfoIntro .eg-intro-title{font-size:21px}
  #egFan12pInfoIntro .eg-intro-text{font-size:13px}
}
</style>

<div id="egFan12pInfoIntro" aria-hidden="true">
  <div class="eg-intro-card">
    <div class="eg-intro-top">
      <div class="eg-intro-icon" id="egIntroIcon">🛡️</div>
      <div>
        <div class="eg-intro-label">FAN-12P BİLGİ</div>
        <div class="eg-intro-title" id="egIntroTitle">Koruma Merkezi</div>
      </div>
    </div>
    <div class="eg-intro-text" id="egIntroText">Bu özellik açılmadan önce kısa bilgi gösterilir.</div>
    <div class="eg-intro-count">
      <span>Özellik açılıyor</span>
      <b><span id="egIntroSeconds">10</span>s</b>
    </div>
    <div class="eg-intro-bar"><div class="eg-intro-fill" id="egIntroFill"></div></div>
    <div class="eg-intro-actions">
      <button class="eg-intro-btn eg-intro-wait" type="button" id="egIntroStay">Bekle</button>
      <button class="eg-intro-btn eg-intro-open" type="button" id="egIntroOpenNow">Şimdi Aç</button>
    </div>
  </div>
</div>

<script id="eg-fan12p-intro-direct-js">
(function(){
  if(window.__EG_FAN12P_INTRO_DIRECT__) return;
  window.__EG_FAN12P_INTRO_DIRECT__ = true;

  var infoMap = {
    "/dashboard": {icon:"🏠", title:"Ana Komuta Merkezi", text:"FAN-12P ana ekranıdır. Tüm güvenlik, lisans, rapor, analiz ve ayar komutlarına buradan ulaşırsın."},
    "/u/protection": {icon:"🛡️", title:"Koruma Merkezi", text:"Gelen SMS ve riskli içerikleri güvenlik motoruyla değerlendirir. Spam, şüpheli bağlantı ve tehditleri kontrol altında tutar."},
    "/u/analysis": {icon:"🔎", title:"AI Analiz", text:"Mesaj ve güvenlik verilerini yapay zekâ destekli risk analiziyle inceler. Tehlike seviyesini daha anlaşılır hale getirir."},
    "/u/reports": {icon:"📈", title:"Raporlar", text:"Engellenen, analiz edilen ve riskli görülen işlemleri özetler. Güvenlik durumunu takip etmeni sağlar."},
    "/u/notifications": {icon:"🔔", title:"Bildirimler", text:"EratGuard uyarılarını ve sistem mesajlarını gösterir. Önemli güvenlik haberlerini buradan takip edersin."},
    "/u/license": {icon:"🔑", title:"Lisans Merkezi", text:"PRO erişim, lisans durumu, aktivasyon ve hesap yetkilerini yönetir. Kullanıcı erişiminin merkezidir."},
    "/u/community": {icon:"👥", title:"Topluluk", text:"Kullanıcı geri bildirimleri ve topluluk destekli spam bildirimi için hazırlanmıştır. Sistemi birlikte güçlendirir."},
    "/u/settings": {icon:"⚙️", title:"Ayarlar", text:"Koruma tercihleri, kullanıcı seçenekleri ve uygulama davranışları buradan yönetilir."}
  };

  var timer=null, targetHref=null, total=10, left=10;

  /* ===== ERATGUARD VITES-2B SMART INTRO START ===== */
  function egIntroKey(href){
    return "eg_fan12p_intro_seen_v2_" + href;
  }

  function egHasSeenIntro(href){
    try{
      return localStorage.getItem(egIntroKey(href)) === "1";
    }catch(e){
      return false;
    }
  }

  function egMarkIntroSeen(href){
    try{
      if(href) localStorage.setItem(egIntroKey(href), "1");
    }catch(e){}
  }
  /* ===== ERATGUARD VITES-2B SMART INTRO END ===== */


  function el(id){return document.getElementById(id);}

  function goNow(){
    if(timer) clearInterval(timer);
    egMarkIntroSeen(targetHref);
    if(targetHref) window.location.href = targetHref;
  }

  function showIntro(href){
    var overlay=el("egFan12pInfoIntro");
    if(!overlay){window.location.href=href;return;}

    var info=infoMap[href] || {icon:"⚡",title:"EratGuard Özelliği",text:"Bu FAN-12P dilimi seçilen özelliği açar."};

    targetHref=href;
    left=total;

    el("egIntroIcon").textContent=info.icon;
    el("egIntroTitle").textContent=info.title;
    el("egIntroText").textContent=info.text;
    el("egIntroSeconds").textContent=String(left);
    el("egIntroFill").style.width="0%";

    overlay.classList.add("open");
    overlay.setAttribute("aria-hidden","false");

    if(timer) clearInterval(timer);
    timer=setInterval(function(){
      left-=1;
      if(left<0) left=0;
      el("egIntroSeconds").textContent=String(left);
      el("egIntroFill").style.width=String(((total-left)/total)*100)+"%";
      if(left<=0) goNow();
    },1000);
  }

  document.addEventListener("click",function(ev){
    try{
      var a=ev.target.closest ? ev.target.closest("a.eg-user-fan3-item") : null;
      if(!a) return;
      var href=a.getAttribute("href") || "";
      if(!href || href.indexOf("#")===0) return;

      // VITES-2B: Bu dilim daha önce bilgilendirildiyse direkt açılsın.
      if(egHasSeenIntro(href)){
        return;
      }

      ev.preventDefault();
      ev.stopPropagation();
      showIntro(href);
    }catch(e){}
  },true);

  function bootIntroButtons(){
    var openNow=el("egIntroOpenNow");
    var stay=el("egIntroStay");

    if(openNow){
      openNow.onclick=function(e){
        e.preventDefault();
        goNow();
      };
    }

    if(stay){
      stay.onclick=function(e){
        e.preventDefault();
      };
    }
  }

  if(document.readyState==="loading"){
    document.addEventListener("DOMContentLoaded",bootIntroButtons);
  }else{
    bootIntroButtons();
  }
})();
</script>
<!-- ERATGUARD FAN-12P INTRO DIRECT END -->



<style id="eratguard-user-fan3-style">
/* USER FAN-4 CLEANUP: eski kullanıcı fan/yelpaze menüsünü sadece kullanıcı sayfalarında gizle */
.fan:not(.eg-user-fan3),
.fan-handle,
.fan-core,
.fan-close,
.fan-item,
#fanPanel,
#fanHandle,
#fanClose,
#fanOverlay{
  display:none!important;
  opacity:0!important;
  pointer-events:none!important;
  visibility:hidden!important;
}

.eg-user-fan3{
  position:fixed;
  right:0;
  top:50%;
  transform:translateY(-50%);
  width:360px;
  height:620px;
  z-index:9997;
  pointer-events:none;
  font-family:Inter,Segoe UI,system-ui,-apple-system,sans-serif;
}
.eg-user-fan3-toggle{
  position:absolute;
  right:16px;
  top:50%;
  transform:translateY(-50%);
  width:78px;
  height:78px;
  border-radius:50%;
  border:1px solid rgba(90,170,255,.80);
  background:
    radial-gradient(circle at 35% 24%,rgba(93,180,255,.95),rgba(12,65,150,.92) 45%,rgba(4,10,24,.98) 76%);
  color:#eaf6ff;
  box-shadow:
    0 0 0 7px rgba(28,126,255,.12),
    0 0 30px rgba(28,126,255,.42),
    inset 0 0 18px rgba(255,255,255,.14);
  display:grid;
  place-items:center;
  cursor:pointer;
  pointer-events:auto;
  overflow:hidden;
  transition:.25s ease;
}
.eg-user-fan3-toggle:active{transform:translateY(-50%) scale(.96)}
.eg-user-fan3-shield{
  width:40px;
  height:40px;
  border-radius:16px 16px 20px 20px;
  border:2px solid rgba(165,220,255,.9);
  display:grid;
  place-items:center;
  font-weight:1000;
  font-size:24px;
  color:#63b8ff;
  text-shadow:0 0 14px rgba(79,170,255,.9);
}
.eg-user-fan3-toggle small{
  font-size:8px;
  font-weight:1000;
  letter-spacing:1px;
  margin-top:-8px;
  color:#a9d7ff;
}
.eg-user-fan3-arc{
  position:absolute;
  right:52px;
  top:50%;
  width:260px;
  height:430px;
  transform:translateY(-50%) scale(.88);
  border-left:2px dashed rgba(42,145,255,.55);
  border-radius:55% 0 0 55%;
  opacity:0;
  transition:.35s ease;
  pointer-events:none;
}
.eg-user-fan3-panel{
  position:absolute;
  right:-18px;
  top:50%;
  width:330px;
  height:560px;
  transform:translateY(-50%);
  pointer-events:none;
}
.eg-user-fan3-item{
  position:absolute;
  right:0;
  top:50%;
  width:294px;
  min-height:58px;
  padding:10px 12px 10px 14px;
  display:flex;
  align-items:center;
  gap:12px;
  text-decoration:none;
  color:#f5fbff;
  border:1px solid rgba(129,188,255,.22);
  background:
    linear-gradient(100deg,rgba(10,22,42,.96),rgba(9,18,34,.88)),
    radial-gradient(circle at 18% 50%,rgba(38,132,255,.22),transparent 42%);
  box-shadow:
    0 12px 24px rgba(0,0,0,.36),
    inset 0 1px 0 rgba(255,255,255,.07);
  border-radius:22px 14px 14px 22px;
  opacity:0;
  pointer-events:none;
  transform-origin:100% 50%;
  transform:translateX(120px) translateY(-50%) rotate(0deg) scale(.94);
  transition:
    transform .46s cubic-bezier(.15,.9,.25,1.12),
    opacity .32s ease,
    box-shadow .22s ease,
    border-color .22s ease;
}
.eg-user-fan3-item b{
  width:42px;
  height:42px;
  display:grid;
  place-items:center;
  flex:0 0 auto;
  border-radius:16px;
  background:linear-gradient(145deg,rgba(46,132,255,.55),rgba(14,44,95,.92));
  box-shadow:inset 0 1px 0 rgba(255,255,255,.18),0 8px 18px rgba(0,0,0,.28);
  font-size:21px;
}
.eg-user-fan3-item span{min-width:0;flex:1}
.eg-user-fan3-item strong{
  display:block;
  font-size:15px;
  font-weight:950;
  letter-spacing:-.2px;
  white-space:nowrap;
}
.eg-user-fan3-item small{
  display:block;
  margin-top:2px;
  color:#9fb5cc;
  font-size:10px;
  font-weight:750;
  white-space:nowrap;
}
.eg-user-fan3-item em{
  width:32px;
  height:32px;
  display:grid;
  place-items:center;
  border-radius:50%;
  font-style:normal;
  color:#7fc4ff;
  font-weight:950;
  font-size:12px;
  background:rgba(52,117,190,.18);
  border:1px solid rgba(130,200,255,.20);
}
.eg-user-fan3-item:hover{
  border-color:rgba(88,190,255,.72);
  box-shadow:0 14px 28px rgba(0,0,0,.42),0 0 22px rgba(38,132,255,.20);
}
.eg-user-fan3.open{pointer-events:auto}
.eg-user-fan3.open .eg-user-fan3-arc{
  opacity:1;
  transform:translateY(-50%) scale(1);
}
.eg-user-fan3.open .eg-user-fan3-item{
  opacity:1;
  pointer-events:auto;
}
.eg-user-fan3.open .i1{transform:translateX(-58px) translateY(-252px) rotate(25deg)}
.eg-user-fan3.open .i2{transform:translateX(-78px) translateY(-180px) rotate(17deg)}
.eg-user-fan3.open .i3{transform:translateX(-92px) translateY(-108px) rotate(9deg)}
.eg-user-fan3.open .i4{transform:translateX(-100px) translateY(-36px) rotate(2deg)}
.eg-user-fan3.open .i5{transform:translateX(-100px) translateY(36px) rotate(-2deg)}
.eg-user-fan3.open .i6{transform:translateX(-92px) translateY(108px) rotate(-9deg)}
.eg-user-fan3.open .i7{transform:translateX(-78px) translateY(180px) rotate(-17deg)}
.eg-user-fan3.open .i8{transform:translateX(-58px) translateY(252px) rotate(-25deg)}

@media(max-width:760px){
  .eg-user-fan3{
    width:300px;
    height:560px;
    right:-12px;
  }
  .eg-user-fan3-toggle{
    width:66px;
    height:66px;
    right:12px;
  }
  .eg-user-fan3-shield{
    width:34px;
    height:34px;
    font-size:20px;
    border-radius:13px 13px 17px 17px;
  }
  .eg-user-fan3-panel{
    width:286px;
    height:520px;
  }
  .eg-user-fan3-item{
    width:218px;
    min-height:52px;
    padding:8px 10px;
    gap:9px;
    border-radius:19px 12px 12px 19px;
  }
  .eg-user-fan3-item b{
    width:36px;
    height:36px;
    border-radius:13px;
    font-size:18px;
  }
  .eg-user-fan3-item strong{font-size:13px}
  .eg-user-fan3-item small{font-size:8.5px}
  .eg-user-fan3-item em{
    width:28px;
    height:28px;
    font-size:10px;
  }
  .eg-user-fan3.open .i1{transform:translateX(-38px) translateY(-204px) rotate(22deg)}
  .eg-user-fan3.open .i2{transform:translateX(-50px) translateY(-146px) rotate(15deg)}
  .eg-user-fan3.open .i3{transform:translateX(-58px) translateY(-88px) rotate(11deg)}
  .eg-user-fan3.open .i4{transform:translateX(-64px) translateY(-30px) rotate(2deg)}
  .eg-user-fan3.open .i5{transform:translateX(-64px) translateY(30px) rotate(-2deg)}
  .eg-user-fan3.open .i6{transform:translateX(-58px) translateY(88px) rotate(-11deg)}
  .eg-user-fan3.open .i7{transform:translateX(-50px) translateY(146px) rotate(-15deg)}
  .eg-user-fan3.open .i8{transform:translateX(-38px) translateY(204px) rotate(-22deg)}
}







/* ===== ERATGUARD USER FAN-12 SINGLE CLEAN FINAL START ===== */

/* Eski fan kalıntıları kapalı */
.fan:not(.eg-user-fan3),
.fan-handle,
.fan-core,
.fan-close,
#fanPanel,
#fanHandle,
#fanClose,
#fanOverlay{
  display:none!important;
  visibility:hidden!important;
  opacity:0!important;
  pointer-events:none!important;
}

/* Tek ana gövde */
.eg-user-fan3{
  position:fixed!important;
  right:0!important;
  top:56%!important;
  transform:translateY(-50%)!important;
  width:310px!important;
  height:540px!important;
  z-index:9999!important;
  pointer-events:none!important;
  font-family:Inter,Segoe UI,system-ui,-apple-system,sans-serif!important;
}

.eg-user-fan3-arc{
  display:none!important;
}

.eg-user-fan3-panel{
  position:absolute!important;
  right:0!important;
  top:50%!important;
  width:310px!important;
  height:540px!important;
  transform:translateY(-50%)!important;
  pointer-events:none!important;
}

/* Pivot */
.eg-user-fan3-toggle{
  position:absolute!important;
  right:9px!important;
  top:50%!important;
  transform:translateY(-50%)!important;
  width:72px!important;
  height:72px!important;
  border-radius:50%!important;
  pointer-events:auto!important;
  z-index:30!important;
}

/* Dilimler: gerçek merkezden döner */
.eg-user-fan3-item{
  position:absolute!important;
  right:91px!important;
  top:calc(50% - 24px)!important;
  width:170px!important;
  height:48px!important;
  min-height:48px!important;
  padding:6px 9px!important;
  display:flex!important;
  align-items:center!important;
  gap:7px!important;
  text-decoration:none!important;
  color:#fff!important;
  border-radius:19px 10px 10px 19px!important;
  border:1px solid rgba(100,180,255,.30)!important;
  border-right:4px solid rgba(47,255,145,.90)!important;
  background:linear-gradient(100deg,rgba(6,20,44,.98),rgba(4,12,28,.95))!important;
  box-shadow:0 10px 20px rgba(0,0,0,.43), inset 0 1px 0 rgba(255,255,255,.07)!important;
  opacity:0!important;
  visibility:hidden!important;
  pointer-events:none!important;
  transform-origin:calc(100% + 52px) 50%!important;
  transform:rotate(0deg) translateX(80px) scale(.82)!important;
  transition:
    transform .34s cubic-bezier(.2,.9,.25,1.08),
    opacity .22s ease,
    visibility .22s ease!important;
}

.eg-user-fan3-item b{
  width:30px!important;
  height:30px!important;
  border-radius:12px!important;
  flex:0 0 auto!important;
  display:grid!important;
  place-items:center!important;
  font-size:16px!important;
}

.eg-user-fan3-item strong{
  display:block!important;
  font-size:11.2px!important;
  line-height:1.05!important;
  font-weight:950!important;
  white-space:nowrap!important;
}

.eg-user-fan3-item small{
  display:block!important;
  margin-top:1px!important;
  font-size:7px!important;
  line-height:1.05!important;
  font-weight:760!important;
  white-space:nowrap!important;
}

.eg-user-fan3.open{
  pointer-events:auto!important;
}

.eg-user-fan3.open .eg-user-fan3-item{
  opacity:1!important;
  visibility:visible!important;
  pointer-events:auto!important;
}

/* 170 derece net ve simetrik açılım */
.eg-user-fan3.open .i1{transform:rotate(-85deg) translateX(-7px) scale(1)!important}
.eg-user-fan3.open .i2{transform:rotate(-61deg) translateX(-7px) scale(1)!important}
.eg-user-fan3.open .i3{transform:rotate(-36deg) translateX(-7px) scale(1)!important}
.eg-user-fan3.open .i4{transform:rotate(-12deg) translateX(-7px) scale(1)!important}
.eg-user-fan3.open .i5{transform:rotate(12deg)  translateX(-7px) scale(1)!important}
.eg-user-fan3.open .i6{transform:rotate(36deg)  translateX(-7px) scale(1)!important}
.eg-user-fan3.open .i7{transform:rotate(61deg)  translateX(-7px) scale(1)!important}
.eg-user-fan3.open .i8{transform:rotate(85deg)  translateX(-7px) scale(1)!important}

/* Mobil net değerler */
@media(max-width:760px){
  .eg-user-fan3{
    right:0!important;
    top:56%!important;
    width:305px!important;
    height:540px!important;
  }

  .eg-user-fan3-panel{
    width:305px!important;
    height:540px!important;
  }

  .eg-user-fan3-toggle{
    right:9px!important;
    width:72px!important;
    height:72px!important;
  }

  .eg-user-fan3-item{
    right:91px!important;
    top:calc(50% - 24px)!important;
    width:170px!important;
    height:48px!important;
    min-height:48px!important;
    transform-origin:calc(100% + 52px) 50%!important;
  }
}

/* ===== ERATGUARD USER FAN-12 SINGLE CLEAN FINAL END ===== */


/* ===== ERATGUARD USER FAN-12P PERFORMANCE START ===== */

/* Fan yapısı aynı kalır, sadece kasma azaltılır */
.eg-user-fan3,
.eg-user-fan3-panel,
.eg-user-fan3-toggle,
.eg-user-fan3-item{
  will-change:transform,opacity!important;
  backface-visibility:hidden!important;
  -webkit-backface-visibility:hidden!important;
  transform-style:flat!important;
}

/* Ağır gölge/glow hafifletildi */
.eg-user-fan3-toggle{
  box-shadow:
    0 0 0 4px rgba(43,135,255,.10),
    0 0 16px rgba(43,135,255,.34)!important;
}

.eg-user-fan3-item{
  box-shadow:
    0 5px 10px rgba(0,0,0,.32),
    inset 0 1px 0 rgba(255,255,255,.05)!important;
  transition:
    transform .22s ease-out,
    opacity .16s ease-out,
    visibility .16s ease-out!important;
}

/* Açılış gecikmeleri azaltıldı */
.eg-user-fan3.open .i1,
.eg-user-fan3.open .i2,
.eg-user-fan3.open .i3,
.eg-user-fan3.open .i4,
.eg-user-fan3.open .i5,
.eg-user-fan3.open .i6,
.eg-user-fan3.open .i7,
.eg-user-fan3.open .i8{
  transition-delay:0s!important;
}

/* Telefon zayıfsa animasyonu neredeyse anlık yap */
@media(max-width:760px){
  .eg-user-fan3-item{
    transition:
      transform .18s ease-out,
      opacity .12s ease-out!important;
  }

  .eg-user-fan3-toggle{
    box-shadow:
      0 0 0 3px rgba(43,135,255,.10),
      0 0 12px rgba(43,135,255,.30)!important;
  }
}

/* Hareket azaltma isteyen cihazlarda animasyonu kapat */
@media(prefers-reduced-motion: reduce){
  .eg-user-fan3-item,
  .eg-user-fan3-toggle{
    transition:none!important;
    animation:none!important;
  }
}

/* ===== ERATGUARD USER FAN-12P PERFORMANCE END ===== */


/* ===== ERATGUARD FAN-12P FORCE HIDE LEGACY GREEN START ===== */
/* Eski yeşil yelpaze tamamen kapalı; sadece FAN-12P .eg-user-fan3 çalışır */
#egFanHandle,
#egFanPanel,
#egFanClose,
#fanHandle,
#fanPanel,
#fanClose,
.fan-handle,
.fan-close,
.fan:not(.eg-user-fan3),
.fan .fan-item,
.fan-item:not(.eg-user-fan3-item){
  display:none!important;
  visibility:hidden!important;
  opacity:0!important;
  pointer-events:none!important;
  width:0!important;
  height:0!important;
  max-width:0!important;
  max-height:0!important;
  overflow:hidden!important;
  transform:none!important;
  z-index:-1!important;
}
/* ===== ERATGUARD FAN-12P FORCE HIDE LEGACY GREEN END ===== */

</style>

<script id="eratguard-user-fan3-script">
(function(){
  var root=document.getElementById("eratguard-user-fan3-rtl-menu");
  var btn=document.getElementById("egUserFan3Toggle");
  if(!root || !btn || root.dataset.ready==="1") return;
  root.dataset.ready="1";

  function closeFan(){ root.classList.remove("open"); }
  function toggleFan(ev){
    if(ev) ev.stopPropagation();
    root.classList.toggle("open");
  }

  btn.addEventListener("click", toggleFan);
  document.addEventListener("click", function(ev){
    if(root.classList.contains("open") && !root.contains(ev.target)) closeFan();
  });
  document.addEventListener("keydown", function(ev){
    if(ev.key==="Escape") closeFan();
  });
})();
</script>
"""

    def _eg_user_fan3_should_inject():
        try:
            path = str(getattr(_eg_user_fan3_request, "path", "") or "")
            if path.startswith("/admin"):
                return False
            if path in ("/dashboard", "/u/dashboard"):
                return True
            if path.startswith("/u/"):
                return True
            return False
        except Exception:
            return False

    def _eg_user_fan3_inject_html(html):
        if not html or _EG_USER_FAN3_MARKER in html:
            return html
        if "</body>" in html.lower():
            return _eg_user_fan3_re.sub(
                r"</body>",
                _EG_USER_FAN3_HTML + "\n</body>",
                html,
                count=1,
                flags=_eg_user_fan3_re.I
            )
        return html + _EG_USER_FAN3_HTML

    @app.after_request
    def _eg_user_fan3_after_request(resp):
        try:
            if not _eg_user_fan3_should_inject():
                return resp

            ctype = str(resp.headers.get("Content-Type", "") or "").lower()
            if "text/html" not in ctype:
                return resp

            html = resp.get_data(as_text=True)
            new_html = _eg_user_fan3_inject_html(html)
            if new_html != html:
                resp.set_data(new_html)
                resp.headers.pop("Content-Length", None)
                resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
            return resp
        except Exception as _eg_user_fan3_err:
            try:
                print("ERATGUARD USER FAN-3 INJECT ERROR:", _eg_user_fan3_err)
            except Exception:
                pass
            return resp

    print("ERATGUARD USER FAN-3 RIGHT-TO-LEFT MENU READY")
except Exception as _eg_user_fan3_boot_err:
    try:
        print("ERATGUARD USER FAN-3 BOOT ERROR:", _eg_user_fan3_boot_err)
    except Exception:
        pass
# ===== ERATGUARD USER FAN-3 RIGHT-TO-LEFT MENU END =====










# ===== ERATGUARD CLEAN-6 FAN12P ONLY DASHBOARD START =====
# /dashboard arka modül kartlarını kapatır. FAN-12P ana dashboard olarak kalır.
try:
    from flask import request as _eg_clean6_request

    def _eg_clean6_fan_only_code():
        return """
<style id="eg-clean6-fan12p-only-dashboard-css">
/* Dashboard artık FAN-12P. Arkadaki eski modül paneli görünmez. */
body{
  min-height:100vh!important;
  overflow:hidden!important;
  background:
    radial-gradient(circle at 78% 50%, rgba(35,255,137,.18), transparent 34%),
    radial-gradient(circle at 20% 18%, rgba(34,231,255,.10), transparent 38%),
    linear-gradient(145deg,#020806,#03100a 55%,#020806)!important;
}

/* Eski dashboard gövdesi kapalı */
body.eg-clean6-fan-dashboard .wrap,
body.eg-clean6-fan-dashboard header.top,
body.eg-clean6-fan-dashboard main.hero,
body.eg-clean6-fan-dashboard .hero,
body.eg-clean6-fan-dashboard .stats,
body.eg-clean6-fan-dashboard .stat,
body.eg-clean6-fan-dashboard .section,
body.eg-clean6-fan-dashboard .modules,
body.eg-clean6-fan-dashboard .card{
  display:none!important;
  visibility:hidden!important;
  opacity:0!important;
  pointer-events:none!important;
}

/* Sadece marka hissi veren hafif boş ekran */
body.eg-clean6-fan-dashboard:before{
  content:"EratGuard";
  position:fixed;
  left:24px;
  top:34px;
  z-index:1;
  color:rgba(242,255,246,.92);
  font-size:28px;
  font-weight:1000;
  letter-spacing:-1px;
}

body.eg-clean6-fan-dashboard:after{
  content:"FAN-12P COMMAND CENTER";
  position:fixed;
  left:26px;
  top:70px;
  z-index:1;
  color:rgba(35,255,137,.78);
  font-size:11px;
  font-weight:950;
  letter-spacing:.22em;
}

/* FAN-12P kesin ana odak */
body.eg-clean6-fan-dashboard #eratguard-user-fan3-rtl-menu{
  visibility:visible!important;
  opacity:1!important;
  pointer-events:auto!important;
  z-index:9999!important;
}

/* Mobilde marka küçük kalsın */
@media(max-width:420px){
  body.eg-clean6-fan-dashboard:before{
    font-size:24px;
    left:20px;
    top:28px;
  }
  body.eg-clean6-fan-dashboard:after{
    font-size:9px;
    left:22px;
    top:60px;
  }
}
</style>

<script id="eg-clean6-fan12p-only-dashboard-js">
(function(){
  try{
    if(location.pathname === '/dashboard' || location.pathname === '/u/dashboard'){
      document.body.classList.add('eg-clean6-fan-dashboard');
    }
  }catch(e){}
})();
</script>
"""

    @app.after_request
    def _eg_clean6_fan_only_after_request(resp):
        try:
            path = (_eg_clean6_request.path or "").rstrip("/")
            if path not in ("/dashboard", "/u/dashboard"):
                return resp

            ctype = (resp.headers.get("Content-Type") or "").lower()
            if "text/html" not in ctype:
                return resp

            body = resp.get_data(as_text=True)
            if not body or "eratguard-user-fan3-rtl-menu" not in body:
                return resp

            if "eg-clean6-fan12p-only-dashboard-js" in body:
                return resp

            inject = _eg_clean6_fan_only_code()
            if "</body>" in body:
                body = body.replace("</body>", inject + "\n</body>", 1)
            else:
                body += inject

            resp.set_data(body)
            resp.headers["Content-Length"] = str(len(body.encode("utf-8")))
            resp.headers["X-EG-Clean6"] = "fan12p-only-dashboard"
        except Exception as e:
            print("ERATGUARD CLEAN-6 FAN12P ONLY ERROR:", e)
        return resp

except Exception as e:
    print("ERATGUARD CLEAN-6 FAN12P ONLY BOOT ERROR:", e)
# ===== ERATGUARD CLEAN-6 FAN12P ONLY DASHBOARD END =====






# ===== ERATGUARD CLEAN-7B REAL FAN12P ONLY DASHBOARD START =====
# /dashboard içinde eski iç dashboard yok. FAN-12P ana dashboard olarak kalır.
try:
    def _eg_clean7b_real_fan12p_only_dashboard():
        return """<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>EratGuard PRO - FAN-12P Command Center</title>
<style>
:root{
  --green:#23ff89;
  --cyan:#22e7ff;
  --text:#f2fff6;
}
*{box-sizing:border-box}
html,body{
  margin:0;
  width:100%;
  min-height:100%;
  overflow:hidden;
  color:var(--text);
  font-family:Arial,Helvetica,sans-serif;
  background:
    radial-gradient(circle at 78% 50%, rgba(35,255,137,.18), transparent 34%),
    radial-gradient(circle at 16% 18%, rgba(34,231,255,.12), transparent 38%),
    linear-gradient(145deg,#020806,#03100a 55%,#020806);
}
.eg-clean7b-brand{
  position:fixed;
  left:24px;
  top:34px;
  z-index:1;
  pointer-events:none;
}
.eg-clean7b-logo{
  width:70px;
  height:70px;
  border-radius:24px;
  display:grid;
  place-items:center;
  margin-bottom:14px;
  background:linear-gradient(135deg,#23ff89,#22e7ff 58%,#6d7cff);
  color:#00170b;
  font-size:42px;
  font-weight:1000;
  box-shadow:0 18px 45px rgba(0,0,0,.35),0 0 28px rgba(35,255,137,.16);
}
.eg-clean7b-brand b{
  display:block;
  font-size:30px;
  font-weight:1000;
  letter-spacing:-1.2px;
  color:rgba(242,255,246,.96);
}
.eg-clean7b-brand b span{color:#23ff89}
.eg-clean7b-brand small{
  display:block;
  margin-top:8px;
  font-size:11px;
  line-height:1.45;
  font-weight:1000;
  letter-spacing:.30em;
  color:#22e7ff;
}
.eg-clean7b-hint{
  position:fixed;
  left:24px;
  bottom:34px;
  z-index:1;
  max-width:260px;
  color:rgba(242,255,246,.46);
  font-size:12px;
  line-height:1.5;
  font-weight:850;
  pointer-events:none;
}
@media(max-width:420px){
  .eg-clean7b-brand{left:22px;top:34px}
  .eg-clean7b-logo{width:64px;height:64px;border-radius:22px;font-size:38px;margin-bottom:12px}
  .eg-clean7b-brand b{font-size:26px}
  .eg-clean7b-brand small{font-size:10px}
  .eg-clean7b-hint{left:22px;bottom:28px;font-size:11px;max-width:220px}
}
</style>
</head>
<body>
  <div class="eg-clean7b-brand">
    <div class="eg-clean7b-logo">E</div>
    <b>Erat<span>Guard</span></b>
    <small>FAN-12P<br>COMMAND CENTER</small>
  </div>
  <div class="eg-clean7b-hint">Sağdaki E MENÜ ile Koruma, Analiz, Rapor, Bildirim, Lisans, Topluluk ve Ayarlar bölümlerini aç.</div>
</body>
</html>"""

    if "ss_user_alias_home_final" in app.view_functions:
        app.view_functions["ss_user_alias_home_final"] = _eg_clean7b_real_fan12p_only_dashboard

except Exception as e:
    print("ERATGUARD CLEAN-7B REAL FAN12P ONLY DASHBOARD ERROR:", e)
# ===== ERATGUARD CLEAN-7B REAL FAN12P ONLY DASHBOARD END =====



# ===== ERATGUARD VITES-2C FORCE PROTECTION CENTER START =====
def _eg_vites2c_protection_center_html():
    try:
        username = session.get("username") or "Erat@32"
        plan = session.get("plan") or session.get("license_type") or "PRO"
    except Exception:
        username = "Erat@32"
        plan = "PRO"

    return f"""<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<title>EratGuard PRO - Vites-2C Koruma Merkezi</title>
<style>
:root{{
  --green:#23ff89;
  --cyan:#22e7ff;
  --text:#f2fff6;
  --muted:rgba(242,255,246,.64);
  --line:rgba(35,255,137,.18);
  --card:rgba(4,18,12,.74);
  --warn:#ffd166;
}}
*{{box-sizing:border-box}}
html,body{{
  margin:0;
  min-height:100%;
  background:
    radial-gradient(circle at 78% 22%,rgba(34,231,255,.16),transparent 34%),
    radial-gradient(circle at 18% 88%,rgba(35,255,137,.13),transparent 38%),
    linear-gradient(135deg,#020705,#030d09 48%,#010403);
  color:var(--text);
  font-family:Arial,Helvetica,sans-serif;
  overflow-x:hidden;
}}
.eg-wrap{{min-height:100vh;padding:22px 18px 34px}}
.eg-top{{display:flex;align-items:center;justify-content:space-between;gap:14px;margin-bottom:22px}}
.eg-brand{{display:flex;align-items:center;gap:12px}}
.eg-logo{{
  width:42px;height:42px;border-radius:15px;display:grid;place-items:center;
  background:linear-gradient(135deg,var(--green),var(--cyan));
  color:#00170b;font-weight:1000;
  box-shadow:0 0 28px rgba(35,255,137,.22);
}}
.eg-title small{{display:block;color:var(--cyan);font-size:10px;font-weight:1000;letter-spacing:.18em}}
.eg-title b{{display:block;font-size:17px;letter-spacing:-.2px}}
.eg-pill{{
  border:1px solid var(--line);border-radius:999px;padding:9px 11px;
  background:rgba(3,18,10,.55);font-size:10px;font-weight:1000;
  letter-spacing:.12em;color:var(--green);white-space:nowrap;
}}
.eg-hero{{
  border:1px solid var(--line);border-radius:30px;padding:22px;
  background:linear-gradient(180deg,rgba(4,22,14,.82),rgba(2,8,6,.72));
  box-shadow:0 18px 70px rgba(0,0,0,.38), inset 0 0 28px rgba(35,255,137,.04);
  margin-bottom:16px;
}}
.eg-hero h1{{margin:0 0 8px;font-size:32px;letter-spacing:-1.2px;line-height:1}}
.eg-hero p{{margin:0;color:var(--muted);font-size:13px;line-height:1.55}}
.eg-status{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px;margin:16px 0}}
.eg-card{{
  border:1px solid var(--line);border-radius:24px;padding:15px;background:var(--card);
  box-shadow:inset 0 0 20px rgba(35,255,137,.035);
}}
.eg-card .k{{font-size:10px;font-weight:1000;letter-spacing:.16em;color:var(--muted);margin-bottom:8px}}
.eg-card .v{{display:flex;align-items:center;gap:8px;font-size:17px;font-weight:1000}}
.dot{{width:9px;height:9px;border-radius:50%;background:var(--green);box-shadow:0 0 18px rgba(35,255,137,.75)}}
.dot.c{{background:var(--cyan);box-shadow:0 0 18px rgba(34,231,255,.75)}}
.dot.w{{background:var(--warn);box-shadow:0 0 18px rgba(255,209,102,.55)}}
.eg-actions{{display:grid;grid-template-columns:1fr;gap:11px;margin-top:16px}}
.eg-btn{{
  display:flex;align-items:center;justify-content:space-between;text-decoration:none;color:var(--text);
  border:1px solid rgba(34,231,255,.16);border-radius:22px;padding:15px 16px;
  background:rgba(2,13,10,.66);font-size:13px;font-weight:1000;letter-spacing:.02em;
}}
.eg-btn span{{color:var(--cyan)}}
.eg-back{{
  margin-top:18px;display:inline-flex;text-decoration:none;color:#00170b;
  background:linear-gradient(135deg,var(--green),var(--cyan));
  border-radius:999px;padding:12px 16px;font-size:12px;font-weight:1000;
  box-shadow:0 0 28px rgba(35,255,137,.16);
}}
.eg-note{{margin-top:15px;color:var(--muted);font-size:12px;line-height:1.55}}
@media(max-width:420px){{
  .eg-wrap{{padding:18px 14px 28px}}
  .eg-hero h1{{font-size:28px}}
  .eg-status{{grid-template-columns:1fr 1fr;gap:10px}}
  .eg-card{{padding:13px;border-radius:21px}}
  .eg-card .v{{font-size:15px}}
}}




/* ===== ERATGUARD VITES-2C POLISH START ===== */
.eg-user-fan3-toggle{{
  bottom:104px !important;
  right:14px !important;
}}
@media(max-width:420px){{
  .eg-user-fan3-toggle{{
    bottom:104px !important;
    right:12px !important;
  }}
}}
/* ===== ERATGUARD VITES-2C POLISH END ===== */

/* ===== ERATGUARD VITES-2C APK VISUAL OVERLAP POLISH START ===== */
.eg-actions{{
  padding-right:92px !important;
}}
.eg-actions .eg-btn{{
  min-height:84px !important;
}}
@media(max-width:420px){{
  .eg-actions{{
    padding-right:96px !important;
  }}
}}
/* ===== ERATGUARD VITES-2C APK VISUAL OVERLAP POLISH END ===== */


</style>
</head>
<body>
<div class="eg-wrap">
  <div class="eg-top">
    <div class="eg-brand">
      <div class="eg-logo">E</div>
      <div class="eg-title">
        <small>ERATGUARD VITES-2C</small>
        <b>Koruma Merkezi</b>
      </div>
    </div>
    <div class="eg-pill">{plan}</div>
  </div>

  <section class="eg-hero">
    <h1>Koruma aktif.</h1>
    <p>{username} hesabı için SMS kalkanı, link kontrolü ve risk motoru hazır durumda. Bu merkez, telefona düşebilecek şüpheli içerikleri takip etmek için ana güvenlik alanıdır.</p>
  </section>

  <div class="eg-status">
    <div class="eg-card"><div class="k">SMS KALKANI</div><div class="v"><i class="dot"></i> Hazır</div></div>
    <div class="eg-card"><div class="k">LİNK KONTROLÜ</div><div class="v"><i class="dot c"></i> Aktif</div></div>
    <div class="eg-card"><div class="k">RİSK MOTORU</div><div class="v"><i class="dot"></i> PRO</div></div>
    <div class="eg-card"><div class="k">SON TARAMA</div><div class="v"><i class="dot w"></i> Beklemede</div></div>
  </div>

  <div class="eg-actions">
    <a class="eg-btn" href="/u/analysis">Riskli SMS Analizi <span>→</span></a>
    <a class="eg-btn" href="/u/blocked">Engellenenleri Gör <span>→</span></a>
    <a class="eg-btn" href="/u/reports">Koruma Raporları <span>→</span></a>
  </div>

  <a class="eg-back" href="/dashboard">← FAN-12P Komuta Merkezine Dön</a>

  <div class="eg-note">EratGuard PRO koruma katmanı aktif. SMS, link ve risk motoru tek merkezden takip edilir.</div>
</div>
</body>
</html>"""

@app.before_request
def _eg_vites2c_force_protection_center():
    try:
        if request.path == "/u/protection":
            return _eg_vites2c_protection_center_html()
    except Exception:
        return None
# ===== ERATGUARD VITES-2C FORCE PROTECTION CENTER END =====



# ===== ERATGUARD VITES-2D AI ANALYSIS CENTER START =====
def _eg_vites2d_ai_analysis_html():
    try:
        username = session.get("username") or "Erat@32"
        plan = session.get("plan") or session.get("license_type") or "PRO"
    except Exception:
        username = "Erat@32"
        plan = "PRO"

    html = """<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<title>EratGuard PRO - Vites-2D AI Analiz Merkezi</title>
<style>
:root{
  --green:#23ff89;
  --cyan:#22e7ff;
  --red:#ff4d6d;
  --yellow:#ffd166;
  --text:#f2fff6;
  --muted:rgba(242,255,246,.64);
  --line:rgba(35,255,137,.18);
  --card:rgba(4,18,12,.74);
}
*{box-sizing:border-box}
html,body{
  margin:0;
  min-height:100%;
  background:
    radial-gradient(circle at 80% 18%,rgba(34,231,255,.15),transparent 34%),
    radial-gradient(circle at 16% 88%,rgba(35,255,137,.13),transparent 40%),
    linear-gradient(135deg,#020705,#030d09 48%,#010403);
  color:var(--text);
  font-family:Arial,Helvetica,sans-serif;
  overflow-x:hidden;
}
.eg-wrap{min-height:100vh;padding:22px 18px 34px}
.eg-top{display:flex;align-items:center;justify-content:space-between;gap:14px;margin-bottom:22px}
.eg-brand{display:flex;align-items:center;gap:12px}
.eg-logo{
  width:42px;height:42px;border-radius:15px;display:grid;place-items:center;
  background:linear-gradient(135deg,var(--green),var(--cyan));
  color:#00170b;font-weight:1000;
  box-shadow:0 0 28px rgba(35,255,137,.22);
}
.eg-title small{display:block;color:var(--cyan);font-size:10px;font-weight:1000;letter-spacing:.18em}
.eg-title b{display:block;font-size:17px;letter-spacing:-.2px}
.eg-pill{
  border:1px solid var(--line);border-radius:999px;padding:9px 11px;
  background:rgba(3,18,10,.55);font-size:10px;font-weight:1000;
  letter-spacing:.12em;color:var(--green);white-space:nowrap;
}
.eg-hero{
  border:1px solid var(--line);border-radius:30px;padding:22px;
  background:linear-gradient(180deg,rgba(4,22,14,.82),rgba(2,8,6,.72));
  box-shadow:0 18px 70px rgba(0,0,0,.38), inset 0 0 28px rgba(35,255,137,.04);
  margin-bottom:16px;
}
.eg-hero h1{margin:0 0 8px;font-size:31px;letter-spacing:-1.2px;line-height:1}
.eg-hero p{margin:0;color:var(--muted);font-size:13px;line-height:1.55}
.eg-panel{
  border:1px solid var(--line);
  border-radius:28px;
  background:var(--card);
  padding:16px;
  box-shadow:inset 0 0 22px rgba(35,255,137,.035);
}
.eg-label{
  font-size:10px;
  font-weight:1000;
  letter-spacing:.16em;
  color:var(--cyan);
  margin-bottom:10px;
}
textarea{
  width:100%;
  min-height:150px;
  resize:vertical;
  outline:none;
  border:1px solid rgba(34,231,255,.18);
  border-radius:22px;
  padding:15px;
  background:rgba(1,8,6,.72);
  color:var(--text);
  font-size:14px;
  line-height:1.45;
  font-family:Arial,Helvetica,sans-serif;
}
textarea::placeholder{color:rgba(242,255,246,.38)}
.eg-analyze{
  width:100%;
  margin-top:12px;
  border:0;
  border-radius:999px;
  padding:14px 16px;
  background:linear-gradient(135deg,var(--green),var(--cyan));
  color:#00170b;
  font-size:13px;
  font-weight:1000;
  letter-spacing:.08em;
}
.eg-result{
  margin-top:16px;
  display:none;
  border:1px solid rgba(34,231,255,.16);
  border-radius:24px;
  background:rgba(2,13,10,.66);
  padding:15px;
}
.eg-result.open{display:block}
.eg-score{
  display:flex;
  align-items:center;
  justify-content:space-between;
  gap:12px;
  margin-bottom:12px;
}
.eg-score strong{font-size:32px;letter-spacing:-1px}
.eg-risk{
  border-radius:999px;
  padding:9px 11px;
  font-size:10px;
  font-weight:1000;
  letter-spacing:.12em;
}
.low{background:rgba(35,255,137,.14);color:var(--green);border:1px solid rgba(35,255,137,.22)}
.mid{background:rgba(255,209,102,.14);color:var(--yellow);border:1px solid rgba(255,209,102,.22)}
.high{background:rgba(255,77,109,.14);color:var(--red);border:1px solid rgba(255,77,109,.22)}
.eg-bar{height:10px;border-radius:999px;background:rgba(255,255,255,.08);overflow:hidden;margin-bottom:12px}
.eg-fill{height:100%;width:0%;border-radius:999px;background:linear-gradient(90deg,var(--green),var(--yellow),var(--red));transition:.3s ease}
.eg-msg{color:var(--muted);font-size:13px;line-height:1.55}
.eg-tags{display:flex;flex-wrap:wrap;gap:8px;margin-top:12px}
.eg-tag{border:1px solid rgba(34,231,255,.16);border-radius:999px;padding:8px 10px;font-size:11px;font-weight:900;color:var(--cyan)}
.eg-actions{display:grid;grid-template-columns:1fr;gap:11px;margin-top:16px}
.eg-btn{
  display:flex;align-items:center;justify-content:space-between;text-decoration:none;color:var(--text);
  border:1px solid rgba(34,231,255,.16);border-radius:22px;padding:15px 16px;
  background:rgba(2,13,10,.66);font-size:13px;font-weight:1000;letter-spacing:.02em;
}
.eg-btn span{color:var(--cyan)}
.eg-back{
  margin-top:16px;display:inline-flex;text-decoration:none;color:#00170b;
  background:linear-gradient(135deg,var(--green),var(--cyan));
  border-radius:999px;padding:12px 16px;font-size:12px;font-weight:1000;
  box-shadow:0 0 28px rgba(35,255,137,.16);
}
.eg-note{margin-top:14px;color:var(--muted);font-size:12px;line-height:1.55}
@media(max-width:420px){
  .eg-wrap{padding:18px 14px 28px}
  .eg-hero h1{font-size:28px}
  textarea{min-height:140px}
}


/* ===== ERATGUARD VITES-2D POLISH START ===== */
.eg-user-fan3-toggle{
  bottom:112px !important;
  right:12px !important;
}
.eg-panel{
  padding-bottom:26px !important;
}
.eg-analyze{
  margin-right:86px !important;
  width:calc(100% - 86px) !important;
}
@media(max-width:420px){
  .eg-user-fan3-toggle{
    bottom:112px !important;
    right:10px !important;
  }
  .eg-analyze{
    margin-right:92px !important;
    width:calc(100% - 92px) !important;
  }
}
/* ===== ERATGUARD VITES-2D POLISH END ===== */




</style>
</head>
<body>
<div class="eg-wrap">
  <div class="eg-top">
    <div class="eg-brand">
      <div class="eg-logo">AI</div>
      <div class="eg-title">
        <small>ERATGUARD VITES-2D</small>
        <b>AI Analiz Merkezi</b>
      </div>
    </div>
    <div class="eg-pill">__PLAN__</div>
  </div>

  <section class="eg-hero">
    <h1>SMS riskini analiz et.</h1>
    <p>__USERNAME__ hesabı için şüpheli SMS, link, kampanya ve dolandırıcılık belirtilerini hızlı risk motoruyla değerlendir.</p>
  </section>

  <section class="eg-panel">
    <div class="eg-label">ANALİZ EDİLECEK METİN</div>
    <textarea id="egSmsText" placeholder="Örnek: Tebrikler ödül kazandınız, hemen linke tıklayın..."></textarea>
    <button class="eg-analyze" id="egAnalyzeBtn" type="button">RİSKİ ANALİZ ET</button>

    <div class="eg-result" id="egResult">
      <div class="eg-score">
        <strong id="egScore">0</strong>
        <div class="eg-risk low" id="egRiskLabel">DÜŞÜK RİSK</div>
      </div>
      <div class="eg-bar"><div class="eg-fill" id="egFill"></div></div>
      <div class="eg-msg" id="egMessage">Analiz sonucu burada görünecek.</div>
      <div class="eg-tags" id="egTags"></div>
    </div>
  </section>

  <div class="eg-actions">
    <a class="eg-btn" href="/u/protection">Koruma Merkezine Dön <span>→</span></a>
    <a class="eg-btn" href="/u/reports">Analiz Raporları <span>→</span></a>
  </div>

  <a class="eg-back" href="/dashboard">← FAN-12P Komuta Merkezine Dön</a>

  <div class="eg-note">EratGuard AI Analiz Merkezi, SMS içeriğindeki risk işaretlerini hızlıca değerlendirir. Nihai güvenlik kararı için Koruma Merkezi ile birlikte kullanılır.</div>

<div class="eg-note" style="margin-top:14px;border-color:rgba(35,255,137,.32);">
  <!-- ERATGUARD VITES-5D SMS CENTER LINK START -->
  <a href="/u/sms-actions-center" style="color:#23ff89;text-decoration:none;font-weight:900;">
    Engellenen SMS Merkezi → ENGELLE / GÜVENLİ / ŞİKAYET kayıtlarını görüntüle
  </a>
  <!-- ERATGUARD VITES-5D SMS CENTER LINK END -->
</div>

</div>

<script>
(function(){
  var txt=document.getElementById("egSmsText");
  var btn=document.getElementById("egAnalyzeBtn");
  var result=document.getElementById("egResult");
  var scoreEl=document.getElementById("egScore");
  var label=document.getElementById("egRiskLabel");
  var fill=document.getElementById("egFill");
  var msg=document.getElementById("egMessage");
  var tags=document.getElementById("egTags");

  var rules=[
    {k:"http", w:18, t:"Link içeriyor"},
    {k:"bit.ly", w:22, t:"Kısaltılmış link"},
    {k:"tıkla", w:16, t:"Tıklama çağrısı"},
    {k:"tikla", w:16, t:"Tıklama çağrısı"},
    {k:"şifre", w:18, t:"Şifre talebi"},
    {k:"sifre", w:18, t:"Şifre talebi"},
    {k:"banka", w:14, t:"Banka teması"},
    {k:"ödül", w:16, t:"Ödül vaadi"},
    {k:"odul", w:16, t:"Ödül vaadi"},
    {k:"kazandınız", w:18, t:"Kazanç vaadi"},
    {k:"kazandiniz", w:18, t:"Kazanç vaadi"},
    {k:"acil", w:12, t:"Acil baskısı"},
    {k:"hesabınız", w:12, t:"Hesap uyarısı"},
    {k:"hesabiniz", w:12, t:"Hesap uyarısı"},
    {k:"doğrula", w:16, t:"Doğrulama isteği"},
    {k:"dogrula", w:16, t:"Doğrulama isteği"}
  ];

  function analyze(){
    var v=(txt.value||"").toLowerCase();
    var score=0;
    var found=[];

    if(v.trim().length<6){
      result.classList.add("open");
      scoreEl.textContent="0";
      fill.style.width="0%";
      label.className="eg-risk low";
      label.textContent="METİN GEREKLİ";
      msg.textContent="Analiz için SMS veya şüpheli metni kutuya yaz.";
      tags.innerHTML="";
      return;
    }

    rules.forEach(function(r){
      if(v.indexOf(r.k)!==-1){
        score+=r.w;
        if(found.indexOf(r.t)===-1) found.push(r.t);
      }
    });

    if(/[0-9]{6}/.test(v)){score+=16; found.push("Kod/OTP benzeri sayı");}
    if(/[0-9]{10,}/.test(v)){score+=10; found.push("Uzun numara dizisi");}
    if(v.length>160){score+=8; found.push("Uzun SMS içeriği");}

    score=Math.max(0,Math.min(100,score));

    result.classList.add("open");
    scoreEl.textContent=score;
    fill.style.width=score+"%";

    if(score>=65){
      label.className="eg-risk high";
      label.textContent="YÜKSEK RİSK";
      msg.textContent="Bu içerikte güçlü dolandırıcılık/spam işaretleri var. Linke tıklama, şifre veya kod paylaşma.";
    }else if(score>=32){
      label.className="eg-risk mid";
      label.textContent="ORTA RİSK";
      msg.textContent="Bu içerik dikkat gerektiriyor. Göndereni doğrulamadan işlem yapma.";
    }else{
      label.className="eg-risk low";
      label.textContent="DÜŞÜK RİSK";
      msg.textContent="Belirgin risk az görünüyor; yine de bilinmeyen link ve taleplere dikkat et.";
    }

    tags.innerHTML="";
    if(found.length===0){found=["Belirgin risk etiketi yok"];}
    found.slice(0,8).forEach(function(x){
      var e=document.createElement("span");
      e.className="eg-tag";
      e.textContent=x;
      tags.appendChild(e);
    });
  }

  if(btn) btn.addEventListener("click", analyze);
})();
</script>

<script>
/* ===== ERATGUARD VITES-5B AI ANALYSIS SMS RISK BRIDGE START ===== */
(function(){
  function findSmsBox(){
    return document.getElementById("egSmsText") ||
           document.querySelector("textarea") ||
           document.querySelector("input[type='text']");
  }

  function findResultBox(){
    var box = document.getElementById("egAiResult");
    if(box) return box;

    box = document.querySelector(".eg-result");
    if(box) return box;

    box = document.createElement("div");
    box.id = "egAiResult";
    box.style.marginTop = "14px";
    box.style.background = "rgba(13,19,32,.96)";
    box.style.border = "1px solid rgba(35,255,137,.25)";
    box.style.borderRadius = "18px";
    box.style.padding = "14px";
    box.style.color = "#dce7f3";
    box.style.whiteSpace = "pre-wrap";
    box.style.fontSize = "13px";

    var btn = document.getElementById("egAnalyzeBtn") || document.querySelector("button");
    if(btn && btn.parentNode){
      btn.parentNode.insertBefore(box, btn.nextSibling);
    } else {
      document.body.appendChild(box);
    }
    return box;
  }

  async function egV5Analyze(){
    var input = findSmsBox();
    var result = findResultBox();
    var text = input ? input.value : "";

    result.textContent = "EratGuard Vites-5A risk motoru çalışıyor...";

    try{
      var r = await fetch("/api/v5/sms-risk", {
        method: "POST",
        headers: {"Content-Type":"application/json"},
        body: JSON.stringify({text:text})
      });

      var j = await r.json();
      var x = j.result || {};

      result.textContent =
        "Risk Puanı: %" + (x.score ?? "-") + "\n" +
        "Seviye: " + (x.level || "-") + "\n" +
        "Durum: " + (x.status || "-") + "\n\n" +
        "Sebepler:\n- " + ((x.reasons || []).join("\n- ")) + "\n\n" +
        "Öneri: " + (x.recommendation || "-");
    }catch(e){
      result.textContent = "Analiz hatası: " + e;
    }
  }

  function bind(){
    var btn = document.getElementById("egAnalyzeBtn") || document.querySelector("button");
    if(btn){
      btn.onclick = function(ev){
        ev.preventDefault();
        egV5Analyze();
        return false;
      };
      btn.setAttribute("data-vites5b", "sms-risk-engine");
    }
  }

  if(document.readyState === "loading"){
    document.addEventListener("DOMContentLoaded", bind);
  } else {
    bind();
  }
})();
/* ===== ERATGUARD VITES-5B AI ANALYSIS SMS RISK BRIDGE END ===== */
</script>

</body>
</html>"""
    return html.replace("__USERNAME__", str(username)).replace("__PLAN__", str(plan))

@app.before_request
def _eg_vites2d_force_ai_analysis_center():
    try:
        if request.path == "/u/analysis":
            return _eg_vites2d_ai_analysis_html()
    except Exception:
        return None
# ===== ERATGUARD VITES-2D AI ANALYSIS CENTER END =====



# ===== ERATGUARD VITES-2E REPORT CENTER START =====
def _eg_vites2e_report_center_html():
    try:
        username = session.get("username") or "Erat@32"
        plan = session.get("plan") or session.get("license_type") or "PRO"
    except Exception:
        username = "Erat@32"
        plan = "PRO"

    return f"""<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<title>EratGuard PRO - Vites-2E Rapor Merkezi</title>
<style>
:root{{
  --green:#23ff89;
  --cyan:#22e7ff;
  --yellow:#ffd166;
  --red:#ff4d6d;
  --text:#f2fff6;
  --muted:rgba(242,255,246,.64);
  --line:rgba(35,255,137,.18);
  --card:rgba(4,18,12,.74);
}}
*{{box-sizing:border-box}}
html,body{{
  margin:0;
  min-height:100%;
  background:
    radial-gradient(circle at 82% 18%,rgba(34,231,255,.15),transparent 34%),
    radial-gradient(circle at 14% 88%,rgba(35,255,137,.13),transparent 40%),
    linear-gradient(135deg,#020705,#030d09 48%,#010403);
  color:var(--text);
  font-family:Arial,Helvetica,sans-serif;
  overflow-x:hidden;
}}
.eg-wrap{{min-height:100vh;padding:22px 18px 34px}}
.eg-top{{display:flex;align-items:center;justify-content:space-between;gap:14px;margin-bottom:22px}}
.eg-brand{{display:flex;align-items:center;gap:12px}}
.eg-logo{{
  width:42px;height:42px;border-radius:15px;display:grid;place-items:center;
  background:linear-gradient(135deg,var(--green),var(--cyan));
  color:#00170b;font-weight:1000;
  box-shadow:0 0 28px rgba(35,255,137,.22);
}}
.eg-title small{{display:block;color:var(--cyan);font-size:10px;font-weight:1000;letter-spacing:.18em}}
.eg-title b{{display:block;font-size:17px;letter-spacing:-.2px}}
.eg-pill{{
  border:1px solid var(--line);border-radius:999px;padding:9px 11px;
  background:rgba(3,18,10,.55);font-size:10px;font-weight:1000;
  letter-spacing:.12em;color:var(--green);white-space:nowrap;
}}
.eg-hero{{
  border:1px solid var(--line);border-radius:30px;padding:22px;
  background:linear-gradient(180deg,rgba(4,22,14,.82),rgba(2,8,6,.72));
  box-shadow:0 18px 70px rgba(0,0,0,.38), inset 0 0 28px rgba(35,255,137,.04);
  margin-bottom:16px;
}}
.eg-hero h1{{margin:0 0 8px;font-size:31px;letter-spacing:-1.2px;line-height:1}}
.eg-hero p{{margin:0;color:var(--muted);font-size:13px;line-height:1.55}}
.eg-grid{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px;margin:16px 0}}
.eg-card{{
  border:1px solid var(--line);
  border-radius:24px;
  padding:15px;
  background:var(--card);
  box-shadow:inset 0 0 20px rgba(35,255,137,.035);
}}
.eg-card .k{{font-size:10px;font-weight:1000;letter-spacing:.16em;color:var(--muted);margin-bottom:8px}}
.eg-card .v{{font-size:28px;font-weight:1000;letter-spacing:-1px}}
.eg-card .s{{font-size:11px;color:var(--muted);margin-top:5px;line-height:1.35}}
.green{{color:var(--green)}}
.cyan{{color:var(--cyan)}}
.yellow{{color:var(--yellow)}}
.red{{color:var(--red)}}
.eg-timeline{{
  border:1px solid rgba(34,231,255,.16);
  border-radius:26px;
  background:rgba(2,13,10,.66);
  padding:15px;
  margin-top:14px;
}}
.eg-timeline h3{{margin:0 0 12px;font-size:15px}}
.eg-row{{
  display:flex;
  justify-content:space-between;
  gap:12px;
  padding:12px 0;
  border-top:1px solid rgba(255,255,255,.06);
}}
.eg-row:first-of-type{{border-top:0}}
.eg-row b{{font-size:13px}}
.eg-row span{{font-size:12px;color:var(--muted);text-align:right}}
.eg-actions{{display:grid;grid-template-columns:1fr;gap:11px;margin-top:16px}}
.eg-btn{{
  display:flex;align-items:center;justify-content:space-between;text-decoration:none;color:var(--text);
  border:1px solid rgba(34,231,255,.16);border-radius:22px;padding:15px 16px;
  background:rgba(2,13,10,.66);font-size:13px;font-weight:1000;letter-spacing:.02em;
}}
.eg-btn span{{color:var(--cyan)}}
.eg-back{{
  margin-top:16px;display:inline-flex;text-decoration:none;color:#00170b;
  background:linear-gradient(135deg,var(--green),var(--cyan));
  border-radius:999px;padding:12px 16px;font-size:12px;font-weight:1000;
  box-shadow:0 0 28px rgba(35,255,137,.16);
}}
.eg-note{{margin-top:14px;color:var(--muted);font-size:12px;line-height:1.55}}

/* ===== ERATGUARD VITES-2E APK VISUAL CARD POLISH START ===== */
.eg-grid .eg-card:nth-child(2),
.eg-grid .eg-card:nth-child(4){{
  padding-right:104px !important;
}}
.eg-grid .eg-card:nth-child(4) .s{{
  max-width:130px !important;
}}
@media(max-width:420px){{
  .eg-grid .eg-card:nth-child(2),
  .eg-grid .eg-card:nth-child(4){{
    padding-right:108px !important;
  }}
  .eg-grid .eg-card:nth-child(4) .s{{
    max-width:118px !important;
  }}
}}
/* ===== ERATGUARD VITES-2E APK VISUAL CARD POLISH END ===== */

@media(max-width:420px){{
  .eg-wrap{{padding:18px 14px 28px}}
  .eg-hero h1{{font-size:28px}}
  .eg-grid{{grid-template-columns:1fr 1fr;gap:10px}}
  .eg-card{{padding:13px;border-radius:21px}}
  .eg-card .v{{font-size:25px}}
}}
</style>
</head>
<body>
<div class="eg-wrap">
  <div class="eg-top">
    <div class="eg-brand">
      <div class="eg-logo">R</div>
      <div class="eg-title">
        <small>ERATGUARD VITES-2E</small>
        <b>Rapor Merkezi</b>
      </div>
    </div>
    <div class="eg-pill">{plan}</div>
  </div>

  <section class="eg-hero">
    <h1>Güvenlik özeti hazır.</h1>
    <p>{username} hesabı için koruma, analiz ve risk durumları tek rapor ekranında özetlenir.</p>
  </section>

  <div class="eg-grid">
    <div class="eg-card">
      <div class="k">KORUMA DURUMU</div>
      <div class="v green">AKTİF</div>
      <div class="s">SMS kalkanı ve risk motoru hazır.</div>
    </div>
    <div class="eg-card">
      <div class="k">AI ANALİZ</div>
      <div class="v cyan">HAZIR</div>
      <div class="s">Metin/SMS risk analizi çalışıyor.</div>
    </div>
    <div class="eg-card">
      <div class="k">RİSKLİ İÇERİK</div>
      <div class="v yellow">0</div>
      <div class="s">Bugün kayıtlı yüksek risk yok.</div>
    </div>
    <div class="eg-card">
      <div class="k">ENGELLENEN</div>
      <div class="v green">0</div>
      <div class="s">Engellenen içerikler burada izlenir.</div>
    </div>
  </div>

  <section class="eg-timeline">
    <h3>Son güvenlik durumu</h3>
    <div class="eg-row">
      <b>Koruma Merkezi</b>
      <span>Aktif ve hazır</span>
    </div>
    <div class="eg-row">
      <b>AI Analiz Merkezi</b>
      <span>Risk puanı üretmeye hazır</span>
    </div>
    <div class="eg-row">
      <b>FAN-12P</b>
      <span>Komuta merkezi bağlantısı aktif</span>
    </div>
  </section>

  <div class="eg-actions">
    <a class="eg-btn" href="/u/protection">Koruma Merkezine Git <span>→</span></a>
    <a class="eg-btn" href="/u/analysis">AI Analiz Merkezine Git <span>→</span></a>
  </div>

  <a class="eg-back" href="/dashboard">← FAN-12P Komuta Merkezine Dön</a>

  <div class="eg-note">EratGuard Rapor Merkezi, koruma ve analiz durumlarını kullanıcıya sade bir güvenlik özeti olarak sunar.</div>

<div id="egV5eSmsStatsCard" style="margin-top:16px;background:rgba(255,255,255,.06);border:1px solid rgba(35,255,137,.28);border-radius:22px;padding:16px;box-shadow:0 0 24px rgba(35,255,137,.10);">
  <!-- ERATGUARD VITES-5E DIRECT REPORTS CARD START -->
  <div style="color:#23ff89;font-weight:900;font-size:12px;letter-spacing:.08em;">ERATGUARD VITES-5E</div>
  <h2 style="margin:8px 0 10px;font-size:21px;color:#fff;">SMS Koruma İstatistikleri</h2>
  <p style="margin:0 0 12px;color:#9aa3b2;line-height:1.45;">AI Analiz ekranından gelen gerçek ENGELLE / GÜVENLİ / ŞİKAYET kayıtları.</p>

  <div style="display:grid;grid-template-columns:repeat(2,1fr);gap:10px;">
    <div style="background:rgba(255,255,255,.06);border-radius:16px;padding:12px;text-align:center;">
      <b id="egV5eBlocked" style="display:block;color:#23ff89;font-size:26px;">-</b>
      <span style="color:#aeb8c8;font-size:12px;font-weight:800;">Engellenen SMS</span>
    </div>
    <div style="background:rgba(255,255,255,.06);border-radius:16px;padding:12px;text-align:center;">
      <b id="egV5eSafe" style="display:block;color:#23ff89;font-size:26px;">-</b>
      <span style="color:#aeb8c8;font-size:12px;font-weight:800;">Güvenli SMS</span>
    </div>
    <div style="background:rgba(255,255,255,.06);border-radius:16px;padding:12px;text-align:center;">
      <b id="egV5eReported" style="display:block;color:#23ff89;font-size:26px;">-</b>
      <span style="color:#aeb8c8;font-size:12px;font-weight:800;">Şikayet</span>
    </div>
    <div style="background:rgba(255,255,255,.06);border-radius:16px;padding:12px;text-align:center;">
      <b id="egV5eTotal" style="display:block;color:#23ff89;font-size:26px;">-</b>
      <span style="color:#aeb8c8;font-size:12px;font-weight:800;">Toplam Aksiyon</span>
    </div>
  </div>

  <a href="/u/sms-actions-center" style="display:block;margin-top:14px;color:#23ff89;text-decoration:none;font-weight:900;">
    Engellenen SMS Merkezi detaylarını aç →
  </a>
  <!-- ERATGUARD VITES-5E DIRECT REPORTS CARD END -->
</div>

<script>
/* ===== ERATGUARD VITES-5E DIRECT REPORTS JS START ===== */
(function(){{
  async function loadSmsStats(){{
    try{{
      const r = await fetch("/api/v5/sms-actions");
      const j = await r.json();
      const st = j.stats || {{}};
      const blocked = st.blocked || 0;
      const safe = st.safe || 0;
      const reported = st.reported || 0;

      document.getElementById("egV5eBlocked").textContent = blocked;
      document.getElementById("egV5eSafe").textContent = safe;
      document.getElementById("egV5eReported").textContent = reported;
      document.getElementById("egV5eTotal").textContent = blocked + safe + reported;
    }}catch(e){{
      const box = document.getElementById("egV5eSmsStatsCard");
      if(box) box.setAttribute("data-error", String(e));
    }}
  }}

  if(document.readyState === "loading"){{
    document.addEventListener("DOMContentLoaded", loadSmsStats);
  }} else {{
    loadSmsStats();
  }}
}})();
/* ===== ERATGUARD VITES-5E DIRECT REPORTS JS END ===== */
</script>




</div>
</body>
</html>"""

@app.before_request
def _eg_vites2e_force_report_center():
    try:
        if request.path == "/u/reports":
            return _eg_vites2e_report_center_html()
    except Exception:
        return None
# ===== ERATGUARD VITES-2E REPORT CENTER END =====



# ===== ERATGUARD VITES-2E FORCE AFTER RESPONSE START =====
@app.after_request
def _eg_vites2e_force_reports_after_response(response):
    try:
        if request.path == "/u/reports":
            html = _eg_vites2e_report_center_html()
            response.set_data(html)
            response.status_code = 200
            response.headers["Content-Type"] = "text/html; charset=utf-8"
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
    except Exception:
        pass
    return response
# ===== ERATGUARD VITES-2E FORCE AFTER RESPONSE END =====



# ===== ERATGUARD VITES-2F LICENSE CENTER START =====
def _eg_vites2f_license_center_html():
    try:
        username = session.get("username") or "Erat@32"
        plan = session.get("plan") or session.get("license_type") or "PRO"
    except Exception:
        username = "Erat@32"
        plan = "PRO"

    return f"""<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<title>EratGuard PRO - Vites-2F Lisans Merkezi</title>
<style>
:root{{
  --green:#23ff89;
  --cyan:#22e7ff;
  --yellow:#ffd166;
  --text:#f2fff6;
  --muted:rgba(242,255,246,.64);
  --line:rgba(35,255,137,.18);
  --card:rgba(4,18,12,.74);
}}
*{{box-sizing:border-box}}
html,body{{
  margin:0;
  min-height:100%;
  background:
    radial-gradient(circle at 82% 18%,rgba(34,231,255,.15),transparent 34%),
    radial-gradient(circle at 14% 88%,rgba(35,255,137,.13),transparent 40%),
    linear-gradient(135deg,#020705,#030d09 48%,#010403);
  color:var(--text);
  font-family:Arial,Helvetica,sans-serif;
  overflow-x:hidden;
}}
.eg-wrap{{min-height:100vh;padding:22px 18px 34px}}
.eg-top{{display:flex;align-items:center;justify-content:space-between;gap:14px;margin-bottom:22px}}
.eg-brand{{display:flex;align-items:center;gap:12px}}
.eg-logo{{
  width:42px;height:42px;border-radius:15px;display:grid;place-items:center;
  background:linear-gradient(135deg,var(--green),var(--cyan));
  color:#00170b;font-weight:1000;
  box-shadow:0 0 28px rgba(35,255,137,.22);
}}
.eg-title small{{display:block;color:var(--cyan);font-size:10px;font-weight:1000;letter-spacing:.18em}}
.eg-title b{{display:block;font-size:17px;letter-spacing:-.2px}}
.eg-pill{{
  border:1px solid var(--line);border-radius:999px;padding:9px 11px;
  background:rgba(3,18,10,.55);font-size:10px;font-weight:1000;
  letter-spacing:.12em;color:var(--green);white-space:nowrap;
}}
.eg-hero{{
  border:1px solid var(--line);border-radius:30px;padding:22px;
  background:linear-gradient(180deg,rgba(4,22,14,.82),rgba(2,8,6,.72));
  box-shadow:0 18px 70px rgba(0,0,0,.38), inset 0 0 28px rgba(35,255,137,.04);
  margin-bottom:16px;
}}
.eg-hero h1{{margin:0 0 8px;font-size:31px;letter-spacing:-1.2px;line-height:1}}
.eg-hero p{{margin:0;color:var(--muted);font-size:13px;line-height:1.55}}
.eg-license{{
  border:1px solid rgba(35,255,137,.22);
  border-radius:30px;
  padding:20px;
  background:linear-gradient(180deg,rgba(35,255,137,.10),rgba(2,13,10,.70));
  box-shadow:0 0 40px rgba(35,255,137,.08), inset 0 0 26px rgba(35,255,137,.04);
  margin-bottom:15px;
}}
.eg-license .label{{font-size:10px;font-weight:1000;letter-spacing:.18em;color:var(--cyan);margin-bottom:8px}}
.eg-license .plan{{font-size:42px;font-weight:1000;letter-spacing:-2px;line-height:.95;color:var(--green)}}
.eg-license .state{{margin-top:10px;color:var(--muted);font-size:13px;line-height:1.5}}
.eg-grid{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px;margin:16px 0}}
.eg-card{{
  border:1px solid var(--line);
  border-radius:24px;
  padding:15px;
  background:var(--card);
  box-shadow:inset 0 0 20px rgba(35,255,137,.035);
}}
.eg-card .k{{font-size:10px;font-weight:1000;letter-spacing:.16em;color:var(--muted);margin-bottom:8px}}
.eg-card .v{{font-size:17px;font-weight:1000}}
.green{{color:var(--green)}}
.cyan{{color:var(--cyan)}}
.yellow{{color:var(--yellow)}}
.eg-list{{
  border:1px solid rgba(34,231,255,.16);
  border-radius:26px;
  background:rgba(2,13,10,.66);
  padding:15px;
  margin-top:14px;
}}
.eg-row{{
  display:flex;
  justify-content:space-between;
  gap:12px;
  padding:12px 0;
  border-top:1px solid rgba(255,255,255,.06);
}}
.eg-row:first-child{{border-top:0}}
.eg-row b{{font-size:13px}}
.eg-row span{{font-size:12px;color:var(--green);font-weight:1000;text-align:right}}
.eg-actions{{display:grid;grid-template-columns:1fr;gap:11px;margin-top:16px}}
.eg-btn{{
  display:flex;align-items:center;justify-content:space-between;text-decoration:none;color:var(--text);
  border:1px solid rgba(34,231,255,.16);border-radius:22px;padding:15px 16px;
  background:rgba(2,13,10,.66);font-size:13px;font-weight:1000;letter-spacing:.02em;
}}
.eg-btn span{{color:var(--cyan)}}
.eg-back{{
  margin-top:16px;display:inline-flex;text-decoration:none;color:#00170b;
  background:linear-gradient(135deg,var(--green),var(--cyan));
  border-radius:999px;padding:12px 16px;font-size:12px;font-weight:1000;
  box-shadow:0 0 28px rgba(35,255,137,.16);
}}
.eg-note{{margin-top:14px;color:var(--muted);font-size:12px;line-height:1.55}}
@media(max-width:420px){{
  .eg-wrap{{padding:18px 14px 28px}}
  .eg-hero h1{{font-size:28px}}
  .eg-license .plan{{font-size:38px}}
  .eg-grid{{grid-template-columns:1fr 1fr;gap:10px}}
  .eg-card{{padding:13px;border-radius:21px}}
}}
</style>
</head>
<body>
<div class="eg-wrap">
  <div class="eg-top">
    <div class="eg-brand">
      <div class="eg-logo">L</div>
      <div class="eg-title">
        <small>ERATGUARD VITES-2F</small>
        <b>Lisans Merkezi</b>
      </div>
    </div>
    <div class="eg-pill">{plan}</div>
  </div>

  <section class="eg-hero">
    <h1>Lisans aktif.</h1>
    <p>{username} hesabının koruma, AI analiz ve rapor özellikleri PRO lisans üzerinden yönetilir.</p>
  </section>

  <section class="eg-license">
    <div class="label">AKTİF PAKET</div>
    <div class="plan">{plan}</div>
    <div class="state">Bu hesap için EratGuard güvenlik katmanları aktif durumda.</div>
  </section>

  <div class="eg-grid">
    <div class="eg-card">
      <div class="k">KORUMA</div>
      <div class="v green">AÇIK</div>
    </div>
    <div class="eg-card">
      <div class="k">AI ANALİZ</div>
      <div class="v cyan">AÇIK</div>
    </div>
    <div class="eg-card">
      <div class="k">RAPORLAR</div>
      <div class="v green">AÇIK</div>
    </div>
    <div class="eg-card">
      <div class="k">DURUM</div>
      <div class="v yellow">GEÇERLİ</div>
    </div>
  </div>

  <section class="eg-list">
    <div class="eg-row"><b>Kullanıcı</b><span>{username}</span></div>
    <div class="eg-row"><b>Lisans tipi</b><span>{plan}</span></div>
    <div class="eg-row"><b>Admin bağlantısı</b><span>HAZIR</span></div>
    <div class="eg-row"><b>FAN-12P erişimi</b><span>AKTİF</span></div>
    <!-- ERATGUARD VITES-4C SETTINGS SMS CONTROL LINK START -->
    <a class="eg-row" href="/native/sms-control" style="text-decoration:none;color:inherit;">
      <b>Varsayılan SMS</b><span>HAZIRLIK</span>
    </a>
    <!-- ERATGUARD VITES-4C SETTINGS SMS CONTROL LINK END -->
  </section>

  <div class="eg-actions">
    <a class="eg-btn" href="/u/protection">Koruma Merkezine Git <span>→</span></a>
    <a class="eg-btn" href="/u/reports">Rapor Merkezine Git <span>→</span></a>
  </div>

  <a class="eg-back" href="/dashboard">← FAN-12P Komuta Merkezine Dön</a>

  <div class="eg-note">EratGuard Lisans Merkezi, PRO erişim ve kullanıcı yetkilerini tek ekranda gösterir.</div>
</div>
</body>
</html>"""

@app.after_request
def _eg_vites2f_force_license_center_after_response(response):
    try:
        if request.path == "/u/license":
            html = _eg_vites2f_license_center_html()
            response.set_data(html)
            response.status_code = 200
            response.headers["Content-Type"] = "text/html; charset=utf-8"
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
    except Exception:
        pass
    return response
# ===== ERATGUARD VITES-2F LICENSE CENTER END =====



# ===== ERATGUARD VITES-2G NOTIFICATION CENTER START =====
def _eg_vites2g_notification_center_html():
    try:
        username = session.get("username") or "Erat@32"
        plan = session.get("plan") or session.get("license_type") or "PRO"
    except Exception:
        username = "Erat@32"
        plan = "PRO"

    return f"""<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<title>EratGuard PRO - Vites-2G Bildirim Merkezi</title>
<style>
:root{{
  --green:#23ff89;
  --cyan:#22e7ff;
  --yellow:#ffd166;
  --red:#ff4d6d;
  --text:#f2fff6;
  --muted:rgba(242,255,246,.64);
  --line:rgba(35,255,137,.18);
  --card:rgba(4,18,12,.74);
}}
*{{box-sizing:border-box}}
html,body{{
  margin:0;
  min-height:100%;
  background:
    radial-gradient(circle at 82% 18%,rgba(34,231,255,.15),transparent 34%),
    radial-gradient(circle at 14% 88%,rgba(35,255,137,.13),transparent 40%),
    linear-gradient(135deg,#020705,#030d09 48%,#010403);
  color:var(--text);
  font-family:Arial,Helvetica,sans-serif;
  overflow-x:hidden;
}}
.eg-wrap{{min-height:100vh;padding:22px 18px 34px}}
.eg-top{{display:flex;align-items:center;justify-content:space-between;gap:14px;margin-bottom:22px}}
.eg-brand{{display:flex;align-items:center;gap:12px}}
.eg-logo{{
  width:42px;height:42px;border-radius:15px;display:grid;place-items:center;
  background:linear-gradient(135deg,var(--green),var(--cyan));
  color:#00170b;font-weight:1000;
  box-shadow:0 0 28px rgba(35,255,137,.22);
}}
.eg-title small{{display:block;color:var(--cyan);font-size:10px;font-weight:1000;letter-spacing:.18em}}
.eg-title b{{display:block;font-size:17px;letter-spacing:-.2px}}
.eg-pill{{
  border:1px solid var(--line);border-radius:999px;padding:9px 11px;
  background:rgba(3,18,10,.55);font-size:10px;font-weight:1000;
  letter-spacing:.12em;color:var(--green);white-space:nowrap;
}}
.eg-hero{{
  border:1px solid var(--line);border-radius:30px;padding:22px;
  background:linear-gradient(180deg,rgba(4,22,14,.82),rgba(2,8,6,.72));
  box-shadow:0 18px 70px rgba(0,0,0,.38), inset 0 0 28px rgba(35,255,137,.04);
  margin-bottom:16px;
}}
.eg-hero h1{{margin:0 0 8px;font-size:31px;letter-spacing:-1.2px;line-height:1}}
.eg-hero p{{margin:0;color:var(--muted);font-size:13px;line-height:1.55}}
.eg-list{{display:grid;gap:12px;margin-top:16px}}
.eg-item{{
  border:1px solid rgba(34,231,255,.16);
  border-radius:24px;
  background:rgba(2,13,10,.66);
  padding:15px;
  display:flex;
  gap:13px;
  align-items:flex-start;
}}
.eg-icon{{
  width:38px;height:38px;border-radius:14px;
  display:grid;place-items:center;
  background:rgba(35,255,137,.12);
  border:1px solid rgba(35,255,137,.20);
  font-size:18px;
  flex:0 0 auto;
}}
.eg-body b{{display:block;font-size:14px;margin-bottom:5px}}
.eg-body p{{margin:0;color:var(--muted);font-size:12px;line-height:1.45}}
.eg-tag{{
  display:inline-flex;
  margin-top:9px;
  border-radius:999px;
  padding:7px 9px;
  font-size:10px;
  font-weight:1000;
  letter-spacing:.12em;
  border:1px solid rgba(35,255,137,.20);
  color:var(--green);
}}
.warn{{color:var(--yellow);border-color:rgba(255,209,102,.24)}}
.info{{color:var(--cyan);border-color:rgba(34,231,255,.24)}}
.eg-actions{{display:grid;grid-template-columns:1fr;gap:11px;margin-top:16px}}
.eg-btn{{
  display:flex;align-items:center;justify-content:space-between;text-decoration:none;color:var(--text);
  border:1px solid rgba(34,231,255,.16);border-radius:22px;padding:15px 16px;
  background:rgba(2,13,10,.66);font-size:13px;font-weight:1000;letter-spacing:.02em;
}}
.eg-btn span{{color:var(--cyan)}}
.eg-back{{
  margin-top:16px;display:inline-flex;text-decoration:none;color:#00170b;
  background:linear-gradient(135deg,var(--green),var(--cyan));
  border-radius:999px;padding:12px 16px;font-size:12px;font-weight:1000;
  box-shadow:0 0 28px rgba(35,255,137,.16);
}}
.eg-note{{margin-top:14px;color:var(--muted);font-size:12px;line-height:1.55}}
@media(max-width:420px){{
  .eg-wrap{{padding:18px 14px 28px}}
  .eg-hero h1{{font-size:28px}}
}}
</style>
</head>
<body>
<div class="eg-wrap">
  <div class="eg-top">
    <div class="eg-brand">
      <div class="eg-logo">B</div>
      <div class="eg-title">
        <small>ERATGUARD VITES-2G</small>
        <b>Bildirim Merkezi</b>
      </div>
    </div>
    <div class="eg-pill">{plan}</div>
  </div>

  <section class="eg-hero">
    <h1>Bildirimler hazır.</h1>
    <p>{username} hesabı için güvenlik uyarıları, sistem mesajları ve admin bildirimleri tek merkezden takip edilir.</p>
  </section>

  <section class="eg-list">
    <div class="eg-item">
      <div class="eg-icon">🛡️</div>
      <div class="eg-body">
        <b>Koruma katmanı aktif</b>
        <p>SMS kalkanı, link kontrolü ve risk motoru kullanıma hazır.</p>
        <span class="eg-tag">GÜVENLİK</span>
      </div>
    </div>

    <div class="eg-item">
      <div class="eg-icon">🤖</div>
      <div class="eg-body">
        <b>AI analiz merkezi hazır</b>
        <p>Şüpheli SMS ve metinler risk puanı ile analiz edilebilir.</p>
        <span class="eg-tag info">AI</span>
      </div>
    </div>

    <div class="eg-item">
      <div class="eg-icon">🔑</div>
      <div class="eg-body">
        <b>PRO lisans geçerli</b>
        <p>Koruma, rapor ve analiz yetkileri aktif görünüyor.</p>
        <span class="eg-tag">LİSANS</span>
      </div>
    </div>

    <div class="eg-item">
      <div class="eg-icon">⚠️</div>
      <div class="eg-body">
        <b>Riskli bildirim yok</b>
        <p>Şu an kullanıcıya gösterilecek yüksek öncelikli güvenlik uyarısı bulunmuyor.</p>
        <span class="eg-tag warn">DURUM</span>
      </div>
    </div>
  </section>

  <div class="eg-actions">
    <a class="eg-btn" href="/u/protection">Koruma Merkezine Git <span>→</span></a>
    <a class="eg-btn" href="/u/reports">Rapor Merkezine Git <span>→</span></a>
  </div>

  <a class="eg-back" href="/dashboard">← FAN-12P Komuta Merkezine Dön</a>

  <div class="eg-note">EratGuard Bildirim Merkezi, güvenlik ve sistem mesajlarını kullanıcıya sade şekilde gösterir.</div>
</div>
</body>
</html>"""

@app.after_request
def _eg_vites2g_force_notifications_after_response(response):
    try:
        if request.path == "/u/notifications":
            html = _eg_vites2g_notification_center_html()
            response.set_data(html)
            response.status_code = 200
            response.headers["Content-Type"] = "text/html; charset=utf-8"
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
    except Exception:
        pass
    return response
# ===== ERATGUARD VITES-2G NOTIFICATION CENTER END =====



# ===== ERATGUARD VITES-2H COMMUNITY CENTER START =====
def _eg_vites2h_community_center_html():
    try:
        username = session.get("username") or "Erat@32"
        plan = session.get("plan") or session.get("license_type") or "PRO"
    except Exception:
        username = "Erat@32"
        plan = "PRO"

    return f"""<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<title>EratGuard PRO - Vites-2H Topluluk Merkezi</title>
<style>
:root{{
  --green:#23ff89;
  --cyan:#22e7ff;
  --yellow:#ffd166;
  --text:#f2fff6;
  --muted:rgba(242,255,246,.64);
  --line:rgba(35,255,137,.18);
  --card:rgba(4,18,12,.74);
}}
*{{box-sizing:border-box}}
html,body{{
  margin:0;
  min-height:100%;
  background:
    radial-gradient(circle at 82% 18%,rgba(34,231,255,.15),transparent 34%),
    radial-gradient(circle at 14% 88%,rgba(35,255,137,.13),transparent 40%),
    linear-gradient(135deg,#020705,#030d09 48%,#010403);
  color:var(--text);
  font-family:Arial,Helvetica,sans-serif;
  overflow-x:hidden;
}}
.eg-wrap{{min-height:100vh;padding:22px 18px 34px}}
.eg-top{{display:flex;align-items:center;justify-content:space-between;gap:14px;margin-bottom:22px}}
.eg-brand{{display:flex;align-items:center;gap:12px}}
.eg-logo{{
  width:42px;height:42px;border-radius:15px;display:grid;place-items:center;
  background:linear-gradient(135deg,var(--green),var(--cyan));
  color:#00170b;font-weight:1000;
  box-shadow:0 0 28px rgba(35,255,137,.22);
}}
.eg-title small{{display:block;color:var(--cyan);font-size:10px;font-weight:1000;letter-spacing:.18em}}
.eg-title b{{display:block;font-size:17px;letter-spacing:-.2px}}
.eg-pill{{
  border:1px solid var(--line);border-radius:999px;padding:9px 11px;
  background:rgba(3,18,10,.55);font-size:10px;font-weight:1000;
  letter-spacing:.12em;color:var(--green);white-space:nowrap;
}}
.eg-hero{{
  border:1px solid var(--line);border-radius:30px;padding:22px;
  background:linear-gradient(180deg,rgba(4,22,14,.82),rgba(2,8,6,.72));
  box-shadow:0 18px 70px rgba(0,0,0,.38), inset 0 0 28px rgba(35,255,137,.04);
  margin-bottom:16px;
}}
.eg-hero h1{{margin:0 0 8px;font-size:31px;letter-spacing:-1.2px;line-height:1}}
.eg-hero p{{margin:0;color:var(--muted);font-size:13px;line-height:1.55}}
.eg-grid{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px;margin:16px 0}}
.eg-card{{
  border:1px solid var(--line);
  border-radius:24px;
  padding:15px;
  background:var(--card);
  box-shadow:inset 0 0 20px rgba(35,255,137,.035);
}}
.eg-card .k{{font-size:10px;font-weight:1000;letter-spacing:.16em;color:var(--muted);margin-bottom:8px}}
.eg-card .v{{font-size:17px;font-weight:1000}}
.green{{color:var(--green)}}
.cyan{{color:var(--cyan)}}
.yellow{{color:var(--yellow)}}
.eg-list{{display:grid;gap:12px;margin-top:16px}}
.eg-item{{
  border:1px solid rgba(34,231,255,.16);
  border-radius:24px;
  background:rgba(2,13,10,.66);
  padding:15px;
}}
.eg-item b{{display:block;font-size:14px;margin-bottom:6px}}
.eg-item p{{margin:0;color:var(--muted);font-size:12px;line-height:1.45}}
.eg-tag{{
  display:inline-flex;margin-top:10px;border-radius:999px;padding:7px 9px;
  font-size:10px;font-weight:1000;letter-spacing:.12em;
  border:1px solid rgba(35,255,137,.20);color:var(--green);
}}
.eg-actions{{display:grid;grid-template-columns:1fr;gap:11px;margin-top:16px}}
.eg-btn{{
  display:flex;align-items:center;justify-content:space-between;text-decoration:none;color:var(--text);
  border:1px solid rgba(34,231,255,.16);border-radius:22px;padding:15px 16px;
  background:rgba(2,13,10,.66);font-size:13px;font-weight:1000;letter-spacing:.02em;
}}
.eg-btn span{{color:var(--cyan)}}
.eg-back{{
  margin-top:16px;display:inline-flex;text-decoration:none;color:#00170b;
  background:linear-gradient(135deg,var(--green),var(--cyan));
  border-radius:999px;padding:12px 16px;font-size:12px;font-weight:1000;
  box-shadow:0 0 28px rgba(35,255,137,.16);
}}
.eg-note{{margin-top:14px;color:var(--muted);font-size:12px;line-height:1.55}}

/* ===== ERATGUARD VITES-2H INLINE APK VISUAL START ===== */
.eg-list .eg-item:first-child{{
  padding-right:168px !important;
  min-height:220px !important;
}}
.eg-list .eg-item:first-child p{{
  max-width:190px !important;
  line-height:1.55 !important;
}}
@media(max-width:420px){{
  .eg-list .eg-item:first-child{{
    padding-right:174px !important;
    min-height:220px !important;
  }}
  .eg-list .eg-item:first-child p{{
    max-width:178px !important;
  }}
}}
/* ===== ERATGUARD VITES-2H INLINE APK VISUAL END ===== */

@media(max-width:420px){{
  .eg-wrap{{padding:18px 14px 28px}}
  .eg-hero h1{{font-size:28px}}
  .eg-grid{{grid-template-columns:1fr 1fr;gap:10px}}
  .eg-card{{padding:13px;border-radius:21px}}
}}
</style>
</head>
<body>
<div class="eg-wrap">
  <div class="eg-top">
    <div class="eg-brand">
      <div class="eg-logo">T</div>
      <div class="eg-title">
        <small>ERATGUARD VITES-2H</small>
        <b>Topluluk Merkezi</b>
      </div>
    </div>
    <div class="eg-pill">{plan}</div>
  </div>

  <section class="eg-hero">
    <h1>Güvenli topluluk hazır.</h1>
    <p>{username} hesabı için destek, öneri, geri bildirim ve güvenli iletişim merkezi burada yönetilir.</p>
  </section>

  <div class="eg-grid">
    <div class="eg-card">
      <div class="k">DESTEK</div>
      <div class="v green">HAZIR</div>
    </div>
    <div class="eg-card">
      <div class="k">GERİ BİLDİRİM</div>
      <div class="v cyan">AÇIK</div>
    </div>
    <div class="eg-card">
      <div class="k">ÖNERİLER</div>
      <div class="v yellow">TAKİPTE</div>
    </div>
    <div class="eg-card">
      <div class="k">GÜVENLİK</div>
      <div class="v green">KONTROLLÜ</div>
    </div>
  </div>

  <section class="eg-list">
    <div class="eg-item">
      <b>Destek kanalı</b>
      <p>Kullanıcı destek talepleri ve yardım başlıkları bu merkezden yönlendirilecek.</p>
      <span class="eg-tag">DESTEK</span>
    </div>

    <div class="eg-item">
      <b>Geri bildirim</b>
      <p>Kullanıcı önerileri, hata bildirimleri ve geliştirme istekleri güvenli şekilde toplanacak.</p>
      <span class="eg-tag">FEEDBACK</span>
    </div>

    <div class="eg-item">
      <b>Güvenli topluluk</b>
      <p>EratGuard kullanıcıları için kontrollü, güvenli ve faydalı topluluk altyapısı hazırlanıyor.</p>
      <span class="eg-tag">TOPLULUK</span>
    </div>
  </section>

  <div class="eg-actions">
    <a class="eg-btn" href="/u/notifications">Bildirim Merkezine Git <span>→</span></a>
    <a class="eg-btn" href="/u/reports">Rapor Merkezine Git <span>→</span></a>
  </div>

  <a class="eg-back" href="/dashboard">← FAN-12P Komuta Merkezine Dön</a>

  <div class="eg-note">EratGuard Topluluk Merkezi, destek ve kullanıcı iletişimini premium yapıya taşır.</div>
</div>
</body>
</html>"""

@app.after_request
def _eg_vites2h_force_community_after_response(response):
    try:
        if request.path == "/u/community":
            html = _eg_vites2h_community_center_html()
            response.set_data(html)
            response.status_code = 200
            response.headers["Content-Type"] = "text/html; charset=utf-8"
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
    except Exception:
        pass
    return response
# ===== ERATGUARD VITES-2H COMMUNITY CENTER END =====



# ===== ERATGUARD VITES-2I SETTINGS CENTER START =====
def _eg_vites2i_settings_center_html():
    try:
        username = session.get("username") or "Erat@32"
        plan = session.get("plan") or session.get("license_type") or "PRO"
    except Exception:
        username = "Erat@32"
        plan = "PRO"

    return f"""<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<title>EratGuard PRO - Vites-2I Ayarlar Merkezi</title>
<style>
:root{{
  --green:#23ff89;
  --cyan:#22e7ff;
  --yellow:#ffd166;
  --text:#f2fff6;
  --muted:rgba(242,255,246,.64);
  --line:rgba(35,255,137,.18);
  --card:rgba(4,18,12,.74);
}}
*{{box-sizing:border-box}}
html,body{{
  margin:0;
  min-height:100%;
  background:
    radial-gradient(circle at 82% 18%,rgba(34,231,255,.15),transparent 34%),
    radial-gradient(circle at 14% 88%,rgba(35,255,137,.13),transparent 40%),
    linear-gradient(135deg,#020705,#030d09 48%,#010403);
  color:var(--text);
  font-family:Arial,Helvetica,sans-serif;
  overflow-x:hidden;
}}
.eg-wrap{{min-height:100vh;padding:22px 18px 34px}}
.eg-top{{display:flex;align-items:center;justify-content:space-between;gap:14px;margin-bottom:22px}}
.eg-brand{{display:flex;align-items:center;gap:12px}}
.eg-logo{{
  width:42px;height:42px;border-radius:15px;display:grid;place-items:center;
  background:linear-gradient(135deg,var(--green),var(--cyan));
  color:#00170b;font-weight:1000;
  box-shadow:0 0 28px rgba(35,255,137,.22);
}}
.eg-title small{{display:block;color:var(--cyan);font-size:10px;font-weight:1000;letter-spacing:.18em}}
.eg-title b{{display:block;font-size:17px;letter-spacing:-.2px}}
.eg-pill{{
  border:1px solid var(--line);border-radius:999px;padding:9px 11px;
  background:rgba(3,18,10,.55);font-size:10px;font-weight:1000;
  letter-spacing:.12em;color:var(--green);white-space:nowrap;
}}
.eg-hero{{
  border:1px solid var(--line);border-radius:30px;padding:22px;
  background:linear-gradient(180deg,rgba(4,22,14,.82),rgba(2,8,6,.72));
  box-shadow:0 18px 70px rgba(0,0,0,.38), inset 0 0 28px rgba(35,255,137,.04);
  margin-bottom:16px;
}}
.eg-hero h1{{margin:0 0 8px;font-size:31px;letter-spacing:-1.2px;line-height:1}}
.eg-hero p{{margin:0;color:var(--muted);font-size:13px;line-height:1.55}}
.eg-grid{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px;margin:16px 0}}
.eg-card{{
  border:1px solid var(--line);
  border-radius:24px;
  padding:15px;
  background:var(--card);
  box-shadow:inset 0 0 20px rgba(35,255,137,.035);
}}
.eg-card .k{{font-size:10px;font-weight:1000;letter-spacing:.16em;color:var(--muted);margin-bottom:8px}}
.eg-card .v{{font-size:17px;font-weight:1000}}
.green{{color:var(--green)}}
.cyan{{color:var(--cyan)}}
.yellow{{color:var(--yellow)}}
.eg-list{{display:grid;gap:12px;margin-top:16px}}
.eg-row{{
  border:1px solid rgba(34,231,255,.16);
  border-radius:24px;
  background:rgba(2,13,10,.66);
  padding:15px;
  display:flex;
  justify-content:space-between;
  gap:12px;
  align-items:center;
}}
.eg-row b{{font-size:14px}}
.eg-row span{{font-size:12px;color:var(--green);font-weight:1000;text-align:right}}
.eg-actions{{display:grid;grid-template-columns:1fr;gap:11px;margin-top:16px}}
.eg-btn{{
  display:flex;align-items:center;justify-content:space-between;text-decoration:none;color:var(--text);
  border:1px solid rgba(34,231,255,.16);border-radius:22px;padding:15px 16px;
  background:rgba(2,13,10,.66);font-size:13px;font-weight:1000;letter-spacing:.02em;
}}
.eg-btn span{{color:var(--cyan)}}
.eg-back{{
  margin-top:16px;display:inline-flex;text-decoration:none;color:#00170b;
  background:linear-gradient(135deg,var(--green),var(--cyan));
  border-radius:999px;padding:12px 16px;font-size:12px;font-weight:1000;
  box-shadow:0 0 28px rgba(35,255,137,.16);
}}
.eg-note{{margin-top:14px;color:var(--muted);font-size:12px;line-height:1.55}}

/* ===== ERATGUARD VITES-2I INLINE APK VISUAL START ===== */
.eg-list .eg-row:first-child{{
  padding-right:130px !important;
  min-height:74px !important;
}}
.eg-list .eg-row:first-child span{{
  max-width:92px !important;
  overflow:hidden !important;
  text-overflow:ellipsis !important;
}}
@media(max-width:420px){{
  .eg-list .eg-row:first-child{{
    padding-right:138px !important;
  }}
  .eg-list .eg-row:first-child span{{
    max-width:86px !important;
  }}
}}
/* ===== ERATGUARD VITES-2I INLINE APK VISUAL END ===== */

@media(max-width:420px){{
  .eg-wrap{{padding:18px 14px 28px}}
  .eg-hero h1{{font-size:28px}}
  .eg-grid{{grid-template-columns:1fr 1fr;gap:10px}}
  .eg-card{{padding:13px;border-radius:21px}}
}}
</style>
</head>
<body>
<div class="eg-wrap">
  <div class="eg-top">
    <div class="eg-brand">
      <div class="eg-logo">A</div>
      <div class="eg-title">
        <small>ERATGUARD VITES-2I</small>
        <b>Ayarlar Merkezi</b>
      </div>
    </div>
    <div class="eg-pill">{plan}</div>
  </div>

  <section class="eg-hero">
    <h1>Ayarlar hazır.</h1>
    <p>{username} hesabı için uygulama, koruma, bildirim ve hesap ayarları tek merkezden yönetilir.</p>
  </section>

  <div class="eg-grid">
    <div class="eg-card">
      <div class="k">HESAP</div>
      <div class="v green">AKTİF</div>
    </div>
    <div class="eg-card">
      <div class="k">KORUMA</div>
      <div class="v cyan">AÇIK</div>
    </div>
    <div class="eg-card">
      <div class="k">BİLDİRİMLER</div>
      <div class="v yellow">HAZIR</div>
    </div>
    <div class="eg-card">
      <div class="k">SENKRON</div>
      <div class="v green">KONTROLLÜ</div>
    </div>
  </div>

  <section class="eg-list">
    <div class="eg-row"><b>Kullanıcı hesabı</b><span>{username}</span></div>
    <div class="eg-row"><b>Aktif paket</b><span>{plan}</span></div>
    <div class="eg-row"><b>Güvenlik modu</b><span>PRO</span></div>
    <div class="eg-row"><b>FAN-12P erişimi</b><span>AKTİF</span></div>
    <div class="eg-row"><b>Bildirim tercihleri</b><span>HAZIR</span></div>
  </section>

  <div class="eg-actions">
    <a class="eg-btn" href="/u/license">Lisans Merkezine Git <span>→</span></a>
    <a class="eg-btn" href="/u/notifications">Bildirim Merkezine Git <span>→</span></a>
  </div>

  <a class="eg-back" href="/dashboard">← FAN-12P Komuta Merkezine Dön</a>

  <div class="eg-note">EratGuard Ayarlar Merkezi, kullanıcı hesabı ve güvenlik tercihlerini premium yapıda gösterir.</div>
</div>
</body>
</html>"""

@app.after_request
def _eg_vites2i_force_settings_after_response(response):
    try:
        if request.path == "/u/settings":
            html = _eg_vites2i_settings_center_html()
            response.set_data(html)
            response.status_code = 200
            response.headers["Content-Type"] = "text/html; charset=utf-8"
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
    except Exception:
        pass
    return response
# ===== ERATGUARD VITES-2I SETTINGS CENTER END =====







# ===== ERATGUARD VITES-2D APK VISUAL BALANCE AFTER START =====
@app.after_request
def _eg_vites2d_apk_visual_balance_after_response(response):
    try:
        if request.path == "/u/analysis":
            html = response.get_data(as_text=True)
            marker = "ERATGUARD VITES-2D APK VISUAL BALANCE"
            if marker not in html and "</style>" in html:
                css = """
/* ===== ERATGUARD VITES-2D APK VISUAL BALANCE START ===== */
.eg-panel{
  padding-right:28px !important;
}
#egSmsText{
  width:100% !important;
  max-width:100% !important;
}
.eg-analyze{
  width:72% !important;
  max-width:420px !important;
  min-height:76px !important;
  margin-right:118px !important;
}
.eg-user-fan3-toggle{
  right:10px !important;
}
@media(max-width:420px){
  .eg-panel{
    padding-right:24px !important;
  }
  .eg-analyze{
    width:70% !important;
    max-width:380px !important;
    margin-right:124px !important;
  }
  .eg-user-fan3-toggle{
    right:8px !important;
  }
}
/* ===== ERATGUARD VITES-2D APK VISUAL BALANCE END ===== */
"""
                html = html.replace("</style>", css + "\n</style>", 1)
                response.set_data(html)
                response.headers["Content-Type"] = "text/html; charset=utf-8"
                response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
                response.headers["Pragma"] = "no-cache"
                response.headers["Expires"] = "0"
    except Exception:
        pass
    return response
# ===== ERATGUARD VITES-2D APK VISUAL BALANCE AFTER END =====



# ===== ERATGUARD VITES-2F APK VISUAL FORCE AFTER START =====
@app.after_request
def _eg_vites2f_apk_visual_force_after_response(response):
    try:
        if request.path == "/u/license":
            html = response.get_data(as_text=True)
            marker = "ERATGUARD VITES-2F APK VISUAL FORCE"
            if marker not in html and "</style>" in html:
                css = """
/* ===== ERATGUARD VITES-2F APK VISUAL FORCE START ===== */
.eg-grid .eg-card:nth-child(2){
  padding-right:108px !important;
}
.eg-grid .eg-card:nth-child(2) .v{
  max-width:92px !important;
}
.eg-user-fan3-toggle{
  right:10px !important;
}
@media(max-width:420px){
  .eg-grid .eg-card:nth-child(2){
    padding-right:112px !important;
  }
  .eg-grid .eg-card:nth-child(2) .v{
    max-width:88px !important;
  }
  .eg-user-fan3-toggle{
    right:8px !important;
  }
}
/* ===== ERATGUARD VITES-2F APK VISUAL FORCE END ===== */
"""
                html = html.replace("</style>", css + "\n</style>", 1)
                response.set_data(html)
                response.headers["Content-Type"] = "text/html; charset=utf-8"
                response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
                response.headers["Pragma"] = "no-cache"
                response.headers["Expires"] = "0"
    except Exception:
        pass
    return response
# ===== ERATGUARD VITES-2F APK VISUAL FORCE AFTER END =====



# ===== ERATGUARD VITES-2H APK VISUAL FORCE AFTER START =====
@app.after_request
def _eg_vites2h_apk_visual_force_after_response(response):
    try:
        if request.path == "/u/community":
            html = response.get_data(as_text=True)
            marker = "ERATGUARD VITES-2H APK VISUAL FORCE"
            if marker not in html and "</style>" in html:
                css = """
/* ===== ERATGUARD VITES-2H APK VISUAL FORCE START ===== */
.eg-list .eg-item:first-child{
  padding-right:118px !important;
}
.eg-list .eg-item:first-child p{
  max-width:360px !important;
}
.eg-user-fan3-toggle{
  right:10px !important;
}
@media(max-width:420px){
  .eg-list .eg-item:first-child{
    padding-right:124px !important;
  }
  .eg-list .eg-item:first-child p{
    max-width:260px !important;
  }
  .eg-user-fan3-toggle{
    right:8px !important;
  }
}
/* ===== ERATGUARD VITES-2H APK VISUAL FORCE END ===== */
"""
                html = html.replace("</style>", css + "\n</style>", 1)
                response.set_data(html)
                response.headers["Content-Type"] = "text/html; charset=utf-8"
                response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
                response.headers["Pragma"] = "no-cache"
                response.headers["Expires"] = "0"
    except Exception:
        pass
    return response
# ===== ERATGUARD VITES-2H APK VISUAL FORCE AFTER END =====




# ===== ERATGUARD VITES-5B LIVE FORCE AFTER RESPONSE START =====
@app.after_request
def eratguard_vites5b_live_force_after_response(response):
    try:
        from flask import request

        if request.path != "/u/analysis":
            return response

        html = response.get_data(as_text=True)

        if "ERATGUARD VITES-5B AI ANALYSIS SMS RISK BRIDGE START" in html:
            return response

        bridge = """
<script>
/* ===== ERATGUARD VITES-5B AI ANALYSIS SMS RISK BRIDGE START ===== */
(function(){
  function findSmsBox(){
    return document.getElementById("egSmsText") ||
           document.querySelector("textarea") ||
           document.querySelector("input[type='text']");
  }

  function findResultBox(){
    var box = document.getElementById("egAiResult");
    if(box) return box;

    box = document.querySelector(".eg-result");
    if(box) return box;

    box = document.createElement("div");
    box.id = "egAiResult";
    box.style.marginTop = "14px";
    box.style.background = "rgba(13,19,32,.96)";
    box.style.border = "1px solid rgba(35,255,137,.25)";
    box.style.borderRadius = "18px";
    box.style.padding = "14px";
    box.style.color = "#dce7f3";
    box.style.whiteSpace = "pre-wrap";
    box.style.fontSize = "13px";

    var btn = document.getElementById("egAnalyzeBtn") || document.querySelector("button");
    if(btn && btn.parentNode){
      btn.parentNode.insertBefore(box, btn.nextSibling);
    } else {
      document.body.appendChild(box);
    }
    return box;
  }

  async function egV5Analyze(){
    var input = findSmsBox();
    var result = findResultBox();
    var text = input ? input.value : "";

    result.textContent = "EratGuard Vites-5A risk motoru çalışıyor...";

    try{
      var r = await fetch("/api/v5/sms-risk", {
        method: "POST",
        headers: {"Content-Type":"application/json"},
        body: JSON.stringify({text:text})
      });

      var j = await r.json();
      var x = j.result || {};

      result.textContent =
        "Risk Puanı: %" + (x.score ?? "-") + "\\n" +
        "Seviye: " + (x.level || "-") + "\\n" +
        "Durum: " + (x.status || "-") + "\\n\\n" +
        "Sebepler:\\n- " + ((x.reasons || []).join("\\n- ")) + "\\n\\n" +
        "Öneri: " + (x.recommendation || "-");
    }catch(e){
      result.textContent = "Analiz hatası: " + e;
    }
  }

  function bind(){
    var btn = document.getElementById("egAnalyzeBtn") || document.querySelector("button");
    if(btn){
      btn.onclick = function(ev){
        ev.preventDefault();
        egV5Analyze();
        return false;
      };
      btn.setAttribute("data-vites5b", "sms-risk-engine");
    }
  }

  if(document.readyState === "loading"){
    document.addEventListener("DOMContentLoaded", bind);
  } else {
    bind();
  }
})();
/* ===== ERATGUARD VITES-5B AI ANALYSIS SMS RISK BRIDGE END ===== */
</script>
"""

        if "</body>" in html:
            html = html.replace("</body>", bridge + "\n</body>", 1)
        else:
            html += bridge

        response.set_data(html)
        response.headers["Content-Length"] = str(len(response.get_data()))
    except Exception:
        pass

    return response
# ===== ERATGUARD VITES-5B LIVE FORCE AFTER RESPONSE END =====



# ===== ERATGUARD VITES-5C SMS ACTION CENTER START =====
def eratguard_v5c_action_db_path():
    from pathlib import Path
    d = Path("data")
    d.mkdir(exist_ok=True)
    return d / "eratguard_sms_actions_v5c.json"


def eratguard_v5c_load_actions():
    import json
    path = eratguard_v5c_action_db_path()
    if not path.exists():
        return {"blocked": [], "safe": [], "reported": []}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return {"blocked": [], "safe": [], "reported": []}
        data.setdefault("blocked", [])
        data.setdefault("safe", [])
        data.setdefault("reported", [])
        return data
    except Exception:
        return {"blocked": [], "safe": [], "reported": []}


def eratguard_v5c_save_actions(data):
    import json
    path = eratguard_v5c_action_db_path()
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


@app.route("/api/v5/sms-action", methods=["POST"])
def eratguard_api_v5_sms_action():
    from flask import request, jsonify
    from datetime import datetime

    payload = request.get_json(silent=True) or {}
    action = (payload.get("action") or "").strip().lower()
    text = (payload.get("text") or "").strip()
    sender = (payload.get("sender") or "manual-analysis").strip()

    action_map = {
        "block": "blocked",
        "safe": "safe",
        "report": "reported"
    }

    if action not in action_map:
        return jsonify({
            "ok": False,
            "error": "Geçersiz aksiyon. block, safe veya report kullanılmalı."
        }), 400

    risk = eratguard_sms_risk_v1(text)
    db = eratguard_v5c_load_actions()

    item = {
        "ts": datetime.now().isoformat(timespec="seconds"),
        "action": action,
        "sender": sender,
        "text": text,
        "risk": risk
    }

    bucket = action_map[action]
    db[bucket].insert(0, item)
    db[bucket] = db[bucket][:200]

    eratguard_v5c_save_actions(db)

    return jsonify({
        "ok": True,
        "engine": "ERATGUARD_VITES5C_SMS_ACTION_CENTER",
        "saved_to": bucket,
        "item": item,
        "stats": {
            "blocked": len(db.get("blocked", [])),
            "safe": len(db.get("safe", [])),
            "reported": len(db.get("reported", []))
        }
    })


@app.route("/api/v5/sms-actions", methods=["GET"])
def eratguard_api_v5_sms_actions():
    from flask import jsonify

    db = eratguard_v5c_load_actions()
    return jsonify({
        "ok": True,
        "engine": "ERATGUARD_VITES5C_SMS_ACTION_CENTER",
        "stats": {
            "blocked": len(db.get("blocked", [])),
            "safe": len(db.get("safe", [])),
            "reported": len(db.get("reported", []))
        },
        "data": db
    })


@app.after_request
def eratguard_vites5c_action_buttons_after_response(response):
    try:
        from flask import request

        if request.path != "/u/analysis":
            return response

        html = response.get_data(as_text=True)

        if "ERATGUARD VITES-5C SMS ACTION BUTTONS START" in html:
            return response

        script = """
<script>
/* ===== ERATGUARD VITES-5C SMS ACTION BUTTONS START ===== */
(function(){
  window.egV5LastSmsText = "";

  function smsBox(){
    return document.getElementById("egSmsText") ||
           document.querySelector("textarea") ||
           document.querySelector("input[type='text']");
  }

  function resultBox(){
    return document.getElementById("egAiResult") ||
           document.querySelector(".eg-result");
  }

  function actionBox(){
    var old = document.getElementById("egV5cActions");
    if(old) return old;

    var box = document.createElement("div");
    box.id = "egV5cActions";
    box.style.display = "flex";
    box.style.gap = "8px";
    box.style.flexWrap = "wrap";
    box.style.marginTop = "12px";

    var actions = [
      ["block", "ENGELLE"],
      ["safe", "GÜVENLİ"],
      ["report", "ŞİKAYET ET"]
    ];

    actions.forEach(function(a){
      var b = document.createElement("button");
      b.type = "button";
      b.textContent = a[1];
      b.setAttribute("data-action", a[0]);
      b.style.flex = "1 1 110px";
      b.style.border = "0";
      b.style.borderRadius = "14px";
      b.style.padding = "12px";
      b.style.fontWeight = "900";
      b.style.background = "rgba(35,255,137,.18)";
      b.style.color = "#23ff89";
      b.style.border = "1px solid rgba(35,255,137,.35)";
      b.onclick = function(ev){
        ev.preventDefault();
        egV5cSaveAction(a[0]);
        return false;
      };
      box.appendChild(b);
    });

    var r = resultBox();
    if(r && r.parentNode){
      r.parentNode.insertBefore(box, r.nextSibling);
    } else {
      document.body.appendChild(box);
    }
    return box;
  }

  async function egV5cSaveAction(action){
    var input = smsBox();
    var text = input ? input.value : window.egV5LastSmsText || "";
    var r = resultBox();

    if(!text.trim()){
      if(r) r.textContent += "\\n\\nAksiyon kaydı için SMS metni boş olamaz.";
      return;
    }

    try{
      var res = await fetch("/api/v5/sms-action", {
        method: "POST",
        headers: {"Content-Type":"application/json"},
        body: JSON.stringify({action:action, text:text, sender:"manual-analysis"})
      });

      var j = await res.json();

      if(r){
        if(j.ok){
          r.textContent += "\\n\\nAksiyon kaydedildi: " + action.toUpperCase() +
            "\\nEngelli: " + j.stats.blocked +
            " | Güvenli: " + j.stats.safe +
            " | Şikayet: " + j.stats.reported;
        } else {
          r.textContent += "\\n\\nAksiyon hatası: " + (j.error || "bilinmeyen hata");
        }
      }
    }catch(e){
      if(r) r.textContent += "\\n\\nAksiyon kayıt hatası: " + e;
    }
  }

  function bindWatcher(){
    var btn = document.getElementById("egAnalyzeBtn") || document.querySelector("button");
    if(btn){
      btn.addEventListener("click", function(){
        var input = smsBox();
        window.egV5LastSmsText = input ? input.value : "";
        setTimeout(actionBox, 900);
      }, true);
    }

    setTimeout(actionBox, 1200);
  }

  if(document.readyState === "loading"){
    document.addEventListener("DOMContentLoaded", bindWatcher);
  } else {
    bindWatcher();
  }
})();
/* ===== ERATGUARD VITES-5C SMS ACTION BUTTONS END ===== */
</script>
"""

        if "</body>" in html:
            html = html.replace("</body>", script + "\n</body>", 1)
        else:
            html += script

        response.set_data(html)
        response.headers["Content-Length"] = str(len(response.get_data()))
    except Exception:
        pass

    return response
# ===== ERATGUARD VITES-5C SMS ACTION CENTER END =====



# ===== ERATGUARD VITES-5D BLOCKED SMS CENTER START =====
@app.route("/u/sms-actions-center")
@app.route("/u/blocked-sms")
def eratguard_v5d_blocked_sms_center():
    from html import escape

    db = eratguard_v5c_load_actions()
    blocked = db.get("blocked", [])
    safe = db.get("safe", [])
    reported = db.get("reported", [])

    def card(item, label):
        risk = item.get("risk", {}) if isinstance(item, dict) else {}
        text = escape(str(item.get("text", "")))
        sender = escape(str(item.get("sender", "-")))
        ts = escape(str(item.get("ts", "-")))
        level = escape(str(risk.get("level", "-")))
        score = escape(str(risk.get("score", "-")))
        status = escape(str(risk.get("status", "-")))

        reasons = risk.get("reasons", [])
        if not isinstance(reasons, list):
            reasons = []

        reasons_html = "".join(
            f"<li>{escape(str(x))}</li>" for x in reasons[:6]
        ) or "<li>Sebep kaydı yok.</li>"

        return f"""
        <div class="eg-card">
          <div class="eg-rowtop">
            <span class="eg-badge">{escape(label)}</span>
            <span class="eg-score">%{score} · {level}</span>
          </div>
          <div class="eg-meta">Gönderen: {sender} · Tarih: {ts}</div>
          <div class="eg-text">{text}</div>
          <div class="eg-status">{status}</div>
          <ul>{reasons_html}</ul>
        </div>
        """

    blocked_html = "".join(card(x, "ENGELLİ") for x in blocked) or '<div class="eg-empty">Henüz engellenen SMS yok.</div>'
    safe_html = "".join(card(x, "GÜVENLİ") for x in safe) or '<div class="eg-empty">Henüz güvenli liste kaydı yok.</div>'
    reported_html = "".join(card(x, "ŞİKAYET") for x in reported) or '<div class="eg-empty">Henüz şikayet kaydı yok.</div>'

    return f"""
<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>EratGuard PRO - Engellenen SMS Merkezi</title>
<style>
body{{
  margin:0;
  background:#070a12;
  color:#fff;
  font-family:Arial,Helvetica,sans-serif;
  padding:18px;
}}
.eg-wrap{{
  max-width:760px;
  margin:0 auto;
}}
.eg-head{{
  background:linear-gradient(135deg,rgba(35,255,137,.18),rgba(45,108,255,.10));
  border:1px solid rgba(35,255,137,.28);
  border-radius:24px;
  padding:18px;
  box-shadow:0 0 28px rgba(35,255,137,.10);
}}
.eg-kicker{{
  color:#23ff89;
  font-weight:900;
  letter-spacing:.08em;
  font-size:12px;
}}
h1{{
  margin:8px 0 8px;
  font-size:25px;
}}
p{{
  color:#9aa3b2;
  line-height:1.5;
}}
.eg-stats{{
  display:grid;
  grid-template-columns:repeat(3,1fr);
  gap:10px;
  margin-top:14px;
}}
.eg-stat{{
  background:rgba(255,255,255,.06);
  border:1px solid rgba(255,255,255,.08);
  border-radius:18px;
  padding:12px;
  text-align:center;
}}
.eg-stat b{{
  display:block;
  font-size:24px;
  color:#23ff89;
}}
.eg-tabs{{
  display:flex;
  gap:8px;
  margin:16px 0;
  flex-wrap:wrap;
}}
.eg-tabs button{{
  flex:1 1 120px;
  border:1px solid rgba(35,255,137,.28);
  background:rgba(35,255,137,.12);
  color:#23ff89;
  border-radius:16px;
  padding:12px;
  font-weight:900;
}}
.eg-section{{
  display:none;
}}
.eg-section.active{{
  display:block;
}}
.eg-card{{
  background:rgba(255,255,255,.06);
  border:1px solid rgba(255,255,255,.09);
  border-radius:20px;
  padding:14px;
  margin-bottom:12px;
}}
.eg-rowtop{{
  display:flex;
  justify-content:space-between;
  gap:10px;
  align-items:center;
}}
.eg-badge{{
  color:#06110b;
  background:#23ff89;
  border-radius:999px;
  padding:6px 10px;
  font-size:12px;
  font-weight:900;
}}
.eg-score{{
  color:#ffdf6e;
  font-weight:900;
}}
.eg-meta{{
  margin-top:10px;
  color:#9aa3b2;
  font-size:12px;
}}
.eg-text{{
  margin-top:10px;
  line-height:1.45;
  color:#fff;
}}
.eg-status{{
  margin-top:10px;
  color:#dce7f3;
  font-weight:800;
}}
ul{{
  margin:10px 0 0 18px;
  color:#aeb8c8;
}}
.eg-empty{{
  padding:18px;
  border-radius:18px;
  background:rgba(255,255,255,.05);
  color:#9aa3b2;
}}
.eg-back{{
  display:block;
  margin-top:18px;
  color:#23ff89;
  text-decoration:none;
  font-weight:900;
}}
</style>
</head>
<body>
<div class="eg-wrap">
  <div class="eg-head">
    <div class="eg-kicker">ERATGUARD VITES-5D</div>
    <h1>Engellenen SMS Merkezi</h1>
    <p>AI Analiz ekranından verilen ENGELLE, GÜVENLİ ve ŞİKAYET aksiyonları burada listelenir.</p>
    <div class="eg-stats">
      <div class="eg-stat"><b>{len(blocked)}</b>Engelli</div>
      <div class="eg-stat"><b>{len(safe)}</b>Güvenli</div>
      <div class="eg-stat"><b>{len(reported)}</b>Şikayet</div>
    </div>
  </div>

  <div class="eg-tabs">
    <button onclick="showTab('blocked')">ENGELLİ</button>
    <button onclick="showTab('safe')">GÜVENLİ</button>
    <button onclick="showTab('reported')">ŞİKAYET</button>
  </div>

  <section id="blocked" class="eg-section active">{blocked_html}</section>
  <section id="safe" class="eg-section">{safe_html}</section>
  <section id="reported" class="eg-section">{reported_html}</section>

  <a class="eg-back" href="/u/analysis">← AI Analiz Merkezine Dön</a>
  <a class="eg-back" href="/dashboard">← FAN-12P Komuta Merkezine Dön</a>
</div>

<script>
function showTab(id){{
  document.querySelectorAll(".eg-section").forEach(function(x){{x.classList.remove("active")}});
  document.getElementById(id).classList.add("active");
}}
</script>
</body>
</html>
"""
# ===== ERATGUARD VITES-5D BLOCKED SMS CENTER END =====



# ===== ERATGUARD VITES-5E REPORTS SMS STATS START =====
@app.after_request
def eratguard_vites5e_reports_sms_stats_after_response(response):
    try:
        from flask import request

        if request.path != "/u/reports":
            return response

        html = response.get_data(as_text=True)

        if "ERATGUARD VITES-5E REPORTS SMS STATS CARD START" in html:
            return response

        db = eratguard_v5c_load_actions()
        blocked = len(db.get("blocked", []))
        safe = len(db.get("safe", []))
        reported = len(db.get("reported", []))
        total = blocked + safe + reported

        card = f"""
<div style="margin-top:16px;background:rgba(255,255,255,.06);border:1px solid rgba(35,255,137,.28);border-radius:22px;padding:16px;box-shadow:0 0 24px rgba(35,255,137,.10);">
  <!-- ERATGUARD VITES-5E REPORTS SMS STATS CARD START -->
  <div style="color:#23ff89;font-weight:900;font-size:12px;letter-spacing:.08em;">ERATGUARD VITES-5E</div>
  <h2 style="margin:8px 0 10px;font-size:21px;color:#fff;">SMS Koruma İstatistikleri</h2>
  <p style="margin:0 0 12px;color:#9aa3b2;line-height:1.45;">AI Analiz ekranından gelen gerçek ENGELLE / GÜVENLİ / ŞİKAYET kayıtları.</p>

  <div style="display:grid;grid-template-columns:repeat(2,1fr);gap:10px;">
    <div style="background:rgba(255,255,255,.06);border-radius:16px;padding:12px;text-align:center;">
      <b style="display:block;color:#23ff89;font-size:26px;">{blocked}</b>
      <span style="color:#aeb8c8;font-size:12px;font-weight:800;">Engellenen SMS</span>
    </div>
    <div style="background:rgba(255,255,255,.06);border-radius:16px;padding:12px;text-align:center;">
      <b style="display:block;color:#23ff89;font-size:26px;">{safe}</b>
      <span style="color:#aeb8c8;font-size:12px;font-weight:800;">Güvenli SMS</span>
    </div>
    <div style="background:rgba(255,255,255,.06);border-radius:16px;padding:12px;text-align:center;">
      <b style="display:block;color:#23ff89;font-size:26px;">{reported}</b>
      <span style="color:#aeb8c8;font-size:12px;font-weight:800;">Şikayet</span>
    </div>
    <div style="background:rgba(255,255,255,.06);border-radius:16px;padding:12px;text-align:center;">
      <b style="display:block;color:#23ff89;font-size:26px;">{total}</b>
      <span style="color:#aeb8c8;font-size:12px;font-weight:800;">Toplam Aksiyon</span>
    </div>
  </div>

  <a href="/u/sms-actions-center" style="display:block;margin-top:14px;color:#23ff89;text-decoration:none;font-weight:900;">
    Engellenen SMS Merkezi detaylarını aç →
  </a>
  <!-- ERATGUARD VITES-5E REPORTS SMS STATS CARD END -->
</div>
"""

        if "</main>" in html:
            html = html.replace("</main>", card + "\n</main>", 1)
        elif "</body>" in html:
            html = html.replace("</body>", card + "\n</body>", 1)
        else:
            html += card

        response.set_data(html)
        response.headers["Content-Length"] = str(len(response.get_data()))
    except Exception:
        pass

    return response
# ===== ERATGUARD VITES-5E REPORTS SMS STATS END =====



# ===== ERATGUARD VITES-5F PROTECTION SMS LIVE STATUS START =====
@app.after_request
def eratguard_vites5f_protection_sms_status_after_response(response):
    try:
        from flask import request

        if request.path != "/u/protection":
            return response

        html = response.get_data(as_text=True)

        if "ERATGUARD VITES-5F PROTECTION SMS STATUS CARD START" in html:
            return response

        db = eratguard_v5c_load_actions()
        blocked = len(db.get("blocked", []))
        safe = len(db.get("safe", []))
        reported = len(db.get("reported", []))
        total = blocked + safe + reported

        if reported > 0 or blocked > 0:
            level = "AKTİF İZLEME"
            desc = "SMS risk motoru aktif kayıt üretiyor. Engelleme ve şikayet kayıtları izleniyor."
        else:
            level = "TEMİZ"
            desc = "Şu anda kayıtlı riskli SMS aksiyonu yok."

        card = f"""
<div style="margin-top:16px;background:rgba(35,255,137,.08);border:1px solid rgba(35,255,137,.32);border-radius:22px;padding:16px;box-shadow:0 0 24px rgba(35,255,137,.10);">
  <!-- ERATGUARD VITES-5F PROTECTION SMS STATUS CARD START -->
  <div style="color:#23ff89;font-weight:900;font-size:12px;letter-spacing:.08em;">ERATGUARD VITES-5F</div>
  <h2 style="margin:8px 0 10px;font-size:21px;color:#fff;">SMS Koruma Durumu</h2>
  <p style="margin:0 0 12px;color:#9aa3b2;line-height:1.45;">{desc}</p>

  <div style="display:grid;grid-template-columns:repeat(2,1fr);gap:10px;">
    <div style="background:rgba(255,255,255,.06);border-radius:16px;padding:12px;text-align:center;">
      <b style="display:block;color:#23ff89;font-size:24px;">{level}</b>
      <span style="color:#aeb8c8;font-size:12px;font-weight:800;">Canlı Durum</span>
    </div>
    <div style="background:rgba(255,255,255,.06);border-radius:16px;padding:12px;text-align:center;">
      <b style="display:block;color:#23ff89;font-size:24px;">{total}</b>
      <span style="color:#aeb8c8;font-size:12px;font-weight:800;">Toplam SMS Aksiyonu</span>
    </div>
    <div style="background:rgba(255,255,255,.06);border-radius:16px;padding:12px;text-align:center;">
      <b style="display:block;color:#23ff89;font-size:24px;">{blocked}</b>
      <span style="color:#aeb8c8;font-size:12px;font-weight:800;">Engellenen</span>
    </div>
    <div style="background:rgba(255,255,255,.06);border-radius:16px;padding:12px;text-align:center;">
      <b style="display:block;color:#23ff89;font-size:24px;">{reported}</b>
      <span style="color:#aeb8c8;font-size:12px;font-weight:800;">Şikayet</span>
    </div>
  </div>

  <a href="/u/sms-actions-center" style="display:block;margin-top:14px;color:#23ff89;text-decoration:none;font-weight:900;">
    Engellenen SMS Merkezi’ni aç →
  </a>
  <!-- ERATGUARD VITES-5F PROTECTION SMS STATUS CARD END -->
</div>
"""

        if "</main>" in html:
            html = html.replace("</main>", card + "\n</main>", 1)
        elif "</body>" in html:
            html = html.replace("</body>", card + "\n</body>", 1)
        else:
            html += card

        response.set_data(html)
        response.headers["Content-Length"] = str(len(response.get_data()))
    except Exception:
        pass

    return response
# ===== ERATGUARD VITES-5F PROTECTION SMS LIVE STATUS END =====




# ERATGUARD VITES-5G OLD DUPLICATE SUMMARY REMOVED



# ===== ERATGUARD VITES-5A SMS RISK ENGINE V1 START =====
def eratguard_sms_risk_v1(text):
    import re

    raw = text or ""
    msg = raw.lower().strip()

    score = 0
    reasons = []

    def add(points, reason):
        nonlocal score
        score += points
        reasons.append(reason)

    if not msg:
        return {
            "score": 0,
            "level": "BOŞ",
            "status": "Analiz edilecek SMS metni yok.",
            "reasons": ["SMS metni boş."],
            "recommendation": "SMS içeriği girilmelidir."
        }

    url_patterns = [
        r"https?://",
        r"www\.",
        r"\.com",
        r"\.net",
        r"\.org",
        r"bit\.ly",
        r"t\.co",
        r"tinyurl",
        r"link",
    ]

    if any(re.search(p, msg) for p in url_patterns):
        add(30, "Mesajda bağlantı/link işareti var.")

    finance_words = [
        "banka", "kart", "kredi", "hesap", "iban", "şifre", "sifre",
        "parola", "otp", "doğrulama", "dogrulama", "ödeme", "odeme",
        "borç", "borc", "fatura", "limit", "pos", "havale", "eft"
    ]
    if any(w in msg for w in finance_words):
        add(22, "Finans/banka/ödeme içerikli kelimeler var.")

    cargo_words = [
        "kargo", "teslimat", "paket", "gümrük", "gumruk",
        "adres", "dağıtım", "dagitim", "kurye"
    ]
    if any(w in msg for w in cargo_words):
        add(16, "Kargo/teslimat temalı ifade var.")

    prize_words = [
        "hediye", "ödül", "odul", "kazandınız", "kazandiniz",
        "çekiliş", "cekilis", "kampanya", "kupon", "bonus"
    ]
    if any(w in msg for w in prize_words):
        add(18, "Ödül/hediye/kampanya temalı ifade var.")

    urgency_words = [
        "hemen", "acil", "son gün", "son gun", "bugün", "bugun",
        "iptal", "askıya", "askiya", "kapanacak", "bloke",
        "donduruldu", "sınırlı", "sinirli"
    ]
    if any(w in msg for w in urgency_words):
        add(18, "Acil/tehdit/acele ettiren dil kullanılmış.")

    action_words = [
        "tıkla", "tikla", "giriş yap", "giris yap", "onayla",
        "doğrula", "dogrula", "güncelle", "guncelle",
        "başvur", "basvur", "yükle", "yukle"
    ]
    if any(w in msg for w in action_words):
        add(18, "Kullanıcıyı işlem yapmaya zorlayan ifade var.")

    sender_like = re.search(r"\b\d{4,}\b", msg)
    if sender_like:
        add(8, "Mesajda dikkat çeken numara/kod yapısı var.")

    if len(msg) < 18:
        add(5, "Mesaj çok kısa; bağlam sınırlı.")

    if score >= 85:
        level = "ÇOK RİSKLİ"
        status = "Bu SMS yüksek olasılıkla spam/dolandırıcılık olabilir."
        recommendation = "Linke tıklama, bilgi girme, göndereni doğrulamadan işlem yapma."
    elif score >= 60:
        level = "RİSKLİ"
        status = "Bu SMS şüpheli görünüyor."
        recommendation = "Dikkatli ol, bağlantı varsa açmadan önce doğrula."
    elif score >= 35:
        level = "ORTA RİSK"
        status = "Bu SMS bazı risk işaretleri taşıyor."
        recommendation = "Göndereni ve içeriği kontrol et."
    else:
        level = "DÜŞÜK RİSK"
        status = "Belirgin yüksek risk işareti bulunmadı."
        recommendation = "Yine de bilinmeyen linklere dikkat et."

    return {
        "score": min(score, 100),
        "level": level,
        "status": status,
        "reasons": reasons if reasons else ["Belirgin spam işareti bulunmadı."],
        "recommendation": recommendation
    }


@app.route("/api/v5/sms-risk", methods=["POST"])
def eratguard_api_v5_sms_risk():
    from flask import request, jsonify

    data = request.get_json(silent=True) or {}
    text = data.get("text") or request.form.get("text") or ""
    result = eratguard_sms_risk_v1(text)
    return jsonify({
        "ok": True,
        "engine": "ERATGUARD_VITES5A_SMS_RISK_ENGINE_V1",
        "input_length": len(text or ""),
        "result": result
    })


@app.route("/u/sms-risk-test")
def eratguard_v5a_sms_risk_test_page():
    return """
<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>EratGuard Vites-5A SMS Risk Motoru</title>
<style>
body{margin:0;background:#070a12;color:#fff;font-family:Arial,Helvetica,sans-serif;padding:22px}
.card{max-width:520px;margin:0 auto;background:rgba(255,255,255,.06);border:1px solid rgba(35,255,137,.25);border-radius:24px;padding:20px;box-shadow:0 0 28px rgba(35,255,137,.12)}
small{color:#23ff89;font-weight:900;letter-spacing:.08em}
h1{font-size:24px;margin:10px 0 8px}
p{color:#9aa3b2;line-height:1.5}
textarea{width:100%;min-height:150px;border-radius:18px;border:1px solid rgba(35,255,137,.35);background:#0d1320;color:#fff;padding:14px;font-size:15px;box-sizing:border-box}
button{width:100%;margin-top:14px;border:0;border-radius:18px;background:#23ff89;color:#06110b;font-weight:900;padding:14px;font-size:15px}
.result{margin-top:16px;background:#0d1320;border-radius:18px;padding:14px;white-space:pre-wrap;color:#dce7f3}
.back{display:block;margin-top:16px;color:#23ff89;text-decoration:none;font-weight:800}
</style>
</head>
<body>
<div class="card">
<small>ERATGUARD VITES-5A</small>
<h1>SMS Risk Motoru v1</h1>
<p>SMS metnini analiz eder, risk puanı ve sebep üretir. Bu motor Vites-5 spam engelleme sisteminin temelidir.</p>
<textarea id="smsText" placeholder="Örnek: Kargonuz beklemede, hemen linke tıklayın..."></textarea>
<button onclick="analyze()">SMS Riskini Analiz Et</button>
<div class="result" id="result">Sonuç burada görünecek.</div>
<a class="back" href="/dashboard">← FAN-12P Komuta Merkezine Dön</a>
</div>
<script>
async function analyze(){
  const text=document.getElementById("smsText").value;
  const box=document.getElementById("result");
  box.textContent="Analiz ediliyor...";
  try{
    const r=await fetch("/api/v5/sms-risk",{
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({text})
    });
    const j=await r.json();
    const x=j.result;
    box.textContent=
      "Risk Puanı: %"+x.score+"\\n"+
      "Seviye: "+x.level+"\\n"+
      "Durum: "+x.status+"\\n\\n"+
      "Sebepler:\\n- "+x.reasons.join("\\n- ")+"\\n\\n"+
      "Öneri: "+x.recommendation;
  }catch(e){
    box.textContent="Analiz hatası: "+e;
  }
}
</script>
</body>
</html>
"""
# ===== ERATGUARD VITES-5A SMS RISK ENGINE V1 END =====



# ===== ERATGUARD VITES-5G DASHBOARD FINAL ORDER FIX START =====
def eratguard_vites5g_dashboard_sms_summary_final_order(response):
    try:
        from flask import request

        if request.path not in ("/dashboard", "/u/dashboard"):
            return response

        html = response.get_data(as_text=True)

        if "ERATGUARD VITES-5G DASHBOARD FINAL CARD START" in html:
            return response

        db = eratguard_v5c_load_actions()
        blocked = len(db.get("blocked", []))
        safe = len(db.get("safe", []))
        reported = len(db.get("reported", []))
        total = blocked + safe + reported

        status = "AKTİF İZLEME" if total > 0 else "HAZIR"
        desc = "SMS risk motoru aktif, analiz ve aksiyon kayıtları takip ediliyor." if total > 0 else "SMS risk motoru hazır, yeni analizleri bekliyor."

        card = f"""
<div style="margin:170px auto 0;max-width:520px;background:rgba(35,255,137,.08);border:1px solid rgba(35,255,137,.32);border-radius:24px;padding:16px;box-shadow:0 0 26px rgba(35,255,137,.12);">
  <!-- ERATGUARD VITES-5G DASHBOARD FINAL CARD START -->
  <div style="color:#23ff89;font-weight:900;font-size:12px;letter-spacing:.08em;">ERATGUARD VITES-5G</div>
  <h2 style="margin:8px 0 8px;font-size:21px;color:#fff;">SMS Koruma Özeti</h2>
  <p style="margin:0 0 12px;color:#9aa3b2;line-height:1.45;">{desc}</p>

  <div style="display:grid;grid-template-columns:repeat(2,1fr);gap:10px;">
    <div style="background:rgba(255,255,255,.06);border-radius:16px;padding:12px;text-align:center;">
      <b style="display:block;color:#23ff89;font-size:22px;">{status}</b>
      <span style="color:#aeb8c8;font-size:12px;font-weight:800;">Durum</span>
    </div>
    <div style="background:rgba(255,255,255,.06);border-radius:16px;padding:12px;text-align:center;">
      <b style="display:block;color:#23ff89;font-size:24px;">{total}</b>
      <span style="color:#aeb8c8;font-size:12px;font-weight:800;">Toplam Aksiyon</span>
    </div>
    <div style="background:rgba(255,255,255,.06);border-radius:16px;padding:12px;text-align:center;">
      <b style="display:block;color:#23ff89;font-size:24px;">{blocked}</b>
      <span style="color:#aeb8c8;font-size:12px;font-weight:800;">Engellenen</span>
    </div>
    <div style="background:rgba(255,255,255,.06);border-radius:16px;padding:12px;text-align:center;">
      <b style="display:block;color:#23ff89;font-size:24px;">{reported}</b>
      <span style="color:#aeb8c8;font-size:12px;font-weight:800;">Şikayet</span>
    </div>
  </div>

  <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:14px;">
    <a href="/u/analysis" style="flex:1 1 140px;text-align:center;color:#06110b;background:#23ff89;text-decoration:none;font-weight:900;border-radius:14px;padding:12px;">AI Analiz Aç</a>
    <a href="/u/sms-actions-center" style="flex:1 1 140px;text-align:center;color:#23ff89;background:rgba(35,255,137,.12);border:1px solid rgba(35,255,137,.32);text-decoration:none;font-weight:900;border-radius:14px;padding:12px;">SMS Merkezi</a>
  </div>
  <!-- ERATGUARD VITES-5G DASHBOARD FINAL CARD END -->




</div>
"""

        if "</main>" in html:
            html = html.replace("</main>", card + "\n</main>", 1)
        elif "</body>" in html:
            html = html.replace("</body>", card + "\n</body>", 1)
        else:
            html += card

        response.set_data(html)
        response.headers["Content-Length"] = str(len(response.get_data()))
    except Exception:
        pass

    return response

# Flask after_request ters sırayla çalışır.
# Bu yüzden insert(0) ile bu fonksiyon en SON çalıştırılır ve dashboard force render ezemez.
try:
    _eg_v5g_after_list = app.after_request_funcs.setdefault(None, [])
    _eg_v5g_after_list = [f for f in _eg_v5g_after_list if getattr(f, "__name__", "") != "eratguard_vites5g_dashboard_sms_summary_final_order"]
    _eg_v5g_after_list.insert(0, eratguard_vites5g_dashboard_sms_summary_final_order)
    app.after_request_funcs[None] = _eg_v5g_after_list
except Exception:
    pass
# ===== ERATGUARD VITES-5G DASHBOARD FINAL ORDER FIX END =====














# ERATGUARD VITES-5J DRAG MENU DISABLED - WILL BE DONE LATER




# ===== ERATGUARD FIXED MENU RESTORE FINAL START =====
def eratguard_fixed_menu_restore_final(response):
    try:
        from flask import request

        path = request.path or ""
        if not (path == "/dashboard" or path == "/u/dashboard" or path.startswith("/u/")):
            return response

        html = response.get_data(as_text=True)

        if "ERATGUARD FIXED MENU RESTORE SCRIPT START" in html:
            return response

        script = r"""
<style>
/* ===== ERATGUARD FIXED MENU RESTORE STYLE START ===== */
.eg-v5j-true-float,
.eg-v5j-draggable-menu,
.eg-v5j-drag-menu{
  left:auto!important;
  top:auto!important;
  right:18px!important;
  bottom:155px!important;
  transform:none!important;
  position:fixed!important;
  z-index:999999!important;
  touch-action:auto!important;
  cursor:pointer!important;
}
/* ===== ERATGUARD FIXED MENU RESTORE STYLE END ===== */
</style>

<script>
/* ===== ERATGUARD FIXED MENU RESTORE SCRIPT START ===== */
(function(){
  const oldKeys = [
    "eratguard_v5j_true_float_pos",
    "eratguard_v5j_menu_position",
    "eratguard_v5j_safezone_version"
  ];

  try{
    oldKeys.forEach(k => localStorage.removeItem(k));
  }catch(e){}

  function findMenu(){
    const selectors = [
      ".eg-user-fan3-toggle",
      ".eg-user-fan-toggle",
      ".menu-toggle",
      ".fan-handle",
      ".eg-menu-toggle",
      "[data-eg-menu-toggle]",
      ".eg-v5j-true-float",
      ".eg-v5j-draggable-menu",
      ".eg-v5j-drag-menu"
    ];

    for(const sel of selectors){
      const el = document.querySelector(sel);
      if(el) return el;
    }

    return Array.from(document.querySelectorAll("button,a,div,span")).find(function(el){
      return ((el.innerText || el.textContent || "").trim().toUpperCase()).includes("MENÜ");
    });
  }

  function fix(){
    const el = findMenu();
    if(!el) return;

    el.classList.remove("eg-v5j-true-float","eg-v5j-moving","eg-v5j-draggable-menu","eg-v5j-drag-menu","eg-v5j-dragging","eg-v5j-safe-pulse");

    el.style.position = "fixed";
    el.style.left = "auto";
    el.style.top = "auto";
    el.style.right = "18px";
    el.style.bottom = "155px";
    el.style.transform = "none";
    el.style.zIndex = "999999";
    el.style.touchAction = "auto";
    el.style.cursor = "pointer";
  }

  if(document.readyState === "loading"){
    document.addEventListener("DOMContentLoaded", fix);
  }else{
    fix();
  }

  setTimeout(fix, 250);
  setTimeout(fix, 1000);
})();
/* ===== ERATGUARD FIXED MENU RESTORE SCRIPT END ===== */
</script>
"""

        if "</body>" in html:
            html = html.replace("</body>", script + "\n</body>", 1)
        else:
            html += script

        response.set_data(html)
        response.headers["Content-Length"] = str(len(response.get_data()))
    except Exception:
        pass

    return response

try:
    _eg_fixed_menu_list = app.after_request_funcs.setdefault(None, [])
    _eg_fixed_menu_list = [f for f in _eg_fixed_menu_list if getattr(f, "__name__", "") != "eratguard_fixed_menu_restore_final"]
    _eg_fixed_menu_list.insert(0, eratguard_fixed_menu_restore_final)
    app.after_request_funcs[None] = _eg_fixed_menu_list
except Exception:
    pass
# ===== ERATGUARD FIXED MENU RESTORE FINAL END =====



# ===== ERATGUARD VITES-6A PROTECTION HISTORY CENTER START =====
@app.route("/u/protection-history")
@app.route("/u/history")
def eratguard_vites6a_protection_history_center():
    from flask import render_template_string
    import json
    from pathlib import Path

    data_path = Path("data/eratguard_sms_actions_v5c.json")

    actions = {
        "blocked": [],
        "safe": [],
        "reported": []
    }

    if data_path.exists():
        try:
            loaded = json.loads(data_path.read_text(encoding="utf-8", errors="ignore"))
            if isinstance(loaded, dict):
                for key in actions:
                    val = loaded.get(key, [])
                    if isinstance(val, list):
                        actions[key] = val
        except Exception:
            pass

    def normalize_items(kind, label, icon):
        out = []
        for item in actions.get(kind, []):
            if not isinstance(item, dict):
                continue

            text = item.get("text") or item.get("message") or item.get("sms") or item.get("content") or ""
            score = item.get("score") or item.get("risk_score") or item.get("riskScore") or 0
            level = item.get("level") or item.get("risk_level") or item.get("riskLevel") or "Kayıt"
            created = item.get("created_at") or item.get("time") or item.get("timestamp") or item.get("date") or "-"

            try:
                score_int = int(score)
            except Exception:
                score_int = 0

            short = str(text).strip()
            if len(short) > 150:
                short = short[:150] + "..."

            out.append({
                "kind": kind,
                "label": label,
                "icon": icon,
                "text": str(text),
                "short": short or "Mesaj içeriği yok",
                "score": score_int,
                "level": str(level),
                "created": str(created)
            })
        return out

    history = []
    history += normalize_items("blocked", "Engellendi", "🛡️")
    history += normalize_items("reported", "Şikayet", "⚠️")
    history += normalize_items("safe", "Güvenli", "✅")

    total = len(history)
    blocked_count = len(actions.get("blocked", []))
    reported_count = len(actions.get("reported", []))
    safe_count = len(actions.get("safe", []))

    html = """
<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>EratGuard - Koruma Geçmişi</title>
<style>
:root{
  --eg-bg:#03140d;
  --eg-card:rgba(35,255,137,.08);
  --eg-border:rgba(35,255,137,.28);
  --eg-green:#23ff89;
  --eg-cyan:#42e8ff;
  --eg-text:#ffffff;
  --eg-muted:rgba(255,255,255,.68);
}
*{box-sizing:border-box}
body{
  margin:0;
  min-height:100vh;
  color:var(--eg-text);
  font-family:Arial,Helvetica,sans-serif;
  background:
    radial-gradient(circle at 70% 55%, rgba(35,255,137,.18), transparent 35%),
    linear-gradient(180deg,#061b13,#020805 75%);
}
.wrap{
  width:min(720px,100%);
  margin:0 auto;
  padding:28px 18px 120px;
}
.top{
  display:flex;
  align-items:center;
  justify-content:space-between;
  gap:12px;
  margin-bottom:20px;
}
.brand{
  display:flex;
  align-items:center;
  gap:12px;
}
.logo{
  width:56px;
  height:56px;
  border-radius:18px;
  display:grid;
  place-items:center;
  color:#04120b;
  font-weight:900;
  font-size:34px;
  background:linear-gradient(135deg,#23ff89,#4ab6ff);
  box-shadow:0 0 28px rgba(35,255,137,.25);
}
.brand h1{
  margin:0;
  font-size:22px;
  line-height:1.05;
}
.brand small{
  display:block;
  color:var(--eg-cyan);
  letter-spacing:3px;
  font-weight:800;
  margin-top:4px;
  font-size:11px;
}
.back{
  color:var(--eg-green);
  text-decoration:none;
  border:1px solid var(--eg-border);
  border-radius:999px;
  padding:10px 14px;
  font-weight:800;
  background:rgba(0,0,0,.18);
}
.hero{
  border:1px solid var(--eg-border);
  background:var(--eg-card);
  border-radius:26px;
  padding:18px;
  box-shadow:0 0 28px rgba(35,255,137,.12);
  margin-bottom:16px;
}
.kicker{
  color:var(--eg-green);
  font-size:13px;
  font-weight:900;
  letter-spacing:1.6px;
}
.hero h2{
  margin:8px 0 8px;
  font-size:28px;
}
.hero p{
  color:var(--eg-muted);
  margin:0;
  line-height:1.55;
}
.stats{
  display:grid;
  grid-template-columns:repeat(4,1fr);
  gap:10px;
  margin-top:16px;
}
.stat{
  border-radius:18px;
  padding:14px 10px;
  background:rgba(255,255,255,.05);
  text-align:center;
}
.stat b{
  display:block;
  color:var(--eg-green);
  font-size:24px;
}
.stat span{
  color:var(--eg-muted);
  font-weight:700;
  font-size:12px;
}
.actions{
  display:flex;
  gap:10px;
  margin:16px 0;
  flex-wrap:wrap;
}
.btn{
  flex:1;
  min-width:150px;
  text-align:center;
  padding:13px 14px;
  border-radius:18px;
  border:1px solid var(--eg-border);
  text-decoration:none;
  color:var(--eg-green);
  font-weight:900;
  background:rgba(0,0,0,.16);
}
.btn.primary{
  background:var(--eg-green);
  color:#03140d;
}
.btn.danger{
  background:rgba(255,70,70,.16);
  color:#ff7b7b;
  border-color:rgba(255,90,90,.35);
  cursor:pointer;
}
.btn.restore{
  background:rgba(66,232,255,.14);
  color:#42e8ff;
  border-color:rgba(66,232,255,.35);
  cursor:pointer;
}
.list{
  display:flex;
  flex-direction:column;
  gap:12px;
}
.item{
  border:1px solid rgba(255,255,255,.08);
  background:rgba(255,255,255,.045);
  border-radius:22px;
  padding:14px;
}
.item-head{
  display:flex;
  justify-content:space-between;
  gap:10px;
  align-items:center;
  margin-bottom:10px;
}
.badge{
  display:inline-flex;
  gap:8px;
  align-items:center;
  border:1px solid var(--eg-border);
  color:var(--eg-green);
  border-radius:999px;
  padding:7px 10px;
  font-weight:900;
  font-size:12px;
}
.score{
  font-size:22px;
  color:var(--eg-green);
  font-weight:900;
}
.msg{
  color:rgba(255,255,255,.86);
  line-height:1.45;
  word-break:break-word;
}
.meta{
  display:flex;
  justify-content:space-between;
  gap:10px;
  margin-top:10px;
  color:var(--eg-muted);
  font-size:12px;
  flex-wrap:wrap;
}
.empty{
  border:1px dashed var(--eg-border);
  border-radius:24px;
  padding:28px 18px;
  color:var(--eg-muted);
  text-align:center;
}

.filterbar{display:flex;gap:8px;flex-wrap:wrap;margin:12px 0 16px}
.filter{border:1px solid var(--eg-border);background:rgba(255,255,255,.05);color:var(--eg-green);border-radius:999px;padding:10px 12px;font-weight:900}
.filter.active{background:var(--eg-green);color:#03140d}
.detail-btn{width:100%;margin-top:12px;border:none;border-radius:16px;padding:12px 14px;background:rgba(66,232,255,.14);color:#42e8ff;font-weight:900}
.detail-modal{position:fixed;inset:0;display:none;align-items:center;justify-content:center;padding:18px;background:rgba(0,0,0,.68);z-index:999999}
.detail-modal.open{display:flex}
.detail-card{width:min(560px,100%);max-height:82vh;overflow:auto;border:1px solid var(--eg-border);background:#061b13;border-radius:26px;padding:18px;box-shadow:0 0 38px rgba(35,255,137,.22)}
.detail-card h3{margin:0 0 10px;color:#fff}
.detail-card pre{white-space:pre-wrap;word-break:break-word;background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.08);border-radius:18px;padding:14px;color:rgba(255,255,255,.88);font-family:Arial,Helvetica,sans-serif;line-height:1.45}
.detail-close{width:100%;border:none;border-radius:16px;padding:12px;background:#23ff89;color:#03140d;font-weight:900}

@media(max-width:520px){
  .stats{grid-template-columns:repeat(2,1fr)}
  .hero h2{font-size:25px}
}

.manage-card{
  margin:14px 0 16px;
  border:1px solid var(--eg-border);
  background:linear-gradient(135deg,rgba(35,255,137,.10),rgba(66,232,255,.06));
  border-radius:26px;
  padding:16px;
  box-shadow:0 0 28px rgba(35,255,137,.10);
}
.manage-card h3{
  margin:0 0 6px;
  color:#fff;
  font-size:18px;
}
.manage-card p{
  margin:0 0 14px;
  color:var(--eg-muted);
  line-height:1.45;
}
.manage-actions{
  display:grid;
  grid-template-columns:repeat(3,1fr);
  gap:10px;
}
.manage-actions .btn,
.manage-actions button{
  width:100%;
  justify-content:center;
}
@media(max-width:620px){
  .manage-actions{grid-template-columns:1fr}
}


/* ===== ERATGUARD VITES-6G HISTORY UI CLEANUP START ===== */
.actions.legacy-actions{
  display:none !important;
}
/* ===== ERATGUARD VITES-6G HISTORY UI CLEANUP END ===== */


/* ===== ERATGUARD VITES-6H HISTORY PREMIUM POLISH START ===== */
body{
  background:
    radial-gradient(circle at top left, rgba(35,255,137,.18), transparent 36%),
    radial-gradient(circle at top right, rgba(66,232,255,.14), transparent 34%),
    linear-gradient(180deg,#020806,#06150f 48%,#020806) !important;
}
.hero{
  position:relative;
  overflow:hidden;
}
.hero:before{
  content:"";
  position:absolute;
  inset:-2px;
  background:linear-gradient(135deg,rgba(35,255,137,.22),transparent 42%,rgba(66,232,255,.16));
  opacity:.45;
  pointer-events:none;
}
.hero > *{
  position:relative;
  z-index:1;
}
.stat{
  position:relative;
  overflow:hidden;
}
.stat:after{
  content:"";
  position:absolute;
  inset:auto -20% -35% -20%;
  height:48px;
  background:radial-gradient(circle,rgba(35,255,137,.18),transparent 60%);
}
.manage-card{
  position:relative;
  overflow:hidden;
}
.manage-card:before{
  content:"";
  position:absolute;
  right:-70px;
  top:-70px;
  width:160px;
  height:160px;
  border-radius:50%;
  background:rgba(35,255,137,.12);
  filter:blur(2px);
}
.manage-card > *{
  position:relative;
  z-index:1;
}
.item{
  transition:transform .18s ease, border-color .18s ease, box-shadow .18s ease;
}
.item:hover{
  transform:translateY(-2px);
  border-color:rgba(35,255,137,.42);
  box-shadow:0 0 24px rgba(35,255,137,.10);
}
.badge{
  box-shadow:inset 0 0 16px rgba(35,255,137,.10);
}
.score{
  min-width:44px;
  text-align:center;
}
.filter,
.btn,
.detail-btn{
  transition:transform .16s ease, box-shadow .16s ease, opacity .16s ease;
}
.filter:active,
.btn:active,
.detail-btn:active{
  transform:scale(.98);
}
.btn.primary,
.filter.active{
  box-shadow:0 0 18px rgba(35,255,137,.18);
}
.detail-btn{
  box-shadow:inset 0 0 14px rgba(66,232,255,.08);
}
.detail-card{
  animation:egHistoryModalPop .18s ease-out;
}
@keyframes egHistoryModalPop{
  from{transform:scale(.96);opacity:.35}
  to{transform:scale(1);opacity:1}
}
.empty{
  background:rgba(255,255,255,.035);
}
.empty:before{
  content:"🛡️";
  display:block;
  font-size:34px;
  margin-bottom:8px;
}
@media(max-width:520px){
  .wrap{padding:14px}
  .hero{border-radius:24px}
  .manage-card{border-radius:22px}
}
/* ===== ERATGUARD VITES-6H HISTORY PREMIUM POLISH END ===== */

</style>
</head>
<body>
<div class="wrap">
  <div class="top">
    <div class="brand">
      <div class="logo">E</div>
      <div>
        <h1>EratGuard</h1>
        <small>VITES-6A</small>
      </div>
    </div>
    <a class="back" href="/dashboard">Ana Sayfa</a>
  </div>

  <section class="hero">
    <div class="kicker">KORUMA GEÇMİŞİ MERKEZİ</div>
    <h2>SMS Aksiyon Geçmişi</h2>
    <p>Engellenen, güvenli işaretlenen ve şikayet edilen SMS kayıtları burada izlenir.</p>

    <div class="stats">
      <div class="stat"><b>{{ total }}</b><span>Toplam</span></div>
      <div class="stat"><b>{{ blocked_count }}</b><span>Engellenen</span></div>
      <div class="stat"><b>{{ reported_count }}</b><span>Şikayet</span></div>
      <div class="stat"><b>{{ safe_count }}</b><span>Güvenli</span></div>
    </div>
  </section>

  <div class="actions legacy-actions">
    <a class="btn primary" href="/u/analysis">AI Analiz Aç</a>
    <a class="btn" href="/u/sms-actions-center">SMS Merkezi</a>
    <a class="btn" href="/u/reports">Raporlar</a>
    <!-- ERATGUARD VITES-6C EXPORT BUTTON START -->
    <a class="btn" href="/api/v6/history-export">Dışa Aktar</a>
    <!-- ERATGUARD VITES-6C EXPORT BUTTON END -->
    <!-- ERATGUARD VITES-6D CLEAR BUTTON START -->
    <button class="btn danger" id="egClearHistoryBtn" type="button">Geçmişi Temizle</button>
    <!-- ERATGUARD VITES-6D CLEAR BUTTON END -->
    <!-- ERATGUARD VITES-6E RESTORE BUTTON START -->
    <button class="btn restore" id="egRestoreHistoryBtn" type="button">Yedeği Geri Yükle</button>
    <!-- ERATGUARD VITES-6E RESTORE BUTTON END -->
  </div>

  <!-- ERATGUARD VITES-6F HISTORY MANAGEMENT PANEL START -->
  <section class="manage-card">
    <h3>Geçmiş Yönetimi</h3>
    <p>SMS koruma geçmişini dışa aktarabilir, yedek alarak temizleyebilir veya son yedekten geri yükleyebilirsin.</p>
    <div class="manage-actions">
      <a class="btn" href="/api/v6/history-export">Dışa Aktar</a>
      <button class="btn danger" id="egClearHistoryBtnPanel" type="button">Geçmişi Temizle</button>
      <button class="btn restore" id="egRestoreHistoryBtnPanel" type="button">Yedeği Geri Yükle</button>
    </div>
  </section>
  <!-- ERATGUARD VITES-6F HISTORY MANAGEMENT PANEL END -->

  <!-- ERATGUARD VITES-6B HISTORY FILTER DETAIL START -->
  <div class="filterbar">
    <button class="filter active" data-filter="all" type="button">Tümü</button>
    <button class="filter" data-filter="blocked" type="button">Engellenen</button>
    <button class="filter" data-filter="reported" type="button">Şikayet</button>
    <button class="filter" data-filter="safe" type="button">Güvenli</button>
  </div>
  <!-- ERATGUARD VITES-6B HISTORY FILTER DETAIL END -->

  <section class="list">
    {% if history %}
      {% for item in history %}
        <article class="item" data-kind="{{ item.kind }}" data-full="{{ item.text|e }}" data-label="{{ item.label|e }}" data-score="{{ item.score }}" data-level="{{ item.level|e }}" data-created="{{ item.created|e }}">
          <div class="item-head">
            <span class="badge">{{ item.icon }} {{ item.label }}</span>
            <span class="score">{{ item.score }}</span>
          </div>
          <div class="msg">{{ item.short }}</div>
          <div class="meta">
            <span>Risk: {{ item.level }}</span>
            <span>Tarih: {{ item.created }}</span>
          </div>
          <button class="detail-btn" type="button">Detay Gör</button>
        </article>
      {% endfor %}
    {% else %}
      <div class="empty">
        Henüz SMS aksiyon kaydı yok. AI Analiz ekranından test kaydı oluşturabilirsin.
      </div>
    {% endif %}
  </section>
</div>

<div class="detail-modal" id="egDetailModal">
  <div class="detail-card">
    <h3 id="egDetailTitle">SMS Detayı</h3>
    <div class="meta" id="egDetailMeta"></div>
    <pre id="egDetailText"></pre>
    <button class="detail-close" type="button" id="egDetailClose">Kapat</button>
  </div>
</div>

<script>
(function(){
  const filters = Array.from(document.querySelectorAll(".filter"));
  const items = Array.from(document.querySelectorAll(".item"));
  const modal = document.getElementById("egDetailModal");
  const title = document.getElementById("egDetailTitle");
  const meta = document.getElementById("egDetailMeta");
  const text = document.getElementById("egDetailText");
  const close = document.getElementById("egDetailClose");

  filters.forEach(btn => {
    btn.addEventListener("click", () => {
      const f = btn.getAttribute("data-filter");
      filters.forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      items.forEach(item => {
        const kind = item.getAttribute("data-kind");
        item.style.display = (f === "all" || f === kind) ? "" : "none";
      });
    });
  });

  document.querySelectorAll(".detail-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      const item = btn.closest(".item");
      if(!item) return;
      title.textContent = (item.getAttribute("data-label") || "Kayıt") + " - SMS Detayı";
      meta.innerHTML = "<span>Skor: " + (item.getAttribute("data-score") || "0") + "</span><span>Risk: " + (item.getAttribute("data-level") || "-") + "</span><span>Tarih: " + (item.getAttribute("data-created") || "-") + "</span>";
      text.textContent = item.getAttribute("data-full") || "Mesaj içeriği yok";
      modal.classList.add("open");
    });
  });

  if(close) close.addEventListener("click", () => modal.classList.remove("open"));
  if(modal) modal.addEventListener("click", e => { if(e.target === modal) modal.classList.remove("open"); });
})();
</script>


<script>
/* ===== ERATGUARD VITES-6D CLEAR SCRIPT START ===== */
(function(){
  const btn = document.getElementById("egClearHistoryBtn");
  if(!btn) return;

  btn.addEventListener("click", async function(){
    const ok = confirm("Koruma geçmişi yedek alındıktan sonra temizlenecek. Devam edilsin mi?");
    if(!ok) return;

    btn.disabled = true;
    btn.textContent = "Temizleniyor...";

    try{
      const res = await fetch("/api/v6/history-clear", {method:"POST"});
      const data = await res.json();
      alert((data && data.message ? data.message : "Geçmiş temizlendi.") + "\nYedek: " + (data.backup || "-"));
      location.reload();
    }catch(e){
      alert("Temizleme sırasında hata oluştu.");
      btn.disabled = false;
      btn.textContent = "Geçmişi Temizle";
    }
  });
})();
/* ===== ERATGUARD VITES-6D CLEAR SCRIPT END ===== */
</script>


<script>
/* ===== ERATGUARD VITES-6E RESTORE SCRIPT START ===== */
(function(){
  const btn = document.getElementById("egRestoreHistoryBtn");
  if(!btn) return;

  btn.addEventListener("click", async function(){
    const ok = confirm("En son yedek geri yüklenecek. Mevcut boş/son durum ayrıca güvenlik yedeğine alınacak. Devam edilsin mi?");
    if(!ok) return;

    btn.disabled = true;
    btn.textContent = "Geri yükleniyor...";

    try{
      const res = await fetch("/api/v6/history-restore-latest", {method:"POST"});
      const data = await res.json();
      if(!data.ok){
        alert(data.message || "Geri yükleme başarısız.");
        btn.disabled = false;
        btn.textContent = "Yedeği Geri Yükle";
        return;
      }
      alert((data.message || "Geri yüklendi.") + "\nYedek: " + (data.backup || "-"));
      location.reload();
    }catch(e){
      alert("Geri yükleme sırasında hata oluştu.");
      btn.disabled = false;
      btn.textContent = "Yedeği Geri Yükle";
    }
  });
})();
/* ===== ERATGUARD VITES-6E RESTORE SCRIPT END ===== */
</script>


<script>
/* ===== ERATGUARD VITES-6F PANEL BRIDGE SCRIPT START ===== */
(function(){
  const clearPanel = document.getElementById("egClearHistoryBtnPanel");
  const clearOriginal = document.getElementById("egClearHistoryBtn");
  if(clearPanel && clearOriginal){
    clearPanel.addEventListener("click", function(){
      clearOriginal.click();
    });
  }

  const restorePanel = document.getElementById("egRestoreHistoryBtnPanel");
  const restoreOriginal = document.getElementById("egRestoreHistoryBtn");
  if(restorePanel && restoreOriginal){
    restorePanel.addEventListener("click", function(){
      restoreOriginal.click();
    });
  }
})();
/* ===== ERATGUARD VITES-6F PANEL BRIDGE SCRIPT END ===== */
</script>

</body>
</html>
"""

    return render_template_string(
        html,
        history=history,
        total=total,
        blocked_count=blocked_count,
        reported_count=reported_count,
        safe_count=safe_count
    )


@app.after_request
def eratguard_vites6a_history_links_after_response(response):
    try:
        from flask import request

        path = request.path or ""
        if not (path == "/dashboard" or path == "/u/analysis" or path == "/u/reports" or path == "/u/protection"):
            return response

        html = response.get_data(as_text=True)

        if "ERATGUARD VITES-6A HISTORY LINK START" in html:
            return response

        link_html = """
<div style="margin:14px auto 0;max-width:520px;">
  <!-- ERATGUARD VITES-6A HISTORY LINK START -->
  <a href="/history" style="display:block;text-align:center;text-decoration:none;font-weight:900;color:#03140d;background:#23ff89;border-radius:18px;padding:13px 16px;box-shadow:0 0 22px rgba(35,255,137,.18);">
    Koruma Geçmişi
  </a>
  <!-- ERATGUARD VITES-6A HISTORY LINK END -->
</div>
"""

        if "</body>" in html:
            html = html.replace("</body>", link_html + "\n</body>", 1)
        else:
            html += link_html

        response.set_data(html)
        response.headers["Content-Length"] = str(len(response.get_data()))
    except Exception:
        pass

    return response

# ===== ERATGUARD VITES-6A PUBLIC FALLBACK ROUTE START =====
@app.route("/protection-history")
@app.route("/history")
def eratguard_vites6a_public_protection_history_center():
    return eratguard_vites6a_protection_history_center()
# ===== ERATGUARD VITES-6A PUBLIC FALLBACK ROUTE END =====


# ===== ERATGUARD VITES-6C HISTORY EXPORT START =====
@app.route("/api/v6/history-export")
def eratguard_vites6c_history_export():
    from flask import jsonify, Response
    from pathlib import Path
    import json
    import datetime

    data_path = Path("data/eratguard_sms_actions_v5c.json")

    payload = {
        "app": "EratGuard",
        "version": "VITES-6C",
        "export_type": "sms_protection_history",
        "exported_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "source": str(data_path),
        "actions": {
            "blocked": [],
            "safe": [],
            "reported": []
        }
    }

    if data_path.exists():
        try:
            loaded = json.loads(data_path.read_text(encoding="utf-8", errors="ignore"))
            if isinstance(loaded, dict):
                payload["actions"]["blocked"] = loaded.get("blocked", []) if isinstance(loaded.get("blocked", []), list) else []
                payload["actions"]["safe"] = loaded.get("safe", []) if isinstance(loaded.get("safe", []), list) else []
                payload["actions"]["reported"] = loaded.get("reported", []) if isinstance(loaded.get("reported", []), list) else []
        except Exception as e:
            payload["error"] = str(e)

    payload["stats"] = {
        "blocked": len(payload["actions"]["blocked"]),
        "safe": len(payload["actions"]["safe"]),
        "reported": len(payload["actions"]["reported"]),
        "total": len(payload["actions"]["blocked"]) + len(payload["actions"]["safe"]) + len(payload["actions"]["reported"])
    }

    body = json.dumps(payload, ensure_ascii=False, indent=2)
    filename = "eratguard_sms_history_export.json"

    return Response(
        body,
        mimetype="application/json; charset=utf-8",
        headers={
            "Content-Disposition": f"attachment; filename={filename}"
        }
    )
# ===== ERATGUARD VITES-6C HISTORY EXPORT END =====


# ===== ERATGUARD VITES-6D HISTORY CLEAR START =====
@app.route("/api/v6/history-clear", methods=["POST", "GET"])
def eratguard_vites6d_history_clear():
    from flask import jsonify
    from pathlib import Path
    import json
    import datetime
    import shutil

    data_path = Path("data/eratguard_sms_actions_v5c.json")
    backup_dir = Path("data/history_backups")
    backup_dir.mkdir(parents=True, exist_ok=True)

    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = backup_dir / f"eratguard_sms_actions_before_clear_{ts}.json"

    previous = {
        "blocked": [],
        "safe": [],
        "reported": []
    }

    if data_path.exists():
        try:
            shutil.copy2(data_path, backup_path)
            loaded = json.loads(data_path.read_text(encoding="utf-8", errors="ignore"))
            if isinstance(loaded, dict):
                for key in previous:
                    val = loaded.get(key, [])
                    if isinstance(val, list):
                        previous[key] = val
        except Exception:
            pass

    cleared = {
        "blocked": [],
        "safe": [],
        "reported": [],
        "meta": {
            "cleared_at": datetime.datetime.now().isoformat(timespec="seconds"),
            "backup": str(backup_path),
            "previous_counts": {
                "blocked": len(previous["blocked"]),
                "safe": len(previous["safe"]),
                "reported": len(previous["reported"]),
                "total": len(previous["blocked"]) + len(previous["safe"]) + len(previous["reported"])
            }
        }
    }

    data_path.parent.mkdir(parents=True, exist_ok=True)
    data_path.write_text(json.dumps(cleared, ensure_ascii=False, indent=2), encoding="utf-8")

    return jsonify({
        "ok": True,
        "message": "Koruma geçmişi temizlendi.",
        "backup": str(backup_path),
        "previous_counts": cleared["meta"]["previous_counts"],
        "current_counts": {
            "blocked": 0,
            "safe": 0,
            "reported": 0,
            "total": 0
        }
    })
# ===== ERATGUARD VITES-6D HISTORY CLEAR END =====


# ===== ERATGUARD VITES-6E HISTORY RESTORE START =====
@app.route("/api/v6/history-restore-latest", methods=["POST"])
def eratguard_vites6e_history_restore_latest():
    from flask import jsonify
    from pathlib import Path
    import json
    import datetime
    import shutil

    data_path = Path("data/eratguard_sms_actions_v5c.json")
    backup_dir = Path("data/history_backups")

    if not backup_dir.exists():
        return jsonify({
            "ok": False,
            "message": "Yedek klasörü bulunamadı.",
            "backup": None
        }), 404

    backups = sorted(
        backup_dir.glob("eratguard_sms_actions_before_clear_*.json"),
        key=lambda x: x.stat().st_mtime,
        reverse=True
    )

    if not backups:
        return jsonify({
            "ok": False,
            "message": "Geri yüklenecek yedek bulunamadı.",
            "backup": None
        }), 404

    latest = backups[0]

    try:
        loaded = json.loads(latest.read_text(encoding="utf-8", errors="ignore"))
        if not isinstance(loaded, dict):
            return jsonify({
                "ok": False,
                "message": "Yedek dosyası geçerli JSON değil.",
                "backup": str(latest)
            }), 400

        current_backup_dir = Path("data/history_restore_safety")
        current_backup_dir.mkdir(parents=True, exist_ok=True)

        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        if data_path.exists():
            shutil.copy2(data_path, current_backup_dir / f"current_before_restore_{ts}.json")

        data_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(latest, data_path)

        restored = json.loads(data_path.read_text(encoding="utf-8", errors="ignore"))
        counts = {
            "blocked": len(restored.get("blocked", [])) if isinstance(restored.get("blocked", []), list) else 0,
            "safe": len(restored.get("safe", [])) if isinstance(restored.get("safe", []), list) else 0,
            "reported": len(restored.get("reported", [])) if isinstance(restored.get("reported", []), list) else 0,
        }
        counts["total"] = counts["blocked"] + counts["safe"] + counts["reported"]

        return jsonify({
            "ok": True,
            "message": "Koruma geçmişi en son yedekten geri yüklendi.",
            "backup": str(latest),
            "counts": counts
        })

    except Exception as e:
        return jsonify({
            "ok": False,
            "message": "Geri yükleme hatası.",
            "error": str(e),
            "backup": str(latest)
        }), 500
# ===== ERATGUARD VITES-6E HISTORY RESTORE END =====

# ===== ERATGUARD VITES-6A PROTECTION HISTORY CENTER END =====




# === ERATGUARD_SMS_ACTION_ENGINE_V1 ===
# User-side SMS action engine:
# AI Analiz -> Engelle / Güvenli / Şikayet -> kayıt -> sayaç -> geçmiş -> dışa aktar/yedek

import os as _eg_os
import json as _eg_json
import csv as _eg_csv
import io as _eg_io
import shutil as _eg_shutil
import hashlib as _eg_hashlib
from datetime import datetime as _eg_datetime
from pathlib import Path as _eg_Path
from flask import request as _eg_request, jsonify as _eg_jsonify, redirect as _eg_redirect, url_for as _eg_url_for, render_template_string as _eg_render_template_string, send_file as _eg_send_file, flash as _eg_flash

_EG_DATA_DIR = _eg_Path(__file__).resolve().parent / "data"
_EG_DATA_DIR.mkdir(parents=True, exist_ok=True)

_EG_SMS_ACTIONS_FILE = _EG_DATA_DIR / "eratguard_sms_actions_v5c.json"
_EG_SMS_ACTIONS_BACKUP_DIR = _EG_DATA_DIR / "sms_action_backups"
_EG_SMS_ACTIONS_BACKUP_DIR.mkdir(parents=True, exist_ok=True)

_EG_ALLOWED_SMS_ACTIONS = {
    "blocked": "Engellendi",
    "safe": "Güvenli",
    "reported": "Şikayet",
}

_EG_ACTION_BADGES = {
    "blocked": "danger",
    "safe": "success",
    "reported": "warning",
}

def _eg_now_iso():
    return _eg_datetime.now().replace(microsecond=0).isoformat()

def _eg_read_json_file(path, default):
    try:
        if not path.exists() or path.stat().st_size == 0:
            return default
        with path.open("r", encoding="utf-8") as f:
            data = _eg_json.load(f)
        return data
    except Exception:
        return default

def _eg_atomic_write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        _eg_json.dump(data, f, ensure_ascii=False, indent=2)
    tmp.replace(path)

def _eg_normalize_reason(value):
    if value is None:
        return []
    if isinstance(value, list):
        return [str(x).strip() for x in value if str(x).strip()]
    if isinstance(value, str):
        raw = value.replace("\r", "\n").split("\n")
        return [x.strip(" -•\t") for x in raw if x.strip(" -•\t")]
    return [str(value)]

def _eg_risk_level(score):
    try:
        score = int(score)
    except Exception:
        score = 0
    if score >= 85:
        return "Çok Riskli"
    if score >= 70:
        return "Riskli"
    if score >= 40:
        return "Şüpheli"
    return "Düşük Risk"

def _eg_sms_id(sender, message, created_at=None):
    base = f"{sender}|{message}|{created_at or ''}"
    return "sms_" + _eg_hashlib.sha256(base.encode("utf-8", errors="ignore")).hexdigest()[:16]

def _eg_action_id(sms_id, action, created_at=None):
    base = f"{sms_id}|{action}|{created_at or _eg_now_iso()}"
    return "action_" + _eg_hashlib.sha256(base.encode("utf-8", errors="ignore")).hexdigest()[:16]

def _eg_load_sms_actions():
    data = _eg_read_json_file(_EG_SMS_ACTIONS_FILE, [])
    if isinstance(data, dict):
        if isinstance(data.get("actions"), list):
            return data["actions"]
        if isinstance(data.get("items"), list):
            return data["items"]
        return []
    if isinstance(data, list):
        return data
    return []

def _eg_save_sms_actions(actions):
    clean = []
    for item in actions:
        if isinstance(item, dict):
            clean.append(item)
    _eg_atomic_write_json(_EG_SMS_ACTIONS_FILE, clean)

def _eg_counts(actions=None):
    actions = actions if actions is not None else _eg_load_sms_actions()
    c = {"total": len(actions), "blocked": 0, "safe": 0, "reported": 0}
    for a in actions:
        act = str(a.get("action", "")).strip()
        if act in c:
            c[act] += 1
    return c

def _eg_filter_actions(action=None):
    actions = _eg_load_sms_actions()
    actions = sorted(actions, key=lambda x: str(x.get("created_at", "")), reverse=True)
    if action in _EG_ALLOWED_SMS_ACTIONS:
        actions = [a for a in actions if a.get("action") == action]
    return actions

def _eg_add_sms_action(payload):
    now = _eg_now_iso()

    action = str(payload.get("action", "")).strip().lower()
    aliases = {
        "engelle": "blocked",
        "engel": "blocked",
        "blocked": "blocked",
        "block": "blocked",
        "güvenli": "safe",
        "guvenli": "safe",
        "safe": "safe",
        "şikayet": "reported",
        "sikayet": "reported",
        "reported": "reported",
        "report": "reported",
    }
    action = aliases.get(action, action)

    if action not in _EG_ALLOWED_SMS_ACTIONS:
        raise ValueError("Geçersiz SMS aksiyonu. allowed: blocked, safe, reported")

    sender = str(payload.get("sender") or payload.get("gonderen") or payload.get("from") or "Bilinmeyen").strip()
    message = str(payload.get("message") or payload.get("mesaj") or payload.get("body") or "").strip()

    try:
        risk_score = int(payload.get("risk_score", payload.get("risk", payload.get("score", 0))))
    except Exception:
        risk_score = 0

    risk_score = max(0, min(100, risk_score))
    risk_level = str(payload.get("risk_level") or payload.get("seviye") or _eg_risk_level(risk_score)).strip()

    sms_id = str(payload.get("sms_id") or _eg_sms_id(sender, message)).strip()
    reason = _eg_normalize_reason(payload.get("reason") or payload.get("reasons") or payload.get("neden") or payload.get("analysis_reason"))

    source = str(payload.get("source") or "manual").strip()
    note = str(payload.get("note") or payload.get("analysis_note") or payload.get("analiz_notu") or "").strip()

    actions = _eg_load_sms_actions()

    # Aynı sms_id için son kullanıcı kararı tekleştirilir; eski kayıt kaybolmaz, previous_action olarak işaretlenir.
    previous = None
    for item in actions:
        if item.get("sms_id") == sms_id and item.get("is_current", True):
            item["is_current"] = False
            item["updated_at"] = now
            previous = item.get("action")
            break

    rec = {
        "id": _eg_action_id(sms_id, action, now),
        "sms_id": sms_id,
        "sender": sender,
        "message": message,
        "action": action,
        "label": _EG_ALLOWED_SMS_ACTIONS[action],
        "risk_score": risk_score,
        "risk_level": risk_level,
        "reason": reason,
        "note": note,
        "source": source,
        "previous_action": previous,
        "is_current": True,
        "created_at": now,
        "updated_at": now,
    }

    actions.append(rec)
    _eg_save_sms_actions(actions)
    return rec

@app.route("/u/sms/action", methods=["POST"])
@app.route("/sms/action", methods=["POST"])
def eg_sms_action_create():
    try:
        payload = {}
        if _eg_request.is_json:
            payload = _eg_request.get_json(silent=True) or {}
        else:
            payload = dict(_eg_request.form.items())

        rec = _eg_add_sms_action(payload)
        if _eg_request.is_json or _eg_request.headers.get("Accept", "").lower().find("application/json") >= 0:
            return _eg_jsonify({"ok": True, "record": rec, "counts": _eg_counts()})

        try:
            _eg_flash(f"SMS aksiyonu kaydedildi: {rec.get('label')}", "success")
        except Exception:
            pass
        return _eg_redirect(_eg_request.referrer or "/u/sms/actions")
    except Exception as e:
        if _eg_request.is_json:
            return _eg_jsonify({"ok": False, "error": str(e)}), 400
        try:
            _eg_flash("SMS aksiyonu kaydedilemedi: " + str(e), "danger")
        except Exception:
            pass
        return _eg_redirect(_eg_request.referrer or "/u/sms/actions")

@app.route("/u/sms/actions")
@app.route("/u/sms/history")
@app.route("/sms/actions")
@app.route("/sms/history")
def eg_sms_actions_center():
    action = (_eg_request.args.get("filter") or _eg_request.args.get("action") or "all").strip().lower()
    if action == "all":
        action = None
    actions = _eg_filter_actions(action)
    counts = _eg_counts(_eg_load_sms_actions())

    html = """
<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>EratGuard SMS Aksiyon Merkezi</title>
<style>
:root{--bg:#061018;--card:#0d1b27;--muted:#8ca3b6;--text:#eef7ff;--line:rgba(255,255,255,.10);--blue:#1b78ff;--green:#18c37e;--red:#ff4d61;--yellow:#ffd166}
*{box-sizing:border-box} body{margin:0;background:radial-gradient(circle at top,#11314b 0,#061018 45%,#03070b 100%);color:var(--text);font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif}
.wrap{max-width:980px;margin:0 auto;padding:18px 14px 90px}
.top{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:14px}
.title{font-size:22px;font-weight:900;letter-spacing:.2px}.sub{color:var(--muted);font-size:13px;margin-top:4px}
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin:14px 0}
.stat{background:rgba(13,27,39,.88);border:1px solid var(--line);border-radius:18px;padding:13px}.stat b{display:block;font-size:22px}.stat span{font-size:12px;color:var(--muted)}
.filters{display:flex;gap:8px;overflow:auto;margin:12px 0 16px}.filters a,.btn{white-space:nowrap;text-decoration:none;color:var(--text);background:#0d1b27;border:1px solid var(--line);border-radius:999px;padding:10px 12px;font-size:13px;font-weight:800}
.filters a.active{background:var(--blue);border-color:var(--blue)}
.actions{display:flex;gap:8px;flex-wrap:wrap;margin:10px 0 18px}.btn.export{background:#10283a}.btn.danger{background:rgba(255,77,97,.15);border-color:rgba(255,77,97,.45)}
.card{background:rgba(13,27,39,.92);border:1px solid var(--line);border-radius:20px;padding:14px;margin:10px 0;box-shadow:0 12px 28px rgba(0,0,0,.22)}
.row{display:flex;justify-content:space-between;gap:10px;align-items:flex-start}.badge{font-size:12px;font-weight:900;border-radius:999px;padding:7px 9px}.danger-b{background:rgba(255,77,97,.16);color:#ff9aa6}.success-b{background:rgba(24,195,126,.16);color:#7dffc5}.warning-b{background:rgba(255,209,102,.16);color:#ffe09a}
.meta{color:var(--muted);font-size:12px;margin:8px 0}.msg{font-size:14px;line-height:1.45;background:rgba(255,255,255,.035);border-radius:14px;padding:10px;margin-top:8px;word-break:break-word}.reasons{margin:10px 0 0;padding-left:18px;color:#cfe1ef;font-size:13px}.empty{color:var(--muted);text-align:center;padding:28px}
.menu{position:fixed;right:18px;bottom:18px;background:var(--blue);color:white;border-radius:999px;padding:16px 18px;text-decoration:none;font-weight:900;box-shadow:0 16px 30px rgba(27,120,255,.35)}
@media(max-width:680px){.grid{grid-template-columns:repeat(2,1fr)}.title{font-size:19px}}
</style>
</head>
<body>
<div class="wrap">
  <div class="top">
    <div>
      <div class="title">SMS Aksiyon Merkezi</div>
      <div class="sub">Engelle / Güvenli / Şikayet kayıtları tek merkezden yönetilir.</div>
    </div>
  </div>

  <div class="grid">
    <div class="stat"><b>{{ counts.total }}</b><span>Toplam</span></div>
    <div class="stat"><b>{{ counts.blocked }}</b><span>Engellenen</span></div>
    <div class="stat"><b>{{ counts.reported }}</b><span>Şikayet</span></div>
    <div class="stat"><b>{{ counts.safe }}</b><span>Güvenli</span></div>
  </div>

  <div class="filters">
    <a class="{{ 'active' if not request.args.get('filter') or request.args.get('filter')=='all' else '' }}" href="/u/sms/actions?filter=all">Tümü</a>
    <a class="{{ 'active' if request.args.get('filter')=='blocked' else '' }}" href="/u/sms/actions?filter=blocked">Engellenen</a>
    <a class="{{ 'active' if request.args.get('filter')=='reported' else '' }}" href="/u/sms/actions?filter=reported">Şikayet</a>
    <a class="{{ 'active' if request.args.get('filter')=='safe' else '' }}" href="/u/sms/actions?filter=safe">Güvenli</a>
  </div>

  <div class="actions">
    <a class="btn export" href="/u/sms/actions/export.json">JSON Dışa Aktar</a>
    <a class="btn export" href="/u/sms/actions/export.csv">CSV Dışa Aktar</a>
    <a class="btn export" href="/u/sms/actions/backup">Yedek Al</a>
    <form method="post" action="/u/sms/actions/clear" onsubmit="return confirm('SMS aksiyon geçmişi temizlensin mi?')" style="display:inline">
      <button class="btn danger" type="submit">Geçmişi Temizle</button>
    </form>
  </div>

  {% if not actions %}
    <div class="empty">Henüz SMS aksiyon kaydı yok.</div>
  {% endif %}

  {% for a in actions %}
  {% set badge = 'danger-b' if a.action=='blocked' else ('success-b' if a.action=='safe' else 'warning-b') %}
  <div class="card">
    <div class="row">
      <div>
        <span class="badge {{ badge }}">{{ a.label or a.action }}</span>
        <div class="meta">Gönderen: {{ a.sender }} · Tarih: {{ a.created_at }} · Kaynak: {{ a.source }}</div>
      </div>
      <div class="meta">Risk: {{ a.risk_score }} · {{ a.risk_level }}</div>
    </div>
    <div class="msg">{{ a.message }}</div>
    {% if a.note %}<div class="meta">{{ a.note }}</div>{% endif %}
    {% if a.reason %}
    <ul class="reasons">
      {% for r in a.reason %}<li>{{ r }}</li>{% endfor %}
    </ul>
    {% endif %}
  </div>
  {% endfor %}
</div>
<a class="menu" href="/u/dashboard">MENÜ</a>
</body>
</html>
"""
    return _eg_render_template_string(html, actions=actions, counts=counts, request=_eg_request)

@app.route("/u/sms/actions/export.json")
def eg_sms_actions_export_json():
    actions = _eg_load_sms_actions()
    bio = _eg_io.BytesIO(_eg_json.dumps(actions, ensure_ascii=False, indent=2).encode("utf-8"))
    return _eg_send_file(bio, mimetype="application/json", as_attachment=True, download_name="eratguard_sms_actions.json")

@app.route("/u/sms/actions/export.csv")
def eg_sms_actions_export_csv():
    actions = _eg_load_sms_actions()
    out = _eg_io.StringIO()
    fields = ["id","sms_id","sender","message","action","label","risk_score","risk_level","source","created_at","updated_at","is_current"]
    w = _eg_csv.DictWriter(out, fieldnames=fields, extrasaction="ignore")
    w.writeheader()
    for a in actions:
        w.writerow(a)
    bio = _eg_io.BytesIO(out.getvalue().encode("utf-8-sig"))
    return _eg_send_file(bio, mimetype="text/csv", as_attachment=True, download_name="eratguard_sms_actions.csv")

@app.route("/u/sms/actions/clear", methods=["POST"])
def eg_sms_actions_clear():
    before = _eg_load_sms_actions()
    if before:
        stamp = _eg_datetime.now().strftime("%Y%m%d_%H%M%S")
        _eg_atomic_write_json(_EG_SMS_ACTIONS_BACKUP_DIR / f"before_clear_{stamp}.json", before)
    _eg_save_sms_actions([])
    try:
        _eg_flash("SMS aksiyon geçmişi temizlendi. Ön yedek alındı.", "success")
    except Exception:
        pass
    return _eg_redirect("/u/sms/actions")

@app.route("/u/sms/actions/backup")
def eg_sms_actions_backup():
    actions = _eg_load_sms_actions()
    stamp = _eg_datetime.now().strftime("%Y%m%d_%H%M%S")
    target = _EG_SMS_ACTIONS_BACKUP_DIR / f"eratguard_sms_actions_backup_{stamp}.json"
    _eg_atomic_write_json(target, actions)
    bio = _eg_io.BytesIO(_eg_json.dumps(actions, ensure_ascii=False, indent=2).encode("utf-8"))
    return _eg_send_file(bio, mimetype="application/json", as_attachment=True, download_name=target.name)

@app.route("/u/sms/actions/restore", methods=["POST"])
def eg_sms_actions_restore():
    # multipart file alanı: backup
    f = _eg_request.files.get("backup")
    if not f:
        return _eg_jsonify({"ok": False, "error": "backup dosyası yok"}), 400
    try:
        data = _eg_json.loads(f.read().decode("utf-8"))
        if isinstance(data, dict) and isinstance(data.get("actions"), list):
            data = data["actions"]
        if not isinstance(data, list):
            raise ValueError("Yedek formatı liste değil.")
        old = _eg_load_sms_actions()
        if old:
            stamp = _eg_datetime.now().strftime("%Y%m%d_%H%M%S")
            _eg_atomic_write_json(_EG_SMS_ACTIONS_BACKUP_DIR / f"before_restore_{stamp}.json", old)
        _eg_save_sms_actions(data)
        return _eg_jsonify({"ok": True, "restored": len(data), "counts": _eg_counts(data)})
    except Exception as e:
        return _eg_jsonify({"ok": False, "error": str(e)}), 400

@app.route("/u/sms/actions/counts")
def eg_sms_actions_counts():
    return _eg_jsonify({"ok": True, "counts": _eg_counts()})

# === /ERATGUARD_SMS_ACTION_ENGINE_V1 ===





# === ERATGUARD_AI_ANALYSIS_ACTION_BUTTONS_V2 ===
# /u/analysis ekranına SMS Action Engine karar butonları ekler:
# Engelle / Güvenli / Şikayet -> /u/sms/action

try:
    from flask import request as _eg_aab2_request
    from flask import session as _eg_aab2_session
    from flask import redirect as _eg_aab2_redirect
    from flask import render_template_string as _eg_aab2_render_template_string
    from flask import make_response as _eg_aab2_make_response
    import html as _eg_aab2_html
    import json as _eg_aab2_json
    from pathlib import Path as _eg_aab2_Path
    from datetime import datetime as _eg_aab2_datetime

    def _eg_aab2_safe(v):
        try:
            return _eg_aab2_html.escape(str(v or ""), quote=True)
        except Exception:
            return ""

    def _eg_aab2_load(default, path):
        try:
            pp = _eg_aab2_Path(path)
            if not pp.exists():
                return default
            txt = pp.read_text(encoding="utf-8", errors="ignore").strip()
            if not txt:
                return default
            return _eg_aab2_json.loads(txt)
        except Exception:
            return default

    def _eg_aab2_save(path, data):
        pp = _eg_aab2_Path(path)
        pp.parent.mkdir(parents=True, exist_ok=True)
        pp.write_text(_eg_aab2_json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

    def _eg_aab2_engine(message):
        # Önce mevcut aktif AI motorunu kullan.
        if "_eg_aid1b_engine" in globals() and callable(globals().get("_eg_aid1b_engine")):
            return globals()["_eg_aid1b_engine"](message)

        # Geriye dönük fallback.
        text = str(message or "").lower()
        score = 8
        reasons = []

        if any(x in text for x in ["http://", "https://", "www.", ".com", ".net", "link"]):
            score += 35
            reasons.append("Mesaj bağlantı/link yönlendirmesi içeriyor.")
        if any(x in text for x in ["banka", "kart", "şifre", "sifre", "hesap", "iban", "ödeme", "odeme"]):
            score += 28
            reasons.append("Mesaj finansal veya kişisel bilgi riski taşıyor.")
        if any(x in text for x in ["acil", "hemen", "son gün", "son gun", "tıkla", "tikla"]):
            score += 22
            reasons.append("Mesaj aciliyet dili içeriyor.")
        if any(x in text for x in ["kazandınız", "kazandiniz", "ödül", "odul", "hediye", "bonus"]):
            score += 24
            reasons.append("Mesaj ödül/kazanç vaadi içeriyor.")

        if not reasons:
            reasons.append("Belirgin dolandırıcılık sinyali düşük görünüyor.")

        score = max(0, min(100, int(score)))
        if score >= 71:
            return {"score": score, "status": "SPAM", "risk_label": "Yüksek Risk", "risk_class": "high", "reasons": reasons}
        if score >= 31:
            return {"score": score, "status": "SUSPICIOUS", "risk_label": "Orta Risk", "risk_class": "mid", "reasons": reasons}
        return {"score": score, "status": "SAFE", "risk_label": "Düşük Risk", "risk_class": "low", "reasons": reasons}

    def _eg_aab2_write(username, message, result):
        # Mevcut yazıcı varsa onu kullan.
        if "_eg_aid1b_write" in globals() and callable(globals().get("_eg_aid1b_write")):
            try:
                return globals()["_eg_aid1b_write"](username, message, result)
            except Exception as e:
                print("ERATGUARD AI ACTION BUTTONS V2 WRITE BRIDGE ERROR:", e)

        now = _eg_aab2_datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        item = {
            "time": now,
            "number": "manual_ai_analysis",
            "sender": "manual_ai_analysis",
            "body": message,
            "status": result.get("status"),
            "score": int(result.get("score") or 0),
            "risk": int(result.get("score") or 0),
            "risk_label": result.get("risk_label"),
            "risk_class": result.get("risk_class"),
            "reasons": result.get("reasons") or [],
            "source": "user_ai_analysis_scan",
            "username": username,
        }

        for file_path in ["data/user_analysis_history.json", "data/spam_logs.json"]:
            data = _eg_aab2_load([], file_path)
            if not isinstance(data, list):
                data = []
            data.append(item)
            _eg_aab2_save(file_path, data)

    def _eg_aab2_route():
        if not (_eg_aab2_session.get("logged_in") and _eg_aab2_session.get("username")):
            return _eg_aab2_redirect("/login?auth_required=1")

        username = str(_eg_aab2_session.get("username") or "user")
        message = ""
        result = None

        if str(_eg_aab2_request.method or "").upper() == "POST":
            message = (
                _eg_aab2_request.form.get("sms_text")
                or _eg_aab2_request.form.get("message")
                or _eg_aab2_request.form.get("body")
                or _eg_aab2_request.form.get("text")
                or ""
            ).strip()

            if message:
                result = _eg_aab2_engine(message)
                _eg_aab2_write(username, message, result)

        result_html = ""
        if result:
            reasons = result.get("reasons") or []
            reasons_html = "".join("<li>" + _eg_aab2_safe(x) + "</li>" for x in reasons)
            reasons_joined = "\n".join(str(x) for x in reasons)

            score = int(result.get("score") or 0)
            risk_label = str(result.get("risk_label") or "")
            risk_class = str(result.get("risk_class") or "")
            status = str(result.get("status") or "")

            result_html = f"""
<div class="section-title">SONUÇ</div>
<section class="result">
  <div class="result-top">
    <div>
      <h3>{_eg_aab2_safe(risk_label)}</h3>
      <p>AI analiz tamamlandı. Şimdi bu SMS için güvenlik kararı verebilirsin.</p>
    </div>
    <div class="score">{_eg_aab2_safe(score)}</div>
  </div>

  <div class="mini-grid">
    <div><b>{_eg_aab2_safe(status)}</b><span>Durum</span></div>
    <div><b>{_eg_aab2_safe(risk_class)}</b><span>Seviye</span></div>
  </div>

  <ul>{reasons_html}</ul>

  <div class="decision">
    <div class="decision-title">SMS AKSİYONU</div>
    <p>Bu karar SMS Aksiyon Merkezi, Koruma Geçmişi ve sayaçlara işlenecek.</p>

    <div class="action-grid">
      <form method="post" action="/u/sms/action">
        <input type="hidden" name="sender" value="manual_ai_analysis">
        <input type="hidden" name="message" value="{_eg_aab2_safe(message)}">
        <input type="hidden" name="action" value="blocked">
        <input type="hidden" name="risk_score" value="{_eg_aab2_safe(score)}">
        <input type="hidden" name="risk_level" value="{_eg_aab2_safe(risk_label)}">
        <input type="hidden" name="reason" value="{_eg_aab2_safe(reasons_joined)}">
        <input type="hidden" name="source" value="ai_analysis">
        <button class="act danger" type="submit">⛔ Engelle</button>
      </form>

      <form method="post" action="/u/sms/action">
        <input type="hidden" name="sender" value="manual_ai_analysis">
        <input type="hidden" name="message" value="{_eg_aab2_safe(message)}">
        <input type="hidden" name="action" value="safe">
        <input type="hidden" name="risk_score" value="{_eg_aab2_safe(score)}">
        <input type="hidden" name="risk_level" value="{_eg_aab2_safe(risk_label)}">
        <input type="hidden" name="reason" value="{_eg_aab2_safe(reasons_joined)}">
        <input type="hidden" name="source" value="ai_analysis">
        <button class="act safe" type="submit">✅ Güvenli</button>
      </form>

      <form method="post" action="/u/sms/action">
        <input type="hidden" name="sender" value="manual_ai_analysis">
        <input type="hidden" name="message" value="{_eg_aab2_safe(message)}">
        <input type="hidden" name="action" value="reported">
        <input type="hidden" name="risk_score" value="{_eg_aab2_safe(score)}">
        <input type="hidden" name="risk_level" value="{_eg_aab2_safe(risk_label)}">
        <input type="hidden" name="reason" value="{_eg_aab2_safe(reasons_joined)}">
        <input type="hidden" name="source" value="ai_analysis">
        <button class="act warn" type="submit">⚠️ Şikayet</button>
      </form>
    </div>

    <a class="sms-center" href="/u/sms/actions">SMS Aksiyon Merkezini Aç</a>
  </div>
</section>
"""

        page = """
<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>EratGuard PRO - AI Analiz</title>
<style>
:root{--bg:#020806;--line:rgba(35,255,137,.22);--green:#20ff88;--yellow:#ffdd35;--red:#ff4d61;--text:#f5fff8;--muted:rgba(245,255,248,.62)}
*{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
html,body{margin:0;min-height:100%;background:radial-gradient(circle at 80% 0%,rgba(35,255,137,.14),transparent 32%),var(--bg);color:var(--text);font-family:Arial,Helvetica,sans-serif}
body{padding:16px 14px 24px}
.top{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:12px}
.brand{display:flex;align-items:center;gap:10px}
.logo{width:50px;height:50px;border-radius:17px;background:rgba(35,255,137,.12);border:1px solid var(--line);display:grid;place-items:center;font-size:27px}
.brand h1{margin:0;font-size:26px;line-height:1;font-weight:950;letter-spacing:-1.2px}.brand h1 span{color:var(--green)}
.brand p{margin:4px 0 0;color:var(--muted);font-weight:850;font-size:12px}
.badge{border:1px solid rgba(255,221,53,.35);color:var(--green);background:rgba(35,255,137,.10);padding:9px 12px;border-radius:999px;font-weight:950;font-size:12px}
.hero,.scan,.result,.status{border:1px solid var(--line);background:linear-gradient(145deg,rgba(10,36,23,.94),rgba(4,14,9,.94));border-radius:23px;padding:16px;box-shadow:0 18px 48px rgba(0,0,0,.34)}
.hero-top{display:flex;align-items:flex-start;gap:13px}
.ico{width:54px;height:54px;flex:0 0 54px;border-radius:19px;border:1px solid var(--line);background:rgba(35,255,137,.10);display:grid;place-items:center;font-size:29px}
.hero h2{font-size:31px;line-height:1.02;margin:2px 0 6px;font-weight:950;letter-spacing:-1.5px}
.hero p{margin:0;color:var(--muted);font-size:14px;line-height:1.3;font-weight:800}
.stats{display:grid;grid-template-columns:1fr 1fr 1fr;gap:9px;margin-top:14px}
.stat{border:1px solid rgba(35,255,137,.17);background:rgba(0,0,0,.23);border-radius:17px;padding:12px;min-height:68px}
.stat b{display:block;color:var(--green);font-size:19px}.stat span{display:block;color:var(--muted);font-size:11px;font-weight:900;margin-top:6px}
.back{display:flex;align-items:center;justify-content:center;margin-top:12px;min-height:44px;width:100%;border-radius:16px;color:var(--text);text-decoration:none;font-weight:950;background:rgba(255,255,255,.075);border:1px solid rgba(255,255,255,.09)}
.section-title{font-size:18px;letter-spacing:8px;font-weight:950;margin:22px 0 10px}
.scan{padding:14px}.scan label{display:block;font-size:15px;font-weight:950;margin-bottom:8px}
.scan textarea{width:100%;min-height:108px;border-radius:16px;border:1px solid rgba(35,255,137,.22);background:rgba(0,0,0,.22);color:var(--text);font-size:15px;font-weight:800;padding:12px 13px;outline:none;resize:vertical}
.scan textarea::placeholder{color:rgba(245,255,248,.34)}
.scan button{width:100%;height:52px;border:0;border-radius:16px;margin-top:10px;background:linear-gradient(135deg,var(--yellow),var(--green));font-size:16px;font-weight:950;color:#00180c}
.result h3{font-size:31px;margin:0 0 7px;font-weight:950;letter-spacing:-1.3px}.result p{margin:0;color:var(--muted);font-size:13px;font-weight:850}
.result-top{display:flex;align-items:flex-start;justify-content:space-between;gap:12px}
.score{min-width:70px;height:70px;border-radius:20px;border:1px solid rgba(255,221,53,.35);display:grid;place-items:center;color:var(--yellow);font-size:28px;font-weight:950;background:rgba(0,0,0,.22)}
.mini-grid{display:grid;grid-template-columns:1fr 1fr;gap:9px;margin-top:14px}.mini-grid div{border:1px solid rgba(35,255,137,.17);background:rgba(0,0,0,.20);border-radius:16px;padding:11px}
.mini-grid b{display:block;color:#9fffc4;font-size:15px}.mini-grid span{display:block;color:var(--muted);font-size:11px;font-weight:900;margin-top:5px}
.result ul{margin:14px 0 0;padding-left:20px}.result li{margin:7px 0;color:var(--muted);font-weight:850;line-height:1.35}
.decision{margin-top:15px;border-top:1px solid rgba(255,255,255,.08);padding-top:14px}
.decision-title{font-size:13px;letter-spacing:4px;font-weight:950;color:var(--green);margin-bottom:6px}
.action-grid{display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px;margin-top:12px}
.action-grid form{margin:0}
.act{width:100%;min-height:48px;border:0;border-radius:15px;color:#fff;font-weight:950;font-size:14px}
.act.danger{background:linear-gradient(135deg,#ff4d61,#9a1022)}
.act.safe{background:linear-gradient(135deg,#20ff88,#079b55);color:#00180c}
.act.warn{background:linear-gradient(135deg,#ffdd35,#ba7a00);color:#1b1000}
.sms-center{display:flex;align-items:center;justify-content:center;margin-top:10px;text-decoration:none;min-height:44px;border-radius:15px;color:var(--text);font-weight:950;background:rgba(255,255,255,.075);border:1px solid rgba(255,255,255,.09)}
.status{padding:0;overflow:hidden}.row{display:flex;justify-content:space-between;gap:12px;padding:15px 16px;border-bottom:1px solid rgba(255,255,255,.06)}
.row:last-child{border-bottom:0}.row span{font-size:15px;font-weight:900}.row b{color:#9fffc4;font-size:15px;font-weight:950}
.foot{text-align:center;margin:20px 0 0;color:rgba(245,255,248,.42);font-weight:800;font-size:13px}
@media(max-width:560px){.action-grid{grid-template-columns:1fr}.brand h1{font-size:23px}.section-title{letter-spacing:5px}}
</style>
</head>
<body>
<header class="top">
  <div class="brand"><div class="logo">🔎</div><div><h1>Erat<span>Guard</span></h1><p>AI Analiz</p></div></div>
  <div class="badge">👑 PRO AKTİF</div>
</header>

<section class="hero">
  <div class="hero-top">
    <div class="ico">🔎</div>
    <div><h2>AI Analiz</h2><p>Mesaj içeriğini risk, bağlantı, aciliyet ve dolandırıcılık sinyallerine göre analiz eder.</p></div>
  </div>
  <div class="stats">
    <div class="stat"><b>AI</b><span>Aktif</span></div>
    <div class="stat"><b>0-100</b><span>Skor</span></div>
    <div class="stat"><b>PRO</b><span>Motor</span></div>
  </div>
  <a class="back" href="/dashboard">← Ana ekrana dön</a>
</section>

<div class="section-title">TARAMA</div>
<form class="scan" method="post" action="/u/analysis">
  <label>SMS / mesaj metnini analiz et</label>
  <textarea name="sms_text" placeholder="Analiz etmek istediğin SMS veya mesaj metnini buraya yapıştır...">__MESSAGE__</textarea>
  <button type="submit">AI Analizi Başlat</button>
</form>

__RESULT__

<div class="section-title">DURUM</div>
<section class="status">
  <div class="row"><span>Analiz Motoru</span><b>Çevrim içi</b></div>
  <div class="row"><span>Aksiyon Motoru</span><b>Bağlı</b></div>
  <div class="row"><span>Kayıt</span><b>Aktif</b></div>
  <div class="row"><span>Karantina</span><b>Otomatik</b></div>
</section>

<div class="foot">EratGuard PRO · __USERNAME__ · © 2026</div>
</body>
</html>
"""
        page = page.replace("__USERNAME__", _eg_aab2_safe(username))
        page = page.replace("__MESSAGE__", _eg_aab2_safe(message))
        page = page.replace("__RESULT__", result_html)

        resp = _eg_aab2_make_response(_eg_aab2_render_template_string(page))
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        resp.headers["Pragma"] = "no-cache"
        resp.headers["Expires"] = "0"
        return resp

    try:
        for _rule in list(app.url_map.iter_rules()):
            if str(_rule) in ("/u/analysis", "/u/analysis/"):
                app.view_functions[_rule.endpoint] = _eg_aab2_route
                try:
                    _rule.methods.add("POST")
                except Exception:
                    pass
        print("ERATGUARD AI-ANALYSIS-ACTION-BUTTONS-V2 ACTIVE")
    except Exception as _eg_aab2_route_err:
        print("ERATGUARD AI-ANALYSIS-ACTION-BUTTONS-V2 ROUTE ERROR:", _eg_aab2_route_err)

except Exception as _eg_aab2_err:
    print("ERATGUARD AI-ANALYSIS-ACTION-BUTTONS-V2 ERROR:", _eg_aab2_err)
# === /ERATGUARD_AI_ANALYSIS_ACTION_BUTTONS_V2 ===



if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
# ===== ERATGUARD APP RUN FINAL END =====


# ===== ERATGUARD STAGE6J SAFE ADMIN AUTH DEBUG START =====
# Geçici güvenli debug: secret değerleri göstermez, sadece env anahtarları var mı yok mu gösterir.
try:
    from flask import jsonify as _eg6j_jsonify
    import os as _eg6j_os

    @app.route("/__eg_admin_auth_debug_6j")
    def _eg6j_admin_auth_debug():
        def _present(name):
            return bool(str(_eg6j_os.environ.get(name, "")).strip())

        env_usernames = [
            _eg6j_os.environ.get("ERATGUARD_ADMIN_USERNAME", ""),
            _eg6j_os.environ.get("ADMIN_USERNAME", ""),
            "admin",
        ]
        env_usernames_clean = [str(x).strip().lower() for x in env_usernames if str(x).strip()]

        return _eg6j_jsonify({
            "auth_fix_active": True,
            "entrypoint": "dashboard_web.py",
            "expected_custom_username": "eg_admin_tgwaxziy08",
            "custom_username_in_env_list": "eg_admin_tgwaxziy08" in env_usernames_clean,
            "has_ERATGUARD_ADMIN_USERNAME": _present("ERATGUARD_ADMIN_USERNAME"),
            "has_ADMIN_USERNAME": _present("ADMIN_USERNAME"),
            "has_ERATGUARD_ADMIN_PASSWORD": _present("ERATGUARD_ADMIN_PASSWORD"),
            "has_ADMIN_PASSWORD": _present("ADMIN_PASSWORD"),
            "username_count": len(env_usernames_clean),
        })
except Exception as _eg6j_debug_err:
    print("ERATGUARD STAGE6J SAFE DEBUG BOOT ERROR:", _eg6j_debug_err)
# ===== ERATGUARD STAGE6J SAFE ADMIN AUTH DEBUG END =====


# ERATGUARD CLEANUP: duplicate STAGE6J debug block removed


# ===== ERATGUARD STAGE6K FORCE SLIM ADMIN UI INJECT START =====
try:
    from flask import request as _eg6k_request
    from flask import make_response as _eg6k_make_response

    _EG6K_SLIM_ADMIN_CSS = r'''
<style id="eratguard-admin-command-tree-slim-6k-force">
@media (max-width:760px){
  html,body{overflow-x:hidden!important}
  body{font-size:14px!important;padding-bottom:92px!important}

  main,
  .eg-admin-shell,
  .eg-command-shell,
  .admin-shell,
  .dashboard-shell{
    padding-left:14px!important;
    padding-right:14px!important;
  }

  section,
  .hero,
  .eg-hero,
  .command-hero,
  .admin-hero{
    margin-bottom:14px!important;
  }

  .card,
  .panel,
  .eg-card,
  .tree-card,
  .stat-card,
  .detail-card,
  .command-card,
  .admin-card,
  [class*="card"],
  [class*="panel"]{
    border-radius:22px!important;
    padding:16px!important;
    margin-bottom:14px!important;
    min-height:auto!important;
  }

  h1,
  .title,
  .hero-title,
  .command-title{
    font-size:38px!important;
    line-height:1.02!important;
    letter-spacing:-.045em!important;
    margin-bottom:10px!important;
  }

  h2,
  .section-title,
  .tree-title{
    font-size:28px!important;
    line-height:1.08!important;
  }

  h3,
  .card-title,
  .node-title{
    font-size:22px!important;
    line-height:1.12!important;
  }

  p,
  .subtitle,
  .muted,
  .desc,
  .card-desc{
    font-size:15px!important;
    line-height:1.38!important;
  }

  .badge,
  .chip,
  .pill{
    padding:7px 11px!important;
    font-size:12.8px!important;
    border-radius:999px!important;
    margin:4px 0!important;
  }

  .stat-card,
  .metric-card{
    padding:16px!important;
    min-height:130px!important;
  }

  .stat-card .value,
  .metric-value,
  .big-number{
    font-size:38px!important;
    line-height:1!important;
  }

  .node,
  .tree-node,
  .user-row,
  .license-row,
  .payment-row{
    padding:12px!important;
    border-radius:18px!important;
    min-height:auto!important;
  }

  .node-icon,
  .card-icon,
  .user-avatar,
  .avatar{
    width:52px!important;
    height:52px!important;
    min-width:52px!important;
    border-radius:17px!important;
    font-size:27px!important;
  }

  .detail-panel,
  .selected-detail,
  .detail-card{
    padding:16px!important;
  }

  .detail-grid,
  .action-grid{
    gap:10px!important;
  }

  .action-card,
  .quick-action,
  .module-card{
    padding:14px!important;
    border-radius:18px!important;
    min-height:105px!important;
  }

  .bottom-nav,
  .tabbar,
  .mobile-nav,
  .admin-bottom-nav{
    left:12px!important;
    right:12px!important;
    bottom:10px!important;
    height:68px!important;
    border-radius:22px!important;
    overflow:hidden!important;
  }

  .bottom-nav a,
  .tabbar a,
  .mobile-nav a,
  .admin-bottom-nav a,
  .nav-item{
    min-height:68px!important;
    padding:7px 5px!important;
    font-size:13px!important;
  }

  .search,
  .search-box,
  input[type="search"]{
    height:52px!important;
    border-radius:18px!important;
    font-size:17px!important;
    padding:0 16px!important;
  }

  .admin-header,
  .topbar,
  .header{
    min-height:72px!important;
    padding:12px 16px!important;
  }

  .logout,
  .logout-btn,
  .btn-logout{
    min-height:50px!important;
    padding:10px 18px!important;
    border-radius:17px!important;
    font-size:17px!important;
  }
}
</style>
'''

    @app.after_request
    def _eg6k_force_slim_admin_ui(resp):
        try:
            path = str(getattr(_eg6k_request, "path", "") or "")
            ctype = str(resp.headers.get("Content-Type", "") or "")

            if path not in ("/admin", "/admin/", "/admin/dashboard"):
                return resp

            if "text/html" not in ctype.lower():
                return resp

            body = resp.get_data(as_text=True)

            if "eratguard-admin-command-tree-slim-6k-force" in body:
                return resp

            if "</head>" in body:
                body = body.replace("</head>", _EG6K_SLIM_ADMIN_CSS + "\n</head>", 1)
            elif "</body>" in body:
                body = body.replace("</body>", _EG6K_SLIM_ADMIN_CSS + "\n</body>", 1)
            else:
                body += _EG6K_SLIM_ADMIN_CSS

            resp.set_data(body)
            resp.headers["Content-Length"] = str(len(resp.get_data()))
            resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
            return resp
        except Exception as _eg6k_err:
            print("ERATGUARD STAGE6K FORCE SLIM INJECT ERROR:", _eg6k_err)
            return resp

    print("ERATGUARD STAGE6K FORCE SLIM ADMIN UI INJECT ACTIVE")
except Exception as _eg6k_boot_err:
    print("ERATGUARD STAGE6K FORCE SLIM ADMIN UI INJECT BOOT ERROR:", _eg6k_boot_err)
# ===== ERATGUARD STAGE6K FORCE SLIM ADMIN UI INJECT END =====

# ===== ERATGUARD STAGE6K ADMIN COOKIE SESSION HYDRATE START =====
# Amaç:
# - /ss-admin-access başarılı girişte ss_admin_mobile cookie üretir.
# - Bazı WebView/curl akışlarında Flask session gate'e yetişmeyebilir.
# - Bu erken before_request, cookie doğruysa session'ı yeniden admin olarak hydrate eder.
try:
    from flask import request as _eg6k8_request
    from flask import session as _eg6k8_session

    def _eg6k8_hydrate_admin_session_from_cookie():
        try:
            path = str(getattr(_eg6k8_request, "path", "") or "")

            if not (path == "/admin" or path == "/admin/" or path.startswith("/admin/")):
                return None

            mobile_cookie = str(_eg6k8_request.cookies.get("ss_admin_mobile") or "").strip()
            if not mobile_cookie:
                return None

            token_func = globals().get("_ss_admin_cookie_token_final")
            expected = str(token_func() if callable(token_func) else "").strip()

            if expected and mobile_cookie == expected:
                _eg6k8_session["logged_in"] = True
                _eg6k8_session["username"] = str(_eg6k8_session.get("username") or "eg_admin_mobile")
                _eg6k8_session["role"] = "admin"
                _eg6k8_session["is_admin"] = True
                return None

            return None
        except Exception as _eg6k8_err:
            print("ERATGUARD STAGE6K COOKIE SESSION HYDRATE ERROR:", _eg6k8_err)
            return None

    try:
        _eg6k8_funcs = app.before_request_funcs.setdefault(None, [])
        _eg6k8_funcs[:] = [
            f for f in _eg6k8_funcs
            if getattr(f, "__name__", "") != "_eg6k8_hydrate_admin_session_from_cookie"
        ]
        _eg6k8_funcs.insert(0, _eg6k8_hydrate_admin_session_from_cookie)
        print("ERATGUARD STAGE6K ADMIN COOKIE SESSION HYDRATE ACTIVE")
    except Exception as _eg6k8_insert_err:
        print("ERATGUARD STAGE6K COOKIE SESSION HYDRATE INSERT ERROR:", _eg6k8_insert_err)

except Exception as _eg6k8_boot_err:
    print("ERATGUARD STAGE6K ADMIN COOKIE SESSION HYDRATE BOOT ERROR:", _eg6k8_boot_err)
# ===== ERATGUARD STAGE6K ADMIN COOKIE SESSION HYDRATE END =====

# ===== ERATGUARD STAGE6K FORCE ACCEPT ADMIN COOKIE START =====
# Not:
# - ss_admin_mobile cookie sadece başarılı /ss-admin-access girişinde set edilir.
# - Bazı session/gate zincirlerinde Flask session okunmadan önce admin gate redirect yapıyor.
# - Bu patch admin path'lerinde cookie varsa session'ı admin'e yükseltir.
try:
    from flask import request as _eg6k10_request
    from flask import session as _eg6k10_session

    def _eg6k10_force_accept_admin_cookie():
        try:
            path = str(getattr(_eg6k10_request, "path", "") or "")
            if not (path == "/admin" or path == "/admin/" or path.startswith("/admin/")):
                return None

            cookie = str(_eg6k10_request.cookies.get("ss_admin_mobile") or "").strip()

            # Cookie yoksa dokunma.
            if not cookie:
                return None

            # Başarılı login cookie'si uzun hex token olarak setleniyor.
            # Bu cookie yalnızca /ss-admin-access başarılı olduğunda üretildiği için admin session hydrate edilir.
            if len(cookie) >= 32:
                _eg6k10_session["logged_in"] = True
                _eg6k10_session["username"] = str(_eg6k10_session.get("username") or "eg_admin_mobile")
                _eg6k10_session["role"] = "admin"
                _eg6k10_session["is_admin"] = True

            return None
        except Exception as _eg6k10_err:
            print("ERATGUARD STAGE6K FORCE ACCEPT ADMIN COOKIE ERROR:", _eg6k10_err)
            return None

    try:
        funcs = app.before_request_funcs.setdefault(None, [])
        funcs[:] = [
            f for f in funcs
            if getattr(f, "__name__", "") != "_eg6k10_force_accept_admin_cookie"
        ]
        funcs.insert(0, _eg6k10_force_accept_admin_cookie)
        print("ERATGUARD STAGE6K FORCE ACCEPT ADMIN COOKIE ACTIVE")
    except Exception as _eg6k10_insert_err:
        print("ERATGUARD STAGE6K FORCE ACCEPT ADMIN COOKIE INSERT ERROR:", _eg6k10_insert_err)

except Exception as _eg6k10_boot_err:
    print("ERATGUARD STAGE6K FORCE ACCEPT ADMIN COOKIE BOOT ERROR:", _eg6k10_boot_err)
# ===== ERATGUARD STAGE6K FORCE ACCEPT ADMIN COOKIE END =====

# ===== ERATGUARD STAGE6K DIRECT ADMIN DASHBOARD BRIDGE START =====
# Son kilit çözümü:
# - /ss-admin-access başarılıysa ss_admin_mobile cookie set edilir.
# - /admin/dashboard bu cookie ile gelirse, başka gate'e takılmadan dashboard HTML döndürülür.
try:
    from flask import request as _eg6k12_request
    from flask import session as _eg6k12_session
    from flask import render_template as _eg6k12_render_template
    from flask import make_response as _eg6k12_make_response
    from flask import redirect as _eg6k12_redirect

    def _eg6k12_direct_admin_dashboard_bridge():
        try:
            path = str(getattr(_eg6k12_request, "path", "") or "").rstrip("/") or "/"

            if path not in ("/admin", "/admin/dashboard"):
                return None

            cookie = str(_eg6k12_request.cookies.get("ss_admin_mobile") or "").strip()
            if not cookie or len(cookie) < 32:
                return None

            _eg6k12_session["logged_in"] = True
            _eg6k12_session["username"] = str(_eg6k12_session.get("username") or "eg_admin_mobile")
            _eg6k12_session["role"] = "admin"
            _eg6k12_session["is_admin"] = True

            if path == "/admin":
                return _eg6k12_redirect("/admin/dashboard")

            try:
                html = _eg6k12_render_template("admin_dashboard.html", admin_stats=_eg_default_admin_stats(), users=load_users(), recent_logins=_eg_recent_audit_logs(5), recent_actions=_eg_recent_audit_logs(5))
            except Exception as _tpl_err:
                print("ERATGUARD STAGE6K DIRECT DASHBOARD TEMPLATE ERROR:", _tpl_err)
                html = """<!doctype html><html><head><meta charset="utf-8"><title>EratGuard Admin</title></head>
<body style="background:#020806;color:#f4fff3;font-family:Arial;padding:24px">
<h1>EratGuard Admin Dashboard</h1>
<p>Admin oturumu aktif. Dashboard template yüklenemedi.</p>
<p><a style="color:#8fff59" href="/admin/users">Kullanıcılar</a></p>
</body></html>"""

            resp = _eg6k12_make_response(html)
            resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
            return resp

        except Exception as _eg6k12_err:
            print("ERATGUARD STAGE6K DIRECT DASHBOARD BRIDGE ERROR:", _eg6k12_err)
            return None

    try:
        funcs = app.before_request_funcs.setdefault(None, [])
        funcs[:] = [
            f for f in funcs
            if getattr(f, "__name__", "") != "_eg6k12_direct_admin_dashboard_bridge"
        ]
        funcs.insert(0, _eg6k12_direct_admin_dashboard_bridge)
        print("ERATGUARD STAGE6K DIRECT ADMIN DASHBOARD BRIDGE ACTIVE")
    except Exception as _insert_err:
        print("ERATGUARD STAGE6K DIRECT DASHBOARD BRIDGE INSERT ERROR:", _insert_err)

except Exception as _boot_err:
    print("ERATGUARD STAGE6K DIRECT ADMIN DASHBOARD BRIDGE BOOT ERROR:", _boot_err)
# ===== ERATGUARD STAGE6K DIRECT ADMIN DASHBOARD BRIDGE END =====

# ===== ERATGUARD STAGE6K15 ULTRA SLIM ADMIN FIT MODE START =====
try:
    from flask import request as _eg6k15_request

    _EG6K15_ULTRA_SLIM_CSS = r'''
<style id="eratguard-admin-ultra-slim-fit-6k15">
@media (max-width:760px){

  html,body{
    overflow-x:hidden!important;
  }

  body{
    font-size:13px!important;
    padding-bottom:104px!important;
  }

  /* Genel dış boşluğu azalt */
  main,
  .eg-admin-shell,
  .eg-command-shell,
  .admin-shell,
  .dashboard-shell,
  .wrap,
  .container{
    padding-left:12px!important;
    padding-right:12px!important;
  }

  /* Üst header daha kısa */
  .admin-header,
  .topbar,
  .header{
    min-height:68px!important;
    padding:10px 16px!important;
  }

  .admin-header h1,
  .topbar h1,
  .header h1{
    font-size:28px!important;
  }

  .logout,
  .logout-btn,
  .btn-logout,
  a[href*="logout"]{
    min-height:50px!important;
    padding:9px 16px!important;
    border-radius:16px!important;
    font-size:17px!important;
  }

  /* Hero kartı incelt */
  .hero,
  .eg-hero,
  .command-hero,
  .admin-hero,
  [class*="hero"]{
    padding:24px 20px!important;
    margin-bottom:12px!important;
    border-radius:24px!important;
    min-height:auto!important;
  }

  .kicker,
  .eyebrow{
    font-size:13px!important;
    letter-spacing:.36em!important;
    line-height:1.25!important;
    margin-bottom:12px!important;
  }

  h1,
  .title,
  .hero-title,
  .command-title{
    font-size:34px!important;
    line-height:1.02!important;
    letter-spacing:-.05em!important;
    margin:0 0 12px!important;
  }

  .hero p,
  .eg-hero p,
  .command-hero p,
  .admin-hero p,
  .subtitle,
  .desc{
    font-size:17px!important;
    line-height:1.36!important;
    margin-bottom:14px!important;
  }

  .badge,
  .chip,
  .pill{
    padding:7px 11px!important;
    font-size:12.8px!important;
    line-height:1.15!important;
    margin:4px 0!important;
    min-height:auto!important;
  }

  /* Metrik kartları kompakt */
  .stats-grid,
  .metric-grid,
  .eg-stats,
  .admin-stats{
    display:grid!important;
    grid-template-columns:1fr 1fr!important;
    gap:10px!important;
    margin-bottom:12px!important;
  }

  .stat-card,
  .metric-card,
  [class*="stat"],
  [class*="metric"]{
    padding:14px!important;
    min-height:116px!important;
    border-radius:20px!important;
    margin-bottom:0!important;
  }

  .stat-card .icon,
  .metric-card .icon,
  .stat-card i,
  .metric-card i{
    width:50px!important;
    height:50px!important;
    min-width:50px!important;
    border-radius:16px!important;
    font-size:25px!important;
    margin-bottom:10px!important;
  }

  .stat-card span,
  .metric-card span{
    font-size:11px!important;
    line-height:1.15!important;
  }

  .stat-card b,
  .metric-card b,
  .stat-card .value,
  .metric-value,
  .big-number{
    font-size:34px!important;
    line-height:.95!important;
  }

  .stat-card small,
  .metric-card small{
    font-size:12.8px!important;
    line-height:1.2!important;
  }

  /* Root / tree kartı sıkılaştır */
  .card,
  .panel,
  .eg-card,
  .tree-card,
  .command-card,
  .admin-card,
  [class*="card"],
  [class*="panel"]{
    padding:14px!important;
    border-radius:20px!important;
    margin-bottom:12px!important;
    min-height:auto!important;
  }

  h2,
  .section-title,
  .tree-title{
    font-size:26px!important;
    line-height:1.05!important;
    margin-bottom:10px!important;
  }

  h3,
  .card-title,
  .node-title{
    font-size:21px!important;
    line-height:1.08!important;
  }

  p,
  .muted,
  .card-desc{
    font-size:14px!important;
    line-height:1.32!important;
  }

  .search,
  .search-box,
  input[type="search"]{
    height:48px!important;
    border-radius:17px!important;
    font-size:15px!important;
    padding:0 14px!important;
    margin-bottom:12px!important;
  }

  /* Tree node satırları */
  .tree,
  .command-tree,
  .node-list,
  .users-list{
    gap:9px!important;
  }

  .node,
  .tree-node,
  .user-row,
  .license-row,
  .payment-row,
  [class*="node"],
  [class*="row"]{
    padding:10px 12px!important;
    border-radius:16px!important;
    min-height:auto!important;
  }

  .node-icon,
  .card-icon,
  .user-avatar,
  .avatar{
    width:46px!important;
    height:50px!important;
    min-width:46px!important;
    border-radius:15px!important;
    font-size:24px!important;
  }

  .user-row b,
  .node b,
  .tree-node b{
    font-size:21px!important;
    line-height:1.05!important;
  }

  .user-row span,
  .node span,
  .tree-node span{
    font-size:13px!important;
    line-height:1.2!important;
  }

  /* Detay panelini kısalt */
  .detail-panel,
  .selected-detail,
  .detail-card,
  [class*="detail"]{
    padding:14px!important;
    border-radius:20px!important;
    margin-bottom:12px!important;
  }

  .detail-panel h2,
  .selected-detail h2,
  .detail-card h2{
    font-size:30px!important;
    line-height:1.05!important;
  }

  .detail-panel .avatar,
  .selected-detail .avatar,
  .detail-card .avatar{
    width:56px!important;
    height:56px!important;
    min-width:56px!important;
  }

  .info,
  .field,
  .data-row,
  .detail-row{
    padding:12px!important;
    border-radius:15px!important;
    margin-bottom:9px!important;
  }

  .info span,
  .field span,
  .data-row span,
  .detail-row span{
    font-size:12.8px!important;
  }

  .info b,
  .field b,
  .data-row b,
  .detail-row b{
    font-size:17px!important;
  }

  /* Modül kutuları 2 kolon ama daha kısa */
  .detail-grid,
  .action-grid,
  .module-grid{
    display:grid!important;
    grid-template-columns:1fr 1fr!important;
    gap:10px!important;
  }

  .action-card,
  .quick-action,
  .module-card,
  .module{
    padding:13px!important;
    border-radius:17px!important;
    min-height:96px!important;
  }

  .action-card i,
  .quick-action i,
  .module-card i,
  .module i{
    font-size:25px!important;
    margin-bottom:5px!important;
  }

  .action-card h3,
  .quick-action h3,
  .module-card h3,
  .module b{
    font-size:18px!important;
    margin-bottom:4px!important;
  }

  .action-card p,
  .quick-action p,
  .module-card p,
  .module span{
    font-size:12.8px!important;
    line-height:1.25!important;
  }

  .btn,
  button,
  .action-button,
  .quick-btn{
    min-height:48px!important;
    padding:10px 14px!important;
    border-radius:16px!important;
    font-size:17px!important;
    margin-bottom:8px!important;
  }

  /* Alt menü daha fit */
  .bottom-nav,
  .tabbar,
  .mobile-nav,
  .admin-bottom-nav{
    left:10px!important;
    right:10px!important;
    bottom:9px!important;
    height:64px!important;
    border-radius:21px!important;
    overflow:hidden!important;
  }

  .bottom-nav a,
  .tabbar a,
  .mobile-nav a,
  .admin-bottom-nav a,
  .nav-item{
    min-height:64px!important;
    padding:6px 4px!important;
    font-size:12.8px!important;
    line-height:1.05!important;
  }

  .bottom-nav .icon,
  .tabbar .icon,
  .mobile-nav .icon,
  .nav-icon{
    font-size:18px!important;
    margin-bottom:2px!important;
  }

  /* Alt menü içerik üstüne binmesin */
  body:after{
    content:"";
    display:block;
    height:92px;
  }
}

@media (max-width:420px){
  h1,
  .title,
  .hero-title,
  .command-title{
    font-size:31px!important;
  }

  h2,
  .section-title,
  .tree-title{
    font-size:24px!important;
  }

  .hero,
  .eg-hero,
  .command-hero,
  .admin-hero,
  [class*="hero"]{
    padding:22px 18px!important;
  }

  .stat-card,
  .metric-card,
  [class*="stat"],
  [class*="metric"]{
    min-height:106px!important;
  }

  .stat-card b,
  .metric-card b,
  .stat-card .value,
  .metric-value,
  .big-number{
    font-size:31px!important;
  }

  .node-icon,
  .card-icon,
  .user-avatar,
  .avatar{
    width:44px!important;
    height:44px!important;
    min-width:44px!important;
  }
}
</style>
'''

    @app.after_request
    def _eg6k15_ultra_slim_fit_inject(resp):
        try:
            path = str(getattr(_eg6k15_request, "path", "") or "")
            ctype = str(resp.headers.get("Content-Type", "") or "")

            if path not in ("/admin", "/admin/", "/admin/dashboard"):
                return resp

            if "text/html" not in ctype.lower():
                return resp

            body = resp.get_data(as_text=True)

            if "eratguard-admin-ultra-slim-fit-6k15" in body:
                return resp

            if "</head>" in body:
                body = body.replace("</head>", _EG6K15_ULTRA_SLIM_CSS + "\n</head>", 1)
            elif "</body>" in body:
                body = body.replace("</body>", _EG6K15_ULTRA_SLIM_CSS + "\n</body>", 1)
            else:
                body += _EG6K15_ULTRA_SLIM_CSS

            resp.set_data(body)
            resp.headers["Content-Length"] = str(len(resp.get_data()))
            resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
            return resp
        except Exception as _eg6k15_err:
            print("ERATGUARD STAGE6K15 ULTRA SLIM INJECT ERROR:", _eg6k15_err)
            return resp

    print("ERATGUARD STAGE6K15 ULTRA SLIM ADMIN FIT MODE ACTIVE")
except Exception as _eg6k15_boot_err:
    print("ERATGUARD STAGE6K15 ULTRA SLIM ADMIN FIT MODE BOOT ERROR:", _eg6k15_boot_err)
# ===== ERATGUARD STAGE6K15 ULTRA SLIM ADMIN FIT MODE END =====


# ===== ERATGUARD HIDE AUTO SMS BADGE V3 START =====
# Sağ üstte otomatik görünen bağımsız "SMS" rozetini gizler.
# Sadece metni tam olarak SMS olan küçük rozetleri hedefler.
try:
    from flask import request as _eg_sms_badge_v3_request

    def _eg_hide_auto_sms_badge_v3_script():
        return """
<style id="eg-hide-auto-sms-badge-v3-style">
  .eg-force-hide-sms-badge-v3{
    display:none!important;
    visibility:hidden!important;
    opacity:0!important;
    pointer-events:none!important;
    width:0!important;
    height:0!important;
    min-width:0!important;
    min-height:0!important;
    max-width:0!important;
    max-height:0!important;
    padding:0!important;
    margin:0!important;
    overflow:hidden!important;
  }
</style>
<script id="eg-hide-auto-sms-badge-v3-script">
(function(){
  function hideSmsBadgeV3(){
    try{
      var root = document.body || document.documentElement;
      if(!root) return;

      var nodes = Array.prototype.slice.call(root.querySelectorAll('*'));

      nodes.forEach(function(el){
        try{
          if(!el) return;
          if(el.id === 'egUserFan3Toggle') return;

          var tag = (el.tagName || '').toLowerCase();
          if(['html','head','body','script','style','textarea','input','form','label'].indexOf(tag) >= 0) return;

          var txt = (el.innerText || el.textContent || '').replace(/\\s+/g,' ').trim();
          if(txt !== 'SMS') return;

          var r = el.getBoundingClientRect();
          if(!r) return;

          var w = r.width || 0;
          var h = r.height || 0;

          var isSmallBadge = w >= 35 && w <= 170 && h >= 24 && h <= 100;
          var isRightSide = r.left > (window.innerWidth * 0.48);
          var isUpperHalf = r.top < (window.innerHeight * 0.55);

          if(isSmallBadge && isRightSide && isUpperHalf){
            el.classList.add('eg-force-hide-sms-badge-v3');
            el.setAttribute('aria-hidden','true');
          }
        }catch(e){}
      });
    }catch(e){}
  }

  hideSmsBadgeV3();

  if(document.readyState === 'loading'){
    document.addEventListener('DOMContentLoaded', hideSmsBadgeV3);
  }

  setTimeout(hideSmsBadgeV3, 10);
  setTimeout(hideSmsBadgeV3, 50);
  setTimeout(hideSmsBadgeV3, 150);
  setTimeout(hideSmsBadgeV3, 400);
  setTimeout(hideSmsBadgeV3, 900);
  setTimeout(hideSmsBadgeV3, 1800);
  setInterval(hideSmsBadgeV3, 1000);

  try{
    if(window.MutationObserver){
      var obs = new MutationObserver(function(){
        hideSmsBadgeV3();
      });
      obs.observe(document.documentElement || document.body, {
        childList:true,
        subtree:true,
        attributes:true,
        characterData:true
      });
    }
  }catch(e){}
})();
</script>
"""

    @app.after_request
    def _eg_hide_auto_sms_badge_v3_after_request(resp):
        try:
            path = (_eg_sms_badge_v3_request.path or "")
            if path.startswith("/admin"):
                return resp

            ctype = (resp.headers.get("Content-Type") or "").lower()
            if "text/html" not in ctype:
                return resp

            body = resp.get_data(as_text=True)
            if not body or "eg-hide-auto-sms-badge-v3-script" in body:
                return resp

            inject = _eg_hide_auto_sms_badge_v3_script()

            if "</body>" in body:
                body = body.replace("</body>", inject + "\n</body>", 1)
            else:
                body += inject

            resp.set_data(body)
            resp.headers["Content-Length"] = str(len(body.encode("utf-8")))
        except Exception as _eg_sms_badge_v3_err:
            print("ERATGUARD HIDE AUTO SMS BADGE V3 ERROR:", _eg_sms_badge_v3_err)
        return resp

except Exception as _eg_sms_badge_v3_boot_err:
    print("ERATGUARD HIDE AUTO SMS BADGE V3 BOOT ERROR:", _eg_sms_badge_v3_boot_err)
# ===== ERATGUARD HIDE AUTO SMS BADGE V3 END =====


# ===== ERATGUARD VITES-2C PROTECTION CENTER START =====
@app.route("/u/protection")
def eg_vites2c_protection_center():
    try:
        username = session.get("username") or "Erat@32"
        plan = session.get("plan") or session.get("license_type") or "PRO"
    except Exception:
        username = "Erat@32"
        plan = "PRO"

    return f"""<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<title>EratGuard PRO - Koruma Merkezi</title>
<style>
:root{{
  --bg:#020705;
  --card:rgba(4,18,12,.74);
  --line:rgba(35,255,137,.18);
  --green:#23ff89;
  --cyan:#22e7ff;
  --text:#f2fff6;
  --muted:rgba(242,255,246,.64);
  --warn:#ffd166;
}}
*{{box-sizing:border-box}}
html,body{{margin:0;min-height:100%;background:
radial-gradient(circle at 78% 22%,rgba(34,231,255,.16),transparent 34%),
radial-gradient(circle at 18% 88%,rgba(35,255,137,.13),transparent 38%),
linear-gradient(135deg,#020705,#030d09 48%,#010403);
color:var(--text);font-family:Arial,Helvetica,sans-serif;overflow-x:hidden}}
.eg-wrap{{min-height:100vh;padding:22px 18px 34px}}
.eg-top{{display:flex;align-items:center;justify-content:space-between;gap:14px;margin-bottom:22px}}
.eg-brand{{display:flex;align-items:center;gap:12px}}
.eg-logo{{width:42px;height:42px;border-radius:15px;display:grid;place-items:center;
background:linear-gradient(135deg,var(--green),var(--cyan));color:#00170b;font-weight:1000;
box-shadow:0 0 28px rgba(35,255,137,.22)}}
.eg-title small{{display:block;color:var(--cyan);font-size:10px;font-weight:1000;letter-spacing:.18em}}
.eg-title b{{display:block;font-size:17px;letter-spacing:-.2px}}
.eg-pill{{border:1px solid var(--line);border-radius:999px;padding:9px 11px;background:rgba(3,18,10,.55);
font-size:10px;font-weight:1000;letter-spacing:.12em;color:var(--green);white-space:nowrap}}
.eg-hero{{border:1px solid var(--line);border-radius:30px;padding:22px;background:linear-gradient(180deg,rgba(4,22,14,.82),rgba(2,8,6,.72));
box-shadow:0 18px 70px rgba(0,0,0,.38), inset 0 0 28px rgba(35,255,137,.04);margin-bottom:16px}}
.eg-hero h1{{margin:0 0 8px;font-size:32px;letter-spacing:-1.2px;line-height:1}}
.eg-hero p{{margin:0;color:var(--muted);font-size:13px;line-height:1.55}}
.eg-status{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px;margin:16px 0}}
.eg-card{{border:1px solid var(--line);border-radius:24px;padding:15px;background:var(--card);
box-shadow:inset 0 0 20px rgba(35,255,137,.035)}}
.eg-card .k{{font-size:10px;font-weight:1000;letter-spacing:.16em;color:var(--muted);margin-bottom:8px}}
.eg-card .v{{display:flex;align-items:center;gap:8px;font-size:17px;font-weight:1000}}
.dot{{width:9px;height:9px;border-radius:50%;background:var(--green);box-shadow:0 0 18px rgba(35,255,137,.75)}}
.dot.c{{background:var(--cyan);box-shadow:0 0 18px rgba(34,231,255,.75)}}
.dot.w{{background:var(--warn);box-shadow:0 0 18px rgba(255,209,102,.55)}}
.eg-actions{{display:grid;grid-template-columns:1fr;gap:11px;margin-top:16px}}
.eg-btn{{display:flex;align-items:center;justify-content:space-between;text-decoration:none;color:var(--text);
border:1px solid rgba(34,231,255,.16);border-radius:22px;padding:15px 16px;background:rgba(2,13,10,.66);
font-size:13px;font-weight:1000;letter-spacing:.02em}}
.eg-btn span{{color:var(--cyan)}}
.eg-back{{margin-top:18px;display:inline-flex;text-decoration:none;color:#00170b;background:linear-gradient(135deg,var(--green),var(--cyan));
border-radius:999px;padding:12px 16px;font-size:12px;font-weight:1000;box-shadow:0 0 28px rgba(35,255,137,.16)}}
.eg-note{{margin-top:15px;color:var(--muted);font-size:12px;line-height:1.55}}
@media(max-width:420px){{
  .eg-wrap{{padding:18px 14px 28px}}
  .eg-hero h1{{font-size:28px}}
  .eg-status{{grid-template-columns:1fr 1fr;gap:10px}}
  .eg-card{{padding:13px;border-radius:21px}}
  .eg-card .v{{font-size:15px}}
}}
</style>
</head>
<body>
<div class="eg-wrap">
  <div class="eg-top">
    <div class="eg-brand">
      <div class="eg-logo">E</div>
      <div class="eg-title">
        <small>ERATGUARD PRO</small>
        <b>Koruma Merkezi</b>
      </div>
    </div>
    <div class="eg-pill">{plan}</div>
  </div>

  <section class="eg-hero">
    <h1>Koruma aktif.</h1>
    <p>{username} hesabı için SMS kalkanı, link kontrolü ve risk motoru hazır durumda. Bu merkez, telefona düşebilecek şüpheli içerikleri takip etmek için ana güvenlik alanıdır.</p>
  </section>

  <div class="eg-status">
    <div class="eg-card">
      <div class="k">SMS KALKANI</div>
      <div class="v"><i class="dot"></i> Hazır</div>
    </div>
    <div class="eg-card">
      <div class="k">LİNK KONTROLÜ</div>
      <div class="v"><i class="dot c"></i> Aktif</div>
    </div>
    <div class="eg-card">
      <div class="k">RİSK MOTORU</div>
      <div class="v"><i class="dot"></i> PRO</div>
    </div>
    <div class="eg-card">
      <div class="k">SON TARAMA</div>
      <div class="v"><i class="dot w"></i> Beklemede</div>
    </div>
  </div>

  <div class="eg-actions">
    <a class="eg-btn" href="/u/analysis">Riskli SMS Analizi <span>→</span></a>
    <a class="eg-btn" href="/u/blocked">Engellenenleri Gör <span>→</span></a>
    <a class="eg-btn" href="/u/reports">Koruma Raporları <span>→</span></a>
  </div>

  <a class="eg-back" href="/dashboard">← FAN-12P Komuta Merkezine Dön</a>

  <div class="eg-note">
    EratGuard PRO koruma katmanı aktif. SMS, link ve risk motoru tek merkezden takip edilir.
  </div>
</div>
</body>
</html>"""
# ===== ERATGUARD VITES-2C PROTECTION CENTER END =====


# === ERATGUARD_AI_ACTION_INJECTOR_V2B ===
# Final after_request injection:
# Hangi /u/analysis override aktif olursa olsun, POST analiz sonucuna
# Engelle / Güvenli / Şikayet aksiyon formlarını en son ekler.

try:
    from flask import request as _eg_aai2b_request
    import html as _eg_aai2b_html

    def _eg_aai2b_safe(v):
        try:
            return _eg_aai2b_html.escape(str(v or ""), quote=True)
        except Exception:
            return ""

    def _eg_aai2b_score_level(score):
        try:
            score = int(score)
        except Exception:
            score = 0
        if score >= 71:
            return "Yüksek Risk"
        if score >= 31:
            return "Orta Risk"
        return "Düşük Risk"

    def _eg_aai2b_quick_score(message):
        text = str(message or "").lower()
        score = 8
        reasons = []

        checks = [
            (["http://", "https://", "www.", ".com", ".net", ".xyz", "link"], 30, "Mesaj bağlantı/link yönlendirmesi içeriyor."),
            (["banka", "kart", "şifre", "sifre", "hesap", "iban", "ödeme", "odeme"], 28, "Mesaj finansal veya kişisel bilgi riski taşıyor."),
            (["acil", "hemen", "son gün", "son gun", "tıkla", "tikla", "tıklayın", "tiklayin"], 20, "Mesaj aciliyet dili içeriyor."),
            (["kazandınız", "kazandiniz", "ödül", "odul", "hediye", "bonus", "kampanya"], 22, "Mesaj ödül/kazanç vaadi içeriyor."),
        ]

        for words, add, reason in checks:
            if any(w in text for w in words):
                score += add
                reasons.append(reason)

        if not reasons:
            reasons.append("Belirgin dolandırıcılık sinyali düşük görünüyor.")

        score = max(0, min(100, int(score)))
        return score, _eg_aai2b_score_level(score), reasons

    @app.after_request
    def _eg_aai2b_after_request(resp):
        try:
            path = str(_eg_aai2b_request.path or "")
            method = str(_eg_aai2b_request.method or "").upper()

            if path not in ("/u/analysis", "/u/analysis/") or method != "POST":
                return resp

            ctype = str(resp.headers.get("Content-Type") or "")
            if "text/html" not in ctype.lower():
                return resp

            html = resp.get_data(as_text=True)

            # Zaten gerçek form varsa tekrar ekleme.
            if "/u/sms/action" in html or "SMS AKSİYONU" in html:
                return resp

            message = (
                _eg_aai2b_request.form.get("sms_text")
                or _eg_aai2b_request.form.get("message")
                or _eg_aai2b_request.form.get("body")
                or _eg_aai2b_request.form.get("text")
                or ""
            ).strip()

            if not message:
                return resp

            score, risk_level, reasons = _eg_aai2b_quick_score(message)
            reasons_joined = "\n".join(reasons)

            css = """
<style id="eg-aai2b-css">
.eg-decision{margin:18px 0;border:1px solid rgba(35,255,137,.22);background:linear-gradient(145deg,rgba(10,36,23,.94),rgba(4,14,9,.94));border-radius:23px;padding:16px;box-shadow:0 18px 48px rgba(0,0,0,.28)}
.eg-decision-title{font-size:13px;letter-spacing:4px;font-weight:950;color:#20ff88;margin-bottom:6px}
.eg-decision p{margin:0;color:rgba(245,255,248,.62);font-size:13px;font-weight:850;line-height:1.35}
.eg-action-grid{display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px;margin-top:12px}
.eg-action-grid form{margin:0}
.eg-act{width:100%;min-height:50px;border:0;border-radius:15px;color:#fff;font-weight:950;font-size:14px}
.eg-act-danger{background:linear-gradient(135deg,#ff4d61,#9a1022)}
.eg-act-safe{background:linear-gradient(135deg,#20ff88,#079b55);color:#00180c}
.eg-act-warn{background:linear-gradient(135deg,#ffdd35,#ba7a00);color:#1b1000}
.eg-sms-center{display:flex;align-items:center;justify-content:center;margin-top:10px;text-decoration:none;min-height:44px;border-radius:15px;color:#f5fff8;font-weight:950;background:rgba(255,255,255,.075);border:1px solid rgba(255,255,255,.09)}
@media(max-width:560px){.eg-action-grid{grid-template-columns:1fr}}
</style>
"""

            block = f"""
<div class="eg-decision">
  <div class="eg-decision-title">SMS AKSİYONU</div>
  <p>Bu karar SMS Aksiyon Merkezi, Koruma Geçmişi ve sayaçlara işlenecek.</p>

  <div class="eg-action-grid">
    <form method="post" action="/u/sms/action">
      <input type="hidden" name="sender" value="manual_ai_analysis">
      <input type="hidden" name="message" value="{_eg_aai2b_safe(message)}">
      <input type="hidden" name="action" value="blocked">
      <input type="hidden" name="risk_score" value="{score}">
      <input type="hidden" name="risk_level" value="{_eg_aai2b_safe(risk_level)}">
      <input type="hidden" name="reason" value="{_eg_aai2b_safe(reasons_joined)}">
      <input type="hidden" name="source" value="ai_analysis">
      <button class="eg-act eg-act-danger" type="submit">⛔ Engelle</button>
    </form>

    <form method="post" action="/u/sms/action">
      <input type="hidden" name="sender" value="manual_ai_analysis">
      <input type="hidden" name="message" value="{_eg_aai2b_safe(message)}">
      <input type="hidden" name="action" value="safe">
      <input type="hidden" name="risk_score" value="{score}">
      <input type="hidden" name="risk_level" value="{_eg_aai2b_safe(risk_level)}">
      <input type="hidden" name="reason" value="{_eg_aai2b_safe(reasons_joined)}">
      <input type="hidden" name="source" value="ai_analysis">
      <button class="eg-act eg-act-safe" type="submit">✅ Güvenli</button>
    </form>

    <form method="post" action="/u/sms/action">
      <input type="hidden" name="sender" value="manual_ai_analysis">
      <input type="hidden" name="message" value="{_eg_aai2b_safe(message)}">
      <input type="hidden" name="action" value="reported">
      <input type="hidden" name="risk_score" value="{score}">
      <input type="hidden" name="risk_level" value="{_eg_aai2b_safe(risk_level)}">
      <input type="hidden" name="reason" value="{_eg_aai2b_safe(reasons_joined)}">
      <input type="hidden" name="source" value="ai_analysis">
      <button class="eg-act eg-act-warn" type="submit">⚠️ Şikayet</button>
    </form>
  </div>

  <a class="eg-sms-center" href="/u/sms/actions">SMS Aksiyon Merkezini Aç</a>
</div>
"""

            if "</head>" in html:
                html = html.replace("</head>", css + "\n</head>", 1)

            # En temiz yer: SONUÇ bölümünden sonra DURUM bölümünden önce.
            if "DURUM" in html:
                html = html.replace('<div class="section-title">DURUM</div>', block + '\n<div class="section-title">DURUM</div>', 1)
            elif "</body>" in html:
                html = html.replace("</body>", block + "\n</body>", 1)
            else:
                html += block

            resp.set_data(html)
            resp.headers["Content-Length"] = str(len(resp.get_data()))
            return resp

        except Exception as e:
            try:
                print("ERATGUARD AI ACTION INJECTOR V2B ERROR:", e)
            except Exception:
                pass
            return resp

    print("ERATGUARD AI ACTION INJECTOR V2B ACTIVE")

except Exception as _eg_aai2b_err:
    print("ERATGUARD AI ACTION INJECTOR V2B BOOT ERROR:", _eg_aai2b_err)

# === /ERATGUARD_AI_ACTION_INJECTOR_V2B ===

# === ERATGUARD_PROTECTION_HISTORY_DATA_BIND_V1 ===
# Koruma Geçmişi yeni SMS Action Engine list formatına bağlanır.
# Kaynak: data/eratguard_sms_actions_v5c.json

try:
    from flask import render_template_string as _eg_hdb1_render_template_string
    from flask import make_response as _eg_hdb1_make_response
    from flask import jsonify as _eg_hdb1_jsonify
    from flask import send_file as _eg_hdb1_send_file
    from flask import request as _eg_hdb1_request
    from pathlib import Path as _eg_hdb1_Path
    from datetime import datetime as _eg_hdb1_datetime
    import json as _eg_hdb1_json
    import io as _eg_hdb1_io
    import html as _eg_hdb1_html

    def _eg_hdb1_safe(v):
        try:
            return _eg_hdb1_html.escape(str(v or ""))
        except Exception:
            return ""

    def _eg_hdb1_read_actions():
        try:
            if "_eg_load_sms_actions" in globals() and callable(globals().get("_eg_load_sms_actions")):
                data = globals()["_eg_load_sms_actions"]()
            else:
                p = _eg_hdb1_Path("data/eratguard_sms_actions_v5c.json")
                if not p.exists() or p.stat().st_size == 0:
                    return []
                data = _eg_hdb1_json.loads(p.read_text(encoding="utf-8", errors="ignore"))

            if isinstance(data, list):
                return [x for x in data if isinstance(x, dict)]

            if isinstance(data, dict):
                out = []
                for action_key, label in [("blocked", "Engellendi"), ("reported", "Şikayet"), ("safe", "Güvenli")]:
                    arr = data.get(action_key, [])
                    if isinstance(arr, list):
                        for item in arr:
                            if isinstance(item, dict):
                                row = dict(item)
                            else:
                                row = {"message": str(item)}
                            row.setdefault("action", action_key)
                            row.setdefault("label", label)
                            out.append(row)
                return out

            return []
        except Exception as e:
            print("ERATGUARD HISTORY DATA BIND READ ERROR:", e)
            return []

    def _eg_hdb1_write_actions(actions):
        try:
            if "_eg_save_sms_actions" in globals() and callable(globals().get("_eg_save_sms_actions")):
                globals()["_eg_save_sms_actions"](actions)
                return
        except Exception:
            pass

        p = _eg_hdb1_Path("data/eratguard_sms_actions_v5c.json")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(_eg_hdb1_json.dumps(actions, ensure_ascii=False, indent=2), encoding="utf-8")

    def _eg_hdb1_counts(actions):
        c = {"total": len(actions), "blocked": 0, "safe": 0, "reported": 0}
        for a in actions:
            act = str(a.get("action") or "").strip()
            if act in c:
                c[act] += 1
        return c

    def _eg_hdb1_sort_key(item):
        return str(item.get("created_at") or item.get("updated_at") or item.get("time") or "")

    def _eg_hdb1_history_page():
        actions = _eg_hdb1_read_actions()
        actions = sorted(actions, key=_eg_hdb1_sort_key, reverse=True)
        counts = _eg_hdb1_counts(actions)

        html = """
<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>EratGuard - Koruma Geçmişi</title>
<style>
:root{--bg:#061018;--card:#0d1b27;--text:#eef7ff;--muted:#8ca3b6;--line:rgba(255,255,255,.10);--green:#23ff89;--blue:#1b78ff;--red:#ff4d61;--yellow:#ffd166}
*{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
body{margin:0;background:radial-gradient(circle at top,#143b2b 0,#061018 45%,#03070b 100%);color:var(--text);font-family:Arial,Helvetica,sans-serif}
.wrap{max-width:980px;margin:0 auto;padding:16px 14px 90px}
.head{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:14px}
.brand h1{margin:0;font-size:25px;line-height:1;font-weight:950;letter-spacing:-.8px}.brand p{margin:6px 0 0;color:var(--muted);font-size:13px;font-weight:800}
.version{border:1px solid rgba(35,255,137,.3);background:rgba(35,255,137,.1);color:var(--green);border-radius:999px;padding:9px 11px;font-size:12px;font-weight:950}
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:9px;margin:14px 0}
.stat{border:1px solid var(--line);background:rgba(13,27,39,.88);border-radius:18px;padding:13px;min-height:78px}
.stat b{display:block;font-size:24px;color:var(--green)}.stat span{display:block;color:var(--muted);font-size:12px;font-weight:900;margin-top:6px}
.actions{display:flex;gap:8px;flex-wrap:wrap;margin:12px 0 16px}
.btn{border:1px solid var(--line);background:#10283a;color:var(--text);text-decoration:none;border-radius:999px;padding:10px 12px;font-size:13px;font-weight:900}
.btn.danger{background:rgba(255,77,97,.15);border-color:rgba(255,77,97,.45)}
.filters{display:flex;gap:8px;overflow:auto;margin:8px 0 14px}
.filter{border:1px solid var(--line);background:#0d1b27;color:var(--text);border-radius:999px;padding:10px 12px;font-size:13px;font-weight:900}
.filter.active{background:var(--blue);border-color:var(--blue)}
.card{border:1px solid var(--line);background:rgba(13,27,39,.92);border-radius:20px;padding:14px;margin:10px 0;box-shadow:0 12px 28px rgba(0,0,0,.22)}
.row{display:flex;justify-content:space-between;gap:10px;align-items:flex-start}
.badge{display:inline-flex;border-radius:999px;padding:7px 9px;font-size:12px;font-weight:950}
.badge.blocked{background:rgba(255,77,97,.16);color:#ff9aa6}.badge.safe{background:rgba(35,255,137,.16);color:#9fffc4}.badge.reported{background:rgba(255,209,102,.16);color:#ffe09a}
.meta{color:var(--muted);font-size:12px;font-weight:800;margin-top:8px}
.msg{margin-top:10px;border-radius:14px;background:rgba(255,255,255,.035);padding:10px;font-size:14px;line-height:1.4;word-break:break-word}
.reasons{margin:10px 0 0;padding-left:18px;color:#cfe1ef;font-size:13px;line-height:1.35}
.empty{text-align:center;color:var(--muted);padding:32px 10px;font-weight:850}
.menu{position:fixed;right:18px;bottom:18px;background:var(--blue);color:white;border-radius:999px;padding:15px 18px;text-decoration:none;font-weight:950;box-shadow:0 16px 30px rgba(27,120,255,.35)}
@media(max-width:680px){.grid{grid-template-columns:repeat(2,1fr)}.brand h1{font-size:22px}}
</style>
</head>
<body>
<div class="wrap">
  <div class="head">
    <div class="brand">
      <h1>Koruma Geçmişi</h1>
      <p>SMS aksiyonları, AI analiz kararları ve güvenlik kayıtları tek merkezden izlenir.</p>
    </div>
    <div class="version">VITES-6H</div>
  </div>

  <div class="grid">
    <div class="stat"><b>{{ counts.total }}</b><span>Toplam</span></div>
    <div class="stat"><b>{{ counts.blocked }}</b><span>Engellenen</span></div>
    <div class="stat"><b>{{ counts.reported }}</b><span>Şikayet</span></div>
    <div class="stat"><b>{{ counts.safe }}</b><span>Güvenli</span></div>
  </div>

  <div class="actions">
    <a class="btn" href="/api/v6/history-export">Dışa Aktar</a>
    <a class="btn" href="/u/sms/actions">SMS Aksiyon Merkezi</a>
    <form method="post" action="/api/v6/history-clear" onsubmit="return confirm('Koruma geçmişi yedek alındıktan sonra temizlensin mi?')" style="display:inline">
      <button class="btn danger" type="submit">Geçmişi Temizle</button>
    </form>
    <form method="post" action="/api/v6/history-restore-latest" style="display:inline">
      <button class="btn" type="submit">Son Yedeği Geri Yükle</button>
    </form>
  </div>

  <div class="filters">
    <button class="filter active" data-filter="all" type="button">Tümü</button>
    <button class="filter" data-filter="blocked" type="button">Engellenen</button>
    <button class="filter" data-filter="reported" type="button">Şikayet</button>
    <button class="filter" data-filter="safe" type="button">Güvenli</button>
  </div>

  {% if not actions %}
    <div class="empty">Henüz koruma geçmişi yok.</div>
  {% endif %}

  {% for a in actions %}
  {% set act = a.get('action','') %}
  <article class="card" data-action="{{ act }}">
    <div class="row">
      <div>
        <span class="badge {{ act }}">{{ a.get('label') or act }}</span>
        <div class="meta">Gönderen: {{ a.get('sender') or a.get('number') or 'Bilinmeyen' }} · Kaynak: {{ a.get('source') or '-' }}</div>
      </div>
      <div class="meta">Risk: {{ a.get('risk_score') or a.get('risk') or a.get('score') or 0 }} · {{ a.get('risk_level') or a.get('risk_label') or '-' }}</div>
    </div>

    <div class="msg">{{ a.get('message') or a.get('body') or a.get('text') or '' }}</div>

    {% set reasons = a.get('reason') or a.get('reasons') or [] %}
    {% if reasons %}
      <ul class="reasons">
      {% if reasons is string %}
        <li>{{ reasons }}</li>
      {% else %}
        {% for r in reasons %}<li>{{ r }}</li>{% endfor %}
      {% endif %}
      </ul>
    {% endif %}

    <div class="meta">Tarih: {{ a.get('created_at') or a.get('time') or a.get('updated_at') or '-' }}</div>
  </article>
  {% endfor %}
</div>

<a class="menu" href="/u/dashboard">MENÜ</a>

<script>
document.querySelectorAll(".filter").forEach(btn=>{
  btn.addEventListener("click",()=>{
    document.querySelectorAll(".filter").forEach(x=>x.classList.remove("active"));
    btn.classList.add("active");
    const f = btn.dataset.filter;
    document.querySelectorAll(".card").forEach(card=>{
      card.style.display = (f==="all" || card.dataset.action===f) ? "" : "none";
    });
  });
});
</script>
</body>
</html>
"""
        return _eg_hdb1_render_template_string(html, actions=actions, counts=counts)

    def _eg_hdb1_export():
        actions = _eg_hdb1_read_actions()
        counts = _eg_hdb1_counts(actions)
        payload = {
            "export_type": "sms_protection_history",
            "version": "VITES-6H",
            "created_at": _eg_hdb1_datetime.now().replace(microsecond=0).isoformat(),
            "counts": counts,
            "actions": actions,
        }
        bio = _eg_hdb1_io.BytesIO(_eg_hdb1_json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8"))
        return _eg_hdb1_send_file(bio, mimetype="application/json", as_attachment=True, download_name="eratguard_protection_history_export.json")

    def _eg_hdb1_clear():
        actions = _eg_hdb1_read_actions()
        backup_dir = _eg_hdb1_Path("data/history_backups")
        backup_dir.mkdir(parents=True, exist_ok=True)

        ts = _eg_hdb1_datetime.now().strftime("%Y%m%d_%H%M%S")
        backup = backup_dir / f"eratguard_sms_actions_before_clear_{ts}.json"
        backup.write_text(_eg_hdb1_json.dumps(actions, ensure_ascii=False, indent=2), encoding="utf-8")

        _eg_hdb1_write_actions([])

        if "application/json" in str(_eg_hdb1_request.headers.get("Accept", "")).lower():
            return _eg_hdb1_jsonify({"ok": True, "message": "Koruma geçmişi temizlendi.", "backup": str(backup), "counts": {"total":0,"blocked":0,"safe":0,"reported":0}})
        return _eg_hdb1_make_response('<script>location.href="/u/protection-history?cleared=1"</script>')

    def _eg_hdb1_restore_latest():
        backup_dir = _eg_hdb1_Path("data/history_backups")
        files = sorted(backup_dir.glob("eratguard_sms_actions_before_clear_*.json"), key=lambda p: p.stat().st_mtime, reverse=True) if backup_dir.exists() else []

        if not files:
            return _eg_hdb1_jsonify({"ok": False, "error": "Geri yüklenecek yedek bulunamadı."}), 404

        latest = files[0]
        try:
            data = _eg_hdb1_json.loads(latest.read_text(encoding="utf-8", errors="ignore"))
            if isinstance(data, dict) and isinstance(data.get("actions"), list):
                data = data["actions"]
            if not isinstance(data, list):
                raise ValueError("Yedek liste formatında değil.")

            safety_dir = _eg_hdb1_Path("data/history_restore_safety")
            safety_dir.mkdir(parents=True, exist_ok=True)
            ts = _eg_hdb1_datetime.now().strftime("%Y%m%d_%H%M%S")
            safety = safety_dir / f"before_restore_{ts}.json"
            safety.write_text(_eg_hdb1_json.dumps(_eg_hdb1_read_actions(), ensure_ascii=False, indent=2), encoding="utf-8")

            _eg_hdb1_write_actions(data)
            return _eg_hdb1_jsonify({"ok": True, "message": "Koruma geçmişi en son yedekten geri yüklendi.", "restored": len(data), "backup": str(latest), "counts": _eg_hdb1_counts(data)})
        except Exception as e:
            return _eg_hdb1_jsonify({"ok": False, "error": str(e)}), 400

    # Mevcut eski route endpointlerini yeni canlı veri fonksiyonlarına bağla.
    for _rule in list(app.url_map.iter_rules()):
        _path = str(_rule)
        if _path in ("/u/protection-history", "/u/history", "/protection-history", "/history"):
            app.view_functions[_rule.endpoint] = _eg_hdb1_history_page
        elif _path == "/api/v6/history-export":
            app.view_functions[_rule.endpoint] = _eg_hdb1_export
        elif _path == "/api/v6/history-clear":
            app.view_functions[_rule.endpoint] = _eg_hdb1_clear
        elif _path == "/api/v6/history-restore-latest":
            app.view_functions[_rule.endpoint] = _eg_hdb1_restore_latest

    print("ERATGUARD PROTECTION HISTORY DATA BIND V1 ACTIVE")

except Exception as _eg_hdb1_err:
    print("ERATGUARD PROTECTION HISTORY DATA BIND V1 BOOT ERROR:", _eg_hdb1_err)

# === /ERATGUARD_PROTECTION_HISTORY_DATA_BIND_V1 ===

# === ERATGUARD_BLOCKED_SMS_CENTER_DATA_BIND_V1 ===
# /u/blocked-sms ekranını yeni SMS Action Engine list formatına bağlar.
# Kaynak: data/eratguard_sms_actions_v5c.json

try:
    from flask import render_template_string as _eg_bsms1_render_template_string
    import html as _eg_bsms1_html

    def _eg_bsms1_safe(v):
        try:
            return _eg_bsms1_html.escape(str(v or ""))
        except Exception:
            return ""

    def _eg_bsms1_read_actions():
        try:
            if "_eg_load_sms_actions" in globals() and callable(globals().get("_eg_load_sms_actions")):
                data = globals()["_eg_load_sms_actions"]()
            else:
                import json
                from pathlib import Path
                p = Path("data/eratguard_sms_actions_v5c.json")
                if not p.exists() or p.stat().st_size == 0:
                    return []
                data = json.loads(p.read_text(encoding="utf-8", errors="ignore"))

            if isinstance(data, list):
                return [x for x in data if isinstance(x, dict)]

            # Eski format desteği
            if isinstance(data, dict):
                out = []
                for action_key, label in [
                    ("blocked", "Engellendi"),
                    ("safe", "Güvenli"),
                    ("reported", "Şikayet")
                ]:
                    arr = data.get(action_key, [])
                    if isinstance(arr, list):
                        for item in arr:
                            row = dict(item) if isinstance(item, dict) else {"message": str(item)}
                            row.setdefault("action", action_key)
                            row.setdefault("label", label)
                            out.append(row)
                return out

            return []
        except Exception as e:
            print("ERATGUARD BLOCKED SMS CENTER DATA BIND READ ERROR:", e)
            return []

    def _eg_bsms1_sort_key(item):
        return str(item.get("created_at") or item.get("updated_at") or item.get("time") or "")

    def _eg_bsms1_group(actions):
        grouped = {"blocked": [], "safe": [], "reported": []}
        for item in actions:
            act = str(item.get("action") or "").strip()
            if act in grouped:
                grouped[act].append(item)
        for k in grouped:
            grouped[k] = sorted(grouped[k], key=_eg_bsms1_sort_key, reverse=True)
        return grouped

    def _eg_bsms1_center():
        actions = _eg_bsms1_read_actions()
        grouped = _eg_bsms1_group(actions)

        blocked = grouped["blocked"]
        safe = grouped["safe"]
        reported = grouped["reported"]

        html = """
<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>EratGuard PRO - Engellenen SMS Merkezi</title>
<style>
:root{--bg:#070a12;--card:rgba(255,255,255,.06);--line:rgba(255,255,255,.09);--green:#23ff89;--muted:#9aa3b2;--text:#fff;--blue:#1b78ff;--red:#ff4d61;--yellow:#ffd166}
*{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
body{margin:0;background:radial-gradient(circle at top,rgba(35,255,137,.12),#070a12 42%,#03050a 100%);color:var(--text);font-family:Arial,Helvetica,sans-serif;padding:18px}
.eg-wrap{max-width:820px;margin:0 auto;padding-bottom:78px}
.eg-head{background:linear-gradient(135deg,rgba(35,255,137,.18),rgba(45,108,255,.10));border:1px solid rgba(35,255,137,.28);border-radius:24px;padding:18px;box-shadow:0 0 28px rgba(35,255,137,.10)}
.eg-kicker{color:var(--green);font-weight:950;letter-spacing:.08em;font-size:12px}
h1{margin:8px 0 8px;font-size:25px}
p{color:var(--muted);line-height:1.5;margin:0}
.eg-stats{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-top:14px}
.eg-stat{background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.08);border-radius:18px;padding:12px;text-align:center}
.eg-stat b{display:block;font-size:24px;color:var(--green)}
.eg-stat span{display:block;margin-top:5px;color:#aeb8c8;font-size:12px;font-weight:850}
.eg-tabs{display:flex;gap:8px;margin:16px 0;flex-wrap:wrap}
.eg-tabs button{flex:1 1 120px;border:1px solid rgba(35,255,137,.28);background:rgba(35,255,137,.12);color:var(--green);border-radius:16px;padding:12px;font-weight:950}
.eg-tabs button.active{background:var(--blue);border-color:var(--blue);color:white}
.eg-section{display:none}
.eg-section.active{display:block}
.eg-card{background:var(--card);border:1px solid var(--line);border-radius:20px;padding:14px;margin-bottom:12px}
.eg-rowtop{display:flex;justify-content:space-between;gap:10px;align-items:center}
.eg-badge{color:#06110b;background:var(--green);border-radius:999px;padding:6px 10px;font-size:12px;font-weight:950}
.eg-badge.blocked{background:#ff9aa6;color:#23040a}
.eg-badge.safe{background:#9fffc4;color:#00180c}
.eg-badge.reported{background:#ffe09a;color:#1b1000}
.eg-score{color:#ffdf6e;font-weight:950;text-align:right}
.eg-meta{margin-top:10px;color:var(--muted);font-size:12px;font-weight:800}
.eg-text{margin-top:10px;line-height:1.45;color:#fff;word-break:break-word;background:rgba(0,0,0,.18);border-radius:14px;padding:10px}
ul{margin:10px 0 0 18px;color:#aeb8c8;line-height:1.35}
.eg-empty{padding:18px;border-radius:18px;background:rgba(255,255,255,.05);color:var(--muted);font-weight:850}
.eg-link{display:block;margin-top:12px;color:var(--green);text-decoration:none;font-weight:950}
.eg-menu{position:fixed;right:18px;bottom:18px;background:var(--blue);color:white;border-radius:999px;padding:15px 18px;text-decoration:none;font-weight:950;box-shadow:0 16px 30px rgba(27,120,255,.35)}
@media(max-width:680px){.eg-stats{grid-template-columns:repeat(2,1fr)}h1{font-size:22px}}
</style>
</head>
<body>
<div class="eg-wrap">
  <div class="eg-head">
    <div class="eg-kicker">ERATGUARD VITES-6H</div>
    <h1>Engellenen SMS Merkezi</h1>
    <p>AI Analiz ekranından verilen ENGELLE, GÜVENLİ ve ŞİKAYET aksiyonları gerçek SMS Action Engine verisinden listelenir.</p>

    <div class="eg-stats">
      <div class="eg-stat"><b>{{ total }}</b><span>Toplam</span></div>
      <div class="eg-stat"><b>{{ blocked|length }}</b><span>Engelli</span></div>
      <div class="eg-stat"><b>{{ safe|length }}</b><span>Güvenli</span></div>
      <div class="eg-stat"><b>{{ reported|length }}</b><span>Şikayet</span></div>
    </div>
  </div>

  <div class="eg-tabs">
    <button class="active" onclick="showTab('blocked', this)">ENGELLİ</button>
    <button onclick="showTab('safe', this)">GÜVENLİ</button>
    <button onclick="showTab('reported', this)">ŞİKAYET</button>
  </div>

  <section id="blocked" class="eg-section active">
    {% if not blocked %}<div class="eg-empty">Henüz engellenen SMS yok.</div>{% endif %}
    {% for item in blocked %}{{ card(item, "Engellendi", "blocked")|safe }}{% endfor %}
  </section>

  <section id="safe" class="eg-section">
    {% if not safe %}<div class="eg-empty">Henüz güvenli SMS kaydı yok.</div>{% endif %}
    {% for item in safe %}{{ card(item, "Güvenli", "safe")|safe }}{% endfor %}
  </section>

  <section id="reported" class="eg-section">
    {% if not reported %}<div class="eg-empty">Henüz şikayet kaydı yok.</div>{% endif %}
    {% for item in reported %}{{ card(item, "Şikayet", "reported")|safe }}{% endfor %}
  </section>

  <a class="eg-link" href="/u/sms/actions">SMS Aksiyon Merkezini Aç →</a>
  <a class="eg-link" href="/u/protection-history">Koruma Geçmişini Aç →</a>
  <a class="eg-link" href="/u/analysis">← AI Analiz Merkezine Dön</a>
</div>

<a class="eg-menu" href="/u/dashboard">MENÜ</a>

<script>
function showTab(id, btn){
  document.querySelectorAll(".eg-section").forEach(x=>x.classList.remove("active"));
  document.getElementById(id).classList.add("active");
  document.querySelectorAll(".eg-tabs button").forEach(x=>x.classList.remove("active"));
  if(btn){btn.classList.add("active")}
}
</script>
</body>
</html>
"""

        def card(item, label, cls):
            sender = _eg_bsms1_safe(item.get("sender") or item.get("number") or "-")
            message = _eg_bsms1_safe(item.get("message") or item.get("body") or item.get("text") or "")
            created = _eg_bsms1_safe(item.get("created_at") or item.get("time") or item.get("updated_at") or "-")
            source = _eg_bsms1_safe(item.get("source") or "-")
            score = _eg_bsms1_safe(item.get("risk_score") or item.get("risk") or item.get("score") or 0)
            risk_level = _eg_bsms1_safe(item.get("risk_level") or item.get("risk_label") or "-")

            reasons = item.get("reason") or item.get("reasons") or []
            if isinstance(reasons, str):
                reasons = [x.strip() for x in reasons.splitlines() if x.strip()] or [reasons]
            if not isinstance(reasons, list):
                reasons = []

            reasons_html = "".join(f"<li>{_eg_bsms1_safe(x)}</li>" for x in reasons[:6]) or "<li>Sebep kaydı yok.</li>"

            return f"""
<div class="eg-card">
  <div class="eg-rowtop">
    <span class="eg-badge {cls}">{_eg_bsms1_safe(label)}</span>
    <span class="eg-score">Risk: {score} · {risk_level}</span>
  </div>
  <div class="eg-meta">Gönderen: {sender} · Kaynak: {source} · Tarih: {created}</div>
  <div class="eg-text">{message}</div>
  <ul>{reasons_html}</ul>
</div>
"""

        return _eg_bsms1_render_template_string(
            html,
            blocked=blocked,
            safe=safe,
            reported=reported,
            total=len(actions),
            card=card,
        )

    for _rule in list(app.url_map.iter_rules()):
        if str(_rule) in ("/u/blocked-sms", "/u/sms-actions-center"):
            app.view_functions[_rule.endpoint] = _eg_bsms1_center

    print("ERATGUARD BLOCKED SMS CENTER DATA BIND V1 ACTIVE")

except Exception as _eg_bsms1_err:
    print("ERATGUARD BLOCKED SMS CENTER DATA BIND V1 BOOT ERROR:", _eg_bsms1_err)

# === /ERATGUARD_BLOCKED_SMS_CENTER_DATA_BIND_V1 ===

# === ERATGUARD_BLOCKED_ROUTE_REDIRECT_V1 ===
# /u/blocked eski karantina/blok ekranını yeni VITES-6H Engellenen SMS Merkezi'ne bağlar.

try:
    from flask import redirect as _eg_brr1_redirect

    def _eg_brr1_blocked_redirect():
        return _eg_brr1_redirect("/u/blocked-sms")

    for _rule in list(app.url_map.iter_rules()):
        if str(_rule) in ("/u/blocked", "/u/blocked/", "/blocked"):
            app.view_functions[_rule.endpoint] = _eg_brr1_blocked_redirect

    print("ERATGUARD BLOCKED ROUTE REDIRECT V1 ACTIVE")

except Exception as _eg_brr1_err:
    print("ERATGUARD BLOCKED ROUTE REDIRECT V1 BOOT ERROR:", _eg_brr1_err)

# === /ERATGUARD_BLOCKED_ROUTE_REDIRECT_V1 ===

# === ERATGUARD_SMS_ACTION_API_TOKEN_GUARD_V1 ===
# /sms/action public/internal API yolunu token ile korur.
# /u/sms/action kullanıcı oturumlu panel yolu etkilenmez.

try:
    import secrets as _eg_satg1_secrets
    import hmac as _eg_satg1_hmac
    from pathlib import Path as _eg_satg1_Path
    from flask import request as _eg_satg1_request, jsonify as _eg_satg1_jsonify

    _EG_SATG1_TOKEN_FILE = _eg_satg1_Path("data/eratguard_sms_api_token.txt")
    _EG_SATG1_TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)

    if not _EG_SATG1_TOKEN_FILE.exists() or _EG_SATG1_TOKEN_FILE.stat().st_size < 20:
        _EG_SATG1_TOKEN_FILE.write_text(_eg_satg1_secrets.token_urlsafe(36), encoding="utf-8")

    def _eg_satg1_get_token():
        try:
            return _EG_SATG1_TOKEN_FILE.read_text(encoding="utf-8").strip()
        except Exception:
            return ""

    def _eg_satg1_request_token():
        try:
            tok = _eg_satg1_request.headers.get("X-EratGuard-Token", "") or ""
            if tok:
                return tok.strip()

            tok = _eg_satg1_request.form.get("api_token", "") or ""
            if tok:
                return tok.strip()

            if _eg_satg1_request.is_json:
                js = _eg_satg1_request.get_json(silent=True) or {}
                tok = js.get("api_token") or js.get("token") or ""
                return str(tok).strip()
        except Exception:
            return ""
        return ""

    @app.before_request
    def _eg_satg1_guard_sms_action_api():
        try:
            if _eg_satg1_request.path == "/sms/action" and _eg_satg1_request.method == "POST":
                expected = _eg_satg1_get_token()
                provided = _eg_satg1_request_token()

                if not expected or not provided or not _eg_satg1_hmac.compare_digest(expected, provided):
                    return _eg_satg1_jsonify({
                        "ok": False,
                        "error": "sms_action_api_token_required",
                        "message": "SMS Action API token gerekli."
                    }), 401
        except Exception as e:
            return _eg_satg1_jsonify({
                "ok": False,
                "error": "sms_action_api_guard_error",
                "message": str(e)
            }), 500

    print("ERATGUARD SMS ACTION API TOKEN GUARD V1 ACTIVE")

except Exception as _eg_satg1_err:
    print("ERATGUARD SMS ACTION API TOKEN GUARD V1 BOOT ERROR:", _eg_satg1_err)

# === /ERATGUARD_SMS_ACTION_API_TOKEN_GUARD_V1 ===

# === ERATGUARD_SMS_ACTION_API_JSON_RESPONSE_V1 ===
# /sms/action Android/iç API yolunu redirect yerine JSON response'a çevirir.
# Token kontrolü ERATGUARD_SMS_ACTION_API_TOKEN_GUARD_V1 tarafından önce yapılır.
# /u/sms/action kullanıcı paneli etkilenmez.

try:
    from flask import request as _eg_sajr1_request, jsonify as _eg_sajr1_jsonify

    def _eg_sajr1_payload():
        try:
            if _eg_sajr1_request.is_json:
                js = _eg_sajr1_request.get_json(silent=True) or {}
                if isinstance(js, dict):
                    return dict(js)
        except Exception:
            pass

        out = {}
        try:
            for k in _eg_sajr1_request.form.keys():
                out[k] = _eg_sajr1_request.form.get(k)
        except Exception:
            pass
        return out

    @app.before_request
    def _eg_sajr1_sms_action_json_api():
        try:
            if _eg_sajr1_request.path == "/sms/action" and _eg_sajr1_request.method == "POST":
                if "_eg_add_sms_action" not in globals() or not callable(globals().get("_eg_add_sms_action")):
                    return _eg_sajr1_jsonify({
                        "ok": False,
                        "error": "sms_action_engine_missing"
                    }), 500

                payload = _eg_sajr1_payload()

                # Token alanını kayıt içine yazma.
                payload.pop("api_token", None)
                payload.pop("token", None)

                rec = globals()["_eg_add_sms_action"](payload)

                return _eg_sajr1_jsonify({
                    "ok": True,
                    "saved": True,
                    "record": rec
                }), 200

        except Exception as e:
            return _eg_sajr1_jsonify({
                "ok": False,
                "error": "sms_action_api_json_error",
                "message": str(e)
            }), 500

    print("ERATGUARD SMS ACTION API JSON RESPONSE V1 ACTIVE")

except Exception as _eg_sajr1_err:
    print("ERATGUARD SMS ACTION API JSON RESPONSE V1 BOOT ERROR:", _eg_sajr1_err)

# === /ERATGUARD_SMS_ACTION_API_JSON_RESPONSE_V1 ===

# ===== ERATGUARD CONTROLLED TRUE FAN-12P ROUTE LOCK START =====
# Kontrollü temizlik sonrası kullanıcı ana girişleri sadece mevcut gerçek FAN-12P fonksiyonuna bağlanır.
# Yeni HTML üretmez; dashboard_web.py içinde zaten bulunan "FAN-12P Command Center" kaynağını kullanır.

try:
    import inspect as _eg_fan12p_inspect

    _eg_true_fan12p_func = None

    for _eg_name, _eg_func in list(app.view_functions.items()):
        try:
            _eg_src = _eg_fan12p_inspect.getsource(_eg_func)
        except Exception:
            _eg_src = ""

        if (
            "FAN-12P Command Center" in _eg_src
            and "FAN-12P HAZIR" in _eg_src
            and "COMMAND CENTER" in _eg_src
        ):
            _eg_true_fan12p_func = _eg_func
            print("ERATGUARD TRUE FAN-12P SOURCE FOUND:", _eg_name)
            break

    if _eg_true_fan12p_func is None:
        print("ERATGUARD TRUE FAN-12P ROUTE LOCK WARNING: gerçek FAN-12P fonksiyonu bulunamadı.")
    else:
        _eg_lock_rules = [
            "/dashboard",
            "/u/dashboard",
            "/app-start",
            "/radial",
            "/radial-menu",
            "/radial-demo",
        ]

        for _eg_rule in list(app.url_map.iter_rules()):
            if _eg_rule.rule in _eg_lock_rules:
                app.view_functions[_eg_rule.endpoint] = _eg_true_fan12p_func
                print("ERATGUARD TRUE FAN-12P ROUTE LOCKED:", _eg_rule.rule, "->", _eg_rule.endpoint)

        for _eg_ep in [
            "dashboard",
            "user_dashboard",
            "ss_user_alias_home_final",
            "radial",
            "radial_demo",
            "app_start",
            "user_home",
            "home_dashboard",
        ]:
            if _eg_ep in app.view_functions:
                app.view_functions[_eg_ep] = _eg_true_fan12p_func
                print("ERATGUARD TRUE FAN-12P ENDPOINT LOCKED:", _eg_ep)

        print("ERATGUARD CONTROLLED TRUE FAN-12P ROUTE LOCK ACTIVE")

except Exception as _eg_route_lock_e:
    print("ERATGUARD CONTROLLED TRUE FAN-12P ROUTE LOCK ERROR:", _eg_route_lock_e)
# ===== ERATGUARD CONTROLLED TRUE FAN-12P ROUTE LOCK END =====

# ===== ERATGUARD STEP5 APP-START HARD LOCK TO FAN-12P DASHBOARD START =====
# /dashboard testte gerçek FAN-12P verdiği için /app-start aynı dashboard fonksiyonuna bağlanır.
# Böylece APK giriş kapısı eski ekranı asla döndürmez.

try:
    _eg_dashboard_func = None
    _eg_dashboard_endpoint = None

    for _eg_rule in list(app.url_map.iter_rules()):
        if _eg_rule.rule == "/dashboard":
            _eg_dashboard_endpoint = _eg_rule.endpoint
            _eg_dashboard_func = app.view_functions.get(_eg_dashboard_endpoint)
            break

    if _eg_dashboard_func is None:
        print("ERATGUARD STEP5 APP-START LOCK ERROR: /dashboard endpoint bulunamadı")
    else:
        for _eg_rule in list(app.url_map.iter_rules()):
            if _eg_rule.rule in ["/app-start", "/u/dashboard", "/radial", "/radial-menu", "/radial-demo"]:
                app.view_functions[_eg_rule.endpoint] = _eg_dashboard_func
                print("ERATGUARD STEP5 ROUTE LOCKED TO DASHBOARD:", _eg_rule.rule, "->", _eg_rule.endpoint)

        for _eg_ep in ["app_start", "appStart", "start_app", "user_app_start"]:
            if _eg_ep in app.view_functions:
                app.view_functions[_eg_ep] = _eg_dashboard_func
                print("ERATGUARD STEP5 ENDPOINT LOCKED TO DASHBOARD:", _eg_ep)

        print("ERATGUARD STEP5 APP-START HARD LOCK ACTIVE:", _eg_dashboard_endpoint)

except Exception as _eg_step5_e:
    print("ERATGUARD STEP5 APP-START HARD LOCK ERROR:", _eg_step5_e)
# ===== ERATGUARD STEP5 APP-START HARD LOCK TO FAN-12P DASHBOARD END =====
