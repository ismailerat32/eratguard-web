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


def _eg_get_last_scan_time():
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



from admin import admin_bp
app = Flask(__name__)

app.register_blueprint(admin_bp)


# ===== ERATGUARD SECURE SESSION SECRET START =====
import os as _eg_secret_os

app.secret_key = (
    _eg_secret_os.environ.get("ERATGUARD_SECRET_KEY")
    or _eg_secret_os.environ.get("FLASK_SECRET_KEY")
    or _eg_secret_os.environ.get("SECRET_KEY")
)

if not app.secret_key:
    raise RuntimeError(
        "Session secret tanimli degil. "
        "ERATGUARD_SECRET_KEY environment variable ayarlanmalidir."
    )

app.config["SECRET_KEY"] = app.secret_key
# Canonical EratGuard browser-session policy.
#
# Production/default:
#     Secure cookie required.
#
# Local HTTP development may explicitly opt out with:
#     ERATGUARD_DEV_INSECURE_COOKIE=1
#
# Never infer an insecure cookie merely from request headers.
_eg_dev_insecure_cookie = (
    str(_eg_secret_os.environ.get(
        "ERATGUARD_DEV_INSECURE_COOKIE",
        ""
    )).strip().lower()
    in {"1", "true", "yes", "on"}
)

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = not _eg_dev_insecure_cookie
app.config["SESSION_COOKIE_NAME"] = "eratguard_session"
app.config["SESSION_REFRESH_EACH_REQUEST"] = False

# ===== ERATGUARD SECURE SESSION SECRET END =====

# ===== ERATGUARD SECURITY SHIELD CSRF CORE V1 =====
#
# SECURITY-SHIELD-04A:
#   AUDIT MODE ONLY.
#
# This stage creates the canonical CSRF primitive without rejecting
# requests yet. Enforcement is enabled only after browser forms/fetch
# callers have been token-bound and verified.
#
# Browser token sources:
#   form field : csrf_token
#   HTTP header: X-CSRF-Token
#
# Exemptions here are authentication-boundary exemptions, not
# "trusted because of path" shortcuts.
#
import hmac as _eg_csrf_hmac
import secrets as _eg_csrf_secrets

_EG_CSRF_SESSION_KEY = "_eg_csrf_token"
_EG_CSRF_HEADER = "X-CSRF-Token"
_EG_CSRF_FORM_FIELD = "csrf_token"

# Native/token-authenticated SMS boundary. These are NOT protected by
# browser-session CSRF; their own API authentication remains mandatory.
_EG_CSRF_NATIVE_API_EXEMPT = frozenset({
    "/api/v5/sms-action",
    "/api/v5/sms-risk",
})

# API_PUSH_KEY authenticated machine endpoint.
_EG_CSRF_MACHINE_API_EXEMPT = frozenset({
    "/api/push-log",
    "/api/mobile/login",
})


def _eg_csrf_token():
    token = session.get(_EG_CSRF_SESSION_KEY)

    if not isinstance(token, str) or len(token) < 32:
        token = _eg_csrf_secrets.token_urlsafe(32)
        session[_EG_CSRF_SESSION_KEY] = token

    return token


def _eg_csrf_supplied_token():
    token = request.headers.get(_EG_CSRF_HEADER, "")

    if token:
        return str(token).strip()

    return str(
        request.form.get(
            _EG_CSRF_FORM_FIELD,
            ""
        )
    ).strip()


def _eg_csrf_valid():
    expected = session.get(_EG_CSRF_SESSION_KEY)
    supplied = _eg_csrf_supplied_token()

    if not isinstance(expected, str):
        return False

    if not expected or not supplied:
        return False

    return _eg_csrf_hmac.compare_digest(
        expected,
        supplied,
    )


def _eg_csrf_exempt_request():
    path = (request.path or "").rstrip("/") or "/"

    if path in _EG_CSRF_NATIVE_API_EXEMPT:
        return True

    if path in _EG_CSRF_MACHINE_API_EXEMPT:
        return True

    return False


def _eg_csrf_audit_state():
    """
    SECURITY-SHIELD-04A diagnostic helper.

    No request is rejected here.
    """
    method = request.method.upper()

    if method not in {
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
    }:
        return "SAFE_METHOD"

    if _eg_csrf_exempt_request():
        return "EXEMPT_API"

    if _eg_csrf_valid():
        return "VALID"

    return "MISSING_OR_INVALID"


def _eg_csrf_failure_response():
    """
    Fail closed without exposing token/session details.

    JSON/API-style callers receive JSON.
    Browser form callers receive a small 403 response.
    """
    path = request.path or ""

    wants_json = (
        request.is_json
        or path.startswith("/api/")
        or path.startswith("/u/sms/")
        or request.headers.get(
            "Accept",
            ""
        ).lower().find("application/json") >= 0
    )

    if wants_json:
        return jsonify({
            "ok": False,
            "error": "CSRF validation failed",
        }), 403

    return (
        "İstek güvenlik doğrulamasından geçemedi.",
        403,
    )


@app.before_request
def _eg_csrf_enforce():
    """
    Canonical browser-session CSRF boundary.

    Safe methods are untouched.

    Explicit native/machine API boundaries retain their own
    authentication and are exempt from browser-session CSRF.

    Every other POST/PUT/PATCH/DELETE fails closed unless its
    synchronizer token matches the session token.
    """
    method = request.method.upper()

    if method not in {
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
    }:
        return None

    if _eg_csrf_exempt_request():
        return None

    if _eg_csrf_valid():
        return None

    return _eg_csrf_failure_response()


@app.context_processor
def _eg_csrf_template_context():
    return {
        "csrf_token": _eg_csrf_token,
    }

# ===== /ERATGUARD SECURITY SHIELD CSRF CORE V1 =====


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
        with open(USERS_FILE, "w", encoding="utf-8") as f:
            json.dump({}, f, ensure_ascii=False, indent=2)


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

# ERATGUARD ADMIN CORE — MAIL DIAGNOSTIC DATA WIRING
from admin.routes import configure_mail_diagnostic_runtime

configure_mail_diagnostic_runtime(
    load_users=load_users,
)



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

    if (
        not expected_key
        or not api_key
        or not __import__("hmac").compare_digest(expected_key, api_key)
    ):
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

            trial_expires_at = _eg_trial_expiry_v1()

            users[username] = {
                "password": generate_password_hash(password),
                "role": "user",
                "active": True,
                "license_key": "NONE",
                "license_type": "trial",
                "plan": "trial",
                "license_status": "trial",
                "trial_started_at": now,
                "trial_expires_at": trial_expires_at,
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
        elif check_password_hash(user["password"], password):
            _eg_login_clear_failures(username)

            # Authentication boundary:
            # discard all pre-auth session state before establishing
            # the authenticated user session. This prevents attacker-
            # controlled/pre-login session data from surviving login.
            session.clear()

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
            return redirect("/u/eg-panel")
        else:
            count = _eg_login_record_failure(username)
            _eg_audit_log("login_failed", username, {"reason": "bad_password", "count": count}, "warning")
            error = "Kullanıcı adı veya şifre yanlış." if get_lang() == "tr" else "Username or password is incorrect."

    return render_template("login.html", error=error, t=t, lang=get_lang())



@app.route("/logout", methods=["POST"])
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


@app.route("/set-lang/<lang>")
def set_lang(lang):
    if lang in ["tr", "en"]:
        session["lang"] = lang
    return redirect(request.referrer or "/u/eg-panel")

@app.route("/splash")
def splash():
    return render_template("splash.html")

@app.route("/splash_admin")
def splash_admin():
    return render_template("splash_admin.html")

@app.route("/")
def index():
    """
    Legacy root compatibility endpoint.

    Canonical authenticated user home lives at /dashboard.
    Keep endpoint name ``index`` so historical url_for("index")
    callers remain valid without rendering the retired dashboard.html.
    """
    if not login_required():
        return redirect(url_for("login"))

    return redirect("/dashboard")


@app.route("/unblock/<sender>", methods=["POST"])
def unblock(sender):
    if not login_required():
        return redirect(url_for("login"))
    if not _eg_admin_core_is_real_admin_v1():
        return redirect("/admin/login", code=302)

    blocklist = load_json_dict(BLOCKLIST_FILE)
    if sender in blocklist:
        del blocklist[sender]
        save_json_dict(BLOCKLIST_FILE, blocklist)

    return redirect(url_for("index"))


@app.route("/watch-remove/<sender>", methods=["POST"])
def watch_remove(sender):
    if not login_required():
        return redirect(url_for("login"))
    if not _eg_admin_core_is_real_admin_v1():
        return redirect("/admin/login", code=302)

    watchlist = load_json_dict(WATCHLIST_FILE)
    if sender in watchlist:
        del watchlist[sender]
        save_json_dict(WATCHLIST_FILE, watchlist)

    return redirect(url_for("index"))


@app.route("/watch-block/<sender>", methods=["POST"])
def watch_block(sender):
    if not login_required():
        return redirect(url_for("login"))
    if not _eg_admin_core_is_real_admin_v1():
        return redirect("/admin/login", code=302)

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
    """Apply the single canonical EratGuard browser security-header policy."""
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault(
        "Permissions-Policy",
        "geolocation=(), microphone=(), camera=(), payment=(), usb=(), bluetooth=()"
    )

    # Active templates still contain inline script/style usage.
    # unsafe-eval is intentionally not permitted.
    response.headers.setdefault(
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

    # Trust forwarded HTTPS state only when proxy trust is explicitly enabled.
    trust_proxy = (
        str(os.getenv("ERATGUARD_TRUST_PROXY_IP", ""))
        .strip()
        .lower()
        in {"1", "true", "yes", "on"}
    )
    forwarded_https = (
        trust_proxy
        and str(request.headers.get("X-Forwarded-Proto", ""))
        .split(",", 1)[0]
        .strip()
        .lower()
        == "https"
    )

    if request.is_secure or forwarded_https:
        response.headers.setdefault(
            "Strict-Transport-Security",
            "max-age=31536000; includeSubDomains"
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


@app.route("/reset-password/<token>", methods=["GET", "POST"])
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

# ===== ERATGUARD ADMIN FORGOT MAIL DIAGNOSTIC END =====



# ===== ERATGUARD ADMIN_STATS BEFORE APP.RUN SAFE OVERRIDE START =====
def _eg_final_safe_admin_stats():
    """Canonical admin stats compatibility context."""
    try:
        from admin.services.dashboard import get_dashboard_data

        payload = get_dashboard_data()
        if isinstance(payload, dict):
            stats = payload.get("admin_stats", {})
            if isinstance(stats, dict):
                return stats
    except Exception:
        pass

    try:
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
def _eg_global_admin_stats_context():
    _stats = _eg_final_safe_admin_stats()
    return {
        "admin_stats": _stats,
        "admin_user_stats": _stats,
        "stats": _stats,
    }


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
                # Same recovery request: preserve the link created immediately above.
                reset_code = create_reset_code(username, invalidate=False)

                try:
                    _eg_user_audit_event(username, "password_reset_requested", {
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


# ===== ERATGUARD SIGNATURE RADIAL HARD ROUTE START =====
# yeni temiz kullanıcı imza paneli ayrı route üzerinden açılır.
# ===== ERATGUARD SIGNATURE RADIAL HARD ROUTE END =====


USER_MODULES = {
    "protection": {
        "icon": "🛡️",
        "title": "Koruma Merkezi",
        "description": "SMS tarama, spam filtreleme ve gerçek zamanlı güvenlik motoru tek ekranda.",
        "stats": [
            {"value": "7/24", "label": "Aktif Koruma"},
            {"value": _eg_get_last_scan_time(), "label": "Son Tarama"},
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
                    {"name": "Oturumu kapat", "value": "Çık", "href": "/logout", "method": "post"},
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
        "primary_href": "/u/eg-panel"
    }
}


def render_user_module_page(module_key):
    if module_key != "legal" and not login_required():
        return redirect(url_for("login"))

    page = USER_MODULES.get(module_key)
    if not page:
        return redirect("/u/eg-panel")

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
    """Canonical EratGuard user notification center."""
    if not login_required():
        return redirect(url_for("login"))

    username = str(session.get("username") or "").strip()
    if not username:
        return redirect(url_for("login"))

    def _load_json(path, default):
        try:
            p = Path(path)
            if not p.exists():
                return default
            with p.open("r", encoding="utf-8") as f:
                data = json.load(f)
            return data
        except Exception:
            return default

    # Canonical entitlement is the only premium source.
    users = load_users()
    user = users.get(username, {}) if isinstance(users, dict) else {}
    entitlement = _eg_user_entitlement_v1(user)
    premium_user = bool(entitlement.get("premium"))

    combined = []

    def _append(item, source):
        if isinstance(item, str):
            item = {
                "title": "Bildirim",
                "message": item,
            }

        if not isinstance(item, dict):
            return

        x = dict(item)
        x["_source_label"] = source
        combined.append(x)

    # --------------------------------------------------------------
    # 1. User-owned notifications
    # --------------------------------------------------------------
    user_data = _load_json(
        "data/user_notifications.json",
        {}
    )

    if isinstance(user_data, dict):
        user_items = user_data.get(username, [])
        if isinstance(user_items, list):
            for item in user_items:
                _append(item, "user_notification")

    # --------------------------------------------------------------
    # 2. Global/system/admin notification feeds
    #
    # Rules:
    # - target=admin is never visible here
    # - target=premium requires canonical entitlement
    # - explicit username/user may only match current user
    # --------------------------------------------------------------
    for path, source in (
        ("data/notifications.json", "system_notification"),
        ("data/admin_notifications.json", "admin_notification"),
    ):
        items = _load_json(path, [])

        if not isinstance(items, list):
            continue

        for item in items:
            if isinstance(item, str):
                item = {
                    "title": "Bildirim",
                    "message": item,
                }

            if not isinstance(item, dict):
                continue

            target = str(
                item.get("target") or "all"
            ).strip().lower()

            if target == "admin":
                continue

            if target == "premium" and not premium_user:
                continue

            item_user = str(
                item.get("username")
                or item.get("user")
                or ""
            ).strip()

            if item_user and item_user != username:
                continue

            _append(item, source)

    # --------------------------------------------------------------
    # 3. Security/risk events
    #
    # Critical isolation rule:
    # A risk event is visible ONLY when it explicitly belongs to
    # the logged-in user. Username-less spam logs never leak into
    # another user's notification center.
    # --------------------------------------------------------------
    for path, source in (
        ("data/user_analysis_history.json", "analysis_history"),
        ("data/spam_logs.json", "spam_logs"),
        ("data/user_quarantine.json", "quarantine"),
    ):
        items = _load_json(path, [])

        if not isinstance(items, list):
            continue

        for item in items:
            if not isinstance(item, dict):
                continue

            item_user = str(
                item.get("username")
                or item.get("user")
                or ""
            ).strip()

            if item_user != username:
                continue

            try:
                score = int(
                    item.get("score")
                    or item.get("risk")
                    or 0
                )
            except Exception:
                score = 0

            status = str(
                item.get("status") or ""
            ).strip().upper()

            # Preserve old notification-risk semantics:
            # only actual spam/high-risk events become notifications.
            if status != "SPAM" and score < 71:
                continue

            x = dict(item)

            if not x.get("title"):
                x["title"] = "Riskli mesaj tespit edildi"

            if not x.get("message"):
                body = str(x.get("body") or "")[:120]
                label = str(
                    x.get("risk_label")
                    or "Yüksek Risk"
                )
                x["message"] = (
                    label + " - " + body
                    if body
                    else label
                )

            if not x.get("priority"):
                if score >= 90:
                    x["priority"] = "critical"
                elif score >= 71:
                    x["priority"] = "high"
                else:
                    x["priority"] = "normal"

            x["_source_label"] = source
            combined.append(x)

    # --------------------------------------------------------------
    # Normalize + sort + dedupe
    # --------------------------------------------------------------
    normalized = []

    for item in combined:
        if not isinstance(item, dict):
            continue

        x = dict(item)

        x["title"] = str(
            x.get("title")
            or "Bildirim"
        )

        x["message"] = str(
            x.get("message")
            or x.get("body")
            or x.get("text")
            or x.get("description")
            or ""
        )

        x["priority"] = str(
            x.get("priority")
            or x.get("level")
            or "normal"
        ).strip().lower()

        if x["priority"] in ("spam", "risk"):
            x["priority"] = "high"

        x["target"] = str(
            x.get("target")
            or "all"
        ).strip().lower()

        x["created_at"] = str(
            x.get("created_at")
            or x.get("time")
            or x.get("date")
            or ""
        )

        normalized.append(x)

    normalized.sort(
        key=lambda x: x.get("created_at", ""),
        reverse=True
    )

    seen = set()
    notifications = []

    for item in normalized:
        key = (
            item.get("created_at", ""),
            item.get("title", "")[:90],
            item.get("message", "")[:120],
            item.get("_source_label", ""),
        )

        if key in seen:
            continue

        seen.add(key)
        notifications.append(item)

        if len(notifications) >= 50:
            break

    notification_stats = {
        "total": len(notifications),
        "high": sum(
            1 for x in notifications
            if x.get("priority") == "high"
        ),
        "critical": sum(
            1 for x in notifications
            if x.get("priority") == "critical"
        ),
    }

    return render_template(
        "user_notifications_admin_feed.html",
        notifications=notifications,
        notification_stats=notification_stats,
        brand="EratGuard PRO",
    )


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


@app.route("/u/settings", methods=["GET", "POST"])
def user_settings():
    """Canonical user settings entry."""
    return user_settings_manage()



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
    """Canonical community page."""
    if not login_required():
        return redirect(url_for("login"))
    return render_template("community.html")


def _eg_community_update_indexes(username, number, body, category="spam", note=""):
    """Maintain community report indexes for a canonical spam report."""
    os.makedirs("data", exist_ok=True)

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    item = {
        "time": now,
        "created_at": now,
        "username": username,
        "reported_by": username,
        "number": number,
        "sender": number,
        "body": body,
        "message": body,
        "status": "SPAM",
        "score": 10,
        "category": category or "spam",
        "note": note or "",
        "reasons": ["community_report"],
        "risk_class": "community",
        "source": "community_report",
    }

    def _load(path, default):
        try:
            if not os.path.exists(path):
                return default
            with open(path, "r", encoding="utf-8") as f:
                value = json.load(f)
            return value
        except Exception:
            return default

    def _save(path, value):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(value, f, ensure_ascii=False, indent=2)

    community_path = "data/community_reports.json"
    spam_reports_path = "data/spam_reports.json"
    reported_path = "data/reported_numbers.json"

    community = _load(community_path, [])
    if not isinstance(community, list):
        community = []
    community.append(item)
    _save(community_path, community)

    spam_reports = _load(spam_reports_path, [])
    if not isinstance(spam_reports, list):
        spam_reports = []
    spam_reports.append(item)
    _save(spam_reports_path, spam_reports)

    reported = _load(reported_path, {})
    if not isinstance(reported, dict):
        reported = {}

    key = number or "unknown_sender"

    old = reported.get(key)
    if not isinstance(old, dict):
        old = {
            "number": key,
            "count": 0,
            "reports": [],
        }

    try:
        old["count"] = int(old.get("count", 0)) + 1
    except Exception:
        old["count"] = 1

    old["last_time"] = now
    old["last_reported_by"] = username

    reports = old.get("reports")
    if not isinstance(reports, list):
        reports = []

    reports.append({
        "time": now,
        "username": username,
        "body": body,
        "category": category or "spam",
        "note": note or "",
    })

    old["reports"] = reports[-10:]
    reported[key] = old

    _save(reported_path, reported)

    return item

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
    username = session.get("username", "unknown")
    category = str(data.get("category", "spam") or "spam").strip()
    note = str(data.get("note", "") or "").strip()

    try:
        _eg_community_update_indexes(
            username,
            number,
            body,
            category,
            note,
        )
    except Exception as e:
        print("ERATGUARD COMMUNITY INDEX ERROR:", e)

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
            "price": "299 TL / ay"
        },
        "pro_yearly": {
            "label": "Shield Pro+",
            "period": "Yıllık",
            "price": "2500 TL / yıl"
        },
        "lifetime": {
            "label": "Lifetime Shield",
            "period": "Tek sefer",
            "price": "5000 TL"
        },
        "pro_monthly": {
            "label": "Starter Shield",
            "period": "Aylık",
            "price": "299 TL / ay"
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


# ERATGUARD ADMIN CORE USER ACTION RUNTIME WIRING V1
from admin.routes import configure_user_action_runtime

configure_user_action_runtime(
    load_users=load_users,
    save_users=save_users,
    audit_log=_eg_audit_log,
)

# ERATGUARD ADMIN CORE COMMERCIAL RUNTIME WIRING V1
from admin.routes import configure_commercial_runtime

configure_commercial_runtime(
    load_users=load_users,
    save_users=save_users,
    load_payment_requests=_eg_load_payment_requests,
    save_payment_requests=_eg_save_payment_requests,
    generate_license_key=generate_license_key,
    audit_log=_eg_audit_log,
)



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



# ===== OLD ADMIN ROUTES REMOVED =====
# Admin artık Blueprint tarafından yönetiliyor.
# Blueprint: admin/routes.py


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

# ERATGUARD ADMIN CORE — USER DETAIL RUNTIME WIRING
from admin.routes import configure_user_detail_runtime

configure_user_detail_runtime(
    load_users=load_users,
    load_user_sessions=_eg_load_user_sessions,
    recent_audit_logs=_eg_recent_audit_logs,
)



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

        # Browser-session history APIs contain user protection data and
        # mutations; keep them behind the canonical user auth boundary.
        if path.startswith("/api/v6/history-"):
            if not session.get("logged_in") or not session.get("username"):
                session.clear()
                return redirect("/login?auth_required=1")

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



# Canonical admin UI is owned by admin.routes/admin.services.



# Session secret yukarida tek merkezden yapilandiriliyor.


# ===== ERATGUARD ADMIN SIGNED COOKIE FALLBACK START =====
def _eg_admin_cookie_secret_final():
    secret = app.secret_key
    if not secret:
        raise RuntimeError("Session secret tanimli degil.")
    return str(secret)

def _eg_admin_cookie_token_final():
    import hmac
    import hashlib
    secret = _eg_admin_cookie_secret_final().encode("utf-8")
    return hmac.new(secret, b"eratguard-admin-mobile-ok", hashlib.sha256).hexdigest()


# Eski admin kontrol fonksiyonlarını cookie fallback ile güçlendir


# Admin login endpointini imzalı cookie basacak şekilde override et

# ===== ERATGUARD ADMIN SIGNED COOKIE FALLBACK END =====

# ===== ERATGUARD USER FINAL ROUTE ALIAS + HOME LOCK START =====
from flask import render_template_string as _eg_user_render_template_string

def _eg_user_logged_in_final():
    return bool(session.get("logged_in") and session.get("username"))

def _eg_user_require_login_redirect():
    if not _eg_user_logged_in_final():
        return redirect("/login")
    return None


@app.route("/dashboard")
@app.route("/home")
@app.route("/user")
@app.route("/main")
def eratguard_user_home():
    """Canonical EratGuard user dashboard entry."""
    if not login_required():
        return redirect(url_for("login"))
    return eg_user_panel_v2()

@app.route("/protection")
@app.route("/koruma")
def eg_user_alias_protection_final():
    return redirect("/u/protection")

@app.route("/reports")
@app.route("/report")
@app.route("/rapor")
@app.route("/raporlar")
def eg_user_alias_reports_final():
    return redirect("/u/reports")

@app.route("/blocked")
@app.route("/block")
@app.route("/engel")
@app.route("/engellenenler")
def eg_user_alias_blocked_final():
    return redirect("/u/blocked")

@app.route("/analysis")
@app.route("/analyze")
@app.route("/analiz")
def eg_user_alias_analysis_final():
    return redirect("/u/analysis")

@app.route("/notifications")
@app.route("/notification")
@app.route("/bildirim")
@app.route("/bildirimler")
def eg_user_alias_notifications_final():
    return redirect("/u/notifications")

@app.route("/settings")
@app.route("/ayarlar")
@app.route("/ayar")
def eg_user_alias_settings_final():
    return redirect("/u/settings")

@app.route("/community")
@app.route("/topluluk")
def eg_user_alias_community_final():
    return redirect("/u/community")

@app.route("/license")
@app.route("/lisans")
def eg_user_alias_license_final():
    return redirect("/u/license")

@app.route("/pricing")
@app.route("/packages")
@app.route("/paketler")
@app.route("/fiyatlandirma")
def eg_user_alias_pricing_final():
    return render_template("pricing.html")

@app.route("/checkout", methods=["GET", "POST"])
@app.route("/payment", methods=["GET", "POST"])
@app.route("/odeme", methods=["GET", "POST"])
@app.route("/satin-al", methods=["GET", "POST"])
def eg_public_checkout_final():
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
def _eg_user_settings_redirect_final():
    return redirect("/u/settings")

try:
    for _rule in list(app.url_map.iter_rules()):
        if str(_rule) in ["/settings", "/ayarlar", "/ayar"]:
            app.view_functions[_rule.endpoint] = _eg_user_settings_redirect_final
except Exception:
    pass
# ===== ERATGUARD USER SETTINGS OVERRIDE FINAL END =====


# ===== ERATGUARD USER AUDIT CORE START =====
from datetime import datetime as _eg_user_audit_datetime
from pathlib import Path as _eg_user_audit_Path
import json as _eg_user_audit_json

_EG_USER_AUDIT_DATA = _eg_user_audit_Path("data")
_EG_USER_AUDIT_DATA.mkdir(exist_ok=True)

_EG_USER_AUDIT_EVENTS_FILE = _EG_USER_AUDIT_DATA / "user_titanium_events.json"

def _eg_user_audit_now():
    return _eg_user_audit_datetime.now().isoformat(timespec="seconds")

def _eg_user_audit_read_json(path, default):
    try:
        if not path.exists():
            return default
        return _eg_user_audit_json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default

def _eg_user_audit_write_json(path, data):
    path.parent.mkdir(exist_ok=True)
    path.write_text(
        _eg_user_audit_json.dumps(data, ensure_ascii=False, indent=2),
        encoding="utf-8"
    )


def _eg_user_audit_event(username, event_type, payload=None):
    try:
        target_username = str(username or "").strip()
        if not target_username:
            return False

        events = _eg_user_audit_read_json(_EG_USER_AUDIT_EVENTS_FILE, [])
        events.append({
            "created_at": _eg_user_audit_now(),
            "username": target_username,
            "event_type": event_type,
            "payload": payload or {}
        })
        _eg_user_audit_write_json(_EG_USER_AUDIT_EVENTS_FILE, events[-300:])
        return True
    except Exception as e:
        print("USER_AUDIT_EVENT_ERROR:", e, flush=True)
        return False


# ===== ERATGUARD USER AUDIT CORE END =====


# ===== ERATGUARD PUBLIC LEGAL PAGES START =====
from flask import render_template_string as _eg_legal_public_render_template_string
from flask import make_response as _eg_legal_public_make_response

def _eg_public_legal_page(title, subtitle, body_html):
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
    resp = _eg_legal_public_make_response(_eg_legal_public_render_template_string(html))
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp


@app.route("/privacy")
@app.route("/gizlilik")
def ss_public_privacy_page():
    return _eg_public_legal_page(
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
    return _eg_public_legal_page(
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
    return _eg_public_legal_page(
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
    return _eg_public_legal_page(
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
    """Return client IP; proxy headers are trusted only when explicitly enabled."""
    try:
        remote_ip = str(request.remote_addr or "").strip() or "unknown"

        trust_proxy = (
            str(os.getenv("ERATGUARD_TRUST_PROXY_IP", ""))
            .strip()
            .lower()
            in {"1", "true", "yes", "on"}
        )

        if not trust_proxy:
            return remote_ip

        cf_ip = str(
            request.headers.get("CF-Connecting-IP", "")
        ).strip()
        if cf_ip:
            return cf_ip

        xff = str(
            request.headers.get("X-Forwarded-For", "")
        ).strip()
        if xff:
            candidate = xff.split(",", 1)[0].strip()
            if candidate:
                return candidate

        return remote_ip
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
            "/login": ("user-login", 12, 15 * 60),
            "/forgot-password": ("forgot-password", 5, 15 * 60),
            "/forgot": ("forgot-password-alias", 5, 15 * 60),
            "/api/mobile/login": ("mobile-login", 20, 15 * 60),
        }

        if path not in rules:
            return None

        bucket, limit, window = rules[path]
        ok, retry_after = _eg_rate_limit_check(bucket, limit, window)

        if ok:
            return None

        if path == "/api/mobile/login":
            resp = jsonify({
                "ok": False,
                "error": "rate_limited",
                "message": "Çok fazla giriş denemesi. Lütfen biraz sonra tekrar deneyin.",
            })
            resp.status_code = 429
        else:
            resp = app.response_class(
                "<h2>EratGuard PRO</h2><p>Çok fazla deneme yapıldı. Lütfen biraz sonra tekrar deneyin.</p>",
                status=429,
                mimetype="text/html",
            )
        resp.headers["Retry-After"] = str(max(retry_after, 60))
        return resp

    except Exception:
        return None

# ===== ERATGUARD BETA SECURITY HARDENING END =====

# ===== ERATGUARD SESSION COOKIE HARDENING START =====
# Ensure Flask session cookies are protected in production.
# ===== ERATGUARD SESSION COOKIE HARDENING END =====

# ===== ERATGUARD MANUAL LICENSE ADMIN FLOW START =====

def _eg_admin_payment_requests_for_template():
    try:
        return _eg_load_payment_requests()
    except Exception:
        return []


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


# ===== ERATGUARD PREMIUM ADMIN USER ACTION ROUTES END =====

# ===== ERATGUARD CANONICAL ADMIN USER DETAIL START =====
# ===== ERATGUARD CANONICAL ADMIN USER DETAIL END =====

# ===== ERATGUARD APP RUN FINAL START =====


# /admin ownership belongs to the canonical admin Blueprint.


# EG5C physically removed by Admin Core cleanup.


# Amaç:
# - Admin paneline dokunmadan kullanıcı tarafına EratGuard sağdan-sola yelpaze menü ekler.
# - /dashboard, /u/dashboard ve /u/* kullanıcı sayfalarında çalışır.
# - /admin yollarında asla çalışmaz.


# ===== ERATGUARD SMS ACTION ENGINE START =====
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
        "engine": "ERATGUARD_SMS_ACTION_ENGINE",
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
        "engine": "ERATGUARD_SMS_ACTION_ENGINE",
        "stats": {
            "blocked": len(db.get("blocked", [])),
            "safe": len(db.get("safe", [])),
            "reported": len(db.get("reported", []))
        },
        "data": db
    })


# ===== ERATGUARD SMS ACTION ENGINE END =====








# ===== ERATGUARD SMS RISK ENGINE START =====
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
        "engine": "ERATGUARD_SMS_RISK_ENGINE",
        "input_length": len(text or ""),
        "result": result
    })


# ===== ERATGUARD SMS RISK ENGINE END =====


# Flask after_request ters sırayla çalışır.
# Bu yüzden insert(0) ile bu fonksiyon en SON çalıştırılır ve dashboard force render ezemez.




# ===== ERATGUARD FIXED MENU RESTORE FINAL START =====

# ===== ERATGUARD FIXED MENU RESTORE FINAL END =====



# ===== ERATGUARD USER HISTORY CORE START =====
@app.route("/u/protection-history")
@app.route("/u/history")
def user_protection_history():
    """Canonical user protection history controller."""
    import json
    from pathlib import Path

    if not login_required():
        return redirect(url_for("login"))

    data_path = Path("data/eratguard_sms_actions_v5c.json")
    actions = {
        "blocked": [],
        "safe": [],
        "reported": [],
    }

    if data_path.exists():
        try:
            loaded = json.loads(
                data_path.read_text(
                    encoding="utf-8",
                    errors="ignore",
                )
            )
            if isinstance(loaded, dict):
                for key in actions:
                    val = loaded.get(key, [])
                    if isinstance(val, list):
                        actions[key] = val
        except Exception:
            pass

    def normalize_items(kind, label):
        out = []

        for item in actions.get(kind, []):
            if not isinstance(item, dict):
                continue

            text = (
                item.get("text")
                or item.get("message")
                or item.get("sms")
                or item.get("content")
                or ""
            )
            score = (
                item.get("score")
                or item.get("risk_score")
                or item.get("riskScore")
                or 0
            )
            level = (
                item.get("level")
                or item.get("risk_level")
                or item.get("riskLevel")
                or "Kayıt"
            )
            created = (
                item.get("created_at")
                or item.get("time")
                or item.get("timestamp")
                or item.get("date")
                or "—"
            )

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
                "text": short,
                "score": score_int,
                "level": str(level),
                "created_at": str(created),
            })

        return out

    history = []
    history += normalize_items("blocked", "Engellendi")
    history += normalize_items("reported", "Şikayet")
    history += normalize_items("safe", "Güvenli")

    return render_template(
        "user_protection_history.html",
        history=history,
        total=len(history),
        blocked_count=len(actions.get("blocked", [])),
        reported_count=len(actions.get("reported", [])),
        safe_count=len(actions.get("safe", [])),
    )





# ===== ERATGUARD USER HISTORY EXPORT START =====
@app.route("/api/v6/history-export")
def user_history_export():
    from flask import jsonify, Response
    from pathlib import Path
    import json
    import datetime

    data_path = Path("data/eratguard_sms_actions_v5c.json")

    payload = {
        "app": "EratGuard",
        "version": "PRO",
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
# ===== ERATGUARD USER HISTORY EXPORT END =====


# ===== ERATGUARD USER HISTORY CLEAR START =====
@app.route("/api/v6/history-clear", methods=["POST"])
def user_history_clear():
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
# ===== ERATGUARD USER HISTORY CLEAR END =====


# ===== ERATGUARD USER HISTORY RESTORE START =====
@app.route("/api/v6/history-restore-latest", methods=["POST"])
def user_history_restore_latest():
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
# ===== ERATGUARD USER HISTORY RESTORE END =====

# ===== ERATGUARD USER HISTORY CORE END =====


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
        return _eg_redirect(_eg_request.referrer or "/sms")
    except Exception as e:
        if _eg_request.is_json:
            return _eg_jsonify({"ok": False, "error": str(e)}), 400
        try:
            _eg_flash("SMS aksiyonu kaydedilemedi: " + str(e), "danger")
        except Exception:
            pass
        return _eg_redirect(_eg_request.referrer or "/sms")


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
    return _eg_redirect("/sms")

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
    #
    # SECURITY-SHIELD-05B:
    # Restore input is fully validated before any backup or live-data
    # write is allowed to occur.
    f = _eg_request.files.get("backup")

    if not f:
        return _eg_jsonify({
            "ok": False,
            "error": "backup dosyası yok",
        }), 400

    max_upload_bytes = 1024 * 1024
    max_records = 5000
    max_depth = 12
    max_string_length = 65536
    max_key_length = 256
    max_container_items = 10000

    def _restore_validate_json_value(value, depth=0):
        if depth > max_depth:
            raise ValueError(
                "Yedek JSON yapısı çok derin."
            )

        if value is None or isinstance(
            value,
            (bool, int, float),
        ):
            return

        if isinstance(value, str):
            if len(value) > max_string_length:
                raise ValueError(
                    "Yedekte izin verilenden uzun metin var."
                )
            return

        if isinstance(value, list):
            if len(value) > max_container_items:
                raise ValueError(
                    "Yedek JSON listesi çok büyük."
                )

            for item in value:
                _restore_validate_json_value(
                    item,
                    depth + 1,
                )
            return

        if isinstance(value, dict):
            if len(value) > max_container_items:
                raise ValueError(
                    "Yedek JSON nesnesi çok büyük."
                )

            for key, item in value.items():
                if not isinstance(key, str):
                    raise ValueError(
                        "Yedek JSON anahtarı geçersiz."
                    )

                if len(key) > max_key_length:
                    raise ValueError(
                        "Yedek JSON anahtarı çok uzun."
                    )

                _restore_validate_json_value(
                    item,
                    depth + 1,
                )
            return

        raise ValueError(
            "Yedekte desteklenmeyen veri tipi var."
        )

    try:
        # Read at most limit + 1. This prevents an unbounded f.read()
        # from consuming arbitrary memory before validation.
        raw = f.read(max_upload_bytes + 1)

        if len(raw) > max_upload_bytes:
            raise ValueError(
                "Yedek dosyası en fazla 1 MiB olabilir."
            )

        if not raw:
            raise ValueError(
                "Yedek dosyası boş."
            )

        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            raise ValueError(
                "Yedek dosyası geçerli UTF-8 değil."
            )

        try:
            data = _eg_json.loads(text)
        except Exception:
            raise ValueError(
                "Yedek dosyası geçerli JSON değil."
            )

        # Canonical export is a list. Historical wrapper
        # {"actions": [...]} remains accepted for compatibility.
        if isinstance(data, dict):
            if set(data.keys()) != {"actions"}:
                raise ValueError(
                    "Yedek nesnesi yalnız actions alanını içerebilir."
                )

            data = data.get("actions")

        if not isinstance(data, list):
            raise ValueError(
                "Yedek formatı liste değil."
            )

        if len(data) > max_records:
            raise ValueError(
                "Yedek en fazla 5000 SMS kaydı içerebilir."
            )

        for index, item in enumerate(data):
            if not isinstance(item, dict):
                raise ValueError(
                    f"Yedek kaydı geçersiz: {index + 1}"
                )

            _restore_validate_json_value(
                item,
                1,
            )

            # If an action field exists, it must use the engine's
            # already-defined canonical action vocabulary.
            if "action" in item:
                action = str(
                    item.get("action", "")
                ).strip()

                if action not in _EG_ALLOWED_SMS_ACTIONS:
                    raise ValueError(
                        f"Geçersiz SMS aksiyonu: kayıt {index + 1}"
                    )

        # IMPORTANT:
        # No live-data or safety-backup write occurs before this point.
        old = _eg_load_sms_actions()

        if old:
            stamp = _eg_datetime.now().strftime(
                "%Y%m%d_%H%M%S"
            )

            _eg_atomic_write_json(
                _EG_SMS_ACTIONS_BACKUP_DIR
                / f"before_restore_{stamp}.json",
                old,
            )

        _eg_save_sms_actions(data)

        return _eg_jsonify({
            "ok": True,
            "restored": len(data),
            "counts": _eg_counts(data),
        })

    except ValueError as e:
        return _eg_jsonify({
            "ok": False,
            "error": str(e),
        }), 400

    except Exception:
        # Do not expose filesystem/parser/internal exception details.
        return _eg_jsonify({
            "ok": False,
            "error": "Yedek geri yüklenemedi.",
        }), 400


@app.route("/u/sms/actions/counts")
def eg_sms_actions_counts():
    return _eg_jsonify({"ok": True, "counts": _eg_counts()})

# === /ERATGUARD_SMS_ACTION_ENGINE_V1 ===


# === ERATGUARD_AI_ANALYSIS_ACTION_BUTTONS_V2 ===
# /u/analysis ekranına SMS Action Engine karar butonları ekler:
# Engelle / Güvenli / Şikayet -> /u/sms/action

# === /ERATGUARD_AI_ANALYSIS_ACTION_BUTTONS_V2 ===


# Yeni HUD Command Center admin Blueprint tarafından yönetiliyor.

# === /ERATGUARD ADMIN COMMAND CENTER V1 ===


# ERATGUARD_12P_FINAL_PRIORITY_FIX_V25_START
# 12P radial dilimlerinin login guard'a düşmesini engelleyen en yüksek öncelikli final köprü.


# ERATGUARD_12P_FINAL_PRIORITY_FIX_V25_END


# ERATGUARD_PRICING_BILLING_V26_START
# Yayın öncesi Ücretlendirme / Paketler / Satın Alma merkezi.


# ERATGUARD_PRICING_BILLING_V26_END

# =====================================================================
# ERATGUARD_CANONICAL_LICENSE_ACTIVATION_LOCK_V1
# /u/license POST -> canonical one-time license validator
# GET/UI/pricing/admin/radial behavior untouched.
# =====================================================================

def _eg_canonical_license_activation_lock_v1():
    try:
        if request.path != "/u/license":
            return None

        if str(request.method).upper() != "POST":
            return None

        return _eg_final_one_time_user_license()

    except Exception as _eg_clal1_error:
        print(
            "ERATGUARD CANONICAL LICENSE ACTIVATION LOCK V1 ERROR:",
            repr(_eg_clal1_error),
            flush=True
        )
        return None


try:
    _eg_clal1_hooks = app.before_request_funcs.setdefault(None, [])

    _eg_clal1_hooks[:] = [
        fn for fn in _eg_clal1_hooks
        if getattr(fn, "__name__", "")
        != "_eg_canonical_license_activation_lock_v1"
    ]

    _eg_clal1_hooks.insert(
        0,
        _eg_canonical_license_activation_lock_v1
    )

    print(
        "ERATGUARD CANONICAL LICENSE ACTIVATION LOCK V1 ACTIVE: "
        "/u/license POST -> _eg_final_one_time_user_license"
    )

except Exception as _eg_clal1_register_error:
    print(
        "ERATGUARD CANONICAL LICENSE ACTIVATION LOCK V1 REGISTER ERROR:",
        repr(_eg_clal1_register_error),
        flush=True
    )


# =====================================================================
# ERATGUARD_CANONICAL_COMMERCIAL_MODEL_V1
# Phase 5B - single canonical plan / price / duration vocabulary.
#
# This layer is intentionally PURE:
# - no file writes
# - no user mutation
# - no payment mutation
# - no license mutation
#
# Mutation paths will consume this model in later gated phases.
# =====================================================================

ERATGUARD_CANONICAL_PLANS_V1 = {
    "starter_monthly": {
        "key": "starter_monthly",
        "label": "Starter Shield",
        "price_try": 299,
        "price_text": "299 TL / ay",
        "billing_period": "monthly",
        "duration_days": 30,
        "license_type": "pro",
        "expires_mode": "days",
    },

    "pro_yearly": {
        "key": "pro_yearly",
        "label": "Shield Pro+",
        "price_try": 2500,
        "price_text": "2500 TL / yıl",
        "billing_period": "yearly",
        "duration_days": 365,
        "license_type": "pro",
        "expires_mode": "days",
    },

    "lifetime": {
        "key": "lifetime",
        "label": "Lifetime Shield",
        "price_try": 5000,
        "price_text": "5000 TL",
        "billing_period": "lifetime",
        "duration_days": None,
        "license_type": "lifetime",
        "expires_mode": "lifetime",
        "expires_at": "2099-12-31",
    },
}


ERATGUARD_CANONICAL_PLAN_ALIASES_V1 = {
    "starter_monthly": "starter_monthly",
    "starter": "starter_monthly",
    "monthly": "starter_monthly",
    "pro_monthly": "starter_monthly",
    "aylik": "starter_monthly",

    "pro_yearly": "pro_yearly",
    "yearly": "pro_yearly",
    "annual": "pro_yearly",
    "pro": "pro_yearly",
    "premium": "pro_yearly",
    "yillik": "pro_yearly",

    "lifetime": "lifetime",
    "lifetime_shield": "lifetime",
    "omurluk": "lifetime",
}


def _eg_canonical_plan_key_v1(plan):
    raw = str(plan or "").strip().lower()

    if not raw:
        return "pro_yearly"

    return ERATGUARD_CANONICAL_PLAN_ALIASES_V1.get(
        raw,
        "pro_yearly"
    )


def _eg_canonical_plan_v1(plan):
    key = _eg_canonical_plan_key_v1(plan)

    data = ERATGUARD_CANONICAL_PLANS_V1.get(
        key,
        ERATGUARD_CANONICAL_PLANS_V1["pro_yearly"]
    )

    return dict(data)


def _eg_canonical_plan_expiry_v1(plan, now=None):
    from datetime import datetime as _eg_ccm_datetime
    from datetime import timedelta as _eg_ccm_timedelta

    info = _eg_canonical_plan_v1(plan)

    if info.get("expires_mode") == "lifetime":
        return "2099-12-31"

    days = int(info.get("duration_days") or 365)

    base = now or _eg_ccm_datetime.now()

    if hasattr(base, "date"):
        base_date = base.date()
    else:
        base_date = base

    return (
        base_date + _eg_ccm_timedelta(days=days)
    ).isoformat()


def _eg_canonical_plan_public_v1(plan):
    info = _eg_canonical_plan_v1(plan)

    return {
        "key": info["key"],
        "label": info["label"],
        "price": info["price_text"],
        "price_try": info["price_try"],
        "billing_period": info["billing_period"],
        "duration_days": info["duration_days"],
        "license_type": info["license_type"],
    }

# ===== ERATGUARD CANONICAL COMMERCIAL FLOW V1 START =====
# Phase 5C
# Canonical plan model -> checkout -> payment request -> admin approval
# -> one-time activation metadata preservation.
#
# Existing data is NOT migrated here.

def _eg_canonical_payment_plan_v1(raw_plan):
    """
    Normalize a commercial plan through the Phase 5B canonical model.
    """
    return _eg_canonical_plan_key_v1(raw_plan)


def _eg_canonical_payment_snapshot_v1(raw_plan):
    """
    Stable commercial snapshot stored with a NEW payment request.
    """
    info = _eg_canonical_plan_v1(raw_plan)

    return {
        "plan": info["key"],
        "plan_key": info["key"],
        "plan_label": info["label"],
        "plan_price": info["price_text"],
        "plan_price_try": info["price_try"],
        "billing_period": info["billing_period"],
        "duration_days": info["duration_days"],
        "license_type": info["license_type"],
    }


def _eg_canonical_payment_request_plan_v1(item):
    """
    Resolve plan from an existing payment request.

    Unknown legacy/test plan values intentionally fall through the
    Phase 5B canonical default (pro_yearly). No data migration occurs.
    """
    if not isinstance(item, dict):
        item = {}

    raw = (
        item.get("plan_key")
        or item.get("plan")
        or "pro_yearly"
    )

    return _eg_canonical_plan_key_v1(raw)


def _eg_canonical_apply_plan_to_user_v1(user, raw_plan, now=None):
    """
    Apply canonical commercial entitlement to a user record.
    """
    if not isinstance(user, dict):
        user = {}

    info = _eg_canonical_plan_v1(raw_plan)
    expiry = _eg_canonical_plan_expiry_v1(info["key"], now=now)

    user["active"] = True
    user["plan"] = info["key"]
    user["license_type"] = info["license_type"]
    user["expires_at"] = expiry
    user["license_expiry"] = expiry

    # Paid entitlement permanently consumes any old trial.
    # A paid plan must never fall back to a previous trial
    # after the paid entitlement expires.
    if info["license_type"] in ("pro", "lifetime"):
        trial_started_at = str(
            user.get("trial_started_at") or ""
        ).strip()

        trial_expires_at = str(
            user.get("trial_expires_at") or ""
        ).strip()

        if trial_started_at or trial_expires_at:
            from datetime import datetime as _eg_trial_datetime_v2

            user["trial_consumed_at"] = (
                _eg_trial_datetime_v2.now()
                .isoformat(timespec="seconds")
            )

        user.pop("trial_started_at", None)
        user.pop("trial_expires_at", None)

    return user


def _eg_canonical_find_payment_license_v1(license_key, username=None):
    """
    Read-only lookup of an approved payment request by license key.
    """
    wanted = _eg_norm_license_key(license_key)

    if not wanted:
        return None

    try:
        items = _eg_load_payment_requests()
    except Exception:
        return None

    if not isinstance(items, list):
        return None

    for item in items:
        if not isinstance(item, dict):
            continue

        item_key = _eg_norm_license_key(item.get("license_key"))

        if item_key != wanted:
            continue

        item_user = str(item.get("username", "") or "").strip()

        if username and item_user and item_user != str(username).strip():
            continue

        status = str(item.get("status", "") or "").lower()

        if "approved" not in status:
            continue

        return item

    return None


# ------------------------------------------------------------------
# Canonical checkout
# ------------------------------------------------------------------

def _eg_canonical_user_checkout_v1():
    if not login_required():
        return redirect(url_for("login"))

    from datetime import datetime

    username = session.get("username", "user")

    raw_plan = request.values.get("plan", "pro_yearly")
    plan_key = _eg_canonical_payment_plan_v1(raw_plan)
    info = _eg_canonical_plan_v1(plan_key)

    period_labels = {
        "monthly": "Aylık",
        "yearly": "Yıllık",
        "lifetime": "Tek sefer",
    }

    plan_period = period_labels.get(
        info.get("billing_period"),
        str(info.get("billing_period") or "")
    )

    if request.method == "POST":
        email = (request.form.get("email") or "").strip()
        note = (request.form.get("note") or "").strip()
        payment_method = (
            request.form.get("payment_method")
            or "manual_transfer"
        ).strip()

        requests_data = _eg_load_payment_requests()

        if not isinstance(requests_data, list):
            requests_data = []

        order_no = _eg_next_order_no()
        snapshot = _eg_canonical_payment_snapshot_v1(plan_key)

        item = {
            "order_no": order_no,
            "created_at": datetime.now().isoformat(timespec="seconds"),
            "username": username,
            "email": email,

            "plan": snapshot["plan"],
            "plan_key": snapshot["plan_key"],
            "plan_label": snapshot["plan_label"],
            "plan_period": plan_period,
            "plan_price": snapshot["plan_price"],
            "plan_price_try": snapshot["plan_price_try"],
            "billing_period": snapshot["billing_period"],
            "duration_days": snapshot["duration_days"],
            "license_type": snapshot["license_type"],

            "payment_method": payment_method,
            "provider": "manual_license_review",
            "status": "payment_waiting",
            "note": note,
            "admin_note": "",
            "license_key": "",
        }

        requests_data.append(item)
        _eg_save_payment_requests(requests_data)

        return redirect(
            url_for(
                "user_payment_success",
                order_no=order_no
            )
        )

    return render_template(
        "checkout.html",
        plan=plan_key,
        plan_label=info["label"],
        plan_period=plan_period,
        plan_price=info["price_text"],
        payment_provider="manual_license_review",
        payment_ready=True,
        message=(
            "EratGuard lisans talebi oluşturun. "
            "Talebiniz için benzersiz sipariş numarası üretilecek "
            "ve ödeme onayı sonrası lisansınız hesabınıza "
            "tanımlanacaktır."
        )
    )


# ------------------------------------------------------------------
# Canonical admin payment approval
# ------------------------------------------------------------------



# ------------------------------------------------------------------
# Canonical activation wrapper
#
# The existing validator owns the one-time-use lock.
# We capture approved payment metadata before activation and restore
# the canonical commercial entitlement after the legacy function
# completes successfully.
# ------------------------------------------------------------------

_eg_phase5c_original_one_time_user_license_v1 = (
    _eg_final_one_time_user_license
)


def _eg_canonical_one_time_user_license_v1():
    if not login_required():
        return redirect(url_for("login"))

    username = session.get("username", "user")

    payment_item = None
    license_key = ""

    if request.method == "POST":
        license_key = _eg_norm_license_key(
            request.form.get("license_key")
        )

        payment_item = _eg_canonical_find_payment_license_v1(
            license_key,
            username
        )

    response = _eg_phase5c_original_one_time_user_license_v1()

    # Only restore metadata when this key belongs to an approved
    # commercial payment request.
    if request.method == "POST" and payment_item:
        try:
            users = load_users()

            if isinstance(users, dict):
                user = users.get(username, {})

                if not isinstance(user, dict):
                    user = {}

                # Successful legacy activation writes this key into
                # the user record. This is our success gate.
                current_key = _eg_norm_license_key(
                    user.get("license_key")
                )

                if current_key == license_key:
                    plan_key = (
                        _eg_canonical_payment_request_plan_v1(
                            payment_item
                        )
                    )

                    user["license_key"] = license_key

                    _eg_canonical_apply_plan_to_user_v1(
                        user,
                        plan_key
                    )

                    users[username] = user
                    save_users(users)

        except Exception as e:
            print(
                "ERATGUARD CANONICAL ACTIVATION METADATA WARN:",
                repr(e),
                flush=True
            )

    return response


# ------------------------------------------------------------------
# Runtime bindings
# ------------------------------------------------------------------

try:
    # Endpoint replacement avoids adding duplicate Flask routes.
    if "user_checkout" in app.view_functions:
        app.view_functions["user_checkout"] = (
            _eg_canonical_user_checkout_v1
        )


    # Direct symbol replacement is needed because the Phase 4
    # before_request lock calls this global function by name.
    _eg_final_one_time_user_license = (
        _eg_canonical_one_time_user_license_v1
    )

    print(
        "ERATGUARD CANONICAL COMMERCIAL FLOW V1 ACTIVE: "
        "checkout -> payment -> approval -> activation"
    )

except Exception as _eg_ccfv1_error:
    print(
        "ERATGUARD CANONICAL COMMERCIAL FLOW V1 ERROR:",
        repr(_eg_ccfv1_error),
        flush=True
    )

# ===== ERATGUARD CANONICAL COMMERCIAL FLOW V1 END =====



print(
    "ERATGUARD CANONICAL COMMERCIAL MODEL V1 ACTIVE: "
    "starter_monthly=299TL/30d, "
    "pro_yearly=2500TL/365d, "
    "lifetime=5000TL"
)


# ===== ERATGUARD APP RUN MOVED TO TRUE EOF BY PHASE 7D.18A =====




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


except Exception as _eg_sms_badge_v3_boot_err:
    print("ERATGUARD HIDE AUTO SMS BADGE V3 BOOT ERROR:", _eg_sms_badge_v3_boot_err)
# ===== ERATGUARD HIDE AUTO SMS BADGE V3 END =====


@app.route("/u/protection")
def user_protection():
    return render_user_module_page("protection")


# Final after_request injection:
# Hangi /u/analysis override aktif olursa olsun, POST analiz sonucuna
# Engelle / Güvenli / Şikayet aksiyon formlarını en son ekler.




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
            if (
                _eg_satg1_request.path in {
                    "/sms/action",
                    "/api/v5/sms-action",
                    "/api/v5/sms-risk",
                }
                and _eg_satg1_request.method == "POST"
            ):
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

# V25: V24 imza radial panel korunur; sadece ekrana sığma, ölçek ve boşluk profesyonel ayarlanır.


# V26: V24/V25 imza radial panel korunur. Yaprak çakışması ve yazı sıkışması azaltılır.


# Amaç: hedef görseldeki radial paneli korumak; karttan sonra büyük, dengeli, taşmadan göstermek.



# ===== ERATGUARD SIGNATURE SVG RADIAL DEMO ROUTE START =====
# ===== ERATGUARD SIGNATURE SVG RADIAL DEMO ROUTE END =====




# ===== ERATGUARD /sms WEB COMPANION START =====
@app.route("/sms")
def eratguard_sms_web_companion():
    """Canonical browser companion for the /sms target."""
    if not login_required():
        return redirect(url_for("login"))

    return render_template("sms_center.html")
# ===== ERATGUARD /sms WEB COMPANION END =====


# ERATGUARD_SMS_DEFAULT_FALLBACK_ROUTE_START
# Web radial içinden SMS Varsayılanılan dilimine basılırsa kullanıcıyı net hedefe götüren güvenli fallback.
try:
    @app.route("/u/sms-default")
    def eratguard_sms_default_fallback_page():
        try:
            from flask import render_template_string
            return render_template_string("""
<!doctype html>
<html lang="tr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>SMS Varsayılanılan · EratGuard</title>
  <style>
    body{margin:0;background:#020806;color:#eafff4;font-family:Arial,sans-serif}
    .wrap{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:18px}
    .card{max-width:520px;width:100%;border:1px solid rgba(0,255,140,.45);border-radius:22px;background:#06140f;padding:22px;box-shadow:0 0 34px rgba(0,255,140,.25)}
    h1{margin:0 0 10px;color:#7cffb2}
    p{line-height:1.5;color:#cffff0}
    .btn{display:block;text-align:center;margin-top:14px;padding:14px 16px;border-radius:16px;text-decoration:none;font-weight:900}
    .primary{background:#00ff8c;color:#00140b}
    .ghost{border:1px solid rgba(0,255,140,.45);color:#7cffb2}
    .note{font-size:13px;color:#9df7c5}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <h1>SMS Varsayılanılan</h1>
      <p>EratGuard’ın spam SMS’leri yüksek oranda yakalayıp engelleyebilmesi için uygulamayı varsayılan SMS uygulaması yapman gerekir.</p>
      <p class="note">Android uygulama içindeki SMS Varsayılanılan dilimi native izin ekranını açar. Bu sayfa web fallback bilgilendirme ekranıdır.</p>
      <a class="btn primary" href="/u/eg-panel">Radial Panele Dön</a>
      <a class="btn ghost" href="/u/protection">PRO Koruma Durumunu Aç</a>
    </div>
  </div>
</body>
</html>
            """)
        except Exception:
            return "SMS Varsayılanılan · EratGuard"
except Exception as _eg_sms_default_route_error:
    print("ERATGUARD SMS DEFAULT FALLBACK ROUTE ERROR:", _eg_sms_default_route_error)
# ERATGUARD_SMS_DEFAULT_FALLBACK_ROUTE_END

# ERATGUARD_SMS_DEFAULT_PRIORITY_BRIDGE_START
# SMS Varsayılanılan dilimi login/auth guard'a takılmayacak.
# Android native köprü yakalayamazsa bu güvenli bilgilendirme ekranı açılır.
def eratguard_sms_default_priority_bridge():
    try:
        from flask import request, render_template_string

        path = (request.path or "/").rstrip("/") or "/"

        if path != "/u/sms-default":
            return None

        return render_template_string("""
<!doctype html>
<html lang="tr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
  <title>SMS Varsayılanılan · EratGuard</title>
  <style>
    body{margin:0;background:#020806;color:#eafff4;font-family:Arial,sans-serif}
    .wrap{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:18px}
    .card{max-width:540px;width:100%;border:1px solid rgba(0,255,140,.50);border-radius:24px;background:#06140f;padding:24px;box-shadow:0 0 38px rgba(0,255,140,.28)}
    h1{margin:0 0 10px;color:#7cffb2;font-size:28px}
    p{line-height:1.52;color:#dfffea}
    .badge{display:inline-block;padding:5px 10px;border-radius:999px;border:1px solid rgba(0,255,140,.55);color:#fff;background:rgba(0,255,140,.13);font-weight:900;font-size:12px}
    .btn{display:block;text-align:center;margin-top:14px;padding:14px 16px;border-radius:16px;text-decoration:none;font-weight:900}
    .primary{background:#00ff8c;color:#00140b}
    .ghost{border:1px solid rgba(0,255,140,.45);color:#7cffb2}
    .note{font-size:13px;color:#9df7c5}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <span class="badge">ERATGUARD 12P RELEASE</span>
      <h1>SMS Varsayılanılan</h1>
      <p>EratGuard’ın spam SMS’leri yüksek oranda yakalayıp engelleyebilmesi için uygulamayı varsayılan SMS uygulaması yapman gerekir.</p>
      <p class="note">Android uygulama içinde bu dilim native “Varsayılan SMS uygulaması yap” ekranını açacak şekilde köprülenir. Bu ekran web fallback bilgilendirmesidir.</p>
      <a class="btn primary" href="/u/eg-panel">Radial Panele Dön</a>
      <a class="btn ghost" href="/u/protection">PRO Koruma Durumunu Aç</a>
    </div>
  </div>
</body>
</html>
        """)

    except Exception:
        return None


try:
    app.before_request(eratguard_sms_default_priority_bridge)

    _lst = app.before_request_funcs.get(None, [])
    if eratguard_sms_default_priority_bridge in _lst:
        _lst.remove(eratguard_sms_default_priority_bridge)
        _lst.insert(0, eratguard_sms_default_priority_bridge)

    print("ERATGUARD SMS DEFAULT PRIORITY BRIDGE ACTIVE")
except Exception as _eg_sms_priority_error:
    print("ERATGUARD SMS DEFAULT PRIORITY BRIDGE ERROR:", _eg_sms_priority_error)
# ERATGUARD_SMS_DEFAULT_PRIORITY_BRIDGE_END



# ERATGUARD_RADIAL_FINAL_RESPONSE_LABEL_LOCK_START
# /radial cevabı başka eski hook'lar tarafından değişse bile en son SMS VARSAYILAN etiketi garanti edilir.


# ERATGUARD_RADIAL_FINAL_RESPONSE_LABEL_LOCK_END

# ERATGUARD_RADIAL_12P_TARGET_FALLBACK_ROUTES_START
# Yayın güvenliği:
# Radial 12P üzerindeki hiçbir dilim 404'e düşmeyecek.
# Eksik modüller güvenli fallback ekranlara bağlanır.


# ERATGUARD_RADIAL_12P_TARGET_FALLBACK_ROUTES_END

# ERATGUARD_PRIVACY_POLICY_PAGE_START
# Play Console için yayın uyumlu gizlilik politikası sayfası.
def eratguard_privacy_policy_page():
    try:
        from flask import render_template_string

        return render_template_string("""
<!doctype html>
<html lang="tr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
  <title>Gizlilik Politikası · EratGuard</title>
  <style>
    body{margin:0;background:#020806;color:#eafff4;font-family:Arial,Helvetica,sans-serif}
    .wrap{max-width:900px;margin:0 auto;padding:26px 18px 50px}
    .card{border:1px solid rgba(0,255,140,.42);border-radius:24px;background:#06140f;padding:24px;box-shadow:0 0 36px rgba(0,255,140,.18)}
    h1{color:#7cffb2;margin:0 0 8px;font-size:30px}
    h2{color:#7cffb2;margin-top:26px;font-size:20px}
    p,li{line-height:1.62;color:#e0fff0}
    .muted{color:#9df7c5;font-size:14px}
    .badge{display:inline-block;padding:6px 10px;border-radius:999px;border:1px solid rgba(0,255,140,.55);background:rgba(0,255,140,.12);font-weight:900;font-size:12px}
    a{color:#7cffb2}
    ul{padding-left:20px}
    .footer{margin-top:22px;border-top:1px solid rgba(0,255,140,.24);padding-top:14px;color:#9df7c5}
  </style>
</head>
<body>
  <main class="wrap">
    <section class="card">
      <span class="badge">ERATGUARD PRIVACY POLICY</span>
      <h1>Gizlilik Politikası</h1>
      <p class="muted">Son güncelleme: 24 Haziran 2026</p>

      <p>
        EratGuard, kullanıcıları spam SMS, şüpheli bağlantılar ve riskli mesaj içeriklerine karşı korumak için geliştirilen güvenli bir SMS koruma uygulamasıdır.
        Bu gizlilik politikası, EratGuard’ın hangi verileri işleyebileceğini, bu verileri hangi amaçlarla kullandığını ve kullanıcı kontrol seçeneklerini açıklar.
      </p>

      <h2>1. Uygulamanın Temel İşlevi</h2>
      <p>
        EratGuard’ın temel işlevi, spam SMS koruma ve güvenli mesaj yönetimi sağlamaktır.
        Uygulama, Android cihazda varsayılan SMS uygulaması olarak çalışacak şekilde tasarlanmıştır.
        Varsayılan SMS uygulaması olduğunda gelen SMS/MMS mesajlarını alabilir, güvenlik kontrolünden geçirebilir, spam veya riskli içerikleri tespit edebilir ve kullanıcıya bildirim gösterebilir.
      </p>

      <h2>2. İşlenebilecek Veriler</h2>
      <p>EratGuard, kullanıcının verdiği izinler ve varsayılan SMS uygulaması durumu kapsamında aşağıdaki verileri işleyebilir:</p>
      <ul>
        <li>Gelen SMS mesajları</li>
        <li>Gelen MMS ve WAP Push mesajları</li>
        <li>Mesaj içeriğinde bulunan bağlantılar veya risk göstergeleri</li>
        <li>Engellenen, şüpheli veya spam olarak işaretlenen mesaj kayıtları</li>
        <li>Spam analiz sonuçları</li>
        <li>Güvenlik skoru, bildirim ve rapor verileri</li>
      </ul>

      <h2>3. SMS ve MMS İzinlerinin Kullanımı</h2>
      <p>
        EratGuard aşağıdaki izinleri yalnızca spam mesaj koruması, güvenli mesaj yönetimi ve varsayılan SMS uygulaması işlevlerini sağlamak için kullanır:
      </p>
      <ul>
        <li><strong>RECEIVE_SMS:</strong> Gelen SMS mesajlarını algılamak ve spam/risk analizi yapmak için kullanılır.</li>
        <li><strong>READ_SMS:</strong> Mesajları spam tespiti, güvenlik kontrolü, engellenen mesaj yönetimi ve raporlama için kullanır.</li>
        <li><strong>SEND_SMS:</strong> Varsayılan SMS uygulaması olarak kullanıcı tarafından başlatılan mesaj gönderme işlemlerini gerçekleştirmek için kullanılır.</li>
        <li><strong>RECEIVE_MMS:</strong> Gelen MMS mesajlarını varsayılan mesajlaşma akışı içinde almak ve güvenlik kontrolünden geçirmek için kullanılır.</li>
        <li><strong>RECEIVE_WAP_PUSH:</strong> MMS/WAP Push mesajlarını işlemek ve varsayılan SMS/MMS uygulaması görevlerini tamamlamak için kullanılır.</li>
      </ul>

      <h2>4. Verilerin Kullanım Amaçları</h2>
      <p>EratGuard verileri şu amaçlarla kullanabilir:</p>
      <ul>
        <li>Spam SMS tespiti yapmak</li>
        <li>Şüpheli bağlantıları veya riskli içerikleri analiz etmek</li>
        <li>Kullanıcıya güvenlik bildirimi göstermek</li>
        <li>Engellenen veya şüpheli mesajları raporlamak</li>
        <li>Varsayılan SMS uygulaması işlevlerini sağlamak</li>
        <li>Güvenlik skoru ve koruma raporları oluşturmak</li>
      </ul>

      <h2>5. Veri Paylaşımı ve Reklam Kullanımı</h2>
      <p>
        EratGuard SMS/MMS verilerini reklam hedefleme, kullanıcı takibi, pazarlama profili oluşturma veya üçüncü taraflara veri satışı amacıyla kullanmaz.
        SMS ve MMS verileri yalnızca uygulamanın güvenlik, spam koruma ve mesaj yönetimi işlevlerini sağlamak için işlenir.
      </p>

      <h2>6. Kullanıcı Kontrolü</h2>
      <p>
        Kullanıcı, Android ayarlarından EratGuard’ı varsayılan SMS uygulaması yapabilir veya varsayılan SMS uygulaması olmaktan çıkarabilir.
        Kullanıcı ayrıca Android uygulama izinleri ekranından SMS/MMS izinlerini yönetebilir.
        EratGuard varsayılan SMS uygulaması olmaktan çıkarılırsa bazı SMS koruma özellikleri sınırlı çalışabilir veya devre dışı kalabilir.
      </p>

      <h2>7. Veri Güvenliği</h2>
      <p>
        EratGuard, kullanıcı verilerinin güvenliğini korumak için makul teknik ve idari önlemler uygular.
        Uygulama, SMS/MMS verilerini yalnızca gerekli güvenlik ve mesaj yönetimi işlevleri için işler.
      </p>

      <h2>8. Çocukların Gizliliği</h2>
      <p>
        EratGuard çocuklara yönelik olarak tasarlanmamıştır.
        Uygulama, bilerek çocuklardan kişisel veri toplamayı amaçlamaz.
      </p>

      <h2>9. Değişiklikler</h2>
      <p>
        Bu gizlilik politikası zaman zaman güncellenebilir.
        Güncel politika bu sayfada yayınlanır.
      </p>

      <h2>10. İletişim</h2>
      <p>
        Gizlilik politikası veya veri kullanımı hakkında sorular için uygulama içindeki destek/topluluk alanı kullanılabilir.
      </p>

      <div class="footer">
        EratGuard · Spam SMS Koruma · Varsayılan SMS Güvenlik Merkezi
        <br>
        <a href="/u/eg-panel">Radial Panele Dön</a>
      </div>
    </section>
  </main>
</body>
</html>
        """)

    except Exception:
        return "EratGuard Gizlilik Politikası", 200


def eratguard_privacy_policy_guard():
    try:
        from flask import request

        path = (request.path or "/").rstrip("/") or "/"

        if path in {"/privacy", "/privacy-policy", "/gizlilik", "/gizlilik-politikasi"}:
            return eratguard_privacy_policy_page()

        return None
    except Exception:
        return None


try:
    app.before_request(eratguard_privacy_policy_guard)

    _lst = app.before_request_funcs.get(None, [])
    if eratguard_privacy_policy_guard in _lst:
        _lst.remove(eratguard_privacy_policy_guard)
        _lst.insert(0, eratguard_privacy_policy_guard)

    print("ERATGUARD PRIVACY POLICY PAGE ACTIVE")
except Exception as _eg_privacy_error:
    print("ERATGUARD PRIVACY POLICY PAGE ERROR:", _eg_privacy_error)
# ERATGUARD_PRIVACY_POLICY_PAGE_END




# ERATGUARD_RADIAL_LAB_DOME_PRO_START


# ERATGUARD_RADIAL_LAB_DOME_PRO_END


# === ERATGUARD HARDENING V1 PRIVACY NO SALE LOCK ===
# Play review için SMS/veri kullanımı netleştirme: satış yok, reklam takibi yok.
try:
    @app.before_request
    def eratguard_hardening_v1_privacy_no_sale_guard():
        try:
            path = request.path or ""
        except Exception:
            path = ""
        if path in ("/privacy", "/privacy-policy", "/gizlilik", "/gizlilik-politikasi"):
            html = """
<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>EratGuard PRO - Gizlilik Politikası</title>
<style>
:root{--bg:#020806;--card:#07130f;--line:rgba(0,255,150,.22);--text:#eafff4;--muted:#9bd8bd;--green:#00f08a}
*{box-sizing:border-box}
body{margin:0;background:radial-gradient(circle at 50% 0%,#0b2b1e 0,#020806 52%,#000 100%);color:var(--text);font-family:Arial,system-ui,sans-serif;padding:22px}
.wrap{max-width:820px;margin:0 auto}
.card{background:rgba(7,19,15,.92);border:1px solid var(--line);border-radius:22px;padding:22px;box-shadow:0 0 28px rgba(0,255,150,.12)}
h1{margin:0 0 10px;color:var(--green);font-size:25px}
h2{margin:22px 0 8px;font-size:18px;color:#cffff0}
p,li{line-height:1.55;color:var(--muted);font-size:15px}
.badge{display:inline-block;border:1px solid var(--line);border-radius:999px;padding:7px 12px;margin:4px 5px 4px 0;color:#cffff0;background:rgba(0,255,150,.06);font-size:13px}
.strong{color:#fff;font-weight:800}
a{color:var(--green)}
</style>
</head>
<body>
<div class="wrap">
<div class="card">
<h1>Gizlilik Politikası</h1>
<p class="strong">EratGuard PRO, spam SMS koruması ve varsayılan SMS uygulaması işlevleri için gerekli verileri kullanır. Kullanıcı verileri satılmaz, reklam profili oluşturmak için kullanılmaz ve üçüncü taraf reklam ağlarıyla paylaşılmaz.</p>

<h2>Kullanılan izinler</h2>
<span class="badge">RECEIVE_SMS</span>
<span class="badge">READ_SMS</span>
<span class="badge">SEND_SMS</span>
<span class="badge">RECEIVE_MMS</span>
<span class="badge">RECEIVE_WAP_PUSH</span>
<span class="badge">POST_NOTIFICATIONS</span>

<h2>SMS verilerinin kullanım amacı</h2>
<ul>
<li>Gelen SMS/MMS mesajlarını spam, riskli bağlantı ve dolandırıcılık işaretleri için analiz etmek.</li>
<li>Engellenen veya riskli mesajları kullanıcıya göstermek.</li>
<li>Varsayılan SMS uygulaması işlevlerini sağlamak.</li>
<li>Bildirim, rapor, güvenlik skoru ve kullanıcı destek süreçlerini çalıştırmak.</li>
</ul>

<h2>Veri satışı ve reklam</h2>
<p class="strong">EratGuard PRO kullanıcı SMS içeriklerini, telefon numaralarını, kişi bilgilerini veya güvenlik raporlarını satmaz. Bu veriler reklam hedefleme, pazarlama profili veya üçüncü taraf takip amacıyla kullanılmaz.</p>

<h2>Kullanıcı kontrolü</h2>
<p>Kullanıcı, Android ayarlarından varsayılan SMS uygulamasını değiştirebilir ve izinleri geri alabilir. İzinler kaldırıldığında SMS koruma özellikleri sınırlı çalışabilir.</p>

<h2>İletişim</h2>
<p>Destek ve gizlilik talepleri için uygulama içindeki Destek bölümünü kullanabilirsiniz.</p>
</div>
</div>
</body>
</html>
"""
            return html, 200, {"Content-Type": "text/html; charset=utf-8"}
except Exception:
    pass
# === /ERATGUARD HARDENING V1 PRIVACY NO SALE LOCK ===

# === ERATGUARD HARDENING V1B PRIVACY PRIORITY FIX ===
# V1 privacy guard eski privacy guard'lardan sonra kaldıysa en başa taşır.
try:
    _eg_hv1b_funcs = app.before_request_funcs.setdefault(None, [])
    _eg_hv1b_funcs = [
        f for f in _eg_hv1b_funcs
        if getattr(f, "__name__", "") != "eratguard_hardening_v1_privacy_no_sale_guard"
    ]
    if "eratguard_hardening_v1_privacy_no_sale_guard" in globals():
        _eg_hv1b_funcs.insert(0, eratguard_hardening_v1_privacy_no_sale_guard)
        app.before_request_funcs[None] = _eg_hv1b_funcs
        print("ERATGUARD HARDENING V1B PRIVACY PRIORITY FIX ACTIVE")
except Exception as _eg_hv1b_err:
    print("ERATGUARD HARDENING V1B PRIVACY PRIORITY FIX ERROR:", _eg_hv1b_err)
# === /ERATGUARD HARDENING V1B PRIVACY PRIORITY FIX ===


# ===== ADMIN BLUE COMMAND CENTER REMOVED =====
# Legacy Admin Blue sistemi tamamen kaldırıldı.
# Yeni admin yapısı admin Blueprint altında geliştiriliyor.

from datetime import timedelta as _eg_timedelta

def _eg_panel_metrics():
    actions = _eg_load_sms_actions()
    counts = _eg_counts(actions)
    total = counts.get("total", 0)
    blocked = counts.get("blocked", 0)
    safe = counts.get("safe", 0)
    reported = counts.get("reported", 0)

    score = round(100 * safe / total) if total > 0 else 100
    score = max(0, min(100, score))

    if score >= 80:
        threat_label = "DÜŞÜK"
    elif score >= 50:
        threat_label = "ORTA"
    else:
        threat_label = "YÜKSEK"

    today = datetime.now().date()
    day_counts = {}
    for i in range(7):
        d = today - _eg_timedelta(days=6 - i)
        day_counts[d.isoformat()] = 0
    for a in actions:
        ts = str(a.get("created_at", ""))
        try:
            d = datetime.fromisoformat(ts.replace("Z", "")).date().isoformat()
        except Exception:
            continue
        if d in day_counts:
            day_counts[d] += 1

    values = list(day_counts.values())
    max_v = max(values) if max(values) > 0 else 1
    n = len(values)
    points = []
    for idx, v in enumerate(values):
        x = round(idx * (98 / (n - 1))) if n > 1 else 0
        y = round(26 - (v / max_v) * 22)
        points.append(f"{x},{y}")
    spark_points = " ".join(points)

    return {
        "total": total, "blocked": blocked, "safe": safe, "reported": reported,
        "score": score, "threat_label": threat_label, "spark_points": spark_points,
    }


@app.route("/u/eg-panel")
def eg_user_panel_v2():
    if not login_required():
        return redirect(url_for("login"))

    metrics = _eg_panel_metrics()

    users = load_users()
    username = session.get("username", "")
    udata = users.get(username, {})
    # Canonical entitlement is the dashboard license source.
    entitlement = _eg_user_entitlement_v1(udata)
    license_info = {
        "plan": entitlement.get("tier") or "FREE",
        "expires_at": entitlement.get("expires_at") or "—",
    }

    return render_template("eg_panel_v2.html", metrics=metrics, license_info=license_info)


# ===== EVA USER ASSISTANT (kullaniciya ozel, kisitli erisim) =====
@app.route("/u/eva-chat", methods=["POST"])
def eva_chat_user():
    if not login_required():
        return jsonify({"ok": False, "error": "Oturum gerekli."}), 401

    from admin.services.eva import ask_eva_user

    try:
        payload = request.get_json(silent=True) or {}
        message = str(payload.get("message", "")).strip()
        history = payload.get("history", [])

        if not message:
            return jsonify({"ok": False, "error": "Mesaj bos olamaz."}), 400

        if not isinstance(history, list):
            history = []

        username = session.get("username", "")
        metrics = _eg_panel_metrics()
        users = load_users()
        udata = users.get(username, {})
        license_info = {
            "plan": udata.get("license_key") or "Ucretsiz",
            "expires_at": udata.get("expires_at") or "-",
        }

        ok, answer = ask_eva_user(username, metrics, license_info, message, history)

        return jsonify({"ok": ok, "answer": answer})

    except Exception as e:
        return jsonify({"ok": False, "error": "Sunucu hatasi."}), 500
# ===== EVA USER ASSISTANT END =====







# =====================================================================



# ============================================================
# ERATGUARD USER AUTH PRIORITY LOCK V1
# Existing strict user auth guard must run before legacy
# before_request render/override bridges.
# ============================================================

try:
    _eg_user_auth_priority_funcs = app.before_request_funcs.setdefault(None, [])

    if "_eg_strict_user_auth_guard_final" in globals():
        _eg_user_auth_priority_guard = _eg_strict_user_auth_guard_final

        # Remove every existing registration of the same function.
        _eg_user_auth_priority_funcs[:] = [
            fn for fn in _eg_user_auth_priority_funcs
            if fn is not _eg_user_auth_priority_guard
        ]

        # Absolute first responder.
        _eg_user_auth_priority_funcs.insert(
            0,
            _eg_user_auth_priority_guard
        )

        print(
            "ERATGUARD USER AUTH PRIORITY LOCK V1 ACTIVE:",
            _eg_user_auth_priority_funcs[0].__name__
        )

except Exception as _eg_user_auth_priority_error:
    print(
        "ERATGUARD USER AUTH PRIORITY LOCK V1 ERROR:",
        repr(_eg_user_auth_priority_error)
    )

# ============================================================
# ERATGUARD USER AUTH RESPONSE LOCK V1
#
# Final response boundary for protected user routes.
# Legacy after_request renderers may rewrite redirect responses.
# This lock executes LAST and restores the authentication
# redirect whenever no valid user session exists.
# ============================================================

def _eg_user_auth_response_lock_v1(response):
    try:
        path = (request.path or "").rstrip("/") or "/"

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
            return response

        if path.startswith("/static/"):
            return response

        if path.startswith("/api/system-resources"):
            return response

        # Admin authentication is handled separately.
        if path.startswith("/admin") or path.startswith("/ss-admin"):
            return response

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

        if not path.startswith(protected_prefixes):
            return response

        has_user_session = bool(
            session.get("logged_in")
            and session.get("username")
        )

        if has_user_session:
            return response

        # Do not trust a legacy after_request-modified response.
        # Rebuild the auth redirect from scratch.
        locked = redirect("/login?auth_required=1")

        locked.headers["Cache-Control"] = (
            "no-store, no-cache, must-revalidate, max-age=0"
        )
        locked.headers["Pragma"] = "no-cache"

        return locked

    except Exception as _eg_user_auth_response_lock_error:
        try:
            print(
                "ERATGUARD USER AUTH RESPONSE LOCK V1 ERROR:",
                repr(_eg_user_auth_response_lock_error),
                flush=True,
            )
        except Exception:
            pass

        return response


try:
    _eg_user_auth_response_funcs = app.after_request_funcs.setdefault(
        None, []
    )

    # Avoid duplicate registration if module is reloaded.
    _eg_user_auth_response_funcs[:] = [
        fn for fn in _eg_user_auth_response_funcs
        if getattr(fn, "__name__", "") !=
        "_eg_user_auth_response_lock_v1"
    ]

    # Flask executes after_request handlers in reverse order.
    # Index 0 therefore executes LAST.
    _eg_user_auth_response_funcs.insert(
        0,
        _eg_user_auth_response_lock_v1
    )

    print(
        "ERATGUARD USER AUTH RESPONSE LOCK V1 ACTIVE:",
        _eg_user_auth_response_funcs[0].__name__
    )

except Exception as _eg_user_auth_response_register_error:
    print(
        "ERATGUARD USER AUTH RESPONSE LOCK V1 REGISTER ERROR:",
        repr(_eg_user_auth_response_register_error)
    )



# =============================================================================

# =============================================================================


# =============================================================================

# =============================================================================


# =============================================================================

# =============================================================================


# ================================================================
# ===== ERATGUARD CANONICAL USER HOME BOUNDARY V1 START =====
#
# Canonical authenticated user home:
#
#     /dashboard
#
# Actual UI implementation remains eg_user_panel_v2().
#
# Compatibility aliases:
#     /radial
#     /signature-radial
#     /u/eg-panel
#     /
#
# Admin routes are intentionally excluded.
#
try:
    from flask import request as _eg_ch1_request
    from flask import session as _eg_ch1_session
    from flask import redirect as _eg_ch1_redirect

    def _eg_canonical_user_home_boundary_v1():
        try:
            path = (_eg_ch1_request.path or "/").rstrip("/") or "/"

            # -------------------------------------------------
            # Never interfere with canonical admin namespace.
            # -------------------------------------------------
            if path == "/admin" or path.startswith("/admin/"):
                return None

            logged_in = bool(
                _eg_ch1_session.get("logged_in")
                and _eg_ch1_session.get("username")
            )

            # -------------------------------------------------
            # Root:
            # anonymous     -> /login
            # authenticated -> /dashboard
            # -------------------------------------------------
            if path == "/":
                if not logged_in:
                    return _eg_ch1_redirect("/login", code=302)
                return _eg_ch1_redirect("/dashboard", code=302)

            # -------------------------------------------------
            # Canonical home.
            #
            # Render the already-existing real user panel
            # directly, avoiding old radial/signature chains.
            # -------------------------------------------------
            if path == "/dashboard":
                if not logged_in:
                    return _eg_ch1_redirect(
                        "/login?auth_required=1",
                        code=302
                    )

                return eg_user_panel_v2()

            # -------------------------------------------------
            # Historical home aliases.
            # Keep URLs alive but canonicalize them.
            # -------------------------------------------------
            if path in {
                "/radial",
                "/radial-menu",
                "/radial-demo",
                "/signature-radial",
                "/u/eg-panel",
                "/u/dashboard",
                "/app-start",
            }:
                if not logged_in:
                    return _eg_ch1_redirect(
                        "/login?auth_required=1",
                        code=302
                    )

                return _eg_ch1_redirect("/dashboard", code=302)

            return None

        except Exception as _eg_ch1_error:
            try:
                print(
                    "ERATGUARD CANONICAL USER HOME BOUNDARY V1 WARN:",
                    repr(_eg_ch1_error),
                    flush=True
                )
            except Exception:
                pass

            return None


    # Register, then force to absolute first position.
    app.before_request(_eg_canonical_user_home_boundary_v1)

    _eg_ch1_funcs = app.before_request_funcs.setdefault(None, [])

    _eg_ch1_funcs = [
        f for f in _eg_ch1_funcs
        if getattr(f, "__name__", "") !=
           "_eg_canonical_user_home_boundary_v1"
    ]

    _eg_ch1_funcs.insert(
        0,
        _eg_canonical_user_home_boundary_v1
    )

    app.before_request_funcs[None] = _eg_ch1_funcs

    print(
        "ERATGUARD CANONICAL USER HOME BOUNDARY V1 ACTIVE: "
        "/dashboard -> eg_user_panel_v2",
        flush=True
    )

except Exception as _eg_ch1_boot_error:
    print(
        "ERATGUARD CANONICAL USER HOME BOUNDARY V1 BOOT ERROR:",
        repr(_eg_ch1_boot_error),
        flush=True
    )

# =============================================================================

# ===== ERATGUARD ADMIN CORE AUTH RUNTIME V1 START =====

# Temporary migration adapter for remaining old ADMIN UI/control planes.
# Authentication authority remains admin.auth; this adapter carries no
# independent authentication policy and will disappear with those planes.
def _eg_admin_core_is_real_admin_v1():
    try:
        from admin.auth import is_real_admin
        return bool(is_real_admin(load_users))
    except Exception:
        return False


#
# Canonical runtime ownership:
#   /admin/login  -> admin.auth.admin_login_view
#   /admin/logout -> admin.auth.admin_logout_view
#   /admin/*      -> admin.auth.admin_auth_boundary
#
# Legacy admin authentication source remains physically present for
# rollback safety, but legacy admin-auth before_request hooks are removed
# from the runtime chain before the canonical boundary is installed.
#
try:
    from admin.auth import (
        admin_auth_boundary as _eg_admin_core_boundary,
        admin_login_view as _eg_admin_core_login,
        admin_logout_view as _eg_admin_core_logout,
    )

    # -----------------------------------------------------------------
    # Runtime adapters.
    # Keep project storage/rate-limit ownership outside admin/auth.py.
    # -----------------------------------------------------------------

    def _eg_admin_core_login_view():
        return _eg_admin_core_login(
            load_users=load_users,
            rate_limit_check=globals().get("_eg_rate_limit_check"),
        )


    def _eg_admin_core_logout_view():
        return _eg_admin_core_logout()


    def _eg_admin_core_auth_boundary_v1():
        return _eg_admin_core_boundary(
            load_users=load_users,
        )


    # -----------------------------------------------------------------
    # /admin/login — force canonical owner.
    # Existing URL rule is reused; no duplicate rule is created.
    # -----------------------------------------------------------------

    _eg_admin_core_login_rules = [
        rule
        for rule in list(app.url_map.iter_rules())
        if str(rule).rstrip("/") == "/admin/login"
    ]

    if not _eg_admin_core_login_rules:
        app.add_url_rule(
            "/admin/login",
            endpoint="eg_admin_core_login",
            view_func=_eg_admin_core_login_view,
            methods=["GET", "POST"],
        )
    else:
        for rule in _eg_admin_core_login_rules:
            app.view_functions[
                rule.endpoint
            ] = _eg_admin_core_login_view


    # -----------------------------------------------------------------
    # /admin/logout — canonical owner.
    # Reuse historical rule if one exists; otherwise create one.
    # -----------------------------------------------------------------

    _eg_admin_core_logout_rules = [
        rule
        for rule in list(app.url_map.iter_rules())
        if str(rule).rstrip("/") == "/admin/logout"
    ]

    if not _eg_admin_core_logout_rules:
        app.add_url_rule(
            "/admin/logout",
            endpoint="eg_admin_core_logout",
            view_func=_eg_admin_core_logout_view,
            methods=["GET", "POST"],
        )
    else:
        for rule in _eg_admin_core_logout_rules:
            app.view_functions[
                rule.endpoint
            ] = _eg_admin_core_logout_view


    # -----------------------------------------------------------------
    # Remove legacy ADMIN-AUTH hooks from runtime.
    #
    # Important:
    # User authentication, license activation, PRO guard, etc. are NOT
    # touched. Removal is by exact function name only.
    # -----------------------------------------------------------------

    _eg_admin_core_retired_hooks = set()

    _eg_admin_core_before = app.before_request_funcs.setdefault(
        None,
        [],
    )

    _eg_admin_core_removed_hooks = [
        getattr(fn, "__name__", "")
        for fn in _eg_admin_core_before
        if getattr(fn, "__name__", "")
        in _eg_admin_core_retired_hooks
    ]

    _eg_admin_core_before[:] = [
        fn
        for fn in _eg_admin_core_before
        if getattr(fn, "__name__", "")
        not in _eg_admin_core_retired_hooks
    ]

    # Remove an earlier copy of our own hook defensively.
    _eg_admin_core_before[:] = [
        fn
        for fn in _eg_admin_core_before
        if getattr(fn, "__name__", "")
        != "_eg_admin_core_auth_boundary_v1"
    ]

    # Absolute priority for admin authorization.
    _eg_admin_core_before.insert(
        0,
        _eg_admin_core_auth_boundary_v1,
    )


    # -----------------------------------------------------------------
    # Legacy /ss-admin-access is compatibility redirect only.
    # It no longer performs authentication.
    # -----------------------------------------------------------------

    def _eg_admin_core_legacy_login_redirect():
        from flask import redirect, request
        from urllib.parse import quote

        raw_next = str(
            request.args.get("next") or ""
        ).strip()

        target = "/admin/login"

        if (
            raw_next.startswith("/admin")
            and not raw_next.startswith("//")
        ):
            target += "?next=" + quote(
                raw_next,
                safe="/?=&",
            )

        return redirect(target, code=302)


    for rule in list(app.url_map.iter_rules()):
        if str(rule).rstrip("/") == "/ss-admin-access":
            app.view_functions[
                rule.endpoint
            ] = _eg_admin_core_legacy_login_redirect


    print(
        "ERATGUARD ADMIN CORE AUTH RUNTIME V1 ACTIVE:",
        "login=/admin/login",
        "logout=/admin/logout",
        "boundary=index0",
        "legacy_hooks_removed="
        + repr(_eg_admin_core_removed_hooks),
        flush=True,
    )

except Exception as _eg_admin_core_auth_boot_error:
    print(
        "ERATGUARD ADMIN CORE AUTH RUNTIME V1 BOOT ERROR:",
        repr(_eg_admin_core_auth_boot_error),
        flush=True,
    )
    raise

# ===== ERATGUARD ADMIN CORE AUTH RUNTIME V1 END =====


# ERATGUARD PHASE 7D.18A - TRUE FINAL APPLICATION BOOT
# =============================================================================
# IMPORTANT:
# All routes, quarantine layers, authentication boundaries and canonical
# runtime control planes must be registered BEFORE the Flask server starts.
# =============================================================================


# === ERATGUARD MOBILE LOGIN API V1 ===

@app.route("/api/mobile/login", methods=["POST"])
def eratguard_mobile_login():
    try:
        data = request.get_json(silent=True) or {}

        username = str(data.get("username", "")).strip()
        password = str(data.get("password", ""))
        installation_id = str(data.get("installation_id", "")).strip()

        if not username or not password:
            return jsonify({
                "ok": False,
                "error": "missing_credentials",
                "message": "Kullanıcı adı ve şifre gerekli."
            }), 400

        users = load_users()
        user = users.get(username)

        locked, remaining = _eg_login_lock_status(username)

        if locked:
            return jsonify({
                "ok": False,
                "error": "login_locked",
                "remaining_seconds": remaining,
                "message": "Çok fazla hatalı giriş denemesi."
            }), 429

        if not user:
            _eg_login_record_failure(username)
            return jsonify({
                "ok": False,
                "error": "invalid_credentials",
                "message": "Kullanıcı adı veya şifre yanlış."
            }), 401

        if not user.get("active", True):
            return jsonify({
                "ok": False,
                "error": "inactive_user",
                "message": "Bu kullanıcı pasif durumda."
            }), 403

        entitlement = _eg_user_entitlement_v1(user)
        expires_at = entitlement.get("expires_at", "")

        stored_password = str(
            user.get("password")
            or user.get("password_hash")
            or ""
        )

        if not stored_password or not check_password_hash(
            stored_password,
            password
        ):
            count = _eg_login_record_failure(username)

            return jsonify({
                "ok": False,
                "error": "invalid_credentials",
                "attempt_count": count,
                "message": "Kullanıcı adı veya şifre yanlış."
            }), 401

        _eg_login_clear_failures(username)

        # === ERATGUARD MOBILE DEVICE LIMIT V1 ===
        # Admin hesapları cihaz sınırından muaftır.
        is_admin_user = (
            str(user.get("role", "")).lower() == "admin"
            or bool(user.get("is_admin"))
        )

        if not is_admin_user:
            if not installation_id:
                return jsonify({
                    "ok": False,
                    "error": "installation_id_required",
                    "message": "Bu uygulama sürümü için cihaz kimliği gerekli."
                }), 400

            import hashlib

            installation_hash = hashlib.sha256(
                installation_id.encode("utf-8")
            ).hexdigest()

            try:
                device_limit = int(user.get("device_limit", 1))
            except (TypeError, ValueError):
                device_limit = 1

            device_limit = max(1, device_limit)

            devices = user.get("devices", [])
            if not isinstance(devices, list):
                devices = []

            now_device = __import__("datetime").datetime.now().isoformat(
                timespec="seconds"
            )

            matched_device = None
            for device in devices:
                if (
                    isinstance(device, dict)
                    and device.get("installation_hash") == installation_hash
                ):
                    matched_device = device
                    break

            if matched_device is not None:
                matched_device["last_seen"] = now_device
            else:
                if len(devices) >= device_limit:
                    return jsonify({
                        "ok": False,
                        "error": "device_limit_reached",
                        "device_limit": device_limit,
                        "message": "Bu lisans için izin verilen cihaz sınırına ulaşıldı."
                    }), 403

                devices.append({
                    "installation_hash": installation_hash,
                    "first_seen": now_device,
                    "last_seen": now_device
                })

            users[username]["device_limit"] = device_limit
            users[username]["devices"] = devices
            user = users[username]
        # === /ERATGUARD MOBILE DEVICE LIMIT V1 ===

        try:
            from datetime import datetime

            now = datetime.now().isoformat(timespec="seconds")
            users[username]["last_login"] = now
            users[username]["last_seen"] = now
            save_users(users)

            _eg_touch_user_session(username, "mobile_login")
            _eg_audit_log(
                "mobile_login_success",
                username,
                {"role": user.get("role", "user")},
                "info"
            )
        except Exception:
            pass

        return jsonify({
            "ok": True,
            "message": "Giriş başarılı.",
            "user": {
                "username": username,
                "email": user.get("email", ""),
                "role": user.get("role", "user"),
                "premium": bool(
                    entitlement.get("premium")
                ),
                "plan": entitlement.get(
                    "tier",
                    "FREE"
                ),
                "license_status": entitlement.get(
                    "tier",
                    "FREE"
                ).lower(),
                "license_expiry": entitlement.get(
                    "expires_at",
                    ""
                ),
                "license_label": entitlement.get(
                    "tier",
                    "FREE"
                )
            }
        }), 200

    except Exception as e:
        print("MOBILE_LOGIN_API_ERROR:", repr(e), flush=True)

        return jsonify({
            "ok": False,
            "error": "server_error",
            "message": "Sunucu hatası."
        }), 500


# === /ERATGUARD MOBILE LOGIN API V1 ===



# === ERATGUARD USER ACCOUNT DELETION V1 ===

def _eg_account_delete_load_json(path, default):
    try:
        from pathlib import Path as _Path
        import json as _json

        p = _Path(path)
        if not p.exists():
            return default

        return _json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return default


def _eg_account_delete_save_json(path, data):
    from pathlib import Path as _Path
    import json as _json

    p = _Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)

    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(
        _json.dumps(data, ensure_ascii=False, indent=2),
        encoding="utf-8"
    )
    tmp.replace(p)


def _eg_delete_username_dict_record(path, username):
    data = _eg_account_delete_load_json(path, {})

    if not isinstance(data, dict):
        return 0

    if username not in data:
        return 0

    del data[username]
    _eg_account_delete_save_json(path, data)
    return 1


def _eg_delete_username_list_records(path, username):
    data = _eg_account_delete_load_json(path, [])

    if not isinstance(data, list):
        return 0

    before = len(data)

    cleaned = [
        item for item in data
        if not (
            isinstance(item, dict)
            and str(item.get("username", "")).strip() == username
        )
    ]

    removed = before - len(cleaned)

    if removed:
        _eg_account_delete_save_json(path, cleaned)

    return removed


def _eg_detach_user_licenses(username):
    changed = 0

    # data/licenses.json -> dict, anahtar lisans kodu
    licenses_path = "data/licenses.json"
    licenses = _eg_account_delete_load_json(licenses_path, {})

    if isinstance(licenses, dict):
        for _, item in licenses.items():
            if not isinstance(item, dict):
                continue

            if str(item.get("username", "")).strip() == username:
                item["username"] = ""
                item["status"] = "revoked_account_deleted"
                item["revoked_reason"] = "account_deleted"
                changed += 1

        if changed:
            _eg_account_delete_save_json(licenses_path, licenses)

    # data/generated_licenses.json -> list
    generated_path = "data/generated_licenses.json"
    generated = _eg_account_delete_load_json(generated_path, [])

    generated_changed = 0

    if isinstance(generated, list):
        for item in generated:
            if not isinstance(item, dict):
                continue

            owner = str(item.get("username", "")).strip()
            activated_by = str(item.get("activated_by", "")).strip()

            if owner == username or activated_by == username:
                if "username" in item:
                    item["username"] = ""

                if "activated_by" in item:
                    item["activated_by"] = ""

                item["status"] = "revoked_account_deleted"
                item["revoked_reason"] = "account_deleted"
                generated_changed += 1

        if generated_changed:
            _eg_account_delete_save_json(generated_path, generated)

    return changed + generated_changed


def _eg_delete_user_application_data(username):
    removed = {}

    # username doğrudan JSON anahtarı olan dosyalar
    dict_files = [
        "data/user_settings.json",
        "data/user_block_list.json",
        "data/user_notification_settings.json",
        "data/user_notifications.json",
    ]

    for path in dict_files:
        removed[path] = _eg_delete_username_dict_record(path, username)

    # username kayıtların içindeki alan olan liste dosyaları
    list_files = [
        "data/user_analysis_history.json",
        "data/user_quarantine.json",
        "data/user_titanium_events.json",
        "data/user_community_feedback.json",
        "data/community_reports.json",
        "data/spam_reports.json",
    ]

    for path in list_files:
        removed[path] = _eg_delete_username_list_records(path, username)

    # Oturumlar mümkünse mevcut yardımcı fonksiyon üzerinden temizlenir.
    try:
        loader = globals().get("_eg_load_user_sessions")
        saver = globals().get("_eg_save_user_sessions")

        if callable(loader) and callable(saver):
            sessions = loader()

            if isinstance(sessions, dict) and username in sessions:
                del sessions[username]
                saver(sessions)
                removed["data/user_sessions.json"] = 1
            else:
                removed["data/user_sessions.json"] = 0
        else:
            removed["data/user_sessions.json"] = \
                _eg_delete_username_dict_record(
                    "data/user_sessions.json",
                    username
                )
    except Exception:
        removed["data/user_sessions.json"] = \
            _eg_delete_username_dict_record(
                "data/user_sessions.json",
                username
            )

    removed["licenses"] = _eg_detach_user_licenses(username)

    return removed


@app.route("/account-deletion", methods=["GET"])
def account_deletion_info():
    deleted = request.args.get("deleted") == "1"

    message = ""
    if deleted:
        message = """
        <div class="success">
            Hesabınız ve EratGuard PRO kullanıcı verileriniz silindi.
        </div>
        """

    return f"""<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>EratGuard PRO - Hesap ve Veri Silme</title>

<style>
body {{
    margin:0;
    padding:24px;
    background:#06110c;
    color:#eef7f1;
    font-family:system-ui,-apple-system,Arial,sans-serif;
}}

.card {{
    max-width:720px;
    margin:40px auto;
    padding:28px;
    border-radius:22px;
    background:#0b1c13;
    border:1px solid #244532;
}}

h1 {{
    margin-top:0;
    color:#5cff9b;
}}

h2 {{
    margin-top:28px;
    color:#c8ffda;
}}

p, li {{
    line-height:1.65;
}}

a.button {{
    display:inline-block;
    margin-top:15px;
    padding:14px 20px;
    border-radius:14px;
    background:#18d878;
    color:#031108;
    font-weight:800;
    text-decoration:none;
}}

.notice {{
    margin-top:20px;
    padding:16px;
    border-radius:14px;
    background:#16241b;
}}

.success {{
    margin-bottom:20px;
    padding:16px;
    border-radius:14px;
    background:#123c25;
    color:#8effb5;
    font-weight:700;
}}
</style>
</head>

<body>
<div class="card">

{message}

<h1>EratGuard PRO Hesap ve Veri Silme</h1>

<p>
EratGuard PRO kullanıcıları hesaplarını ve hesaplarıyla ilişkili
kişisel uygulama verilerini silebilir.
</p>

<h2>Hesabınızı nasıl silebilirsiniz?</h2>

<p>
EratGuard PRO hesabınıza giriş yapın ve
<strong>Hesabımı Sil</strong> sayfasını açın.
Kimliğinizi doğrulamak için mevcut şifrenizi tekrar girmeniz gerekir.
</p>

<a class="button" href="/account/delete">
Hesabımı Sil
</a>

<h2>Silinen veriler</h2>

<ul>
<li>Kullanıcı hesabı ve giriş bilgileri</li>
<li>Kullanıcı tercihleri ve ayarları</li>
<li>Bildirim tercihleri ve kullanıcı bildirimleri</li>
<li>Kullanıcı oturum kayıtları</li>
<li>Kullanıcı engelleme listesi</li>
<li>Kullanıcı analiz geçmişi</li>
<li>Kullanıcı karantina kayıtları</li>
<li>Kullanıcıya bağlı Titanium olay kayıtları</li>
<li>Kullanıcı topluluk geri bildirimleri</li>
<li>Hesaba bağlı aktif lisans bağlantısı</li>
</ul>

<div class="notice">
<strong>Ödeme ve işlem kayıtları:</strong>
Hesap silindiğinde ödeme, sipariş veya zorunlu işlem kayıtları
otomatik olarak silinmez. Dolandırıcılığın önlenmesi,
muhasebe, uyuşmazlık çözümü veya geçerli yasal yükümlülükler
gerektirdiği ölçüde bu kayıtlar ayrı olarak saklanabilir.
</div>

<p>
Silme işlemi tamamlandığında kullanıcı oturumu da kapatılır
ve silinen hesapla yeniden giriş yapılamaz.
</p>

<p>
EratGuard PRO
</p>

</div>
</body>
</html>
"""


@app.route("/account/delete", methods=["GET", "POST"])
def account_delete_self():
    if not login_required():
        return redirect(url_for("login"))

    username = str(session.get("username", "")).strip()

    if not username:
        session.clear()
        return redirect(url_for("login"))

    # Sistem hesaplarının yanlışlıkla silinmesini engelle.
    if username in {"admin", "demo"}:
        return """
        <h2>Bu sistem hesabı bu ekrandan silinemez.</h2>
        <p><a href="/">Ana sayfaya dön</a></p>
        """, 403

    error = None

    if request.method == "POST":
        password = request.form.get("password", "")
        confirmation = request.form.get("confirmation", "").strip()

        users = load_users()
        user = users.get(username)

        if not user:
            session.clear()
            return redirect(url_for("login"))

        if confirmation != "HESABIMI SIL":
            error = 'Onay alanına tam olarak "HESABIMI SIL" yazın.'

        elif not check_password_hash(
            str(user.get("password", "")),
            password
        ):
            error = "Şifreniz yanlış."

        else:
            try:
                # Önce kullanıcıya bağlı uygulama verilerini temizle.
                removed = _eg_delete_user_application_data(username)

                # Ana kullanıcı hesabını en son kaldır.
                users = load_users()

                if username in users:
                    del users[username]
                    save_users(users)

                # Güvenlik/audit kaydında içerik yerine yalnızca olay tutulur.
                try:
                    _eg_audit_log(
                        "account_deleted",
                        username,
                        {
                            "self_service": True,
                            "removed_categories": [
                                key for key, value in removed.items()
                                if value
                            ],
                        },
                        "info"
                    )
                except Exception:
                    pass

                session.clear()

                return redirect("/account-deletion?deleted=1")

            except Exception as exc:
                print(
                    "ACCOUNT_DELETE_ERROR:",
                    repr(exc),
                    flush=True
                )
                error = (
                    "Hesap şu anda silinemedi. "
                    "Lütfen daha sonra tekrar deneyin."
                )

    error_html = ""

    if error:
        error_html = f"""
        <div class="error">{error}</div>
        """

    return f"""<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">

<title>EratGuard PRO - Hesabımı Sil</title>

<style>
body {{
    margin:0;
    padding:24px;
    background:#080d0a;
    color:#f2f5f3;
    font-family:system-ui,-apple-system,Arial,sans-serif;
}}

.card {{
    max-width:620px;
    margin:40px auto;
    padding:28px;
    border-radius:22px;
    background:#151b17;
    border:1px solid #463030;
}}

h1 {{
    color:#ff7070;
}}

input {{
    width:100%;
    box-sizing:border-box;
    margin-top:8px;
    margin-bottom:18px;
    padding:14px;
    border-radius:12px;
    border:1px solid #555;
    background:#090c0a;
    color:white;
    font-size:16px;
}}

button {{
    width:100%;
    padding:15px;
    border:0;
    border-radius:14px;
    background:#d83f3f;
    color:white;
    font-size:16px;
    font-weight:800;
}}

.error {{
    margin-bottom:18px;
    padding:14px;
    border-radius:12px;
    background:#471d1d;
    color:#ffd2d2;
}}

.warning {{
    padding:15px;
    margin-bottom:22px;
    border-radius:12px;
    background:#2a2016;
}}
</style>
</head>

<body>

<div class="card">

<h1>Hesabımı Sil</h1>

<p>
<strong>{username}</strong> hesabını kalıcı olarak silmek üzeresiniz.
</p>

<div class="warning">
Bu işlem kullanıcı hesabınızı ve EratGuard PRO içindeki
hesabınıza bağlı kullanıcı verilerini silecektir.
Bu işlem geri alınamaz.
</div>

{error_html}

<form method="post">

<label>Mevcut şifreniz</label>
<input
    type="password"
    name="password"
    autocomplete="current-password"
    required
>

<label>Onaylamak için <strong>HESABIMI SIL</strong> yazın</label>
<input
    type="text"
    name="confirmation"
    autocomplete="off"
    required
>

<button type="submit">
HESABIMI KALICI OLARAK SİL
</button>

</form>

<p style="margin-top:22px">
<a href="/" style="color:#8effb5">
Vazgeç ve geri dön
</a>
</p>

</div>

</body>
</html>
"""

# === /ERATGUARD USER ACCOUNT DELETION V1 ===



# =============================================================================
# ERATGUARD LIVE PANEL API V1
# =============================================================================

@app.route("/api/logs")
def eg_live_api_logs():
    if not session.get("username") and not session.get("user"):
        return jsonify({"status": "error", "message": "unauthorized"}), 401

    try:
        path = "data/spam_logs.json"

        if not os.path.exists(path):
            logs = []
        else:
            with open(path, "r", encoding="utf-8") as f:
                logs = json.load(f)

        if not isinstance(logs, list):
            logs = []

        logs = list(reversed(logs))[:100]

        return jsonify({
            "status": "success",
            "total": len(logs),
            "logs": logs
        })

    except Exception as e:
        print("ERATGUARD LIVE API ERROR:", repr(e), flush=True)
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


@app.route("/api/stats")
def eg_live_api_stats():
    if not session.get("username") and not session.get("user"):
        return jsonify({"status": "error", "message": "unauthorized"}), 401

    try:
        path = "data/spam_logs.json"

        if not os.path.exists(path):
            logs = []
        else:
            with open(path, "r", encoding="utf-8") as f:
                logs = json.load(f)

        if not isinstance(logs, list):
            logs = []

        spam = 0
        temiz = 0
        blocked = 0
        reported = 0

        for item in logs:
            if not isinstance(item, dict):
                continue

            status = str(item.get("status", "")).strip().upper()

            if status == "SPAM":
                spam += 1
            elif status == "OK":
                temiz += 1
            elif status == "BLOCKED":
                blocked += 1
            elif bool(item.get("blocked")):
                blocked += 1

            if item.get("reported_by"):
                reported += 1

        total = len(logs)

        return jsonify({
            "status": "success",
            "total": total,
            "spam": spam,
            "temiz": temiz,
            "blocked_count": blocked,
            "safe_count": temiz,
            "reported_count": reported,
            "security_percent": (
                0 if total == 0
                else round((temiz / total) * 100)
            ),
            "protection_status": (
                "Yüksek" if spam > 10
                else "Orta" if spam > 3
                else "Düşük"
            )
        })

    except Exception as e:
        print("ERATGUARD LIVE API ERROR:", repr(e), flush=True)
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

# =============================================================================
# /ERATGUARD LIVE PANEL API V1
# =============================================================================



# =============================================================================
# ERATGUARD MOBILE NAV V1
# =============================================================================


# =============================================================================
# /ERATGUARD MOBILE NAV V1
# =============================================================================


# =====================================================================
# ERATGUARD USER ENTITLEMENT V1
# Trial -> Free -> Paid PRO
#
# Rules:
# - New users receive 14 days of full PRO trial.
# - Trial expiry NEVER disables the account.
# - Expired paid licenses fall back to FREE.
# - Lifetime remains permanently premium.
# - Admin remains premium.
# - Commercial plan/payment model remains untouched.
# =====================================================================

ERATGUARD_TRIAL_DAYS_V1 = 14


def _eg_entitlement_date_v1(value):
    from datetime import datetime

    raw = str(value or "").strip()
    if not raw:
        return None

    try:
        return datetime.strptime(raw[:10], "%Y-%m-%d").date()
    except Exception:
        return None


def _eg_entitlement_date_active_v1(value, today=None):
    from datetime import datetime

    expiry = _eg_entitlement_date_v1(value)
    if expiry is None:
        return False

    current = today or datetime.now().date()
    return expiry >= current


def _eg_trial_expiry_v1(start=None):
    from datetime import datetime, timedelta

    base = start or datetime.now()

    if hasattr(base, "date"):
        base = base.date()

    return (base + timedelta(
        days=ERATGUARD_TRIAL_DAYS_V1
    )).isoformat()


def _eg_user_entitlement_v1(user, today=None):
    """
    Read-only entitlement resolver.

    Returns:
      tier: ADMIN / PRO / TRIAL / FREE
      premium: full premium access
      trial_active: trial currently valid
      paid: paid commercial entitlement
      expires_at: effective entitlement expiry
    """
    from datetime import datetime

    if not isinstance(user, dict):
        user = {}

    current = today or datetime.now().date()

    role = str(
        user.get("role") or ""
    ).strip().lower()

    username = str(
        user.get("username") or ""
    ).strip().lower()

    if role == "admin" or username == "admin":
        return {
            "tier": "ADMIN",
            "premium": True,
            "trial_active": False,
            "paid": False,
            "expires_at": "2099-12-31",
        }

    if user.get("active") is False:
        return {
            "tier": "FREE",
            "premium": False,
            "trial_active": False,
            "paid": False,
            "expires_at": "",
        }

    license_type = str(
        user.get("license_type")
        or user.get("license_mode")
        or ""
    ).strip().lower()

    plan = str(
        user.get("plan") or ""
    ).strip().lower()

    license_key = str(
        user.get("license_key") or ""
    ).strip().upper()

    paid_types = {
        "pro",
        "premium",
        "paid",
        "pro_monthly",
        "pro_yearly",
        "lifetime",
    }

    paid_plans = {
        "starter_monthly",
        "pro_monthly",
        "pro_yearly",
        "yearly",
        "lifetime",
    }

    if license_type == "lifetime" or plan == "lifetime":
        return {
            "tier": "PRO",
            "premium": True,
            "trial_active": False,
            "paid": True,
            "expires_at": "2099-12-31",
        }

    paid_candidate = (
        license_type in paid_types
        or plan in paid_plans
        or (license_key not in ("", "NONE"))
    )

    paid_expiry = (
        user.get("license_expiry")
        or user.get("expires_at")
        or ""
    )

    if (
        paid_candidate
        and _eg_entitlement_date_active_v1(
            paid_expiry,
            today=current
        )
    ):
        return {
            "tier": "PRO",
            "premium": True,
            "trial_active": False,
            "paid": True,
            "expires_at": str(paid_expiry),
        }

    trial_consumed = bool(
        str(
            user.get("trial_consumed_at")
            or ""
        ).strip()
    )

    trial_expiry = (
        user.get("trial_expires_at")
        or ""
    )

    if (
        not trial_consumed
        and _eg_entitlement_date_active_v1(
            trial_expiry,
            today=current
        )
    ):
        return {
            "tier": "TRIAL",
            "premium": True,
            "trial_active": True,
            "paid": False,
            "expires_at": str(trial_expiry),
        }

    return {
        "tier": "FREE",
        "premium": False,
        "trial_active": False,
        "paid": False,
        "expires_at": "",
    }


def _eg_user_has_premium_v1(user):
    return bool(
        _eg_user_entitlement_v1(user).get("premium")
    )


print(
    "ERATGUARD USER ENTITLEMENT V1 ACTIVE: "
    "TRIAL -> FREE -> PAID PRO"
)


# =====================================================================
# ERATGUARD PRO ACCESS GUARD V1
# TRIAL / PRO / ADMIN -> allowed
# FREE -> AI Analysis + Reports locked
# =====================================================================

_EG_PRO_PATHS_V1 = {
    "/analysis",
    "/u/analysis",
    "/u/analysis/check",
    "/report",
    "/reports",
    "/u/reports",
}


def _eg_current_user_entitlement_v1():
    username = str(
        session.get("username") or ""
    ).strip()

    role = str(
        session.get("role") or ""
    ).strip().lower()

    if role == "admin" or username.lower() == "admin":
        return {
            "tier": "ADMIN",
            "premium": True,
            "trial_active": False,
            "paid": False,
            "expires_at": "2099-12-31",
        }

    if not username:
        return {
            "tier": "FREE",
            "premium": False,
            "trial_active": False,
            "paid": False,
            "expires_at": "",
        }

    users = load_users()
    user = users.get(username)

    if not isinstance(user, dict):
        return {
            "tier": "FREE",
            "premium": False,
            "trial_active": False,
            "paid": False,
            "expires_at": "",
        }

    return _eg_user_entitlement_v1(user)


def _eg_pro_locked_page_v1(entitlement):
    tier = str(
        entitlement.get("tier") or "FREE"
    ).upper()

    return """
<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport"
      content="width=device-width,initial-scale=1">
<title>EratGuard PRO</title>
<style>
*{box-sizing:border-box}
body{
 margin:0;
 min-height:100vh;
 display:flex;
 align-items:center;
 justify-content:center;
 padding:24px;
 background:#01070c;
 color:#d9f8ff;
 font-family:Arial,sans-serif
}
.card{
 width:100%;
 max-width:520px;
 padding:28px 22px;
 border:1px solid rgba(0,231,255,.42);
 border-radius:16px;
 background:#020a10;
 text-align:center
}
.lock{
 font-size:46px;
 margin-bottom:10px
}
h1{
 margin:0 0 12px;
 font-size:24px
}
p{
 color:#8fb8c8;
 line-height:1.55
}
.badge{
 display:inline-block;
 margin:6px 0 18px;
 padding:7px 12px;
 border:1px solid rgba(0,231,255,.35);
 border-radius:999px;
 color:#00e7ff
}
a{
 display:block;
 margin-top:12px;
 padding:13px 16px;
 border-radius:10px;
 text-decoration:none;
 font-weight:700
}
.pro{
 background:#00e7ff;
 color:#01070c
}
.back{
 border:1px solid rgba(143,184,200,.35);
 color:#d9f8ff
}
</style>
</head>
<body>
<div class="card">
 <div class="lock">🔒</div>
 <h1>PRO Özelliği</h1>
 <div class="badge">Mevcut Plan: """ + tier + """</div>
 <p>
  Bu bölüm EratGuard TRIAL veya PRO üyeliğinde kullanılabilir.
  Temel güvenlik ve SMS korumasını FREE planında kullanmaya
  devam edebilirsiniz.
 </p>
 <a class="pro" href="/pricing">PRO'ya Geç</a>
 <a class="back" href="/dashboard">Panele Dön</a>
</div>
</body>
</html>
""", 403


@app.before_request
def _eg_pro_access_guard_v1():
    path = request.path.rstrip("/") or "/"

    if path not in _EG_PRO_PATHS_V1:
        return None

    # Önce normal auth katmanı çalışsın:
    # giriş yapılmamış kullanıcı burada premium ekranı görmemeli.
    if not (
        session.get("logged_in")
        and session.get("username")
    ):
        return None

    entitlement = _eg_current_user_entitlement_v1()

    if entitlement.get("premium"):
        return None

    return _eg_pro_locked_page_v1(
        entitlement
    )


print(
    "ERATGUARD PRO ACCESS GUARD V1 ACTIVE: "
    "AI ANALYSIS + REPORTS"
)


# =====================================================================
# ERATGUARD PRO ACCESS GUARD PRIORITY V2
#
# Auth guard first, entitlement guard immediately after it.
# Legacy UI before_request bridges must not bypass PRO access control.
# =====================================================================

try:
    _eg_pro_before_v2 = app.before_request_funcs.get(None, [])

    if _eg_pro_access_guard_v1 in _eg_pro_before_v2:
        _eg_pro_before_v2.remove(
            _eg_pro_access_guard_v1
        )

    _eg_auth_guard_index_v2 = next(
        (
            i for i, fn in enumerate(_eg_pro_before_v2)
            if getattr(fn, "__name__", "") ==
            "_eg_strict_user_auth_guard_final"
        ),
        None,
    )

    if _eg_auth_guard_index_v2 is None:
        raise RuntimeError(
            "strict user auth guard bulunamadi"
        )

    _eg_pro_before_v2.insert(
        _eg_auth_guard_index_v2 + 1,
        _eg_pro_access_guard_v1,
    )

    print(
        "ERATGUARD PRO ACCESS GUARD PRIORITY V2 ACTIVE: "
        "AUTH -> PRO -> LEGACY UI"
    )

except Exception as _eg_pro_priority_error_v2:
    print(
        "ERATGUARD PRO ACCESS GUARD PRIORITY V2 ERROR:",
        _eg_pro_priority_error_v2,
    )
    raise


# =============================================================================
# ERATGUARD PHASE 7D.18A END
# =============================================================================

# =====================================================================
#
# Do not touch canonical POST activation.
# =====================================================================



# ============================================================
# ERATGUARD REFERENCE EXPERIENCE
# TRANSFORMATION 02A — SHIELD PREVIEW
# Preview-only. Canonical /u/protection ownership is unchanged.
# ============================================================


# ============================================================
# ERATGUARD CANONICAL RUNTIME ENTRYPOINT
# Must remain LAST so every route/hook is registered first.
# ============================================================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
