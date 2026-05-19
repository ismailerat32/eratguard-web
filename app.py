from functools import wraps
from mailer import send_mail

def is_user_pro_and_secure(username):
    users = _read_json_file("data/users.json", {})
    if not isinstance(users, dict):
        return False, "Kullanıcı verisi bozuk."

    user = users.get(username, {})
    role = str(user.get("role", "")).strip().lower()
    if role == "admin":
        return True, "admin"

    plan = str(user.get("license_type") or user.get("plan") or "trial").strip().lower()
    if plan == "pro":
        return True, "pro"

    return False, "PRO lisans gerekli."



def pro_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        from flask import session, redirect, request, render_template, abort
        username = str(session.get("username") or session.get("user") or "").strip()
        if not username:
            return redirect("/login")

        ok, msg = is_user_pro_and_secure(username)
        if not ok:
            return redirect("/activate-license")

        return f(*args, **kwargs)
    return wrapper


# Telegram sistemi kapatildi


def verify_generated_license(key):
    import json
    from pathlib import Path
    from datetime import datetime

    path = Path("data/generated_licenses.json")
    if not path.exists():
        return False, "Lisans bulunamadı"

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return False, "Lisans verisi bozuk"

    key = str(key).strip().upper()

    for item in data:
        if str(item.get("key", "")).strip().upper() == key:
            if item.get("used") is True:
                return False, "Lisans zaten kullanılmış"

            expiry = str(item.get("expiry", "")).strip()
            if expiry:
                try:
                    if datetime.now() > datetime.strptime(expiry, "%Y-%m-%d %H:%M:%S"):
                        return False, "Lisans süresi dolmuş"
                except Exception:
                    pass

            return True, item

    return False, "Lisans bulunamadı"

def mark_generated_license_used(key):
    import json
    from pathlib import Path

    path = Path("data/generated_licenses.json")
    if not path.exists():
        return False

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return False

    key = str(key).strip().upper()
    changed = False

    for item in data:
        if str(item.get("key", "")).strip().upper() == key:
            item["used"] = True
            changed = True
            break

    if changed:
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

    return changed

def create_license(note="", license_type="pro", days=30):
    import random
    import string
    from datetime import datetime, timedelta
    import json
    from pathlib import Path

    key = "LIC-" + "".join(random.choices(string.ascii_uppercase + string.digits, k=12))
    created_at = datetime.now()
    expiry = created_at + timedelta(days=days)

    record = {
        "key": key,
        "note": note,
        "type": license_type,
        "days": days,
        "created_at": created_at.strftime("%Y-%m-%d %H:%M:%S"),
        "expiry": expiry.strftime("%Y-%m-%d %H:%M:%S"),
        "used": False
    }

    path = Path("data/generated_licenses.json")
    items = []

    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, list):
                items = data
        except Exception:
            items = []

    items.append(record)
    path.write_text(json.dumps(items, ensure_ascii=False, indent=2), encoding="utf-8")

    return key



def get_current_user():
    users = load_users()
    username = session.get("username")
    return users.get(username, {})


from flask import Flask, render_template, request, redirect, url_for, session, jsonify, abort
import json
import os
from datetime import datetime



def license_required():
    from datetime import datetime

    username = session.get("username")
    if not username:
        return redirect(url_for("login"))

    users = load_users()
    if username not in users:
        return redirect(url_for("login"))

    user = users[username]
    expiry = user.get("license_expiry", "")

    if not expiry:
        return redirect(url_for("activate_license"))

    try:
        exp_date = datetime.strptime(expiry, "%Y-%m-%d")
        if exp_date < datetime.now():
            return redirect(url_for("activate_license"))
    except:
        return redirect(url_for("activate_license"))

    return None
# =========================================
# EratGuard © 2026
# Owner: ismail erat
# All rights reserved.
# Unauthorized copying, resale, distribution,
# reverse engineering, or modification of this
# software without permission is prohibited.
# =========================================

import json
import os
from datetime import datetime, timedelta
import random
import string

from werkzeug.security import generate_password_hash, check_password_hash

from utils.reset_utils import (
    find_user_by_identity,
    create_reset_token,
    create_reset_code,
    find_valid_token_record,
    find_valid_code_record,
    mark_token_used,
    reset_user_password,
    cleanup_expired_tokens
)


# ===== ERATGUARD IYZICO PAYMENT CONFIG START =====
# iyzico onayı gelince 3 iyzilink ödeme linki buraya yazılacak.
# Linkler boş/placeholder kaldığı sürece ödeme sayfası "hazırlanıyor" ekranı gösterir.
PAYMENT_PROVIDER = "iyzico"

import os as _ss_iyzico_os

try:
    from dotenv import load_dotenv as _ss_load_dotenv
    _ss_load_dotenv(dotenv_path=".env")
except Exception:
    pass

PAYMENT_LINKS = {
    "starter_monthly": _ss_iyzico_os.getenv("IYZICO_STARTER_MONTHLY_URL", "PASTE_STARTER_IYZICO_LINK_HERE"),
    "pro_yearly": _ss_iyzico_os.getenv("IYZICO_PRO_YEARLY_URL", "PASTE_YEARLY_IYZICO_LINK_HERE"),
    "lifetime": _ss_iyzico_os.getenv("IYZICO_LIFETIME_URL", "PASTE_LIFETIME_IYZICO_LINK_HERE"),
}

PLAN_LABELS = {
    "starter_monthly": "Starter Shield",
    "pro_yearly": "Shield Pro+",
    "lifetime": "Lifetime Shield",
}

PLAN_PRICES = {
    "starter_monthly": "150 TL / Ay",
    "pro_yearly": "1000 TL / Yıl",
    "lifetime": "2000 TL / Tek Sefer",
}
# ===== ERATGUARD IYZICO PAYMENT CONFIG END =====


app = Flask(__name__)

# ===== ERATGUARD SECURITY LEVEL 1 START =====
import secrets as _ss_secrets
import time as _ss_time
from pathlib import Path as _ss_Path
from functools import wraps as _ss_wraps

_SS_SECRET_FILE = _ss_Path("data/.eratguard_secret_key")
_SS_SECRET_FILE.parent.mkdir(exist_ok=True)

def _ss_get_or_create_secret_key():
    env_key = os.environ.get("SECRET_KEY", "").strip()
    if env_key and env_key != "dev-change-this-now" and len(env_key) >= 32:
        return env_key

    if _SS_SECRET_FILE.exists():
        key = _SS_SECRET_FILE.read_text(encoding="utf-8").strip()
        if key and len(key) >= 32:
            return key

    key = _ss_secrets.token_urlsafe(64)
    _SS_SECRET_FILE.write_text(key, encoding="utf-8")
    try:
        _SS_SECRET_FILE.chmod(0o600)
    except Exception:
        pass
    return key

# Default/dev SECRET_KEY yerine güçlü kalıcı key
app.config["SECRET_KEY"] = _ss_get_or_create_secret_key()

# Session güvenliği
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = 60 * 60 * 8

# Lokal HTTP test bozulmasın diye Secure cookie varsayılan kapalı.
# Yayına HTTPS ile çıkarken env'e ERATGUARD_SECURE_COOKIES=1 koy.
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("ERATGUARD_SECURE_COOKIES", "0") == "1"

_SS_LOGIN_ATTEMPTS = {}

def _ss_client_key():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "local")
    ip = str(ip).split(",")[0].strip()
    username = ""
    try:
        username = str(request.form.get("username", "")).strip().lower()
    except Exception:
        pass
    return f"{ip}:{username}"

def _ss_too_many_login_attempts():
    key = _ss_client_key()
    now = _ss_time.time()
    bucket = [t for t in _SS_LOGIN_ATTEMPTS.get(key, []) if now - t < 300]
    _SS_LOGIN_ATTEMPTS[key] = bucket
    return len(bucket) >= 8

def _ss_record_login_attempt():
    key = _ss_client_key()
    now = _ss_time.time()
    bucket = [t for t in _SS_LOGIN_ATTEMPTS.get(key, []) if now - t < 300]
    bucket.append(now)
    _SS_LOGIN_ATTEMPTS[key] = bucket

def _ss_is_logged_in():
    return bool(session.get("logged_in") or session.get("username") or session.get("user"))

def _ss_is_admin_session():
    # Mevcut sistem role bilgisini farklı yerlerde tutabiliyor; güvenli tarafta kalıyoruz.
    if session.get("role") == "admin" or session.get("is_admin"):
        return True
    username = str(session.get("username") or session.get("user") or "").strip()
    if username == "admin":
        return True
    return False

@app.before_request
def ss_security_gatekeeper():
    path = request.path or ""

    # Security Level 3 hard block: bu yollar login'e bile yönlenmeden yokmuş gibi davranır.
    _ss_hard_block_paths = (
        "/u/activate-pro-now",
        "/orders",
        "/bot-orders",
        "/orders/give-license",
        "/bot-orders/give-license",
    )
    if path.startswith(_ss_hard_block_paths):
        return "Not Found", 404

    # Dev-only test payment route: production'da kapalı, FLASK_DEBUG=1 iken test edilebilir.
    if path.startswith("/u/test-payment-complete") and os.environ.get("FLASK_DEBUG", "0") != "1":
        return "Not Found", 404

    # Gizli/runtime dosyaları web üzerinden engelle
    blocked_prefixes = (
        "/.env",
        "/data/",
        "/logs/",
        "/backups/",
        "/backup",
        "/emergency_backup/",
        "/stable_backups/",
        "/SECURITY_AUDIT_",
    )
    if path.startswith(blocked_prefixes) or ".." in path:
        return "Not Found", 404

    # Login brute-force yavaşlatma
    if path == "/login" and request.method == "POST":
        if _ss_too_many_login_attempts():
            return "Çok fazla giriş denemesi. Lütfen birkaç dakika sonra tekrar deneyin.", 429
        _ss_record_login_attempt()

    # Admin ve tehlikeli API yolları ekstra koruma
    protected_prefixes = (
        "/admin",
        "/api/admin",
    )
    if path.startswith(protected_prefixes):
        if not _ss_is_logged_in():
            return redirect("/login")
        if not _ss_is_admin_session():
            abort(403)

@app.after_request
def ss_security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"

    # HTTPS yayında açılabilir; lokal HTTP testte sorun çıkarmaması için env kontrollü.
    if os.environ.get("ERATGUARD_HSTS", "0") == "1":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

    return response
# ===== ERATGUARD SECURITY LEVEL 1 END =====




# ============================================================
# HARDCORE LICENSE / PREMIUM HELPERS
# ============================================================
import json as _license_json
from pathlib import Path as _LicensePath
from datetime import datetime as _license_datetime, timedelta as _license_timedelta

_USERS_FILE = _LicensePath("data/users.json")
_LICENSES_FILE = _LicensePath("data/licenses.json")

def _license_load_json(path, default):
    try:
        if path.exists():
            return _license_json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        pass
    return default

def _license_save_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        _license_json.dumps(data, ensure_ascii=False, indent=2),
        encoding="utf-8"
    )

def _current_username_hardcore():
    try:
        return (
            session.get("username")
            or session.get("user")
            or session.get("email")
            or "demo"
        )
    except Exception:
        return "demo"

def _make_license_code(username):
    import hashlib
    raw = f"{username}-{_license_datetime.now().isoformat()}-ERATGUARD"
    return "ERATGUARD-PRO-" + hashlib.sha1(raw.encode()).hexdigest()[:6].upper()

def _activate_premium_hardcore(username=None, plan="starter_monthly"):
    username = username or _current_username_hardcore()
    plan = (plan or "starter_monthly").strip()
    plan_days = {
        "starter_monthly": 30,
        "pro_yearly": 365,
        "lifetime": 3650,
    }.get(plan, 30)

    code = _make_license_code(username)
    now = _license_datetime.now()
    expires = now + _license_timedelta(days=plan_days)

    # Session'a yaz
    try:
        session["premium"] = True
        session["is_premium"] = True
        session["license_status"] = "premium"
        session["license_code"] = code
        session["plan"] = plan
    except Exception:
        pass

    # users.json'a yaz
    users = _license_load_json(_USERS_FILE, {})
    if isinstance(users, dict):
        user_obj = users.get(username, {})
        if not isinstance(user_obj, dict):
            user_obj = {}
        user_obj.update({
            "premium": True,
            "is_premium": True,
            "license_status": "premium",
            "license_code": code,
            "plan": plan,
            "premium_started_at": now.isoformat(),
            "premium_expires_at": expires.isoformat(),
            "premium_days": plan_days,
        })
        users[username] = user_obj
        _license_save_json(_USERS_FILE, users)

    # licenses.json'a yaz
    licenses = _license_load_json(_LICENSES_FILE, {})
    if not isinstance(licenses, dict):
        licenses = {}
    licenses[code] = {
        "username": username,
        "code": code,
        "plan": plan,
        "status": "active",
        "premium": True,
        "created_at": now.isoformat(),
        "expires_at": expires.isoformat(),
        "days": plan_days,
    }
    _license_save_json(_LICENSES_FILE, licenses)

    return code

def _get_license_state_hardcore(username=None):
    username = username or _current_username_hardcore()

    # Önce session
    try:
        if session.get("premium") or session.get("is_premium") or session.get("license_status") == "premium":
            return {
                "premium": True,
                "status": "premium",
                "code": session.get("license_code", "ERATGUARD-PRO"),
                "plan": session.get("plan", "pro"),
                "days_left": 365,
            }
    except Exception:
        pass

    # Sonra users.json
    users = _license_load_json(_USERS_FILE, {})
    user_obj = {}
    if isinstance(users, dict):
        user_obj = users.get(username, {}) or {}

    if isinstance(user_obj, dict) and (
        user_obj.get("premium")
        or user_obj.get("is_premium")
        or user_obj.get("license_status") == "premium"
    ):
        try:
            session["premium"] = True
            session["is_premium"] = True
            session["license_status"] = "premium"
            session["license_code"] = user_obj.get("license_code", "ERATGUARD-PRO")
            session["plan"] = user_obj.get("plan", "pro")
        except Exception:
            pass

        return {
            "premium": True,
            "status": "premium",
            "code": user_obj.get("license_code", "ERATGUARD-PRO"),
            "plan": user_obj.get("plan", "pro"),
            "days_left": 365,
        }

    # Trial fallback
    return {
        "premium": False,
        "status": "trial",
        "code": None,
        "plan": "trial",
        "days_left": 5,
    }
# ============================================================




@app.route("/api/analysis-data")
def api_analysis_data():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    import json
    from pathlib import Path
    from datetime import datetime
    from flask import Response

    log_path = Path("data/spam_logs.json")
    logs = []

    if log_path.exists():
        try:
            raw = json.loads(log_path.read_text(encoding="utf-8"))
            if isinstance(raw, list):
                logs = raw
            elif isinstance(raw, dict):
                logs = raw.get("logs", []) or raw.get("items", []) or raw.get("messages", [])
        except Exception:
            logs = []

    total = len(logs)
    blocked = 0
    spam_count = 0

    type_counts = {
        "Reklam": 0,
        "Dolandırıcılık": 0,
        "Sahte Banka": 0
    }

    trend_labels = ["Pzt","Sal","Çar","Per","Cum","Cmt","Paz"]
    trend_values = [0,0,0,0,0,0,0]

    for item in logs:
        text = str(item.get("message", item.get("text", item.get("body", "")))).lower()
        kind = str(item.get("type", item.get("category", ""))).lower()
        status = str(item.get("status", item.get("result", ""))).lower()

        is_spam = (
            item.get("is_spam") is True or
            item.get("blocked") is True or
            "spam" in status or
            "spam" in kind or
            "reklam" in text or
            "kampanya" in text or
            "tıkla" in text or
            "tikla" in text or
            "banka" in text or
            "link" in text
        )

        if is_spam:
            spam_count += 1

        if item.get("blocked") is True or "engel" in status or "blocked" in status:
            blocked += 1

        if "banka" in text or "bank" in text or "banka" in kind:
            type_counts["Sahte Banka"] += 1
        elif "dolandır" in text or "link" in text or "tıkla" in text or "tikla" in text or "phish" in kind:
            type_counts["Dolandırıcılık"] += 1
        elif is_spam:
            type_counts["Reklam"] += 1

        ts = item.get("timestamp") or item.get("time") or item.get("date")
        if ts:
            try:
                dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
                trend_values[dt.weekday()] += 1
            except Exception:
                pass

    # Log yoksa demo verisiyle ekran boş kalmasın
    if total == 0:
        total = 35
        spam_count = 19
        blocked = 3
        type_counts = {"Reklam": 16, "Dolandırıcılık": 3, "Sahte Banka": 0}
        trend_values = [12,19,7,14,10,20,15]

    # Timestamp yoksa trend yine düz kalmasın
    if sum(trend_values) == 0:
        trend_values = [12,19,7,14,10,20,15]

    spam_ratio = round((spam_count / total) * 100) if total else 0
    trust_score = max(0, min(100, 100 - spam_ratio + 24))

    data = {
        "spam_ratio": spam_ratio,
        "trust_score": trust_score,
        "total": total,
        "blocked": blocked,
        "trend_labels": trend_labels,
        "trend_values": trend_values,
        "type_labels": list(type_counts.keys()),
        "type_values": list(type_counts.values()),
        "daily": {
            "spam": spam_count,
            "blocked": blocked,
            "clean": max(0, total - spam_count)
        }
    }

    return Response(
        json.dumps(data, ensure_ascii=False),
        content_type="application/json; charset=utf-8"
    )



@app.route("/admin/")
@app.route("/admin")
def admin_home():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    if not login_required():
        return redirect(url_for("login"))
    return redirect("/radial")
# SECURITY_LEVEL1_DISABLED_DEV_SECRET = os.environ.get("SECRET_KEY", "dev-change-this-now")
app.config["DEBUG"] = os.environ.get("FLASK_DEBUG", "0") == "1"

def apply_runtime_env_overrides():
    import json
    users_file = globals().get("USERS_FILE", "data/users.json")
    admin_password = os.environ.get("ADMIN_PASSWORD", "").strip()

    if admin_password and os.path.exists(users_file):
        try:
            with open(users_file, "r", encoding="utf-8") as f:
                users = json.load(f)

            if "admin" in users:
                users["admin"]["password"] = admin_password
                with open(users_file, "w", encoding="utf-8") as f:
                    json.dump(users, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print("ENV_OVERRIDE_ERROR:", e)

apply_runtime_env_overrides()
# SECURITY_LEVEL1_DISABLED_DEV_SECRET = os.environ.get("SECRET_KEY", "dev-change-this-now")

USERS_FILE = "data/users.json"
SETTINGS_FILE = "data/settings.json"
LICENSES_FILE = "data/licenses.json"
LOGS_FILE = "data/logs.json"
FEEDBACK_FILE = "data/feedback.json"

def load_feedback():
    return read_json(FEEDBACK_FILE, [])

def save_feedback(items):
    write_json(FEEDBACK_FILE, items)

def load_logs():
    return read_json(LOGS_FILE, [])

def save_logs(logs):
    write_json(LOGS_FILE, logs)

# -----------------------
# BASIC HELPERS
# -----------------------
def read_json(path, default):
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return default

def write_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=4)

# -----------------------
# LICENSE KEY GENERATORS
# -----------------------
def generate_license_key():
    parts = []
    for _ in range(4):
        part = ''.join(random.choices(string.ascii_uppercase + string.digits, k=4))
        parts.append(part)
    return "SPM-" + "-".join(parts)


def generate_reset_code():
    import random
    import string
    return "RST-" + ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))

def generate_pool_license(days=30):
    licenses = load_licenses()

    while True:
        key = "LIC-" + ''.join(random.choices(string.ascii_uppercase + string.digits, k=12))
        if key not in licenses:
            break

    licenses[key] = {
        "days": int(days),
        "used": False,
        "used_by": "",
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    save_licenses(licenses)
    return key

# -----------------------
# USERS
# -----------------------
def load_users():
    users = read_json(USERS_FILE, None)
    if users is not None:
        return users

    users = {
        "admin": {
            "password": "1234",
            "role": "admin",
            "license_type": "pro",
            "license_key": "MASTER-KEY",
            "license_expiry": "2099-01-01"
        }
    }
    save_users(users)
    return users

def save_users(users):
    write_json(USERS_FILE, users)

# -----------------------
# SETTINGS
# -----------------------
def load_settings():
    settings = read_json(SETTINGS_FILE, None)
    if settings is not None:
        return settings

    settings = {
        "app_name": "EratGuard Premium",
        "trial_days": 7,
        "license_mode": "trial_pro"
    }
    save_settings(settings)
    return settings

def save_settings(settings):
    write_json(SETTINGS_FILE, settings)

# -----------------------
# LICENSE POOL
# -----------------------
def load_licenses():
    return read_json(LICENSES_FILE, {})

def save_licenses(licenses):
    write_json(LICENSES_FILE, licenses)

# -----------------------
# SESSION / AUTH HELPERS
# -----------------------
def login_required():
    return session.get("logged_in", False)

def current_username():
    return session.get("username", "")

def current_user():
    return load_users().get(current_username(), {})

def is_admin():
    return current_user().get("role") == "admin"

def admin_required():
    return login_required() and is_admin()

# -----------------------
# LICENSE HELPERS
# -----------------------
def is_license_active(user):
    try:
        expiry = datetime.strptime(user.get("license_expiry", ""), "%Y-%m-%d")
        return expiry >= datetime.now()
    except:
        return False

def days_left(user):
    try:
        expiry = datetime.strptime(user.get("license_expiry", ""), "%Y-%m-%d")
        delta = expiry - datetime.now()
        return max(delta.days, 0)
    except:
        return 0

def activate_pool_license(username, entered_key):
    entered_key = entered_key.strip().upper()
    users = load_users()
    licenses = load_licenses()

    if username not in users:
        return False, "Kullanıcı bulunamadı."

    if entered_key not in licenses:
        return False, "Geçersiz lisans kodu."

    if licenses[entered_key]["used"]:
        return False, "Bu lisans zaten kullanılmış."

    extra_days = int(licenses[entered_key].get("days", 30))
    now = datetime.now()

    current_expiry_raw = users[username].get("license_expiry", "")
    try:
        current_expiry = datetime.strptime(current_expiry_raw, "%Y-%m-%d")
        base_date = current_expiry if current_expiry > now else now
    except:
        base_date = now

    new_expiry = base_date + timedelta(days=extra_days)

    users[username]["license_type"] = "pro"
    users[username]["license_key"] = entered_key
    users[username]["license_expiry"] = new_expiry.strftime("%Y-%m-%d")

    licenses[entered_key]["used"] = True
    licenses[entered_key]["used_by"] = username
    licenses[entered_key]["used_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    save_users(users)
    save_licenses(licenses)

    return True, f"PRO aktif edildi. +{extra_days} gün eklendi."

# -----------------------
# HOME
# -----------------------


WHITELIST_FILE = "data/whitelist.json"

def load_whitelist():
    import json, os
    if not os.path.exists(WHITELIST_FILE):
        return []
    try:
        with open(WHITELIST_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except:
        return []

def save_whitelist(data):
    import json
    with open(WHITELIST_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def add_to_whitelist(sender):
    sender = str(sender).upper()
    wl = load_whitelist()
    if sender not in wl:
        wl.append(sender)
        save_whitelist(wl)


@app.route("/login", methods=["GET", "POST"])
def login():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "").strip()

        if username.lower() == "admin":
            return render_template("login.html", error="Admin girişi bu ekrandan yapılamaz.")

        users = load_users()
        user = users.get(username)

        if user:
            stored_hash = user.get("password_hash", "")
            stored_plain = user.get("password", "")

            valid = False

            if stored_hash:
                valid = check_password_hash(stored_hash, password)
            elif stored_plain:
                if stored_plain == password:
                    valid = True
                    users[username]["password_hash"] = generate_password_hash(password)
                    users[username].pop("password", None)
                    save_users(users)

            if valid:
                session["logged_in"] = True
                session["username"] = username

                if not is_license_active(user):
                    return redirect("/radial")

                return redirect("/radial")

        return render_template("login.html", error="Kullanıcı adı veya şifre yanlış.")

    return render_template("login.html", error="")


# -----------------------
# REGISTER
# -----------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "").strip()
        password2 = request.form.get("password2", "").strip()

        users = load_users()
        settings = load_settings()

        if not username or not email or not password or not password2:
            return render_template("register.html", error="Tüm alanları doldurun.")

        if username in users:
            return render_template("register.html", error="Bu kullanıcı zaten var.")

        if password != password2:
            return render_template("register.html", error="Şifreler eşleşmiyor.")

        expiry = datetime.now() + timedelta(days=settings.get("trial_days", 7))

        users[username] = {
            "password_hash": generate_password_hash(password),
            "email": email,
            "role": "user",
            "license_type": "trial",
            "license_key": "TRIAL",
            "license_expiry": expiry.strftime("%Y-%m-%d"),
            "is_active": True,
            "active": True,
            "status": "active",
            "is_banned": False,
            "disabled": False
        }

        save_users(users)
        return redirect(url_for("login"))

    return render_template("register.html", error="")


# -----------------------
# DASHBOARD
# -----------------------
@app.route("/admin-home-alias")
def admin_home_alias():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    return redirect("/radial")



@app.route("/spam-logs")
def spam_logs_alias():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    return redirect(url_for("admin_spam_logs"))

@app.route("/whitelist", methods=["GET", "POST"])
@app.route("/admin/whitelist", methods=["GET", "POST"])
def admin_whitelist():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    if not login_required():
        return redirect(url_for("login"))

    whitelist = load_whitelist()

    if request.method == "POST":
        number = request.form.get("number", "").strip()
        if number and number not in whitelist:
            whitelist.append(number)
            save_whitelist(whitelist)
        return redirect("/admin/whitelist")

    return render_template("whitelist.html", whitelist=whitelist)


@app.route("/admin/panel")
def admin_panel():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    if not login_required():
        return redirect(url_for("login"))
    if not admin_required():
        return redirect("/radial")

    users = load_users()
    rows = []
    for username, data in users.items():
        rows.append({
            "username": username,
            "role": data.get("role", "user"),
            "license_type": data.get("license_type", "trial"),
            "license_expiry": data.get("license_expiry", ""),
            "license_key": data.get("license_key", ""),
            "is_banned": bool(data.get("is_banned", False)),
        })

    rows = sorted(rows, key=lambda x: x["username"].lower())
    requests = load_upgrade_requests()
    return render_template("admin_panel.html", users=rows, upgrade_requests=requests)


@app.route("/admin/add-user", methods=["POST"])
def admin_add_user():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    if not login_required():
        return redirect(url_for("login"))
    if not admin_required():
        return redirect("/radial")

    username = request.form.get("username", "").strip()
    email = request.form.get("email", "").strip()
    password = request.form.get("password", "").strip()
    role = request.form.get("role", "user").strip() or "user"
    license_type = request.form.get("license_type", "trial").strip() or "trial"
    license_expiry = request.form.get("license_expiry", "").strip()

    if not username or not password:
        return redirect("/admin/panel?ok=missing_fields&open=add")

    users = load_users()
    if username in users:
        return redirect("/admin/panel?ok=user_exists&open=add")

    try:
        from werkzeug.security import generate_password_hash
        password_hash = generate_password_hash(password)
    except Exception:
        password_hash = password

    users[username] = {
        "password_hash": password_hash,
        "email": email,
        "role": role,
        "license_type": license_type,
        "license_mode": license_type,
        "license_expiry": license_expiry,
        "license_key": users.get(username, {}).get("license_key", ""),
        "is_banned": False,
    }

    # eski yapılarla uyum için
    if "password" not in users[username]:
        users[username]["password"] = password

    save_users(users)
    return redirect("/admin/panel?ok=user_added&open=users")


@app.route("/admin/toggle-ban/<target_username>", methods=["POST"])
def admin_toggle_ban(target_username):
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    if not login_required():
        return redirect(url_for("login"))
    if not admin_required():
        return redirect("/radial")

    users = load_users()
    if target_username in users:
        current = bool(users[target_username].get("is_banned", False))
        users[target_username]["is_banned"] = not current
        save_users(users)

    return redirect(f"/admin/panel?ok=ban_toggled&open=users#user-{target_username}")


@app.route("/admin/generate-license/<target_username>", methods=["POST"])
def admin_generate_license(target_username):
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    if not login_required():
        return redirect(url_for("login"))
    if not admin_required():
        return redirect("/radial")

    users = load_users()
    if target_username not in users:
        return redirect("/admin/panel?ok=user_not_found")

    current = str(users[target_username].get("license_key", "")).strip().upper()

    invalid_keys = {"", "TRIAL", "PRO", "FREE", "NONE", "-", "NULL"}
    if current in invalid_keys or not current.startswith("LIC-"):
        users[target_username]["license_key"] = generate_simple_license_key(users)
        save_users(users)
        current = users[target_username]["license_key"]
        print("LICENSE_GENERATED:", target_username, current, flush=True)
        return redirect(f"/admin/panel?ok=license_generated&license_key={current}&open=users#user-{target_username}")
    else:
        print("LICENSE_ALREADY_EXISTS:", target_username, current, flush=True)
        return redirect(f"/admin/panel?ok=license_exists&license_key={current}&open=users#user-{target_username}")
@app.route("/admin/approve-upgrade/<target_username>", methods=["POST"])
def admin_approve_upgrade(target_username):
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    if not login_required():
        return redirect(url_for("login"))
    if not admin_required():
        return redirect("/radial")

    users = load_users()
    if target_username not in users:
        return redirect(f"/admin/panel?ok=done&open=users#user-{target_username}")

    users[target_username]["license_type"] = "pro"
    users[target_username]["license_mode"] = "pro"
    if not str(users[target_username].get("license_expiry", "")).strip():
        users[target_username]["license_expiry"] = "2099-01-01"

    current_key = str(users[target_username].get("license_key", "")).strip().upper()
    if not current_key:
        users[target_username]["license_key"] = generate_simple_license_key(users)

    save_users(users)

    requests = load_upgrade_requests()
    for row in requests:
        if row.get("username") == target_username and row.get("status") == "pending":
            row["status"] = "approved"
    save_upgrade_requests(requests)

    print("UPGRADE_APPROVED:", target_username, flush=True)
    return redirect(f"/admin/panel?ok=upgrade_approved&open=users#user-{target_username}")

@app.route("/admin/update-license/<target_username>", methods=["POST"])
def admin_update_license(target_username):
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    if not login_required():
        return redirect(url_for("login"))
    if not admin_required():
        return redirect("/radial")

    users = load_users()
    if target_username not in users:
        print("LICENSE_UPDATE_ERROR: user not found ->", target_username, flush=True)
        return redirect(f"/admin/panel?ok=user_not_found&open=users#user-{target_username}")

    license_type = request.form.get("license_type", "trial").strip() or "trial"
    license_expiry = request.form.get("license_expiry", "").strip()

    users[target_username]["license_type"] = license_type
    users[target_username]["license_mode"] = license_type
    users[target_username]["license_expiry"] = license_expiry

    save_users(users)

    print("LICENSE_UPDATE_OK:", target_username, "type=", license_type, "expiry=", license_expiry, flush=True)
    return redirect(f"/admin/panel?ok=license_updated&open=users#user-{target_username}")


UPGRADE_REQUESTS_FILE = "data/upgrade_requests.json"

def load_upgrade_requests():
    if not os.path.exists(UPGRADE_REQUESTS_FILE):
        return []
    try:
        with open(UPGRADE_REQUESTS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except Exception:
        return []

def save_upgrade_requests(data):
    os.makedirs("data", exist_ok=True)
    with open(UPGRADE_REQUESTS_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def is_real_license_key(value):
    v = str(value or "").strip().upper()
    if not v:
        return False
    if v in {"TRIAL", "PRO", "FREE", "NONE", "-", "NULL"}:
        return False
    return v.startswith("LIC-") and len(v) >= 8

def generate_simple_license_key(users):
    import random, string
    while True:
        code = "LIC-" + "".join(random.choices(string.ascii_uppercase + string.digits, k=12))
        exists = False
        for _, u in users.items():
            if str(u.get("license_key", "")).upper() == code:
                exists = True
                break
        if not exists:
            return code

def _normalize_license_key(value):
    return str(value or "").strip().upper()




@app.route("/dashboard")
def dashboard():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    return redirect("/radial")


@app.route("/radial-demo")
def radial_demo():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    return render_template("radial_demo.html")

@app.route("/radial/koruma")
def radial_koruma():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    return redirect("/radial")

@app.route("/radial/analiz")
def radial_analiz():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    return redirect("/radial")

@app.route("/radial/engel")
def radial_engel():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    return redirect("/radial")

@app.route("/radial/bildirim")
def radial_bildirim():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    return redirect("/radial")

@app.route("/radial/topluluk")
def radial_topluluk():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    return redirect("/radial")

@app.route("/radial/ayarlar")
def radial_ayarlar():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    return redirect(url_for("setting"))

# -----------------------
# USERS
# -----------------------
@app.route("/users")
def users():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    if not admin_required():
        return redirect("/radial")

    return render_template(
        "users.html",
        users=load_users(),
        username=current_username()
    )

# -----------------------
# ADD USER
# -----------------------
@app.route("/add-user", methods=["GET", "POST"])
def add_user():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    if not admin_required():
        return redirect("/radial")

    message = ""
    error = ""

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "").strip()
        role = request.form.get("role", "user").strip()

        users = load_users()
        settings = load_settings()

        if not username or not password:
            error = "Kullanıcı adı ve şifre zorunlu."
        elif username in users:
            error = "Bu kullanıcı zaten mevcut."
        else:
            expiry = datetime.now() + timedelta(days=settings.get("trial_days", 7))

            users[username] = {
                "password_hash": generate_password_hash(password),
                "role": role,
                "license_type": "trial",
                "license_key": generate_license_key(),
                "license_expiry": expiry.strftime("%Y-%m-%d")
            }
            save_users(users)
            message = "Kullanıcı + lisans oluşturuldu."

    return render_template("add_user.html", message=message, error=error)


# -----------------------
# DELETE USER
# -----------------------
@app.route("/delete-user/<username>", methods=["POST"])
def delete_user(username):
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    if not admin_required():
        return redirect("/radial")

    username = username.strip().lower()
    users = load_users()

    if username == "admin":
        return redirect(url_for("users"))

    if username in users:
        del users[username]
        save_users(users)

    return redirect(url_for("users"))

# -----------------------
# MANAGE LICENSE
# -----------------------
@app.route("/manage-license/<username>", methods=["GET", "POST"])
def manage_license(username):
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    if not admin_required():
        return redirect("/radial")

    username = username.strip().lower()
    users = load_users()

    if username not in users:
        return redirect(url_for("users"))

    message = ""
    error = ""
    user = users[username]

    if request.method == "POST":
        action = request.form.get("action", "").strip()

        if action == "extend":
            try:
                extra_days = int(request.form.get("extra_days", "0").strip())
                if extra_days <= 0:
                    error = "Geçerli bir gün sayısı gir."
                else:
                    now = datetime.now()
                    current_expiry_raw = user.get("license_expiry", "")
                    try:
                        current_expiry = datetime.strptime(current_expiry_raw, "%Y-%m-%d")
                        base_date = current_expiry if current_expiry > now else now
                    except:
                        base_date = now

                    new_expiry = base_date + timedelta(days=extra_days)
                    user["license_expiry"] = new_expiry.strftime("%Y-%m-%d")
                    save_users(users)
                    message = f"{username} için +{extra_days} gün eklendi."
            except:
                error = "Gün sayısı hatalı."

        elif action == "make_pro":
            user["license_type"] = "pro"
            if user.get("license_key") in ["", "TRIAL"]:
                user["license_key"] = generate_license_key()
            if not user.get("license_expiry"):
                user["license_expiry"] = (datetime.now() + timedelta(days=30)).strftime("%Y-%m-%d")
            save_users(users)
            message = f"{username} PRO yapıldı."

        elif action == "make_trial":
            settings = load_settings()
            user["license_type"] = "trial"
            user["license_key"] = "TRIAL"
            user["license_expiry"] = (datetime.now() + timedelta(days=settings.get("trial_days", 7))).strftime("%Y-%m-%d")
            save_users(users)
            message = f"{username} trial yapıldı."

        elif action == "reset_license":
            user["license_key"] = generate_license_key()
            save_users(users)
            message = f"{username} için lisans kodu yenilendi."

    users = load_users()
    user = users[username]

    return render_template(
        "manage_license.html",
        target_username=username,
        target_user=user,
        message=message,
        error=error,
        days_left=days_left(user)
    )

# -----------------------
# CHANGE PASSWORD
# -----------------------
@app.route("/change", methods=["GET", "POST"])
def change():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    if not login_required():
        return redirect(url_for("login"))

    message = ""
    error = ""

    if request.method == "POST":
        current_password = request.form.get("current_password", "").strip()
        new_password = request.form.get("new_password", "").strip()
        new_password2 = request.form.get("new_password2", "").strip()

        users = load_users()
        username = current_username()

        if username not in users:
            error = "Kullanıcı bulunamadı."
        elif users[username]["password"] != current_password:
            error = "Mevcut şifre yanlış."
        elif not new_password:
            error = "Yeni şifre boş olamaz."
        elif new_password != new_password2:
            error = "Yeni şifreler eşleşmiyor."
        else:
            users[username]["password"] = new_password
            save_users(users)
            message = "Şifre başarıyla değiştirildi."

    return render_template("change.html", message=message, error=error)

# -----------------------
# SETTINGS
# -----------------------
@app.route("/setting", methods=["GET", "POST"])
def setting():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    if not admin_required():
        return redirect("/radial")

    settings = load_settings()
    message = ""

    if request.method == "POST":
        app_name = request.form.get("app_name", "").strip()
        trial_days = request.form.get("trial_days", "").strip()
        license_mode = request.form.get("license_mode", "").strip()

        if app_name:
            settings["app_name"] = app_name

        try:
            settings["trial_days"] = int(trial_days)
        except:
            pass

        if license_mode:
            settings["license_mode"] = license_mode

        save_settings(settings)
        message = "Ayarlar kaydedildi."

    return render_template("setting.html", config=settings, message=message)

# -----------------------
# ACTIVATE LICENSE
# -----------------------
@app.route("/admin/licenses", methods=["GET", "POST"])
def admin_licenses():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    if not login_required():
        return redirect(url_for("login"))
    if not admin_required():
        return redirect("/radial")

    users = load_users()
    licenses = load_licenses()

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        plan = request.form.get("plan", "pro").strip() or "pro"
        duration_days_raw = request.form.get("duration_days", "30").strip()

        if not username:
            return render_template(
                "admin_licenses.html",
                users=users,
                licenses=licenses,
                error="Kullanıcı adı gerekli"
            )

        if username not in users:
            return render_template(
                "admin_licenses.html",
                users=users,
                licenses=licenses,
                error="Kullanıcı bulunamadı"
            )

        try:
            duration_days = int(duration_days_raw)
        except Exception:
            duration_days = 30

        if duration_days < 1:
            duration_days = 1

        from datetime import datetime, timedelta

        license_key = generate_license_key()
        created_at = datetime.now().strftime("%Y-%m-%d")
        expires_at = (datetime.now() + timedelta(days=duration_days)).strftime("%Y-%m-%d")

        licenses[license_key] = {
            "username": username,
            "username": username,
            "plan": plan,
            "status": "active",
            "created_at": created_at,
            "expires_at": expires_at
        }
        save_licenses(licenses)
        sync_user_license(username, license_key, plan, expires_at)

        users = load_users()
        licenses = load_licenses()

        mail_status = ""
        target_user = users.get(username, {}) if isinstance(users, dict) else {}
        target_email = str(target_user.get("email", "")).strip()

        if target_email:
            subject = f"EratGuard {plan.upper()} Lisans Bilgilerin"
            body = (
                f"Merhaba {username},"
                f"Lisansın oluşturuldu."
                f"Lisans Kodu: {license_key}"
                f"Paket: {plan}"
                f"Başlangıç: {created_at}"
                f"Bitiş: {expires_at}"
                f"EratGuard'i kullandığın için teşekkür ederiz."
            )
            ok, msg = send_mail(
                to_email=target_email,
                subject=subject,
                body=body
            )
            if ok:
                mail_status = f" | Mail gönderildi: {target_email}"
            else:
                mail_status = f" | Mail gönderilemedi: {msg}"
        else:
            mail_status = " | Kullanıcıda email kayıtlı değil"

        return render_template(
            "admin_licenses.html",
            users=users,
            licenses=licenses,
            success="Lisans oluşturuldu" + mail_status,
            new_license_key=license_key
        )

    return render_template(
        "admin_licenses.html",
        users=users,
        licenses=licenses
    )

@app.route("/landing")
def landing():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    from flask import session, redirect, render_template
    if session.get("username") or session.get("user"):
        return redirect("/radial")
    return render_template("landing.html")

@app.route("/logout")
def logout():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    session.clear()
    return redirect(url_for("login"))


# -----------------------
# RUN
# -----------------------
# -----------------------
# LOG API
# -----------------------

@app.route("/api/logs")
def api_logs():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    logs = load_logs()
    logs = list(reversed(logs))[:100]
    return jsonify({
        "status": "success",
        "total": len(logs),
        "logs": logs
    })


@app.route("/api/add-log", methods=["POST"])
def api_add_log():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    try:
        data = request.get_json(force=True)

        new_log = {
            "timestamp": data.get("timestamp") or datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "from": data.get("from", "BILINMEYEN"),
            "status": data.get("status", "TEMIZ"),
            "score": data.get("score", 0),
            "message": data.get("message", "")
        }

        logs = load_logs()
        logs.append(new_log)

        if len(logs) > 1000:
            logs = logs[-1000:]

        save_logs(logs)

        return jsonify({
            "status": "success",
            "log": new_log
        })

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

# -----------------------
# FEEDBACK API
# -----------------------

@app.route("/api/feedback", methods=["POST"])
def api_feedback():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    try:
        data = request.get_json(force=True)

        entry = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "correct": bool(data.get("correct")),
            "log": data.get("log", {})
        }

        items = load_feedback()
        items.append(entry)

        if len(items) > 2000:
            items = items[-2000:]

        save_feedback(items)

        return jsonify({
            "status": "success",
            "feedback": entry
        })

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

# -----------------------
# STATS API
# -----------------------

@app.route("/api/stats")
def api_stats():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    try:
        logs = load_logs()

        spam = 0
        temiz = 0

        for log in logs:
            status = str(log.get("status", "")).upper()
            if status == "SPAM":
                spam += 1
            elif status == "TEMIZ":
                temiz += 1

        return jsonify({
            "status": "success",
            "total": len(logs),
            "spam": spam,
            "temiz": temiz
        })

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    cleanup_expired_tokens()

    if request.method == "POST":
        identity = (request.form.get("identity", "") or "").strip()

        if not identity:
            return render_template(
                "forgot.html",
                success=False,
                error="Lütfen kullanıcı adı veya e-posta girin.",
                message=None,
                reset_link=None,
                reset_code=None
            )

        username, user = find_user_by_identity(identity)
        reset_link = None
        reset_code = None

        if username and user:
            raw_token = create_reset_token(username)
            reset_link = url_for("reset_password", token=raw_token, _external=True)
            reset_code = create_reset_code(username)

            target_email = str(user.get("email", "") or "").strip()
            if not target_email and "@" in username:
                target_email = username

            if target_email:
                subject = "EratGuard Şifre Sıfırlama"
                body = (
                    f"Merhaba {username},\n\n"
                    f"EratGuard hesabın için şifre sıfırlama isteği oluşturuldu.\n\n"
                    f"Sıfırlama linki:\n{reset_link}\n\n"
                    f"6 haneli kodun: {reset_code}\n\n"
                    f"Bu işlemi sen yapmadıysan bu mesajı yok sayabilirsin.\n"
                )

                try:
                    ok, msg = send_mail(
                        to_email=target_email,
                        subject=subject,
                        body=body
                    )
                    print("Password reset mail:", ok, msg)
                except Exception as e:
                    print("Password reset mail error:", e)

        return render_template(
            "forgot.html",
            success=True,
            message="Bu bilgi sistemde varsa sıfırlama bilgisi oluşturuldu.",
            reset_link=reset_link,
            reset_code=reset_code,
            error=None
        )

    return render_template(
        "forgot.html",
        success=False,
        error=None,
        message=None,
        reset_link=None,
        reset_code=None
    )



@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    import time

    users = load_users()

    if request.method == "POST":
        username = request.form.get("username") or request.args.get("username", "")
        code = request.form.get("code") or request.args.get("code", "")

        username = username.strip()
        code = code.strip()
        new_password = request.form.get("password", "").strip()
        email = request.form.get("email", "").strip()

        if not username or not code or not new_password:
            return render_template("reset.html", error="Tüm alanları doldur")

        if username not in users:
            return render_template("reset.html", error="Kullanıcı bulunamadı")

        user = users[username]
        saved_code = str(user.get("reset_code", "")).strip()
        expires_at = int(user.get("reset_code_expires_at", 0) or 0)
        used = bool(user.get("reset_code_used", False))
        now_ts = int(time.time())

        attempts = int(user.get("reset_attempts", 0) or 0)
        max_attempts = 5

        if attempts >= max_attempts:
            return render_template("reset.html", error="Çok fazla hatalı deneme yapıldı. Yeni kod oluştur.")

        if not saved_code or saved_code != code:
            user["reset_attempts"] = attempts + 1
            save_users(users)
            kalan = max_attempts - user["reset_attempts"]
            if kalan < 0:
                kalan = 0
            return render_template("reset.html", error=f"Kod yanlış veya geçersiz. Kalan deneme: {kalan}")

        if used:
            return render_template("reset.html", error="Bu kod daha önce kullanılmış")

        if not expires_at or now_ts > expires_at:
            user["reset_code"] = ""
            user["reset_code_expires_at"] = 0
            user["reset_code_used"] = False
            user["reset_attempts"] = 0
            save_users(users)
            return render_template("reset.html", error="Kodun süresi dolmuş")

        user["password"] = new_password
        user["reset_code_used"] = True
        user["reset_code"] = ""
        user["reset_code_expires_at"] = 0
        user["reset_attempts"] = 0
        save_users(users)

        return render_template("reset.html", success="Şifre başarıyla değiştirildi")

    return render_template("reset.html")

# === LICENSE SYSTEM PHASE 1 START ===
LICENSES_FILE = "data/licenses.json"

def load_licenses():
    import json
    import os

    if not os.path.exists(LICENSES_FILE):
        with open(LICENSES_FILE, "w", encoding="utf-8") as f:
            json.dump({}, f, ensure_ascii=False, indent=2)

    try:
        with open(LICENSES_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except Exception:
        return {}

def save_licenses(data):
    import json
    with open(LICENSES_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def generate_license_key():
    import random
    import string
    chars = string.ascii_uppercase + string.digits
    while True:
        parts = []
        for _ in range(3):
            parts.append("".join(random.choice(chars) for _ in range(4)))
        key = "SSHD-" + "-".join(parts)
        licenses = load_licenses()
        if key not in licenses:
            return key

def get_current_username():
    try:
        return str(session.get("username", "")).strip()
    except Exception:
        return ""

def days_left_from_expiry(expiry_str):
    from datetime import datetime
    try:
        exp = datetime.strptime(expiry_str, "%Y-%m-%d").date()
        today = datetime.now().date()
        return (exp - today).days
    except Exception:
        return -1

def sync_user_license(username, license_key, plan, expires_at):
    users = load_users()
    if username not in users:
        return False

    users[username]["license_key"] = license_key
    users[username]["license_type"] = plan
    users[username]["license_expiry"] = expires_at
    save_users(users)
    return True

@app.route("/my-license-old-disabled", methods=["GET"])
def my_license_old_disabled():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    if not login_required():
        return redirect(url_for("login"))

    username = get_current_username()
    users = load_users()
    licenses = load_licenses()

    if username not in users:
        return redirect(url_for("login"))

    user = users[username]
    license_key = str(user.get("license_key", "")).strip()
    license_data = licenses.get(license_key, {}) if license_key else {}
    expiry = str(user.get("license_expiry", "")).strip()
    remaining_days = days_left_from_expiry(expiry) if expiry else -1

    return render_template(
        "my_license.html",
        username=username,
        user=user,
        license_key=license_key,
        license_data=license_data,
        remaining_days=remaining_days
    )


@app.route("/pricing")
def pricing():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    if not login_required():
        return redirect(url_for("login"))
    return render_template("pricing.html")



# ===== PAYMENT REQUEST LEGACY ALIAS FIX =====
# Eski route load_payment_requests/save_payment_requests çağırıyor olabilir.
# Aktif sistemde ss_load_payment_requests varsa ona yönlendiriyoruz.
try:
    load_payment_requests
except NameError:
    try:
        load_payment_requests = ss_load_payment_requests
    except NameError:
        def load_payment_requests():
            return []

try:
    save_payment_requests
except NameError:
    try:
        save_payment_requests = ss_save_payment_requests
    except NameError:
        def save_payment_requests(data):
            return None
# ===== /PAYMENT REQUEST LEGACY ALIAS FIX =====


@app.route("/admin/payment-requests")
def admin_payment_requests():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    if not login_required():
        return redirect(url_for("login"))
    if not admin_required():
        return redirect("/radial")

    requests_data = load_payment_requests()
    return render_template("admin_payment_requests.html", requests=requests_data)

@app.route("/buy-license")
def buy_license():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    if not login_required():
        return redirect(url_for("login"))

    key = generate_pool_license(30)

    return f"""
    <html>
    <head><meta charset='UTF-8'><title>Satın Alma Başarılı</title></head>
    <body style="background:#0b1220;color:white;font-family:Arial;padding:30px;">
        <h2>Satın alma başarılı</h2>
        <p>Tek kullanımlık lisans kodun:</p>
        <p style="font-size:24px;font-weight:bold;">{key}</p>
        <p>Bu kod bir kez kullanılabilir.</p>
        <a href="/activate-license" style="color:#60a5fa;">Lisansı aktifleştir</a><br><br>
        <a href="/dashboard" style="color:#60a5fa;">Dashboard'a dön</a>
    </body>
    </html>
    """

# -----------------------
# ADMIN LICENSE PANEL
# -----------------------



@app.route("/reset-code", methods=["GET", "POST"])
def reset_code():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    cleanup_expired_tokens()

    if request.method == "POST":
        code = (request.form.get("code", "") or "").strip()
        password = (request.form.get("password", "") or "").strip()
        confirm_password = (request.form.get("confirm_password", "") or "").strip()

        record = find_valid_code_record(code)
        if not record:
            return render_template(
                "reset_code.html",
                error="Geçersiz, kullanılmış veya süresi dolmuş kod.",
                success=None
            )

        if len(password) < 8:
            return render_template(
                "reset_code.html",
                error="Şifre en az 8 karakter olmalıdır.",
                success=None
            )

        if password != confirm_password:
            return render_template(
                "reset_code.html",
                error="Şifreler eşleşmiyor.",
                success=None
            )

        username = record["username"]
        ok = reset_user_password(username, password)

        if not ok:
            return render_template(
                "reset_code.html",
                error="Kullanıcı bulunamadı veya işlem başarısız.",
                success=None
            )

        mark_token_used(code)
        return render_template("reset_success.html")

    return render_template("reset_code.html", error=None, success=None)

# =========================
# ⚙️ ADMIN SETTINGS
# =========================
import json
SETTINGS_FILE = "eratguard_runtime_settings.json"

def load_runtime_settings():
    if not os.path.exists(SETTINGS_FILE):
        return {
            "enable_notifications": True,
            "enable_vibration": True,
            "enable_auto_delete": False,
            "sms_limit": 5,
            "poll_interval": 10,
            "spam_threshold": 40
        }
    with open(SETTINGS_FILE, "r") as f:
        return json.load(f)

def save_runtime_settings(data):
    with open(SETTINGS_FILE, "w") as f:
        json.dump(data, f, indent=2)




@app.route("/admin/overview")
def admin_overview():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    if not login_required():
        return redirect(url_for("login"))

    if not admin_required():
        return redirect("/radial")

    users = load_users()
    runtime_settings = load_runtime_settings()
    spam_logs = load_spam_logs() if 'load_spam_logs' in globals() else []

    stats = {
        "total_users": len(users),
        "spam_log_count": len(spam_logs),
        "notifications": runtime_settings.get("enable_notifications", True),
        "vibration": runtime_settings.get("enable_vibration", True),
        "auto_delete": runtime_settings.get("enable_auto_delete", False),
        "sms_limit": runtime_settings.get("sms_limit", 5),
        "poll_interval": runtime_settings.get("poll_interval", 10),
        "spam_threshold": runtime_settings.get("spam_threshold", 40)
    }

    recent_logs = spam_logs[:10] if isinstance(spam_logs, list) else []

    return render_template("admin_overview.html", stats=stats, recent_logs=recent_logs)



SPAM_LOGS_FILE = "data/spam_logs.json"



def save_spam_logs(logs):
    SPAM_LOGS_FILE = "data/spam_logs.json"
    import json
    with open(SPAM_LOGS_FILE, "w", encoding="utf-8") as f:
        json.dump(logs, f, indent=2, ensure_ascii=False)

def load_spam_logs():
    if not os.path.exists(SPAM_LOGS_FILE):
        return []
    try:
        with open(SPAM_LOGS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except Exception:
        return []





@app.route("/admin/mark-clean", methods=["POST"])
def admin_mark_clean():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    if not login_required():
        return redirect(url_for("login"))

    if not admin_required():
        return redirect("/radial")

    sender = request.form.get("sender", "").upper().strip()
    body = request.form.get("body", "")

    # WHITELIST
    whitelist = load_whitelist()
    if sender and sender not in whitelist:
        whitelist.append(sender)
        save_whitelist(whitelist)

    # AI öğrenme
    try:
        from ai_model import learn
        learn(body, "clean")
    except Exception as e:
        print("AI ERROR:", e)

    # logdan sil
    logs = load_spam_logs()
    logs = [x for x in logs if not (x.get("sender") == sender and x.get("body") == body)]
    save_spam_logs(logs)

    return redirect(url_for("admin_spam_logs"))


@app.route("/admin/spam-logs")
def admin_spam_logs():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    if not login_required():
        return redirect(url_for("login"))

    if not admin_required():
        return redirect("/radial")

    spam_logs = load_spam_logs()
    return render_template("admin_spam_logs.html", spam_logs=spam_logs)




# =========================
# ⚙️ ADMIN SETTINGS
# =========================
RUNTIME_SETTINGS_FILE = "eratguard_runtime_settings.json"

def load_runtime_settings():
    defaults = {
        "enable_notifications": True,
        "enable_vibration": True,
        "enable_auto_delete": False,
        "sms_limit": 5,
        "poll_interval": 10,
        "spam_threshold": 40
    }

    if not os.path.exists(RUNTIME_SETTINGS_FILE):
        with open(RUNTIME_SETTINGS_FILE, "w", encoding="utf-8") as f:
            json.dump(defaults, f, ensure_ascii=False, indent=2)
        return defaults

    try:
        with open(RUNTIME_SETTINGS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            defaults.update(data)
        return defaults
    except Exception:
        return defaults

def save_runtime_settings(data):
    with open(RUNTIME_SETTINGS_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

@app.route("/admin/settings", methods=["GET", "POST"])



def admin_settings():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    if not login_required():
        return redirect(url_for("login"))

    if not admin_required():
        return redirect("/radial")

    settings = load_runtime_settings()

    if request.method == "POST":
        settings["enable_notifications"] = "enable_notifications" in request.form
        settings["enable_vibration"] = "enable_vibration" in request.form
        settings["enable_auto_delete"] = "enable_auto_delete" in request.form

        try:
            settings["sms_limit"] = int(request.form.get("sms_limit", 5))
        except:
            settings["sms_limit"] = 5

        try:
            settings["poll_interval"] = int(request.form.get("poll_interval", 10))
        except:
            settings["poll_interval"] = 10

        try:
            settings["spam_threshold"] = int(request.form.get("spam_threshold", 40))
        except:
            settings["spam_threshold"] = 40

        save_runtime_settings(settings)

    return render_template("admin_settings.html", settings=settings)




@app.route("/request-upgrade", methods=["POST"])
def request_upgrade():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    if not login_required():
        return redirect(url_for("login"))

    users = load_users()
    username = session.get("username")
    user = users.get(username, {})

    requests = load_upgrade_requests()

    already_open = False
    for row in requests:
        if row.get("username") == username and row.get("status") == "pending":
            already_open = True
            break

    if not already_open:
        requests.insert(0, {
            "username": username,
            "current_license": user.get("license_type", "trial"),
            "status": "pending"
        })
        save_upgrade_requests(requests)

    return redirect("/upgrade")

@app.route("/upgrade")
def upgrade():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    if not login_required():
        return redirect(url_for("login"))

    users = load_users()
    username = session.get("username")
    user = users.get(username, {})

    return render_template(
        "upgrade.html",
        user=user,
        username=username
    )

def _normalize_license_key(value):
    return str(value or "").strip().upper()

def _read_json_file(path, default):
    import json
    from pathlib import Path
    p = Path(path)
    if not p.exists():
        return default
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return default

def _write_json_file(path, data):
    import json
    from pathlib import Path
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

def strict_find_generated_license(key):
    key = _normalize_license_key(key)
    items = _read_json_file("data/generated_licenses.json", [])
    if not isinstance(items, list):
        return None
    for item in items:
        if _normalize_license_key(item.get("key", "")) == key:
            return item
    return None

def strict_verify_generated_license(key):
    from datetime import datetime

    key = _normalize_license_key(key)
    if not key:
        return False, "Lisans kodu boş."

    item = strict_find_generated_license(key)
    if not item:
        return False, "Lisans kodu geçersiz."

    if bool(item.get("used", False)):
        return False, "Bu lisans daha önce kullanılmış."

    expiry = str(item.get("expiry", "")).strip()
    if expiry:
        parsed = None
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
            try:
                parsed = datetime.strptime(expiry, fmt)
                break
            except Exception:
                pass
        if parsed and parsed < datetime.now():
            return False, "Bu lisansın süresi dolmuş."

    return True, "OK"

def strict_mark_generated_license_used(key, username=""):
    from datetime import datetime

    key = _normalize_license_key(key)
    items = _read_json_file("data/generated_licenses.json", [])
    if not isinstance(items, list):
        items = []

    changed = False
    for item in items:
        if _normalize_license_key(item.get("key", "")) == key:
            item["used"] = True
            item["activated_by"] = username
            item["activated_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            changed = True
            break

    if changed:
        _write_json_file("data/generated_licenses.json", items)

    return changed

def strict_activate_generated_license(username, key):
    key = _normalize_license_key(key)

    ok, msg = strict_verify_generated_license(key)
    if not ok:
        return False, msg

    users = _read_json_file("data/users.json", {})
    if not isinstance(users, dict):
        users = {}

    if username not in users:
        return False, "Kullanıcı bulunamadı."

    item = strict_find_generated_license(key)
    if not item:
        return False, "Lisans kaydı bulunamadı."

    users[username]["license_key"] = key
    users[username]["license_type"] = str(item.get("type", "pro") or "pro")
    users[username]["plan"] = str(item.get("type", "pro") or "pro")
    users[username]["license_expiry"] = str(item.get("expiry", "")).strip()

    _write_json_file("data/users.json", users)
    strict_mark_generated_license_used(key, username=username)
    bind_user_license_security(username)

    return True, "Lisans başarıyla aktifleştirildi."

def get_device_fingerprint():
    import hashlib
    from flask import request

    raw = "||".join([
        str(request.headers.get("User-Agent", "")),
        str(request.headers.get("Accept-Language", "")),
        str(request.headers.get("Host", "")),
    ])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()

def sign_license_payload(username, license_key, expiry, device_id):
    import hashlib
    secret = "ERATGUARD_PRO_CORE_V1"
    raw = f"{username}|{license_key}|{expiry}|{device_id}|{secret}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()

def bind_user_license_security(username):
    users = _read_json_file("data/users.json", {})
    if not isinstance(users, dict) or username not in users:
        return False

    user = users.get(username, {})
    license_key = str(user.get("license_key", "")).strip()
    expiry = str(user.get("license_expiry", "")).strip()
    if not license_key:
        return False

    device_id = get_device_fingerprint()
    signature = sign_license_payload(username, license_key, expiry, device_id)

    user["device_id"] = device_id
    user["license_signature"] = signature
    users[username] = user
    _write_json_file("data/users.json", users)
    return True

def verify_user_license_security(username):
    users = _read_json_file("data/users.json", {})
    if not isinstance(users, dict) or username not in users:
        return False, "Kullanıcı bulunamadı."

    user = users.get(username, {})
    license_key = str(user.get("license_key", "")).strip()
    expiry = str(user.get("license_expiry", "")).strip()
    stored_device = str(user.get("device_id", "")).strip()
    stored_signature = str(user.get("license_signature", "")).strip()

    if not license_key:
        return False, "Lisans bulunamadı."

    current_device = get_device_fingerprint()

    if stored_device and stored_device != current_device:
        return False, "Bu lisans farklı cihazda kayıtlı."

    expected_signature = sign_license_payload(username, license_key, expiry, current_device)

    if stored_signature and stored_signature != expected_signature:
        return False, "Lisans bütünlüğü bozulmuş."

    return True, "OK"

@app.route("/activate-license", methods=["GET", "POST"])
def activate_license():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    from flask import session

    username = str(session.get("username") or session.get("user") or "").strip()
    error = ""
    success = ""

    users = _read_json_file("data/users.json", {})
    if not isinstance(users, dict):
        users = {}

    user = users.get(username, {}) if username else {}

    if request.method == "POST":
        key = request.form.get("license_key", "").strip()

        if not username:
            error = "Oturum bulunamadı. Lütfen tekrar giriş yap."
        else:
            ok, msg = strict_activate_generated_license(username, key)
            if ok:
                success = msg
                users = _read_json_file("data/users.json", {})
                if not isinstance(users, dict):
                    users = {}
                user = users.get(username, {})
            else:
                error = msg

    return render_template(
        "activate_license.html",
        error=error,
        success=success,
        user=user,
        username=username
    )


@app.route("/radial")
def radial():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    if not login_required():
        return redirect(url_for("login"))

    username = session.get("username") or session.get("user") or ""
    users = {}
    try:
        users = load_users()
    except Exception:
        users = {}

    user_row = users.get(username, {}) if isinstance(users, dict) else {}
    current_plan = (
        user_row.get("license_type")
        or user_row.get("license_mode")
        or user_row.get("plan")
        or "trial"
    )

    is_admin_user = False
    try:
        is_admin_user = admin_required()
    except Exception:
        is_admin_user = (user_row.get("role") == "admin" or username == "admin")

    license_target = "/admin/licenses" if is_admin_user else "/pricing"
    panel_target = "/admin/panel" if is_admin_user else "/dashboard"

    stats = {
        "total_sms": 125,
        "blocked_count": 24,
        "notification_count": 3,
        "protection_status": "Aktif",
    }

    return render_template(
        "radial_menu.html",
        current_plan=current_plan,
        license_target=license_target,
        panel_target=panel_target,
        stats=stats,
        username=username,
    )


@app.route("/")
def home():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    user_now = session.get("username") or session.get("user")
    if user_now:
        return redirect("/radial")
    return render_template("landing.html")


@app.route("/protection")
# @pro_required
def protection_page():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    return """
    <html><head><meta charset="UTF-8"><title>Koruma</title></head>
    <body style="background:#06122b;color:white;font-family:Arial;padding:24px;">
        <h2>🛡 Koruma</h2>
        <p>Koruma modülü hazırlık aşamasında.</p>
        <p><a href="/radial" style="color:#7dd3fc;">← Radial'e dön</a></p>
    </body></html>
    """

@app.route("/analysis")
def analysis_page():
    # Admin analiz eski placeholder yerine premium admin analiz merkezine gider.
    try:
        if session.get("is_admin") or session.get("role") == "admin" or session.get("username") == "admin":
            return redirect("/admin/overview")
    except Exception:
        pass
    return redirect("/u/analysis")

@app.route("/blocked")
# @pro_required
def blocked_page():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    return """
    <html><head><meta charset="UTF-8"><title>Engellenenler</title></head>
    <body style="background:#06122b;color:white;font-family:Arial;padding:24px;">
        <h2>🚫 Engellenenler</h2>
        <p>Engellenenler modülü hazırlık aşamasında.</p>
        <p><a href="/radial" style="color:#7dd3fc;">← Radial'e dön</a></p>
    </body></html>
    """

@app.route("/notifications")
# @pro_required
def notifications_page():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    return """
    <html><head><meta charset="UTF-8"><title>Bildirimler</title></head>
    <body style="background:#06122b;color:white;font-family:Arial;padding:24px;">
        <h2>🔔 Bildirimler</h2>
        <p>Bildirimler modülü hazırlık aşamasında.</p>
        <p><a href="/radial" style="color:#7dd3fc;">← Radial'e dön</a></p>
    </body></html>
    """

@app.route("/settings")
def settings_page():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    return """
    <html><head><meta charset="UTF-8"><title>Ayarlar</title></head>
    <body style="background:#06122b;color:white;font-family:Arial;padding:24px;">
        <h2>⚙️ Ayarlar</h2>
        <p>Ayarlar modülü hazırlık aşamasında.</p>
        <p><a href="/radial" style="color:#7dd3fc;">← Radial'e dön</a></p>
    </body></html>
    """

@app.route("/license")
def license_page():
    return redirect("/u/license")

@app.route("/reports")
# @pro_required
def reports_page():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    return """
    <html><head><meta charset="UTF-8"><title>Raporlar</title></head>
    <body style="background:#06122b;color:white;font-family:Arial;padding:24px;">
        <h2>📈 Raporlar</h2>
        <p>Raporlar modülü hazırlık aşamasında.</p>
        <p><a href="/radial" style="color:#7dd3fc;">← Radial'e dön</a></p>
    </body></html>
    """

@app.route("/community")
# @pro_required
def community_page():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    return """
    <html><head><meta charset="UTF-8"><title>Topluluk</title></head>
    <body style="background:#06122b;color:white;font-family:Arial;padding:24px;">
        <h2>👥 Topluluk</h2>
        <p>Topluluk modülü hazırlık aşamasında.</p>
        <p><a href="/radial" style="color:#7dd3fc;">← Radial'e dön</a></p>
    </body></html>
    """

@app.route("/activate")
def activate_alias():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    return redirect("/activate-license")

def load_order_requests():
    from pathlib import Path
    import json

    primary = Path("data/orders.json")
    legacy = Path("data/bot_orders.json")

    for path in [primary, legacy]:
        if path.exists():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(data, list):
                    return data
            except Exception:
                pass

    return []


def save_order_requests(orders):
    from pathlib import Path
    import json

    Path("data").mkdir(exist_ok=True)

    primary = Path("data/orders.json")
    legacy = Path("data/bot_orders.json")

    payload = json.dumps(orders, ensure_ascii=False, indent=2)

    primary.write_text(payload, encoding="utf-8")
    legacy.write_text(payload, encoding="utf-8")


def issue_order_license(order_id):
    orders = load_order_requests()

    for order in orders:
        if str(order.get("order_id", "")) == str(order_id):
            if str(order.get("status", "")).strip().lower() == "licensed" and order.get("license_key"):
                save_order_requests(orders)
                return order.get("license_key")

            created_key = create_license(note=f"order:{order_id}")
            if isinstance(created_key, dict):
                created_key = created_key.get("key")

            order["status"] = "licensed"
            order["license_key"] = created_key
            save_order_requests(orders)
            return created_key

    return None

@app.route("/orders")
@app.route("/bot-orders")
def orders_page():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    orders = load_order_requests()
    orders = list(reversed(orders))
    return render_template("bot_orders.html", orders=orders)


@app.route("/orders/give-license/<order_id>", methods=["POST"])
@app.route("/bot-orders/give-license/<order_id>", methods=["POST"])
def give_order_license(order_id):
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    issue_order_license(order_id)
    return redirect("/orders")



SS_PROTECTED_PATHS = {
    "/protection",
    "/analysis",
    "/blocked",
    "/notifications",
    "/reports",
    "/community",
}
SS_LOGIN_REQUIRED_PATHS = SS_PROTECTED_PATHS | {"/radial"}

def _ss_current_username():
    from flask import session
    return str(session.get("username") or session.get("user") or "").strip()

def _ss_user_record(username):
    users = _read_json_file("data/users.json", {})
    if not isinstance(users, dict):
        users = {}
    return users.get(username, {}) if username else {}

def _ss_is_allowed(username, path):
    user = _ss_user_record(username)
    role = str(user.get("role", "")).strip().lower()

    # 🔥 ADMIN HER ZAMAN GEÇER
    if role == "admin":
        return True, "ADMIN_OK"

    if path in SS_PROTECTED_PATHS:
        plan = str(user.get("license_type") or user.get("plan") or "trial").strip().lower()

        if plan != "pro":
            return False, "PRO_REQUIRED"

        if "verify_user_license_security" in globals():
            return verify_user_license_security(username)

    return True, "OK"


def _ss_before_request_guard():
    from flask import request, redirect

    path = str(request.path or "/").strip()

    if (
        path.startswith("/static/")
        or path in {"/login", "/logout", "/activate-license", "/activate", "/favicon.ico"}
        or path.startswith("/admin")
        or path.startswith("/orders")
        or path.startswith("/bot-orders")
    ):
        return None

    if path == "/dashboard":
        return redirect("/radial")

    username = _ss_current_username()

    if path in SS_LOGIN_REQUIRED_PATHS and not username:
        return redirect("/login")

    if path in SS_PROTECTED_PATHS:
        ok, msg = _ss_is_allowed(username, path)
        if not ok:
            return redirect("/activate-license")

    return None




@app.route("/admin/dashboard")
def admin_dashboard_new():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    return render_template("admin_dashboard.html")




@app.route("/admin/mobile_ui")
def admin_mobile_ui():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    return render_template("mobile_ui.html")
@app.route("/admin/dashboard_v2")
def dashboard_v2():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    return render_template("dashboard_v2.html")




# === SYSTEM RESOURCES API START ===
import time
import subprocess
import re as _re

def _read_cpu_stat():
    with open("/proc/stat") as f:
        vals = list(map(int, f.readline().split()[1:]))
    idle = vals[3]
    total = sum(vals)
    return idle, total

def _cpu_percent():
    try:
        i1, t1 = _read_cpu_stat()
        time.sleep(0.25)
        i2, t2 = _read_cpu_stat()
        dt = t2 - t1
        di = i2 - i1
        if dt <= 0:
            return 1
        return max(1, min(100, int((1 - di / dt) * 100)))
    except Exception:
        return 1

def _ram_percent():
    try:
        mem = {}
        for line in open("/proc/meminfo"):
            parts = line.split()
            if len(parts) >= 2:
                mem[parts[0].replace(":", "")] = int(parts[1])
        total = mem.get("MemTotal", 1)
        avail = mem.get("MemAvailable", 0)
        return max(0, min(100, int((total - avail) * 100 / total)))
    except Exception:
        return 0

def _battery_percent():
    try:
        out = subprocess.check_output(["termux-battery-status"], timeout=2).decode()
        m = _re.search(r'"percentage"\s*:\s*(\d+)', out)
        if m:
            return int(m.group(1))
    except Exception:
        pass
    return 0

@app.route("/api/system-resources")
def system_resources_api():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    return jsonify({
        "cpu": _cpu_percent(),
        "ram": _ram_percent(),
        "battery": _battery_percent()
    })
# === SYSTEM RESOURCES API END ===




# === ADMIN QUICK ACTIONS START ===
@app.route("/api/start-scan")
def api_start_scan():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    import json, time
    from pathlib import Path

    path = Path("data/admin_actions.json")
    path.parent.mkdir(parents=True, exist_ok=True)

    try:
        data = json.loads(path.read_text(encoding="utf-8")) if path.exists() else []
    except Exception:
        data = []

    item = {
        "time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "action": "quick_scan",
        "status": "ok",
        "message": "Hızlı tarama tamamlandı"
    }

    data.append(item)
    path.write_text(json.dumps(data[-300:], ensure_ascii=False, indent=2), encoding="utf-8")

    return jsonify({"ok": True, "message": "Hızlı tarama tamamlandı"})


@app.route("/api/full-scan")
def api_full_scan():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    import json, time
    from pathlib import Path

    path = Path("data/admin_actions.json")
    path.parent.mkdir(parents=True, exist_ok=True)

    try:
        data = json.loads(path.read_text(encoding="utf-8")) if path.exists() else []
    except Exception:
        data = []

    item = {
        "time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "action": "full_scan",
        "status": "ok",
        "message": "Tam tarama tamamlandı"
    }

    data.append(item)
    path.write_text(json.dumps(data[-300:], ensure_ascii=False, indent=2), encoding="utf-8")

    return jsonify({"ok": True, "message": "Tam tarama tamamlandı"})
# === ADMIN QUICK ACTIONS END ===




# === ADMIN REAL STATS START ===
@app.route("/api/admin-real-stats")
def api_admin_real_stats():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    import json
    from pathlib import Path

    log_file = Path("data/spam_logs.json")

    try:
        logs = json.loads(log_file.read_text(encoding="utf-8")) if log_file.exists() else []
    except Exception:
        logs = []

    total = len(logs)
    spam = sum(1 for x in logs if str(x.get("status", "")).upper() == "SPAM")
    ok = sum(1 for x in logs if str(x.get("status", "")).upper() == "OK")

    top = {}
    for x in logs:
        if str(x.get("status", "")).upper() == "SPAM":
            n = str(x.get("number", "Bilinmiyor"))
            top[n] = top.get(n, 0) + 1

    top_numbers = [
        {"number": k, "count": v}
        for k, v in sorted(top.items(), key=lambda item: item[1], reverse=True)[:5]
    ]

    return jsonify({
        "spam": spam,
        "calls": 0,
        "scans": total,
        "threats": spam,
        "ok": ok,
        "top_numbers": top_numbers
    })
# === ADMIN REAL STATS END ===




# === REAL SMS SCAN API START ===
@app.route("/api/run-sms-scan")
def api_run_sms_scan():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    import subprocess

    try:
        out = subprocess.check_output(
            ["python", "sms_ai_reader.py"],
            stderr=subprocess.STDOUT,
            timeout=20
        ).decode("utf-8", "ignore")

        return jsonify({
            "ok": True,
            "message": "SMS AI taraması tamamlandı",
            "output": out[-1200:]
        })
    except Exception as e:
        return jsonify({
            "ok": False,
            "message": "SMS taraması çalıştırılamadı",
            "error": str(e)
        })


@app.route("/api/run-full-sms-scan")
def api_run_full_sms_scan():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    import subprocess

    try:
        out = subprocess.check_output(
            ["python", "sms_ai_reader.py"],
            stderr=subprocess.STDOUT,
            timeout=25
        ).decode("utf-8", "ignore")

        return jsonify({
            "ok": True,
            "message": "Tam SMS AI taraması tamamlandı",
            "output": out[-1200:]
        })
    except Exception as e:
        return jsonify({
            "ok": False,
            "message": "Tam tarama çalıştırılamadı",
            "error": str(e)
        })
# === REAL SMS SCAN API END ===



@app.route("/api/client-alert")
def api_client_alert():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    import json, os
    path = "data/client_alert.json"
    if not os.path.exists(path):
        return {"id": 0, "type": "none", "title": "", "message": ""}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"id": 0, "type": "none", "title": "", "message": ""}
@app.route("/client")
def client_ui():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    return render_template("client_ui.html")



# ===== RADIAL FINAL ALIAS ROUTES =====
@app.route("/setting-radial-legacy-disabled")
def radial_alias_setting_legacy_disabled():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    return redirect("/settings")

@app.route("/alerts")
def radial_alias_alerts():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    return redirect("/notifications")

@app.route("/analytic")
@app.route("/analytics")
def radial_alias_analytics():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    return redirect("/analysis")

@app.route("/block-radial-legacy-disabled")
@app.route("/blocker-radial-legacy-disabled")
@app.route("/blocked-radial-legacy-disabled")
def radial_alias_blocked_legacy_disabled():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    return """
    <html><head><meta charset="UTF-8"><title>Engellenenler</title></head>
    <body style="background:#06122b;color:white;font-family:Arial;padding:24px;">
      <h2>🚫 Engellenenler</h2>
      <p>Engellenenler modülü hazırlık aşamasında.</p>
      <p><a href="/radial" style="color:#7dd3fc;">← Radial'e dön</a></p>
    </body></html>
    """

@app.route("/licence")
def radial_alias_licence():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    return redirect("/license")




# ===== ERATGUARD USER FINAL ROUTES =====
def ss_user_page(title, icon, text):
    return f"""
    <!doctype html>
    <html lang="tr">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>{title} - EratGuard</title>
      <style>
        body {{
          margin:0;
          background:#06122b;
          color:white;
          font-family:Arial,Helvetica,sans-serif;
          padding:24px;
        }}
        .card {{
          max-width:520px;
          margin:0 auto;
          background:rgba(255,255,255,.06);
          border:1px solid rgba(96,165,250,.25);
          border-radius:22px;
          padding:22px;
          box-shadow:0 0 35px rgba(59,130,246,.18);
        }}
        h1 {{font-size:28px;margin:0 0 12px}}
        p {{color:#cbd5e1;font-size:16px;line-height:1.55}}
        a {{
          display:inline-block;
          margin-top:18px;
          color:#7dd3fc;
          text-decoration:none;
          font-weight:bold;
        }}
      </style>
    </head>
    <body>
      <div class="card">
        <h1>{icon} {title}</h1>
        <p>{text}</p>
        <a href="/radial">← Radial menüye dön</a>
      </div>
    </body>
    </html>
    """

@app.route("/u/protection")
def ss_u_protection():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    return ss_user_page("Koruma", "🛡", "Koruma motoru kullanıcı tarafında aktif edilecek. SMS tarama, whitelist ve spam kontrol burada yönetilecek.")

@app.route("/u/analysis")
def user_analysis():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    return render_template("analysis.html")


@app.route("/u/blocked")
def ss_u_blocked():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    return ss_user_page("Engellenenler", "🚫", "Engellenen numaralar, mesajlar ve spam kayıtları bu ekranda listelenecek.")


@app.route("/u/notifications")
def ss_u_notifications():
    return render_template("alerts.html")

@app.route("/u/settings")
def ss_u_settings():
    return render_template("settings_page.html")

@app.route("/u/reports")
def ss_u_reports():
    return render_template("reports.html")

@app.route("/u/license")
def ss_u_license():
    state = _get_license_state_hardcore()
    if state.get("premium"):
        return render_template(
            "license.html",
            premium=True,
            is_premium=True,
            license_status="premium",
            license_code=state.get("code"),
            plan=state.get("plan", "pro"),
            days_left=state.get("days_left", 365),
        )

    return render_template(
        "license.html",
        premium=False,
        is_premium=False,
        license_status="trial",
        license_code=None,
        plan="trial",
        days_left=state.get("days_left", 5),
    )

@app.route("/u/pricing")
def ss_u_pricing():
    return render_template("pricing.html")

@app.route("/u/activate")
def ss_u_activate():
    return redirect("/activate-license")

@app.route("/u/checkout", methods=["GET", "POST"])
def ss_u_checkout():
    from flask import request, render_template, redirect, session
    import json, secrets
    from pathlib import Path
    from datetime import datetime, timedelta

    plans = {
        "starter_monthly": {"name": "Starter Shield", "price": "150 TL", "days": 30},
        "pro_yearly": {"name": "Shield Pro+", "price": "1000 TL", "days": 365},
        "lifetime": {"name": "Lifetime Shield", "price": "2000 TL", "days": 3650},
    }

    plan_id = request.values.get("plan", "starter_monthly")
    plan = plans.get(plan_id, plans["starter_monthly"])

    if request.method == "POST":
        Path("data").mkdir(exist_ok=True)

        users_path = Path("data/users.json")
        licenses_path = Path("data/licenses.json")

        users = json.loads(users_path.read_text(encoding="utf-8"))
        try:
            licenses = json.loads(licenses_path.read_text(encoding="utf-8"))
        except Exception:
            licenses = {}

        username = session.get("username") or session.get("user") or "admin"
        user = users.get(username) or users.get("admin") or {}

        key = "ERATGUARD-PRO-" + secrets.token_hex(3).upper()
        expiry = (datetime.now() + timedelta(days=plan["days"])).strftime("%Y-%m-%d")

        licenses[key] = {
            "key": key,
            "plan": plan_id,
            "type": "pro",
            "days": plan["days"],
            "expiry": expiry,
            "used": True,
            "used_by": username,
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "source": "hardcore_test_payment"
        }

        user["license_type"] = "pro"
        user["license_mode"] = "pro"
        user["license_key"] = key
        user["license_expiry"] = expiry
        users[username] = user

        users_path.write_text(json.dumps(users, ensure_ascii=False, indent=2), encoding="utf-8")
        licenses_path.write_text(json.dumps(licenses, ensure_ascii=False, indent=2), encoding="utf-8")

        return redirect("/u/payment-success?key=" + key)

    return render_template("checkout.html", plan_id=plan_id, plan=plan)

@app.route("/u/payment-success-legacy-disabled", methods=["GET"])
def ss_u_payment_success_legacy_disabled():
    from flask import redirect
    return redirect("/u/payment-success")



# ===== ERATGUARD U PREFIX CATCH FIX =====

# ===== ERATGUARD LEGAL CONTRACT ROUTES LIVE START =====
@app.route("/u/terms", endpoint="ss_terms_page_live")
def ss_terms_page_live():
    return render_template("terms.html")

@app.route("/u/privacy", endpoint="ss_privacy_page_live")
def ss_privacy_page_live():
    return render_template("privacy.html")

@app.route("/u/refund", endpoint="ss_refund_page_live")
def ss_refund_page_live():
    return render_template("refund.html")
# ===== ERATGUARD LEGAL CONTRACT ROUTES LIVE END =====

@app.route("/u/<path:slug>")
def ss_u_prefix_catch(slug):
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    s = (slug or "").lower().strip("/")

    if s.startswith("notifi") or s.startswith("alert"):
        return redirect("/u/notifications")

    if s.startswith("block") or s.startswith("blo"):
        return redirect("/u/blocked")

    if s.startswith("analy") or s.startswith("analyt"):
        return redirect("/u/analysis")

    if s.startswith("comm") or s.startswith("topl"):
        return redirect("/u/community")

    if s.startswith("licens") or s.startswith("licen") or s.startswith("lisans"):
        return redirect("/u/license")

    if s.startswith("repor") or s.startswith("rapor"):
        return redirect("/u/reports")

    if s.startswith("setti") or s.startswith("settir") or s.startswith("ayar"):
        return redirect("/u/settings")

    return redirect("/radial")




# ===== RADIAL DASH TYPO CATCH =====
@app.route("/radial-<path:anything>")
def ss_radial_dash_catch(anything):
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    return redirect("/radial")


@app.route("/u/community", endpoint="community_page_final")
def community_page_final():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    return render_template("community.html")


@app.route("/api/community-data", endpoint="api_community_data_final")
def api_community_data_final():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    import json
    from flask import Response

    data = {
        "active": True,
        "alert": "Yeni dolandırıcılık kampanyası tespit edildi!",
        "alert_text": "Banka hesabınız askıya alındı, doğrulamak için tıklayın.",
        "stats": {"today": 35, "shared": 24710, "trust": 92, "users": 2341},
        "feed": [
            {"type":"Dolandırıcılık","phone":"+905xx xxx 45 67","message":"Banka hesabınız askıya alındı.","risk":96,"reports":14,"time":"2 dk önce"},
            {"type":"Reklam","phone":"+905xx xxx 12 34","message":"%80 indirim fırsatı.","risk":78,"reports":8,"time":"5 dk önce"},
            {"type":"Sahte Banka","phone":"+905xx xxx 98 76","message":"Hesabınız kapatılacak.","risk":94,"reports":21,"time":"7 dk önce"}
        ],
        "types": {"Reklam": 9, "Dolandırıcılık": 8, "Sahte Banka": 3},
        "regions": [["İstanbul",45],["Ankara",18],["İzmir",12]],
        "contributors": [["Anonim #A92",1248],["Anonim #X7B",842]],
        "trend_labels": ["00:00","06:00","12:00","18:00","24:00"],
        "trend_values": [18,32,28,44,58]
    }

    return Response(json.dumps(data, ensure_ascii=False), content_type="application/json; charset=utf-8")



# ============================================================
# FINAL HARDCORE PREMIUM OVERRIDE - MUST RUN BEFORE app.run
# ============================================================
import json as _ss_json
from pathlib import Path as _ss_Path
from datetime import datetime as _ss_dt, timedelta as _ss_td

_SS_USERS = _ss_Path("data/users.json")
_SS_LICENSES = _ss_Path("data/licenses.json")

def _ss_load(path, default):
    try:
        if path.exists():
            return _ss_json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        pass
    return default

def _ss_save(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_ss_json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

def _ss_user():
    try:
        return session.get("username") or session.get("user") or session.get("email") or "demo"
    except Exception:
        return "demo"

def _ss_make_code(username):
    import hashlib
    raw = f"{username}-{_ss_dt.now().isoformat()}-ERATGUARD-PRO"
    return "ERATGUARD-PRO-" + hashlib.sha1(raw.encode()).hexdigest()[:6].upper()

def _ss_activate(username=None, plan="pro"):
    username = username or _ss_user()
    now = _ss_dt.now()
    code = _ss_make_code(username)

    try:
        session["premium"] = True
        session["is_premium"] = True
        session["license_status"] = "premium"
        session["license_code"] = code
        session["plan"] = plan
    except Exception:
        pass

    users = _ss_load(_SS_USERS, {})
    if not isinstance(users, dict):
        users = {}

    u = users.get(username, {})
    if not isinstance(u, dict):
        u = {}

    u.update({
        "premium": True,
        "is_premium": True,
        "license_status": "premium",
        "license_code": code,
        "plan": plan,
        "premium_started_at": now.isoformat(),
        "premium_expires_at": (now + _ss_td(days=365)).isoformat()
    })
    users[username] = u
    _ss_save(_SS_USERS, users)

    licenses = _ss_load(_SS_LICENSES, {})
    if not isinstance(licenses, dict):
        licenses = {}

    licenses[code] = {
        "username": username,
        "code": code,
        "status": "active",
        "plan": plan,
        "premium": True,
        "created_at": now.isoformat(),
        "expires_at": (now + _ss_td(days=365)).isoformat()
    }
    _ss_save(_SS_LICENSES, licenses)

    return code

def _ss_state():
    username = _ss_user()

    try:
        if session.get("premium") or session.get("is_premium") or session.get("license_status") == "premium":
            return True, session.get("license_code") or "ERATGUARD-PRO"
    except Exception:
        pass

    users = _ss_load(_SS_USERS, {})
    u = {}
    if isinstance(users, dict):
        u = users.get(username, {}) or {}

    if isinstance(u, dict) and (
        u.get("premium") or u.get("is_premium") or u.get("license_status") == "premium"
    ):
        try:
            session["premium"] = True
            session["is_premium"] = True
            session["license_status"] = "premium"
            session["license_code"] = u.get("license_code", "ERATGUARD-PRO")
            session["plan"] = u.get("plan", "pro")
        except Exception:
            pass
        return True, u.get("license_code", "ERATGUARD-PRO")

    return False, None

def _ss_license_page_override():
    premium, code = _ss_state()
    return render_template(
        "license.html",
        premium=premium,
        is_premium=premium,
        license_status="premium" if premium else "trial",
        license_code=code,
        plan="pro" if premium else "trial",
        days_left=365 if premium else 5,
    )

def _ss_payment_success_override():
    code = _ss_activate(plan=request.args.get("plan", "starter_monthly"))
    return render_template("payment_success.html", license_code=code)

def _ss_test_payment_complete_override():
    _ss_activate(plan=request.args.get("plan", "starter_monthly"))
    return redirect("/u/payment-success")

# Mevcut route endpointlerini URL üzerinden bul ve zorla değiştir
try:
    for _rule in list(app.url_map.iter_rules()):
        if str(_rule.rule) == "/u/license":
            app.view_functions[_rule.endpoint] = _ss_license_page_override

        if str(_rule.rule) in ["/u/payment_success", "/u/payment-complete"]:
            app.view_functions[_rule.endpoint] = _ss_payment_success_override

        # Disabled: /u/test-payment-complete is owned by user_test_payment_complete_hardcore below.
except Exception as e:
    print("Premium override route scan error:", e)

# Eksik route varsa ekle
try:
    # Disabled: /u/payment-success is owned by ss_manual_payment_success below.
    # Old ss_payment_success_added auto-activation route intentionally not registered.
    # Disabled: old ss_test_payment_complete_added route intentionally not registered.
    pass
except Exception as e:
    print("Premium override add route error:", e)
# ============================================================



# ============================================================
# DIRECT PREMIUM ACTIVATOR - GET SAFE
# ============================================================
@app.route("/u/activate-pro-now", methods=["GET", "POST"])
def activate_pro_now_direct():
    import json, hashlib
    from pathlib import Path
    from datetime import datetime, timedelta

    username = (
        session.get("username")
        or session.get("user")
        or session.get("email")
        or "demo"
    )

    now = datetime.now()
    code = "ERATGUARD-PRO-" + hashlib.sha1(
        f"{username}-{now.isoformat()}".encode()
    ).hexdigest()[:6].upper()

    session["premium"] = True
    session["is_premium"] = True
    session["license_status"] = "premium"
    session["license_code"] = code
    session["plan"] = "pro"

    data_dir = Path("data")
    data_dir.mkdir(exist_ok=True)

    users_file = data_dir / "users.json"
    try:
        users = json.loads(users_file.read_text(encoding="utf-8")) if users_file.exists() else {}
    except Exception:
        users = {}

    if not isinstance(users, dict):
        users = {}

    user_obj = users.get(username, {})
    if not isinstance(user_obj, dict):
        user_obj = {}

    user_obj.update({
        "premium": True,
        "is_premium": True,
        "license_status": "premium",
        "license_code": code,
        "plan": "pro",
        "premium_started_at": now.isoformat(),
        "premium_expires_at": (now + timedelta(days=365)).isoformat()
    })

    users[username] = user_obj
    users_file.write_text(json.dumps(users, ensure_ascii=False, indent=2), encoding="utf-8")

    licenses_file = data_dir / "licenses.json"
    try:
        licenses = json.loads(licenses_file.read_text(encoding="utf-8")) if licenses_file.exists() else {}
    except Exception:
        licenses = {}

    if not isinstance(licenses, dict):
        licenses = {}

    licenses[code] = {
        "username": username,
        "code": code,
        "status": "active",
        "premium": True,
        "plan": "pro",
        "created_at": now.isoformat(),
        "expires_at": (now + timedelta(days=365)).isoformat()
    }

    licenses_file.write_text(json.dumps(licenses, ensure_ascii=False, indent=2), encoding="utf-8")

    return redirect("/u/payment-success")
# ============================================================



# ============================================================
# SHIELD PRO REDEEM ROUTE - LOCKED LICENSE COMPANION
# ============================================================
@app.route("/u/redeem", methods=["GET", "POST"])
def shield_pro_redeem_page():
    if request.method == "POST":
        code = (request.form.get("license_code") or "").strip().upper()
        if code.startswith("ERATGUARD-PRO"):
            try:
                session["premium"] = True
                session["is_premium"] = True
                session["license_status"] = "premium"
                session["license_code"] = code
                session["plan"] = "pro"
            except Exception:
                pass
            return redirect("/u/license")
    return render_template("redeem.html")
# ============================================================



# ============================================================
# FORCE BLOCKED CENTER OVERRIDE - MUST RUN BEFORE app.run
# ============================================================
def _ss_blocked_center_force():
    return render_template("blocked.html")

try:
    for _rule in list(app.url_map.iter_rules()):
        if str(_rule.rule) in ["/u/blocked", "/blocked", "/block", "/blocker"]:
            app.view_functions[_rule.endpoint] = _ss_blocked_center_force
except Exception as e:
    print("Blocked force override route scan error:", e)
# ============================================================



# ============================================================
# FORCE SETTINGS CENTER OVERRIDE - MUST RUN BEFORE app.run
# ============================================================
def _ss_settings_center_force():
    return render_template("settings_page.html")

try:
    for _rule in list(app.url_map.iter_rules()):
        if str(_rule.rule) in ["/u/settings", "/settings"]:
            app.view_functions[_rule.endpoint] = _ss_settings_center_force
except Exception as e:
    print("Settings force override route scan error:", e)
# ============================================================



# ============================================================
# FORCE NOTIFICATION CENTER OVERRIDE - MUST RUN BEFORE app.run
# ============================================================
def _ss_notification_center_force():
    return render_template("alerts.html")

try:
    for _rule in list(app.url_map.iter_rules()):
        if str(_rule.rule) in ["/u/notifications", "/notifications", "/alerts"]:
            app.view_functions[_rule.endpoint] = _ss_notification_center_force
except Exception as e:
    print("Notification force override route scan error:", e)
# ============================================================



# ============================================================
# FORCE PROTECTION CENTER OVERRIDE - MUST RUN BEFORE app.run
# ============================================================
def _ss_protection_center_force():
    return render_template("protection.html")

try:
    for _rule in list(app.url_map.iter_rules()):
        if str(_rule.rule) in ["/u/protection", "/protection"]:
            app.view_functions[_rule.endpoint] = _ss_protection_center_force
except Exception as e:
    print("Protection force override route scan error:", e)
# ============================================================



@app.route("/u/legal")
def ss_legal_notice():
    return render_template("legal_notice.html")


# ===== ERATGUARD IYZICO PAYMENT ROUTE START =====
@app.route("/u/pay")
def ss_iyzico_pay():
    plan = request.args.get("plan", "starter_monthly").strip()
    link = PAYMENT_LINKS.get(plan, "")
    label = PLAN_LABELS.get(plan, "EratGuard PRO")
    price = PLAN_PRICES.get(plan, "")

    payment_ready = bool(link) and not link.startswith("PASTE_")

    if not payment_ready:
        return render_template(
            "checkout.html",
            plan=plan,
            plan_label=label,
            plan_price=price,
            payment_provider=PAYMENT_PROVIDER,
            payment_ready=False,
            payment_link="",
            message="iyzico ödeme linki onay süreci tamamlanınca aktif edilecek."
        )

    return redirect(link)
# ===== ERATGUARD IYZICO PAYMENT ROUTE END =====



# ===== ERATGUARD MANUAL LICENSE ACTIVATION START =====
def ss_payment_request_store_path():
    from pathlib import Path
    data_dir = Path("data")
    data_dir.mkdir(exist_ok=True)
    return data_dir / "payment_requests.json"


def ss_load_payment_requests():
    path = ss_payment_request_store_path()
    if not path.exists():
        return []
    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except Exception:
        return []


def ss_save_payment_request(item):
    data = ss_load_payment_requests()
    data.append(item)
    path = ss_payment_request_store_path()
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def ss_current_username():
    for key in ("username", "user", "logged_in_user"):
        val = session.get(key)
        if val:
            return str(val)
    return "Giriş yapan kullanıcı"


@app.route("/u/payment-success", methods=["GET", "POST"])
def ss_manual_payment_success():
    plan = request.values.get("plan", "starter_monthly").strip()

    label = PLAN_LABELS.get(plan, "EratGuard PRO")
    price = PLAN_PRICES.get(plan, "")
    username = ss_current_username()

    saved = False

    if request.method == "POST":
        try:
            item = {
                "created_at": datetime.now().isoformat(timespec="seconds"),
                "username": username,
                "plan": plan,
                "plan_label": label,
                "plan_price": price,
                "provider": PAYMENT_PROVIDER,
                "status": "pending_manual_review",
                "note": "Kullanıcı ödeme sonrası manuel lisans aktivasyon talebi oluşturdu."
            }
            ss_save_payment_request(item)
            saved = True
        except Exception:
            saved = False

    return render_template(
        "payment_success.html",
        saved=saved,
        username=username,
        plan=plan,
        plan_label=label,
        plan_price=price
    )
# ===== ERATGUARD MANUAL LICENSE ACTIVATION END =====



# ===== ERATGUARD PAYMENT REQUEST POST FIX START =====
@app.route("/u/payment-request", methods=["POST"])
def ss_payment_request_post():
    plan = request.form.get("plan", "starter_monthly").strip()

    label = PLAN_LABELS.get(plan, "EratGuard PRO")
    price = PLAN_PRICES.get(plan, "")

    username = "Giriş yapan kullanıcı"
    try:
        for key in ("username", "user", "logged_in_user"):
            val = session.get(key)
            if val:
                username = str(val)
                break
    except Exception:
        pass

    try:
        from pathlib import Path
        data_dir = Path("data")
        data_dir.mkdir(exist_ok=True)
        path = data_dir / "payment_requests.json"

        if path.exists():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                if not isinstance(data, list):
                    data = []
            except Exception:
                data = []
        else:
            data = []

        data.append({
            "created_at": datetime.now().isoformat(timespec="seconds"),
            "username": username,
            "plan": plan,
            "plan_label": label,
            "plan_price": price,
            "provider": PAYMENT_PROVIDER,
            "status": "pending_manual_review",
            "note": "Kullanıcı ödeme sonrası manuel lisans aktivasyon talebi oluşturdu."
        })

        path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        saved = True
    except Exception:
        saved = False

    return render_template(
        "payment_success.html",
        saved=saved,
        username=username,
        plan=plan,
        plan_label=label,
        plan_price=price
    )
# ===== ERATGUARD PAYMENT REQUEST POST FIX END =====



# ===== ERATGUARD ACTIVATE LICENSE REQUEST START =====
@app.route("/u/activate-license-request", methods=["POST"])
def ss_activate_license_request():
    plan = request.form.get("plan", "starter_monthly").strip()

    label = PLAN_LABELS.get(plan, "EratGuard PRO")
    price = PLAN_PRICES.get(plan, "")

    username = "Giriş yapan kullanıcı"
    try:
        for key in ("username", "user", "logged_in_user"):
            val = session.get(key)
            if val:
                username = str(val)
                break
    except Exception:
        pass

    saved = False

    try:
        from pathlib import Path
        data_dir = Path("data")
        data_dir.mkdir(exist_ok=True)
        path = data_dir / "payment_requests.json"

        if path.exists():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                if not isinstance(data, list):
                    data = []
            except Exception:
                data = []
        else:
            data = []

        data.append({
            "created_at": datetime.now().isoformat(timespec="seconds"),
            "username": username,
            "plan": plan,
            "plan_label": label,
            "plan_price": price,
            "provider": PAYMENT_PROVIDER,
            "status": "pending_manual_review",
            "note": "Kullanıcı ödeme sonrası manuel lisans aktivasyon talebi oluşturdu."
        })

        path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        saved = True
    except Exception:
        saved = False

    return render_template(
        "payment_success.html",
        saved=saved,
        username=username,
        plan=plan,
        plan_label=label,
        plan_price=price
    )
# ===== ERATGUARD ACTIVATE LICENSE REQUEST END =====



# ===== ERATGUARD SECURITY LEVEL 2 START =====
_SS_PAYMENT_REQUEST_ATTEMPTS = {}

def _ss_same_origin_post_ok():
    """
    Basit CSRF benzeri koruma:
    Admin/lisans POST istekleri başka domainlerden gelmesin.
    Mobil/local kullanım bozulmasın diye Origin/Referer yoksa izin veriyoruz.
    """
    if request.method != "POST":
        return True

    origin = request.headers.get("Origin", "")
    referer = request.headers.get("Referer", "")
    host = request.host_url.rstrip("/")

    if origin and not origin.startswith(host):
        return False
    if referer and not referer.startswith(host):
        return False
    return True


def _ss_rate_limit_bucket(name, limit=5, window=600):
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "local")
    ip = str(ip).split(",")[0].strip()
    key = f"{name}:{ip}"
    now = _ss_time.time()
    bucket = [t for t in _SS_PAYMENT_REQUEST_ATTEMPTS.get(key, []) if now - t < window]
    if len(bucket) >= limit:
        _SS_PAYMENT_REQUEST_ATTEMPTS[key] = bucket
        return False
    bucket.append(now)
    _SS_PAYMENT_REQUEST_ATTEMPTS[key] = bucket
    return True


@app.before_request
def ss_security_level2_gatekeeper():
    path = request.path or ""

    # Demo/test/backdoor gibi davranabilecek yolları admin dışında kapat
    admin_only_paths = (
        "/u/activate-pro-now",
        "/orders",
        "/bot-orders",
    )

    if path.startswith(admin_only_paths):
        if not _ss_is_logged_in():
            return redirect("/login")
        if not _ss_is_admin_session():
            abort(403)

    # Admin ve lisans/ödeme POST işlemleri için same-origin kontrol
    sensitive_post_prefixes = (
        "/admin",
        "/orders",
        "/bot-orders",
        "/u/activate-license-request",
        "/u/payment-request",
        "/u/redeem",
        "/u/activate",
    )

    if request.method == "POST" and path.startswith(sensitive_post_prefixes):
        if not _ss_same_origin_post_ok():
            return "Forbidden", 403

    # Kullanıcı aktivasyon talebi spam koruması
    if path == "/u/activate-license-request" and request.method == "POST":
        if not _ss_rate_limit_bucket("activate_license_request", limit=5, window=600):
            return "Çok fazla aktivasyon talebi. Lütfen birkaç dakika sonra tekrar deneyin.", 429

# ===== ERATGUARD SECURITY LEVEL 2 END =====



# ===== ERATGUARD SECURITY LEVEL 3 START =====
# Level 3: production lockdown, stronger admin validation, duplicate payment request guard.

# Büyük kötü niyetli POST/upload denemelerini sınırlıyoruz.
# Normal login/form/ödeme talebi için fazlasıyla yeterli.
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024

_SS_PRODUCTION_LOCKDOWN = os.environ.get("ERATGUARD_PRODUCTION_LOCKDOWN", "1") == "1"


def _ss_load_users_for_security():
    try:
        path = _ss_Path("data/users.json")
        if not path.exists():
            return {}
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


# Level 1/2'deki admin kontrolünü daha sıkı hale getiriyoruz.
# Artık sadece session'da username=admin demek yetmez; data/users.json içinde role=admin aranır.
def _ss_is_admin_session():
    if not _ss_is_logged_in():
        return False

    username = str(session.get("username") or session.get("user") or "").strip()
    if not username:
        return False

    users = _ss_load_users_for_security()
    user = users.get(username, {}) if isinstance(users, dict) else {}

    role = str(user.get("role", "")).strip().lower()
    if role == "admin":
        return True

    # Eski sistem bazı yerlerde session role tutuyor olabilir.
    # Ama sadece username=admin yetmesin; en azından session role/admin flag de olmalı.
    if username == "admin" and (session.get("role") == "admin" or session.get("is_admin")):
        return True

    return False


def _ss_duplicate_payment_request_exists(username, plan, window_seconds=3600):
    try:
        path = _ss_Path("data/payment_requests.json")
        if not path.exists():
            return False

        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, list):
            return False

        now = _ss_time.time()

        for item in reversed(data[-80:]):
            if not isinstance(item, dict):
                continue
            if str(item.get("username")) != str(username):
                continue
            if str(item.get("plan")) != str(plan):
                continue
            if str(item.get("status")) not in ("pending_manual_review", "pending"):
                continue

            created = str(item.get("created_at", ""))
            try:
                from datetime import datetime as _ss_dt
                ts = _ss_dt.fromisoformat(created).timestamp()
                if now - ts < window_seconds:
                    return True
            except Exception:
                # Tarih okunamazsa güvenli tarafta kal.
                return True

        return False
    except Exception:
        return False


@app.before_request
def ss_security_level3_gatekeeper():
    path = request.path or ""

    # Üretim modunda eski demo/test/arka-kapı gibi kullanılabilecek yolları tamamen kapat.
    # Gerekirse sadece lokal geliştirme için:
    # export ERATGUARD_PRODUCTION_LOCKDOWN=0
    hard_block_paths = (
        "/u/activate-pro-now",
        "/orders",
        "/bot-orders",
        "/orders/give-license",
        "/bot-orders/give-license",
    )

    if _SS_PRODUCTION_LOCKDOWN and path.startswith(hard_block_paths):
        return "Not Found", 404

    # Hassas admin işlemlerinde admin değilse 403/redirect.
    high_risk_admin_prefixes = (
        "/admin/create-paid-license",
        "/admin/approve-payment",
        "/admin/generate-license",
        "/admin/approve-upgrade",
        "/admin/update-license",
        "/admin/toggle-ban",
        "/admin/add-user",
        "/delete-user",
        "/manage-license",
    )

    if path.startswith(high_risk_admin_prefixes):
        if not _ss_is_logged_in():
            return redirect("/login")
        if not _ss_is_admin_session():
            return "Forbidden", 403

    # Aktivasyon talebi için aynı kullanıcı + aynı paket tekrarını 1 saat engelle.
    if path == "/u/activate-license-request" and request.method == "POST":
        try:
            username = str(session.get("username") or session.get("user") or "Giriş yapan kullanıcı")
            plan = str(request.form.get("plan", "starter_monthly")).strip()
            if _ss_duplicate_payment_request_exists(username, plan, window_seconds=3600):
                return "Bu paket için bekleyen aktivasyon talebiniz zaten var.", 429
        except Exception:
            pass


@app.after_request
def ss_security_level3_headers(response):
    path = request.path or ""

    # Admin, ödeme ve lisans sayfaları tarayıcı/cache içinde tutulmasın.
    no_store_prefixes = (
        "/admin",
        "/u/pay",
        "/u/payment-success",
        "/u/activate-license-request",
        "/u/license",
        "/u/redeem",
        "/u/checkout",
        "/license",
        "/my-license",
    )

    if path.startswith(no_store_prefixes):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"

    # Basit fingerprint azaltma
    response.headers.pop("Server", None)

    return response
# ===== ERATGUARD SECURITY LEVEL 3 END =====



# ===== ERATGUARD SECURITY LEVEL 4 START =====
# Level 4: API lockdown + backup/source probing protection.

def _ss_is_local_request():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "")
    ip = str(ip).split(",")[0].strip()

    if ip in ("127.0.0.1", "::1", "localhost"):
        return True
    if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172."):
        return True
    return False


@app.before_request
def ss_security_level4_gatekeeper():
    path = request.path or ""
    low = path.lower()

    # Kaynak kod / backup / runtime dosya avcılığını yokmuş gibi göster.
    blocked_fragments = (
        ".bak",
        ".backup",
        ".broken",
        ".corrupted",
        ".save",
        ".working",
        ".tar.gz",
        ".sha256",
        "__pycache__",
        "backup",
        "locked_",
        "final_lock",
        "release_lock",
        "security_audit",
    )

    blocked_suffixes = (
        ".py",
        ".db",
        ".sqlite",
        ".json",
        ".env",
        ".log",
        ".pid",
        ".pkl",
    )

    if any(x in low for x in blocked_fragments) or low.endswith(blocked_suffixes):
        # API JSON dosya uzantısı gibi gerçek route yok; dosya avcılığını engeller.
        if not low.startswith("/api/"):
            return "Not Found", 404

    # Hassas API endpointleri: admin veya lokal istek dışında kapalı.
    high_risk_api_prefixes = (
        "/api/system-resources",
        "/api/start-scan",
        "/api/full-scan",
        "/api/admin-real-stats",
        "/api/run-sms-scan",
        "/api/run-full-sms-scan",
        "/api/client-alert",
    )

    if path.startswith(high_risk_api_prefixes):
        if _ss_is_local_request():
            return None
        if not _ss_is_logged_in():
            return redirect("/login")
        if not _ss_is_admin_session():
            return "Forbidden", 403

    # API POST isteklerinde dış origin engeli.
    if path.startswith("/api/") and request.method == "POST":
        if not _ss_same_origin_post_ok():
            return "Forbidden", 403

    return None


@app.after_request
def ss_security_level4_headers(response):
    path = request.path or ""

    if path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"

    return response
# ===== ERATGUARD SECURITY LEVEL 4 END =====



# ===== ERATGUARD LEGAL CONTRACT ROUTES START =====
@app.route("/u/terms-legacy-disabled")
def ss_terms_page_legacy_disabled():
    return render_template("terms.html")

@app.route("/u/privacy-legacy-disabled")
def ss_privacy_page_legacy_disabled():
    return render_template("privacy.html")

@app.route("/u/refund-legacy-disabled")
def ss_refund_page_legacy_disabled():
    return render_template("refund.html")
# ===== ERATGUARD LEGAL CONTRACT ROUTES END =====


# -----------------------
# PASSWORD RESET
# -----------------------


# =========================
# ✅ ADMIN ONAY
# =========================
@app.route("/admin/approve-payment/<username>/<license_key>")
def approve_payment(username, license_key):
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    users = load_users()

    for p in users[username].get("pending_payments", []):
        if p["license_key"] == license_key:
            p["status"] = "approved"
            users[username]["license_key"] = license_key
            users[username]["license_type"] = "pro"

    save_users(users)
    return redirect(url_for("admin_payment_requests"))


# =========================
# 🔑 LİSANS AKTİVASYON
# =========================


# =========================
# 📊 ERATGUARD ADMIN OVERVIEW + LOGS
# =========================
# =========================
# 📊 SPAM LOGS + ADMIN ROUTES
# =========================

@app.route("/admin/whitelist-legacy", methods=["GET","POST"])
def admin_whitelist_legacy():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    if not login_required():
        return redirect(url_for("login"))

    whitelist = load_whitelist()

    if request.method == "POST":
        number = request.form.get("number","").strip()
        if number and number not in whitelist:
            whitelist.append(number)
            save_whitelist(whitelist)

    return render_template("whitelist.html", whitelist=whitelist)



    if not login_required():
        return redirect(url_for("login"))
    return redirect("/radial")









@app.route("/license-legacy-disabled")
def license_page_2_legacy_disabled():
    return redirect("/u/license")

def protection_page_2_disabled():
    return "<h2>Protection (yakında)</h2>"

@app.route("/analyze")
def analyze_page():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    return "<h2>Analyze (yakında)</h2>"

def blocked_page_2_disabled():
    return "<h2>Blocked (yakında)</h2>"

def notifications_page_2_disabled():
    return "<h2>Notifications (yakında)</h2>"

def reports_page_2_disabled():
    return "<h2>Reports (yakında)</h2>"

def settings_page_2_disabled():
    return "<h2>Settings (yakında)</h2>"

def community_page_2_disabled():
    return "<h2>Community (yakında)</h2>"

@app.route("/simple-page-preview-fallback")
def simple_page_preview_fallback():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    return render_template(
        "simple_page.html",
        page_title="Sayfa",
        page_desc="Bu alan daha sonra gerçek içerikle güncellenecek."
    )


# === ERATGUARD LICENSE CORE V1 ===
PRICE_MONTHLY_TRY = 199
PRICE_YEARLY_EUR = 100
PRICE_YEARLY_TRY = 3999
TRIAL_PRO_DAYS = 3

def _ss_now():
    from datetime import datetime
    return datetime.now()

def _ss_fmt(dt_obj):
    return dt_obj.strftime("%Y-%m-%d")

def _ss_parse(date_str):
    from datetime import datetime
    try:
        return datetime.strptime(str(date_str), "%Y-%m-%d")
    except Exception:
        return None

def _ss_load_json(path, default):
    import json
    from pathlib import Path
    p = Path(path)
    if not p.exists():
        return default
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return default

def _ss_save_json(path, data):
    import json
    from pathlib import Path
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

def _ss_ensure_first_pro(username):
    users = _ss_load_json("data/users.json", {})
    if not isinstance(users, dict) or username not in users:
        return

    user = users.get(username, {}) or {}
    role = str(user.get("role", "")).strip().lower()
    if role == "admin" or username == "admin":
        return

    current_type = str(user.get("license_type") or "").strip().lower()
    expiry = str(user.get("license_expiry") or "").strip()

    if not current_type and not expiry:
        from datetime import timedelta
        exp = _ss_now() + timedelta(days=TRIAL_PRO_DAYS)
        user["license_type"] = "pro"
        user["license_mode"] = "pro"
        user["license_expiry"] = _ss_fmt(exp)
        user["trial_bootstrap"] = True
        users[username] = user
        _ss_save_json("data/users.json", users)

def _ss_auto_downgrade_if_expired(username):
    users = _ss_load_json("data/users.json", {})
    if not isinstance(users, dict) or username not in users:
        return

    user = users.get(username, {}) or {}
    role = str(user.get("role", "")).strip().lower()
    if role == "admin" or username == "admin":
        return

    lic_type = str(user.get("license_type") or "trial").strip().lower()
    expiry = str(user.get("license_expiry") or "").strip()

    if not expiry:
        return

    expiry_dt = _ss_parse(expiry)
    if not expiry_dt:
        return

    if _ss_now().date() > expiry_dt.date():
        user["license_type"] = "trial"
        user["license_mode"] = "trial"
        user["license_key"] = ""
        users[username] = user
        _ss_save_json("data/users.json", users)

def _ss_activate_license(username, license_key):
    from datetime import timedelta

    users = _ss_load_json("data/users.json", {})
    licenses = _ss_load_json("data/licenses.json", {})

    if not isinstance(users, dict) or username not in users:
        return False, "Kullanıcı bulunamadı"

    key = str(license_key or "").strip()
    if not key:
        return False, "Lisans kodu boş"

    lic = licenses.get(key)
    if not isinstance(lic, dict):
        return False, "Lisans bulunamadı"

    if bool(lic.get("used", False)):
        return False, "Bu lisans daha önce kullanılmış"

    if not bool(lic.get("paid", False)):
        return False, "Ödeme onayı olmadan lisans kullanılamaz"

    duration_days = int(lic.get("duration_days", 365))
    exp = _ss_now() + timedelta(days=duration_days)

    user = users.get(username, {}) or {}
    user["license_type"] = "pro"
    user["license_mode"] = "pro"
    user["license_expiry"] = _ss_fmt(exp)
    user["license_key"] = key
    users[username] = user

    lic["used"] = True
    lic["used_by"] = username
    lic["used_at"] = _ss_fmt(_ss_now())
    licenses[key] = lic

    _ss_save_json("data/users.json", users)
    _ss_save_json("data/licenses.json", licenses)

    return True, f"Lisans aktif. Bitiş: {user['license_expiry']}"

def _ss_generate_key():
    import secrets
    part1 = secrets.token_hex(3).upper()
    part2 = secrets.token_hex(3).upper()
    part3 = secrets.token_hex(3).upper()
    return f"SS-{part1}-{part2}-{part3}"

@app.before_request
def _ss_license_tick():
    from flask import session
    username = session.get("username") or session.get("user")
    if not username:
        return
    try:
        _ss_ensure_first_pro(username)
        _ss_auto_downgrade_if_expired(username)
    except Exception:
        pass

@app.route("/admin/create-paid-license/<username>/<plan>", methods=["GET"])
def admin_create_paid_license(username, plan):
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    if not login_required():
        return redirect(url_for("login"))
    if not admin_required():
        return redirect("/radial")

    plan = str(plan or "").strip().lower()
    if plan not in {"month", "year"}:
        return "Geçersiz plan", 400

    licenses = _ss_load_json("data/licenses.json", {})

    key = _ss_generate_key()
    duration_days = 30 if plan == "month" else 365
    price_try = PRICE_MONTHLY_TRY if plan == "month" else PRICE_YEARLY_TRY
    price_eur = None if plan == "month" else PRICE_YEARLY_EUR

    licenses[key] = {
        "username": username,
        "plan": "pro",
        "duration_days": duration_days,
        "paid": True,
        "used": False,
        "created_at": _ss_fmt(_ss_now()),
        "price_try": price_try,
        "price_eur": price_eur
    }

    _ss_save_json("data/licenses.json", licenses)
    return redirect("/admin/licenses")

@app.route("/my-license", methods=["GET", "POST"])
def my_license():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    if not login_required():
        return redirect(url_for("login"))

    from flask import session
    username = session.get("username") or session.get("user")
    msg = ""
    ok = False

    if request.method == "POST":
        code = request.form.get("license_key", "").strip()
        ok, msg = _ss_activate_license(username, code)

    users = _ss_load_json("data/users.json", {})
    user = users.get(username, {}) if isinstance(users, dict) else {}
    current_type = str(user.get("license_type") or "trial").strip().lower()
    current_expiry = str(user.get("license_expiry") or "").strip()

    return render_template(
        "my_license.html",
        ok=ok,
        msg=msg,
        current_type=current_type,
        current_expiry=current_expiry,
        monthly_try=PRICE_MONTHLY_TRY,
        yearly_eur=PRICE_YEARLY_EUR,
        yearly_try=PRICE_YEARLY_TRY
    )





# ===== RADIAL ALIAS ROUTES =====
@app.route("/setting-alias-legacy-disabled")
def setting_alias_legacy_disabled():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    return redirect("/settings")

@app.route("/alerts-alias-legacy-disabled")
def alerts_alias_legacy_disabled():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    return redirect("/notifications")

@app.route("/analytic-alias-legacy-disabled")
@app.route("/analytics-alias-legacy-disabled")
def analytics_alias_legacy_disabled():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    return redirect("/analysis")

@app.route("/block")
@app.route("/blocker")
def block_alias():
    # ---- DYNAMIC PREMIUM STATE ----
    premium_status = 'trial'
    days_left = 5
    return redirect("/blocked")




@app.route("/u/test-payment-complete", methods=["GET", "POST"])
def user_test_payment_complete_hardcore():
    username = _current_username_hardcore()
    _activate_premium_hardcore(username=username, plan=request.args.get("plan", "starter_monthly"))
    return redirect("/u/payment-success")


# ===== ERATGUARD USER RADIAL PREVIEW DEV ONLY START =====
@app.route("/dev/radial-user-preview")
def ss_dev_radial_user_preview():
    if os.environ.get("FLASK_DEBUG", "0") != "1":
        return "Not Found", 404
    return render_template("radial_menu.html")
# ===== ERATGUARD USER RADIAL PREVIEW DEV ONLY END =====


# ===== ERATGUARD ADMIN RADIAL PREVIEW DEV ONLY START =====
@app.route("/dev/admin-radial-preview")
def ss_dev_admin_radial_preview():
    if os.environ.get("FLASK_DEBUG", "0") != "1":
        return "Not Found", 404
    return render_template("admin_dashboard.html")
# ===== ERATGUARD ADMIN RADIAL PREVIEW DEV ONLY END =====


# ===== ERATGUARD HIDDEN ADMIN LOGIN START =====
@app.route("/ss-admin-access", methods=["GET", "POST"])
def ss_hidden_admin_access():
    try:
        from werkzeug.security import check_password_hash
    except Exception:
        check_password_hash = globals().get("check_password_hash")

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        users = load_users()
        user = users.get(username)

        valid = False
        if username == "admin" and isinstance(user, dict):
            stored_hash = user.get("password_hash", "")
            stored_plain = user.get("password", "")

            if stored_hash and check_password_hash:
                valid = check_password_hash(stored_hash, password)
            elif stored_plain:
                valid = stored_plain == password

        if valid:
            session["logged_in"] = True
            session["username"] = "admin"
            session["role"] = "admin"
            session["is_admin"] = True
            return redirect("/admin/dashboard")

        return render_template("admin_login.html", error="Yetkisiz admin erişimi reddedildi.")

    return render_template("admin_login.html", error="")
# ===== ERATGUARD HIDDEN ADMIN LOGIN END =====


# ===== ERATGUARD ADMIN SYSTEM PAGE START =====
@app.route("/admin/system")
def ss_admin_system_page():
    if not _ss_is_admin_session():
        return redirect("/ss-admin-access")

    import sys
    from pathlib import Path

    users_state = "VAR" if Path("data/users.json").exists() else "YOK"
    licenses_state = "VAR" if Path("data/licenses.json").exists() else "YOK"
    settings_state = "VAR" if Path("data/settings.json").exists() else "RUNTIME"

    mode = "DEBUG" if os.environ.get("FLASK_DEBUG", "0") == "1" else "PRODUCTION"
    debug_state = "AÇIK" if os.environ.get("FLASK_DEBUG", "0") == "1" else "KAPALI"

    return render_template(
        "admin_system.html",
        users_state=users_state,
        licenses_state=licenses_state,
        settings_state=settings_state,
        mode=mode,
        debug_state=debug_state,
        python_version=sys.version.split()[0],
    )
# ===== ERATGUARD ADMIN SYSTEM PAGE END =====



# ===== ERATGUARD MOBILE APP START ROUTES START =====
@app.route("/app-start")
def ss_mobile_user_app_start():
    """
    Kullanıcı mobil uygulaması giriş köprüsü.
    Normal kullanıcı APK/AAB bu URL ile başlar.
    """
    try:
        if session.get("logged_in"):
            return redirect("/radial")
    except Exception:
        pass
    return redirect("/login")


@app.route("/admin-app-start")
def ss_mobile_admin_app_start():
    """
    Admin mobil uygulaması giriş köprüsü.
    Admin APK/AAB bu URL ile başlar.
    """
    try:
        if session.get("logged_in") and (
            session.get("is_admin") or session.get("role") == "admin" or session.get("username") == "admin"
        ):
            return redirect("/admin")
    except Exception:
        pass
    return redirect("/ss-admin-access")
# ===== ERATGUARD MOBILE APP START ROUTES END =====



# ===== ERATGUARD SAFE ADMIN MOBILE APP START ROUTE START =====
@app.route("/ss-admin-app-start")
def ss_safe_mobile_admin_app_start():
    """
    Admin mobil uygulaması güvenli giriş köprüsü.
    /admin prefix'i kullanmaz; mevcut admin guard ile çakışmaz.
    """
    try:
        if session.get("logged_in") and (
            session.get("is_admin") or session.get("role") == "admin" or session.get("username") == "admin"
        ):
            return redirect("/admin")
    except Exception:
        pass
    return redirect("/ss-admin-access")
# ===== ERATGUARD SAFE ADMIN MOBILE APP START ROUTE END =====

if __name__ == "__main__":
    load_users()
    load_settings()
    if not os.path.exists(LICENSES_FILE):
        save_licenses({})
    local_debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(host="0.0.0.0", port=8080, debug=local_debug)
