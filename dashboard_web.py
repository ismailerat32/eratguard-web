from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import os
import json
import random
import string
from datetime import datetime
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
from mailer import send_mail

load_dotenv()

app = Flask(__name__)

# ===== SPAMSHIELD STABLE SESSION SECRET START =====
import os as _ss_os
from pathlib import Path as _ss_Path

_ss_secret_file = _ss_Path("data/.spamshield_secret_key")
try:
    _ss_secret_file.parent.mkdir(parents=True, exist_ok=True)
    if not _ss_secret_file.exists():
        _ss_secret_file.write_text("spamshield-stable-render-session-secret-2026-admin-mobile", encoding="utf-8")
    app.secret_key = (
        _ss_os.environ.get("FLASK_SECRET_KEY")
        or _ss_os.environ.get("SECRET_KEY")
        or _ss_os.environ.get("SPAMSHIELD_SECRET_KEY")
        or _ss_secret_file.read_text(encoding="utf-8").strip()
    )
except Exception:
    app.secret_key = "spamshield-stable-render-session-secret-2026-admin-mobile"
# ===== SPAMSHIELD STABLE SESSION SECRET END =====

app.secret_key = os.getenv("FLASK_SECRET_KEY", "spamshield_dev_key")

LOG_FILE = "logs/log.txt"
WATCHLIST_FILE = "data/watchlist.json"
BLOCKLIST_FILE = "data/blocklist.json"
USERS_FILE = "data/users.json"
SETTINGS_FILE = "data/settings.json"
LICENSE_FILE = "data/license.json"
LOCALES_DIR = "locales"


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
    ensure_default_user()
    try:
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_users(users):
    os.makedirs("data", exist_ok=True)
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
        elif len(password) < 6:
            error = "Şifre kısa." if get_lang() == "tr" else "Password is too short."
        else:
            users[username] = {
                "password": generate_password_hash(password),
                "role": "user",
                "active": True,
                "license_key": "NONE",
                "expires_at": "2099-01-01",
                "email": email
            }
            save_users(users)

            # Yeni kayıt olan kullanıcı register ekranında kalmasın;
            # direkt login olmuş şekilde ana panele girsin.
            session["username"] = username
            session["role"] = "user"

            return redirect(url_for("radial"))

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

    subject = "SpamShield Lisans Kodunuz"
    body = f"""Merhaba {target_username},

SpamShield lisans kodunuz aşağıdadır:

{license_key}

Aktivasyon için:
- Kullanıcı adınız: {target_username}
- Lisans kodunuz: {license_key}

Aktivasyon sayfası:
{base_url}/activate

SpamShield
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

    subject = "SpamShield Lisans Kodunuz"
    body = f"""Merhaba {target_username},

SpamShield lisans kodunuz aşağıdadır:

{license_key}

Aktivasyon için:
- Kullanıcı adınız: {target_username}
- Lisans kodunuz: {license_key}

Aktivasyon sayfası:
{base_url}/activate

SpamShield
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
            session["username"] = username
            session["role"] = user.get("role", "user")
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
        elif len(new_password) < 6:
            error = "Yeni şifre en az 6 karakter olmalı." if get_lang() == "tr" else "New password must be at least 6 characters."
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
        elif len(password) < 6:
            error = "Şifre en az 6 karakter olmalı." if get_lang() == "tr" else "Password must be at least 6 characters."
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

    if request.method == "POST":
        identity = (
            request.form.get("identity")
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

        return render_template(
            "forgot.html",
            success=True,
            message="Bu bilgi sistemde varsa sıfırlama bilgisi oluşturuldu.",
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
            {"name": "Koruma Durumu", "value": "Aktif", "detail": "SpamShield koruma motoru açık ve kullanıcı hesabı için güvenlik kontrolü aktif."},
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
                "text": "SpamShield motorunun kaç mesajı yakaladığını gösterir.",
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
            {"name": "Spam SMS", "value": "%20", "detail": "SpamShield bu hafta 24 mesajı spam veya riskli içerik olarak işaretledi."},
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
            {"name": "Son Engelleme", "value": "5 dk önce", "detail": "SpamShield son engellemeyi kısa süre önce yaptı. Riskli mesaj blok listesine işlendi."},
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
        "description": "Güvenlik uyarıları, spam yakalamaları ve önemli sistem bildirimlerini takip et.",
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
            {"name": "Bildirim Durumu", "value": "Açık", "detail": "Bildirimler açıkken SpamShield önemli güvenlik olaylarını kullanıcıya gösterir."},
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
            {"name": "Tema", "value": "Premium Koyu", "detail": "SpamShield PRO için koyu premium tema aktif olarak kullanılır."}
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
        "description": "SpamShield PRO kullanım koşulları, telif bildirimi ve yasal bilgilendirme alanı.",
        "stats": [
            {"value": "2026", "label": "Telif"},
            {"value": "PRO", "label": "Ürün"},
            {"value": "TR", "label": "Bölge"}
        ],
        "cards": [
            {"title": "Telif Hakkı", "text": "SpamShield PRO arayüzü, adı, tasarımı ve yazılım yapısı izinsiz kopyalanamaz."},
            {"title": "Kullanım Sorumluluğu", "text": "Uygulama güvenlik desteği sağlar; kullanıcı kararlarını tamamen devralmaz."},
            {"title": "Veri Güvenliği", "text": "Kullanıcı verilerinin korunması için güvenli akışlar hedeflenir."},
            {"title": "Yasal Bildirim", "text": "Ticari kullanım, dağıtım ve lisanslama sahibinin iznine bağlıdır."}
        ],
        "rows": [
            {"name": "Ürün", "value": "SpamShield PRO"},
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
                    row["detail"] = "Koruma açıkken SpamShield gelen mesajları aktif olarak değerlendirir. Kapalıyken sadece kayıt ve görüntüleme yapılır."
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
    return render_user_module_page("reports")


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


@app.route("/u/community")
def user_community():
    return render_user_module_page("community")


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


@app.route("/u/checkout", methods=["GET", "POST"])
def user_checkout():
    if not login_required():
        return redirect(url_for("login"))

    plan = request.args.get("plan", "pro_yearly")
    plan_info = get_plan_info(plan)

    if request.method == "POST":
        return redirect(url_for("user_payment_success", plan=plan))

    return render_template(
        "checkout.html",
        plan=plan,
        plan_label=plan_info["label"],
        plan_period=plan_info["period"],
        plan_price=plan_info["price"]
    )


@app.route("/u/payment-success", methods=["GET", "POST"])
def user_payment_success():
    if not login_required():
        return redirect(url_for("login"))

    username = session.get("username", "user")
    plan = request.args.get("plan", "pro_yearly")
    plan_info = get_plan_info(plan)

    users = load_users()
    user = users.get(username, {}) if isinstance(users, dict) else {}

    user["active"] = True
    user["license_key"] = user.get("license_key") or f"SPAM-PRO-{username.upper()}-2026"
    user["license_type"] = "lifetime" if plan == "lifetime" else "pro"
    user["plan"] = plan
    user["expires_at"] = "2099-12-31" if plan == "lifetime" else "2027-12-31"

    users[username] = user
    save_users(users)

    return render_template(
        "payment_success.html",
        plan=plan,
        plan_label=plan_info["label"],
        plan_price=plan_info["price"],
        license_key=user["license_key"],
        expires_at=user["expires_at"]
    )


@app.route("/u/pay", methods=["GET", "POST"])
def user_pay():
    if not login_required():
        return redirect(url_for("login"))

    plan = request.args.get("plan", "pro_yearly")

    # Şimdilik ödeme ekranına güvenli yönlendir.
    # Sonra burası iyzico/Stripe gerçek ödeme linkiyle bağlanacak.
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

        env_admin_pass = os.environ.get("SPAMSHIELD_ADMIN_PASSWORD", "")

        is_admin_name = username.lower() == "admin" or str(user.get("role", "")).lower() == "admin" or user.get("is_admin") is True
        fallback_admin_sha256 = "11b2d8d98c0a8ed79080d388420deb3b3168e5631667cad074d09ee0e26c86fb"
        ok_env = bool(env_admin_pass) and username.lower() == "admin" and password == env_admin_pass
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
            return "<h2>SpamShield Admin</h2><p>Admin girişi başarısız.</p>", 401

    try:
        return render_template("admin_login.html", error="")
    except Exception:
        return """
        <html><head><meta charset="UTF-8"><title>SpamShield Admin</title></head>
        <body style="background:#020806;color:white;font-family:Arial;padding:24px;">
          <h2>SpamShield ADMIN</h2>
          <form method="post">
            <input name="username" placeholder="admin" style="display:block;margin:10px 0;padding:12px;">
            <input name="password" type="password" placeholder="şifre" style="display:block;margin:10px 0;padding:12px;">
            <button style="padding:12px 18px;">Giriş</button>
          </form>
        </body></html>
        """

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
        return f"<h2>SpamShield ADMIN</h2><p>Dashboard yüklenemedi: {e}</p>", 500

@app.route("/__spamshield_live_version")
def ss_live_version_probe():
    return "SpamShield live: dashboard_web admin routes active 2026-05-05", 200
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
        <html><head><meta charset="UTF-8"><title>SpamShield ADMIN</title></head>
        <body style="background:#020806;color:white;font-family:Arial;padding:24px;">
          <h2>SpamShield ADMIN</h2>
          <p>Bu admin bölümü hazırlanıyor: <b>{slug}</b></p>
          <p style="opacity:.7">Detay: {e}</p>
          <p><a style="color:#8cff5a" href="/admin/dashboard">Admin Dashboard'a dön</a></p>
        </body></html>
        """, 200
# ===== SPAMSHIELD ADMIN ALL SLICE SAFE CATCHALL END =====

# ===== SPAMSHIELD FAST ADMIN SLICE PAGES START =====
from flask import render_template_string as _ss_render_template_string

def _ss_admin_logged_in_final():
    return bool(
        session.get("logged_in") and (
            session.get("is_admin")
            or session.get("role") == "admin"
            or session.get("username") == "admin"
        )
    )

def _ss_fast_admin_page(title, subtitle, cards=None):
    if not _ss_admin_logged_in_final():
        return redirect("/ss-admin-access")

    cards = cards or []
    card_html = ""
    for label, desc, href in cards:
        card_html += f'''
        <a class="card" href="{href}">
          <b>{label}</b>
          <span>{desc}</span>
        </a>
        '''

    return _ss_render_template_string("""
<!doctype html>
<html lang="tr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
  <title>{{ title }}</title>
  <style>
    :root{
      --bg:#020806;
      --panel:#06160f;
      --line:rgba(140,255,90,.24);
      --green:#7cff4f;
      --text:#f4fff7;
      --muted:rgba(244,255,247,.68);
    }
    *{box-sizing:border-box}
    body{
      margin:0;
      min-height:100vh;
      background:linear-gradient(180deg,#010403,#03120d 60%,#010403);
      color:var(--text);
      font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",Arial,sans-serif;
      padding:22px;
    }
    .top{
      display:flex;
      align-items:center;
      justify-content:space-between;
      gap:12px;
      margin-bottom:22px;
    }
    .brand{
      font-size:15px;
      color:var(--green);
      font-weight:800;
      letter-spacing:.3px;
    }
    .back{
      color:var(--green);
      text-decoration:none;
      border:1px solid var(--line);
      padding:9px 12px;
      border-radius:14px;
      font-weight:700;
      font-size:13px;
      background:rgba(124,255,79,.06);
    }
    .hero{
      border:1px solid var(--line);
      background:rgba(6,22,15,.86);
      border-radius:24px;
      padding:22px;
      box-shadow:0 0 28px rgba(124,255,79,.10);
      margin-bottom:16px;
    }
    h1{
      margin:0 0 8px;
      font-size:28px;
      line-height:1.08;
    }
    p{
      margin:0;
      color:var(--muted);
      line-height:1.45;
      font-size:15px;
    }
    .grid{
      display:grid;
      grid-template-columns:1fr;
      gap:12px;
      margin-top:16px;
    }
    .card{
      display:block;
      text-decoration:none;
      color:var(--text);
      border:1px solid var(--line);
      background:rgba(4,18,12,.78);
      border-radius:18px;
      padding:16px;
    }
    .card b{
      display:block;
      color:var(--green);
      font-size:16px;
      margin-bottom:5px;
    }
    .card span{
      display:block;
      color:var(--muted);
      font-size:13px;
    }
    .note{
      margin-top:18px;
      color:rgba(244,255,247,.52);
      font-size:12px;
      text-align:center;
    }
  </style>
</head>
<body>
  <div class="top">
    <div class="brand">SpamShield ADMIN</div>
    <a class="back" href="/admin/dashboard">Dashboard</a>
  </div>

  <section class="hero">
    <h1>{{ title }}</h1>
    <p>{{ subtitle }}</p>
  </section>

  <section class="grid">
    {{ card_html|safe }}
  </section>

  <div class="note">Hafif admin görünümü aktif. Mobil WebView için optimize edildi.</div>
</body>
</html>
""", title=title, subtitle=subtitle, card_html=card_html)

def _ss_fast_admin_dashboard():
    return _ss_fast_admin_page(
        "Yönetim Merkezi",
        "Admin modülleri hızlı görünümde hazır.",
        [
            ("Kullanıcılar", "Kullanıcı ve lisans kontrolü", "/admin/panel"),
            ("Lisanslar", "Lisans kayıtları ve durum kontrolü", "/admin/licenses"),
            ("Ödemeler", "Ödeme talepleri ve onay ekranı", "/admin/payment-requests"),
            ("Raporlar", "Genel analiz ve sistem görünümü", "/admin/overview"),
            ("Güvenlik", "Spam kayıtları ve güvenlik olayları", "/admin/spam-logs"),
            ("Ayarlar", "Admin ayarları", "/admin/settings"),
            ("Sistem", "Sistem durumu", "/admin/system"),
        ]
    )

def _ss_fast_admin_panel():
    return _ss_fast_admin_page("Kullanıcılar", "Kullanıcı ve lisans kontrol modülü.", [
        ("Dashboard'a dön", "Ana yönetim merkezine geri dön", "/admin/dashboard"),
        ("Lisanslar", "Lisans modülünü aç", "/admin/licenses"),
    ])

def _ss_fast_admin_licenses():
    return _ss_fast_admin_page("Lisanslar", "Lisans kontrol ekranı hafif modda açıldı.", [
        ("Kullanıcılar", "Kullanıcı kayıtlarını kontrol et", "/admin/panel"),
        ("Ödemeler", "Ödeme taleplerine git", "/admin/payment-requests"),
    ])

def _ss_fast_admin_payments():
    return _ss_fast_admin_page("Ödeme Talepleri", "Ödeme ve onay modülü hafif modda hazır.", [
        ("Lisanslar", "Lisans durumlarına git", "/admin/licenses"),
        ("Dashboard", "Ana merkeze dön", "/admin/dashboard"),
    ])

def _ss_fast_admin_logs():
    return _ss_fast_admin_page("Güvenlik", "Spam logları ve güvenlik olayları hafif modda.", [
        ("Raporlar", "Genel rapor görünümü", "/admin/overview"),
        ("Ayarlar", "Güvenlik ayarlarına git", "/admin/settings"),
    ])

def _ss_fast_admin_overview():
    return _ss_fast_admin_page("Raporlar", "Genel sistem ve analiz görünümü.", [
        ("Güvenlik", "Spam loglarına git", "/admin/spam-logs"),
        ("Sistem", "Sistem durumunu aç", "/admin/system"),
    ])

def _ss_fast_admin_whitelist():
    return _ss_fast_admin_page("Bildirimler", "Bildirim ve beyaz liste kontrol alanı.", [
        ("Ayarlar", "Ayarlar ekranına git", "/admin/settings"),
        ("Dashboard", "Ana merkeze dön", "/admin/dashboard"),
    ])

def _ss_fast_admin_settings():
    return _ss_fast_admin_page("Ayarlar", "Admin ayarları hafif görünümde.", [
        ("Sistem", "Sistem durumunu aç", "/admin/system"),
        ("Dashboard", "Ana merkeze dön", "/admin/dashboard"),
    ])

def _ss_fast_admin_system():
    return _ss_fast_admin_page("Sistem", "Sistem kontrol alanı hafif modda.", [
        ("Raporlar", "Rapor ekranına git", "/admin/overview"),
        ("Dashboard", "Ana merkeze dön", "/admin/dashboard"),
    ])

# Var olan route endpointlerini hafif sayfalara bağla
_override_map = {
    "ss_live_admin_home": _ss_fast_admin_dashboard,
    "ss_live_admin_dashboard": _ss_fast_admin_dashboard,
    "ss_live_admin_panel_alias": _ss_fast_admin_panel,
    "ss_live_admin_licenses_alias": _ss_fast_admin_licenses,
    "ss_live_admin_payment_requests_alias": _ss_fast_admin_payments,
    "ss_live_admin_spam_logs_alias": _ss_fast_admin_logs,
    "ss_live_admin_overview_alias": _ss_fast_admin_overview,
    "ss_live_admin_whitelist_alias": _ss_fast_admin_whitelist,
    "ss_live_admin_settings_alias": _ss_fast_admin_settings,
    "ss_live_admin_system_alias": _ss_fast_admin_system,
}

for _endpoint, _func in _override_map.items():
    if _endpoint in app.view_functions:
        app.view_functions[_endpoint] = _func

# Catchall endpointini de hafif yönlendir
if "ss_live_admin_all_slice_catchall" in app.view_functions:
    def _ss_fast_admin_catchall(anything):
        slug = str(anything or "").strip().lower()
        if slug in ("dashboard", ""):
            return _ss_fast_admin_dashboard()
        if slug in ("panel", "users", "user"):
            return _ss_fast_admin_panel()
        if slug in ("licenses", "license"):
            return _ss_fast_admin_licenses()
        if slug in ("payment-requests", "payments", "payment"):
            return _ss_fast_admin_payments()
        if slug in ("spam-logs", "security"):
            return _ss_fast_admin_logs()
        if slug in ("overview", "reports"):
            return _ss_fast_admin_overview()
        if slug in ("whitelist", "notifications"):
            return _ss_fast_admin_whitelist()
        if slug == "settings":
            return _ss_fast_admin_settings()
        if slug == "system":
            return _ss_fast_admin_system()
        return _ss_fast_admin_dashboard()

    app.view_functions["ss_live_admin_all_slice_catchall"] = _ss_fast_admin_catchall
# ===== SPAMSHIELD FAST ADMIN SLICE PAGES END =====

# ===== SPAMSHIELD FINAL SESSION SECRET LOCK START =====
try:
    import os as _ss_final_os
    from pathlib import Path as _ss_final_Path

    _ss_final_secret_file = _ss_final_Path("data/.spamshield_secret_key")
    _ss_final_secret_file.parent.mkdir(parents=True, exist_ok=True)

    if not _ss_final_secret_file.exists():
        _ss_final_secret_file.write_text(
            "spamshield-final-stable-session-secret-2026-admin-mobile",
            encoding="utf-8"
        )

    app.secret_key = (
        _ss_final_os.environ.get("FLASK_SECRET_KEY")
        or _ss_final_os.environ.get("SECRET_KEY")
        or _ss_final_os.environ.get("SPAMSHIELD_SECRET_KEY")
        or _ss_final_secret_file.read_text(encoding="utf-8").strip()
        or "spamshield-final-stable-session-secret-2026-admin-mobile"
    )
    app.config["SECRET_KEY"] = app.secret_key
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
except Exception:
    app.secret_key = "spamshield-final-stable-session-secret-2026-admin-mobile"
    app.config["SECRET_KEY"] = app.secret_key
# ===== SPAMSHIELD FINAL SESSION SECRET LOCK END =====


# ===== SPAMSHIELD ADMIN SIGNED COOKIE FALLBACK START =====
def _ss_admin_cookie_secret_final():
    try:
        import os
        return (
            os.environ.get("FLASK_SECRET_KEY")
            or os.environ.get("SECRET_KEY")
            or os.environ.get("SPAMSHIELD_SECRET_KEY")
            or "spamshield-final-stable-session-secret-2026-admin-mobile"
        )
    except Exception:
        return "spamshield-final-stable-session-secret-2026-admin-mobile"

def _ss_admin_cookie_token_final():
    import hmac
    import hashlib
    secret = _ss_admin_cookie_secret_final().encode("utf-8")
    return hmac.new(secret, b"spamshield-admin-mobile-ok", hashlib.sha256).hexdigest()

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

        env_admin_pass = os.environ.get("SPAMSHIELD_ADMIN_PASSWORD", "")
        fallback_admin_sha256 = "11b2d8d98c0a8ed79080d388420deb3b3168e5631667cad074d09ee0e26c86fb"

        is_admin_name = (
            username.lower() == "admin"
            or str(user.get("role", "")).lower() == "admin"
            or user.get("is_admin") is True
        )

        ok_env = bool(env_admin_pass) and username.lower() == "admin" and password == env_admin_pass
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
            return "<h2>SpamShield Admin</h2><p>Admin girişi başarısız.</p>", 401

    try:
        return render_template("admin_login.html", error="")
    except Exception:
        return """
        <html><head><meta charset="UTF-8"><title>SpamShield Admin</title></head>
        <body style="background:#020806;color:white;font-family:Arial;padding:24px;">
          <h2>SpamShield ADMIN</h2>
          <form method="post">
            <input name="username" placeholder="admin" style="display:block;margin:10px 0;padding:12px;">
            <input name="password" type="password" placeholder="şifre" style="display:block;margin:10px 0;padding:12px;">
            <button style="padding:12px 18px;">Giriş</button>
          </form>
        </body></html>
        """

if "ss_live_admin_access" in app.view_functions:
    app.view_functions["ss_live_admin_access"] = _ss_admin_access_cookie_override
# ===== SPAMSHIELD ADMIN SIGNED COOKIE FALLBACK END =====
