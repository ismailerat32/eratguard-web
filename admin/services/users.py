from pathlib import Path
import json
import os
import urllib.parse
import urllib.request


USERS_PATH = Path("data/users.json")

def _db_enabled():
    flag = str(os.getenv("ERATGUARD_DB_ENABLED", "")).strip().lower()
    return (
        bool(os.getenv("SUPABASE_URL"))
        and bool(os.getenv("SUPABASE_SERVICE_ROLE_KEY"))
        and flag in {"1", "true", "yes", "on"}
    )


def _load_db_users():
    if not _db_enabled():
        return None

    try:
        base_url = os.getenv("SUPABASE_URL", "").strip().rstrip("/")
        key = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip()
        encoded_key = urllib.parse.quote("users", safe="")

        url = (
            f"{base_url}/rest/v1/eratguard_kv"
            f"?key=eq.{encoded_key}&select=value"
        )

        req = urllib.request.Request(
            url,
            headers={
                "apikey": key,
                "Authorization": "Bearer " + key,
                "Accept": "application/json",
            },
            method="GET",
        )

        with urllib.request.urlopen(req, timeout=15) as resp:
            rows = json.loads(resp.read().decode("utf-8") or "[]")

        if not isinstance(rows, list) or not rows:
            return None

        users = rows[0].get("value")
        return users if isinstance(users, dict) and users else None

    except Exception as exc:
        print("ADMIN_USERS_DB_READ_WARN:", repr(exc), flush=True)
        return None



# Bu alanlar hiçbir zaman admin template'ine gönderilmez.
SENSITIVE_FIELDS = {
    "password",
    "password_hash",
    "admin_password",
    "secret",
    "token",
    "reset_token",
}


def _load_raw_users():
    # Production'da Supabase/KV canonical kaynak.
    db_users = _load_db_users()

    if isinstance(db_users, dict) and db_users:
        # Local dosyayi fallback/cache olarak senkron tut.
        try:
            USERS_PATH.parent.mkdir(parents=True, exist_ok=True)
            USERS_PATH.write_text(
                json.dumps(
                    db_users,
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )
        except Exception:
            pass

        return db_users

    # DB kapali, erisilemez veya bos ise local fallback.
    if not USERS_PATH.exists():
        return {}

    try:
        data = json.loads(
            USERS_PATH.read_text(
                encoding="utf-8",
                errors="replace",
            )
        )
    except Exception:
        return {}

    return data if isinstance(data, dict) else {}

def _normalize_user(username, raw):
    if not isinstance(raw, dict):
        raw = {}

    role = str(raw.get("role") or "user").strip().lower()

    is_admin = bool(
        raw.get("is_admin") is True
        or role == "admin"
    )

    active = raw.get("active")

    if active is None:
        active = raw.get("is_active", True)

    active = bool(active)

    license_type = (
        raw.get("license_type")
        or raw.get("plan")
        or raw.get("license_mode")
        or "standard"
    )

    license_expiry = (
        raw.get("license_expiry")
        or raw.get("expires_at")
        or ""
    )

    # Explicit allow-list.
    # Raw kullanıcı sözlüğünü template'e göndermiyoruz.
    return {
        "username": str(
            raw.get("username")
            or username
        ),
        "email": str(
            raw.get("email")
            or ""
        ),
        "role": "admin" if is_admin else role,
        "active": active,
        "is_admin": is_admin,
        "license_type": str(license_type),
        "license_expiry": str(license_expiry),
        "license_label": str(
            raw.get("license_label")
            or license_type
        ),
        "created_at": str(
            raw.get("created_at")
            or ""
        ),
        "last_login": str(
            raw.get("last_login")
            or ""
        ),
        "last_seen": str(
            raw.get("last_seen")
            or ""
        ),
        "probe_account": bool(
            raw.get("probe_account")
            or raw.get("live_probe")
        ),
        # Yalnizca guvenli cihaz ozeti admin UI'ye gonderilir.
        # Installation ID/hash degerleri browser'a cikmaz.
        "device_count": (
            len(raw.get("devices", []))
            if isinstance(raw.get("devices"), list)
            else 0
        ),
        "device_limit": (
            max(1, int(raw.get("device_limit", 1)))
            if str(raw.get("device_limit", 1)).isdigit()
            else 1
        ),
    }


def get_users_center_data():
    raw_users = _load_raw_users()

    users = {}

    for username, raw in raw_users.items():
        users[str(username)] = _normalize_user(
            username,
            raw,
        )

    total_users = len(users)

    active_users = sum(
        1
        for user in users.values()
        if user["active"]
    )

    admin_users = sum(
        1
        for user in users.values()
        if user["is_admin"]
    )

    banned_users = sum(
        1
        for user in users.values()
        if not user["active"]
    )

    return {
        "users": users,
        "total_users": total_users,
        "active_users": active_users,
        "admin_users": admin_users,
        "banned_users": banned_users,
    }


def service_health():
    data = get_users_center_data()

    return {
        "ok": True,
        "source": str(USERS_PATH),
        "users": data["total_users"],
    }
