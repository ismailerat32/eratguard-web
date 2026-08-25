from pathlib import Path
import json


USERS_PATH = Path("data/users.json")


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

    if not isinstance(data, dict):
        return {}

    return data


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
