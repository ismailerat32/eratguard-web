from pathlib import Path
import json


DATA_DIR = Path("data")

LICENSES_FILE = DATA_DIR / "licenses.json"
GENERATED_FILE = DATA_DIR / "generated_licenses.json"
USERS_FILE = DATA_DIR / "users.json"


def _read_json(path, default):
    try:
        if not path.exists():
            return default

        return json.loads(
            path.read_text(encoding="utf-8") or ""
        )
    except Exception:
        return default


def _text(value):
    return str(value or "").strip()


def _legacy_licenses():
    raw = _read_json(LICENSES_FILE, {})

    result = []

    if not isinstance(raw, dict):
        return result

    for key, value in raw.items():
        if not isinstance(value, dict):
            value = {}

        item = dict(value)

        item["key"] = _text(
            item.get("key") or key
        )

        item["source"] = "licenses.json"

        result.append(item)

    return result


def _generated_licenses():
    raw = _read_json(GENERATED_FILE, [])

    if not isinstance(raw, list):
        return []

    result = []

    for value in raw:
        if not isinstance(value, dict):
            continue

        item = dict(value)

        item["key"] = _text(
            item.get("key")
            or item.get("license_key")
        )

        item["source"] = "generated_licenses.json"

        result.append(item)

    return result


def _normalize(item):
    result = dict(item)

    result["key"] = _text(
        result.get("key")
        or result.get("license_key")
    )

    result["username"] = _text(
        result.get("username")
        or result.get("activated_by")
    )

    result["license_type"] = _text(
        result.get("license_type")
        or result.get("type")
        or "pro"
    )

    result["expiry"] = _text(
        result.get("license_expiry")
        or result.get("expiry")
        or result.get("expires_at")
        or "-"
    )

    raw_status = _text(
        result.get("status")
    ).lower()

    used = bool(
        result.get("used")
    )

    if raw_status in (
        "revoked",
        "disabled",
        "expired",
    ):
        status = raw_status
    elif used or raw_status in (
        "used",
        "active",
        "activated",
    ):
        status = "active"
    else:
        status = raw_status or "available"

    result["status"] = status
    result["used"] = (
        used
        or status == "active"
    )

    return result


def get_license_items():
    merged = (
        _legacy_licenses()
        + _generated_licenses()
    )

    result = []
    seen = set()

    for raw in merged:
        item = _normalize(raw)

        key = item["key"].upper()

        if not key:
            continue

        if key in seen:
            continue

        seen.add(key)
        result.append(item)

    result.sort(
        key=lambda x: x.get("key", "")
    )

    return result


def get_license_center_data():
    licenses = get_license_items()

    users = _read_json(
        USERS_FILE,
        {},
    )

    if not isinstance(users, dict):
        users = {}

    active = sum(
        1 for x in licenses
        if x.get("status") == "active"
    )

    available = sum(
        1 for x in licenses
        if x.get("status") == "available"
    )

    disabled = sum(
        1 for x in licenses
        if x.get("status") in (
            "expired",
            "disabled",
            "revoked",
        )
    )

    assigned_users = sum(
        1
        for _, user in users.items()
        if isinstance(user, dict)
        and _text(user.get("license_key"))
    )

    return {
        "licenses": licenses,
        "license_items": licenses,
        "total_licenses": len(licenses),
        "active_licenses": active,
        "available_licenses": available,
        "disabled_licenses": disabled,
        "licensed_users": assigned_users,
    }
