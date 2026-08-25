from pathlib import Path
import json
import time
from datetime import datetime, timezone


ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "data"


def _read_json(name, default):
    path = DATA / name

    try:
        if not path.exists():
            return default

        text = path.read_text(
            encoding="utf-8",
            errors="replace",
        ).strip()

        if not text:
            return default

        return json.loads(text)

    except Exception:
        return default


def _as_list(value):
    if isinstance(value, list):
        return value

    if isinstance(value, dict):
        for key in (
            "items",
            "data",
            "logs",
            "requests",
            "licenses",
            "notifications",
        ):
            nested = value.get(key)

            if isinstance(nested, list):
                return nested

        return list(value.values())

    return []


def _users():
    raw = _read_json("users.json", {})

    if isinstance(raw, dict):
        nested = raw.get("users")

        if isinstance(nested, dict):
            return nested

        return raw

    return {}


def _licenses():
    primary = _as_list(
        _read_json("licenses.json", [])
    )

    generated = _as_list(
        _read_json("generated_licenses.json", [])
    )

    result = []
    seen = set()

    for item in primary + generated:
        if not isinstance(item, dict):
            continue

        key = str(
            item.get("license_key")
            or item.get("key")
            or item.get("license")
            or ""
        ).strip()

        marker = key or repr(sorted(item.items()))

        if marker in seen:
            continue

        seen.add(marker)
        result.append(item)

    return result


def _payments():
    return _as_list(
        _read_json("payment_requests.json", [])
    )


def _audit():
    primary = _as_list(
        _read_json("audit_logs.json", [])
    )

    if primary:
        return primary

    return _as_list(
        _read_json("admin_actions.json", [])
    )


def _spam_logs():
    return _as_list(
        _read_json("spam_logs.json", [])
    )


def _blocked_messages():
    return _as_list(
        _read_json("blocked_messages.json", [])
    )


def _safe_list():
    raw = _read_json("safe_list.json", [])

    if isinstance(raw, dict):
        return list(raw.values())

    return _as_list(raw)


def _notifications():
    admin_items = _as_list(
        _read_json("admin_notifications.json", [])
    )

    if admin_items:
        return admin_items

    return _as_list(
        _read_json("notifications.json", [])
    )


def _event_level(event):
    if not isinstance(event, dict):
        return "info"

    return str(
        event.get("level")
        or event.get("severity")
        or event.get("type")
        or "info"
    ).strip().lower()



# ERATGUARD PHASE 8B.1 - SIGNATURE TELEMETRY

_PROCESS_STARTED_MONOTONIC = time.monotonic()


def _runtime_uptime():
    try:
        seconds = max(
            0,
            int(
                time.monotonic()
                - _PROCESS_STARTED_MONOTONIC
            ),
        )

        days, remainder = divmod(
            seconds,
            86400,
        )

        hours, remainder = divmod(
            remainder,
            3600,
        )

        minutes, seconds = divmod(
            remainder,
            60,
        )

        if days:
            label = (
                f"{days}d "
                f"{hours:02d}:"
                f"{minutes:02d}:"
                f"{seconds:02d}"
            )
        else:
            label = (
                f"{hours:02d}:"
                f"{minutes:02d}:"
                f"{seconds:02d}"
            )

        return {
            "seconds": (
                days * 86400
                + hours * 3600
                + minutes * 60
                + seconds
            ),
            "label": label,
        }

    except Exception:
        return {
            "seconds": 0,
            "label": "00:00:00",
        }


def _threat_state(critical_events, security_warnings):
    if critical_events > 0:
        return {
            "level": "HIGH",
            "class": "danger",
        }

    if security_warnings > 0:
        return {
            "level": "ELEVATED",
            "class": "warning",
        }

    return {
        "level": "LOW",
        "class": "safe",
    }

def get_dashboard_data():
    users = _users()
    licenses = _licenses()
    payments = _payments()
    audit = _audit()
    spam_logs = _spam_logs()
    blocked = _blocked_messages()
    safe_list = _safe_list()
    notifications = _notifications()

    total_users = len(users)
    active_users = 0
    admin_users = 0
    banned_users = 0

    for username, user in users.items():
        if not isinstance(user, dict):
            continue

        role = str(
            user.get("role") or ""
        ).strip().lower()

        if (
            role == "admin"
            or user.get("is_admin") is True
            or str(username).strip().lower() == "admin"
        ):
            admin_users += 1

        if user.get("is_banned") is True:
            banned_users += 1

        elif user.get("active", True):
            active_users += 1

    used_licenses = 0
    expired_licenses = 0

    for item in licenses:
        if not isinstance(item, dict):
            continue

        status = str(
            item.get("status") or ""
        ).strip().lower()

        if (
            item.get("used") is True
            or status in (
                "used",
                "active",
                "activated",
            )
        ):
            used_licenses += 1

        if status in (
            "expired",
            "disabled",
            "revoked",
        ):
            expired_licenses += 1

    pending_payments = 0

    for item in payments:
        if not isinstance(item, dict):
            continue

        status = str(
            item.get("status") or ""
        ).strip().lower()

        if status not in (
            "approved",
            "rejected",
            "cancelled",
            "canceled",
        ):
            pending_payments += 1

    security_warnings = 0
    critical_events = 0

    for event in audit:
        level = _event_level(event)

        if level in (
            "warning",
            "warn",
            "error",
            "critical",
        ):
            security_warnings += 1

        if level in (
            "error",
            "critical",
        ):
            critical_events += 1

    recent_events = []

    for event in reversed(audit[-12:]):
        if isinstance(event, dict):
            recent_events.append(event)

    uptime = _runtime_uptime()
    threat = _threat_state(
        critical_events,
        security_warnings,
    )

    stats = {
        "users": total_users,
        "total_users": total_users,
        "active_users": active_users,
        "admin_users": admin_users,
        "banned_users": banned_users,

        "licenses": len(licenses),
        "total_licenses": len(licenses),
        "used_licenses": used_licenses,
        "expired_licenses": expired_licenses,

        "payments": pending_payments,
        "payment_requests": len(payments),
        "pending_payments": pending_payments,

        "security": security_warnings,
        "security_warnings": security_warnings,
        "critical_events": critical_events,

        "audit_events": len(audit),
        "spam_logs": len(spam_logs),
        "blocked": len(blocked),
        "safe_list": len(safe_list),
        "notifications": len(notifications),

        "engine_status": "ONLINE",
        "threat_level": threat["level"],
        "threat_class": threat["class"],
        "uptime": uptime["label"],
        "uptime_seconds": uptime["seconds"],

        "system_score": 100,
        "health_score": 100,
        "ops_score": (
            100 if critical_events == 0 else 80
        ),
        "release_score": 100,

        "system": "ONLINE",
        "health": (
            "HEALTHY"
            if critical_events == 0
            else "ATTENTION"
        ),
    }

    return {
        "admin_stats": stats,
        "recent_events": recent_events,
        "generated_at": datetime.now(
            timezone.utc
        ).isoformat(),
    }
