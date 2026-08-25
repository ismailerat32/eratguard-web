from pathlib import Path
import json
from datetime import datetime, timedelta


ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = ROOT / "data"

AUDIT_LOGS_FILE = DATA_DIR / "audit_logs.json"
SPAM_LOGS_FILE = DATA_DIR / "spam_logs.json"
QUARANTINE_FILE = DATA_DIR / "user_quarantine.json"
BLOCKED_MESSAGES_FILE = DATA_DIR / "blocked_messages.json"


def _read_json(path, default):
    try:
        if not path.exists():
            return default

        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)

        return data

    except Exception:
        return default


def _safe_text(value, default="-"):
    if value is None:
        return default

    text = str(value).strip()

    return text if text else default


def _parse_time(value):
    if not value:
        return None

    text = str(value).strip()

    formats = (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%d %H:%M",
    )

    # ISO timezone suffix
    candidate = text.replace("Z", "+00:00")

    try:
        dt = datetime.fromisoformat(candidate)

        # Dashboard karşılaştırmalarını naive yap.
        if dt.tzinfo is not None:
            dt = dt.replace(tzinfo=None)

        return dt
    except Exception:
        pass

    for fmt in formats:
        try:
            return datetime.strptime(text, fmt)
        except Exception:
            pass

    return None


def _normalize_level(value):
    level = str(value or "info").strip().lower()

    if level in {
        "critical",
        "fatal",
        "danger",
        "error",
        "high",
        "p0",
        "p1",
    }:
        return "critical"

    if level in {
        "warning",
        "warn",
        "medium",
        "suspicious",
        "p2",
    }:
        return "warning"

    return "info"


def _audit_events():
    raw = _read_json(AUDIT_LOGS_FILE, [])

    if not isinstance(raw, list):
        return []

    events = []

    for item in raw:
        if not isinstance(item, dict):
            continue

        events.append({
            "time": _safe_text(
                item.get("time")
                or item.get("timestamp")
            ),
            "event": _safe_text(
                item.get("event")
                or item.get("type"),
                "security_event",
            ),
            "username": _safe_text(
                item.get("username")
                or item.get("user")
            ),
            "level": _normalize_level(
                item.get("level")
            ),
            "ip": _safe_text(
                item.get("ip")
            ),
            "path": _safe_text(
                item.get("path")
            ),
            "detail": _safe_text(
                item.get("detail")
                or item.get("message")
            ),
            "_dt": _parse_time(
                item.get("time")
                or item.get("timestamp")
            ),
        })

    events.sort(
        key=lambda x: x["_dt"] or datetime.min,
        reverse=True,
    )

    return events


def _spam_stats():
    raw = _read_json(SPAM_LOGS_FILE, [])

    if not isinstance(raw, list):
        raw = []

    total = len(raw)
    high = 0

    for item in raw:
        if not isinstance(item, dict):
            continue

        label = str(
            item.get("risk_label")
            or item.get("risk")
            or item.get("status")
            or ""
        ).lower()

        try:
            score = float(item.get("score", 0) or 0)
        except Exception:
            score = 0

        if (
            "yüksek" in label
            or "high" in label
            or "critical" in label
            or "spam" in label
            or score >= 70
        ):
            high += 1

    return {
        "total": total,
        "high_risk": high,
    }


def _quarantine_stats():
    raw = _read_json(QUARANTINE_FILE, [])

    if not isinstance(raw, list):
        raw = []

    active = 0

    for item in raw:
        if not isinstance(item, dict):
            continue

        status = str(
            item.get("quarantine_status")
            or item.get("status")
            or ""
        ).strip().lower()

        if status not in {
            "released",
            "safe",
            "removed",
            "deleted",
            "closed",
        }:
            active += 1

    return {
        "total": len(raw),
        "active": active,
    }


def _blocked_stats():
    raw = _read_json(BLOCKED_MESSAGES_FILE, [])

    if not isinstance(raw, list):
        raw = []

    return {
        "total": len(raw),
    }


def get_security_center(limit=50):
    events = _audit_events()

    now = datetime.now()
    window_start = now - timedelta(hours=24)

    critical = sum(
        1 for e in events
        if e["level"] == "critical"
    )

    warning = sum(
        1 for e in events
        if e["level"] == "warning"
    )

    recent = sum(
        1 for e in events
        if e["_dt"] is not None
        and e["_dt"] >= window_start
    )

    spam = _spam_stats()
    quarantine = _quarantine_stats()
    blocked = _blocked_stats()

    clean_events = []

    for event in events[:limit]:
        clean_events.append({
            k: v
            for k, v in event.items()
            if k != "_dt"
        })

    if critical > 0:
        state = "critical"
        state_label = "Kritik olay var"
    elif warning > 0:
        state = "warning"
        state_label = "İzleme gerekli"
    else:
        state = "healthy"
        state_label = "Sistem normal"

    return {
        "total_events": len(events),
        "critical_events": critical,
        "warning_events": warning,
        "recent_window": recent,

        "spam_total": spam["total"],
        "spam_high_risk": spam["high_risk"],

        "quarantine_total": quarantine["total"],
        "quarantine_active": quarantine["active"],

        "blocked_total": blocked["total"],

        "security_state": state,
        "security_state_label": state_label,

        "events": clean_events,
    }
