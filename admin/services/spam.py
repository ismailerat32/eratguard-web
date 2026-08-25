from pathlib import Path
from datetime import datetime
import json


ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "data"


def _load_json(name, default):
    path = DATA / name

    if not path.exists():
        return default

    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def _as_list(value):
    if isinstance(value, list):
        return value

    if isinstance(value, dict):
        return list(value.values())

    return []


def _text(value, default="—"):
    if value is None:
        return default

    value = str(value).strip()
    return value if value else default


def _number(value, default=0):
    try:
        return int(float(value))
    except Exception:
        return default


def _parse_time(value):
    if not value:
        return None

    raw = str(value).strip()

    candidates = [
        raw,
        raw.replace("Z", "+00:00"),
    ]

    for candidate in candidates:
        try:
            return datetime.fromisoformat(candidate)
        except Exception:
            pass

    for fmt in (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
    ):
        try:
            return datetime.strptime(raw, fmt)
        except Exception:
            pass

    return None


def _normalize_reason(item):
    reasons = item.get("reasons")

    if isinstance(reasons, list):
        values = [
            str(x).strip()
            for x in reasons
            if str(x).strip()
        ]
        if values:
            return " • ".join(values)

    if isinstance(reasons, str) and reasons.strip():
        return reasons.strip()

    for key in ("reason", "detail", "description"):
        value = item.get(key)
        if value:
            return _text(value)

    return "—"


def _normalize(item, source="spam_logs"):
    if not isinstance(item, dict):
        item = {}

    status = _text(
        item.get("status")
        or item.get("result")
        or item.get("classification"),
        "UNKNOWN",
    ).upper()

    score = _number(
        item.get("score", item.get("risk", 0)),
        0,
    )

    sender = (
        item.get("phone")
        or item.get("number")
        or item.get("sender")
        or item.get("source")
        or "Bilinmeyen"
    )

    message = (
        item.get("message")
        or item.get("body")
        or item.get("text")
        or item.get("subject")
        or "—"
    )

    time_value = (
        item.get("time")
        or item.get("timestamp")
        or item.get("date")
        or ""
    )

    dt = _parse_time(time_value)

    if status == "SPAM":
        state = "spam"
        state_label = "SPAM"
    elif status in ("SAFE", "CLEAN", "OK", "HAM"):
        state = "safe"
        state_label = "GÜVENLİ"
    else:
        state = "unknown"
        state_label = status if status != "UNKNOWN" else "BİLİNMİYOR"

    if score >= 70:
        risk_level = "high"
        risk_label = "Yüksek"
    elif score >= 30:
        risk_level = "medium"
        risk_label = "Orta"
    else:
        risk_level = "low"
        risk_label = "Düşük"

    return {
        "time": _text(time_value),
        "_dt": dt,
        "sender": _text(sender, "Bilinmeyen"),
        "message": _text(message),
        "score": score,
        "status": status,
        "state": state,
        "state_label": state_label,
        "risk_level": risk_level,
        "risk_label": risk_label,
        "reason": _normalize_reason(item),
        "username": _text(item.get("username")),
        "source": source,
    }


def get_spam_center_data(limit=100):
    spam_raw = _as_list(
        _load_json("spam_logs.json", [])
    )

    blocked_raw = _as_list(
        _load_json("blocked_messages.json", [])
    )

    history_raw = _as_list(
        _load_json("user_analysis_history.json", [])
    )

    quarantine_raw = _as_list(
        _load_json("user_quarantine.json", [])
    )

    spam_items = [
        _normalize(item, "spam_logs")
        for item in spam_raw
    ]

    history_items = [
        _normalize(item, "analysis_history")
        for item in history_raw
    ]

    all_items = spam_items + history_items

    all_items.sort(
        key=lambda x: (
            x["_dt"] is not None,
            x["_dt"] or datetime.min,
        ),
        reverse=True,
    )

    total_logs = len(spam_items)

    spam_total = sum(
        1 for x in spam_items
        if x["state"] == "spam"
    )

    safe_total = sum(
        1 for x in spam_items
        if x["state"] == "safe"
    )

    unknown_total = max(
        0,
        total_logs - spam_total - safe_total,
    )

    high_risk = sum(
        1 for x in spam_items
        if x["score"] >= 70
    )

    medium_risk = sum(
        1 for x in spam_items
        if 30 <= x["score"] < 70
    )

    blocked_total = len(blocked_raw)
    quarantine_total = len(quarantine_raw)

    for item in all_items:
        item.pop("_dt", None)

    return {
        "total_logs": total_logs,
        "spam_total": spam_total,
        "safe_total": safe_total,
        "unknown_total": unknown_total,
        "high_risk": high_risk,
        "medium_risk": medium_risk,
        "blocked_total": blocked_total,
        "quarantine_total": quarantine_total,
        "analysis_history_total": len(history_raw),
        "logs": all_items[:max(1, int(limit))],
    }
