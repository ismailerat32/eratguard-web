from pathlib import Path
import json


DATA_DIR = Path("data")
PAYMENT_REQUESTS_FILE = DATA_DIR / "payment_requests.json"


def _read_json(path, default):
    try:
        if not path.exists():
            return default

        data = json.loads(
            path.read_text(encoding="utf-8") or ""
        )

        return data
    except Exception:
        return default


def _as_list(value):
    if isinstance(value, list):
        return value

    if isinstance(value, dict):
        for key in ("items", "data", "requests", "payments"):
            nested = value.get(key)

            if isinstance(nested, list):
                return nested

        return list(value.values())

    return []


def _text(value):
    return str(value or "").strip()


def _status_group(status):
    value = _text(status).lower()

    if "approved" in value:
        return "approved"

    if (
        "reject" in value
        or "cancel" in value
        or "iptal" in value
    ):
        return "rejected"

    return "pending"


def get_payment_requests():
    items = _as_list(
        _read_json(PAYMENT_REQUESTS_FILE, [])
    )

    clean = []

    for raw in items:
        if not isinstance(raw, dict):
            continue

        item = dict(raw)

        item["order_no"] = _text(
            item.get("order_no")
        )

        item["username"] = _text(
            item.get("username")
        )

        item["email"] = _text(
            item.get("email")
        )

        item["plan"] = _text(
            item.get("plan_key")
            or item.get("plan")
            or "pro_yearly"
        )

        item["plan_label"] = _text(
            item.get("plan_label")
            or item.get("plan")
            or item.get("plan_key")
            or "PRO"
        )

        item["price"] = _text(
            item.get("plan_price")
            or item.get("amount")
            or item.get("price")
            or "-"
        )

        item["created_at"] = _text(
            item.get("created_at")
        )

        item["status"] = _text(
            item.get("status")
            or "payment_waiting"
        )

        item["status_group"] = _status_group(
            item["status"]
        )

        item["license_key"] = _text(
            item.get("license_key")
        )

        clean.append(item)

    clean.sort(
        key=lambda x: x.get("created_at", ""),
        reverse=True,
    )

    return clean


def get_payments_center_data():
    items = get_payment_requests()

    pending = sum(
        1 for x in items
        if x["status_group"] == "pending"
    )

    approved = sum(
        1 for x in items
        if x["status_group"] == "approved"
    )

    rejected = sum(
        1 for x in items
        if x["status_group"] == "rejected"
    )

    return {
        "payment_requests": items,
        "payments": items,
        "total_payments": len(items),
        "pending_payments": pending,
        "approved_payments": approved,
        "rejected_payments": rejected,
    }
