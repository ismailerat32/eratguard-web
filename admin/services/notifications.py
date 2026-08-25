from pathlib import Path
from datetime import datetime
import json


DATA_FILE = Path("data/admin_notifications.json")


def _load_items():
    try:
        if not DATA_FILE.exists():
            return []

        raw = DATA_FILE.read_text(
            encoding="utf-8"
        )

        data = json.loads(raw or "[]")

        if not isinstance(data, list):
            return []

        return [
            item
            for item in data
            if isinstance(item, dict)
        ]

    except Exception:
        return []


def _normalize_item(item):
    status = str(
        item.get("status", "created") or "created"
    ).strip().lower()

    priority = str(
        item.get("priority", "normal") or "normal"
    ).strip().lower()

    target = str(
        item.get("target", "all") or "all"
    ).strip().lower()

    if priority not in {
        "normal",
        "high",
        "critical",
    }:
        priority = "normal"

    if target not in {
        "all",
        "premium",
        "admin",
    }:
        target = "all"

    return {
        "id": str(
            item.get("id", "")
        ).strip(),

        "title": str(
            item.get("title", "")
        ).strip(),

        "message": str(
            item.get("message", "")
        ).strip(),

        "priority": priority,
        "target": target,
        "status": status,

        "created_at": str(
            item.get("created_at", "")
        ).strip(),

        "archived_at": str(
            item.get("archived_at", "")
        ).strip(),
    }


def get_notifications_center_data(limit=100):
    items = [
        _normalize_item(item)
        for item in _load_items()
    ]

    active = [
        item
        for item in items
        if item["status"] != "archived"
    ]

    archived = [
        item
        for item in items
        if item["status"] == "archived"
    ]

    today = datetime.now().strftime(
        "%Y-%m-%d"
    )

    today_count = sum(
        1
        for item in active
        if item["created_at"].startswith(today)
    )

    critical_count = sum(
        1
        for item in active
        if item["priority"] == "critical"
    )

    high_count = sum(
        1
        for item in active
        if item["priority"] == "high"
    )

    admin_target = sum(
        1
        for item in active
        if item["target"] == "admin"
    )

    public_target = sum(
        1
        for item in active
        if item["target"] in {
            "all",
            "premium",
        }
    )

    display = list(
        reversed(items[-max(1, int(limit)):])
    )

    return {
        "title": "Bildirim Merkezi",
        "status": "READY",
        "read_only": True,

        "notifications": display,

        "notification_stats": {
            "total": len(items),
            "active": len(active),
            "archived": len(archived),
            "today": today_count,
            "critical": critical_count,
            "high": high_count,
            "admin_target": admin_target,
            "public_target": public_target,
        },

        "data_source": str(DATA_FILE),

        "runtime": {
            "owner": "admin.routes",
            "service": "admin.services.notifications",
            "template": "admin/notifications.html",
            "mode": "READ ONLY",
        },
    }
