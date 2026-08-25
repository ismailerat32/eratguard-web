from pathlib import Path
from datetime import datetime, timezone
import json
import os
import platform
import sys


BASE_DIR = Path(__file__).resolve().parents[2]
DATA_DIR = BASE_DIR / "data"


def _safe_json(path, default):
    try:
        if not path.exists():
            return default

        raw = path.read_text(encoding="utf-8").strip()

        if not raw:
            return default

        return json.loads(raw)

    except Exception:
        return default


def _count_json(name):
    data = _safe_json(DATA_DIR / name, None)

    if isinstance(data, dict):
        return len(data)

    if isinstance(data, list):
        return len(data)

    return 0


def _file_state(name):
    path = DATA_DIR / name

    try:
        exists = path.exists()
        size = path.stat().st_size if exists else 0

        if exists:
            modified = datetime.fromtimestamp(
                path.stat().st_mtime,
                tz=timezone.utc
            ).isoformat()
        else:
            modified = None

        return {
            "name": name,
            "exists": exists,
            "size": size,
            "modified": modified,
        }

    except Exception:
        return {
            "name": name,
            "exists": False,
            "size": 0,
            "modified": None,
        }


def get_settings_center_data():
    """
    Canonical admin settings center.

    Phase 7D.11 is intentionally READ ONLY.
    It exposes runtime/configuration state without mutating
    production configuration or JSON data.
    """

    users = _safe_json(
        DATA_DIR / "users.json",
        {}
    )

    admin_count = 0
    active_count = 0

    if isinstance(users, dict):
        for _, item in users.items():
            if not isinstance(item, dict):
                continue

            role = str(
                item.get("role", "")
            ).strip().lower()

            is_admin = bool(
                item.get("is_admin")
            ) or role == "admin"

            if is_admin:
                admin_count += 1

            if item.get("active", True) is not False:
                active_count += 1

    data_files = [
        _file_state("users.json"),
        _file_state("licenses.json"),
        _file_state("generated_licenses.json"),
        _file_state("payment_requests.json"),
    ]

    missing_files = [
        item["name"]
        for item in data_files
        if not item["exists"]
    ]

    environment = {
        "platform": platform.system() or "Unknown",
        "release": platform.release() or "Unknown",
        "python_version": platform.python_version(),
        "working_directory": str(BASE_DIR),
        "debug": bool(
            os.environ.get("FLASK_DEBUG", "").lower()
            in ("1", "true", "yes", "on")
        ),
    }

    counters = {
        "users": _count_json("users.json"),
        "active_users": active_count,
        "admins": admin_count,
        "licenses": _count_json("licenses.json"),
        "generated_licenses":
            _count_json("generated_licenses.json"),
        "payment_requests":
            _count_json("payment_requests.json"),
    }

    safeguards = {
        "read_only": True,
        "production_data_write": False,
        "canonical_admin": True,
        "auth_boundary": True,
    }

    return {
        "title": "Ayarlar Merkezi",
        "status": (
            "READY"
            if not missing_files
            else "WARNING"
        ),
        "environment": environment,
        "counters": counters,
        "data_files": data_files,
        "missing_files": missing_files,
        "safeguards": safeguards,
        "generated_at":
            datetime.now(timezone.utc).isoformat(),
    }
