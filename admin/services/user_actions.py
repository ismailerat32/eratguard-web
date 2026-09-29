from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Mapping

from werkzeug.security import generate_password_hash
from .commercial_actions import _eg_canonical_apply_plan_to_user_v1



PROJECT_ROOT = Path(__file__).resolve().parents[2]
USERS_FILE = PROJECT_ROOT / "data" / "users.json"


def _read_users() -> dict[str, dict[str, Any]]:
    try:
        raw = json.loads(
            USERS_FILE.read_text(encoding="utf-8") or "{}"
        )
    except Exception:
        return {}

    return raw if isinstance(raw, dict) else {}


def _write_users(users: Mapping[str, Any]) -> None:
    USERS_FILE.parent.mkdir(parents=True, exist_ok=True)

    temp = USERS_FILE.with_suffix(".json.tmp")

    temp.write_text(
        json.dumps(
            dict(users),
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    temp.replace(USERS_FILE)


def _normalize_username(value: Any) -> str:
    return str(value or "").strip()


def _generate_unique_license_key(
    users: Mapping[str, Any],
    generator: Callable[[], str],
) -> str:
    used = set()

    for info in users.values():
        if not isinstance(info, dict):
            continue

        key = str(
            info.get("license_key", "") or ""
        ).strip().upper()

        if key:
            used.add(key)

    for _ in range(1000):
        key = str(generator() or "").strip().upper()

        if key and key not in used:
            return key

    raise RuntimeError(
        "unique_license_generation_exhausted"
    )


def create_user(
    *,
    username: str,
    email: str,
    password: str,
    role: str,
    license_type: str,
    license_expiry: str,
    password_policy: Callable[[str], Any],
    license_generator: Callable[[], str],
    audit: Callable[..., Any] | None = None,
    users: dict[str, Any] | None = None,
    persist: bool = True,
) -> dict[str, Any]:
    """
    Business action only.

    No Flask request/session/auth/redirect logic belongs here.
    """

    username = _normalize_username(username)
    email = str(email or "").strip()
    password = str(password or "")
    role = str(role or "user").strip().lower()
    license_type = str(
        license_type or "trial"
    ).strip().lower()
    license_expiry = str(
        license_expiry or ""
    ).strip()

    if not username:
        return {"ok": False, "code": "missing_username"}

    if not password:
        return {"ok": False, "code": "missing_password"}

    if role not in {"user", "admin"}:
        role = "user"

    store = users if users is not None else _read_users()

    if not isinstance(store, dict):
        store = {}

    if username in store:
        return {"ok": False, "code": "user_exists"}

    policy_error = password_policy(password)

    if policy_error:
        return {
            "ok": False,
            "code": "weak_password",
            "detail": str(policy_error),
        }

    if role == "admin":
        license_key = "ADMIN-SYSTEM"
    else:
        license_key = _generate_unique_license_key(
            store,
            license_generator,
        )

    expires_at = (
        "2099-12-31"
        if role == "admin" or license_type == "lifetime"
        else (license_expiry or "2027-12-31")
    )

    store[username] = {
        "password": generate_password_hash(password),
        "role": role,
        "active": True,
        "email": email,
        "license_type": (
            "admin" if role == "admin" else license_type
        ),
        "license_key": license_key,
        "license_expiry": expires_at,
        "expires_at": expires_at,
        "created_at": datetime.now().isoformat(
            timespec="seconds"
        ),
    }

    if persist:
        _write_users(store)

    if audit:
        try:
            audit(
                "admin_user_created",
                username,
                {
                    "role": role,
                    "license_type": license_type,
                    "email_present": bool(email),
                },
                "info",
            )
        except Exception:
            pass

    return {
        "ok": True,
        "code": "user_created",
        "username": username,
    }


def reset_devices(
    target_username: str,
    *,
    audit: Callable[..., Any] | None = None,
    users: dict[str, Any] | None = None,
    persist: bool = True,
) -> dict[str, Any]:

    target_username = _normalize_username(target_username)
    store = users if users is not None else _read_users()

    if (
        not isinstance(store, dict)
        or target_username not in store
    ):
        return {"ok": False, "code": "user_not_found"}

    user = store.get(target_username)

    if not isinstance(user, dict):
        return {"ok": False, "code": "user_invalid"}

    devices = user.get("devices", [])

    old_count = (
        len(devices)
        if isinstance(devices, list)
        else 0
    )

    user["devices"] = []
    store[target_username] = user

    if persist:
        _write_users(store)

    if audit:
        try:
            audit(
                "admin_devices_reset",
                target_username,
                {
                    "removed_device_count": old_count,
                    "device_limit": user.get(
                        "device_limit",
                        1,
                    ),
                },
                "info",
            )
        except Exception:
            pass

    return {
        "ok": True,
        "code": "devices_reset",
        "username": target_username,
        "removed_device_count": old_count,
    }


def update_license(
    target_username: str,
    *,
    license_type: str,
    license_expiry: str,
    license_generator: Callable[[], str],
    audit: Callable[..., Any] | None = None,
    users: dict[str, Any] | None = None,
    persist: bool = True,
) -> dict[str, Any]:

    target_username = _normalize_username(target_username)
    license_type = str(
        license_type or "trial"
    ).strip().lower()
    license_expiry = str(
        license_expiry or ""
    ).strip()

    store = users if users is not None else _read_users()

    if (
        not isinstance(store, dict)
        or target_username not in store
    ):
        return {"ok": False, "code": "user_not_found"}

    user = store.get(target_username)

    if not isinstance(user, dict):
        user = {}

    user["license_type"] = license_type
    user["license_expiry"] = license_expiry

    if license_expiry:
        user["expires_at"] = license_expiry

    if license_type == "lifetime":
        user["expires_at"] = "2099-12-31"
        user["license_expiry"] = "2099-12-31"

    if not user.get("license_key"):
        user["license_key"] = _generate_unique_license_key(
            store,
            license_generator,
        )

    store[target_username] = user

    if persist:
        _write_users(store)

    if audit:
        try:
            audit(
                "admin_license_updated",
                target_username,
                {
                    "license_type": license_type,
                    "license_expiry": (
                        user.get("license_expiry")
                        or user.get("expires_at")
                    ),
                },
                "info",
            )
        except Exception:
            pass

    return {
        "ok": True,
        "code": "license_updated",
        "username": target_username,
    }


def generate_license(
    target_username: str,
    *,
    license_generator: Callable[[], str],
    audit: Callable[..., Any] | None = None,
    users: dict[str, Any] | None = None,
    persist: bool = True,
) -> dict[str, Any]:
    """
    Generate and assign a unique license key.

    This operation does not create, extend or replace
    the user's entitlement.
    """

    target_username = _normalize_username(target_username)
    store = users if users is not None else _read_users()

    if (
        not isinstance(store, dict)
        or target_username not in store
    ):
        return {"ok": False, "code": "user_not_found"}

    user = store.get(target_username)

    if not isinstance(user, dict):
        user = {}

    if (
        str(user.get("role", "")).strip().lower() == "admin"
        or bool(user.get("is_admin"))
    ):
        return {"ok": False, "code": "admin_protected"}

    old_plan = user.get("plan")
    old_type = user.get("license_type")
    old_expires = user.get("expires_at")
    old_license_expiry = user.get("license_expiry")

    license_key = _generate_unique_license_key(
        store,
        license_generator,
    )

    user["license_key"] = license_key
    user["active"] = True

    # Explicit invariant: key generation must not mutate entitlement.
    assert user.get("plan") == old_plan
    assert user.get("license_type") == old_type
    assert user.get("expires_at") == old_expires
    assert user.get("license_expiry") == old_license_expiry

    store[target_username] = user

    if persist:
        _write_users(store)

    if audit:
        try:
            audit(
                "admin_license_generated",
                target_username,
                {
                    "license_key": license_key,
                },
                "info",
            )
        except Exception:
            pass

    return {
        "ok": True,
        "code": "license_generated",
        "username": target_username,
        "license_key": license_key,
    }


def approve_upgrade(
    target_username: str,
    *,
    license_generator: Callable[[], str],
    audit: Callable[..., Any] | None = None,
    users: dict[str, Any] | None = None,
    persist: bool = True,
) -> dict[str, Any]:
    """
    Approve an administrative Pro upgrade using the
    canonical pro_yearly commercial entitlement.
    """

    target_username = _normalize_username(target_username)
    store = users if users is not None else _read_users()

    if (
        not isinstance(store, dict)
        or target_username not in store
    ):
        return {"ok": False, "code": "user_not_found"}

    user = store.get(target_username)

    if not isinstance(user, dict):
        user = {}

    if (
        str(user.get("role", "")).strip().lower() == "admin"
        or bool(user.get("is_admin"))
    ):
        return {"ok": False, "code": "admin_protected"}

    if not user.get("license_key"):
        user["license_key"] = _generate_unique_license_key(
            store,
            license_generator,
        )

    _eg_canonical_apply_plan_to_user_v1(
        user,
        "pro_yearly",
    )

    store[target_username] = user

    if persist:
        _write_users(store)

    if audit:
        try:
            audit(
                "admin_premium_approved",
                target_username,
                {
                    "plan": user.get("plan"),
                    "license_type": user.get("license_type"),
                    "expires_at": user.get("expires_at"),
                },
                "info",
            )
        except Exception:
            pass

    return {
        "ok": True,
        "code": "premium_approved",
        "username": target_username,
        "plan": user.get("plan"),
    }


def toggle_ban(
    target_username: str,
    *,
    audit: Callable[..., Any] | None = None,
    users: dict[str, Any] | None = None,
    persist: bool = True,
) -> dict[str, Any]:

    target_username = _normalize_username(target_username)
    store = users if users is not None else _read_users()

    if (
        not isinstance(store, dict)
        or target_username not in store
    ):
        return {"ok": False, "code": "user_not_found"}

    user = store.get(target_username)

    if not isinstance(user, dict):
        user = {}

    # Do not protect an account merely because its username is "admin".
    # Persisted authority is what matters.
    is_admin_account = bool(
        str(user.get("role", "")).lower() == "admin"
        or user.get("is_admin")
    )

    if is_admin_account:
        return {
            "ok": False,
            "code": "admin_protected",
        }

    new_state = not bool(user.get("is_banned"))

    user["is_banned"] = new_state
    user["active"] = not new_state

    store[target_username] = user

    if persist:
        _write_users(store)

    if audit:
        try:
            audit(
                (
                    "admin_user_banned"
                    if new_state
                    else "admin_user_unbanned"
                ),
                target_username,
                {"is_banned": new_state},
                "warning" if new_state else "info",
            )
        except Exception:
            pass

    return {
        "ok": True,
        "code": (
            "user_banned"
            if new_state
            else "user_unbanned"
        ),
        "username": target_username,
        "is_banned": new_state,
    }
