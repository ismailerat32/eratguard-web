"""
EratGuard Admin Auth Core
=========================

Single authentication/security contract for the new Admin Core.

This module deliberately does not register Flask routes or before_request
hooks. Runtime ownership is transferred only after independent verification.
"""

from __future__ import annotations

import hmac
import os
from typing import Any, Callable, Mapping, Optional

from flask import abort, redirect, request, session
from werkzeug.security import check_password_hash


ADMIN_SESSION_KEYS = (
    "logged_in",
    "username",
    "role",
    "is_admin",
)

LEGACY_ADMIN_SESSION_KEYS = (
    "admin",
    "admin_ok",
    "admin_logged_in",
)

ADMIN_LOGIN_PATH = "/admin/login"
ADMIN_HOME_PATH = "/admin/dashboard"

ADMIN_LOGIN_LIMIT = 8
ADMIN_LOGIN_WINDOW_SECONDS = 15 * 60


def _clean_username(value: Any) -> str:
    return str(value or "").strip()


def _admin_record(user: Any) -> bool:
    """
    Persisted account authority.

    A username string by itself never grants admin authority.
    """
    if not isinstance(user, Mapping):
        return False

    role = str(user.get("role") or "").strip().lower()

    return bool(
        role == "admin"
        or user.get("is_admin") is True
    )


def resolve_user(
    users: Any,
    username: Any,
) -> tuple[str, Optional[Mapping[str, Any]]]:
    """
    Resolve a persisted user with case-insensitive compatibility.
    """
    username = _clean_username(username)

    if not username or not isinstance(users, Mapping):
        return username, None

    direct = users.get(username)

    if isinstance(direct, Mapping):
        return username, direct

    lowered = username.lower()

    for key, value in users.items():
        if (
            str(key).lower() == lowered
            and isinstance(value, Mapping)
        ):
            return str(key), value

    return username, None


def is_persisted_admin(
    users: Any,
    username: Any,
) -> bool:
    _, user = resolve_user(users, username)
    return _admin_record(user)


def verify_admin_password(
    password: Any,
    user: Optional[Mapping[str, Any]] = None,
) -> bool:
    """
    Transitional canonical password policy.

    Primary source:
        ERATGUARD_ADMIN_PASSWORD

    Compatibility fallback:
        persisted Werkzeug password hash, when present.

    Plaintext/SHA256 persisted password fallback is intentionally rejected.
    """
    raw = str(password or "")

    if not raw:
        return False

    env_password = os.environ.get(
        "ERATGUARD_ADMIN_PASSWORD",
        "",
    )

    if env_password:
        try:
            return hmac.compare_digest(
                raw,
                str(env_password),
            )
        except Exception:
            return False

    if not isinstance(user, Mapping):
        return False

    stored = str(
        user.get("password")
        or user.get("password_hash")
        or ""
    )

    if not stored:
        return False

    try:
        return bool(check_password_hash(stored, raw))
    except Exception:
        return False


def clear_admin_session() -> None:
    """
    Remove only authentication-related admin/session identity fields.
    """
    for key in (
        *ADMIN_SESSION_KEYS,
        *LEGACY_ADMIN_SESSION_KEYS,
    ):
        session.pop(key, None)


def establish_admin_session(username: Any) -> None:
    """
    Create the single canonical admin session contract.
    """
    clear_admin_session()

    session["logged_in"] = True
    session["username"] = _clean_username(username)
    session["role"] = "admin"
    session["is_admin"] = True

    # Protect authenticated session state against fixation.
    session.modified = True


def destroy_admin_session() -> None:
    clear_admin_session()
    session.modified = True


def session_contract_valid() -> bool:
    """
    Session-side half of real-admin verification.
    """
    username = _clean_username(
        session.get("username")
    )

    return bool(
        session.get("logged_in") is True
        and username
        and str(
            session.get("role") or ""
        ).strip().lower() == "admin"
        and session.get("is_admin") is True
    )


def is_real_admin(load_users: Callable[[], Any]) -> bool:
    """
    Admin authority requires BOTH:
      1. strict authenticated session
      2. persisted admin account authority
    """
    if not session_contract_valid():
        return False

    try:
        users = load_users()
    except Exception:
        return False

    return is_persisted_admin(
        users,
        session.get("username"),
    )


def authenticate_admin(
    username: Any,
    password: Any,
    load_users: Callable[[], Any],
) -> tuple[bool, str, Optional[Mapping[str, Any]]]:
    """
    Validate identity + admin authority + password.

    Does not mutate Flask session.
    """
    username = _clean_username(username)

    if not username or not str(password or ""):
        return False, username, None

    try:
        users = load_users()
    except Exception:
        return False, username, None

    canonical_username, user = resolve_user(
        users,
        username,
    )

    if not _admin_record(user):
        return False, canonical_username, user

    if not verify_admin_password(
        password,
        user,
    ):
        return False, canonical_username, user

    return True, canonical_username, user


def admin_login_rate_limit(
    rate_limit_check: Optional[Callable[..., Any]],
):
    """
    Canonical admin-login limiter.

    Returns:
        None when request may continue,
        Flask response when blocked.

    Policy:
        8 attempts / 15 minutes.
    """
    if request.path.rstrip("/") != ADMIN_LOGIN_PATH:
        return None

    if request.method.upper() != "POST":
        return None

    if not callable(rate_limit_check):
        return None

    try:
        ok, retry_after = rate_limit_check(
            "admin-login",
            ADMIN_LOGIN_LIMIT,
            ADMIN_LOGIN_WINDOW_SECONDS,
        )
    except Exception:
        # Availability compatibility with current EratGuard behavior.
        return None

    if ok:
        return None

    try:
        retry_after = max(1, int(retry_after))
    except Exception:
        retry_after = 60

    response = (
        "Çok fazla admin giriş denemesi. "
        "Lütfen daha sonra tekrar deneyin.",
        429,
        {
            "Retry-After": str(retry_after),
            "Cache-Control": "no-store",
        },
    )

    return response


def admin_auth_boundary(
    load_users: Callable[[], Any],
):
    """
    Single Admin Core authorization boundary.

    HTML:
        unauthenticated -> /admin/login

    Admin API:
        unauthenticated -> 403

    Public:
        /admin/login
        /admin/static/*
    """
    raw_path = str(request.path or "")
    path = raw_path.rstrip("/") or "/"

    is_admin_page = (
        path == "/admin"
        or path.startswith("/admin/")
    )

    is_admin_api = (
        path == "/api/admin"
        or path.startswith("/api/admin/")
    )

    if not (is_admin_page or is_admin_api):
        return None

    if path == ADMIN_LOGIN_PATH:
        return None

    if path.startswith("/admin/static/"):
        return None

    if is_real_admin(load_users):
        return None

    if is_admin_api:
        return abort(403)

    next_path = (
        raw_path
        if raw_path.startswith("/")
        else ADMIN_HOME_PATH
    )

    return redirect(
        ADMIN_LOGIN_PATH + "?next=" + next_path,
        code=302,
    )


# ============================================================================
# ADMIN CORE ROUTE HANDLERS
# ============================================================================
# These handlers are intentionally registration-free.
# dashboard_web.py does not yet delegate runtime ownership to them.
# ============================================================================

from urllib.parse import urlsplit

from flask import make_response, render_template


def _safe_admin_next(value: Any) -> str:
    """
    Accept only local /admin paths.

    Prevents external/open redirects and protocol-relative redirects.
    """
    raw = str(value or "").strip()

    if not raw:
        return ADMIN_HOME_PATH

    try:
        parsed = urlsplit(raw)
    except Exception:
        return ADMIN_HOME_PATH

    if parsed.scheme or parsed.netloc:
        return ADMIN_HOME_PATH

    if raw.startswith("//"):
        return ADMIN_HOME_PATH

    path = str(parsed.path or "")

    if not (
        path == "/admin"
        or path.startswith("/admin/")
    ):
        return ADMIN_HOME_PATH

    # Login should never redirect back into itself.
    if path.rstrip("/") == ADMIN_LOGIN_PATH:
        return ADMIN_HOME_PATH

    result = path

    if parsed.query:
        result += "?" + parsed.query

    return result


def admin_login_view(
    load_users: Callable[[], Any],
    rate_limit_check: Optional[Callable[..., Any]] = None,
):
    """
    Canonical /admin/login handler.

    GET:
        render login

    POST:
        rate limit -> identity -> persisted admin authority ->
        password -> canonical session -> local admin redirect
    """
    if request.method.upper() == "GET":
        # Do not destroy an already authenticated admin session merely
        # because the login page was visited.
        if is_real_admin(load_users):
            return redirect(ADMIN_HOME_PATH, code=302)

        return render_template(
            "admin_login.html",
            error="",
        )

    limited = admin_login_rate_limit(
        rate_limit_check
    )

    if limited is not None:
        return limited

    username = _clean_username(
        request.form.get("username")
    )

    password = str(
        request.form.get("password") or ""
    )

    ok, canonical_username, _user = authenticate_admin(
        username,
        password,
        load_users,
    )

    if not ok:
        # Any stale identity from a previous/legacy flow must not survive
        # a failed authentication attempt.
        clear_admin_session()

        response = make_response(
            render_template(
                "admin_login.html",
                error="Admin girişi başarısız.",
            )
        )
        response.headers["Cache-Control"] = "no-store"
        return response

    establish_admin_session(
        canonical_username
    )

    target = _safe_admin_next(
        request.args.get("next")
    )

    response = make_response(
        redirect(target, code=302)
    )

    response.headers["Cache-Control"] = "no-store"

    return response


def admin_logout_view():
    """
    Canonical admin logout.

    Old admin identity fields are removed together with the new contract.
    """
    destroy_admin_session()

    response = make_response(
        redirect(ADMIN_LOGIN_PATH, code=302)
    )

    response.headers["Cache-Control"] = "no-store"

    # Retire historical admin compatibility cookie when present.
    response.delete_cookie(
        "ss_admin_mobile",
        path="/",
    )

    return response
