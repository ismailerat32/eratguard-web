from flask import Blueprint, render_template

from .services.users import get_users_center_data
from .services.dashboard import get_dashboard_data
from .services.payments import get_payments_center_data
from .services.licenses import get_license_center_data
from .services.commercial_actions import approve_payment_request, reject_payment_request
from .services.user_actions import reset_devices, toggle_ban

from .services.user_actions import (
    create_user,
    update_license,
    generate_license,
    approve_upgrade,
)



admin_bp = Blueprint(
    "admin",
    __name__,
    url_prefix="/admin",
    template_folder="templates",
    static_folder="static",
)


@admin_bp.route("/")
@admin_bp.route("/dashboard")
def dashboard():
    data = get_dashboard_data()

    return render_template(
        "admin/dashboard.html",
        **data,
    )


@admin_bp.route("/users")
def users():
    data = get_users_center_data()

    return render_template("admin/users.html",
        **data,
    )


# ERATGUARD NEW ADMIN SECURITY CENTER
@admin_bp.route("/security")
def security_center():
    from flask import render_template
    from .services.security import get_security_center

    context = get_security_center()

    return render_template(
        "admin/security.html",
        **context,
    )


@admin_bp.route("/spam-logs")
def spam_logs_center():
    from .services.spam import get_spam_center_data

    data = get_spam_center_data(limit=100)

    return render_template(
        "admin/spam_logs.html",
        data=data,
    )


# ------------------------------------------------------------------
# ERATGUARD PHASE 7D.7 - CANONICAL COMMERCIAL ADMIN CENTERS
# ------------------------------------------------------------------

@admin_bp.route("/payments")
@admin_bp.route("/payment-requests")
@admin_bp.route("/license-requests")
def payments_center():
    data = get_payments_center_data()

    return render_template(
        "admin/payments.html",
        **data,
    )


@admin_bp.route("/licenses")
def licenses_center():
    data = get_license_center_data()

    return render_template(
        "admin/licenses.html",
        **data,
    )

# ERATGUARD PHASE 7D.9 CANONICAL SYSTEM CENTER
@admin_bp.route("/system")
def system_center():
    from .services.system import get_system_center_data

    data = get_system_center_data()

    return render_template(
        "admin/system.html",
        **data,
    )



# ERATGUARD PHASE 7D.11 CANONICAL SETTINGS CENTER
@admin_bp.route("/settings")
def settings_center():
    from .services.settings import get_settings_center_data

    data = get_settings_center_data()

    return render_template(
        "admin/settings.html",
        **data,
    )

# ERATGUARD PHASE 7D.14 CANONICAL NOTIFICATIONS CENTER
@admin_bp.route("/notifications")
def notifications_center():
    from .services.notifications import (
        get_notifications_center_data,
    )

    data = get_notifications_center_data(
        limit=100
    )

    return render_template(
        "admin/notifications.html",
        **data,
    )



# ===== EVA AI ASSISTANT (Gemini API) =====


# ================================================================


# ================================================================
# ERATGUARD ADMIN CORE — SAFE USER ACTIONS V1
# reset-devices + toggle-ban
#
# Persistence/audit are injected by application startup.
# No dashboard_web reverse import.
# ================================================================

_user_action_runtime = {}


def configure_user_action_runtime(
    *,
    load_users,
    save_users,
    audit_log,
):
    _user_action_runtime.clear()

    _user_action_runtime.update({
        "load_users": load_users,
        "save_users": save_users,
        "audit_log": audit_log,
    })


def _user_action_runtime_ready():
    return all(
        callable(_user_action_runtime.get(name))
        for name in (
            "load_users",
            "save_users",
            "audit_log",
        )
    )


def _user_action_redirect(result):
    from flask import redirect
    from urllib.parse import urlencode

    if not isinstance(result, dict):
        result = {
            "ok": False,
            "code": "action_error",
        }

    code = str(
        result.get("code") or "action_error"
    )

    params = {"ok": code}

    username = str(
        result.get("username") or ""
    ).strip()

    if username and code == "devices_reset":
        params["username"] = username

    return redirect(
        "/admin/users?" + urlencode(params)
    )


@admin_bp.route(
    "/reset-devices/<target_username>",
    methods=["POST"],
)
def reset_user_devices(target_username):
    from flask import abort

    if not _user_action_runtime_ready():
        abort(503)

    users = _user_action_runtime["load_users"]()

    if not isinstance(users, dict):
        users = {}

    result = reset_devices(
        target_username,
        users=users,
        persist=False,
        audit=None,
    )

    if result.get("ok"):
        _user_action_runtime["save_users"](
            users
        )

        try:
            _user_action_runtime["audit_log"](
                "admin_devices_reset",
                target_username,
                {
                    "removed_device_count":
                        result.get(
                            "removed_device_count",
                            0,
                        ),
                    "device_limit":
                        users.get(
                            target_username,
                            {},
                        ).get(
                            "device_limit",
                            1,
                        ),
                },
                "info",
            )
        except Exception:
            pass

    return _user_action_redirect(result)


@admin_bp.route(
    "/toggle-ban/<target_username>",
    methods=["POST"],
)
def toggle_user_ban(target_username):
    from flask import abort

    if not _user_action_runtime_ready():
        abort(503)

    users = _user_action_runtime["load_users"]()

    if not isinstance(users, dict):
        users = {}

    result = toggle_ban(
        target_username,
        users=users,
        persist=False,
        audit=None,
    )

    if result.get("ok"):
        _user_action_runtime["save_users"](
            users
        )

        is_banned = bool(
            result.get("is_banned")
        )

        try:
            _user_action_runtime["audit_log"](
                (
                    "admin_user_banned"
                    if is_banned
                    else "admin_user_unbanned"
                ),
                target_username,
                {"is_banned": is_banned},
                (
                    "warning"
                    if is_banned
                    else "info"
                ),
            )
        except Exception:
            pass

    return _user_action_redirect(result)


# ERATGUARD ADMIN CORE — COMMERCIAL ACTION BRIDGE V1
# Runtime dependencies are injected by dashboard_web at startup.
# Admin Core never imports dashboard_web.
# ================================================================

_commercial_runtime = {}


def configure_commercial_runtime(
    *,
    load_users,
    save_users,
    load_payment_requests,
    save_payment_requests,
    generate_license_key,
    audit_log,
):
    _commercial_runtime.clear()

    _commercial_runtime.update({
        "load_users": load_users,
        "save_users": save_users,
        "load_payment_requests": load_payment_requests,
        "save_payment_requests": save_payment_requests,
        "generate_license_key": generate_license_key,
        "audit_log": audit_log,
    })


def _commercial_runtime_ready():
    required = (
        "load_users",
        "save_users",
        "load_payment_requests",
        "save_payment_requests",
        "generate_license_key",
        "audit_log",
    )

    return all(
        callable(_commercial_runtime.get(name))
        for name in required
    )


@admin_bp.route(
    "/license-request/approve/<order_no>",
    methods=["POST"],
)
def approve_license_request(order_no):
    from flask import redirect, abort

    if not _commercial_runtime_ready():
        abort(503)

    users = _commercial_runtime["load_users"]()
    requests_data = _commercial_runtime["load_payment_requests"]()

    if not isinstance(users, dict):
        users = {}

    if not isinstance(requests_data, list):
        requests_data = []

    result = approve_payment_request(
        requests_data,
        users,
        order_no,
        license_key_factory=_commercial_runtime[
            "generate_license_key"
        ],
    )

    if result.get("changed"):
        _commercial_runtime["save_users"](users)
        _commercial_runtime["save_payment_requests"](
            requests_data
        )

        try:
            _commercial_runtime["audit_log"](
                "admin_payment_request_approved",
                result.get("username", ""),
                {
                    "order_no": order_no,
                    "license_key": result.get(
                        "license_key",
                        "",
                    ),
                    "plan": result.get("plan", ""),
                },
                "info",
            )
        except Exception:
            pass

    return redirect("/admin/payment-requests")


@admin_bp.route(
    "/license-request/reject/<order_no>",
    methods=["POST"],
)
def reject_license_request(order_no):
    from flask import redirect, abort

    if not _commercial_runtime_ready():
        abort(503)

    requests_data = _commercial_runtime[
        "load_payment_requests"
    ]()

    if not isinstance(requests_data, list):
        requests_data = []

    result = reject_payment_request(
        requests_data,
        order_no,
    )

    if result.get("changed"):
        _commercial_runtime["save_payment_requests"](
            requests_data
        )

        try:
            _commercial_runtime["audit_log"](
                "admin_payment_request_rejected",
                "",
                {"order_no": order_no},
                "warning",
            )
        except Exception:
            pass

    return redirect("/admin/payment-requests")


@admin_bp.route("/eva-chat", methods=["POST"])
def eva_chat():
    from flask import request, jsonify
    from .services.eva import ask_eva

    try:
        payload = request.get_json(silent=True) or {}
        message = str(payload.get("message", "")).strip()
        history = payload.get("history", [])

        if not message:
            return jsonify({"ok": False, "error": "Mesaj boş olamaz."}), 400

        if not isinstance(history, list):
            history = []

        ok, answer = ask_eva(message, history)

        return jsonify({"ok": ok, "answer": answer})

    except Exception as e:
        return jsonify({"ok": False, "error": "Sunucu hatası: " + repr(e)}), 500
# ===== EVA AI ASSISTANT END =====

# ==================================================================
# ERATGUARD PHASE 8B.7C.5B - REAL COMMAND API
# Canonical read-only Command Core orchestration endpoint.
# ==================================================================

@admin_bp.route("/api/command", methods=["POST"])
def command_api():
    from flask import jsonify, request
    from .services.command import execute_admin_command

    payload = request.get_json(silent=True) or {}

    action = str(
        payload.get("action", "")
    ).strip().lower()

    if not action:
        return jsonify({
            "ok": False,
            "status": "INVALID_REQUEST",
            "error": "Command action is required.",
        }), 400

    result = execute_admin_command(action)

    if not result.get("ok"):
        if result.get("status") == "UNKNOWN_COMMAND":
            return jsonify(result), 404

        return jsonify(result), 500

    return jsonify(result), 200


# ===== /ERATGUARD PHASE 8B.7C.5B - REAL COMMAND API =====

# ==================================================================
# ERATGUARD PHASE 8B.7C.7 - COMMAND EXECUTION ARCHITECTURE
# Canonical Command Core mode dispatcher.
# ==================================================================

@admin_bp.route("/api/command/dispatch", methods=["POST"])
def command_dispatch_api():
    from flask import jsonify, request
    from .services.command import execute_command_mode

    payload = request.get_json(silent=True) or {}

    action = str(
        payload.get("action", "")
    ).strip().lower()

    mode = str(
        payload.get("mode", "inspect")
    ).strip().lower()

    if not action:
        return jsonify({
            "ok": False,
            "status": "INVALID_REQUEST",
            "error": "Command action is required.",
        }), 400

    result = execute_command_mode(
        action,
        mode,
    )

    if result.get("ok"):
        return jsonify(result), 200

    status = result.get("status")

    if status == "UNKNOWN_COMMAND":
        return jsonify(result), 404

    if status in {
        "UNKNOWN_MODE",
        "MODE_NOT_SUPPORTED",
    }:
        return jsonify(result), 400

    if status in {
        "EXECUTION_LOCKED",
        "EXECUTOR_NOT_INSTALLED",
    }:
        return jsonify(result), 409

    return jsonify(result), 500


# ===== /ERATGUARD PHASE 8B.7C.7 - COMMAND EXECUTION ARCHITECTURE =====


# ==================================================================
# ERATGUARD PHASE 8B.7C.10A - CONTROLLED OPERATION REGISTRY API
# Capability metadata only. No operation execution occurs here.
# ==================================================================

@admin_bp.route(
    "/api/command/operations",
    methods=["POST"]
)
def command_operations_api():
    from flask import jsonify, request

    from .services.command import (
        get_command_operations,
        resolve_command_operation,
    )

    payload = request.get_json(
        silent=True
    ) or {}

    action = str(
        payload.get(
            "action",
            ""
        )
    ).strip().lower()

    operation = str(
        payload.get(
            "operation",
            ""
        )
    ).strip().lower()

    if not action:
        return jsonify({
            "ok": False,
            "status": "INVALID_REQUEST",
            "error": "Command action is required.",
        }), 400

    if operation:
        result = resolve_command_operation(
            action,
            operation
        )
    else:
        result = get_command_operations(
            action
        )

    if result.get("ok"):
        return jsonify(result), 200

    status = result.get("status")

    if status in (
        "UNKNOWN_COMMAND",
        "UNKNOWN_OPERATION",
    ):
        return jsonify(result), 404

    return jsonify(result), 400


# ===== /ERATGUARD PHASE 8B.7C.10A - CONTROLLED OPERATION REGISTRY API =====

# ==================================================================
# ERATGUARD PHASE 8B.7C.10C-C - READ OPERATION API BINDING
#
# Explicit reviewed read-only operation execution endpoint.
#
# SECURITY:
# - Operation ownership remains server-side.
# - No arbitrary callable/module/path.
# - No generic executor.
# - Refresh/write operations remain fail-closed.
# ==================================================================

@admin_bp.route(
    "/api/command/operation/execute",
    methods=["POST"]
)
def command_operation_execute_api():
    from flask import jsonify, request

    from .services.command import execute_command_operation

    payload = request.get_json(
        silent=True
    ) or {}

    action = str(
        payload.get(
            "action",
            ""
        )
    ).strip().lower()

    operation = str(
        payload.get(
            "operation",
            ""
        )
    ).strip().lower()

    if not action:
        return jsonify({
            "ok": False,
            "status": "INVALID_REQUEST",
            "error": "Command action is required.",
        }), 400

    result = execute_command_operation(
        action,
        operation,
    )

    if result.get("ok"):
        return jsonify(result), 200

    status = result.get(
        "status",
        "OPERATION_FAILED"
    )

    if status in {
        "UNKNOWN_COMMAND",
        "UNKNOWN_OPERATION",
        "HANDLER_NOT_INSTALLED",
    }:
        return jsonify(result), 404

    if status in {
        "INVALID_REQUEST",
    }:
        return jsonify(result), 400

    if status in {
        "OPERATION_LOCKED",
        "WRITE_EXECUTION_LOCKED",
    }:
        return jsonify(result), 409

    return jsonify(result), 500


# ===== /ERATGUARD PHASE 8B.7C.10C-C - READ OPERATION API BINDING =====


# ============================================================
# ERATGUARD ADMIN CORE — CANONICAL USER ACTION ROUTES
# ============================================================

@admin_bp.route("/add-user", methods=["POST"])
def add_user_action():
    if not _user_action_runtime_ready():
        abort(503)

    users = _user_action_runtime["load_users"]()

    result = create_user(
        username=request.form.get("username", ""),
        email=request.form.get("email", ""),
        password=request.form.get("password", ""),
        role=request.form.get("role", "user"),
        license_type=request.form.get(
            "license_type",
            "trial",
        ),
        license_expiry=request.form.get(
            "license_expiry",
            "",
        ),
        password_policy=_user_action_runtime[
            "password_policy"
        ],
        license_generator=_user_action_runtime[
            "generate_license_key"
        ],
        audit=_user_action_runtime["audit_log"],
        users=users,
        persist=False,
    )

    if result.get("ok"):
        _user_action_runtime["save_users"](users)

    return redirect(url_for("admin.users"))


@admin_bp.route(
    "/update-license/<target_username>",
    methods=["POST"],
)
def update_user_license(target_username):
    if not _user_action_runtime_ready():
        abort(503)

    users = _user_action_runtime["load_users"]()

    result = update_license(
        target_username,
        license_type=request.form.get(
            "license_type",
            "trial",
        ),
        license_expiry=request.form.get(
            "license_expiry",
            "",
        ),
        license_generator=_user_action_runtime[
            "generate_license_key"
        ],
        audit=_user_action_runtime["audit_log"],
        users=users,
        persist=False,
    )

    if result.get("ok"):
        _user_action_runtime["save_users"](users)

    return redirect(url_for("admin.users"))


@admin_bp.route(
    "/generate-license/<target_username>",
    methods=["POST"],
)
def generate_user_license(target_username):
    if not _user_action_runtime_ready():
        abort(503)

    users = _user_action_runtime["load_users"]()

    result = generate_license(
        target_username,
        license_generator=_user_action_runtime[
            "generate_license_key"
        ],
        audit=_user_action_runtime["audit_log"],
        users=users,
        persist=False,
    )

    if result.get("ok"):
        _user_action_runtime["save_users"](users)

    return redirect(url_for("admin.users"))


@admin_bp.route(
    "/approve-upgrade/<target_username>",
    methods=["POST"],
)
def approve_user_upgrade(target_username):
    if not _user_action_runtime_ready():
        abort(503)

    users = _user_action_runtime["load_users"]()

    result = approve_upgrade(
        target_username,
        license_generator=_user_action_runtime[
            "generate_license_key"
        ],
        audit=_user_action_runtime["audit_log"],
        users=users,
        persist=False,
    )

    if result.get("ok"):
        _user_action_runtime["save_users"](users)

    return redirect(url_for("admin.users"))


# ============================================================
# ERATGUARD ADMIN CORE — USER DETAIL RUNTIME
# ============================================================

_user_detail_runtime = {}


def configure_user_detail_runtime(
    *,
    load_users,
    load_user_sessions,
    recent_audit_logs,
):
    _user_detail_runtime.clear()
    _user_detail_runtime.update({
        "load_users": load_users,
        "load_user_sessions": load_user_sessions,
        "recent_audit_logs": recent_audit_logs,
    })


def _user_detail_runtime_ready():
    return all(
        callable(_user_detail_runtime.get(k))
        for k in (
            "load_users",
            "load_user_sessions",
            "recent_audit_logs",
        )
    )


@admin_bp.route("/user/<target_username>", methods=["GET"])
def user_detail(target_username):
    if not _user_detail_runtime_ready():
        abort(503)

    try:
        users = _user_detail_runtime["load_users"]()
    except Exception:
        users = {}

    if not isinstance(users, dict):
        users = {}

    user = users.get(target_username)

    if not isinstance(user, dict):
        return render_template(
            "admin/user_detail.html",
            found=False,
            target_username=target_username,
        ), 404

    try:
        sessions = _user_detail_runtime[
            "load_user_sessions"
        ]()
    except Exception:
        sessions = {}

    if not isinstance(sessions, dict):
        sessions = {}

    sess = sessions.get(target_username, {})
    if not isinstance(sess, dict):
        sess = {}

    try:
        audit_events = _user_detail_runtime[
            "recent_audit_logs"
        ](200)
    except Exception:
        audit_events = []

    if not isinstance(audit_events, list):
        audit_events = []

    user_events = []

    for ev in audit_events:
        try:
            if str(ev.get("username", "")) == str(
                target_username
            ):
                user_events.append(ev)
        except Exception:
            pass

    user_events = user_events[:30]

    role = str(user.get("role", "user") or "user")

    # Persisted authority only.
    is_admin = bool(
        role.lower() == "admin"
        or user.get("is_admin")
    )

    active = bool(user.get("active", True))
    banned = bool(user.get("is_banned", False))

    license_type = str(
        user.get("license_type")
        or user.get("license_mode")
        or "trial"
    )

    license_key = str(
        user.get("license_key") or "-"
    )

    if len(license_key) > 10:
        masked_license_key = (
            license_key[:9]
            + "..."
            + license_key[-5:]
        )
    else:
        masked_license_key = license_key

    expires_at = str(
        user.get("expires_at")
        or user.get("license_expiry")
        or "-"
    )

    email = str(user.get("email") or "-")

    last_seen = str(
        sess.get("last_seen")
        or user.get("last_seen")
        or "-"
    )

    last_login = str(
        sess.get("last_login")
        or user.get("last_login")
        or "-"
    )

    last_ip = str(
        sess.get("last_ip")
        or user.get("last_ip")
        or "-"
    )

    user_agent = str(
        sess.get("user_agent")
        or "-"
    )[:140]

    devices = user.get("devices", [])
    device_count = (
        len(devices)
        if isinstance(devices, list)
        else 0
    )

    try:
        device_limit = max(
            1,
            int(user.get("device_limit", 1)),
        )
    except Exception:
        device_limit = 1

    if is_admin:
        account_status = "ADMIN"
        risk_label = "Yetkili"
        health = "admin"
    elif banned:
        account_status = "BANLI"
        risk_label = "Yüksek"
        health = "danger"
    elif not active:
        account_status = "PASİF"
        risk_label = "Orta"
        health = "warning"
    else:
        account_status = "AKTİF"
        risk_label = "Düşük"
        health = "good"

    return render_template(
        "admin/user_detail.html",
        found=True,
        target_username=target_username,
        email=email,
        role=role,
        is_admin=is_admin,
        active=active,
        banned=banned,
        license_type=license_type,
        masked_license_key=masked_license_key,
        expires_at=expires_at,
        last_seen=last_seen,
        last_login=last_login,
        last_ip=last_ip,
        user_agent=user_agent,
        device_count=device_count,
        device_limit=device_limit,
        account_status=account_status,
        risk_label=risk_label,
        health=health,
        user_events=user_events,
    )


# ============================================================
# ERATGUARD ADMIN CORE — FORGOT MAIL DIAGNOSTIC
# ============================================================

from mailer import send_mail as _admin_send_mail


_mail_diagnostic_runtime = {}


def configure_mail_diagnostic_runtime(
    *,
    load_users,
):
    _mail_diagnostic_runtime.clear()
    _mail_diagnostic_runtime.update({
        "load_users": load_users,
    })


def _mail_diagnostic_runtime_ready():
    return callable(
        _mail_diagnostic_runtime.get("load_users")
    )


def _mask_diagnostic_email(value):
    value = str(value or "").strip()

    if "@" not in value:
        return "EMPTY"

    left, right = value.split("@", 1)
    return left[:2] + "***@" + right


@admin_bp.route(
    "/forgot-mail-diagnostic",
    methods=["GET", "POST"],
)
def forgot_mail_diagnostic():
    if not _mail_diagnostic_runtime_ready():
        abort(503)

    result = None
    identity = ""

    if request.method == "POST":
        identity = (
            request.form.get("identity")
            or request.form.get("username_or_email")
            or request.form.get("email")
            or request.form.get("username")
            or ""
        ).strip()

        try:
            users = _mail_diagnostic_runtime[
                "load_users"
            ]()
        except Exception:
            users = {}

        if not isinstance(users, dict):
            users = {}

        found_username = None
        found_user = None

        for uname, udata in users.items():
            if not isinstance(udata, dict):
                continue

            email = str(
                udata.get("email", "") or ""
            ).strip().lower()

            if (
                str(uname).strip().lower()
                == identity.lower()
                or email == identity.lower()
            ):
                found_username = uname
                found_user = udata
                break

        if found_username and found_user:
            target_email = str(
                found_user.get("email", "") or ""
            ).strip()

            if target_email:
                try:
                    ok, msg = _admin_send_mail(
                        to_email=target_email,
                        subject=(
                            "EratGuard Forgot Diagnostic"
                        ),
                        body=(
                            "Bu mesaj geldiyse EratGuard "
                            "canlı SMTP sistemi bu kullanıcı "
                            "e-postasına gönderebiliyor."
                        ),
                    )
                except Exception as exc:
                    ok = False
                    msg = str(exc)
            else:
                ok = False
                msg = "Kullanıcı email alanı boş"

            result = {
                "account_found": True,
                "matched_user": found_username,
                "target_email_masked":
                    _mask_diagnostic_email(
                        target_email
                    ),
                "mail_ok": ok,
                "mail_msg": msg,
            }

        else:
            result = {
                "account_found": False,
                "matched_user": "NONE",
                "target_email_masked": "NONE",
                "mail_ok": False,
                "mail_msg": (
                    "Bu identity canlı kullanıcı "
                    "datasında bulunamadı."
                ),
            }

    html = f"""<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>EratGuard Admin Forgot Diagnostic</title>
<style>
body{{font-family:Arial,sans-serif;background:#010805;color:#eefaf2;padding:24px}}
.card{{max-width:680px;margin:auto;background:#06170f;border:1px solid rgba(120,255,150,.22);border-radius:22px;padding:24px}}
input,button{{width:100%;box-sizing:border-box;padding:14px;border-radius:14px;margin-top:10px;font-size:16px}}
input{{background:#000;color:#fff;border:1px solid #284}}
button{{border:0;background:linear-gradient(90deg,#00d66f,#18c6e8);color:white;font-weight:800}}
pre{{white-space:pre-wrap;background:#000;padding:16px;border-radius:14px;color:#9f9}}
a{{color:#a9c8ff}}
</style>
</head>
<body>
<div class="card">
<h1>Forgot Mail Diagnostic</h1>
<p>Admin-only canlı teşhis. Kullanıcıya bilgi sızdırmaz.</p>
<form method="post">
<input name="identity" placeholder="Kullanıcı adı veya e-posta" value="{identity}">
<button type="submit">Kontrol Et ve Test Maili Gönder</button>
</form>
<pre>{result if result else "Henüz test yapılmadı."}</pre>
<a href="/admin">← Admin paneline dön</a>
</div>
</body>
</html>"""

    return html

