from flask import Blueprint, render_template

from .services.users import get_users_center_data
from .services.dashboard import get_dashboard_data
from .services.payments import get_payments_center_data
from .services.licenses import get_license_center_data


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


