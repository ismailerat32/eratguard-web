"""
ERATGUARD PHASE 8B.7C.5B - REAL COMMAND SERVICE

Read-only command orchestration layer for the canonical admin package.

This service does not mutate EratGuard state.
It resolves Command Core actions to the existing canonical
admin services and returns a stable JSON-safe command contract.
"""

from datetime import datetime, timezone


COMMAND_OWNERSHIP = {
    "ai-analysis": {
        "label": "AI ANALYSIS",
        "module": "security",
        "href": "/admin/security",
    },
    "network": {
        "label": "NETWORK",
        "module": "system",
        "href": "/admin/system",
    },
    "firewall": {
        "label": "FIREWALL",
        "module": "security",
        "href": "/admin/security",
    },
    "devices": {
        "label": "DEVICES",
        "module": "users",
        "href": "/admin/users",
    },
    "quarantine": {
        "label": "QUARANTINE",
        "module": "security",
        "href": "/admin/security",
    },
    "reports": {
        "label": "REPORTS",
        "module": "security",
        "href": "/admin/security",
    },
    "licenses": {
        "label": "LICENSES",
        "module": "licenses",
        "href": "/admin/licenses",
    },
    "sms-shield": {
        "label": "SMS SHIELD",
        "module": "spam",
        "href": "/admin/spam-logs",
    },
    "eva-core": {
        "label": "EVA CORE",
        "module": "eva",
        "href": "/admin/eva-chat",
    },
}


def _utc_now():
    return datetime.now(timezone.utc).isoformat()


def _safe_count(value):
    if value is None:
        return 0

    if isinstance(value, (list, tuple, set, dict)):
        return len(value)

    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _first(mapping, *names, default=None):
    if not isinstance(mapping, dict):
        return default

    for name in names:
        value = mapping.get(name)

        if value is not None:
            return value

    return default


def _security_snapshot():
    from .security import get_security_center

    data = get_security_center() or {}

    return {
        "threat_level": _first(
            data,
            "threat_level",
            "risk_level",
            "status",
            default="UNKNOWN",
        ),
        "warnings": _first(
            data,
            "security_warnings",
            "warnings",
            "warning_count",
            default=0,
        ),
        "blocked": _first(
            data,
            "blocked",
            "blocked_count",
            "quarantine_count",
            default=0,
        ),
        "events": _first(
            data,
            "audit_events",
            "events",
            "event_count",
            default=0,
        ),
    }


def _system_snapshot():
    from .system import get_system_center_data

    data = get_system_center_data() or {}

    return {
        "status": _first(
            data,
            "system",
            "status",
            "engine_status",
            default="ONLINE",
        ),
        "uptime": _first(
            data,
            "uptime",
            "runtime_uptime",
            default="UNKNOWN",
        ),
        "network": _first(
            data,
            "network",
            "network_status",
            "internet",
            default="MONITORING",
        ),
    }


def _users_snapshot():
    from .users import get_users_center_data

    data = get_users_center_data() or {}

    users = _first(
        data,
        "users",
        "items",
        "records",
        default=[],
    )

    active = _first(
        data,
        "active_users",
        "active",
        "online_users",
        default=None,
    )

    return {
        "users": _safe_count(users),
        "active": (
            _safe_count(active)
            if active is not None
            else _safe_count(users)
        ),
    }


def _licenses_snapshot():
    from .licenses import get_license_center_data

    data = get_license_center_data() or {}

    licenses = _first(
        data,
        "licenses",
        "items",
        "records",
        default=[],
    )

    used = _first(
        data,
        "used_licenses",
        "used",
        "active_licenses",
        default=None,
    )

    return {
        "licenses": _safe_count(licenses),
        "used": (
            _safe_count(used)
            if used is not None
            else 0
        ),
    }


def _spam_snapshot():
    from .spam import get_spam_center_data

    data = get_spam_center_data(limit=100)

    if isinstance(data, dict):
        logs = _first(
            data,
            "logs",
            "items",
            "records",
            "spam_logs",
            default=[],
        )
    else:
        logs = data or []

    return {
        "logs": _safe_count(logs),
    }


def _eva_snapshot():
    return {
        "status": "READY",
        "endpoint": "/admin/eva-chat",
    }


def _load_module_snapshot(module):
    loaders = {
        "security": _security_snapshot,
        "system": _system_snapshot,
        "users": _users_snapshot,
        "licenses": _licenses_snapshot,
        "spam": _spam_snapshot,
        "eva": _eva_snapshot,
    }

    loader = loaders.get(module)

    if loader is None:
        return {}

    return loader()


def execute_admin_command(action):
    action = str(action or "").strip().lower()

    config = COMMAND_OWNERSHIP.get(action)

    if config is None:
        return {
            "ok": False,
            "action": action,
            "status": "UNKNOWN_COMMAND",
            "error": "Unknown EratGuard command action.",
            "allowed_actions": sorted(COMMAND_OWNERSHIP),
            "timestamp": _utc_now(),
        }

    try:
        snapshot = _load_module_snapshot(
            config["module"]
        )

        return {
            "ok": True,
            "action": action,
            "label": config["label"],
            "module": config["module"],
            "href": config["href"],
            "status": "READY",
            "read_only": True,
            "snapshot": snapshot,
            "timestamp": _utc_now(),
        }

    except Exception as exc:
        return {
            "ok": False,
            "action": action,
            "label": config["label"],
            "module": config["module"],
            "href": config["href"],
            "status": "SERVICE_ERROR",
            "read_only": True,
            "error": str(exc),
            "timestamp": _utc_now(),
        }


# ===== /ERATGUARD PHASE 8B.7C.5B - REAL COMMAND SERVICE =====

# ==================================================================
# ERATGUARD PHASE 8B.7C.7 - COMMAND EXECUTION ARCHITECTURE
#
# Canonical Command Core capability contract.
#
# Modes:
#   inspect -> obtain live read-only snapshot
#   open    -> resolve canonical admin module
#   execute -> explicit command execution contract
#
# Phase 8B.7C.7 does NOT perform destructive writes.
# ==================================================================

COMMAND_CAPABILITIES = {
    "ai-analysis": {
        "modes": ["inspect", "open"],
        "risk": "READ_ONLY",
        "execute_enabled": False,
        "requires_confirmation": False,
        "description": "Inspect AI security analysis state.",
    },

    "network": {
        "modes": ["inspect", "open"],
        "risk": "READ_ONLY",
        "execute_enabled": False,
        "requires_confirmation": False,
        "description": "Inspect system and network telemetry.",
    },

    "firewall": {
        "modes": ["inspect", "open", "execute"],
        "risk": "CONTROLLED_WRITE",
        "execute_enabled": False,
        "requires_confirmation": True,
        "description": "Firewall command capability.",
    },

    "devices": {
        "modes": ["inspect", "open"],
        "risk": "READ_ONLY",
        "execute_enabled": False,
        "requires_confirmation": False,
        "description": "Inspect active user and device state.",
    },

    "quarantine": {
        "modes": ["inspect", "open", "execute"],
        "risk": "CONTROLLED_WRITE",
        "execute_enabled": False,
        "requires_confirmation": True,
        "description": "Quarantine command capability.",
    },

    "reports": {
        "modes": ["inspect", "open"],
        "risk": "READ_ONLY",
        "execute_enabled": False,
        "requires_confirmation": False,
        "description": "Inspect security and audit reports.",
    },

    "licenses": {
        "modes": ["inspect", "open", "execute"],
        "risk": "CONTROLLED_WRITE",
        "execute_enabled": False,
        "requires_confirmation": True,
        "description": "License administration capability.",
    },

    "sms-shield": {
        "modes": ["inspect", "open", "execute"],
        "risk": "CONTROLLED_WRITE",
        "execute_enabled": False,
        "requires_confirmation": True,
        "description": "SMS Shield command capability.",
    },

    "eva-core": {
        "modes": ["inspect"],
        "risk": "READ_ONLY",
        "execute_enabled": False,
        "requires_confirmation": False,
        "description": "EVA Command Core interaction.",
    },
}


def get_command_capability(action):
    """
    Return the canonical capability contract for one Command Core action.

    This function exposes architecture only. It performs no write.
    """

    action = str(action or "").strip().lower()

    ownership = COMMAND_OWNERSHIP.get(action)
    capability = COMMAND_CAPABILITIES.get(action)

    if ownership is None or capability is None:
        return {
            "ok": False,
            "action": action,
            "status": "UNKNOWN_COMMAND",
            "error": "Unknown EratGuard command action.",
            "allowed_actions": sorted(COMMAND_OWNERSHIP),
            "timestamp": _utc_now(),
        }

    return {
        "ok": True,
        "action": action,
        "label": ownership["label"],
        "module": ownership["module"],
        "href": ownership["href"],
        "status": "CAPABILITY_READY",
        "capability": {
            "modes": list(
                capability.get("modes", [])
            ),
            "risk": capability.get(
                "risk",
                "READ_ONLY"
            ),
            "execute_enabled": bool(
                capability.get(
                    "execute_enabled",
                    False
                )
            ),
            "requires_confirmation": bool(
                capability.get(
                    "requires_confirmation",
                    False
                )
            ),
            "description": capability.get(
                "description",
                ""
            ),
        },
        "timestamp": _utc_now(),
    }


def execute_command_mode(action, mode="inspect"):
    """
    Canonical mode dispatcher.

    inspect:
        delegates to the existing real read-only command service.

    open:
        returns the canonical module href.

    execute:
        validates the execution contract but intentionally refuses
        execution until a later phase explicitly enables an action.
    """

    action = str(action or "").strip().lower()
    mode = str(mode or "inspect").strip().lower()

    capability_result = get_command_capability(action)

    if not capability_result.get("ok"):
        return capability_result

    capability = capability_result["capability"]
    modes = capability.get("modes", [])

    if mode not in ("inspect", "open", "execute"):
        return {
            "ok": False,
            "action": action,
            "mode": mode,
            "status": "UNKNOWN_MODE",
            "error": "Unknown Command Core execution mode.",
            "allowed_modes": [
                "inspect",
                "open",
                "execute",
            ],
            "timestamp": _utc_now(),
        }

    if mode not in modes:
        return {
            "ok": False,
            "action": action,
            "mode": mode,
            "status": "MODE_NOT_SUPPORTED",
            "error": (
                "Requested mode is not supported "
                "by this command."
            ),
            "allowed_modes": list(modes),
            "timestamp": _utc_now(),
        }

    if mode == "inspect":
        result = execute_admin_command(action)

        if isinstance(result, dict):
            result = dict(result)
            result["mode"] = "inspect"
            result["capability"] = capability

        return result

    if mode == "open":
        return {
            "ok": True,
            "action": action,
            "mode": "open",
            "label": capability_result["label"],
            "module": capability_result["module"],
            "href": capability_result["href"],
            "status": "MODULE_READY",
            "capability": capability,
            "timestamp": _utc_now(),
        }

    # ----------------------------------------------------------
    # EXECUTE CONTRACT
    # ----------------------------------------------------------

    if not capability.get("execute_enabled"):
        return {
            "ok": False,
            "action": action,
            "mode": "execute",
            "label": capability_result["label"],
            "module": capability_result["module"],
            "href": capability_result["href"],
            "status": "EXECUTION_LOCKED",
            "error": (
                "Command execution is defined but "
                "not enabled."
            ),
            "capability": capability,
            "timestamp": _utc_now(),
        }

    # Defensive fail-closed behavior.
    #
    # A future phase must install a specific executor instead
    # of allowing generic arbitrary execution here.

    return {
        "ok": False,
        "action": action,
        "mode": "execute",
        "status": "EXECUTOR_NOT_INSTALLED",
        "error": "No canonical executor is installed.",
        "capability": capability,
        "timestamp": _utc_now(),
    }


# ===== /ERATGUARD PHASE 8B.7C.7 - COMMAND EXECUTION ARCHITECTURE =====


# ==================================================================
# ERATGUARD PHASE 8B.7C.10A - CONTROLLED OPERATION REGISTRY
#
# This registry defines explicit Command Core operation ownership.
#
# IMPORTANT:
# - No shell execution.
# - No eval / exec.
# - No arbitrary function dispatch.
# - No client supplied callable/module/path.
# - Write execution remains locked.
#
# A later phase may bind individual operation IDs to dedicated,
# reviewed Python handlers.
# ==================================================================

COMMAND_OPERATION_REGISTRY = {

    "ai-analysis": {
        "default_operation": "inspect-security",
        "operations": {
            "inspect-security": {
                "label": "INSPECT SECURITY",
                "kind": "read",
                "enabled": True,
            },
            "refresh-analysis": {
                "label": "REFRESH ANALYSIS",
                "kind": "refresh",
                "enabled": False,
            },
        },
    },

    "network": {
        "default_operation": "inspect-network",
        "operations": {
            "inspect-network": {
                "label": "INSPECT NETWORK",
                "kind": "read",
                "enabled": True,
            },
            "refresh-network": {
                "label": "REFRESH NETWORK",
                "kind": "refresh",
                "enabled": False,
            },
        },
    },

    "firewall": {
        "default_operation": "inspect-firewall",
        "operations": {
            "inspect-firewall": {
                "label": "INSPECT FIREWALL",
                "kind": "read",
                "enabled": True,
            },
            "refresh-firewall": {
                "label": "REFRESH FIREWALL",
                "kind": "refresh",
                "enabled": False,
            },
        },
    },

    "devices": {
        "default_operation": "inspect-devices",
        "operations": {
            "inspect-devices": {
                "label": "INSPECT DEVICES",
                "kind": "read",
                "enabled": True,
            },
            "refresh-devices": {
                "label": "REFRESH DEVICES",
                "kind": "refresh",
                "enabled": False,
            },
        },
    },

    "quarantine": {
        "default_operation": "inspect-quarantine",
        "operations": {
            "inspect-quarantine": {
                "label": "INSPECT QUARANTINE",
                "kind": "read",
                "enabled": True,
            },
            "refresh-quarantine": {
                "label": "REFRESH QUARANTINE",
                "kind": "refresh",
                "enabled": False,
            },
        },
    },

    "reports": {
        "default_operation": "inspect-reports",
        "operations": {
            "inspect-reports": {
                "label": "INSPECT REPORTS",
                "kind": "read",
                "enabled": True,
            },
            "refresh-reports": {
                "label": "REFRESH REPORTS",
                "kind": "refresh",
                "enabled": False,
            },
        },
    },

    "licenses": {
        "default_operation": "inspect-licenses",
        "operations": {
            "inspect-licenses": {
                "label": "INSPECT LICENSES",
                "kind": "read",
                "enabled": True,
            },
            "refresh-licenses": {
                "label": "REFRESH LICENSES",
                "kind": "refresh",
                "enabled": False,
            },
        },
    },

    "sms-shield": {
        "default_operation": "inspect-sms",
        "operations": {
            "inspect-sms": {
                "label": "INSPECT SMS SHIELD",
                "kind": "read",
                "enabled": True,
            },
            "refresh-sms": {
                "label": "REFRESH SMS SHIELD",
                "kind": "refresh",
                "enabled": False,
            },
        },
    },

    "eva-core": {
        "default_operation": "inspect-eva",
        "operations": {
            "inspect-eva": {
                "label": "INSPECT EVA CORE",
                "kind": "read",
                "enabled": True,
            },
        },
    },
}


def get_command_operations(action):
    """
    Return the explicit operation contract for one Command Core action.

    This function exposes capability metadata only.
    It does not execute an operation.
    """

    action = str(action or "").strip().lower()

    if not action:
        return {
            "ok": False,
            "status": "INVALID_REQUEST",
            "error": "Command action is required.",
        }

    config = COMMAND_OPERATION_REGISTRY.get(action)

    if config is None:
        return {
            "ok": False,
            "action": action,
            "status": "UNKNOWN_COMMAND",
            "error": "Unknown EratGuard command action.",
            "allowed_actions":
                sorted(COMMAND_OPERATION_REGISTRY),
        }

    operations = []

    for operation_id, operation in (
        config.get("operations") or {}
    ).items():

        operations.append({
            "id": operation_id,
            "label": operation.get(
                "label",
                operation_id
            ),
            "kind": operation.get(
                "kind",
                "read"
            ),
            "enabled": bool(
                operation.get(
                    "enabled",
                    False
                )
            ),
        })

    return {
        "ok": True,
        "action": action,
        "status": "OPERATION_CONTRACT_READY",
        "default_operation":
            config.get("default_operation"),
        "operations": operations,
        "execution_policy": {
            "generic_executor": False,
            "arbitrary_dispatch": False,
            "controlled_writes": False,
        },
    }


def resolve_command_operation(action, operation_id):
    """
    Resolve one explicit operation ID.

    Resolution is NOT execution.
    """

    action = str(action or "").strip().lower()

    operation_id = str(
        operation_id or ""
    ).strip().lower()

    contract = COMMAND_OPERATION_REGISTRY.get(action)

    if contract is None:
        return {
            "ok": False,
            "action": action,
            "operation": operation_id,
            "status": "UNKNOWN_COMMAND",
            "error": "Unknown EratGuard command action.",
        }

    if not operation_id:
        operation_id = str(
            contract.get(
                "default_operation",
                ""
            )
        ).strip().lower()

    operation = (
        contract.get("operations") or {}
    ).get(operation_id)

    if operation is None:
        return {
            "ok": False,
            "action": action,
            "operation": operation_id,
            "status": "UNKNOWN_OPERATION",
            "error":
                "Operation is not registered for this command.",
            "allowed_operations":
                sorted(
                    (contract.get("operations") or {}).keys()
                ),
        }

    enabled = bool(
        operation.get(
            "enabled",
            False
        )
    )

    return {
        "ok": True,
        "action": action,
        "operation": operation_id,
        "label": operation.get(
            "label",
            operation_id
        ),
        "kind": operation.get(
            "kind",
            "read"
        ),
        "enabled": enabled,
        "executable": False,
        "status":
            "OPERATION_AVAILABLE"
            if enabled
            else "OPERATION_LOCKED",
    }


# ===== /ERATGUARD PHASE 8B.7C.10A - CONTROLLED OPERATION REGISTRY =====

# ==================================================================
# ERATGUARD PHASE 8B.7C.10C-B - CONTROLLED READ HANDLERS
#
# Explicit operation ID -> dedicated reviewed read-only handler.
#
# SECURITY CONTRACT:
# - No generic executor.
# - No eval / exec.
# - No shell execution.
# - No arbitrary import/module/function dispatch.
# - No client supplied callable/path.
# - Refresh/write operations remain locked.
# ==================================================================

def _operation_read_security():
    from .security import get_security_center

    return get_security_center()


def _operation_read_network():
    from .system import get_system_center_data

    return get_system_center_data()


def _operation_read_firewall():
    from .security import get_security_center

    data = get_security_center()

    return {
        "source": "security-center",
        "scope": "firewall",
        "snapshot": data,
    }


def _operation_read_devices():
    from .users import get_users_center_data

    return get_users_center_data()


def _operation_read_quarantine():
    from .security import get_security_center

    data = get_security_center()

    return {
        "source": "security-center",
        "scope": "quarantine",
        "snapshot": data,
    }


def _operation_read_reports():
    from .dashboard import get_dashboard_data

    data = get_dashboard_data()

    return {
        "source": "dashboard-service",
        "scope": "reports",
        "snapshot": data,
    }


def _operation_read_licenses():
    from .licenses import get_license_center_data

    return get_license_center_data()


def _operation_read_sms():
    from .spam import get_spam_center_data

    return get_spam_center_data()


def _operation_read_eva():
    return execute_admin_command("eva-core")


COMMAND_READ_OPERATION_HANDLERS = {
    ("ai-analysis", "inspect-security"):
        _operation_read_security,

    ("network", "inspect-network"):
        _operation_read_network,

    ("firewall", "inspect-firewall"):
        _operation_read_firewall,

    ("devices", "inspect-devices"):
        _operation_read_devices,

    ("quarantine", "inspect-quarantine"):
        _operation_read_quarantine,

    ("reports", "inspect-reports"):
        _operation_read_reports,

    ("licenses", "inspect-licenses"):
        _operation_read_licenses,

    ("sms-shield", "inspect-sms"):
        _operation_read_sms,

    ("eva-core", "inspect-eva"):
        _operation_read_eva,
}


def execute_command_operation(action, operation_id=None):
    """
    Execute one explicitly registered READ operation.

    Only reviewed read-only handlers in
    COMMAND_READ_OPERATION_HANDLERS can run.

    Refresh/write operations remain fail-closed.
    """

    action = str(action or "").strip().lower()

    operation_id = str(
        operation_id or ""
    ).strip().lower()

    resolved = resolve_command_operation(
        action,
        operation_id,
    )

    if not resolved.get("ok"):
        return resolved

    operation_id = resolved.get(
        "operation",
        ""
    )

    if not resolved.get("enabled"):
        return {
            "ok": False,
            "action": action,
            "operation": operation_id,
            "status": "OPERATION_LOCKED",
            "error": "Operation is registered but locked.",
        }

    if resolved.get("kind") != "read":
        return {
            "ok": False,
            "action": action,
            "operation": operation_id,
            "status": "WRITE_EXECUTION_LOCKED",
            "error": (
                "Only explicit read-only operations "
                "are executable in this phase."
            ),
        }

    handler = COMMAND_READ_OPERATION_HANDLERS.get(
        (action, operation_id)
    )

    if handler is None:
        return {
            "ok": False,
            "action": action,
            "operation": operation_id,
            "status": "HANDLER_NOT_INSTALLED",
            "error": (
                "No reviewed read-only handler is "
                "installed for this operation."
            ),
        }

    try:
        snapshot = handler()

    except Exception as exc:
        return {
            "ok": False,
            "action": action,
            "operation": operation_id,
            "status": "OPERATION_FAILED",
            "error": (
                "Read-only operation handler failed: "
                + exc.__class__.__name__
            ),
        }

    return {
        "ok": True,
        "action": action,
        "operation": operation_id,
        "label": resolved.get("label"),
        "kind": "read",
        "status": "OPERATION_COMPLETE",
        "snapshot": snapshot,
        "execution_policy": {
            "generic_executor": False,
            "arbitrary_dispatch": False,
            "controlled_writes": False,
            "read_only": True,
        },
    }


# ===== /ERATGUARD PHASE 8B.7C.10C-B - CONTROLLED READ HANDLERS =====


