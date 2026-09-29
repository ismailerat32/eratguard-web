"""
EratGuard Admin Core — Canonical Commercial Actions

Extracted from the verified canonical commercial model in
dashboard_web.py.

SHADOW MODE:
- no Flask routes
- no live persistence
- no payment mutation
- no user mutation except caller-owned in-memory dictionaries
- no dependency on dashboard_web.py
"""

ERATGUARD_CANONICAL_PLANS_V1 = {
    "starter_monthly": {
        "key": "starter_monthly",
        "label": "Starter Shield",
        "price_try": 299,
        "price_text": "299 TL / ay",
        "billing_period": "monthly",
        "duration_days": 30,
        "license_type": "pro",
        "expires_mode": "days",
    },

    "pro_yearly": {
        "key": "pro_yearly",
        "label": "Shield Pro+",
        "price_try": 2500,
        "price_text": "2500 TL / yıl",
        "billing_period": "yearly",
        "duration_days": 365,
        "license_type": "pro",
        "expires_mode": "days",
    },

    "lifetime": {
        "key": "lifetime",
        "label": "Lifetime Shield",
        "price_try": 5000,
        "price_text": "5000 TL",
        "billing_period": "lifetime",
        "duration_days": None,
        "license_type": "lifetime",
        "expires_mode": "lifetime",
        "expires_at": "2099-12-31",
    },
}


ERATGUARD_CANONICAL_PLAN_ALIASES_V1 = {
    "starter_monthly": "starter_monthly",
    "starter": "starter_monthly",
    "monthly": "starter_monthly",
    "pro_monthly": "starter_monthly",
    "aylik": "starter_monthly",

    "pro_yearly": "pro_yearly",
    "yearly": "pro_yearly",
    "annual": "pro_yearly",
    "pro": "pro_yearly",
    "premium": "pro_yearly",
    "yillik": "pro_yearly",

    "lifetime": "lifetime",
    "lifetime_shield": "lifetime",
    "omurluk": "lifetime",
}


def _eg_canonical_plan_key_v1(plan):
    raw = str(plan or "").strip().lower()

    if not raw:
        return "pro_yearly"

    return ERATGUARD_CANONICAL_PLAN_ALIASES_V1.get(
        raw,
        "pro_yearly"
    )


def _eg_canonical_plan_v1(plan):
    key = _eg_canonical_plan_key_v1(plan)

    data = ERATGUARD_CANONICAL_PLANS_V1.get(
        key,
        ERATGUARD_CANONICAL_PLANS_V1["pro_yearly"]
    )

    return dict(data)


def _eg_canonical_plan_expiry_v1(plan, now=None):
    from datetime import datetime as _eg_ccm_datetime
    from datetime import timedelta as _eg_ccm_timedelta

    info = _eg_canonical_plan_v1(plan)

    if info.get("expires_mode") == "lifetime":
        return "2099-12-31"

    days = int(info.get("duration_days") or 365)

    base = now or _eg_ccm_datetime.now()

    if hasattr(base, "date"):
        base_date = base.date()
    else:
        base_date = base

    return (
        base_date + _eg_ccm_timedelta(days=days)
    ).isoformat()


def _eg_canonical_apply_plan_to_user_v1(user, raw_plan, now=None):
    """
    Apply canonical commercial entitlement to a user record.
    """
    if not isinstance(user, dict):
        user = {}

    info = _eg_canonical_plan_v1(raw_plan)
    expiry = _eg_canonical_plan_expiry_v1(info["key"], now=now)

    user["active"] = True
    user["plan"] = info["key"]
    user["license_type"] = info["license_type"]
    user["expires_at"] = expiry
    user["license_expiry"] = expiry

    # Paid entitlement permanently consumes any old trial.
    # A paid plan must never fall back to a previous trial
    # after the paid entitlement expires.
    if info["license_type"] in ("pro", "lifetime"):
        trial_started_at = str(
            user.get("trial_started_at") or ""
        ).strip()

        trial_expires_at = str(
            user.get("trial_expires_at") or ""
        ).strip()

        if trial_started_at or trial_expires_at:
            from datetime import datetime as _eg_trial_datetime_v2

            user["trial_consumed_at"] = (
                _eg_trial_datetime_v2.now()
                .isoformat(timespec="seconds")
            )

        user.pop("trial_started_at", None)
        user.pop("trial_expires_at", None)

    return user


# ================================================================
# ERATGUARD ADMIN CORE — PAYMENT REQUEST MUTATIONS V1
# Pure service layer.
# No Flask session/auth/redirect dependencies.
# Caller owns authorization, persistence and HTTP response.
# ================================================================

def _payment_request_plan_v1(item):
    if not isinstance(item, dict):
        item = {}

    raw = (
        item.get("plan_key")
        or item.get("plan")
        or "pro_yearly"
    )

    return _eg_canonical_plan_key_v1(raw)


def _used_license_keys_v1(users):
    used = set()

    if not isinstance(users, dict):
        return used

    for info in users.values():
        if not isinstance(info, dict):
            continue

        key = str(
            info.get("license_key", "") or ""
        ).strip().upper()

        if key and key != "NONE":
            used.add(key)

    return used


def approve_payment_request(
    requests_data,
    users,
    order_no,
    *,
    license_key_factory,
    now=None,
):
    """
    Memory-only approval mutation.

    Returns:
        {
            "changed": bool,
            "requests": list,
            "users": dict,
            "username": str,
            "license_key": str,
            "plan": str,
        }

    This function performs no file write, auth check,
    redirect, session access or audit write.
    """

    if not isinstance(requests_data, list):
        requests_data = []

    if not isinstance(users, dict):
        users = {}

    changed = False
    approved_license = ""
    approved_username = ""
    approved_plan = ""

    for item in requests_data:
        if not isinstance(item, dict):
            continue

        if str(item.get("order_no", "")) != str(order_no):
            continue

        username = str(
            item.get("username", "") or ""
        ).strip()

        if not username:
            continue

        user = users.get(username, {})

        if not isinstance(user, dict):
            user = {}

        license_key = str(
            item.get("license_key", "") or ""
        ).strip().upper()

        if not license_key:
            used = _used_license_keys_v1(users)

            for _ in range(10000):
                candidate = str(
                    license_key_factory() or ""
                ).strip().upper()

                if (
                    candidate
                    and candidate != "NONE"
                    and candidate not in used
                ):
                    license_key = candidate
                    break

            if not license_key:
                raise RuntimeError(
                    "unable_to_generate_unique_license_key"
                )

        plan_key = _payment_request_plan_v1(item)
        info = _eg_canonical_plan_v1(plan_key)

        user["license_key"] = license_key

        _eg_canonical_apply_plan_to_user_v1(
            user,
            plan_key,
            now=now,
        )

        users[username] = user

        item["plan"] = plan_key
        item["plan_key"] = plan_key
        item["plan_label"] = info["label"]
        item["plan_price"] = info["price_text"]
        item["plan_price_try"] = info["price_try"]
        item["billing_period"] = info["billing_period"]
        item["duration_days"] = info["duration_days"]
        item["license_type"] = info["license_type"]

        item["expires_at"] = user["expires_at"]
        item["license_expiry"] = user["license_expiry"]

        item["status"] = "approved_license_assigned"
        item["license_key"] = license_key

        item["admin_note"] = (
            "Admin onayıyla canonical lisans "
            "kullanıcı hesabına tanımlandı."
        )

        changed = True
        approved_license = license_key
        approved_username = username
        approved_plan = plan_key
        break

    return {
        "changed": changed,
        "requests": requests_data,
        "users": users,
        "username": approved_username,
        "license_key": approved_license,
        "plan": approved_plan,
    }


def reject_payment_request(
    requests_data,
    order_no,
):
    """
    Memory-only rejection mutation.

    Performs no file write, auth check,
    redirect, session access or audit write.
    """

    if not isinstance(requests_data, list):
        requests_data = []

    changed = False

    for item in requests_data:
        if not isinstance(item, dict):
            continue

        if str(item.get("order_no", "")) != str(order_no):
            continue

        item["status"] = "rejected_or_cancelled"
        item["admin_note"] = (
            "Talep admin tarafından iptal edildi."
        )

        changed = True
        break

    return {
        "changed": changed,
        "requests": requests_data,
    }

