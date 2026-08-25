import os
import json
import secrets
import hashlib
from datetime import datetime, timedelta, timezone
from werkzeug.security import generate_password_hash

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
USERS_FILE = os.path.join(BASE_DIR, "users.json")
RESET_TOKENS_FILE = os.path.join(DATA_DIR, "reset_tokens.json")

TOKEN_TTL_MINUTES = 30
CODE_TTL_MINUTES = 10


def _ensure_file(path, default_data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if not os.path.exists(path):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(default_data, f, ensure_ascii=False, indent=2)


def _load_json(path, default_data):
    _ensure_file(path, default_data)
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default_data


def _save_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def load_users():
    data = _load_json(USERS_FILE, {})
    return data if isinstance(data, dict) else {}


def save_users(users):
    _save_json(USERS_FILE, users)


def load_reset_tokens():
    data = _load_json(RESET_TOKENS_FILE, {})
    return data if isinstance(data, dict) else {}


def save_reset_tokens(tokens):
    _save_json(RESET_TOKENS_FILE, tokens)


def _now_utc():
    return datetime.now(timezone.utc)


def _token_hash(raw_value: str) -> str:
    return hashlib.sha256(raw_value.encode("utf-8")).hexdigest()


def find_user_by_identity(identity: str):
    identity = (identity or "").strip().lower()
    if not identity:
        return None, None

    users = load_users()

    for username, user in users.items():
        if username.lower() == identity:
            return username, user

        email = str(user.get("email", "")).strip().lower()
        if email and email == identity:
            return username, user

    return None, None


def invalidate_existing_tokens(username: str):
    tokens = load_reset_tokens()
    changed = False

    for _, record in tokens.items():
        if record.get("username") == username and not record.get("used", False):
            record["used"] = True
            changed = True

    if changed:
        save_reset_tokens(tokens)


def create_reset_token(username: str, invalidate: bool = True) -> str:
    if invalidate:
        invalidate_existing_tokens(username)

    raw_token = secrets.token_hex(32)
    hashed = _token_hash(raw_token)
    expires_at = (_now_utc() + timedelta(minutes=TOKEN_TTL_MINUTES)).isoformat()

    tokens = load_reset_tokens()
    tokens[hashed] = {
        "type": "link",
        "username": username,
        "used": False,
        "expires_at": expires_at,
        "created_at": _now_utc().isoformat()
    }
    save_reset_tokens(tokens)

    return raw_token


def create_reset_code(username: str, invalidate: bool = True) -> str:
    if invalidate:
        invalidate_existing_tokens(username)

    code = str(secrets.randbelow(900000) + 100000)
    hashed = _token_hash(code)
    expires_at = (_now_utc() + timedelta(minutes=CODE_TTL_MINUTES)).isoformat()

    tokens = load_reset_tokens()
    tokens[hashed] = {
        "type": "code",
        "username": username,
        "used": False,
        "expires_at": expires_at,
        "created_at": _now_utc().isoformat()
    }
    save_reset_tokens(tokens)

    return code


def is_token_format_valid(token: str) -> bool:
    return isinstance(token, str) and len(token) == 64 and all(c in "0123456789abcdefABCDEF" for c in token)


def is_code_format_valid(code: str) -> bool:
    return isinstance(code, str) and len(code) == 6 and code.isdigit()


def find_valid_token_record(raw_token: str):
    if not is_token_format_valid(raw_token):
        return None

    hashed = _token_hash(raw_token)
    tokens = load_reset_tokens()
    record = tokens.get(hashed)

    if not record or record.get("type") != "link":
        return None

    if record.get("used", False):
        return None

    expires_at = record.get("expires_at", "")
    try:
        expires_dt = datetime.fromisoformat(expires_at)
    except Exception:
        return None

    if _now_utc() > expires_dt:
        return None

    return {
        "token_hash": hashed,
        "username": record.get("username", "")
    }


def find_valid_code_record(code: str):
    if not is_code_format_valid(code):
        return None

    hashed = _token_hash(code)
    tokens = load_reset_tokens()
    record = tokens.get(hashed)

    if not record or record.get("type") != "code":
        return None

    if record.get("used", False):
        return None

    expires_at = record.get("expires_at", "")
    try:
        expires_dt = datetime.fromisoformat(expires_at)
    except Exception:
        return None

    if _now_utc() > expires_dt:
        return None

    return {
        "token_hash": hashed,
        "username": record.get("username", "")
    }


def mark_token_used(raw_value: str):
    hashed = _token_hash(raw_value)
    tokens = load_reset_tokens()

    if hashed in tokens:
        tokens[hashed]["used"] = True
        save_reset_tokens(tokens)


def reset_user_password(username: str, new_password: str) -> bool:
    users = load_users()

    if username not in users:
        return False

    # Canonical EratGuard user-login contract:
    # /login reads the Werkzeug hash from the "password" field.
    users[username]["password"] = generate_password_hash(new_password)
    users[username].pop("password_hash", None)

    save_users(users)
    return True


def cleanup_expired_tokens():
    tokens = load_reset_tokens()
    now = _now_utc()
    cleaned = {}

    for token_hash, record in tokens.items():
        try:
            expires_dt = datetime.fromisoformat(record.get("expires_at", ""))
            if expires_dt >= now:
                cleaned[token_hash] = record
        except Exception:
            continue

    save_reset_tokens(cleaned)
