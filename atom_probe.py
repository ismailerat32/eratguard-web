#!/usr/bin/env python3
import os, re, sys, json, time, random, string, getpass
from urllib.parse import urljoin, urlparse, urldefrag
import requests

BASE_URL = os.getenv("BASE_URL", "https://spamshield-peld.onrender.com").rstrip("/")
ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASS = os.getenv("ADMIN_PASS", "")
ADMIN_CODE = os.getenv("ADMIN_CODE", "")
USER_PASS = os.getenv("PROBE_USER_PASS", "Probe12345")
MAX_VISITS = int(os.getenv("MAX_VISITS", "300"))
TIMEOUT = int(os.getenv("TIMEOUT", "20"))

BAD_PATTERNS = [
    "Internal Server Error",
    "Traceback",
    "TemplateNotFound",
    "UndefinedError",
    "BuildError",
    "NameError",
    "KeyError",
    "AttributeError",
    "OperationalError",
    "sqlite3.",
    "jinja2.exceptions",
    "Hafif admin görünümü",
    "hafif modda",
    "Mobil WebView için optimize",
    "hazırlanıyor",
    "Not implemented",
    "Coming soon",
    "TODO",
]

SEED_PATHS = [
    "/",
    "/login",
    "/register",
    "/forgot",
    "/forgot-password",
    "/reset-password-code",
    "/pricing",
    "/checkout",
    "/checkout/basic",
    "/checkout/pro",
    "/checkout/premium",
    "/payment",
    "/iyzico",
    "/dashboard",
    "/radial",
    "/analysis",
    "/blocked",
    "/notifications",
    "/settings",
    "/license",
    "/community",
    "/profile",
    "/change-password",
    "/ss-admin-access",
    "/admin",
    "/admin/",
    "/admin/dashboard",
    "/admin/panel",
    "/admin/users",
    "/admin/licenses",
    "/admin/generated-licenses",
    "/admin/payment-requests",
    "/admin/payments",
    "/admin/overview",
    "/admin/reports",
    "/admin/spam-logs",
    "/admin/security",
    "/admin/whitelist",
    "/admin/notifications",
    "/admin/settings",
    "/admin/system",
    "/admin/forgot-mail-diagnostic",
    "/api/stats",
    "/api/user",
    "/api/license",
    "/api/notifications",
    "/health",
    "/ping",
    "/__spamshield_live_version",
]

report = {
    "base_url": BASE_URL,
    "visited": [],
    "errors": [],
    "warnings": [],
    "ok": [],
    "forms": [],
    "buttons": [],
    "discovered_urls": [],
}

def say(prefix, msg):
    print(f"{prefix} {msg}", flush=True)

def add_error(msg):
    report["errors"].append(msg)
    say("❌", msg)

def add_warn(msg):
    report["warnings"].append(msg)
    say("⚠️", msg)

def add_ok(msg):
    report["ok"].append(msg)
    say("✅", msg)

def normalize_url(raw, base):
    if not raw:
        return None
    raw = raw.strip()
    if raw.startswith(("javascript:", "mailto:", "tel:", "#", "data:")):
        return None
    full = urljoin(base, raw)
    full = urldefrag(full)[0]
    parsed = urlparse(full)
    if parsed.netloc != urlparse(BASE_URL).netloc:
        return None
    return full

def title_of(html):
    m = re.search(r"<title[^>]*>(.*?)</title>", html or "", re.I | re.S)
    if m:
        return re.sub(r"\s+", " ", re.sub(r"<.*?>", "", m.group(1))).strip()
    h = re.search(r"<h1[^>]*>(.*?)</h1>", html or "", re.I | re.S)
    if h:
        return re.sub(r"\s+", " ", re.sub(r"<.*?>", "", h.group(1))).strip()
    return ""

def bad_scan(url, html, code):
    if code >= 500:
        add_error(f"500 SERVER ERROR: {url}")
    if code == 404:
        add_error(f"404 NOT FOUND: {url}")
    if code in (401, 403):
        add_warn(f"AUTH/BLOCKED {code}: {url}")

    for p in BAD_PATTERNS:
        if re.search(re.escape(p), html or "", re.I):
            add_error(f"BAD PATTERN '{p}' at {url}")

def discover_atoms(html, current_url):
    found = set()

    patterns = [
        r'''href=["']([^"']+)["']''',
        r'''src=["']([^"']+)["']''',
        r'''action=["']([^"']+)["']''',
        r'''data-href=["']([^"']+)["']''',
        r'''data-url=["']([^"']+)["']''',
        r'''window\.location\.href\s*=\s*["']([^"']+)["']''',
        r'''location\.href\s*=\s*["']([^"']+)["']''',
        r'''window\.location\s*=\s*["']([^"']+)["']''',
        r'''onclick=["'][^"']*(?:href|location)[^"']*["']([^"']+)["']''',
        r'''fetch\(["']([^"']+)["']''',
        r'''axios\.(?:get|post|put|delete)\(["']([^"']+)["']''',
        r'''\$\.ajax\(\{[^}]*url\s*:\s*["']([^"']+)["']''',
    ]

    for pat in patterns:
        for m in re.finditer(pat, html or "", re.I | re.S):
            u = normalize_url(m.group(1), current_url)
            if u:
                found.add(u)

    # Route-like strings inside JS/HTML
    for m in re.finditer(r'''["'](/(?:admin|api|user|dashboard|radial|analysis|blocked|notifications|settings|license|community|checkout|pricing|login|register|forgot)[^"'\s<]*)["']''', html or "", re.I):
        u = normalize_url(m.group(1), current_url)
        if u:
            found.add(u)

    return sorted(found)

def extract_forms(html, current_url):
    forms = []
    for fm in re.finditer(r"<form\b.*?</form>", html or "", re.I | re.S):
        block = fm.group(0)
        method = "GET"
        mm = re.search(r'''method=["']?([a-zA-Z]+)''', block)
        if mm:
            method = mm.group(1).upper()
        action = current_url
        am = re.search(r'''action=["']([^"']+)["']''', block, re.I)
        if am:
            action = normalize_url(am.group(1), current_url) or current_url
        fields = sorted(set(re.findall(r'''name=["']([^"']+)["']''', block, re.I)))
        buttons = [re.sub(r"\s+", " ", re.sub(r"<.*?>", "", b)).strip() for b in re.findall(r"<button\b.*?</button>", block, re.I | re.S)]
        forms.append({"url": current_url, "method": method, "action": action, "fields": fields, "buttons": buttons})
    return forms

def session_get(sess, url, label):
    try:
        r = sess.get(url, timeout=TIMEOUT, allow_redirects=True, headers={"User-Agent": f"EratGuard-AtomProbe/{label}"})
        t = title_of(r.text)
        say("GET", f"[{label}] {r.status_code} {url} -> {r.url} | {t[:80]}")
        report["visited"].append({"label": label, "method": "GET", "url": url, "final_url": r.url, "status": r.status_code, "title": t})
        bad_scan(url, r.text, r.status_code)

        for f in extract_forms(r.text, r.url):
            report["forms"].append(f)

        for b in re.findall(r"<button\b.*?</button>", r.text or "", re.I | re.S):
            txt = re.sub(r"\s+", " ", re.sub(r"<.*?>", "", b)).strip()
            if txt:
                report["buttons"].append({"url": url, "text": txt[:120]})

        links = discover_atoms(r.text, r.url)
        for l in links:
            report["discovered_urls"].append(l)
        return r, links
    except Exception as e:
        add_error(f"REQUEST FAILED [{label}] {url}: {e}")
        return None, []

def session_post(sess, url, data, label):
    try:
        r = sess.post(url, data=data, timeout=TIMEOUT, allow_redirects=True, headers={"User-Agent": f"EratGuard-AtomProbe/{label}"})
        t = title_of(r.text)
        say("POST", f"[{label}] {r.status_code} {url} -> {r.url} | {t[:80]}")
        report["visited"].append({"label": label, "method": "POST", "url": url, "final_url": r.url, "status": r.status_code, "title": t})
        bad_scan(url, r.text, r.status_code)
        return r
    except Exception as e:
        add_error(f"POST FAILED [{label}] {url}: {e}")
        return None

def make_user():
    s = "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(8))
    return f"probe_{s}", f"probe_{s}@example.com"

def try_register_and_login(sess):
    username, email = make_user()

    session_get(sess, BASE_URL + "/register", "user")
    payloads = [
        {"username": username, "email": email, "password": USER_PASS, "confirm_password": USER_PASS},
        {"name": username, "username": username, "email": email, "password": USER_PASS, "confirm": USER_PASS},
    ]
    for p in payloads:
        session_post(sess, BASE_URL + "/register", p, "user-register")

    login_payloads = [
        {"username": username, "password": USER_PASS},
        {"email": email, "password": USER_PASS},
    ]
    for p in login_payloads:
        session_post(sess, BASE_URL + "/login", p, "user-login")

def try_admin_login(sess):
    global ADMIN_PASS, ADMIN_CODE

    session_get(sess, BASE_URL + "/ss-admin-access", "admin")

    if not ADMIN_PASS:
        try:
            ADMIN_PASS = getpass.getpass("Admin şifresi gir: ").strip()
        except Exception:
            ADMIN_PASS = ""

    if ADMIN_PASS and not ADMIN_CODE:
        try:
            tmp_code = getpass.getpass("Admin kodu varsa gir, yoksa Enter: ").strip()
            ADMIN_CODE = tmp_code
        except Exception:
            ADMIN_CODE = ""

    if not ADMIN_PASS:
        add_warn("ADMIN_PASS boş; admin POST login atlandı.")
        return

    session_post(
        sess,
        BASE_URL + "/ss-admin-access",
        {"username": ADMIN_USER, "password": ADMIN_PASS, "admin_code": ADMIN_CODE},
        "admin-login"
    )

def crawl(sess, label, seeds):
    seen = set()
    queue = []

    for p in seeds:
        u = normalize_url(p, BASE_URL + "/") if p.startswith("/") else normalize_url(p, BASE_URL + "/")
        if u:
            queue.append(u)

    while queue and len(seen) < MAX_VISITS:
        url = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)

        # Destructive routes skip
        low = url.lower()
        if any(x in low for x in ["logout", "delete", "remove", "destroy", "drop", "reset-password/"]):
            add_warn(f"destructive/sensitive route skipped: {url}")
            continue

        r, links = session_get(sess, url, label)

        for l in links:
            if l not in seen and l not in queue:
                queue.append(l)

    add_ok(f"{label} crawl completed: {len(seen)} URLs")

def static_source_scan():
    say("\n===", "STATIC SOURCE ATOM SCAN")
    files = []
    for root, dirs, fs in os.walk("."):
        # heavy dirs skip
        if any(x in root for x in ["/.git", "/node_modules", "/build/", "/__pycache__", "/APK_OUTPUTS"]):
            continue
        for name in fs:
            if name in ("atom_probe.py", "deep_probe.py", "atom_probe_report.json", "deep_probe_report.json", "change_password_live.html"):
                continue
            if name in ("atom_probe.py", "deep_probe.py", "atom_probe_report.json", "deep_probe_report.json", "change_password_live.html"):
                continue
            if name.endswith((".py", ".html", ".js", ".java")):
                files.append(os.path.join(root, name))

    forbidden = ["Hafif admin görünümü", "_ss_fast_admin", "Admin ayarları hafif", "Mobil WebView için optimize edildi"]
    for fp in files:
        try:
            txt = open(fp, encoding="utf-8", errors="ignore").read()
        except Exception:
            continue
        for f in forbidden:
            if f in txt and ".bak_" not in fp:
                add_error(f"FORBIDDEN SOURCE TEXT '{f}' in {fp}")

    add_ok(f"static source scan completed: {len(files)} files")

def final_report():
    # Dedup
    report["discovered_urls"] = sorted(set(report["discovered_urls"]))
    out = "atom_probe_report.json"
    with open(out, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    say("\n===", "FORMS FOUND")
    unique_forms = []
    seen = set()
    for f in report["forms"]:
        key = (f["url"], f["method"], f["action"], tuple(f["fields"]))
        if key not in seen:
            seen.add(key)
            unique_forms.append(f)
            say("FORM", f"{f['method']} {f['url']} -> {f['action']} fields={f['fields']} buttons={f['buttons']}")

    say("\n===", "SUMMARY")
    say("BASE", BASE_URL)
    say("VISITED", str(len(report["visited"])))
    say("DISCOVERED_URLS", str(len(report["discovered_urls"])))
    say("FORMS", str(len(unique_forms)))
    say("WARNINGS", str(len(report["warnings"])))
    say("ERRORS", str(len(report["errors"])))
    say("REPORT", out)

    if report["errors"]:
        say("\n❌", "ERROR LIST")
        for e in report["errors"]:
            print(" - " + e)
        sys.exit(2)
    add_ok("ATOM PROBE PASSED")

if __name__ == "__main__":
    say("===", "ERATGUARD ATOM PROBE START")
    say("BASE_URL", BASE_URL)

    static_source_scan()

    public = requests.Session()
    user = requests.Session()
    admin = requests.Session()

    try_register_and_login(user)
    try_admin_login(admin)

    crawl(public, "public", SEED_PATHS)
    crawl(user, "user-auth", SEED_PATHS)
    crawl(admin, "admin-auth", SEED_PATHS)

    final_report()
