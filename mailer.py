import os
import smtplib
import socket
import ssl
import requests
from pathlib import Path
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


def _load_dotenv_fallback():
    """
    Render ortamında gerçek env kullanılır.
    Lokal/Termux ortamında .env varsa SMTP_*, BREVO_* ve MAIL_* değerlerini os.environ içine alır.
    Var olan env değerlerini ezmez.
    """
    env_path = Path(__file__).resolve().parent / ".env"
    if not env_path.exists():
        return

    try:
        for line in env_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            s = line.strip()
            if not s or s.startswith("#") or "=" not in s:
                continue

            key, value = s.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")

            if key and key not in os.environ:
                os.environ[key] = value
    except Exception:
        pass


def _smtp_connect_ipv4_fast(smtp_host, smtp_port, timeout=8):
    try:
        addr_infos = socket.getaddrinfo(
            smtp_host,
            smtp_port,
            socket.AF_INET,
            socket.SOCK_STREAM
        )
    except Exception as e:
        raise RuntimeError(f"SMTP DNS/IPv4 çözümleme hatası: {e}")

    if not addr_infos:
        raise RuntimeError("SMTP IPv4 adresi bulunamadı")

    last_error = None

    for family, socktype, proto, canonname, sockaddr in addr_infos[:2]:
        ip = sockaddr[0]
        sock = None
        try:
            sock = socket.create_connection((ip, smtp_port), timeout=timeout)
            server = smtplib.SMTP(timeout=timeout)
            server.sock = sock
            server.file = sock.makefile("rb")
            server.helo_resp = None
            server.ehlo_resp = None
            server.esmtp_features = {}
            server.does_esmtp = False
            server.getreply()
            return server, ip
        except Exception as e:
            last_error = e
            try:
                if sock:
                    sock.close()
            except Exception:
                pass

    raise RuntimeError(f"SMTP IPv4 hızlı bağlantı hatası: {last_error}")


def _send_mail_brevo(to_email="", subject="", body=""):
    api_key = (os.getenv("BREVO_API_KEY", "") or "").strip()
    if not api_key:
        return None, "BREVO_API_KEY yok"

    sender_email = (
        os.getenv("MAIL_FROM", "")
        or os.getenv("BREVO_FROM_EMAIL", "")
        or os.getenv("SMTP_FROM", "")
        or os.getenv("SMTP_USER", "")
    ).strip()

    sender_name = (
        os.getenv("MAIL_FROM_NAME", "")
        or os.getenv("BREVO_FROM_NAME", "")
        or "EratGuard"
    ).strip()

    if not sender_email:
        return False, "Brevo gönderici e-posta eksik: MAIL_FROM veya BREVO_FROM_EMAIL gerekli"

    payload = {
        "sender": {
            "name": sender_name,
            "email": sender_email
        },
        "to": [
            {
                "email": to_email
            }
        ],
        "subject": subject,
        "textContent": body
    }

    headers = {
        "accept": "application/json",
        "api-key": api_key,
        "content-type": "application/json"
    }

    try:
        r = requests.post(
            "https://api.brevo.com/v3/smtp/email",
            json=payload,
            headers=headers,
            timeout=20
        )

        if 200 <= r.status_code < 300:
            return True, f"Mail gönderildi via Brevo API: HTTP {r.status_code}"

        safe_body = (r.text or "").replace("\n", " ")[:400]
        return False, f"Brevo API hatası: HTTP {r.status_code} {safe_body}"

    except Exception as e:
        return False, f"Brevo API bağlantı hatası: {e}"


def _send_mail_smtp(host=None, port=None, user=None, password=None, to_email="", subject="", body=""):
    smtp_host = host or os.getenv("SMTP_HOST", "smtp.gmail.com")
    smtp_port = int(port or os.getenv("SMTP_PORT", "587"))
    smtp_user = (user or os.getenv("SMTP_USER", "")).strip()
    smtp_pass = (password or os.getenv("SMTP_PASS", "")).strip()
    smtp_from = (os.getenv("SMTP_FROM", "") or os.getenv("MAIL_FROM", "") or smtp_user).strip()
    timeout = int(os.getenv("SMTP_TIMEOUT", "8"))

    smtp_pass = smtp_pass.replace(" ", "")

    if not smtp_user or not smtp_pass:
        return False, "SMTP ayarları eksik"

    if not to_email:
        return False, "Alıcı e-posta eksik"

    server = None

    try:
        msg = MIMEMultipart()
        msg["From"] = smtp_from
        msg["To"] = to_email
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain", "utf-8"))

        context = ssl.create_default_context()

        if smtp_port == 465:
            server = smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=timeout, context=context)
            connected_via = smtp_host
        else:
            server, connected_via = _smtp_connect_ipv4_fast(smtp_host, smtp_port, timeout=timeout)
            server.ehlo()
            server.starttls(context=context)
            server.ehlo()

        server.login(smtp_user, smtp_pass)
        server.sendmail(smtp_from, [to_email], msg.as_string())
        server.quit()

        return True, f"Mail gönderildi via SMTP {connected_via}"

    except Exception as e:
        try:
            if server:
                server.close()
        except Exception:
            pass
        return False, f"SMTP Mail hatası: {e}"


def send_mail(host=None, port=None, user=None, password=None, to_email="", subject="", body=""):
    _load_dotenv_fallback()

    if not to_email:
        return False, "Alıcı e-posta eksik"

    brevo_ok, brevo_msg = _send_mail_brevo(to_email=to_email, subject=subject, body=body)

    if brevo_ok is True:
        return True, brevo_msg

    # BREVO_API_KEY hiç yoksa eski SMTP fallback çalışır.
    # BREVO_API_KEY varsa ama hata verirse SMTP'ye düşmeden hatayı döndürürüz;
    # böylece yanlış API/sender ayarı net loglanır.
    if brevo_ok is False:
        return False, brevo_msg

    return _send_mail_smtp(
        host=host,
        port=port,
        user=user,
        password=password,
        to_email=to_email,
        subject=subject,
        body=body
    )
