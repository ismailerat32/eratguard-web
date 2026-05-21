import os
import smtplib
import socket
import ssl
from pathlib import Path
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


def _load_dotenv_fallback():
    """
    Render ortamında gerçek env kullanılır.
    Lokal/Termux ortamında .env varsa SMTP_* değerlerini os.environ içine alır.
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
    """
    SMTP bağlantısını kısa timeout ile sadece IPv4 üzerinden dener.
    Uzun bekleyip Gunicorn worker timeout oluşturmaması için bilinçli olarak hızlı başarısız olur.
    """
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
                sock.close()
            except Exception:
                pass

    raise RuntimeError(f"SMTP IPv4 hızlı bağlantı hatası: {last_error}")


def send_mail(host=None, port=None, user=None, password=None, to_email="", subject="", body=""):
    _load_dotenv_fallback()

    smtp_host = host or os.getenv("SMTP_HOST", "smtp.gmail.com")
    smtp_port = int(port or os.getenv("SMTP_PORT", "587"))
    smtp_user = (user or os.getenv("SMTP_USER", "")).strip()
    smtp_pass = (password or os.getenv("SMTP_PASS", "")).strip()
    smtp_from = (os.getenv("SMTP_FROM", "") or smtp_user).strip()
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

        return True, f"Mail gönderildi via {connected_via}"

    except Exception as e:
        try:
            if server:
                server.close()
        except Exception:
            pass
        return False, f"Mail hatası: {e}"
