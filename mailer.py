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


def _smtp_connect_ipv4(smtp_host, smtp_port, timeout=25):
    """
    Render üzerinde bazı ortamlarda SMTP host IPv6 çözülürse
    [Errno 101] Network is unreachable hatası oluşabiliyor.
    Bu yardımcı fonksiyon sadece IPv4 A kayıtlarını dener.
    """
    last_error = None

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

    for family, socktype, proto, canonname, sockaddr in addr_infos:
        ip = sockaddr[0]
        server = None
        try:
            server = smtplib.SMTP(timeout=timeout)
            server.connect(ip, smtp_port)
            return server, ip
        except Exception as e:
            last_error = e
            try:
                if server:
                    server.close()
            except Exception:
                pass

    raise RuntimeError(f"SMTP IPv4 bağlantı hatası: {last_error}")


def send_mail(host=None, port=None, user=None, password=None, to_email="", subject="", body=""):
    _load_dotenv_fallback()

    smtp_host = host or os.getenv("SMTP_HOST", "smtp.gmail.com")
    smtp_port = int(port or os.getenv("SMTP_PORT", "587"))
    smtp_user = (user or os.getenv("SMTP_USER", "")).strip()
    smtp_pass = (password or os.getenv("SMTP_PASS", "")).strip()
    smtp_from = (os.getenv("SMTP_FROM", "") or smtp_user).strip()

    smtp_pass = smtp_pass.replace(" ", "")

    if not smtp_user or not smtp_pass:
        return False, "SMTP ayarları eksik"

    if not to_email:
        return False, "Alıcı e-posta eksik"

    try:
        msg = MIMEMultipart()
        msg["From"] = smtp_from
        msg["To"] = to_email
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain", "utf-8"))

        context = ssl.create_default_context()

        if smtp_port == 465:
            server = smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=25, context=context)
            connected_via = smtp_host
        else:
            try:
                server, connected_via = _smtp_connect_ipv4(smtp_host, smtp_port, timeout=25)
            except Exception:
                server = smtplib.SMTP(smtp_host, smtp_port, timeout=25)
                connected_via = smtp_host

            server.ehlo()
            server.starttls(context=context)
            server.ehlo()

        server.login(smtp_user, smtp_pass)
        server.sendmail(smtp_from, [to_email], msg.as_string())
        server.quit()

        return True, f"Mail gönderildi via {connected_via}"
    except Exception as e:
        return False, f"Mail hatası: {e}"
