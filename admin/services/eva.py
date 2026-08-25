"""
EVA — EratGuard AI asistanı.
Google Gemini API'sini kullanir. Anahtar ortam degiskeninden okunur,
koda asla yazilmaz.
"""
import os
import json
import urllib.request
import urllib.error

from .dashboard import get_dashboard_data


GEMINI_MODEL = "gemini-flash-latest"
GEMINI_URL = (
    "https://generativelanguage.googleapis.com/v1beta/models/"
    + GEMINI_MODEL
    + ":generateContent"
)


def _api_key():
    return os.environ.get("GEMINI_API_KEY", "").strip()


def _build_admin_context():
    """Gercek admin_stats verisini EVA'nin baglamina (context) donusturur.
    Hicbir sayi uydurulmaz, sadece dashboard servisinden okunan gercek veri kullanilir."""
    data = get_dashboard_data()
    stats = data.get("admin_stats", {})

    lines = [
        "Sen EVA'sin, EratGuard adli bir SMS/spam guvenlik uygulamasinin "
        "admin panelinde calisan bir yapay zeka asistanisin.",
        "Asagida sistemin GUNCEL, GERCEK verileri var. Sadece bu verilere dayanarak konus, "
        "sayi uydurma, tahmin etme; bilmedigin bir sey sorulursa bilmedigini soyle.",
        "",
        f"- Toplam kullanici: {stats.get('total_users', 0)} "
        f"(aktif: {stats.get('active_users', 0)}, admin: {stats.get('admin_users', 0)}, "
        f"banli: {stats.get('banned_users', 0)})",
        f"- Lisanslar: {stats.get('total_licenses', 0)} toplam, "
        f"{stats.get('used_licenses', 0)} kullanilan, {stats.get('expired_licenses', 0)} suresi dolmus",
        f"- Bekleyen odeme talebi: {stats.get('pending_payments', 0)}",
        f"- Guvenlik uyarilari: {stats.get('security_warnings', 0)}, "
        f"kritik olay: {stats.get('critical_events', 0)}",
        f"- Spam kayitlari: {stats.get('spam_logs', 0)}, engellenen: {stats.get('blocked', 0)}, "
        f"guvenli liste: {stats.get('safe_list', 0)}",
        f"- Bildirimler: {stats.get('notifications', 0)}",
        f"- Sistem durumu: {stats.get('system', 'ONLINE')} / {stats.get('health', 'HEALTHY')}",
    ]

    return "\n".join(lines)


def ask_eva(user_message, history=None):
    """
    user_message: kullanicinin son mesaji (str)
    history: onceki mesajlar listesi [{"role": "user"|"model", "text": "..."}]
    Donus: (basarili: bool, cevap_veya_hata: str)
    """
    key = _api_key()
    if not key:
        return False, "EVA su an devrede degil: GEMINI_API_KEY tanimli degil."

    system_context = _build_admin_context()

    contents = []
    contents.append({
        "role": "user",
        "parts": [{"text": system_context}],
    })
    contents.append({
        "role": "model",
        "parts": [{"text": "Anladim, hazirim. EratGuard admin paneli icin size yardimci olabilirim."}],
    })

    if history:
        for turn in history[-10:]:
            role = "model" if turn.get("role") == "model" else "user"
            text = str(turn.get("text", "")).strip()
            if text:
                contents.append({"role": role, "parts": [{"text": text}]})

    contents.append({
        "role": "user",
        "parts": [{"text": str(user_message)}],
    })

    payload = json.dumps({"contents": contents}).encode("utf-8")

    req = urllib.request.Request(
        GEMINI_URL + "?key=" + key,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        try:
            err_body = json.loads(e.read().decode("utf-8"))
            msg = err_body.get("error", {}).get("message", str(e))
        except Exception:
            msg = str(e)
        return False, "EVA API hatasi: " + msg
    except Exception as e:
        return False, "EVA baglanti hatasi: " + repr(e)

    try:
        candidates = body.get("candidates", [])
        if not candidates:
            return False, "EVA bos cevap dondurdu."

        parts = candidates[0].get("content", {}).get("parts", [])
        text_parts = [p.get("text", "") for p in parts if "text" in p]
        answer = "".join(text_parts).strip()

        if not answer:
            return False, "EVA bos cevap dondurdu."

        return True, answer
    except Exception as e:
        return False, "EVA cevap ayristirma hatasi: " + repr(e)


def _build_user_context(username, metrics, license_info):
    """Kullanicinin SADECE KENDI verisini icerir. Admin/diger kullanici
    verisine hicbir sekilde erisim yoktur."""
    lines = [
        "Sen EVA'sin, EratGuard adli bir SMS/spam guvenlik uygulamasinin "
        "kullanici asistanisin.",
        "Sadece bu kullanicinin KENDI verilerine gore konus. Diger kullanicilar, "
        "admin bilgileri veya sistem geneli hakkinda hicbir sey bilmiyorsun ve "
        "bu konularda soru gelirse bilgin olmadigini soyle.",
        "",
        f"- Kullanici adi: {username}",
        f"- Toplam taranan: {metrics.get('total', 0)}",
        f"- Engellenen: {metrics.get('blocked', 0)}",
        f"- Guvenli: {metrics.get('safe', 0)}",
        f"- Sikayet edilen: {metrics.get('reported', 0)}",
        f"- Guvenlik skoru: {metrics.get('score', 0)}",
        f"- Tehdit seviyesi: {metrics.get('threat_label', 'Bilinmiyor')}",
        f"- Lisans plani: {license_info.get('plan', 'Ucretsiz')}",
        f"- Lisans bitis: {license_info.get('expires_at', '-')}",
    ]
    return "\n".join(lines)


def ask_eva_user(username, metrics, license_info, user_message, history=None):
    """Kullanici modu: sadece kendi verisiyle sinirli EVA cevabi uretir."""
    key = _api_key()
    if not key:
        return False, "EVA su an devrede degil, lutfen daha sonra tekrar deneyin."

    system_context = _build_user_context(username, metrics, license_info)

    contents = [
        {"role": "user", "parts": [{"text": system_context}]},
        {"role": "model", "parts": [{"text": "Anladim, hazirim. Size nasil yardimci olabilirim?"}]},
    ]

    if history:
        for turn in history[-10:]:
            role = "model" if turn.get("role") == "model" else "user"
            text = str(turn.get("text", "")).strip()
            if text:
                contents.append({"role": role, "parts": [{"text": text}]})

    contents.append({"role": "user", "parts": [{"text": str(user_message)}]})

    payload = json.dumps({"contents": contents}).encode("utf-8")
    req = urllib.request.Request(
        GEMINI_URL + "?key=" + key,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        try:
            err_body = json.loads(e.read().decode("utf-8"))
            msg = err_body.get("error", {}).get("message", str(e))
        except Exception:
            msg = str(e)
        return False, "EVA su an yanit veremiyor: " + msg
    except Exception:
        return False, "EVA baglanti hatasi, lutfen tekrar deneyin."

    try:
        candidates = body.get("candidates", [])
        if not candidates:
            return False, "EVA bos cevap dondurdu."
        parts = candidates[0].get("content", {}).get("parts", [])
        answer = "".join(p.get("text", "") for p in parts if "text" in p).strip()
        if not answer:
            return False, "EVA bos cevap dondurdu."
        return True, answer
    except Exception:
        return False, "EVA cevap ayristirma hatasi."


# ===== KALICI KONUSMA HAFIZASI =====
import os as _eva_os

_EVA_CONV_FILE = "data/eva_conversations.json"


def _eva_load_conversations():
    try:
        if _eva_os.path.exists(_EVA_CONV_FILE):
            with open(_EVA_CONV_FILE, encoding="utf-8") as f:
                txt = f.read().strip()
                if txt:
                    return json.loads(txt)
    except Exception:
        pass
    return {}


def _eva_save_conversations(data):
    try:
        _eva_os.makedirs("data", exist_ok=True)
        with open(_EVA_CONV_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


def get_conversation(conv_key):
    """conv_key ornek: 'admin:admin' veya 'user:demo' """
    data = _eva_load_conversations()
    return data.get(conv_key, [])


def append_conversation(conv_key, role, text):
    data = _eva_load_conversations()
    history = data.get(conv_key, [])
    history.append({"role": role, "text": text})
    # Son 40 mesajla sinirla, dosya sonsuza kadar buyumesin
    data[conv_key] = history[-40:]
    _eva_save_conversations(data)
# ===== KALICI KONUSMA HAFIZASI END =====
