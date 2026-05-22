import json
import os
import re
from ai_model import predict

WHITELIST_FILE = "data/whitelist.json"

SPAM_KEYWORDS = [
    "kazandın", "kazandiniz", "kazandınız", "kazandin",
    "ödül", "odul", "bedava", "ücretsiz", "ucretsiz",
    "tıkla", "tikla", "linke tıkla", "linke tikla",
    "hemen", "şimdi", "simdi", "son gün", "son gun",
    "bonus", "casino", "bahis", "freebet",
    "promosyon", "kampanya", "fırsat", "firsat",
    "linke gir", "giriş yap", "giris yap",
    "onayla", "doğrula", "dogrula", "güncelle", "guncelle",
    "askıya", "askiya", "hesap askıya", "hesap askiya",
    "teslim edilemedi", "kargonuz teslim edilemedi",
    "kartınız", "kartiniz", "hesabınız", "hesabiniz",
    "şifre", "sifre", "parola", "otp",
]

DANGEROUS_DOMAINS = [
    "bit.ly", "tinyurl", "t.me", "goo.gl", "grabify",
    "short.link", "cutt.ly", "rebrand.ly", "is.gd", "ow.ly"
]

CATEGORY_RULES = {
    "BANKA": [
        "iban", "kart", "banka", "hesap", "şifre", "sifre",
        "otp", "işlem", "islem", "ödeme", "odeme",
        "askıya", "askiya", "doğrula", "dogrula"
    ],
    "KARGO": [
        "kargo", "teslimat", "paket", "gönderi", "gonderi",
        "kurye", "takip no", "sipariş", "siparis",
        "teslim edilemedi", "adres"
    ],
    "PROMOSYON": [
        "bonus", "kampanya", "promosyon", "indirim", "fırsat",
        "firsat", "bedava", "kupon", "hediye", "kazandın",
        "kazandiniz", "kazandınız"
    ],
    "DOLANDIRICILIK": [
        "tıkla", "tikla", "hemen", "onayla", "doğrula", "dogrula",
        "şifre", "sifre", "hesap askıya", "hesap askiya",
        "freebet", "casino", "bahis", "güncelle", "guncelle"
    ]
}

TR_MAP = str.maketrans({
    "ı": "i", "İ": "i", "ğ": "g", "Ğ": "g",
    "ü": "u", "Ü": "u", "ş": "s", "Ş": "s",
    "ö": "o", "Ö": "o", "ç": "c", "Ç": "c",
})


def normalize(text):
    text = str(text or "").lower().translate(TR_MAP)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def load_whitelist():
    if not os.path.exists(WHITELIST_FILE):
        return []
    try:
        with open(WHITELIST_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except Exception:
        return []


def is_whitelisted_sender(sender):
    try:
        whitelist = load_whitelist()
        sender = str(sender or "").upper().strip()
        return any(str(w).upper().strip() in sender for w in whitelist)
    except Exception:
        return False


def contains_link(text):
    text = str(text or "")
    return bool(
        re.search(r"http[s]?://", text)
        or re.search(r"\bwww\.", text.lower())
        or re.search(r"\b[a-z0-9-]+\.(com|net|org|site|click|link|xyz|top|shop|info)\b", text.lower())
    )


def extract_links(text):
    text = str(text or "")
    found = re.findall(r"http[s]?://\S+", text)
    found += re.findall(r"\bwww\.\S+", text.lower())
    found += re.findall(r"\b[a-z0-9-]+\.(?:com|net|org|site|click|link|xyz|top|shop|info)\S*", text.lower())
    return found


def detect_category(message):
    msg = normalize(message)
    scores = {}
    for category, words in CATEGORY_RULES.items():
        scores[category] = sum(1 for w in words if normalize(w) in msg)

    best_category = "GENEL"
    best_score = 0

    for category, score in scores.items():
        if score > best_score:
            best_category = category
            best_score = score

    return best_category


def calc_confidence(score, ai_used=False, whitelist_used=False):
    if whitelist_used:
        return 100
    if ai_used:
        return 95
    if score >= 90:
        return 98
    if score >= 70:
        return 94
    if score >= 50:
        return 88
    if score >= 35:
        return 80
    if score >= 20:
        return 60
    return 30


def _add(score, reasons, points, reason):
    reasons.append(reason)
    return score + points


def _keyword_matches(keyword, msg):
    keyword = normalize(keyword)
    if not keyword:
        return False

    # Çok kelimeli ifadelerde doğrudan ifade geçişi yeterli.
    if " " in keyword:
        return keyword in msg

    # Tek kelimelerde substring hatasını engelle:
    # kazandin kelimesi kazandiniz içinde sayılmasın.
    return re.search(r"(?<!\w)" + re.escape(keyword) + r"(?!\w)", msg) is not None


def analyze_sms(sender, message):
    sender = str(sender or "")
    message = str(message or "")
    msg = normalize(message)

    # 1) WHITELIST
    if is_whitelisted_sender(sender):
        return {
            "status": "TEMIZ",
            "score": 0,
            "category": "WHITELIST",
            "reason": "WHITELIST_OVERRIDE",
            "confidence": 100
        }

    # 2) AI memory
    try:
        ai_result = predict(message)

        if ai_result == "TEMIZ_AI":
            return {
                "status": "TEMIZ",
                "score": 0,
                "category": detect_category(message),
                "reason": "AI_CLEAN",
                "confidence": 95
            }

        if ai_result == "SPAM_AI":
            return {
                "status": "SPAM",
                "score": 80,
                "category": detect_category(message),
                "reason": "AI_SPAM",
                "confidence": 95
            }
    except Exception:
        pass

    # 3) Rule-based hardened engine
    score = 0
    reasons = []

    matched_keywords = set()
    matched_phrases = []

    for word in sorted(SPAM_KEYWORDS, key=lambda x: len(normalize(x)), reverse=True):
        normalized_word = normalize(word)
        if not normalized_word or normalized_word in matched_keywords:
            continue

        # Daha uzun bir ifade zaten yakalandıysa, içindeki kısa kelimeyi tekrar sayma.
        # Örnek: "linke tikla" yakalandıysa ayrıca "tikla" sayılmasın.
        if any(normalized_word != phrase and normalized_word in phrase for phrase in matched_phrases):
            continue

        if _keyword_matches(normalized_word, msg):
            matched_keywords.add(normalized_word)
            matched_phrases.append(normalized_word)
            score = _add(score, reasons, 8, normalized_word)

    has_link = contains_link(message)
    links = extract_links(message)
    link_intent = has_link or any(x in msg for x in [
        "linke tikla", "linke gir", "tikla", "giris yap"
    ])

    action_intent = has_link or any(x in msg for x in [
        "linke tikla", "linke gir", "tikla", "giris yap", "guncelle", "onayla"
    ])

    if has_link:
        score = _add(score, reasons, 18, "link")

    for link in links:
        low = link.lower()
        for domain in DANGEROUS_DOMAINS:
            if domain in low:
                score = _add(score, reasons, 28, domain)

    # High-risk phishing combinations
    if link_intent and any(x in msg for x in ["kargo", "teslimat", "paket", "kurye", "teslim edilemedi", "adres"]):
        score = _add(score, reasons, 25, "kargo_link_riski")

    if action_intent and any(x in msg for x in ["guncelle", "güncelle", "dogrula", "doğrula", "onayla", "giris yap", "giriş yap"]):
        score = _add(score, reasons, 25, "link_ile_islem_istegi")

    if any(x in msg for x in ["banka", "hesap", "kart", "iban"]) and any(x in msg for x in ["sifre", "şifre", "parola", "dogrula", "doğrula", "onayla", "askiya", "askıya"]):
        score = _add(score, reasons, 35, "banka_kimlik_avı_riski")

    if any(x in msg for x in ["hesap askiya", "hesap askıya", "askiya alindi", "askıya alındı"]):
        score = _add(score, reasons, 30, "hesap_askiya_alindi")

    if any(x in msg for x in ["kazandin", "kazandiniz", "kazandın", "kazandınız", "odul", "ödül", "bedava"]) and has_link:
        score = _add(score, reasons, 30, "odul_link_riski")

    if re.search(r"\b\d{4,6}\b", msg) and any(x in msg for x in ["kod", "sifre", "şifre", "dogrulama", "doğrulama"]):
        # OTP tarzı mesajlar tek başına spam sayılmasın; link varsa yine riskli kalır.
        if not has_link:
            score -= 12
            reasons.append("otp_benzeri_mesaj_-12")

    if len(msg) > 160 and has_link:
        score = _add(score, reasons, 10, "uzun_linkli_mesaj")

    category = detect_category(message)

    # Thresholds
    status = "SPAM" if score >= 30 else "TEMIZ"
    confidence = calc_confidence(score)

    return {
        "status": status,
        "score": max(0, score),
        "category": category,
        "reason": " + ".join(reasons) if reasons else "CLEAN",
        "confidence": confidence
    }
