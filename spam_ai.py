import re

OFFICIAL_DOMAINS = {
    "akbank": ["akbank.com"],
    "garanti": ["garanti.com.tr"],
    "ziraat": ["ziraatbank.com.tr"],
    "halkbank": ["halkbank.com.tr"],
    "isbank": ["isbank.com.tr"],
    "edevlet": ["turkiye.gov.tr"],
    "e-devlet": ["turkiye.gov.tr"],
    "sgk": ["sgk.gov.tr"],
    "gib": ["gib.gov.tr"],
    "ptt": ["ptt.gov.tr"],
}


SPAM_WORDS = {
    "kazan": 5,
    "kazandınız": 6,
    "kazandiniz": 6,
    "ödül": 5,
    "odul": 5,
    "bedava": 3,
    "ücretsiz": 2,
    "ucretsiz": 2,
    "çekiliş": 3,
    "cekilis": 3,
    "kampanya": 2,
    "indirim": 2,
    "fırsat": 2,
    "firsat": 2,
    "kaçırma": 2,
    "kacirma": 2,
    "hediye": 2,
    "kupon": 2,
    "bonus": 2,
    "puan": 2,
    "gb": 1,
    "tl": 1,
    "market": 1,
    "alışveriş": 1,
    "alisveris": 1,
    "anket": 2,
    "katıl": 2,
    "katil": 2,
    "hemen": 3,
    "son gün": 2,
    "son gun": 2,
    "özel": 1,
    "ozel": 1,
}

SAFE_WORDS = {
    "şifre": 4,
    "sifre": 4,
    "şifreniz": 4,
    "sifreniz": 4,
    "doğrulama": 4,
    "dogrulama": 4,
    "kod": 3,
    "kodunuz": 4,
    "tek kullanımlık": 4,
    "tek kullanimlik": 4,
    "kartınızdan": 4,
    "kartinizdan": 4,
    "hesabınızdan": 4,
    "hesabinizdan": 4,
    "dekont": 3,
    "sorgu numarası": 4,
    "sorgu numarasi": 4,
    "ödeme": 3,
    "odeme": 3,
    "işlem": 3,
    "islem": 3,
    "başvuru": 3,
    "basvuru": 3,
}

SAFE_SENDERS = [
    "HALKBANK", "ON.", "TURKTELEKOM", "TT", "GARANTI", "AKBANK",
    "YAPIKREDI", "ISBANK", "ZIRAAT", "VAKIFBANK"
]

PROMO_SENDERS = [
    "MARKET", "COCO", "MEYDAN", "KAZAN", "FIRSAT", "FIDAN", "SOK"
]

def normalize(text):
    text = str(text or "").lower()
    tr = str.maketrans({
        "ı": "i", "İ": "i", "ğ": "g", "Ğ": "g",
        "ü": "u", "Ü": "u", "ş": "s", "Ş": "s",
        "ö": "o", "Ö": "o", "ç": "c", "Ç": "c",
    })
    text = text.translate(tr)
    text = re.sub(r"\s+", " ", text)
    return text.strip()

def analiz_et(text, sender=""):
    raw = str(text or "")
    clean = normalize(raw)
    sender_raw = str(sender or "")
    sender_up = sender_raw.upper()

    score = 0
    reasons = []

    for word, weight in SPAM_WORDS.items():
        if normalize(word) in clean:
            score += weight
            reasons.append(f"spam:{word}+{weight}")

    for word, weight in SAFE_WORDS.items():
        if normalize(word) in clean:
            score -= weight
            reasons.append(f"safe:{word}-{weight}")

    if "http" in clean or "www" in clean or ".com" in clean:
        score += 8

        reasons.append("link+8")

    m = re.search(r'https?://([^/\s]+)', clean)
    if m:
        domain = m.group(1).lower()

        trusted_domain = False

        for kurum, domains in OFFICIAL_DOMAINS.items():
            if kurum in clean:
                if any(domain.endswith(d) for d in domains):
                    trusted_domain = True
                else:
                    score += 20
                    reasons.append(f"fake_domain:{kurum}+20")
                    break

        if trusted_domain and "link+8" in reasons:
            score -= 8
            reasons.remove("link+8")


    # URL Risk Engine v1
    if m:
        # IP adresiyle link
        if re.match(r'^\d{1,3}(?:\.\d{1,3}){3}$', domain):
            score += 15
            reasons.append("ip_link+15")

        # URL kısaltıcıları
        elif domain.endswith((
            "bit.ly",
            "tinyurl.com",
            "t.co",
            "rb.gy",
            "cutt.ly",
            "is.gd"
        )):
            score += 10
            reasons.append("short_url+10")


        # Unicode / IDN (Punycode) domain
        if domain.startswith("xn--"):
            score += 12
            reasons.append("idn_domain+12")

        # Şüpheli TLD
        elif domain.endswith((
            ".xyz",
            ".top",
            ".click",
            ".live",
            ".shop"
        )):
            score += 8
            reasons.append("suspicious_tld+8")


    if ("http" in clean or "www" in clean or ".com" in clean):
        if any(x in clean for x in ["ödül","odul","kazandınız","kazandiniz"]):
            score += 10
            reasons.append("reward+link+10")

        if any(x in clean for x in ["hemen","acil","tıklayın","tiklayin"]):
            score += 8
            reasons.append("urgent+link+8")

        if (not trusted_domain) and any(x in clean for x in [
            "ziraat","akbank","garanti","isbank",
            "vakif","vakıf","halkbank"
        ]):
            score += 15
            reasons.append("bank+link+15")

    if "%" in raw:
        score += 2
        reasons.append("yuzde+2")

    if re.search(r"\b\d+\s*(tl|gb)\b", clean):
        score += 2
        reasons.append("para_gb+2")

    if re.search(r"\b\d{4,6}\b", clean) and ("sifre" in clean or "kod" in clean):
        score -= 3
        reasons.append("otp_kod-3")

    if any(x in sender_up for x in PROMO_SENDERS):
        score += 2
        reasons.append("promo_sender+2")

    if any(x in sender_up for x in SAFE_SENDERS):
        if any(normalize(w) in clean for w in SAFE_WORDS):
            score -= 2
            reasons.append("trusted_sender_safe-2")

    # Kısa mesaj ama promosyon kelimesi varsa şüpheli
    if len(clean) < 25 and score > 0:
        score += 1
        reasons.append("kisa_supheli+1")

    # Güvenli banka işlemleri negatifte kalırsa spam olmasın
    is_spam = score >= 8

    return {
        "spam": is_spam,
        "score": score,
        "reasons": reasons[:10]
    }

def spam_mi(text):
    return analiz_et(text)["spam"]
