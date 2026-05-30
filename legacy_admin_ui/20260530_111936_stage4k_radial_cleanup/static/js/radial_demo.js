const radialScreen = document.getElementById("radial-screen");
const featureScreen = document.getElementById("feature-screen");
const featurePanel = document.getElementById("feature-panel");
const featureTitle = document.getElementById("feature-title");
const featureIcon = document.getElementById("feature-icon");
const featureDesc = document.getElementById("feature-desc");
const featureBody = document.getElementById("feature-body");
const backBtn = document.getElementById("backBtn");

const features = {
    "panel-spam": {
        icon: "🛡️",
        title: "Spam Koruma",
        desc: "Şüpheli mesajları otomatik algılar ve koruma akışını yönetir.",
        body: `
            <p>Bu bölümde kullanıcı spam koruma seviyesini yönetebilir.</p>
            <div class="card-list">
                <div class="mini-card">Canlı spam filtresi aç / kapat</div>
                <div class="mini-card">Anahtar kelime bazlı bloklama</div>
                <div class="mini-card">Risk skoru eşik ayarı</div>
            </div>
        `
    },
    "panel-analysis": {
        icon: "📩",
        title: "SMS Analizi",
        desc: "Mesaj içerikleri akıllı şekilde incelenir ve puanlanır.",
        body: `
            <p>Burada gelen SMS'lerin analiz sonuçları gösterilir.</p>
            <div class="card-list">
                <div class="mini-card">Spam skoru</div>
                <div class="mini-card">Şüpheli kelime tespiti</div>
                <div class="mini-card">Link kontrolü</div>
            </div>
        `
    },
    "panel-blocked": {
        icon: "🚫",
        title: "Engellenenler",
        desc: "Engellenen numaralar ve mesaj geçmişi görüntülenir.",
        body: `
            <p>Kullanıcı burada bloklanan göndericileri yönetebilir.</p>
            <div class="card-list">
                <div class="mini-card">Blok listesi</div>
                <div class="mini-card">Tek dokunuşla kaldırma</div>
                <div class="mini-card">Tekrar engelleme</div>
            </div>
        `
    },
    "panel-notify": {
        icon: "🔔",
        title: "Bildirimler",
        desc: "Önemli uyarılar ve sistem bildirimleri bu bölümde toplanır.",
        body: `
            <p>SpamShield'in verdiği önemli uyarılar burada yer alır.</p>
            <div class="card-list">
                <div class="mini-card">Kritik tehdit uyarısı</div>
                <div class="mini-card">Yeni spam modeli bildirimi</div>
                <div class="mini-card">Lisans süresi hatırlatma</div>
            </div>
        `
    },
    "panel-community": {
        icon: "👥",
        title: "Topluluk",
        desc: "Topluluktan gelen spam raporları ve ortak veri akışı burada olur.",
        body: `
            <p>Topluluktan gelen raporlarla sistem güçlenir.</p>
            <div class="card-list">
                <div class="mini-card">Topluluk spam raporları</div>
                <div class="mini-card">Yeni tehdit paylaşımı</div>
                <div class="mini-card">Ortak kara liste desteği</div>
            </div>
        `
    },
    "panel-settings": {
        icon: "⚙️",
        title: "Ayarlar",
        desc: "Genel sistem tercihleri, tema ve kullanıcı yapılandırmaları burada olur.",
        body: `
            <p>Uygulamanın davranışı buradan özelleştirilir.</p>
            <div class="card-list">
                <div class="mini-card">Tema seçimi</div>
                <div class="mini-card">Bildirim ayarları</div>
                <div class="mini-card">Güvenlik tercihleri</div>
            </div>
        `
    }
};

document.querySelectorAll(".slice").forEach((btn) => {
    btn.addEventListener("click", () => {
        const key = btn.dataset.target;
        const item = features[key];
        if (!item) return;

        featureTitle.textContent = item.title;
        featureIcon.textContent = item.icon;
        featureDesc.textContent = item.desc;
        featureBody.innerHTML = item.body;

        radialScreen.classList.remove("active");
        featureScreen.classList.add("active");

        setTimeout(() => {
            featurePanel.classList.add("show");
        }, 50);
    });
});

backBtn.addEventListener("click", () => {
    featurePanel.classList.remove("show");

    setTimeout(() => {
        featureScreen.classList.remove("active");
        radialScreen.classList.add("active");
    }, 220);
});
