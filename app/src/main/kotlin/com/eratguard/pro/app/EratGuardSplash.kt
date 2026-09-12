package com.eratguard.pro.app

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.eratguard.pro.R

private val SplashBg = Color(0xFF01070C)
private val SplashCyan = Color(0xFF00E7FF)
private val SplashText = Color(0xFFD9F8FF)
private val SplashMuted = Color(0xFF8FB8C8)

private data class SplashInfo(
    val code: String,
    val category: String,
    val title: String,
    val description: String
)

private val splashInfos = listOf(
    SplashInfo(
        "01",
        "KORUMA",
        "GERÇEK ZAMANLI KORUMA",
        "Tehditleri ve şüpheli etkinlikleri sürekli analiz eder, cihazınızı anlık olarak korur."
    ),
    SplashInfo(
        "02",
        "YAPAY ZEKA",
        "YAPAY ZEKA ANALİZİ",
        "Güvenlik verilerini yapay zeka desteğiyle analiz eder ve olası riskleri değerlendirir."
    ),
    SplashInfo(
        "03",
        "OPTİMİZASYON",
        "SİSTEM OPTİMİZASYONU",
        "Sistem durumunu izler ve güvenlik bileşenlerinin düzenli çalışmasını destekler."
    ),
    SplashInfo(
        "04",
        "GİZLİLİK",
        "GİZLİLİK KONTROLÜ",
        "Gizlilik ve güvenlik kontrollerini tek merkezden yönetmenize yardımcı olur."
    ),
    SplashInfo(
        "05",
        "SİSTEM",
        "ERATGUARD HAZIR",
        "Koruma sistemleri hazırlanıyor. EratGuard her zaman bir adım önde."
    )
)

@Composable
fun EratGuardSplash(
    progress: Int,
    statusText: String
) {
    val safeProgress = progress.coerceIn(0, 100)

    // 13 sn splash:
    // 01: 0.0 - 2.5 sn
    // 02: 2.5 - 5.0 sn
    // 03: 5.0 - 7.5 sn
    // 04: 7.5 - 10.0 sn
    // 05: 10.0 sn -> WebView READY
    val index = when {
        safeProgress < 19 -> 0
        safeProgress < 38 -> 1
        safeProgress < 57 -> 2
        safeProgress < 76 -> 3
        else -> 4
    }

    val info = splashInfos[index]

    BoxWithConstraints(
        modifier = Modifier
            .fillMaxSize()
            .background(SplashBg)
    ) {

        /*
         * Kullanıcının seçtiği FINAL EratGuard görseli.
         */
        Image(
            painter = painterResource(
                id = R.drawable.eratguard_splash_final
            ),
            contentDescription = "EratGuard Splash",
            modifier = Modifier.fillMaxSize(),
            contentScale = ContentScale.Crop
        )

        /*
         * FINAL PNG içindeki sabit kart ve sabit 5 nokta
         * ayrı, tam opak bir katmanla kapatılır.
         */
        Box(
            modifier = Modifier
                .align(Alignment.TopCenter)
                .fillMaxWidth()
                .padding(top = maxHeight * 0.640f)
                .height(maxHeight * 0.270f)
                .background(SplashBg)
        )

        /*
         * Dinamik bilgi kartı.
         */
        Column(
            modifier = Modifier
                .align(Alignment.TopCenter)
                .fillMaxWidth()
                .padding(horizontal = 20.dp)
                .padding(top = maxHeight * 0.655f)
                .height(maxHeight * 0.155f)
                .clip(RoundedCornerShape(7.dp))
                .background(Color(0xFF020A10))
                .border(
                    width = 1.dp,
                    color = SplashCyan.copy(alpha = 0.42f),
                    shape = RoundedCornerShape(7.dp)
                )
                .padding(
                    horizontal = 17.dp,
                    vertical = 14.dp
                )
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "${info.code} / 05",
                    color = SplashCyan,
                    fontSize = 10.sp,
                    fontWeight = FontWeight.Bold,
                    letterSpacing = 1.4.sp
                )

                Spacer(Modifier.width(12.dp))

                Box(
                    modifier = Modifier
                        .height(1.dp)
                        .weight(1f)
                        .background(
                            SplashCyan.copy(alpha = 0.30f)
                        )
                )

                Spacer(Modifier.width(12.dp))

                Text(
                    text = info.category,
                    color = SplashMuted,
                    fontSize = 8.sp,
                    letterSpacing = 1.3.sp
                )
            }

            Spacer(Modifier.height(12.dp))

            Text(
                text = info.title,
                color = SplashCyan,
                fontSize = 15.sp,
                fontWeight = FontWeight.Bold,
                letterSpacing = 0.7.sp
            )

            Spacer(Modifier.height(7.dp))

            Text(
                text = info.description,
                color = SplashText.copy(alpha = 0.80f),
                fontSize = 10.sp,
                lineHeight = 15.sp
            )
        }

        /*
         * FINAL PNG içindeki eski sabit 5 nokta için
         * bağımsız maske. Alt motto korunur.
         */
        Box(
            modifier = Modifier
                .align(Alignment.TopCenter)
                .fillMaxWidth()
                .padding(top = maxHeight * 0.865f)
                .height(maxHeight * 0.055f)
                .background(SplashBg)
        )

        /*
         * Dinamik 5 aşama göstergesi.
         * Bu katman nokta maskesinin üstünde çizilir.
         */
        Row(
            modifier = Modifier
                .align(Alignment.TopCenter)
                .padding(top = maxHeight * 0.830f),
            horizontalArrangement = Arrangement.Center,
            verticalAlignment = Alignment.CenterVertically
        ) {
            repeat(5) { dot ->
                Box(
                    modifier = Modifier
                        .width(
                            if (dot == index) 12.dp
                            else 7.dp
                        )
                        .height(7.dp)
                        .clip(RoundedCornerShape(50))
                        .background(
                            if (dot == index)
                                SplashCyan
                            else
                                SplashMuted.copy(alpha = 0.35f)
                        )
                )

                if (dot < 4) {
                    Spacer(Modifier.width(18.dp))
                }
            }
        }

        /*
         * Alt motto görselde zaten bulunuyor.
         * statusText bilinçli olarak çizilmiyor.
         * Render gate EratGuardApp içinde çalışmaya devam ediyor.
         */
    }
}
