package com.eratguard.pro.components

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.eratguard.pro.screens.ModuleCard

private val modules = listOf(
    "Spam Koruması" to "AI Filtre",
    "AI Analiz" to "Akıllı Tarama",
    "Risk Tarama" to "Canlı Kontrol",
    "Engellenenler" to "Kara Liste",
    "SMS Merkezi" to "Mesajlar",
    "Geçmiş" to "Kayıtlar",
    "Raporlar" to "İstatistik",
    "Bildirimler" to "Uyarılar",
    "İzinler" to "Android",
    "Güvenlik" to "Koruma",
    "Lisans" to "Premium",
    "Ayarlar" to "Sistem"
)

@Composable
fun ModuleGrid(
    onSmsCenterClick: () -> Unit = {}
) {

    LazyVerticalGrid(
        columns = GridCells.Fixed(3),
        modifier = Modifier.height(520.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
        horizontalArrangement = Arrangement.spacedBy(12.dp)
    ) {

        items(modules) { module ->

            ModuleCard(
                title = module.first,
                subtitle = module.second,
                onClick = {
                    if (module.first == "SMS Merkezi") {
                        onSmsCenterClick()
                    }
                }
            )

        }

    }

}
