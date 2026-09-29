package com.eratguard.pro.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.eratguard.pro.designsystem.EratGuardColors
import com.eratguard.pro.designsystem.EratGuardSpacing
import com.eratguard.pro.designsystem.components.EratGuardPanel

private val modules = listOf(
    "Spam Koruması",
    "AI Analiz",
    "Risk Tarama",
    "Engellenenler",
    "SMS Merkezi",
    "Geçmiş",
    "Raporlar",
    "Bildirimler",
    "İzinler",
    "Güvenlik",
    "Lisans",
    "Ayarlar"
)

@Composable
fun DashboardScreen() {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(EratGuardColors.Background)
            .padding(EratGuardSpacing.Lg)
    ) {
        HudTopBar()

        Spacer(
            modifier = Modifier.height(EratGuardSpacing.Xxl)
        )

        Text(
            text = "ERATGUARD PREMIUM",
            color = EratGuardColors.Primary,
            fontSize = 28.sp,
            fontWeight = FontWeight.Bold
        )

        Spacer(
            modifier = Modifier.height(EratGuardSpacing.Xl)
        )

        LazyVerticalGrid(
            columns = GridCells.Fixed(3),
            verticalArrangement =
                Arrangement.spacedBy(EratGuardSpacing.Md),
            horizontalArrangement =
                Arrangement.spacedBy(EratGuardSpacing.Md),
            modifier = Modifier.fillMaxSize()
        ) {
            items(modules) { item ->
                EratGuardPanel(
                    modifier = Modifier.height(120.dp)
                ) {
                    Box(
                        modifier = Modifier.fillMaxSize(),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(
                            text = item,
                            color = EratGuardColors.TextPrimary
                        )
                    }
                }
            }
        }
    }
}
