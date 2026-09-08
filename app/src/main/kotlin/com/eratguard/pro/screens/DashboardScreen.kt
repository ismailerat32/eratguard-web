package com.eratguard.pro.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

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
            .background(Color(0xFF07121B))
            .padding(16.dp)
    ) {

        HudTopBar()

        Spacer(modifier = Modifier.height(24.dp))

        Text(
            text = "ERATGUARD PREMIUM",
            color = Color(0xFF00E5FF),
            fontSize = 28.sp,
            fontWeight = FontWeight.Bold
        )

        Spacer(modifier = Modifier.height(20.dp))

        LazyVerticalGrid(
            columns = GridCells.Fixed(3),
            verticalArrangement = Arrangement.spacedBy(12.dp),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            modifier = Modifier.fillMaxSize()
        ) {

            items(modules) { item ->

                Card(
                    colors = CardDefaults.cardColors(
                        containerColor = Color(0xFF102430)
                    ),
                    shape = RoundedCornerShape(20.dp),
                    modifier = Modifier.height(120.dp)
                ) {

                    Box(
                        modifier = Modifier.fillMaxSize(),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(
                            text = item,
                            color = Color.White,
                            style = MaterialTheme.typography.titleMedium
                        )
                    }

                }

            }

        }

    }

}
