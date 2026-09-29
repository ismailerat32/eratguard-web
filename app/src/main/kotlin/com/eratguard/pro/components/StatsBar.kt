package com.eratguard.pro.components

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.eratguard.pro.core.SpamEngine
import com.eratguard.pro.designsystem.EratGuardColors
import com.eratguard.pro.designsystem.EratGuardSpacing
import com.eratguard.pro.designsystem.components.EratGuardPanel

@Composable
fun StatsBar() {
    val blocked = SpamEngine.blockedMessages()

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = EratGuardSpacing.Md),
        horizontalArrangement = Arrangement.SpaceEvenly
    ) {
        StatCard(blocked.toString(), "BLOCK")
        StatCard("99%", "AI")
        StatCard("LOW", "RISK")
    }
}

@Composable
private fun StatCard(
    value: String,
    label: String
) {
    EratGuardPanel(
        modifier = Modifier.height(78.dp)
    ) {
        Column(
            verticalArrangement = Arrangement.Center
        ) {
            Text(
                text = value,
                color = EratGuardColors.TextPrimary,
                fontWeight = FontWeight.Bold,
                fontSize = 20.sp
            )

            Text(
                text = label,
                color = EratGuardColors.Primary,
                fontSize = 12.sp
            )
        }
    }
}
