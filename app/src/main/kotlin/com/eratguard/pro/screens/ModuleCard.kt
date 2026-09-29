package com.eratguard.pro.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.eratguard.pro.components.GlassPanel
import com.eratguard.pro.components.neonGlow
import com.eratguard.pro.designsystem.EratGuardColors
import com.eratguard.pro.designsystem.EratGuardSpacing

@Composable
fun ModuleCard(
    title: String,
    subtitle: String = "",
    active: Boolean = true,
    onClick: () -> Unit = {}
) {
    GlassPanel(
        modifier = Modifier
            .fillMaxWidth()
            .height(140.dp)
            .neonGlow()
            .clickable(onClick = onClick)
    ) {
        Column(
            modifier = Modifier.fillMaxSize()
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement =
                    Arrangement.SpaceBetween,
                verticalAlignment =
                    Alignment.CenterVertically
            ) {
                Text(
                    text = "🛡",
                    fontSize = 22.sp
                )

                Box(
                    modifier = Modifier
                        .size(10.dp)
                        .clip(CircleShape)
                        .background(
                            if (active) {
                                EratGuardColors.Accent
                            } else {
                                EratGuardColors.Danger
                            }
                        )
                )
            }

            Spacer(
                modifier = Modifier.weight(1f)
            )

            Text(
                text = title,
                color = EratGuardColors.TextPrimary,
                fontWeight = FontWeight.Bold,
                fontSize = 16.sp,
                textAlign = TextAlign.Center,
                modifier = Modifier.fillMaxWidth()
            )

            Spacer(
                modifier = Modifier.height(EratGuardSpacing.Xs)
            )

            Text(
                text = subtitle,
                color = EratGuardColors.TextSecondary,
                fontSize = 12.sp,
                textAlign = TextAlign.Center,
                modifier = Modifier.fillMaxWidth()
            )
        }
    }
}
