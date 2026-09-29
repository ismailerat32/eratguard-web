package com.eratguard.pro.components

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp
import com.eratguard.pro.core.ThreatEngine
import com.eratguard.pro.designsystem.EratGuardColors
import com.eratguard.pro.designsystem.EratGuardSpacing

@Composable
fun SecurityScore() {
    val state = ThreatEngine.currentState()

    GlassPanel(
        modifier = Modifier.fillMaxWidth()
    ) {
        Column {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement =
                    Arrangement.SpaceBetween
            ) {
                Text(
                    text = "SECURITY SCORE",
                    color = EratGuardColors.TextSecondary,
                    fontSize = 12.sp
                )

                Text(
                    text = state.securityScore.toString(),
                    color = EratGuardColors.Accent,
                    fontWeight = FontWeight.Bold,
                    fontSize = 24.sp
                )
            }

            Spacer(
                modifier = Modifier.height(EratGuardSpacing.Md)
            )

            LinearProgressIndicator(
                progress = {
                    (state.securityScore / 100f)
                        .coerceIn(0f, 1f)
                },
                modifier = Modifier.fillMaxWidth(),
                color = EratGuardColors.Primary,
                trackColor = EratGuardColors.SurfaceElevated
            )

            Spacer(
                modifier = Modifier.height(EratGuardSpacing.Md)
            )

            Text(
                text = "Threat Level : ${state.threatLevel}",
                color = EratGuardColors.TextPrimary,
                fontSize = 13.sp
            )
        }
    }
}
