package com.eratguard.pro.components

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.eratguard.pro.theme.DashboardColors
import com.eratguard.pro.core.EngineState
import com.eratguard.pro.core.ThreatEngine

@Composable
fun SecurityScore() {
    val state = ThreatEngine.currentState()

    GlassPanel(
        modifier = Modifier.fillMaxWidth()
    ) {

        Column {

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {

                Text(
                    "SECURITY SCORE",
                    color = DashboardColors.SubText,
                    fontSize = 12.sp
                )

                Text(
                    state.securityScore.toString(),
                    color = DashboardColors.Accent,
                    fontWeight = FontWeight.Bold,
                    fontSize = 24.sp
                )

            }

            Spacer(modifier = Modifier.height(12.dp))

            LinearProgressIndicator(
                progress = state.securityScore / 100f,
                modifier = Modifier.fillMaxWidth(),
                color = DashboardColors.Primary,
                trackColor = Color(0xFF173648)
            )

            Spacer(modifier = Modifier.height(10.dp))

            Text(
                "Threat Level : ${state.threatLevel}",
                color = DashboardColors.Text,
                fontSize = 13.sp
            )

        }

    }

}
