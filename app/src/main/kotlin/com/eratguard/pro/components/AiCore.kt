package com.eratguard.pro.components

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.eratguard.pro.theme.DashboardColors

@Composable
fun AiCore() {

    Box(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 24.dp),
        contentAlignment = Alignment.Center
    ) {

        Canvas(
            modifier = Modifier.size(220.dp)
        ) {

            drawArc(
                color = DashboardColors.Primary,
                startAngle = 0f,
                sweepAngle = 300f,
                useCenter = false,
                topLeft = Offset.Zero,
                size = Size(size.width, size.height),
                style = Stroke(width = 3.dp.toPx())
            )

        }

        Box(
            modifier = Modifier
                .size(170.dp)
                .clip(CircleShape)
                .background(
                    Brush.radialGradient(
                        listOf(
                            DashboardColors.Primary,
                            Color(0xFF004A63),
                            DashboardColors.Background
                        )
                    )
                )
                .border(
                    2.dp,
                    DashboardColors.Primary,
                    CircleShape
                ),
            contentAlignment = Alignment.Center
        ) {

            Column(
                horizontalAlignment = Alignment.CenterHorizontally
            ) {

                Text(
                    text = "AI",
                    color = DashboardColors.Text,
                    fontWeight = FontWeight.Bold,
                    fontSize = 34.sp
                )

                Spacer(modifier = Modifier.height(6.dp))

                Text(
                    text = "ACTIVE",
                    color = DashboardColors.Accent,
                    fontSize = 14.sp
                )

            }

        }

    }

}
