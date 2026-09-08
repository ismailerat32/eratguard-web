package com.eratguard.pro.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.eratguard.pro.components.GlassPanel
import com.eratguard.pro.components.neonGlow
import com.eratguard.pro.theme.DashboardColors

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
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
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
                            if (active)
                                DashboardColors.Accent
                            else
                                DashboardColors.Danger
                        )
                )

            }

            Spacer(modifier = Modifier.weight(1f))

            Text(
                text = title,
                color = DashboardColors.Text,
                fontWeight = FontWeight.Bold,
                fontSize = 16.sp,
                textAlign = TextAlign.Center,
                modifier = Modifier.fillMaxWidth()
            )

            Spacer(modifier = Modifier.height(6.dp))

            Text(
                text = subtitle,
                color = DashboardColors.SubText,
                fontSize = 12.sp,
                textAlign = TextAlign.Center,
                modifier = Modifier.fillMaxWidth()
            )

        }

    }

}
