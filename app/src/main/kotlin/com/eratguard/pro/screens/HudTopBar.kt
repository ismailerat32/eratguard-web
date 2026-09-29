package com.eratguard.pro.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp
import com.eratguard.pro.designsystem.EratGuardColors
import com.eratguard.pro.designsystem.EratGuardShapeTokens
import com.eratguard.pro.designsystem.EratGuardSizes
import com.eratguard.pro.designsystem.EratGuardSpacing
import kotlinx.coroutines.delay
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Composable
fun HudTopBar() {
    var time by remember { mutableStateOf("") }

    LaunchedEffect(Unit) {
        while (true) {
            time =
                SimpleDateFormat(
                    "HH:mm:ss",
                    Locale.getDefault()
                ).format(Date())

            delay(1000)
        }
    }

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .border(
                EratGuardSizes.BorderThin,
                EratGuardColors.Border,
                EratGuardShapeTokens.Large
            )
            .background(
                EratGuardColors.SurfaceDark,
                EratGuardShapeTokens.Large
            )
            .padding(EratGuardSpacing.Lg),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column {
            Text(
                text = "KORUMA AKTİF",
                color = EratGuardColors.Accent,
                fontWeight = FontWeight.Bold,
                fontSize = 18.sp
            )

            Text(
                text = "Sistem Tam Koruma Altında",
                color = EratGuardColors.TextSecondary,
                fontSize = 12.sp
            )
        }

        Text(
            text = time,
            color = EratGuardColors.TextPrimary,
            fontSize = 22.sp,
            fontWeight = FontWeight.Bold
        )
    }
}
