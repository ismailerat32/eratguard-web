package com.eratguard.pro.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable

private val EratGuardColors = darkColorScheme(
    primary = DashboardColors.Primary,
    secondary = DashboardColors.Accent,
    background = DashboardColors.Background,
    surface = DashboardColors.Surface,
    onPrimary = DashboardColors.Text,
    onBackground = DashboardColors.Text,
    onSurface = DashboardColors.Text
)

@Composable
fun DashboardTheme(
    content: @Composable () -> Unit
) {
    MaterialTheme(
        colorScheme = EratGuardColors,
        content = content
    )
}
