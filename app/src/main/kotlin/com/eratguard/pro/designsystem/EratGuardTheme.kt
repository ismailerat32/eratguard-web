package com.eratguard.pro.designsystem

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable

private val EratGuardDarkColorScheme =
    darkColorScheme(
        primary = EratGuardColors.Primary,
        onPrimary = EratGuardColors.Background,
        secondary = EratGuardColors.Accent,
        onSecondary = EratGuardColors.Background,
        background = EratGuardColors.Background,
        onBackground = EratGuardColors.TextPrimary,
        surface = EratGuardColors.Surface,
        onSurface = EratGuardColors.TextPrimary,
        surfaceVariant = EratGuardColors.SurfaceElevated,
        onSurfaceVariant = EratGuardColors.TextSecondary,
        error = EratGuardColors.Danger,
        onError = EratGuardColors.TextPrimary,
        outline = EratGuardColors.Border,
        outlineVariant = EratGuardColors.Divider
    )

@Composable
fun EratGuardTheme(
    content: @Composable () -> Unit
) {
    MaterialTheme(
        colorScheme = EratGuardDarkColorScheme,
        typography = EratGuardTypography,
        shapes = EratGuardShapes,
        content = content
    )
}
