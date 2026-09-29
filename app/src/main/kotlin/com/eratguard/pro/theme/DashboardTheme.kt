package com.eratguard.pro.theme

import androidx.compose.runtime.Composable
import com.eratguard.pro.designsystem.EratGuardTheme

/**
 * Compatibility entry point.
 *
 * Existing callers can keep DashboardTheme while the application
 * migrates to the unified EratGuard design system.
 */
@Composable
fun DashboardTheme(
    content: @Composable () -> Unit
) {
    EratGuardTheme(
        content = content
    )
}
