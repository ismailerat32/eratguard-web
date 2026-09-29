package com.eratguard.pro.designsystem.components

import androidx.compose.foundation.layout.RowScope
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import com.eratguard.pro.designsystem.EratGuardColors

@Composable
fun EratGuardTextButton(
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    content: @Composable RowScope.() -> Unit
) {
    TextButton(
        onClick = onClick,
        modifier = modifier,
        enabled = enabled,
        colors = ButtonDefaults.textButtonColors(
            contentColor = EratGuardColors.Primary,
            disabledContentColor = EratGuardColors.TextSecondary
        ),
        content = content
    )
}
