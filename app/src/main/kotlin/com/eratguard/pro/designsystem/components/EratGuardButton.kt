package com.eratguard.pro.designsystem.components

import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.height
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.eratguard.pro.designsystem.EratGuardColors
import com.eratguard.pro.designsystem.EratGuardShapeTokens
import com.eratguard.pro.designsystem.EratGuardSizes

@Composable
fun EratGuardButton(
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    loading: Boolean = false,
    content: @Composable RowScope.() -> Unit
) {
    Button(
        onClick = onClick,
        modifier = modifier.height(EratGuardSizes.ButtonHeight),
        enabled = enabled && !loading,
        shape = EratGuardShapeTokens.Large,
        colors = ButtonDefaults.buttonColors(
            containerColor = EratGuardColors.Primary,
            contentColor = EratGuardColors.Background,
            disabledContainerColor =
                EratGuardColors.SurfaceElevated,
            disabledContentColor =
                EratGuardColors.TextSecondary
        )
    ) {
        if (loading) {
            CircularProgressIndicator(
                modifier = Modifier.height(22.dp),
                strokeWidth = 2.dp,
                color = MaterialTheme.colorScheme.onPrimary
            )
        } else {
            content()
        }
    }
}
