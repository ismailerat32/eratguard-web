package com.eratguard.pro.designsystem.components

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import com.eratguard.pro.designsystem.EratGuardColors
import com.eratguard.pro.designsystem.EratGuardShapeTokens
import com.eratguard.pro.designsystem.EratGuardSizes
import com.eratguard.pro.designsystem.EratGuardSpacing

@Composable
fun EratGuardPanel(
    modifier: Modifier = Modifier,
    content: @Composable ColumnScope.() -> Unit
) {
    Card(
        modifier = modifier,
        shape = EratGuardShapeTokens.ExtraLarge,
        border = BorderStroke(
            EratGuardSizes.BorderThin,
            EratGuardColors.Border
        ),
        colors = CardDefaults.cardColors(
            containerColor = EratGuardColors.SurfaceElevated
        )
    ) {
        Column(
            modifier = Modifier.padding(EratGuardSpacing.Lg),
            content = content
        )
    }
}
