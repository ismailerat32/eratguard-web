package com.eratguard.pro.components

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxScope
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
fun NeonPanel(
    modifier: Modifier = Modifier,
    content: @Composable BoxScope.() -> Unit
) {

    Card(
        modifier = modifier,
        shape = EratGuardShapeTokens.Large,
        border = BorderStroke(
            EratGuardSizes.BorderThin,
            EratGuardColors.Border
        ),
        colors = CardDefaults.cardColors(
            containerColor = EratGuardColors.Surface
        )
    ) {

        Box(
            modifier = Modifier.padding(EratGuardSpacing.Lg),
            content = content
        )

    }

}
