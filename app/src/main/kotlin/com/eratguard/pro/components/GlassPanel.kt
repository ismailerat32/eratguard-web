package com.eratguard.pro.components

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxScope
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.eratguard.pro.theme.DashboardColors

@Composable
fun GlassPanel(
    modifier: Modifier = Modifier,
    content: @Composable BoxScope.() -> Unit
) {

    Card(
        modifier = modifier,
        shape = RoundedCornerShape(22.dp),
        border = BorderStroke(
            1.dp,
            DashboardColors.Border
        ),
        colors = CardDefaults.cardColors(
            containerColor = DashboardColors.SurfaceLight
        )
    ) {

        Box(
            modifier = Modifier.padding(16.dp),
            content = content
        )

    }

}
