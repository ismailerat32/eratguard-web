package com.eratguard.pro.designsystem

import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Shapes
import androidx.compose.ui.unit.dp

object EratGuardShapeTokens {

    val Small =
        RoundedCornerShape(8.dp)

    val Medium =
        RoundedCornerShape(12.dp)

    val Large =
        RoundedCornerShape(18.dp)

    val ExtraLarge =
        RoundedCornerShape(22.dp)

    val Pill =
        RoundedCornerShape(50)
}

val EratGuardShapes =
    Shapes(
        small = EratGuardShapeTokens.Small,
        medium = EratGuardShapeTokens.Medium,
        large = EratGuardShapeTokens.Large
    )

