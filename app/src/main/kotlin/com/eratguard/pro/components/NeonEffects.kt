package com.eratguard.pro.components

import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha

fun Modifier.neonGlow(
    enabled: Boolean = true
): Modifier {

    return if (enabled) {
        this.alpha(0.98f)
    } else {
        this
    }

}
