package com.eratguard.pro.theme

import com.eratguard.pro.designsystem.EratGuardColors

/**
 * Compatibility bridge for existing UI.
 *
 * New UI should consume EratGuardColors directly.
 * This object remains temporarily so existing screens can migrate
 * without a large-bang rewrite.
 */
object DashboardColors {

    val Background
        get() = EratGuardColors.Background

    val Surface
        get() = EratGuardColors.Surface

    val SurfaceLight
        get() = EratGuardColors.SurfaceElevated

    val Primary
        get() = EratGuardColors.Primary

    val PrimaryGlow
        get() = EratGuardColors.PrimaryGlow

    val Accent
        get() = EratGuardColors.Accent

    val Warning
        get() = EratGuardColors.Warning

    val Danger
        get() = EratGuardColors.Danger

    val Text
        get() = EratGuardColors.TextPrimary

    val SubText
        get() = EratGuardColors.TextSecondary

    val Border
        get() = EratGuardColors.Border

    val Divider
        get() = EratGuardColors.Divider
}
