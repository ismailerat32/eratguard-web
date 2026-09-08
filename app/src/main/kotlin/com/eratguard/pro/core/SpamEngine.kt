package com.eratguard.pro.core

object SpamEngine {

    fun blockedMessages(): Int = 1247

    fun isProtectionEnabled(): Boolean = true

    fun protectionStatus(): String =
        if (isProtectionEnabled()) "ACTIVE"
        else "OFF"

}
