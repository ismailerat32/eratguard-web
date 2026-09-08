package com.eratguard.pro.core

data class EngineState(

    val securityScore: Int = 98,

    val threatLevel: String = "LOW",

    val blockedThreats: Int = 1247,

    val aiStatus: String = "ACTIVE",

    val riskStatus: String = "LOW"

)
