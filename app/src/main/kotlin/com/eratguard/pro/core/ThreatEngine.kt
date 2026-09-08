package com.eratguard.pro.core

object ThreatEngine {

    fun currentState(): EngineState {

        return EngineState(
            securityScore = 98,
            threatLevel = "LOW",
            blockedThreats = 1247,
            aiStatus = "ACTIVE",
            riskStatus = "LOW"
        )

    }

}
