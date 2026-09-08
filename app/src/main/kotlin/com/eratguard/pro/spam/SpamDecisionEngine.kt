package com.eratguard.pro.spam

import android.content.Context
import com.eratguard.pro.spam.learning.SpamLearningStore
import com.eratguard.pro.spam.model.SpamResult

object SpamDecisionEngine {

    fun analyze(
        context: Context,
        sender: String,
        message: String
    ): SpamResult {

        val base =
            SpamRiskEngine.analyze(
                sender = sender,
                message = message
            )

        val learningAdjustment =
            SpamLearningStore.senderAdjustment(
                context = context,
                sender = sender
            )

        return SpamDecisionCore.applyLearning(
            base = base,
            learningAdjustment = learningAdjustment
        )
    }
}
