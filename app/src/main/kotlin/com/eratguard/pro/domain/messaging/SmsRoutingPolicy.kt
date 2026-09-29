package com.eratguard.pro.domain.messaging

import com.eratguard.pro.spam.model.SpamVerdict

object SmsRoutingPolicy {

    enum class Destination {
        INBOX,
        QUARANTINE,
        /*
         * DROP means:
         * do not persist the newly received message to Inbox
         * or quarantine.
         *
         * It does NOT delete an existing provider row.
         */
        DROP
    }

    data class Decision(
        val destination: Destination
    )

    fun decide(
        verdict: SpamVerdict,
        highConfidenceSpam: Boolean,
        autoDeleteHighConfidenceEnabled: Boolean
    ): Decision {

        val destination =
            when {
                verdict == SpamVerdict.SPAM &&
                    highConfidenceSpam &&
                    autoDeleteHighConfidenceEnabled ->
                    Destination.DROP

                verdict == SpamVerdict.SAFE ->
                    Destination.INBOX

                else ->
                    Destination.QUARANTINE
            }

        return Decision(
            destination = destination
        )
    }
}
