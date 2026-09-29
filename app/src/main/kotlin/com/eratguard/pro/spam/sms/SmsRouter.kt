package com.eratguard.pro.spam.sms

import android.content.Context
import com.eratguard.pro.domain.messaging.SmsRoutingPolicy
import com.eratguard.pro.spam.SpamDecisionEngine
import com.eratguard.pro.spam.model.SpamVerdict
import com.eratguard.pro.spam.store.SmsInboxStore
import com.eratguard.pro.spam.store.SpamProtectionSettings
import com.eratguard.pro.spam.store.SpamQuarantineStore

object SmsRouter {

    data class RouteResult(
        val verdict: SpamVerdict,
        val score: Int,
        val inboxInserted: Boolean,
        val quarantined: Boolean,
        val failSafeActivated: Boolean = false,
        val highConfidenceSpam: Boolean = false,
        val autoDeleted: Boolean = false
    )

    fun route(
        context: Context,
        sender: String,
        body: String,
        timestamp: Long
    ): RouteResult {

        val result =
            SpamDecisionEngine.analyze(
                context = context,
                sender = sender,
                message = body
            )

        val autoDeleteEnabled =
            SpamProtectionSettings
                .isAutoDeleteHighConfidenceEnabled(
                    context
                )

        val routingDecision =
            SmsRoutingPolicy.decide(
                verdict = result.verdict,
                highConfidenceSpam =
                    result.highConfidenceSpam,
                autoDeleteHighConfidenceEnabled =
                    autoDeleteEnabled
            )

        if (
            routingDecision.destination ==
            SmsRoutingPolicy.Destination.DROP
        ) {
            return RouteResult(
                verdict = result.verdict,
                score = result.score,
                inboxInserted = false,
                quarantined = false,
                failSafeActivated = false,
                highConfidenceSpam =
                    result.highConfidenceSpam,
                autoDeleted = true
            )
        }

        return when (routingDecision.destination) {

            SmsRoutingPolicy.Destination.INBOX -> {

                val inserted =
                    SmsInboxStore.insertIfMissing(
                        context = context,
                        sender = sender,
                        body = body,
                        timestamp = timestamp
                    )

                RouteResult(
                    verdict = result.verdict,
                    score = result.score,
                    inboxInserted = inserted,
                    quarantined = false,
                    failSafeActivated = false,
                    highConfidenceSpam = result.highConfidenceSpam,
                    autoDeleted = false
                )
            }

            SmsRoutingPolicy.Destination.QUARANTINE -> {

                val quarantined =
                    SpamQuarantineStore.add(
                        context = context,
                        sender = sender,
                        body = body,
                        timestamp = timestamp,
                        score = result.score,
                        verdict = result.verdict.name,
                        reasons = result.reasons
                    )

                /*
                 * KRİTİK FAIL-SAFE:
                 *
                 * Karantinaya kalıcı yazma başarısızsa mesajı
                 * kaybetmemek için Inbox'a bırakmayı dene.
                 *
                 * Bu fail-safe otomatik silme dalında çalışmaz;
                 * çünkü kullanıcı KESİN SPAM otomatik silmeyi
                 * açıkça etkinleştirmiştir.
                 */
                if (!quarantined) {

                    val fallbackInserted =
                        SmsInboxStore.insertIfMissing(
                            context = context,
                            sender = sender,
                            body = body,
                            timestamp = timestamp
                        )

                    RouteResult(
                        verdict = result.verdict,
                        score = result.score,
                        inboxInserted = fallbackInserted,
                        quarantined = false,
                        failSafeActivated = true,
                        highConfidenceSpam = result.highConfidenceSpam,
                        autoDeleted = false
                    )

                } else {

                    RouteResult(
                        verdict = result.verdict,
                        score = result.score,
                        inboxInserted = false,
                        quarantined = true,
                        failSafeActivated = false,
                        highConfidenceSpam = result.highConfidenceSpam,
                        autoDeleted = false
                    )
                }
            }

            SmsRoutingPolicy.Destination.DROP -> {
                error(
                    "AUTO_DELETE must be handled before persistence routing."
                )
            }
        }
    }
}
