package com.eratguard.pro.spam.sms

import android.content.Context
import com.eratguard.pro.spam.SpamDecisionEngine
import com.eratguard.pro.spam.model.SpamVerdict
import com.eratguard.pro.spam.store.SmsInboxStore
import com.eratguard.pro.spam.store.SpamQuarantineStore

object SmsRouter {

    data class RouteResult(
        val verdict: SpamVerdict,
        val score: Int,
        val inboxInserted: Boolean,
        val quarantined: Boolean,
        val failSafeActivated: Boolean = false
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

        return when (
            result.verdict
        ) {

            SpamVerdict.SAFE -> {

                val inserted =
                    SmsInboxStore.insert(
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
                    failSafeActivated = false
                )
            }

            SpamVerdict.SUSPICIOUS,
            SpamVerdict.SPAM -> {

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
                 * EratGuard spam olduğuna karar verdi fakat
                 * kendi karantinasına kalıcı olarak yazamadıysa
                 * mesajı yok etmiyoruz.
                 *
                 * Sistem inbox'una bırakmayı deniyoruz.
                 */
                if (!quarantined) {

                    val fallbackInserted =
                        SmsInboxStore.insert(
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
                        failSafeActivated = true
                    )

                } else {

                    RouteResult(
                        verdict = result.verdict,
                        score = result.score,
                        inboxInserted = false,
                        quarantined = true,
                        failSafeActivated = false
                    )
                }
            }
        }
    }
}
