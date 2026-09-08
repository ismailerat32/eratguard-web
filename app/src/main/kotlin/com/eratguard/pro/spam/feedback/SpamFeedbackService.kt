package com.eratguard.pro.spam.feedback

import android.content.Context
import com.eratguard.pro.spam.learning.SpamLearningStore
import com.eratguard.pro.spam.store.SmsInboxStore
import com.eratguard.pro.spam.store.SpamQuarantineStore

object SpamFeedbackService {

    enum class SafeResult {
        SUCCESS,
        INVALID_ID,
        NOT_FOUND,
        INBOX_INSERT_FAILED,
        QUARANTINE_REMOVE_FAILED
    }

    @Synchronized
    fun markSafe(
        context: Context,
        messageId: String
    ): SafeResult {

        if (messageId.isBlank()) {
            return SafeResult.INVALID_ID
        }

        val message =
            SpamQuarantineStore
                .list(context)
                .firstOrNull {
                    it.id == messageId
                }
                ?: return SafeResult.NOT_FOUND

        /*
         * Önce Android Inbox'a kalıcı olarak yaz.
         *
         * Bu adım başarısızsa karantinaya veya learning
         * verisine dokunma.
         */
        val inserted =
            SmsInboxStore.insertIfMissing(
                context = context,
                sender = message.sender,
                body = message.body,
                timestamp = message.timestamp
            )

        if (!inserted) {
            return SafeResult.INBOX_INSERT_FAILED
        }

        /*
         * Inbox yazımı başarılı olduktan sonra karantinadan
         * kaldırmayı dene.
         *
         * Remove başarısız olursa mesaj karantinada kalır.
         * Bu durumda veri kaybı yerine olası duplicate tercih
         * edilir ve learning uygulanmaz.
         */
        val removed =
            SpamQuarantineStore.remove(
                context = context,
                id = message.id
            )

        if (!removed) {
            return SafeResult.QUARANTINE_REMOVE_FAILED
        }

        /*
         * Kullanıcı feedback'i ancak Inbox + quarantine
         * işlemleri başarıyla tamamlandıktan sonra öğrenilir.
         */
        SpamLearningStore.markSafe(
            context = context,
            sender = message.sender
        )

        return SafeResult.SUCCESS
    }
}
