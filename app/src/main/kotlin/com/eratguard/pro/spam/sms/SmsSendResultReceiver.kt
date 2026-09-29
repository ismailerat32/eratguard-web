package com.eratguard.pro.spam.sms

import com.eratguard.pro.domain.messaging.SmsActiveMessagePolicy

import android.app.Activity
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.telephony.SmsManager
import com.eratguard.pro.domain.messaging.SmsSendStateMachine
import com.eratguard.pro.spam.store.SmsSentStore

class SmsSendResultReceiver : BroadcastReceiver() {

    override fun onReceive(
        context: Context,
        intent: Intent
    ) {

        val prefs =
            context.getSharedPreferences(
                PREFS_NAME,
                Context.MODE_PRIVATE
            )

        val messageId =
            intent.getLongExtra(
                EXTRA_MESSAGE_ID,
                -1L
            )

        val partIndex =
            intent.getIntExtra(
                EXTRA_PART_INDEX,
                0
            )

        val partCount =
            intent.getIntExtra(
                EXTRA_PART_COUNT,
                1
            ).coerceAtLeast(1)

        if (messageId <= 0L) {
            return
        }

        when (intent.action) {

            SmsSender.ACTION_SMS_SENT -> {

                if (resultCode == Activity.RESULT_OK) {

                    val previousParts =
                        readPartSet(
                            prefs.getStringSet(
                                sentSuccessPartsKey(messageId),
                                emptySet()
                            )
                        )

                    val progressResult =
                        SmsSendStateMachine.recordSuccessfulPart(
                            completedParts = previousParts,
                            partIndex = partIndex,
                            partCount = partCount
                        )

                    val progress =
                        progressResult.progress

                    val currentStatus =
                        SmsSendStateMachine.parseSendStatus(
                            prefs.getString(
                                sendStatusKey(messageId),
                                null
                            )
                        )

                    val resolvedStatus =
                        SmsSendStateMachine
                            .successfulCallbackStatus(
                                progress = progress,
                                currentStatus = currentStatus
                            )

                    val status =
                        SmsSendStateMachine.persistedValue(
                            resolvedStatus
                        )

                    prefs.edit()
                        .putString(
                            sendStatusKey(messageId),
                            status
                        )
                        .putStringSet(
                            sentSuccessPartsKey(messageId),
                            writePartSet(
                                progress.completedParts
                            )
                        )
                        .putInt(
                            sentSuccessCountKey(messageId),
                            progress.completedCount
                        )
                        .apply()

                    val activeMessageId =
                        prefs.getLong(
                            KEY_LAST_MESSAGE_ID,
                            -1L
                        )

                    if (
                        SmsActiveMessagePolicy
                            .mayUpdateUiProjection(
                                callbackMessageId = messageId,
                                activeMessageId = activeMessageId
                            )
                    ) {
                        prefs.edit()
                            .putString(
                                KEY_LAST_SENT_STATUS,
                                status
                            )
                            .putInt(
                                KEY_LAST_SENT_PART,
                                partIndex
                            )
                            .putInt(
                                KEY_LAST_PART_COUNT,
                                progress.partCount
                            )
                            .putLong(
                                KEY_UPDATED_AT,
                                System.currentTimeMillis()
                            )
                            .apply()
                    }

                    val alreadyStored =
                        prefs.getBoolean(
                            sentStoredKey(messageId),
                            false
                        )

                    if (
                        SmsSendStateMachine.storageRequired(
                            sendStatus = resolvedStatus,
                            alreadyStored = alreadyStored
                        )
                    ) {

                        val recipient =
                            prefs.getString(
                                pendingRecipientKey(messageId),
                                null
                            ).orEmpty()

                        val body =
                            prefs.getString(
                                pendingBodyKey(messageId),
                                null
                            ).orEmpty()

                        val timestamp =
                            prefs.getLong(
                                pendingTimestampKey(messageId),
                                0L
                            )

                        val pendingResult =
                            goAsync()

                        val appContext =
                            context.applicationContext

                        SmsBroadcastAsyncRunner.execute(
                            pendingResult = pendingResult
                        ) {

                            val storedBeforeWork =
                                prefs.getBoolean(
                                    sentStoredKey(messageId),
                                    false
                                )

                            if (!storedBeforeWork) {

                                val storeResult =
                                    if (timestamp > 0L) {
                                        SmsSentStore.ensureStored(
                                            context = appContext,
                                            recipient = recipient,
                                            body = body,
                                            timestamp = timestamp
                                        )
                                    } else {
                                        SmsSentStore.EnsureResult.FAILED
                                    }

                                if (
                                    storeResult !=
                                    SmsSentStore.EnsureResult.FAILED
                                ) {

                                    val checkpointPersisted =
                                        prefs.edit()
                                            .putBoolean(
                                                sentStoredKey(messageId),
                                                true
                                            )
                                            .remove(
                                                pendingRecipientKey(messageId)
                                            )
                                            .remove(
                                                pendingBodyKey(messageId)
                                            )
                                            .remove(
                                                pendingTimestampKey(messageId)
                                            )
                                            .commit()

                                    if (!checkpointPersisted) {
                                        // Telephony row may already exist.
                                        // Disk checkpoint was not confirmed.
                                        // A later callback/process recovery
                                        // remains duplicate-safe because the
                                        // Telephony lookup precedes insertion.
                                    }
                                }
                            }
                        }
                    }

                } else {

                    val failureStatus =
                        SmsSendStateMachine.sendFailureStatus(
                            resultCode = resultCode,
                            genericFailureCode =
                                SmsManager.RESULT_ERROR_GENERIC_FAILURE,
                            noServiceCode =
                                SmsManager.RESULT_ERROR_NO_SERVICE,
                            nullPduCode =
                                SmsManager.RESULT_ERROR_NULL_PDU,
                            radioOffCode =
                                SmsManager.RESULT_ERROR_RADIO_OFF
                        )

                    val status =
                        SmsSendStateMachine.persistedValue(
                            failureStatus
                        )

                    prefs.edit()
                        .putString(
                            sendStatusKey(messageId),
                            status
                        )
                        .apply()

                    val activeMessageId =
                        prefs.getLong(
                            KEY_LAST_MESSAGE_ID,
                            -1L
                        )

                    if (
                        SmsActiveMessagePolicy
                            .mayUpdateUiProjection(
                                callbackMessageId = messageId,
                                activeMessageId = activeMessageId
                            )
                    ) {
                        prefs.edit()
                            .putString(
                                KEY_LAST_SENT_STATUS,
                                status
                            )
                            .putInt(
                                KEY_LAST_SENT_PART,
                                partIndex
                            )
                            .putInt(
                                KEY_LAST_PART_COUNT,
                                partCount
                            )
                            .putLong(
                                KEY_UPDATED_AT,
                                System.currentTimeMillis()
                            )
                            .apply()
                    }
                }
            }

            SmsSender.ACTION_SMS_DELIVERED -> {

                if (resultCode == Activity.RESULT_OK) {

                    val previousParts =
                        readPartSet(
                            prefs.getStringSet(
                                deliveredSuccessPartsKey(messageId),
                                emptySet()
                            )
                        )

                    val progressResult =
                        SmsSendStateMachine.recordSuccessfulPart(
                            completedParts = previousParts,
                            partIndex = partIndex,
                            partCount = partCount
                        )

                    val progress =
                        progressResult.progress

                    val currentStatus =
                        SmsSendStateMachine.parseDeliveryStatus(
                            prefs.getString(
                                deliveryStatusKey(messageId),
                                null
                            )
                        )

                    val resolvedStatus =
                        SmsSendStateMachine
                            .successfulDeliveryCallbackStatus(
                                progress = progress,
                                currentStatus = currentStatus
                            )

                    val status =
                        SmsSendStateMachine.persistedValue(
                            resolvedStatus
                        )

                    prefs.edit()
                        .putString(
                            deliveryStatusKey(messageId),
                            status
                        )
                        .putStringSet(
                            deliveredSuccessPartsKey(messageId),
                            writePartSet(
                                progress.completedParts
                            )
                        )
                        .putInt(
                            deliveredSuccessCountKey(messageId),
                            progress.completedCount
                        )
                        .apply()

                    val activeMessageId =
                        prefs.getLong(
                            KEY_LAST_MESSAGE_ID,
                            -1L
                        )

                    if (
                        SmsActiveMessagePolicy
                            .mayUpdateUiProjection(
                                callbackMessageId = messageId,
                                activeMessageId = activeMessageId
                            )
                    ) {
                        prefs.edit()
                            .putString(
                                KEY_LAST_DELIVERY_STATUS,
                                status
                            )
                            .putInt(
                                KEY_LAST_DELIVERED_PART,
                                partIndex
                            )
                            .putInt(
                                KEY_LAST_PART_COUNT,
                                progress.partCount
                            )
                            .putLong(
                                KEY_UPDATED_AT,
                                System.currentTimeMillis()
                            )
                            .apply()
                    }

                } else {

                    val status =
                        SmsSendStateMachine.persistedValue(
                            SmsSendStateMachine
                                .deliveryFailureStatus()
                        )

                    prefs.edit()
                        .putString(
                            deliveryStatusKey(messageId),
                            status
                        )
                        .apply()

                    val activeMessageId =
                        prefs.getLong(
                            KEY_LAST_MESSAGE_ID,
                            -1L
                        )

                    if (
                        SmsActiveMessagePolicy
                            .mayUpdateUiProjection(
                                callbackMessageId = messageId,
                                activeMessageId = activeMessageId
                            )
                    ) {
                        prefs.edit()
                            .putString(
                                KEY_LAST_DELIVERY_STATUS,
                                status
                            )
                            .putInt(
                                KEY_LAST_DELIVERED_PART,
                                partIndex
                            )
                            .putInt(
                                KEY_LAST_PART_COUNT,
                                partCount
                            )
                            .putLong(
                                KEY_UPDATED_AT,
                                System.currentTimeMillis()
                            )
                            .apply()
                    }
                }
            }
        }
    }

    companion object {

        const val PREFS_NAME =
            "eratguard_sms_send_status"

        const val EXTRA_MESSAGE_ID =
            "message_id"

        const val EXTRA_PART_INDEX =
            "part_index"

        const val EXTRA_PART_COUNT =
            "part_count"

        fun pendingRecipientKey(
            messageId: Long
        ): String =
            "pending_recipient_$messageId"

        fun pendingBodyKey(
            messageId: Long
        ): String =
            "pending_body_$messageId"

        fun pendingTimestampKey(
            messageId: Long
        ): String =
            "pending_timestamp_$messageId"

        fun sentStoredKey(
            messageId: Long
        ): String =
            "sent_stored_$messageId"

        fun sentSuccessCountKey(
            messageId: Long
        ): String =
            "sent_success_count_$messageId"

        fun deliveredSuccessCountKey(
            messageId: Long
        ): String =
            "delivered_success_count_$messageId"

        fun sentSuccessPartsKey(
            messageId: Long
        ): String =
            "sent_success_parts_$messageId"

        fun sendStatusKey(
            messageId: Long
        ): String =
            "send_status_$messageId"

        fun deliveredSuccessPartsKey(
            messageId: Long
        ): String =
            "delivered_success_parts_$messageId"

        fun deliveryStatusKey(
            messageId: Long
        ): String =
            "delivery_status_$messageId"

        const val KEY_LAST_MESSAGE_ID =
            "last_message_id"

        const val KEY_LAST_SENT_STATUS =
            "last_sent_status"

        const val KEY_LAST_DELIVERY_STATUS =
            "last_delivery_status"

        const val KEY_LAST_SENT_PART =
            "last_sent_part"

        const val KEY_LAST_DELIVERED_PART =
            "last_delivered_part"

        const val KEY_LAST_PART_COUNT =
            "last_part_count"

        const val KEY_UPDATED_AT =
            "updated_at"

        private fun readPartSet(
            values: Set<String>?
        ): Set<Int> =
            values
                .orEmpty()
                .mapNotNull { it.toIntOrNull() }
                .toSet()

        private fun writePartSet(
            values: Set<Int>
        ): Set<String> =
            values
                .map { it.toString() }
                .toSet()
    }
}
