package com.eratguard.pro.spam.sms

import com.eratguard.pro.domain.messaging.SmsMessageIdentity
import com.eratguard.pro.domain.messaging.SmsStorageTimestamp

import android.Manifest
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.content.pm.PackageManager
import android.telephony.SmsManager
import androidx.core.content.ContextCompat

object SmsSender {

    const val ACTION_SMS_SENT =
        "com.eratguard.pro.SMS_SENT"

    const val ACTION_SMS_DELIVERED =
        "com.eratguard.pro.SMS_DELIVERED"

    data class SendResult(
        val accepted: Boolean,
        val partCount: Int = 0,
        val error: String? = null
    )

    fun partCount(
        context: Context,
        message: String
    ): Int {

        if (message.isEmpty()) {
            return 0
        }

        return try {

            context.getSystemService(
                SmsManager::class.java
            ).divideMessage(message).size

        } catch (_: Exception) {

            0
        }
    }

    fun send(
        context: Context,
        destination: String,
        message: String
    ): SendResult {

        val number = destination.trim()
        val body = message.trim()

        if (number.isBlank()) {
            return SendResult(
                accepted = false,
                error = "Telefon numarası boş."
            )
        }

        if (body.isBlank()) {
            return SendResult(
                accepted = false,
                error = "Mesaj boş."
            )
        }

        if (
            ContextCompat.checkSelfPermission(
                context,
                Manifest.permission.SEND_SMS
            ) != PackageManager.PERMISSION_GRANTED
        ) {
            return SendResult(
                accepted = false,
                error = "SMS gönderme izni verilmemiş."
            )
        }

        return try {

            val smsManager =
                context.getSystemService(
                    SmsManager::class.java
                )

            val parts =
                smsManager.divideMessage(body)

            val prefs =
                context.getSharedPreferences(
                    SmsSendResultReceiver.PREFS_NAME,
                    Context.MODE_PRIVATE
                )

            val messageCreatedAt =
                System.currentTimeMillis()

            val sendIdentity =
                allocateSendIdentity(
                    prefs = prefs,
                    nowMillis = messageCreatedAt
                )

            val messageId =
                sendIdentity.messageId

            val storageTimestamp =
                sendIdentity.storageTimestamp

            prefs.edit()
                .putString(
                    SmsSendResultReceiver.pendingRecipientKey(
                        messageId
                    ),
                    number
                )
                .putString(
                    SmsSendResultReceiver.pendingBodyKey(
                        messageId
                    ),
                    body
                )
                .putLong(
                    SmsSendResultReceiver.pendingTimestampKey(
                        messageId
                    ),
                    storageTimestamp
                )
                .putBoolean(
                    SmsSendResultReceiver.sentStoredKey(
                        messageId
                    ),
                    false
                )
                .putInt(
                    SmsSendResultReceiver.sentSuccessCountKey(
                        messageId
                    ),
                    0
                )
                .putInt(
                    SmsSendResultReceiver.deliveredSuccessCountKey(
                        messageId
                    ),
                    0
                )
                .putStringSet(
                    SmsSendResultReceiver.sentSuccessPartsKey(
                        messageId
                    ),
                    emptySet()
                )
                .putStringSet(
                    SmsSendResultReceiver.deliveredSuccessPartsKey(
                        messageId
                    ),
                    emptySet()
                )
                .remove(
                    SmsSendResultReceiver.KEY_LAST_DELIVERY_STATUS
                )
                .putLong(
                    SmsSendResultReceiver.KEY_LAST_MESSAGE_ID,
                    messageId
                )
                .putString(
                    SmsSendResultReceiver.sendStatusKey(
                        messageId
                    ),
                    "sending"
                )
                .putString(
                    SmsSendResultReceiver.deliveryStatusKey(
                        messageId
                    ),
                    "delivering"
                )
                .putString(
                    SmsSendResultReceiver.KEY_LAST_SENT_STATUS,
                    "sending"
                )
                .putLong(
                    SmsSendResultReceiver.KEY_UPDATED_AT,
                    System.currentTimeMillis()
                )
                .apply()

            val sentIntents =
                ArrayList<PendingIntent>()

            val deliveredIntents =
                ArrayList<PendingIntent>()

            parts.indices.forEach { index ->

                val sentIntent =
                    Intent(
                        context,
                        SmsSendResultReceiver::class.java
                    )
                        .setAction(ACTION_SMS_SENT)
                        .setData(
                            callbackUri(
                                callbackType = "sent",
                                messageId = messageId,
                                partIndex = index
                            )
                        )
                        .putExtra(
                            SmsSendResultReceiver.EXTRA_PART_INDEX,
                            index
                        )
                        .putExtra(
                            SmsSendResultReceiver.EXTRA_PART_COUNT,
                            parts.size
                        )
                        .putExtra(
                            SmsSendResultReceiver.EXTRA_MESSAGE_ID,
                            messageId
                        )

                val deliveredIntent =
                    Intent(
                        context,
                        SmsSendResultReceiver::class.java
                    )
                        .setAction(ACTION_SMS_DELIVERED)
                        .setData(
                            callbackUri(
                                callbackType = "delivered",
                                messageId = messageId,
                                partIndex = index
                            )
                        )
                        .putExtra(
                            SmsSendResultReceiver.EXTRA_PART_INDEX,
                            index
                        )
                        .putExtra(
                            SmsSendResultReceiver.EXTRA_PART_COUNT,
                            parts.size
                        )
                        .putExtra(
                            SmsSendResultReceiver.EXTRA_MESSAGE_ID,
                            messageId
                        )

                sentIntents.add(
                    PendingIntent.getBroadcast(
                        context,
                        SmsMessageIdentity.requestCode(
                            messageId = messageId,
                            partIndex = index,
                            callbackType =
                                SmsMessageIdentity.CallbackType.SENT
                        ),
                        sentIntent,
                        PendingIntent.FLAG_UPDATE_CURRENT or
                            PendingIntent.FLAG_IMMUTABLE
                    )
                )

                deliveredIntents.add(
                    PendingIntent.getBroadcast(
                        context,
                        SmsMessageIdentity.requestCode(
                            messageId = messageId,
                            partIndex = index,
                            callbackType =
                                SmsMessageIdentity.CallbackType.DELIVERED
                        ),
                        deliveredIntent,
                        PendingIntent.FLAG_UPDATE_CURRENT or
                            PendingIntent.FLAG_IMMUTABLE
                    )
                )
            }

            if (parts.size == 1) {

                smsManager.sendTextMessage(
                    number,
                    null,
                    parts[0],
                    sentIntents[0],
                    deliveredIntents[0]
                )

            } else {

                smsManager.sendMultipartTextMessage(
                    number,
                    null,
                    parts,
                    sentIntents,
                    deliveredIntents
                )
            }

            SendResult(
                accepted = true,
                partCount = parts.size
            )

        } catch (e: Exception) {

            SendResult(
                accepted = false,
                error =
                    e.message
                        ?: "SMS gönderilemedi."
            )
        }
    }
    private data class SendIdentity(
        val messageId: Long,
        val storageTimestamp: Long
    )

    private fun allocateSendIdentity(
        prefs: android.content.SharedPreferences,
        nowMillis: Long
    ): SendIdentity =
        synchronized(messageIdLock) {

            val previousMessageId =
                prefs.getLong(
                    KEY_LAST_GENERATED_MESSAGE_ID,
                    0L
                )

            val previousStorageTimestamp =
                prefs.getLong(
                    KEY_LAST_STORAGE_TIMESTAMP,
                    0L
                )

            val messageId =
                SmsMessageIdentity.nextMessageId(
                    nowMillis = nowMillis,
                    previousMessageId =
                        previousMessageId
                )

            val storageTimestamp =
                SmsStorageTimestamp.next(
                    nowMillis = nowMillis,
                    previousTimestamp =
                        previousStorageTimestamp
                )

            val persisted =
                prefs.edit()
                    .putLong(
                        KEY_LAST_GENERATED_MESSAGE_ID,
                        messageId
                    )
                    .putLong(
                        KEY_LAST_STORAGE_TIMESTAMP,
                        storageTimestamp
                    )
                    .commit()

            check(persisted) {
                "SMS kimliği kalıcılaştırılamadı."
            }

            SendIdentity(
                messageId = messageId,
                storageTimestamp = storageTimestamp
            )
        }

    private fun callbackUri(
        callbackType: String,
        messageId: Long,
        partIndex: Int
    ): Uri =
        Uri.Builder()
            .scheme("eratguard")
            .authority("sms-callback")
            .appendPath(callbackType)
            .appendPath(messageId.toString())
            .appendPath(partIndex.toString())
            .build()

    private val messageIdLock =
        Any()

    private const val KEY_LAST_GENERATED_MESSAGE_ID =
        "last_generated_message_id"

    private const val KEY_LAST_STORAGE_TIMESTAMP =
        "last_storage_timestamp"

}
