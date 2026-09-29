package com.eratguard.pro.spam.store

import android.content.ContentValues
import android.content.Context
import android.provider.Telephony
import com.eratguard.pro.domain.messaging.SmsSentRecordIdentity

object SmsSentStore {

    enum class EnsureResult {
        ALREADY_STORED,
        INSERTED,
        FAILED
    }

    fun ensureStored(
        context: Context,
        recipient: String,
        body: String,
        timestamp: Long
    ): EnsureResult {

        val fingerprint =
            SmsSentRecordIdentity.create(
                recipient = recipient,
                body = body,
                timestamp = timestamp
            ) ?: return EnsureResult.FAILED

        return synchronized(storeLock) {

            when (
                lookup(
                    context = context,
                    fingerprint = fingerprint
                )
            ) {
                LookupResult.FOUND ->
                    return@synchronized EnsureResult.ALREADY_STORED

                LookupResult.QUERY_FAILED ->
                    return@synchronized EnsureResult.FAILED

                LookupResult.NOT_FOUND ->
                    Unit
            }

            val values =
                ContentValues().apply {

                    put(
                        Telephony.Sms.ADDRESS,
                        fingerprint.recipient
                    )

                    put(
                        Telephony.Sms.BODY,
                        fingerprint.body
                    )

                    put(
                        Telephony.Sms.DATE,
                        fingerprint.timestamp
                    )

                    put(
                        Telephony.Sms.DATE_SENT,
                        fingerprint.timestamp
                    )

                    put(
                        Telephony.Sms.READ,
                        1
                    )

                    put(
                        Telephony.Sms.SEEN,
                        1
                    )

                    put(
                        Telephony.Sms.TYPE,
                        Telephony.Sms.MESSAGE_TYPE_SENT
                    )
                }

            try {

                val uri =
                    context.contentResolver.insert(
                        Telephony.Sms.Sent.CONTENT_URI,
                        values
                    )

                if (uri != null) {
                    EnsureResult.INSERTED
                } else {
                    EnsureResult.FAILED
                }

            } catch (_: SecurityException) {

                EnsureResult.FAILED

            } catch (_: Exception) {

                EnsureResult.FAILED
            }
        }
    }

    private fun lookup(
        context: Context,
        fingerprint: SmsSentRecordIdentity.Fingerprint
    ): LookupResult {

        return try {

            context.contentResolver.query(
                Telephony.Sms.Sent.CONTENT_URI,
                arrayOf(
                    Telephony.Sms.ADDRESS,
                    Telephony.Sms.BODY,
                    Telephony.Sms.DATE
                ),
                "${Telephony.Sms.ADDRESS} = ? AND " +
                    "${Telephony.Sms.BODY} = ? AND " +
                    "${Telephony.Sms.DATE} = ?",
                arrayOf(
                    fingerprint.recipient,
                    fingerprint.body,
                    fingerprint.timestamp.toString()
                ),
                null
            )?.use { cursor ->

                val addressIndex =
                    cursor.getColumnIndex(
                        Telephony.Sms.ADDRESS
                    )

                val bodyIndex =
                    cursor.getColumnIndex(
                        Telephony.Sms.BODY
                    )

                val dateIndex =
                    cursor.getColumnIndex(
                        Telephony.Sms.DATE
                    )

                if (
                    addressIndex < 0 ||
                    bodyIndex < 0 ||
                    dateIndex < 0
                ) {
                    return@use LookupResult.QUERY_FAILED
                }

                var matched = false

                while (
                    !matched &&
                    cursor.moveToNext()
                ) {

                    matched =
                        SmsSentRecordIdentity.matches(
                            fingerprint = fingerprint,
                            storedRecipient =
                                cursor.getString(
                                    addressIndex
                                ),
                            storedBody =
                                cursor.getString(
                                    bodyIndex
                                ),
                            storedTimestamp =
                                if (
                                    cursor.isNull(
                                        dateIndex
                                    )
                                ) {
                                    null
                                } else {
                                    cursor.getLong(
                                        dateIndex
                                    )
                                }
                        )
                }

                if (matched) {
                    LookupResult.FOUND
                } else {
                    LookupResult.NOT_FOUND
                }

            } ?: LookupResult.QUERY_FAILED

        } catch (_: SecurityException) {

            LookupResult.QUERY_FAILED

        } catch (_: Exception) {

            LookupResult.QUERY_FAILED
        }
    }

    private enum class LookupResult {
        FOUND,
        NOT_FOUND,
        QUERY_FAILED
    }

    private val storeLock =
        Any()
}
