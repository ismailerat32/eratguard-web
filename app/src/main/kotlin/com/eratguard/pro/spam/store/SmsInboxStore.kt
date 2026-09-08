package com.eratguard.pro.spam.store

import android.content.ContentValues
import android.content.Context
import android.provider.Telephony

object SmsInboxStore {

    /*
     * Karantinadan Inbox'a geri yükleme için idempotent yazma.
     *
     * Aynı sender + body + timestamp zaten Inbox'ta bulunuyorsa
     * yeniden insert edilmez ve işlem başarılı kabul edilir.
     *
     * Bu API normal SAFE routing insert() davranışını değiştirmez.
     */
    fun insertIfMissing(
        context: Context,
        sender: String,
        body: String,
        timestamp: Long
    ): Boolean {

        if (body.isBlank()) {
            return false
        }

        val projection =
            arrayOf(
                Telephony.Sms._ID
            )

        val selection =
            "${Telephony.Sms.ADDRESS} = ? AND " +
                "${Telephony.Sms.BODY} = ? AND " +
                "${Telephony.Sms.DATE} = ?"

        val selectionArgs =
            arrayOf(
                sender,
                body,
                timestamp.toString()
            )

        return try {

            val exists =
                context.contentResolver.query(
                    Telephony.Sms.Inbox.CONTENT_URI,
                    projection,
                    selection,
                    selectionArgs,
                    null
                )?.use { cursor ->
                    cursor.moveToFirst()
                } ?: false

            if (exists) {
                true
            } else {
                insert(
                    context = context,
                    sender = sender,
                    body = body,
                    timestamp = timestamp
                )
            }

        } catch (_: SecurityException) {

            false

        } catch (_: Exception) {

            false
        }
    }


    fun insert(
        context: Context,
        sender: String,
        body: String,
        timestamp: Long
    ): Boolean {

        if (body.isBlank()) {
            return false
        }

        val values =
            ContentValues().apply {

                put(
                    Telephony.Sms.ADDRESS,
                    sender
                )

                put(
                    Telephony.Sms.BODY,
                    body
                )

                put(
                    Telephony.Sms.DATE,
                    timestamp
                )

                put(
                    Telephony.Sms.DATE_SENT,
                    timestamp
                )

                put(
                    Telephony.Sms.READ,
                    0
                )

                put(
                    Telephony.Sms.SEEN,
                    0
                )
            }

        return try {

            val uri =
                context.contentResolver.insert(
                    Telephony.Sms.Inbox.CONTENT_URI,
                    values
                )

            uri != null

        } catch (_: SecurityException) {

            false

        } catch (_: Exception) {

            false
        }
    }
}
