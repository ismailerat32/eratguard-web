package com.eratguard.pro.spam.store

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.provider.Telephony
import androidx.core.content.ContextCompat

object SmsInboxReader {

    data class InboxMessage(
        val id: Long,
        val sender: String,
        val body: String,
        val timestamp: Long,
        val read: Boolean
    )

    fun list(
        context: Context,
        limit: Int = 100
    ): List<InboxMessage> {

        if (
            ContextCompat.checkSelfPermission(
                context,
                Manifest.permission.READ_SMS
            ) != PackageManager.PERMISSION_GRANTED
        ) {
            return emptyList()
        }

        val safeLimit =
            limit.coerceIn(1, 500)

        val projection =
            arrayOf(
                Telephony.Sms._ID,
                Telephony.Sms.ADDRESS,
                Telephony.Sms.BODY,
                Telephony.Sms.DATE,
                Telephony.Sms.READ
            )

        return try {

            val output =
                ArrayList<InboxMessage>()

            context.contentResolver.query(
                Telephony.Sms.Inbox.CONTENT_URI,
                projection,
                null,
                null,
                "${Telephony.Sms.DATE} DESC"
            )?.use { cursor ->

                val idIndex =
                    cursor.getColumnIndex(
                        Telephony.Sms._ID
                    )

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

                val readIndex =
                    cursor.getColumnIndex(
                        Telephony.Sms.READ
                    )

                while (
                    cursor.moveToNext() &&
                    output.size < safeLimit
                ) {

                    val id =
                        if (idIndex >= 0)
                            cursor.getLong(idIndex)
                        else
                            continue

                    val sender =
                        if (addressIndex >= 0)
                            cursor.getString(addressIndex)
                                .orEmpty()
                        else
                            ""

                    val body =
                        if (bodyIndex >= 0)
                            cursor.getString(bodyIndex)
                                .orEmpty()
                        else
                            ""

                    val timestamp =
                        if (dateIndex >= 0)
                            cursor.getLong(dateIndex)
                        else
                            0L

                    val read =
                        if (readIndex >= 0)
                            cursor.getInt(readIndex) != 0
                        else
                            false

                    output.add(
                        InboxMessage(
                            id = id,
                            sender = sender,
                            body = body,
                            timestamp = timestamp,
                            read = read
                        )
                    )
                }
            }

            output

        } catch (_: SecurityException) {

            emptyList()

        } catch (_: Exception) {

            emptyList()
        }
    }
}
