package com.eratguard.pro.contacts

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.net.Uri
import android.provider.ContactsContract
import androidx.core.content.ContextCompat

object ContactNameResolver {

    fun resolve(
        context: Context,
        phoneNumber: String
    ): String? {

        val number =
            phoneNumber.trim()

        if (number.isBlank()) {
            return null
        }

        if (
            ContextCompat.checkSelfPermission(
                context,
                Manifest.permission.READ_CONTACTS
            ) != PackageManager.PERMISSION_GRANTED
        ) {
            return null
        }

        return try {

            val lookupUri =
                Uri.withAppendedPath(
                    ContactsContract.PhoneLookup.CONTENT_FILTER_URI,
                    Uri.encode(number)
                )

            val projection =
                arrayOf(
                    ContactsContract.PhoneLookup.DISPLAY_NAME
                )

            context.contentResolver.query(
                lookupUri,
                projection,
                null,
                null,
                null
            )?.use { cursor ->

                if (!cursor.moveToFirst()) {
                    return@use null
                }

                val nameIndex =
                    cursor.getColumnIndex(
                        ContactsContract.PhoneLookup.DISPLAY_NAME
                    )

                if (nameIndex < 0) {
                    return@use null
                }

                cursor.getString(nameIndex)
                    ?.trim()
                    ?.takeIf { it.isNotBlank() }
            }

        } catch (_: SecurityException) {

            null

        } catch (_: Exception) {

            null
        }
    }

    fun displayName(
        context: Context,
        phoneNumber: String
    ): String {

        return resolve(
            context = context,
            phoneNumber = phoneNumber
        ) ?: phoneNumber.ifBlank {
            "Bilinmeyen gönderici"
        }
    }
}
