package com.eratguard.pro.network

import android.content.Context
import java.util.UUID

object InstallationIdManager {

    private const val PREFS_NAME = "eratguard_installation"
    private const val KEY_INSTALLATION_ID = "installation_id"

    fun get(context: Context): String {
        val prefs = context.getSharedPreferences(
            PREFS_NAME,
            Context.MODE_PRIVATE
        )

        val existing = prefs.getString(KEY_INSTALLATION_ID, null)

        if (!existing.isNullOrBlank()) {
            return existing
        }

        val newId = UUID.randomUUID().toString()

        prefs.edit()
            .putString(KEY_INSTALLATION_ID, newId)
            .apply()

        return newId
    }
}
