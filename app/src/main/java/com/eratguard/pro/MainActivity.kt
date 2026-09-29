package com.eratguard.pro

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.runtime.mutableStateOf
import com.eratguard.pro.app.EratGuardApp
import com.eratguard.pro.spam.update.FilterUpdateScheduler

class MainActivity : ComponentActivity() {

    private val openSmsCenter =
        mutableStateOf(false)

    override fun onCreate(
        savedInstanceState: Bundle?
    ) {
        super.onCreate(savedInstanceState)

        FilterUpdateScheduler.schedule(
            applicationContext
        )

        handleIntent(intent)

        setContent {
            EratGuardApp(
                openSmsCenter =
                    openSmsCenter.value,
                onSmsCenterRequestConsumed = {
                    openSmsCenter.value = false
                }
            )
        }
    }

    override fun onNewIntent(
        intent: Intent
    ) {
        super.onNewIntent(intent)

        setIntent(intent)
        handleIntent(intent)
    }

    private fun handleIntent(
        intent: Intent?
    ) {

        if (
            intent?.getBooleanExtra(
                EXTRA_OPEN_SMS_CENTER,
                false
            ) == true
        ) {
            openSmsCenter.value = true
            intent.removeExtra(
                EXTRA_OPEN_SMS_CENTER
            )
        }
    }

    companion object {

        const val EXTRA_OPEN_SMS_CENTER =
            "open_sms_center"
    }
}
