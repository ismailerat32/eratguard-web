package com.eratguard.pro

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import com.eratguard.pro.app.EratGuardApp
import com.eratguard.pro.spam.update.FilterUpdateScheduler

class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        FilterUpdateScheduler.schedule(
            applicationContext
        )


        setContent {
            EratGuardApp()
        }
    }
}
