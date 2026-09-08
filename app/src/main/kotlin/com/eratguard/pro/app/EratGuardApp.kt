package com.eratguard.pro.app

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.size
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.eratguard.pro.dashboard.PremiumDashboard
import com.eratguard.pro.screens.SmsCenterScreen
import com.eratguard.pro.theme.DashboardTheme
import kotlinx.coroutines.delay

private enum class EratGuardScreen {
    SPLASH,
    DASHBOARD,
    SMS_CENTER
}

@Composable
fun EratGuardApp() {

    var screen by remember {
        mutableStateOf(EratGuardScreen.SPLASH)
    }

    DashboardTheme {

        when (screen) {

            EratGuardScreen.SPLASH -> {

                LaunchedEffect(Unit) {
                    delay(1800)
                    screen = EratGuardScreen.DASHBOARD
                }

                AnimatedVisibility(
                    visible = true,
                    enter = fadeIn(),
                    exit = fadeOut()
                ) {
                    EratGuardSplash()
                }
            }

            EratGuardScreen.DASHBOARD -> {

                PremiumDashboard(
                    onSmsCenterClick = {
                        screen = EratGuardScreen.SMS_CENTER
                    }
                )
            }

            EratGuardScreen.SMS_CENTER -> {

                SmsCenterScreen(
                    onBack = {
                        screen = EratGuardScreen.DASHBOARD
                    }
                )
            }
        }
    }
}

@Composable
private fun EratGuardSplash() {

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(Color(0xFF020E07)),
        contentAlignment = Alignment.Center
    ) {

        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {

            Box(
                modifier = Modifier
                    .size(110.dp),
                contentAlignment = Alignment.Center
            ) {

                Text(
                    text = "🛡",
                    fontSize = 64.sp
                )
            }

            Spacer(modifier = Modifier.height(20.dp))

            Text(
                text = "EratGuard",
                fontSize = 38.sp,
                fontWeight = FontWeight.Bold,
                color = Color.White
            )

            Spacer(modifier = Modifier.height(8.dp))

            Text(
                text = "AI SPAM KORUMA SİSTEMİ",
                fontSize = 11.sp,
                letterSpacing = 3.sp,
                color = Color(0xFF00FF88)
            )

            Spacer(modifier = Modifier.height(32.dp))

            CircularProgressIndicator(
                modifier = Modifier.size(24.dp),
                color = Color(0xFF00FF88),
                strokeWidth = 2.dp
            )

            Spacer(modifier = Modifier.height(14.dp))

            Text(
                text = "Güvenlik başlatılıyor...",
                fontSize = 12.sp,
                color = Color.White.copy(alpha = 0.55f)
            )
        }
    }
}
