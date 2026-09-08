package com.eratguard.pro.dashboard

import androidx.compose.foundation.layout.*
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.eratguard.pro.components.AiCore
import com.eratguard.pro.components.BottomNav
import com.eratguard.pro.components.ModuleGrid
import com.eratguard.pro.components.SecurityScore
import com.eratguard.pro.components.StatsBar
import com.eratguard.pro.screens.HudTopBar
import com.eratguard.pro.theme.DashboardColors

@Composable
fun PremiumDashboard(
    onSmsCenterClick: () -> Unit = {}
) {

    Surface(
        modifier = Modifier.fillMaxSize(),
        color = DashboardColors.Background
    ) {

        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(16.dp)
        ) {

            HudTopBar()

            Spacer(modifier = Modifier.height(12.dp))

            SecurityScore()

            Spacer(modifier = Modifier.height(16.dp))

            AiCore()

            Spacer(modifier = Modifier.height(12.dp))

            StatsBar()

            Spacer(modifier = Modifier.height(16.dp))

            ModuleGrid(
                onSmsCenterClick = onSmsCenterClick
            )

            Spacer(modifier = Modifier.weight(1f))

            BottomNav()

        }

    }

}
