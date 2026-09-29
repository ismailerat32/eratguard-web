package com.eratguard.pro.components

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import com.eratguard.pro.designsystem.EratGuardColors
import com.eratguard.pro.designsystem.EratGuardShapeTokens
import com.eratguard.pro.designsystem.EratGuardSizes

@Composable
fun BottomNav() {
    var selected by remember { mutableIntStateOf(0) }

    val items = listOf(
        "Ana",
        "Koruma",
        "AI",
        "Rapor",
        "Profil"
    )

    val icons = listOf(
        Icons.Default.Home,
        Icons.Default.Settings,
        Icons.Default.Home,
        Icons.Default.Settings,
        Icons.Default.Person
    )

    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = EratGuardShapeTokens.Large,
        border = BorderStroke(
            EratGuardSizes.BorderThin,
            EratGuardColors.Border
        ),
        colors = CardDefaults.cardColors(
            containerColor = EratGuardColors.Surface
        )
    ) {
        NavigationBar(
            containerColor = EratGuardColors.Transparent
        ) {
            items.forEachIndexed { index, title ->
                NavigationBarItem(
                    selected = selected == index,
                    onClick = { selected = index },
                    icon = {
                        Icon(
                            imageVector = icons[index],
                            contentDescription = title
                        )
                    },
                    label = {
                        Text(title)
                    },
                    colors =
                        NavigationBarItemDefaults.colors(
                            selectedIconColor =
                                EratGuardColors.Primary,
                            selectedTextColor =
                                EratGuardColors.Primary,
                            indicatorColor =
                                EratGuardColors.PrimaryGlow,
                            unselectedIconColor =
                                EratGuardColors.TextSecondary,
                            unselectedTextColor =
                                EratGuardColors.TextSecondary
                        )
                )
            }
        }
    }
}
