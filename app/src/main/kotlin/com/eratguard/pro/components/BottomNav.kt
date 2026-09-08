package com.eratguard.pro.components

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Person
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp

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
        shape = RoundedCornerShape(20.dp),
        border = BorderStroke(1.dp, Color(0xFF00E5FF)),
        colors = CardDefaults.cardColors(
            containerColor = Color(0xFF102430)
        )
    ) {

        NavigationBar(
            containerColor = Color.Transparent
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
                    label = { Text(title) },
                    colors = NavigationBarItemDefaults.colors(
                        selectedIconColor = Color.Cyan,
                        selectedTextColor = Color.Cyan,
                        indicatorColor = Color(0x2200E5FF),
                        unselectedIconColor = Color.Gray,
                        unselectedTextColor = Color.Gray
                    )
                )

            }

        }

    }

}
