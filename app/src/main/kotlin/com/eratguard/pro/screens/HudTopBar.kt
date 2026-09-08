package com.eratguard.pro.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.delay
import java.text.SimpleDateFormat
import java.util.*

@Composable
fun HudTopBar() {

    var time by remember { mutableStateOf("") }

    LaunchedEffect(Unit) {
        while (true) {
            time = SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date())
            delay(1000)
        }
    }

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, Color(0xFF00E5FF), RoundedCornerShape(18.dp))
            .background(Color(0xFF0A1622), RoundedCornerShape(18.dp))
            .padding(16.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {

        Column {

            Text(
                "KORUMA AKTİF",
                color = Color(0xFF00FF99),
                fontWeight = FontWeight.Bold,
                fontSize = 18.sp
            )

            Text(
                "Sistem Tam Koruma Altında",
                color = Color.Gray,
                fontSize = 12.sp
            )

        }

        Text(
            text = time,
            color = Color.White,
            fontSize = 22.sp,
            fontWeight = FontWeight.Bold
        )

    }

}
