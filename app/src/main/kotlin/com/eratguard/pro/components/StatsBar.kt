package com.eratguard.pro.components

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.eratguard.pro.core.SpamEngine

@Composable
fun StatsBar() {
    val blocked = SpamEngine.blockedMessages()

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 12.dp),
        horizontalArrangement = Arrangement.SpaceEvenly
    ) {

        StatCard(blocked.toString(),"BLOCK")
        StatCard("99%","AI")
        StatCard("LOW","RISK")

    }

}

@Composable
private fun StatCard(
    value:String,
    label:String
){

    Card(
        modifier = Modifier
            .height(78.dp),
        shape = RoundedCornerShape(18.dp),
        border = BorderStroke(1.dp, Color(0xFF00E5FF)),
        colors = CardDefaults.cardColors(
            containerColor = Color(0xFF102430)
        )
    ){

        Column(
            modifier = Modifier.padding(12.dp),
            verticalArrangement = Arrangement.Center
        ){

            Text(
                text = value,
                color = Color.White,
                fontWeight = FontWeight.Bold,
                fontSize = 20.sp
            )

            Text(
                text = label,
                color = Color(0xFF6BE7FF),
                fontSize = 12.sp
            )

        }

    }

}
