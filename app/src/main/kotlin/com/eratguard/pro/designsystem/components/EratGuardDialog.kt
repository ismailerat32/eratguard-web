package com.eratguard.pro.designsystem.components

import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import com.eratguard.pro.designsystem.EratGuardColors

@Composable
fun EratGuardDialog(
    title: String,
    message: String,
    confirmText: String,
    onConfirm: () -> Unit,
    onDismiss: () -> Unit,
    dismissText: String? = null
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Text(
                text = title,
                color = EratGuardColors.TextPrimary
            )
        },
        text = {
            Text(
                text = message,
                color = EratGuardColors.TextSecondary
            )
        },
        confirmButton = {
            EratGuardTextButton(
                onClick = onConfirm
            ) {
                Text(confirmText)
            }
        },
        dismissButton = dismissText?.let { label ->
            {
                EratGuardTextButton(
                    onClick = onDismiss
                ) {
                    Text(label)
                }
            }
        },
        containerColor = EratGuardColors.Surface
    )
}
