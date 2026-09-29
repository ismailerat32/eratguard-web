package com.eratguard.pro.designsystem.components

import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.VisualTransformation
import com.eratguard.pro.designsystem.EratGuardColors
import com.eratguard.pro.designsystem.EratGuardShapeTokens

@Composable
fun EratGuardField(
    value: String,
    onValueChange: (String) -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    singleLine: Boolean = true,
    minLines: Int = 1,
    label: @Composable (() -> Unit)? = null,
    leadingIcon: @Composable (() -> Unit)? = null,
    trailingIcon: @Composable (() -> Unit)? = null,
    visualTransformation: VisualTransformation =
        VisualTransformation.None,
    keyboardOptions: KeyboardOptions =
        KeyboardOptions.Default
) {
    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        modifier = modifier,
        enabled = enabled,
        singleLine = singleLine,
        minLines = minLines,
        label = label,
        leadingIcon = leadingIcon,
        trailingIcon = trailingIcon,
        visualTransformation = visualTransformation,
        keyboardOptions = keyboardOptions,
        shape = EratGuardShapeTokens.Large,
        colors = OutlinedTextFieldDefaults.colors(
            focusedTextColor = EratGuardColors.TextPrimary,
            unfocusedTextColor = EratGuardColors.TextPrimary,
            disabledTextColor = EratGuardColors.TextSecondary,
            focusedBorderColor = EratGuardColors.Primary,
            unfocusedBorderColor = EratGuardColors.TextSecondary,
            focusedLabelColor = EratGuardColors.Primary,
            unfocusedLabelColor = EratGuardColors.TextSecondary,
            cursorColor = EratGuardColors.Primary
        )
    )
}
