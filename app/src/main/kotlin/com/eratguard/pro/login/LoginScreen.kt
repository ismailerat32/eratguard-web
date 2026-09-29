package com.eratguard.pro.login

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Email
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.eratguard.pro.network.MobileAuthApi
import com.eratguard.pro.network.InstallationIdManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import com.eratguard.pro.designsystem.EratGuardColors
import com.eratguard.pro.designsystem.EratGuardSpacing
import com.eratguard.pro.designsystem.components.EratGuardButton
import com.eratguard.pro.designsystem.components.EratGuardField
import com.eratguard.pro.designsystem.components.EratGuardTextButton

@Composable
fun LoginScreen(
    onLoginSuccess: () -> Unit
) {
    var username by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var showPassword by remember { mutableStateOf(false) }
    var loading by remember { mutableStateOf(false) }
    var errorMessage by remember { mutableStateOf<String?>(null) }

    val scope = rememberCoroutineScope()
    val context = LocalContext.current

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(EratGuardColors.Background)
    ) {
        Column(
            modifier = Modifier
                .align(Alignment.Center)
                .fillMaxWidth()
                .padding(EratGuardSpacing.Xxl),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text(
                text = "ERATGUARD PRO",
                color = EratGuardColors.Primary,
                fontSize = 30.sp
            )

            Spacer(modifier = Modifier.height(EratGuardSpacing.Sm))

            Text(
                text = "AI Powered Mobile Security",
                color = EratGuardColors.TextSecondary
            )

            Spacer(modifier = Modifier.height(EratGuardSpacing.Xxxl))

            EratGuardField(
                value = username,
                onValueChange = {
                    username = it
                    errorMessage = null
                },
                singleLine = true,
                enabled = !loading,
                modifier = Modifier.fillMaxWidth(),
                label = { Text("Kullanıcı adı") },
                leadingIcon = {
                    Icon(Icons.Default.Email, contentDescription = null)
                },
                keyboardOptions = KeyboardOptions(
                    keyboardType = KeyboardType.Text
                )
            )

            Spacer(modifier = Modifier.height(EratGuardSpacing.Lg))

            EratGuardField(
                value = password,
                onValueChange = {
                    password = it
                    errorMessage = null
                },
                singleLine = true,
                enabled = !loading,
                modifier = Modifier.fillMaxWidth(),
                label = { Text("Şifre") },
                leadingIcon = {
                    Icon(Icons.Default.Lock, contentDescription = null)
                },
                trailingIcon = {
                    EratGuardTextButton(
                        enabled = !loading,
                        onClick = {
                            showPassword = !showPassword
                        }
                    ) {
                        Text(
                            text = if (showPassword) "GİZLE" else "GÖSTER"
                        )
                    }
                },
                visualTransformation =
                    if (showPassword) {
                        VisualTransformation.None
                    } else {
                        PasswordVisualTransformation()
                    }
            )

            errorMessage?.let { message ->
                Spacer(modifier = Modifier.height(14.dp))

                Text(
                    text = message,
                    color = MaterialTheme.colorScheme.error
                )
            }

            Spacer(modifier = Modifier.height(28.dp))

            EratGuardButton(
                modifier = Modifier.fillMaxWidth(),
                enabled = !loading,
                onClick = {
                    if (username.isBlank() || password.isBlank()) {
                        errorMessage = "Kullanıcı adı ve şifre gerekli."
                        return@EratGuardButton
                    }

                    loading = true
                    errorMessage = null

                    scope.launch {
                        val result =
                            withContext(Dispatchers.IO) {
                                MobileAuthApi.login(
                                    username = username,
                                    password = password,
                                    installationId = InstallationIdManager.get(context)
                                )
                            }

                        loading = false

                        if (result.ok) {
                            onLoginSuccess()
                        } else {
                            errorMessage = result.message
                        }
                    }
                }
            ) {
                if (loading) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(22.dp),
                        strokeWidth = 2.dp
                    )
                } else {
                    Text("GİRİŞ YAP")
                }
            }

            Spacer(modifier = Modifier.height(EratGuardSpacing.Lg))

            EratGuardTextButton(
                enabled = !loading,
                onClick = { }
            ) {
                Text("Şifremi Unuttum")
            }

            EratGuardTextButton(
                enabled = !loading,
                onClick = { }
            ) {
                Text("Hesap Oluştur")
            }

            Spacer(modifier = Modifier.height(EratGuardSpacing.Xxxl))

            Text(
                text = "Protected by ERAT AI Engine",
                color = EratGuardColors.Primary
            )
        }
    }
}
