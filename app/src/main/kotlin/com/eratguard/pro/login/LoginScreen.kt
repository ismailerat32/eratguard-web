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

private val BackgroundColor = Color(0xFF07121B)
private val NeonColor = Color(0xFF00E5FF)

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
            .background(BackgroundColor)
    ) {
        Column(
            modifier = Modifier
                .align(Alignment.Center)
                .fillMaxWidth()
                .padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text(
                text = "ERATGUARD PRO",
                color = NeonColor,
                fontSize = 30.sp
            )

            Spacer(modifier = Modifier.height(8.dp))

            Text(
                text = "AI Powered Mobile Security",
                color = Color.LightGray
            )

            Spacer(modifier = Modifier.height(32.dp))

            OutlinedTextField(
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

            Spacer(modifier = Modifier.height(16.dp))

            OutlinedTextField(
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
                    TextButton(
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

            Button(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(56.dp),
                enabled = !loading,
                shape = RoundedCornerShape(18.dp),
                onClick = {
                    if (username.isBlank() || password.isBlank()) {
                        errorMessage = "Kullanıcı adı ve şifre gerekli."
                        return@Button
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

            Spacer(modifier = Modifier.height(16.dp))

            TextButton(
                enabled = !loading,
                onClick = { }
            ) {
                Text("Şifremi Unuttum")
            }

            TextButton(
                enabled = !loading,
                onClick = { }
            ) {
                Text("Hesap Oluştur")
            }

            Spacer(modifier = Modifier.height(32.dp))

            Text(
                text = "Protected by ERAT AI Engine",
                color = NeonColor
            )
        }
    }
}
