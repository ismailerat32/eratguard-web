package com.eratguard.pro.screens

import android.app.Activity
import android.Manifest
import android.content.pm.PackageManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.compose.ui.unit.dp
import com.eratguard.pro.contacts.ContactNameResolver
import com.eratguard.pro.spam.feedback.SpamFeedbackService
import com.eratguard.pro.spam.sms.SmsRoleManager
import com.eratguard.pro.spam.store.SpamQuarantineStore
import com.eratguard.pro.theme.DashboardColors

@Composable
fun SmsCenterScreen(
    onBack: () -> Unit
) {

    val context =
        LocalContext.current

    val requiredSmsPermissions =
        arrayOf(
            Manifest.permission.RECEIVE_SMS,
            Manifest.permission.READ_SMS
        )

    val optionalContactsPermission =
        Manifest.permission.READ_CONTACTS

    var permissionRefreshKey by
        remember {
            mutableIntStateOf(0)
        }

    val permissionLauncher =
        rememberLauncherForActivityResult(
            contract =
                ActivityResultContracts.RequestMultiplePermissions()
        ) {
            permissionRefreshKey++
        }

    val contactsPermissionLauncher =
        rememberLauncherForActivityResult(
            contract =
                ActivityResultContracts.RequestPermission()
        ) {
            permissionRefreshKey++
        }

    val smsPermissionsGranted =
        remember(permissionRefreshKey) {
            requiredSmsPermissions.all { permission ->
                ContextCompat.checkSelfPermission(
                    context,
                    permission
                ) == PackageManager.PERMISSION_GRANTED
            }
        }

    var refreshKey by
        remember {
            mutableIntStateOf(0)
        }

    var statusMessage by
        remember {
            mutableStateOf<String?>(null)
        }

    var roleRefreshKey by
        remember {
            mutableIntStateOf(0)
        }

    val lifecycleOwner =
        LocalLifecycleOwner.current

    DisposableEffect(lifecycleOwner) {

        val observer =
            LifecycleEventObserver { _, event ->

                if (
                    event ==
                    Lifecycle.Event.ON_RESUME
                ) {
                    roleRefreshKey++
                }
            }

        lifecycleOwner.lifecycle
            .addObserver(observer)

        onDispose {
            lifecycleOwner.lifecycle
                .removeObserver(observer)
        }
    }

    val messages =
        remember(refreshKey) {
            SpamQuarantineStore.list(
                context
            )
        }

    val isDefaultSmsApp =
        remember(roleRefreshKey) {
            SmsRoleManager.isDefaultSmsApp(
                context
            )
        }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
    ) {

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement =
                Arrangement.SpaceBetween
        ) {

            Text(
                text = "SMS Merkezi"
            )

            Button(
                onClick = onBack
            ) {
                Text("Geri")
            }
        }

        Spacer(
            modifier = Modifier.height(12.dp)
        )

        Text(
            text =
                if (isDefaultSmsApp)
                    "SMS koruması aktif"
                else
                    "EratGuard varsayılan SMS uygulaması değil"
        )

        if (isDefaultSmsApp && !smsPermissionsGranted) {

            Spacer(
                modifier = Modifier.height(8.dp)
            )

            Text(
                text = "SMS erişim izinleri gerekli."
            )

            Spacer(
                modifier = Modifier.height(8.dp)
            )

            Button(
                onClick = {
                    permissionLauncher.launch(
                        requiredSmsPermissions
                    )
                }
            ) {
                Text("SMS izinlerini ver")
            }
        }

        if (
            isDefaultSmsApp &&
            smsPermissionsGranted &&
            ContextCompat.checkSelfPermission(
                context,
                optionalContactsPermission
            ) != PackageManager.PERMISSION_GRANTED
        ) {

            Spacer(
                modifier = Modifier.height(8.dp)
            )

            Text(
                text =
                    "Kayıtlı kişilerin adlarını göstermek için rehber erişimi isteğe bağlıdır."
            )

            Spacer(
                modifier = Modifier.height(8.dp)
            )

            Button(
                onClick = {
                    contactsPermissionLauncher.launch(
                        optionalContactsPermission
                    )
                }
            ) {
                Text("Kişi adlarını göster")
            }
        }

        if (!isDefaultSmsApp) {

            Spacer(
                modifier = Modifier.height(8.dp)
            )

            Button(
                onClick = {

                    val activity =
                        context as? Activity

                    if (activity == null) {

                        statusMessage =
                            "SMS rolü istenemedi."

                    } else {

                        val requested =
                            SmsRoleManager
                                .requestDefaultSmsRole(
                                    activity
                                )

                        statusMessage =
                            if (requested)
                                "SMS rolü isteği açıldı."
                            else
                                "SMS rolü isteği başlatılamadı."
                    }
                }
            ) {
                Text(
                    "Varsayılan SMS uygulaması yap"
                )
            }
        }

        statusMessage?.let { status ->

            Spacer(
                modifier = Modifier.height(8.dp)
            )

            Text(
                text = status
            )
        }

        Spacer(
            modifier = Modifier.height(16.dp)
        )

        if (messages.isEmpty()) {

            Text(
                text = "Karantinada mesaj yok."
            )

        } else {

            LazyColumn(
                verticalArrangement =
                    Arrangement.spacedBy(12.dp)
            ) {

                items(
                    items = messages,
                    key = { it.id }
                ) { message ->

                    Card(
                        modifier =
                            Modifier.fillMaxWidth(),
                        colors =
                            CardDefaults.cardColors(
                                containerColor =
                                    DashboardColors.SurfaceLight
                            )
                    ) {

                        Column(
                            modifier =
                                Modifier.padding(16.dp)
                        ) {

                            Text(
                                text =
                                    ContactNameResolver.displayName(
                                        context = context,
                                        phoneNumber = message.sender
                                    )
                            )

                            Spacer(
                                modifier =
                                    Modifier.height(8.dp)
                            )

                            Text(
                                text = message.body
                            )

                            Spacer(
                                modifier =
                                    Modifier.height(8.dp)
                            )

                            Text(
                                text =
                                    "Risk: ${message.score} / ${message.verdict}"
                            )

                            Spacer(
                                modifier =
                                    Modifier.height(12.dp)
                            )

                            Button(
                                enabled =
                                    isDefaultSmsApp,
                                onClick = {

                                    val result =
                                        SpamFeedbackService
                                            .markSafe(
                                                context =
                                                    context,
                                                messageId =
                                                    message.id
                                            )

                                    statusMessage =
                                        when (result) {

                                            SpamFeedbackService
                                                .SafeResult
                                                .SUCCESS ->
                                                "Mesaj güvenli olarak işaretlendi ve Inbox'a taşındı."

                                            SpamFeedbackService
                                                .SafeResult
                                                .INVALID_ID ->
                                                "Geçersiz mesaj kimliği."

                                            SpamFeedbackService
                                                .SafeResult
                                                .NOT_FOUND ->
                                                "Mesaj karantinada bulunamadı."

                                            SpamFeedbackService
                                                .SafeResult
                                                .INBOX_INSERT_FAILED ->
                                                "Inbox'a yazılamadı. Mesaj karantinada tutuldu."

                                            SpamFeedbackService
                                                .SafeResult
                                                .QUARANTINE_REMOVE_FAILED ->
                                                "Inbox yazıldı ancak karantina kaydı kaldırılamadı."
                                        }

                                    if (
                                        result ==
                                        SpamFeedbackService
                                            .SafeResult
                                            .SUCCESS
                                    ) {
                                        refreshKey++
                                    }
                                }
                            ) {

                                Text(
                                    "Güvenli - Inbox'a taşı"
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}
