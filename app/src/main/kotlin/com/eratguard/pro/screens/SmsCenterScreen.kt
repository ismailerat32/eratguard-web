package com.eratguard.pro.screens

import com.eratguard.pro.designsystem.EratGuardColors
import com.eratguard.pro.designsystem.EratGuardShapeTokens
import com.eratguard.pro.designsystem.EratGuardSpacing
import com.eratguard.pro.designsystem.components.EratGuardButton
import com.eratguard.pro.designsystem.components.EratGuardField
import com.eratguard.pro.designsystem.components.EratGuardPanel

import com.eratguard.pro.domain.messaging.SmsAddressValidator

import android.app.Activity
import android.content.Context
import android.Manifest
import android.content.pm.PackageManager
import android.database.ContentObserver
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.provider.ContactsContract
import android.provider.Telephony
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
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
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
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
import com.eratguard.pro.spam.sms.SmsSendResultReceiver
import com.eratguard.pro.spam.sms.SmsSender
import com.eratguard.pro.spam.store.SpamQuarantineStore
import com.eratguard.pro.spam.store.SpamProtectionSettings
import com.eratguard.pro.spam.store.SmsInboxReader
import com.eratguard.pro.spam.store.SmsInboxStore

@Composable
fun SmsCenterScreen(
    onBack: () -> Unit
) {

    val context =
        LocalContext.current

    val requiredSmsPermissions =
        arrayOf(
            Manifest.permission.RECEIVE_SMS,
            Manifest.permission.READ_SMS,
            Manifest.permission.SEND_SMS
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

    val notificationPermissionLauncher =
        rememberLauncherForActivityResult(
            contract =
                ActivityResultContracts.RequestPermission()
        ) {
            permissionRefreshKey++
        }

    val notificationPermissionGranted =
        Build.VERSION.SDK_INT <
            Build.VERSION_CODES.TIRAMISU ||
            ContextCompat.checkSelfPermission(
                context,
                Manifest.permission.POST_NOTIFICATIONS
            ) == PackageManager.PERMISSION_GRANTED

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

    DisposableEffect(context) {

        val observer =
            object : ContentObserver(
                Handler(Looper.getMainLooper())
            ) {
                override fun onChange(
                    selfChange: Boolean
                ) {
                    super.onChange(selfChange)
                    refreshKey++
                }
            }

        context.contentResolver
            .registerContentObserver(
                Telephony.Sms.CONTENT_URI,
                true,
                observer
            )

        onDispose {
            context.contentResolver
                .unregisterContentObserver(
                    observer
                )
        }
    }

    /*
     * Karantina SharedPreferences üzerinde tutuluyor.
     * Yeni spam eklenince veya karantinadan mesaj silinince
     * ekran açıkken listeyi anında yenile.
     */
    DisposableEffect(context) {

        val quarantinePrefs =
            context.getSharedPreferences(
                "eratguard_spam_quarantine",
                Context.MODE_PRIVATE
            )

        val listener =
            android.content.SharedPreferences
                .OnSharedPreferenceChangeListener {
                    _, key ->

                    if (key == "messages") {
                        refreshKey++
                    }
                }

        quarantinePrefs
            .registerOnSharedPreferenceChangeListener(
                listener
            )

        onDispose {
            quarantinePrefs
                .unregisterOnSharedPreferenceChangeListener(
                    listener
                )
        }
    }

    var statusMessage by
        remember {
            mutableStateOf<String?>(null)
        }

    var sendStatusRefreshKey by
        remember {
            mutableIntStateOf(0)
        }

    DisposableEffect(context) {

        val sendStatusPrefs =
            context.getSharedPreferences(
                SmsSendResultReceiver.PREFS_NAME,
                Context.MODE_PRIVATE
            )

        val listener =
            android.content.SharedPreferences
                .OnSharedPreferenceChangeListener {
                    _, _ ->
                    sendStatusRefreshKey++
                }

        sendStatusPrefs
            .registerOnSharedPreferenceChangeListener(
                listener
            )

        onDispose {
            sendStatusPrefs
                .unregisterOnSharedPreferenceChangeListener(
                    listener
                )
        }
    }

    /*
     * SMS silme sonucu kalıcı durum yazısı olarak
     * ekranda kalmasın. Diğer durum mesajlarına dokunma.
     */
    LaunchedEffect(statusMessage) {

        if (
            statusMessage == "SMS silindi." ||
            statusMessage == "SMS silinemedi."
        ) {
            kotlinx.coroutines.delay(3000L)

            if (
                statusMessage == "SMS silindi." ||
                statusMessage == "SMS silinemedi."
            ) {
                statusMessage = null
            }
        }
    }

    var autoDeleteHighConfidence by
        remember {
            mutableStateOf(
                SpamProtectionSettings
                    .isAutoDeleteHighConfidenceEnabled(
                        context
                    )
            )
        }

    var showAutoDeleteWarning by
        remember {
            mutableStateOf(false)
        }

    var pendingDeleteMessageId by
        remember {
            mutableStateOf<Long?>(null)
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

    val quarantineMessages =
        remember(refreshKey) {
            SpamQuarantineStore.list(
                context
            )
        }

    var showInbox by
        remember {
            mutableStateOf(true)
        }

    var showComposer by
        remember {
            mutableStateOf(false)
        }

    var composeRecipient by
        remember {
            mutableStateOf("")
        }

    var composeBody by
        remember {
            mutableStateOf("")
        }

    val contactPickerLauncher =
        rememberLauncherForActivityResult(
            contract =
                ActivityResultContracts.PickContact()
        ) { contactUri ->

            if (contactUri != null) {

                try {

                    context.contentResolver.query(
                        contactUri,
                        arrayOf(
                            ContactsContract.Contacts._ID
                        ),
                        null,
                        null,
                        null
                    )?.use { cursor ->

                        if (cursor.moveToFirst()) {

                            val idIndex =
                                cursor.getColumnIndex(
                                    ContactsContract.Contacts._ID
                                )

                            if (idIndex >= 0) {

                                val contactId =
                                    cursor.getLong(idIndex)

                                context.contentResolver.query(
                                    ContactsContract.CommonDataKinds.Phone.CONTENT_URI,
                                    arrayOf(
                                        ContactsContract.CommonDataKinds.Phone.NUMBER
                                    ),
                                    "${ContactsContract.CommonDataKinds.Phone.CONTACT_ID} = ?",
                                    arrayOf(contactId.toString()),
                                    null
                                )?.use { phoneCursor ->

                                    if (phoneCursor.moveToFirst()) {

                                        val numberIndex =
                                            phoneCursor.getColumnIndex(
                                                ContactsContract.CommonDataKinds.Phone.NUMBER
                                            )

                                        if (numberIndex >= 0) {
                                            composeRecipient =
                                                phoneCursor
                                                    .getString(numberIndex)
                                                    .orEmpty()
                                        }
                                    }
                                }
                            }
                        }
                    }

                } catch (_: SecurityException) {

                    statusMessage =
                        "Rehber izni gerekli."

                } catch (_: Exception) {

                    statusMessage =
                        "Kişi seçilemedi."
                }
            }
        }

    val inboxMessages =
        remember(
            refreshKey,
            permissionRefreshKey
        ) {
            if (smsPermissionsGranted) {
                SmsInboxReader.list(
                    context = context,
                    limit = 100
                )
            } else {
                emptyList()
            }
        }

    val isDefaultSmsApp =
        remember(roleRefreshKey) {
            SmsRoleManager.isDefaultSmsApp(
                context
            )
        }

    val outgoingSmsStatus =
        remember(sendStatusRefreshKey) {

            val prefs =
                context.getSharedPreferences(
                    SmsSendResultReceiver.PREFS_NAME,
                    Context.MODE_PRIVATE
                )

            val sentStatus =
                prefs.getString(
                    SmsSendResultReceiver.KEY_LAST_SENT_STATUS,
                    null
                )

            val deliveryStatus =
                prefs.getString(
                    SmsSendResultReceiver.KEY_LAST_DELIVERY_STATUS,
                    null
                )

            when {

                deliveryStatus == "delivered" ->
                    "Son SMS: Teslim edildi."

                deliveryStatus == "delivering" ->
                    "Son SMS: Teslim ediliyor."

                deliveryStatus == "delivery_failed" ->
                    "Son SMS gönderildi ancak teslim raporu başarısız."

                sentStatus == "sent" ->
                    "Son SMS: Gönderildi."

                sentStatus == "sending" ->
                    "Son SMS: Gönderiliyor."

                sentStatus == "no_service" ->
                    "SMS gönderilemedi: Şebeke hizmeti yok."

                sentStatus == "radio_off" ->
                    "SMS gönderilemedi: Mobil bağlantı kapalı."

                sentStatus == "null_pdu" ->
                    "SMS gönderilemedi: Geçersiz SMS verisi."

                sentStatus == "generic_failure" ->
                    "SMS gönderilemedi: Operatör/modem hatası."

                sentStatus == "send_failed" ->
                    "SMS gönderilemedi."

                else ->
                    null
            }
        }

    if (showAutoDeleteWarning) {

        AlertDialog(
            containerColor = EratGuardColors.SurfaceElevated,
            titleContentColor = EratGuardColors.TextPrimary,
            textContentColor = EratGuardColors.TextSecondary,
            shape = EratGuardShapeTokens.ExtraLarge,
            onDismissRequest = {
                showAutoDeleteWarning = false
            },
            title = {
                Text(
                    "Otomatik silme açılsın mı?"
                )
            },
            text = {
                Text(
                    "Yüksek güvenle spam/phishing olarak belirlenen mesajlar Gelen Kutusu'na veya Karantina'ya kaydedilmeden engellenir. Bu mesajlar sonradan geri getirilemez."
                )
            },
            dismissButton = {
                EratGuardButton(
                    onClick = {
                        showAutoDeleteWarning = false
                    }
                ) {
                    Text("Vazgeç")
                }
            },
            confirmButton = {
                EratGuardButton(
                    onClick = {

                        SpamProtectionSettings
                            .setAutoDeleteHighConfidenceEnabled(
                                context = context,
                                enabled = true
                            )

                        autoDeleteHighConfidence = true
                        showAutoDeleteWarning = false

                        statusMessage =
                            "Kesin spam otomatik silme açıldı."
                    }
                ) {
                    Text("Aç")
                }
            }
        )
    }

    pendingDeleteMessageId?.let { messageId ->

        AlertDialog(
            containerColor = EratGuardColors.SurfaceElevated,
            titleContentColor = EratGuardColors.TextPrimary,
            textContentColor = EratGuardColors.TextSecondary,
            shape = EratGuardShapeTokens.ExtraLarge,
            onDismissRequest = {
                pendingDeleteMessageId = null
            },
            title = {
                Text("SMS silinsin mi?")
            },
            text = {
                Text(
                    "Bu SMS cihazdan kalıcı olarak silinecek."
                )
            },
            dismissButton = {
                EratGuardButton(
                    onClick = {
                        pendingDeleteMessageId = null
                    }
                ) {
                    Text("İptal")
                }
            },
            confirmButton = {
                EratGuardButton(
                    onClick = {

                        val deleted =
                            if (
                                SmsRoleManager
                                    .isDefaultSmsApp(context)
                            ) {
                                SmsInboxStore.deleteById(
                                    context = context,
                                    messageId = messageId
                                )
                            } else {
                                false
                            }

                        pendingDeleteMessageId = null

                        if (deleted) {
                            statusMessage =
                                "SMS silindi."
                            refreshKey++
                        } else {
                            statusMessage =
                                "SMS silinemedi."
                        }
                    }
                ) {
                    Text("Sil")
                }
            }
        )
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(EratGuardSpacing.Lg)
    ) {

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement =
                Arrangement.SpaceBetween
        ) {

            Text(
                text = "SMS Merkezi"
            )

            EratGuardButton(
                onClick = onBack
            ) {
                Text("Geri")
            }
        }

        Spacer(
            modifier = Modifier.height(EratGuardSpacing.Md)
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
                modifier = Modifier.height(EratGuardSpacing.Sm)
            )

            Text(
                text = "SMS erişim izinleri gerekli."
            )

            Spacer(
                modifier = Modifier.height(EratGuardSpacing.Sm)
            )

            EratGuardButton(
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
                modifier = Modifier.height(EratGuardSpacing.Sm)
            )

            Text(
                text =
                    "Kayıtlı kişilerin adlarını göstermek için rehber erişimi isteğe bağlıdır."
            )

            Spacer(
                modifier = Modifier.height(EratGuardSpacing.Sm)
            )

            EratGuardButton(
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
                modifier = Modifier.height(EratGuardSpacing.Sm)
            )

            EratGuardButton(
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
                modifier = Modifier.height(EratGuardSpacing.Sm)
            )

            Text(
                text = status
            )
        }

        outgoingSmsStatus?.let { status ->

            Spacer(
                modifier = Modifier.height(EratGuardSpacing.Sm)
            )

            Text(
                text = status,
                color = EratGuardColors.TextSecondary
            )
        }

        Spacer(
            modifier = Modifier.height(EratGuardSpacing.Lg)
        )

        if (!notificationPermissionGranted) {

            EratGuardPanel(
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(
                    modifier =
                        Modifier
                            .fillMaxWidth()
                            .padding(14.dp)
                ) {
                    Text(
                        text = "SMS bildirimleri",
                        color = EratGuardColors.TextPrimary
                    )

                    Spacer(
                        modifier = Modifier.height(EratGuardSpacing.Xxs)
                    )

                    Text(
                        text =
                            "Yeni SMS ve engellenen spam mesajları için bildirim alın.",
                        color = EratGuardColors.TextSecondary
                    )

                    Spacer(
                        modifier = Modifier.height(10.dp)
                    )

                    EratGuardButton(
                        onClick = {
                            if (
                                Build.VERSION.SDK_INT >=
                                Build.VERSION_CODES.TIRAMISU
                            ) {
                                notificationPermissionLauncher
                                    .launch(
                                        Manifest.permission
                                            .POST_NOTIFICATIONS
                                    )
                            }
                        }
                    ) {
                        Text("Bildirimleri etkinleştir")
                    }
                }
            }

            Spacer(
                modifier = Modifier.height(EratGuardSpacing.Lg)
            )
        }

        if (isDefaultSmsApp && smsPermissionsGranted) {

            EratGuardButton(
                modifier = Modifier.fillMaxWidth(),
                onClick = {
                    showComposer = !showComposer

                    if (!showComposer) {
                        composeRecipient = ""
                        composeBody = ""
                    }
                }
            ) {
                Text(
                    if (showComposer)
                        "Yeni Mesajı Kapat"
                    else
                        "Yeni Mesaj"
                )
            }

            if (showComposer) {

                Spacer(
                    modifier = Modifier.height(EratGuardSpacing.Md)
                )

                EratGuardPanel(
                    modifier = Modifier.fillMaxWidth()
                ) {

                    Column(
                        modifier =
                            Modifier
                                .fillMaxWidth()
                                .padding(14.dp)
                    ) {

                        Text(
                            text = "Yeni SMS",
                            color = EratGuardColors.TextPrimary
                        )

                        Spacer(
                            modifier = Modifier.height(10.dp)
                        )

                        EratGuardField(
                            modifier =
                                Modifier.fillMaxWidth(),
                            value = composeRecipient,
                            onValueChange = {
                                composeRecipient = it
                            },
                            label = {
                                Text("Telefon numarası")
                            },
                            singleLine = true
                        )

                        Spacer(
                            modifier = Modifier.height(EratGuardSpacing.Sm)
                        )

                        EratGuardButton(
                            modifier =
                                Modifier.fillMaxWidth(),
                            onClick = {

                                if (
                                    ContextCompat.checkSelfPermission(
                                        context,
                                        Manifest.permission.READ_CONTACTS
                                    ) ==
                                    PackageManager.PERMISSION_GRANTED
                                ) {
                                    contactPickerLauncher.launch(null)
                                } else {
                                    contactsPermissionLauncher.launch(
                                        Manifest.permission.READ_CONTACTS
                                    )
                                    statusMessage =
                                        "Önce rehber iznini ver, sonra tekrar Rehberden Seç'e dokun."
                                }
                            }
                        ) {
                            Text("Rehberden Seç")
                        }

                        Spacer(
                            modifier = Modifier.height(10.dp)
                        )

                        EratGuardField(
                            modifier =
                                Modifier.fillMaxWidth(),
                            value = composeBody,
                            onValueChange = {
                                composeBody = it
                            },
                            label = {
                                Text("Mesaj")
                            },
                            minLines = 4
                        )

                        Spacer(
                            modifier = Modifier.height(EratGuardSpacing.Sm)
                        )

                        val actualParts =
                            SmsSender.partCount(
                                context = context,
                                message = composeBody
                            )

                        Text(
                            text =
                                "${composeBody.length} karakter • " +
                                    "$actualParts SMS",
                            color =
                                EratGuardColors.TextSecondary
                        )

                        Spacer(
                            modifier = Modifier.height(EratGuardSpacing.Md)
                        )

                        Row(
                            modifier =
                                Modifier.fillMaxWidth(),
                            horizontalArrangement =
                                Arrangement.spacedBy(EratGuardSpacing.Sm)
                        ) {

                            EratGuardButton(
                                modifier =
                                    Modifier.weight(1f),
                                onClick = {
                                    composeRecipient = ""
                                    composeBody = ""
                                    showComposer = false
                                }
                            ) {
                                Text("Vazgeç")
                            }

                            EratGuardButton(
                                modifier =
                                    Modifier.weight(1f),
                                enabled =
                                    SmsAddressValidator.isReplyable(
                                        composeRecipient
                                    ) &&
                                    composeBody
                                        .isNotBlank(),
                                onClick = {

                                    val result =
                                        SmsSender.send(
                                            context =
                                                context,
                                            destination =
                                                composeRecipient,
                                            message =
                                                composeBody
                                        )

                                    if (result.accepted) {

                                        statusMessage = null
                                        composeBody = ""

                                    } else {

                                        statusMessage =
                                            result.error
                                                ?: "SMS gönderilemedi."
                                    }
                                }
                            ) {
                                Text("Gönder")
                            }
                        }
                    }
                }
            }

            Spacer(
                modifier = Modifier.height(EratGuardSpacing.Lg)
            )
        }

        EratGuardPanel(
            modifier = Modifier.fillMaxWidth()
        ) {
            Row(
                modifier =
                    Modifier
                        .fillMaxWidth()
                        .padding(14.dp),
                horizontalArrangement =
                    Arrangement.spacedBy(EratGuardSpacing.Md)
            ) {
                Column(
                    modifier = Modifier.weight(1f)
                ) {
                    Text(
                        text =
                            "Kesin spam'i otomatik sil",
                        color = EratGuardColors.TextPrimary
                    )

                    Spacer(
                        modifier = Modifier.height(EratGuardSpacing.Xxs)
                    )

                    Text(
                        text =
                            "Yalnızca çok güçlü spam/phishing sinyalleri taşıyan mesajlar Gelen Kutusu'na veya Karantina'ya kaydedilmeden engellenir.",
                        color = EratGuardColors.TextSecondary
                    )
                }

                Switch(
                    checked =
                        autoDeleteHighConfidence,
                    onCheckedChange = { enabled ->

                        if (enabled) {

                            showAutoDeleteWarning = true

                        } else {

                            SpamProtectionSettings
                                .setAutoDeleteHighConfidenceEnabled(
                                    context = context,
                                    enabled = false
                                )

                            autoDeleteHighConfidence = false

                            statusMessage =
                                "Kesin spam otomatik silme kapatıldı."
                        }
                    }
                )
            }
        }

        Spacer(
            modifier = Modifier.height(EratGuardSpacing.Lg)
        )

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement =
                Arrangement.spacedBy(EratGuardSpacing.Sm)
        ) {
            EratGuardButton(
                modifier = Modifier.weight(1f),
                onClick = {
                    showInbox = true
                }
            ) {
                Text(
                    if (showInbox)
                        "● Gelen Kutusu"
                    else
                        "Gelen Kutusu"
                )
            }

            EratGuardButton(
                modifier = Modifier.weight(1f),
                onClick = {
                    showInbox = false
                }
            ) {
                Text(
                    if (!showInbox)
                        "● Karantina"
                    else
                        "Karantina"
                )
            }
        }

        Spacer(
            modifier = Modifier.height(EratGuardSpacing.Md)
        )

        if (showInbox) {

            if (!smsPermissionsGranted) {

                Text(
                    text =
                        "Gelen kutusunu görmek için SMS okuma izni gerekli."
                )

            } else if (inboxMessages.isEmpty()) {

                Text(
                    text = "Gelen kutusunda mesaj yok."
                )

            } else {

                LazyColumn(
                    verticalArrangement =
                        Arrangement.spacedBy(EratGuardSpacing.Md)
                ) {
                    items(
                        items = inboxMessages,
                        key = { "inbox_${it.id}" }
                    ) { message ->

                        EratGuardPanel(
                            modifier =
                                Modifier.fillMaxWidth()
                        ) {
                            Column(
                                modifier =
                                    Modifier.padding(EratGuardSpacing.Lg)
                            ) {
                                Text(
                                    text =
                                        ContactNameResolver.displayName(
                                            context = context,
                                            phoneNumber = message.sender
                                        ),
                                    color = EratGuardColors.TextPrimary
                                )

                                Spacer(
                                    modifier =
                                        Modifier.height(EratGuardSpacing.Sm)
                                )

                                Text(
                                    text = message.body,
                                    color = EratGuardColors.TextPrimary
                                )

                                Spacer(
                                    modifier =
                                        Modifier.height(EratGuardSpacing.Sm)
                                )

                                Text(
                                    text =
                                        SimpleDateFormat(
                                            "dd.MM.yyyy HH:mm",
                                            Locale.getDefault()
                                        ).format(
                                            Date(message.timestamp)
                                        ),
                                    color = EratGuardColors.TextSecondary
                                )

                                Spacer(
                                    modifier =
                                        Modifier.height(EratGuardSpacing.Xxs)
                                )

                                Text(
                                    text =
                                        if (message.read)
                                            "Okundu"
                                        else
                                            "Okunmadı",
                                    color = EratGuardColors.TextSecondary
                                )

                                Spacer(
                                    modifier =
                                        Modifier.height(EratGuardSpacing.Md)
                                )

                                Row(
                                    modifier =
                                        Modifier.fillMaxWidth(),
                                    horizontalArrangement =
                                        Arrangement.spacedBy(EratGuardSpacing.Sm)
                                ) {

                                    val replyableSender =
                                        SmsAddressValidator.isReplyable(
                                            message.sender
                                        )

                                    EratGuardButton(
                                        modifier =
                                            Modifier.weight(1f),
                                        enabled =
                                            isDefaultSmsApp &&
                                            smsPermissionsGranted &&
                                            replyableSender,
                                        onClick = {
                                            composeRecipient =
                                                message.sender
                                            composeBody = ""
                                            showComposer = true
                                        }
                                    ) {
                                        Text(
                                            if (replyableSender) {
                                                "Yanıtla"
                                            } else {
                                                "Yanıt Yok"
                                            }
                                        )
                                    }

                                    EratGuardButton(
                                        modifier =
                                            Modifier.weight(1f),
                                        enabled =
                                            isDefaultSmsApp,
                                        onClick = {
                                            pendingDeleteMessageId =
                                                message.id
                                        }
                                    ) {
                                        Text("Sil")
                                    }
                                }
                            }
                        }
                    }
                }
            }

        } else {

            if (quarantineMessages.isEmpty()) {

                Text(
                    text = "Karantinada mesaj yok."
                )

            } else {

                LazyColumn(
                    verticalArrangement =
                        Arrangement.spacedBy(EratGuardSpacing.Md)
                ) {
                    items(
                        items = quarantineMessages,
                        key = { "quarantine_${it.id}" }
                    ) { message ->

                        EratGuardPanel(
                            modifier =
                                Modifier.fillMaxWidth()
                        ) {
                            Column(
                                modifier =
                                    Modifier.padding(EratGuardSpacing.Lg)
                            ) {
                                Text(
                                    text =
                                        ContactNameResolver.displayName(
                                            context = context,
                                            phoneNumber = message.sender
                                        ),
                                    color = EratGuardColors.TextPrimary
                                )

                                Spacer(
                                    modifier =
                                        Modifier.height(EratGuardSpacing.Sm)
                                )

                                Text(
                                    text = message.body,
                                    color = EratGuardColors.TextPrimary
                                )

                                Spacer(
                                    modifier =
                                        Modifier.height(EratGuardSpacing.Sm)
                                )

                                Text(
                                    text =
                                        "Risk: ${message.score} / ${message.verdict}",
                                    color = EratGuardColors.Warning
                                )

                                Spacer(
                                    modifier =
                                        Modifier.height(EratGuardSpacing.Md)
                                )

                                EratGuardButton(
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
}
