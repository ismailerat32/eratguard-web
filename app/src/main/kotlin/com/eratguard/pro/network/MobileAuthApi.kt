package com.eratguard.pro.network

import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

data class MobileLoginResult(
    val ok: Boolean,
    val message: String,
    val username: String = "",
    val email: String = "",
    val plan: String = "",
    val premium: Boolean = false,
    val licenseStatus: String = "",
    val licenseExpiry: String = ""
)

object MobileAuthApi {

    /*
     * Geliştirme adresi.
     * Android cihaz fiziksel olarak Termux sunucusuna bağlanacaksa
     * 127.0.0.1 değil, telefonun erişebildiği sunucu adresi kullanılmalı.
     */
    private const val BASE_URL = "https://app.eratguard.com"

    fun login(
        username: String,
        password: String,
        installationId: String
    ): MobileLoginResult {

        var connection: HttpURLConnection? = null

        return try {
            val url = URL("$BASE_URL/api/mobile/login")

            connection =
                (url.openConnection() as HttpURLConnection).apply {
                    requestMethod = "POST"
                    connectTimeout = 10000
                    readTimeout = 10000
                    doOutput = true

                    setRequestProperty(
                        "Content-Type",
                        "application/json; charset=UTF-8"
                    )
                    setRequestProperty(
                        "Accept",
                        "application/json"
                    )
                }

            val requestJson =
                JSONObject().apply {
                    put("username", username.trim())
                    put("password", password)
                    put("installation_id", installationId)
                }

            connection.outputStream.use { output ->
                output.write(
                    requestJson
                        .toString()
                        .toByteArray(Charsets.UTF_8)
                )
            }

            val statusCode = connection.responseCode

            val stream =
                if (statusCode in 200..299) {
                    connection.inputStream
                } else {
                    connection.errorStream
                }

            val responseText =
                stream
                    ?.bufferedReader(Charsets.UTF_8)
                    ?.use { it.readText() }
                    .orEmpty()

            if (responseText.isBlank()) {
                return MobileLoginResult(
                    ok = false,
                    message = "Sunucudan boş yanıt alındı."
                )
            }

            val json = JSONObject(responseText)
            val ok = json.optBoolean("ok", false)
            val message =
                json.optString(
                    "message",
                    if (ok) "Giriş başarılı." else "Giriş başarısız."
                )

            if (!ok) {
                return MobileLoginResult(
                    ok = false,
                    message = message
                )
            }

            val user =
                json.optJSONObject("user")
                    ?: JSONObject()

            MobileLoginResult(
                ok = true,
                message = message,
                username = user.optString("username"),
                email = user.optString("email"),
                plan = user.optString("plan"),
                premium = user.optBoolean("premium", false),
                licenseStatus = user.optString("license_status"),
                licenseExpiry = user.optString("license_expiry")
            )

        } catch (e: Exception) {

            MobileLoginResult(
                ok = false,
                message = "Sunucu bağlantısı kurulamadı: ${e.message ?: "bilinmeyen hata"}"
            )

        } finally {
            connection?.disconnect()
        }
    }
}
