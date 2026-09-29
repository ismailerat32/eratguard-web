package com.eratguard.pro.domain.shell

object EratGuardShellPolicy {

    const val PANEL_URL =
        "https://app.eratguard.com/dashboard"

    private const val TRUSTED_SCHEME = "https"
    private const val TRUSTED_HOST = "app.eratguard.com"

    fun shouldOpenNativeSms(path: String?): Boolean {
        val value = path.orEmpty()

        return value.equals(
            "/sms",
            ignoreCase = true
        ) ||
            value.contains(
                "sms-center",
                ignoreCase = true
            ) ||
            value.contains(
                "sms-actions-center",
                ignoreCase = true
            )
    }

    fun isTrustedEratGuardUrl(url: String?): Boolean {
        val value = url.orEmpty()

        val match =
            Regex(
                pattern =
                    """^(https?)://([^/:?#]+)(?::\d+)?(?:[/?#].*)?$""",
                option = RegexOption.IGNORE_CASE
            ).matchEntire(value)
                ?: return false

        val scheme = match.groupValues[1]
        val host = match.groupValues[2]

        return scheme.equals(
            TRUSTED_SCHEME,
            ignoreCase = true
        ) &&
            host.equals(
                TRUSTED_HOST,
                ignoreCase = true
            )
    }

    fun isRenderLoading(bodyText: String?): Boolean {
        val text = bodyText.orEmpty().lowercase()

        return text.contains("application loading") ||
            text.contains("render.com")
    }

    fun isContentReady(
        url: String?,
        bodyText: String?
    ): Boolean {
        val text = bodyText.orEmpty().lowercase()

        val eratGuardContentReady =
            isTrustedEratGuardUrl(url) &&
                text.contains("eratguard") &&
                (
                    text.contains("ana koruma") ||
                        text.contains(
                            "pro notification control"
                        ) ||
                        text.contains("sistem aktif")
                    )

        val authPageReady =
            isTrustedEratGuardUrl(url) &&
                isAuthPath(url) &&
                text.contains("eratguard")

        return eratGuardContentReady || authPageReady
    }

    private fun isAuthPath(url: String?): Boolean {
        val value = url.orEmpty()

        return value.contains(
            "/login",
            ignoreCase = true
        ) ||
            value.contains(
                "/register",
                ignoreCase = true
            ) ||
            value.contains(
                "/forgot-password",
                ignoreCase = true
            ) ||
            value.contains(
                "/reset-password",
                ignoreCase = true
            )
    }
}
