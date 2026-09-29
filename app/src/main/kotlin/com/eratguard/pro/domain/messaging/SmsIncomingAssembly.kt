package com.eratguard.pro.domain.messaging

object SmsIncomingAssembly {

    data class Part(
        val sender: String,
        val body: String,
        val timestamp: Long
    )

    data class Message(
        val sender: String,
        val body: String,
        val timestamp: Long
    )

    fun assemble(
        parts: List<Part>,
        fallbackTimestamp: Long
    ): Message? {

        if (parts.isEmpty()) {
            return null
        }

        val sender =
            parts.first()
                .sender
                .trim()

        if (sender.isBlank()) {
            return null
        }

        /*
         * Multipart SMS'in bütün parçaları aynı göndericiye
         * ait olmalıdır. Farklı sender görülürse mesajı
         * birleştirmek güvenli değildir.
         */
        if (
            parts.any {
                it.sender.trim() != sender
            }
        ) {
            return null
        }

        val body =
            parts.joinToString(
                separator = ""
            ) {
                it.body
            }

        if (body.isBlank()) {
            return null
        }

        val timestamp =
            parts.firstNotNullOfOrNull { part ->
                part.timestamp
                    .takeIf { it > 0L }
            }
                ?: fallbackTimestamp
                    .takeIf { it > 0L }
                ?: return null

        return Message(
            sender = sender,
            body = body,
            timestamp = timestamp
        )
    }
}
