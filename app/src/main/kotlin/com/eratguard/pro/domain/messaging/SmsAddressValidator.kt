package com.eratguard.pro.domain.messaging

object SmsAddressValidator {

    fun isReplyable(
        value: String
    ): Boolean {

        val trimmed =
            value.trim()

        if (trimmed.isEmpty()) {
            return false
        }

        val allowed =
            trimmed.all { character ->
                character.isDigit() ||
                    character == '+' ||
                    character == '-' ||
                    character == ' ' ||
                    character == '(' ||
                    character == ')'
            }

        if (!allowed) {
            return false
        }

        val compact =
            trimmed.filterNot { character ->
                character == '-' ||
                    character == ' ' ||
                    character == '(' ||
                    character == ')'
            }

        if (
            compact.count { it == '+' } > 1
        ) {
            return false
        }

        if (
            '+' in compact &&
            !compact.startsWith("+")
        ) {
            return false
        }

        val digits =
            compact.removePrefix("+")

        return digits.length >= 3 &&
            digits.all { it.isDigit() }
    }
}
