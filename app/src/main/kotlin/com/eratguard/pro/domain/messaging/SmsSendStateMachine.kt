package com.eratguard.pro.domain.messaging

object SmsSendStateMachine {

    enum class SendStatus {
        SENDING,
        SENT,
        GENERIC_FAILURE,
        NO_SERVICE,
        NULL_PDU,
        RADIO_OFF,
        SEND_FAILED
    }

    enum class DeliveryStatus {
        DELIVERING,
        DELIVERED,
        DELIVERY_FAILED
    }

    data class PartProgress(
        val completedParts: Set<Int>,
        val partCount: Int
    ) {
        val completedCount: Int
            get() = completedParts.size

        val complete: Boolean
            get() = completedCount >= partCount
    }

    data class ProgressResult(
        val progress: PartProgress,
        val changed: Boolean
    )

    fun recordSuccessfulPart(
        completedParts: Set<Int>,
        partIndex: Int,
        partCount: Int
    ): ProgressResult {

        val safePartCount =
            partCount.coerceAtLeast(1)

        if (partIndex !in 0 until safePartCount) {
            return ProgressResult(
                progress = PartProgress(
                    completedParts = completedParts
                        .filter { it in 0 until safePartCount }
                        .toSet(),
                    partCount = safePartCount
                ),
                changed = false
            )
        }

        val normalized =
            completedParts
                .filter { it in 0 until safePartCount }
                .toSet()

        val updated =
            normalized + partIndex

        return ProgressResult(
            progress = PartProgress(
                completedParts = updated,
                partCount = safePartCount
            ),
            changed = updated.size != normalized.size
        )
    }

    fun sendStatus(
        progress: PartProgress
    ): SendStatus =
        if (progress.complete) {
            SendStatus.SENT
        } else {
            SendStatus.SENDING
        }

    fun deliveryStatus(
        progress: PartProgress
    ): DeliveryStatus =
        if (progress.complete) {
            DeliveryStatus.DELIVERED
        } else {
            DeliveryStatus.DELIVERING
        }

    fun sendFailureStatus(
        resultCode: Int,
        genericFailureCode: Int,
        noServiceCode: Int,
        nullPduCode: Int,
        radioOffCode: Int
    ): SendStatus =
        when (resultCode) {
            genericFailureCode ->
                SendStatus.GENERIC_FAILURE

            noServiceCode ->
                SendStatus.NO_SERVICE

            nullPduCode ->
                SendStatus.NULL_PDU

            radioOffCode ->
                SendStatus.RADIO_OFF

            else ->
                SendStatus.SEND_FAILED
        }

    fun deliveryFailureStatus(): DeliveryStatus =
        DeliveryStatus.DELIVERY_FAILED


    fun isTerminalFailure(
        status: DeliveryStatus
    ): Boolean =
        status == DeliveryStatus.DELIVERY_FAILED

    fun successfulDeliveryCallbackStatus(
        progress: PartProgress,
        currentStatus: DeliveryStatus?
    ): DeliveryStatus =
        if (
            currentStatus != null &&
            isTerminalFailure(currentStatus)
        ) {
            currentStatus
        } else {
            deliveryStatus(progress)
        }

    fun parseDeliveryStatus(
        value: String?
    ): DeliveryStatus? =
        when (value) {
            "delivering" ->
                DeliveryStatus.DELIVERING

            "delivered" ->
                DeliveryStatus.DELIVERED

            "delivery_failed" ->
                DeliveryStatus.DELIVERY_FAILED

            else ->
                null
        }

    fun isTerminalFailure(
        status: SendStatus
    ): Boolean =
        when (status) {
            SendStatus.GENERIC_FAILURE,
            SendStatus.NO_SERVICE,
            SendStatus.NULL_PDU,
            SendStatus.RADIO_OFF,
            SendStatus.SEND_FAILED ->
                true

            SendStatus.SENDING,
            SendStatus.SENT ->
                false
        }

    fun successfulCallbackStatus(
        progress: PartProgress,
        currentStatus: SendStatus?
    ): SendStatus =
        if (
            currentStatus != null &&
            isTerminalFailure(currentStatus)
        ) {
            currentStatus
        } else {
            sendStatus(progress)
        }

    fun storageRequired(
        sendStatus: SendStatus,
        alreadyStored: Boolean
    ): Boolean =
        sendStatus == SendStatus.SENT &&
            !alreadyStored

    fun parseSendStatus(
        value: String?
    ): SendStatus? =
        when (value) {
            "sending" ->
                SendStatus.SENDING

            "sent" ->
                SendStatus.SENT

            "generic_failure" ->
                SendStatus.GENERIC_FAILURE

            "no_service" ->
                SendStatus.NO_SERVICE

            "null_pdu" ->
                SendStatus.NULL_PDU

            "radio_off" ->
                SendStatus.RADIO_OFF

            "send_failed" ->
                SendStatus.SEND_FAILED

            else ->
                null
        }

    fun persistedValue(
        status: SendStatus
    ): String =
        status.name.lowercase()

    fun persistedValue(
        status: DeliveryStatus
    ): String =
        status.name.lowercase()
}
