package com.eratguard.pro.domain.messaging

object SmsIncomingProcessing {

    enum class Stage {
        ROUTING,
        NOTIFICATION
    }

    enum class Status {
        SUCCESS,
        ROUTING_FAILED,
        NOTIFICATION_FAILED
    }

    data class Outcome(
        val status: Status,
        val failedStage: Stage?,
        val routingCompleted: Boolean,
        val notificationCompleted: Boolean
    )

    fun success(): Outcome =
        Outcome(
            status = Status.SUCCESS,
            failedStage = null,
            routingCompleted = true,
            notificationCompleted = true
        )

    fun routingFailed(): Outcome =
        Outcome(
            status = Status.ROUTING_FAILED,
            failedStage = Stage.ROUTING,
            routingCompleted = false,
            notificationCompleted = false
        )

    fun notificationFailed(): Outcome =
        Outcome(
            status = Status.NOTIFICATION_FAILED,
            failedStage = Stage.NOTIFICATION,
            routingCompleted = true,
            notificationCompleted = false
        )

    fun shouldNotify(
        outcome: Outcome
    ): Boolean =
        outcome.routingCompleted

    fun shouldPreserveRoutingResult(
        outcome: Outcome
    ): Boolean =
        outcome.routingCompleted
}
