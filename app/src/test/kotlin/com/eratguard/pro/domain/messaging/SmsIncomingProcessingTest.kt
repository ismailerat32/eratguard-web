package com.eratguard.pro.domain.messaging

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SmsIncomingProcessingTest {

    @Test
    fun successMarksEntirePipelineCompleted() {
        val outcome =
            SmsIncomingProcessing.success()

        assertEquals(
            SmsIncomingProcessing.Status.SUCCESS,
            outcome.status
        )
        assertNull(outcome.failedStage)
        assertTrue(outcome.routingCompleted)
        assertTrue(outcome.notificationCompleted)
    }

    @Test
    fun routingFailureStopsPipelineBeforeNotification() {
        val outcome =
            SmsIncomingProcessing.routingFailed()

        assertEquals(
            SmsIncomingProcessing.Status.ROUTING_FAILED,
            outcome.status
        )
        assertEquals(
            SmsIncomingProcessing.Stage.ROUTING,
            outcome.failedStage
        )
        assertFalse(outcome.routingCompleted)
        assertFalse(outcome.notificationCompleted)
    }

    @Test
    fun notificationFailurePreservesCompletedRouting() {
        val outcome =
            SmsIncomingProcessing.notificationFailed()

        assertEquals(
            SmsIncomingProcessing.Status.NOTIFICATION_FAILED,
            outcome.status
        )
        assertEquals(
            SmsIncomingProcessing.Stage.NOTIFICATION,
            outcome.failedStage
        )
        assertTrue(outcome.routingCompleted)
        assertFalse(outcome.notificationCompleted)
    }

    @Test
    fun successfulRoutingAllowsNotification() {
        assertTrue(
            SmsIncomingProcessing.shouldNotify(
                SmsIncomingProcessing.success()
            )
        )
    }

    @Test
    fun routingFailureDoesNotAllowNotification() {
        assertFalse(
            SmsIncomingProcessing.shouldNotify(
                SmsIncomingProcessing.routingFailed()
            )
        )
    }

    @Test
    fun notificationFailurePreservesRoutingResult() {
        assertTrue(
            SmsIncomingProcessing.shouldPreserveRoutingResult(
                SmsIncomingProcessing.notificationFailed()
            )
        )
    }

    @Test
    fun routingFailureHasNoRoutingResultToPreserve() {
        assertFalse(
            SmsIncomingProcessing.shouldPreserveRoutingResult(
                SmsIncomingProcessing.routingFailed()
            )
        )
    }
}
