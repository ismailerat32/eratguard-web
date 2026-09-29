package com.eratguard.pro.domain.messaging

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.assertNull
import org.junit.Test

class SmsSendStateMachineTest {

    @Test
    fun firstMultipartPartKeepsSending() {
        val result =
            SmsSendStateMachine.recordSuccessfulPart(
                completedParts = emptySet(),
                partIndex = 0,
                partCount = 3
            )

        assertEquals(1, result.progress.completedCount)
        assertTrue(result.changed)
        assertEquals(
            SmsSendStateMachine.SendStatus.SENDING,
            SmsSendStateMachine.sendStatus(
                result.progress
            )
        )
    }

    @Test
    fun allMultipartPartsBecomeSent() {
        var parts =
            emptySet<Int>()

        repeat(3) { index ->
            parts =
                SmsSendStateMachine
                    .recordSuccessfulPart(
                        completedParts = parts,
                        partIndex = index,
                        partCount = 3
                    )
                    .progress
                    .completedParts
        }

        val progress =
            SmsSendStateMachine.PartProgress(
                completedParts = parts,
                partCount = 3
            )

        assertEquals(
            SmsSendStateMachine.SendStatus.SENT,
            SmsSendStateMachine.sendStatus(
                progress
            )
        )
    }

    @Test
    fun duplicateSentCallbackDoesNotIncreaseCount() {
        val first =
            SmsSendStateMachine.recordSuccessfulPart(
                completedParts = emptySet(),
                partIndex = 0,
                partCount = 2
            )

        val duplicate =
            SmsSendStateMachine.recordSuccessfulPart(
                completedParts =
                    first.progress.completedParts,
                partIndex = 0,
                partCount = 2
            )

        assertEquals(
            1,
            duplicate.progress.completedCount
        )
        assertFalse(duplicate.changed)
    }

    @Test
    fun duplicateDeliveryCallbackDoesNotCompleteEarly() {
        val first =
            SmsSendStateMachine.recordSuccessfulPart(
                completedParts = emptySet(),
                partIndex = 0,
                partCount = 2
            )

        val duplicate =
            SmsSendStateMachine.recordSuccessfulPart(
                completedParts =
                    first.progress.completedParts,
                partIndex = 0,
                partCount = 2
            )

        assertEquals(
            SmsSendStateMachine.DeliveryStatus.DELIVERING,
            SmsSendStateMachine.deliveryStatus(
                duplicate.progress
            )
        )
    }

    @Test
    fun invalidPartIndexIsIgnored() {
        val result =
            SmsSendStateMachine.recordSuccessfulPart(
                completedParts = emptySet(),
                partIndex = 5,
                partCount = 2
            )

        assertEquals(0, result.progress.completedCount)
        assertFalse(result.changed)
    }

    @Test
    fun partCountIsNeverBelowOne() {
        val result =
            SmsSendStateMachine.recordSuccessfulPart(
                completedParts = emptySet(),
                partIndex = 0,
                partCount = 0
            )

        assertEquals(1, result.progress.partCount)
        assertTrue(result.progress.complete)
    }

    @Test
    fun completeMessageRequiresStorageWhenNotStored() {
        assertTrue(
            SmsSendStateMachine.storageRequired(
                sendStatus =
                    SmsSendStateMachine.SendStatus.SENT,
                alreadyStored = false
            )
        )
    }

    @Test
    fun storedMessageDoesNotRequireStorageAgain() {
        assertFalse(
            SmsSendStateMachine.storageRequired(
                sendStatus =
                    SmsSendStateMachine.SendStatus.SENT,
                alreadyStored = true
            )
        )
    }

    @Test
    fun sendingMessageDoesNotRequireStorage() {
        assertFalse(
            SmsSendStateMachine.storageRequired(
                sendStatus =
                    SmsSendStateMachine.SendStatus.SENDING,
                alreadyStored = false
            )
        )
    }

    @Test
    fun failureCodesMapToStableStatuses() {
        assertEquals(
            SmsSendStateMachine.SendStatus.GENERIC_FAILURE,
            SmsSendStateMachine.sendFailureStatus(
                resultCode = 1,
                genericFailureCode = 1,
                noServiceCode = 2,
                nullPduCode = 3,
                radioOffCode = 4
            )
        )

        assertEquals(
            SmsSendStateMachine.SendStatus.NO_SERVICE,
            SmsSendStateMachine.sendFailureStatus(
                resultCode = 2,
                genericFailureCode = 1,
                noServiceCode = 2,
                nullPduCode = 3,
                radioOffCode = 4
            )
        )

        assertEquals(
            SmsSendStateMachine.SendStatus.NULL_PDU,
            SmsSendStateMachine.sendFailureStatus(
                resultCode = 3,
                genericFailureCode = 1,
                noServiceCode = 2,
                nullPduCode = 3,
                radioOffCode = 4
            )
        )

        assertEquals(
            SmsSendStateMachine.SendStatus.RADIO_OFF,
            SmsSendStateMachine.sendFailureStatus(
                resultCode = 4,
                genericFailureCode = 1,
                noServiceCode = 2,
                nullPduCode = 3,
                radioOffCode = 4
            )
        )

        assertEquals(
            SmsSendStateMachine.SendStatus.SEND_FAILED,
            SmsSendStateMachine.sendFailureStatus(
                resultCode = 99,
                genericFailureCode = 1,
                noServiceCode = 2,
                nullPduCode = 3,
                radioOffCode = 4
            )
        )
    }

    @Test
    fun persistedStatusValuesRemainCompatibleWithUi() {
        assertEquals(
            "sending",
            SmsSendStateMachine.persistedValue(
                SmsSendStateMachine.SendStatus.SENDING
            )
        )

        assertEquals(
            "sent",
            SmsSendStateMachine.persistedValue(
                SmsSendStateMachine.SendStatus.SENT
            )
        )

        assertEquals(
            "delivering",
            SmsSendStateMachine.persistedValue(
                SmsSendStateMachine.DeliveryStatus.DELIVERING
            )
        )

        assertEquals(
            "delivered",
            SmsSendStateMachine.persistedValue(
                SmsSendStateMachine.DeliveryStatus.DELIVERED
            )
        )

        assertEquals(
            "delivery_failed",
            SmsSendStateMachine.persistedValue(
                SmsSendStateMachine.DeliveryStatus.DELIVERY_FAILED
            )
        )
    }
    @Test
    fun sendFailureIsTerminal() {
        assertTrue(
            SmsSendStateMachine.isTerminalFailure(
                SmsSendStateMachine.SendStatus.NO_SERVICE
            )
        )

        assertTrue(
            SmsSendStateMachine.isTerminalFailure(
                SmsSendStateMachine.SendStatus.SEND_FAILED
            )
        )
    }

    @Test
    fun sendingAndSentAreNotTerminalFailures() {
        assertFalse(
            SmsSendStateMachine.isTerminalFailure(
                SmsSendStateMachine.SendStatus.SENDING
            )
        )

        assertFalse(
            SmsSendStateMachine.isTerminalFailure(
                SmsSendStateMachine.SendStatus.SENT
            )
        )
    }

    @Test
    fun successfulCallbackCannotOverwriteFailure() {
        val progress =
            SmsSendStateMachine.PartProgress(
                completedParts = setOf(0, 1),
                partCount = 2
            )

        assertEquals(
            SmsSendStateMachine.SendStatus.NO_SERVICE,
            SmsSendStateMachine.successfulCallbackStatus(
                progress = progress,
                currentStatus =
                    SmsSendStateMachine.SendStatus.NO_SERVICE
            )
        )
    }

    @Test
    fun successfulCallbackAdvancesNormalState() {
        val progress =
            SmsSendStateMachine.PartProgress(
                completedParts = setOf(0, 1),
                partCount = 2
            )

        assertEquals(
            SmsSendStateMachine.SendStatus.SENT,
            SmsSendStateMachine.successfulCallbackStatus(
                progress = progress,
                currentStatus =
                    SmsSendStateMachine.SendStatus.SENDING
            )
        )
    }


    @Test
    fun persistedSendStatusesRoundTrip() {
        SmsSendStateMachine.SendStatus.values()
            .forEach { status ->

                val persisted =
                    SmsSendStateMachine.persistedValue(
                        status
                    )

                assertEquals(
                    status,
                    SmsSendStateMachine.parseSendStatus(
                        persisted
                    )
                )
            }
    }

    @Test
    fun unknownPersistedSendStatusReturnsNull() {
        assertNull(
            SmsSendStateMachine.parseSendStatus(
                "unknown_status"
            )
        )
    }

    @Test
    fun nullPersistedSendStatusReturnsNull() {
        assertNull(
            SmsSendStateMachine.parseSendStatus(
                null
            )
        )
    }


    @Test
    fun deliveryFailureIsTerminal() {
        assertTrue(
            SmsSendStateMachine.isTerminalFailure(
                SmsSendStateMachine.DeliveryStatus.DELIVERY_FAILED
            )
        )
    }

    @Test
    fun successfulDeliveryCallbackCannotOverwriteFailure() {
        val progress =
            SmsSendStateMachine.PartProgress(
                completedParts = setOf(0, 1),
                partCount = 2
            )

        assertEquals(
            SmsSendStateMachine.DeliveryStatus.DELIVERY_FAILED,
            SmsSendStateMachine.successfulDeliveryCallbackStatus(
                progress = progress,
                currentStatus =
                    SmsSendStateMachine.DeliveryStatus.DELIVERY_FAILED
            )
        )
    }

    @Test
    fun successfulDeliveryCallbackAdvancesNormalState() {
        val progress =
            SmsSendStateMachine.PartProgress(
                completedParts = setOf(0, 1),
                partCount = 2
            )

        assertEquals(
            SmsSendStateMachine.DeliveryStatus.DELIVERED,
            SmsSendStateMachine.successfulDeliveryCallbackStatus(
                progress = progress,
                currentStatus =
                    SmsSendStateMachine.DeliveryStatus.DELIVERING
            )
        )
    }

    @Test
    fun persistedDeliveryStatusesRoundTrip() {
        SmsSendStateMachine.DeliveryStatus.values()
            .forEach { status ->

                val persisted =
                    SmsSendStateMachine.persistedValue(
                        status
                    )

                assertEquals(
                    status,
                    SmsSendStateMachine.parseDeliveryStatus(
                        persisted
                    )
                )
            }
    }


}
