package com.eratguard.pro.domain.messaging

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertNotNull
import org.junit.Test

class SmsIncomingAssemblyTest {

    @Test
    fun emptyPartsRejected() {
        assertNull(
            SmsIncomingAssembly.assemble(
                parts = emptyList(),
                fallbackTimestamp = 1000L
            )
        )
    }

    @Test
    fun blankSenderRejected() {
        assertNull(
            SmsIncomingAssembly.assemble(
                parts = listOf(
                    SmsIncomingAssembly.Part(
                        sender = "   ",
                        body = "hello",
                        timestamp = 1000L
                    )
                ),
                fallbackTimestamp = 2000L
            )
        )
    }

    @Test
    fun blankBodyRejected() {
        assertNull(
            SmsIncomingAssembly.assemble(
                parts = listOf(
                    SmsIncomingAssembly.Part(
                        sender = "5551234",
                        body = "   ",
                        timestamp = 1000L
                    )
                ),
                fallbackTimestamp = 2000L
            )
        )
    }

    @Test
    fun singlePartAssembled() {
        val result =
            SmsIncomingAssembly.assemble(
                parts = listOf(
                    SmsIncomingAssembly.Part(
                        sender = "5551234",
                        body = "hello",
                        timestamp = 1000L
                    )
                ),
                fallbackTimestamp = 2000L
            )

        assertNotNull(result)
        assertEquals("5551234", result!!.sender)
        assertEquals("hello", result.body)
        assertEquals(1000L, result.timestamp)
    }

    @Test
    fun multipartBodyPreservesOrder() {
        val result =
            SmsIncomingAssembly.assemble(
                parts = listOf(
                    SmsIncomingAssembly.Part(
                        sender = "5551234",
                        body = "hello ",
                        timestamp = 1000L
                    ),
                    SmsIncomingAssembly.Part(
                        sender = "5551234",
                        body = "world",
                        timestamp = 1000L
                    )
                ),
                fallbackTimestamp = 2000L
            )

        assertNotNull(result)
        assertEquals("hello world", result!!.body)
    }

    @Test
    fun differentMultipartSendersRejected() {
        assertNull(
            SmsIncomingAssembly.assemble(
                parts = listOf(
                    SmsIncomingAssembly.Part(
                        sender = "111",
                        body = "first",
                        timestamp = 1000L
                    ),
                    SmsIncomingAssembly.Part(
                        sender = "222",
                        body = "second",
                        timestamp = 1000L
                    )
                ),
                fallbackTimestamp = 2000L
            )
        )
    }

    @Test
    fun senderWhitespaceNormalizedForComparison() {
        val result =
            SmsIncomingAssembly.assemble(
                parts = listOf(
                    SmsIncomingAssembly.Part(
                        sender = " 5551234 ",
                        body = "A",
                        timestamp = 1000L
                    ),
                    SmsIncomingAssembly.Part(
                        sender = "5551234",
                        body = "B",
                        timestamp = 1000L
                    )
                ),
                fallbackTimestamp = 2000L
            )

        assertNotNull(result)
        assertEquals("5551234", result!!.sender)
        assertEquals("AB", result.body)
    }

    @Test
    fun firstPositivePartTimestampUsed() {
        val result =
            SmsIncomingAssembly.assemble(
                parts = listOf(
                    SmsIncomingAssembly.Part(
                        sender = "555",
                        body = "A",
                        timestamp = 0L
                    ),
                    SmsIncomingAssembly.Part(
                        sender = "555",
                        body = "B",
                        timestamp = 3000L
                    )
                ),
                fallbackTimestamp = 4000L
            )

        assertNotNull(result)
        assertEquals(3000L, result!!.timestamp)
    }

    @Test
    fun fallbackTimestampUsedWhenPartsHaveNoValidTimestamp() {
        val result =
            SmsIncomingAssembly.assemble(
                parts = listOf(
                    SmsIncomingAssembly.Part(
                        sender = "555",
                        body = "hello",
                        timestamp = 0L
                    )
                ),
                fallbackTimestamp = 5000L
            )

        assertNotNull(result)
        assertEquals(5000L, result!!.timestamp)
    }

    @Test
    fun invalidPartAndFallbackTimestampRejected() {
        assertNull(
            SmsIncomingAssembly.assemble(
                parts = listOf(
                    SmsIncomingAssembly.Part(
                        sender = "555",
                        body = "hello",
                        timestamp = 0L
                    )
                ),
                fallbackTimestamp = 0L
            )
        )
    }
}
