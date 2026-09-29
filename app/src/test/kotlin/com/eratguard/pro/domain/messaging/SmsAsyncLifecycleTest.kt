package com.eratguard.pro.domain.messaging

import java.util.concurrent.Executor
import java.util.concurrent.RejectedExecutionException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SmsAsyncLifecycleTest {

    private val directExecutor =
        Executor { command ->
            command.run()
        }

    @Test
    fun successfulWorkCompletesExactlyOnce() {

        var workCount = 0
        var completeCount = 0

        SmsAsyncLifecycle.execute(
            executor = directExecutor,
            work = {
                workCount += 1
            },
            complete = {
                completeCount += 1
            }
        )

        assertEquals(1, workCount)
        assertEquals(1, completeCount)
    }

    @Test
    fun throwingWorkStillCompletesExactlyOnce() {

        var completeCount = 0
        var thrown = false

        try {
            SmsAsyncLifecycle.execute(
                executor = directExecutor,
                work = {
                    throw IllegalStateException(
                        "test failure"
                    )
                },
                complete = {
                    completeCount += 1
                }
            )
        } catch (_: IllegalStateException) {
            thrown = true
        }

        assertTrue(thrown)
        assertEquals(1, completeCount)
    }

    @Test
    fun rejectedSubmissionCompletesExactlyOnce() {

        val rejectingExecutor =
            Executor {
                throw RejectedExecutionException(
                    "rejected"
                )
            }

        var workRan = false
        var completeCount = 0

        SmsAsyncLifecycle.execute(
            executor = rejectingExecutor,
            work = {
                workRan = true
            },
            complete = {
                completeCount += 1
            }
        )

        assertFalse(workRan)
        assertEquals(1, completeCount)
    }
}
