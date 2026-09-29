package com.eratguard.pro.domain.messaging

import java.util.concurrent.Executor
import java.util.concurrent.RejectedExecutionException

object SmsAsyncLifecycle {

    fun execute(
        executor: Executor,
        work: () -> Unit,
        complete: () -> Unit
    ) {
        try {
            executor.execute {
                try {
                    work()
                } finally {
                    complete()
                }
            }
        } catch (_: RejectedExecutionException) {
            complete()
        }
    }
}
