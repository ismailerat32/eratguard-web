package com.eratguard.pro.domain.shell

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class EratGuardShellPolicyTest {

    @Test
    fun smsPathOpensNativeSms() {
        assertTrue(
            EratGuardShellPolicy.shouldOpenNativeSms("/sms")
        )
    }

    @Test
    fun smsCenterPathOpensNativeSms() {
        assertTrue(
            EratGuardShellPolicy.shouldOpenNativeSms(
                "/dashboard/sms-center"
            )
        )
    }

    @Test
    fun smsActionsCenterPathOpensNativeSms() {
        assertTrue(
            EratGuardShellPolicy.shouldOpenNativeSms(
                "/sms-actions-center"
            )
        )
    }

    @Test
    fun normalDashboardDoesNotOpenNativeSms() {
        assertFalse(
            EratGuardShellPolicy.shouldOpenNativeSms(
                "/dashboard"
            )
        )
    }

    @Test
    fun trustedHttpsHostAccepted() {
        assertTrue(
            EratGuardShellPolicy.isTrustedEratGuardUrl(
                "https://app.eratguard.com/dashboard"
            )
        )
    }

    @Test
    fun httpTrustedHostRejected() {
        assertFalse(
            EratGuardShellPolicy.isTrustedEratGuardUrl(
                "http://app.eratguard.com/dashboard"
            )
        )
    }

    @Test
    fun lookalikeHostRejected() {
        assertFalse(
            EratGuardShellPolicy.isTrustedEratGuardUrl(
                "https://app.eratguard.com.attacker.test/login"
            )
        )
    }

    @Test
    fun renderLoadingDetected() {
        assertTrue(
            EratGuardShellPolicy.isRenderLoading(
                "Application Loading"
            )
        )
    }

    @Test
    fun dashboardContentCanBecomeReady() {
        assertTrue(
            EratGuardShellPolicy.isContentReady(
                "https://app.eratguard.com/dashboard",
                "ERATGUARD ANA KORUMA"
            )
        )
    }

    @Test
    fun untrustedDashboardContentCannotBecomeReady() {
        assertFalse(
            EratGuardShellPolicy.isContentReady(
                "https://attacker.test/dashboard",
                "ERATGUARD ANA KORUMA"
            )
        )
    }


    @Test
    fun trustedLoginCanBecomeReady() {
        assertTrue(
            EratGuardShellPolicy.isContentReady(
                "https://app.eratguard.com/login",
                "ERATGUARD"
            )
        )
    }

    @Test
    fun untrustedLoginCannotBecomeReadyFromAuthRule() {
        assertFalse(
            EratGuardShellPolicy.isContentReady(
                "https://attacker.test/login",
                "ERATGUARD"
            )
        )
    }
}
