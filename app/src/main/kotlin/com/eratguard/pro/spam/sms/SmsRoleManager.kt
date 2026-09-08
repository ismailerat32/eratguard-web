package com.eratguard.pro.spam.sms

import android.app.Activity
import android.app.role.RoleManager
import android.content.Context
import android.content.Intent
import android.os.Build
import android.provider.Telephony

object SmsRoleManager {

    const val REQUEST_CODE_SMS_ROLE = 4201

    fun isDefaultSmsApp(context: Context): Boolean {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            val roleManager =
                context.getSystemService(RoleManager::class.java)

            roleManager?.isRoleAvailable(RoleManager.ROLE_SMS) == true &&
                roleManager.isRoleHeld(RoleManager.ROLE_SMS)
        } else {
            Telephony.Sms.getDefaultSmsPackage(context) ==
                context.packageName
        }
    }

    fun requestDefaultSmsRole(activity: Activity): Boolean {

        if (isDefaultSmsApp(activity)) {
            return true
        }

        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {

            val roleManager =
                activity.getSystemService(RoleManager::class.java)
                    ?: return false

            if (!roleManager.isRoleAvailable(RoleManager.ROLE_SMS)) {
                return false
            }

            activity.startActivityForResult(
                roleManager.createRequestRoleIntent(
                    RoleManager.ROLE_SMS
                ),
                REQUEST_CODE_SMS_ROLE
            )

            true

        } else {

            val intent =
                Intent(Telephony.Sms.Intents.ACTION_CHANGE_DEFAULT).apply {
                    putExtra(
                        Telephony.Sms.Intents.EXTRA_PACKAGE_NAME,
                        activity.packageName
                    )
                }

            activity.startActivityForResult(
                intent,
                REQUEST_CODE_SMS_ROLE
            )

            true
        }
    }
}
