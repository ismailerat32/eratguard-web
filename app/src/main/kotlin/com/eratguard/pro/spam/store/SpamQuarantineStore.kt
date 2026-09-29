package com.eratguard.pro.spam.store

import android.content.Context
import com.eratguard.pro.domain.messaging.SmsIncomingIdentity
import org.json.JSONArray
import org.json.JSONObject

object SpamQuarantineStore {

    private const val PREFS =
        "eratguard_spam_quarantine"

    private const val KEY_MESSAGES =
        "messages"

    private const val MAX_MESSAGES = 200

    @Synchronized
    fun add(
        context: Context,
        sender: String,
        body: String,
        timestamp: Long,
        score: Int,
        verdict: String,
        reasons: List<String>
    ): Boolean {

        if (body.isBlank()) {
            return false
        }

        val prefs =
            context.getSharedPreferences(
                PREFS,
                Context.MODE_PRIVATE
            )

        return try {

            val existing =
                try {

                    JSONArray(
                        prefs.getString(
                            KEY_MESSAGES,
                            "[]"
                        ) ?: "[]"
                    )

                } catch (_: Exception) {

                    JSONArray()
                }

            val id =
                SmsIncomingIdentity.fingerprint(
                    sender = sender,
                    body = body,
                    timestamp = timestamp
                ) ?: return false

            /*
             * Aynı mesaj zaten varsa yeniden ekleme.
             * İşlem başarılı kabul edilir.
             */
            for (i in 0 until existing.length()) {

                val old =
                    existing.optJSONObject(i)
                        ?: continue

                if (
                    old.optString("id") == id
                ) {
                    return true
                }
            }

            val item =
                JSONObject().apply {

                    put(
                        "id",
                        id
                    )

                    put(
                        "sender",
                        sender
                    )

                    put(
                        "body",
                        body
                    )

                    put(
                        "timestamp",
                        timestamp
                    )

                    put(
                        "score",
                        score
                    )

                    put(
                        "verdict",
                        verdict
                    )

                    put(
                        "reasons",
                        JSONArray(reasons)
                    )

                    put(
                        "createdAt",
                        System.currentTimeMillis()
                    )
                }

            val output =
                JSONArray()

            output.put(item)

            val keep =
                minOf(
                    existing.length(),
                    MAX_MESSAGES - 1
                )

            for (i in 0 until keep) {
                output.put(
                    existing.get(i)
                )
            }

            /*
             * commit() özellikle kullanılıyor.
             *
             * apply() asenkron olduğu için SMS routing
             * açısından yazmanın gerçekten tamamlandığını
             * bilemeyiz.
             */
            prefs.edit()
                .putString(
                    KEY_MESSAGES,
                    output.toString()
                )
                .commit()

        } catch (_: Exception) {

            false
        }
    }

    data class QuarantinedMessage(
        val id: String,
        val sender: String,
        val body: String,
        val timestamp: Long,
        val score: Int,
        val verdict: String,
        val reasons: List<String>,
        val createdAt: Long
    )

    fun list(
        context: Context
    ): List<QuarantinedMessage> {

        val prefs =
            context.getSharedPreferences(
                PREFS,
                Context.MODE_PRIVATE
            )

        return try {

            val messages =
                JSONArray(
                    prefs.getString(
                        KEY_MESSAGES,
                        "[]"
                    ) ?: "[]"
                )

            val output =
                ArrayList<QuarantinedMessage>(
                    messages.length()
                )

            for (i in 0 until messages.length()) {

                val item =
                    messages.optJSONObject(i)
                        ?: continue

                val id =
                    item.optString("id")

                if (id.isBlank()) {
                    continue
                }

                val reasonArray =
                    item.optJSONArray("reasons")
                        ?: JSONArray()

                val reasons =
                    ArrayList<String>(
                        reasonArray.length()
                    )

                for (
                    reasonIndex in
                    0 until reasonArray.length()
                ) {

                    val reason =
                        reasonArray.optString(
                            reasonIndex
                        )

                    if (reason.isNotBlank()) {
                        reasons.add(reason)
                    }
                }

                output.add(
                    QuarantinedMessage(
                        id = id,
                        sender =
                            item.optString(
                                "sender"
                            ),
                        body =
                            item.optString(
                                "body"
                            ),
                        timestamp =
                            item.optLong(
                                "timestamp"
                            ),
                        score =
                            item.optInt(
                                "score"
                            ),
                        verdict =
                            item.optString(
                                "verdict"
                            ),
                        reasons = reasons,
                        createdAt =
                            item.optLong(
                                "createdAt"
                            )
                    )
                )
            }

            output

        } catch (_: Exception) {

            emptyList()
        }
    }

    @Synchronized
    fun remove(
        context: Context,
        id: String
    ): Boolean {

        if (id.isBlank()) {
            return false
        }

        val prefs =
            context.getSharedPreferences(
                PREFS,
                Context.MODE_PRIVATE
            )

        return try {

            val existing =
                JSONArray(
                    prefs.getString(
                        KEY_MESSAGES,
                        "[]"
                    ) ?: "[]"
                )

            val output =
                JSONArray()

            var found =
                false

            for (i in 0 until existing.length()) {

                val item =
                    existing.optJSONObject(i)

                if (item == null) {
                    output.put(
                        existing.get(i)
                    )
                    continue
                }

                if (
                    item.optString("id") == id
                ) {

                    found = true
                    continue
                }

                output.put(item)
            }

            if (!found) {
                return false
            }

            prefs.edit()
                .putString(
                    KEY_MESSAGES,
                    output.toString()
                )
                .commit()

        } catch (_: Exception) {

            false
        }
    }

    fun count(
        context: Context
    ): Int {

        val prefs =
            context.getSharedPreferences(
                PREFS,
                Context.MODE_PRIVATE
            )

        return try {

            JSONArray(
                prefs.getString(
                    KEY_MESSAGES,
                    "[]"
                ) ?: "[]"
            ).length()

        } catch (_: Exception) {

            0
        }
    }
}
