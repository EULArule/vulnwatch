package app.vulnwatch

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import org.json.JSONArray

/** Shows the notifications the core produced. Local only: no push service is involved. */
object Notifier {
    private const val ALERTS = "alerts"
    private const val URGENT = "urgent"
    private const val SERVICE = "service"
    private const val GROUP = "vulnwatch"
    const val SERVICE_ID = 1
    private const val SUMMARY_ID = 2
    private const val TEST_ID = 3

    private fun channels(ctx: Context) {
        val nm = ctx.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        nm.createNotificationChannel(
            NotificationChannel(URGENT, "Critical and exploited", NotificationManager.IMPORTANCE_HIGH)
                .apply { description = "Critical vulnerabilities and ones being exploited in the wild" })
        nm.createNotificationChannel(
            NotificationChannel(ALERTS, "Vulnerability alerts", NotificationManager.IMPORTANCE_DEFAULT)
                .apply { description = "Everything else that matches what you watch" })
        nm.createNotificationChannel(
            NotificationChannel(SERVICE, "Background checking", NotificationManager.IMPORTANCE_MIN)
                .apply { description = "Shown while always-on checking is active"; setShowBadge(false) })
    }

    private fun opening(ctx: Context, route: String, request: Int): PendingIntent {
        val intent = Intent(ctx, MainActivity::class.java)
            .putExtra("route", route)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP)
        return PendingIntent.getActivity(ctx, request, intent, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
    }

    /** `list` is the core's `notifications` array: `{id, title, body, url, priority, vuln_id}`. */
    fun show(ctx: Context, list: JSONArray) {
        if (list.length() == 0) return
        channels(ctx)
        val nm = NotificationManagerCompat.from(ctx)
        if (!nm.areNotificationsEnabled()) return
        for (i in 0 until list.length()) {
            val n = list.optJSONObject(i) ?: continue
            val alertId = n.optLong("id")
            val vuln = n.optString("vuln_id")
            val priority = n.optInt("priority", 3)
            val body = n.optString("body")
            // Alert ids start at 1; keep clear of the fixed ids above.
            val id = when {
                alertId > 0 -> 100 + (alertId % 2_000_000_000L).toInt()
                vuln.isEmpty() && n.optString("title").contains("test", ignoreCase = true) -> TEST_ID
                else -> SUMMARY_ID
            }
            val route = if (vuln.isNotEmpty()) "/cve/$vuln" else "/alerts"
            val built = NotificationCompat.Builder(ctx, if (priority >= 5) URGENT else ALERTS)
                .setSmallIcon(R.drawable.ic_stat_vulnwatch)
                .setContentTitle(n.optString("title"))
                .setContentText(body.lineSequence().firstOrNull() ?: "")
                .setStyle(NotificationCompat.BigTextStyle().bigText(body))
                .setContentIntent(opening(ctx, route, id))
                .setAutoCancel(true)
                .setCategory(NotificationCompat.CATEGORY_MESSAGE)
                .setPriority(if (priority >= 5) NotificationCompat.PRIORITY_HIGH else NotificationCompat.PRIORITY_DEFAULT)
                .setColor(0xFF1D4ED8.toInt())
                .setGroup(GROUP)
                .build()
            try {
                nm.notify(id, built)
            } catch (e: SecurityException) {
                return // permission was revoked between the check above and here
            }
        }
    }

    /** The permanent notification Android requires for the always-on service. */
    fun ongoing(ctx: Context): Notification {
        channels(ctx)
        return NotificationCompat.Builder(ctx, SERVICE)
            .setSmallIcon(R.drawable.ic_stat_vulnwatch)
            .setContentTitle("Watching for new vulnerabilities")
            .setContentText("Always-on checking is active. Change it in Settings.")
            .setContentIntent(opening(ctx, "/settings", SERVICE_ID))
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_MIN)
            .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)
            .build()
    }
}
