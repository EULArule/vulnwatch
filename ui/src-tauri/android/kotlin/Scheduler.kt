package app.vulnwatch

import android.app.AlarmManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.SystemClock
import androidx.work.ExistingWorkPolicy
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.OutOfQuotaPolicy
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import org.json.JSONObject
import java.util.concurrent.TimeUnit

/**
 * Turns the "background checking" setting into Android scheduling. Nothing here needs Google
 * Play services: WorkManager runs on the platform's JobScheduler.
 *
 *  - periodic: an alarm every N minutes that starts the check as urgent work, and a WorkManager
 *              job at the same pace (Android's floor is 15) as a net under it. Android holds jobs
 *              back as it sees fit (an idle phone, an app not opened lately), sometimes until the
 *              app is next opened, so the job alone is not enough. The alarm is exact when the
 *              user allows "Alarms & reminders"; otherwise Android may still move it by several
 *              minutes. The job only checks when the alarm's check is overdue.
 *  - realtime: a foreground service checking every N minutes, plus a 30-minute job as a watchdog
 *              that brings the service back if the system killed it.
 *  - off:      nothing; the app checks only while it is open.
 */
object Scheduler {
    private const val WORK = "vulnwatch-poll"
    private const val WORK_NOW = "vulnwatch-poll-now"
    const val TICK = "app.vulnwatch.TICK"
    /** Marks the check the alarm asked for, as opposed to the periodic job. */
    const val URGENT = "urgent"

    /** [sinceLast]: seconds since this device last finished a check, or -1 if it never has. */
    data class Config(val mode: String, val minutes: Long, val sinceLast: Long)

    fun config(): Config {
        val c = JSONObject(Native.config())
        return Config(c.optString("background", "periodic"), c.optLong("interval_minutes", 15).coerceAtLeast(1), c.optLong("since_last", -1))
    }

    private fun alarm(ctx: Context): PendingIntent =
        PendingIntent.getBroadcast(
            ctx, 1, Intent(ctx, BootReceiver::class.java).setAction(TICK),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )

    /** Whether Android lets this app set alarms for an exact time ("Alarms & reminders"). */
    fun exact(ctx: Context): Boolean =
        Build.VERSION.SDK_INT < 31 || (ctx.getSystemService(Context.ALARM_SERVICE) as AlarmManager).canScheduleExactAlarms()

    /** Set the alarm for [seconds] from now. Both kinds may fire while the phone is idle. */
    private fun arm(ctx: Context, seconds: Long) {
        val alarms = ctx.getSystemService(Context.ALARM_SERVICE) as AlarmManager
        val at = SystemClock.elapsedRealtime() + seconds * 1000
        try {
            if (exact(ctx)) {
                alarms.setExactAndAllowWhileIdle(AlarmManager.ELAPSED_REALTIME_WAKEUP, at, alarm(ctx))
                return
            }
        } catch (e: SecurityException) {
            // The permission was taken away between the question and the call.
        }
        alarms.setAndAllowWhileIdle(AlarmManager.ELAPSED_REALTIME_WAKEUP, at, alarm(ctx))
    }

    private fun disarm(ctx: Context) {
        (ctx.getSystemService(Context.ALARM_SERVICE) as AlarmManager).cancel(alarm(ctx))
    }

    /** The alarm went off: set the next one, and have a check run now. */
    fun tick(context: Context) {
        val ctx = context.applicationContext
        val cfg = config()
        if (cfg.mode != "periodic") return
        arm(ctx, cfg.minutes.coerceAtLeast(15) * 60)
        val request = OneTimeWorkRequestBuilder<PollWorker>().addTag(URGENT)
        // Urgent work starts at once even on an idle phone. Before Android 12 it would need a
        // notification, so there it is ordinary work.
        if (Build.VERSION.SDK_INT >= 31) request.setExpedited(OutOfQuotaPolicy.RUN_AS_NON_EXPEDITED_WORK_REQUEST)
        WorkManager.getInstance(ctx).enqueueUniqueWork(WORK_NOW, ExistingWorkPolicy.KEEP, request.build())
    }

    fun apply(context: Context) {
        val ctx = context.applicationContext
        val cfg = config()
        val work = WorkManager.getInstance(ctx)
        if (cfg.mode == "off") {
            work.cancelUniqueWork(WORK)
            work.cancelUniqueWork(WORK_NOW)
            disarm(ctx)
            WatchService.stop(ctx)
            return
        }
        val every = if (cfg.mode == "realtime") 30 else cfg.minutes.coerceAtLeast(15)
        // No "needs a network" condition: Android may count the network as unusable for an app
        // in the background and then never start the job. Without one a check simply fails
        // fast, and says so in the list of recent checks.
        val request = PeriodicWorkRequestBuilder<PollWorker>(every, TimeUnit.MINUTES).build()
        work.enqueueUniquePeriodicWork(WORK, ExistingPeriodicWorkPolicy.UPDATE, request)
        if (cfg.mode == "realtime") {
            disarm(ctx)
            WatchService.start(ctx)
        } else {
            // Counted from the last check, so that opening the app does not push the next one back.
            val due = if (cfg.sinceLast < 0) every * 60 else (every * 60 - cfg.sinceLast).coerceIn(60, every * 60)
            arm(ctx, due)
            WatchService.stop(ctx)
        }
    }
}
