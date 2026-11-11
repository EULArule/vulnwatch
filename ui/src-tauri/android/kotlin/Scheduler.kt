package app.vulnwatch

import android.content.Context
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import org.json.JSONObject
import java.util.concurrent.TimeUnit

/**
 * Turns the "background checking" setting into Android scheduling. Nothing here needs Google
 * Play services: WorkManager runs on the platform's JobScheduler.
 *
 *  - periodic: a WorkManager job every N minutes (Android's floor is 15).
 *  - realtime: a foreground service checking every N minutes, plus a 30-minute job as a watchdog
 *              that brings the service back if the system killed it.
 *  - off:      nothing; the app checks only while it is open.
 */
object Scheduler {
    private const val WORK = "vulnwatch-poll"

    data class Config(val mode: String, val minutes: Long)

    fun config(): Config {
        val c = JSONObject(Native.config())
        return Config(c.optString("background", "periodic"), c.optLong("interval_minutes", 15).coerceAtLeast(1))
    }

    fun apply(context: Context) {
        val ctx = context.applicationContext
        val cfg = config()
        val work = WorkManager.getInstance(ctx)
        if (cfg.mode == "off") {
            work.cancelUniqueWork(WORK)
            WatchService.stop(ctx)
            return
        }
        val every = if (cfg.mode == "realtime") 30 else cfg.minutes.coerceAtLeast(15)
        val request = PeriodicWorkRequestBuilder<PollWorker>(every, TimeUnit.MINUTES)
            .setConstraints(Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build())
            .build()
        work.enqueueUniquePeriodicWork(WORK, ExistingPeriodicWorkPolicy.UPDATE, request)
        if (cfg.mode == "realtime") WatchService.start(ctx) else WatchService.stop(ctx)
    }
}
