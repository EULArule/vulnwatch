package app.vulnwatch

import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat
import org.json.JSONObject

/** "Always on" mode: a foreground service that checks every few minutes. */
class WatchService : Service() {
    companion object {
        @Volatile var running = false

        fun start(ctx: Context): Boolean = try {
            ContextCompat.startForegroundService(ctx, Intent(ctx, WatchService::class.java))
            true
        } catch (e: Exception) {
            android.util.Log.w("vulnwatch", "cannot start the watch service", e)
            false
        }

        fun stop(ctx: Context) {
            ctx.stopService(Intent(ctx, WatchService::class.java))
        }
    }

    private var loop: Thread? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        try {
            val type = if (Build.VERSION.SDK_INT >= 34) ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE else 0
            ServiceCompat.startForeground(this, Notifier.SERVICE_ID, Notifier.ongoing(this), type)
        } catch (e: Exception) {
            android.util.Log.w("vulnwatch", "cannot enter the foreground", e)
            stopSelf()
            return START_NOT_STICKY
        }
        running = true
        if (loop == null) {
            loop = Thread({ run() }, "vulnwatch-watch").also { it.start() }
        }
        return START_STICKY
    }

    private fun run() {
        try {
            while (!Thread.currentThread().isInterrupted) {
                if (!Native.ensure(this)) {
                    Thread.sleep(60_000)
                    continue
                }
                val cfg = Scheduler.config()
                if (cfg.mode != "realtime") break
                val report = JSONObject(Native.poll())
                report.optJSONArray("notifications")?.let { Notifier.show(this, it) }
                Thread.sleep(cfg.minutes * 60_000)
            }
        } catch (e: InterruptedException) {
            return
        } catch (e: Exception) {
            android.util.Log.w("vulnwatch", "watch loop stopped", e)
        }
        stopSelf()
    }

    override fun onDestroy() {
        running = false
        loop?.interrupt()
        loop = null
        super.onDestroy()
    }
}
