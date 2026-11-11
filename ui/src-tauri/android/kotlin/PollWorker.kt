package app.vulnwatch

import android.content.Context
import androidx.work.Worker
import androidx.work.WorkerParameters
import org.json.JSONObject

/** One background check. Android may start the whole process just for this. */
class PollWorker(context: Context, params: WorkerParameters) : Worker(context, params) {
    override fun doWork(): Result {
        val ctx = applicationContext
        if (!Native.ensure(ctx)) return Result.retry()
        val cfg = Scheduler.config()
        if (cfg.mode == "off") return Result.success()
        if (cfg.mode == "realtime") {
            if (WatchService.running) return Result.success()
            // The service was killed. Bring it back; if Android refuses (background start
            // restrictions), fall through and do the check here instead.
            if (WatchService.start(ctx)) return Result.success()
        }
        val report = JSONObject(Native.poll())
        report.optJSONArray("notifications")?.let { Notifier.show(ctx, it) }
        return Result.success()
    }
}
