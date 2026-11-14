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
        // The alarm and the periodic job both lead here. The alarm's check always runs (unless
        // one has only just finished); the job is the net under it and runs when a check is overdue.
        val recent = if (tags.contains(Scheduler.URGENT)) 60L else cfg.minutes.coerceAtLeast(15) * 60
        if (cfg.mode == "periodic" && cfg.sinceLast in 0 until recent) return Result.success()
        val report = JSONObject(Native.poll())
        report.optJSONArray("notifications")?.let { Notifier.show(ctx, it) }
        return Result.success()
    }
}
