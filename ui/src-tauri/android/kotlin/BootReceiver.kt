package app.vulnwatch

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/** Re-plan background checks after a reboot or an app update, and take the check alarm. */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        when (intent.action) {
            Scheduler.TICK -> try {
                if (Native.ensure(context)) Scheduler.tick(context)
            } catch (e: Exception) {
                android.util.Log.w("vulnwatch", "could not start the check", e)
            }
            Intent.ACTION_BOOT_COMPLETED, Intent.ACTION_MY_PACKAGE_REPLACED -> try {
                if (Native.ensure(context)) Scheduler.apply(context)
            } catch (e: Exception) {
                android.util.Log.w("vulnwatch", "could not schedule after boot", e)
            }
        }
    }
}
