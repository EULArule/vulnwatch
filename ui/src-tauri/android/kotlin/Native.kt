package app.vulnwatch

import android.Manifest
import android.app.Activity
import android.content.ClipData
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.PowerManager
import android.provider.Settings
import android.widget.Toast
import androidx.core.app.ActivityCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import androidx.core.content.FileProvider
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.lang.ref.WeakReference
import androidx.annotation.Keep

/**
 * The seam between Kotlin and the Rust core (src/lib.rs).
 *
 * Kotlin -> Rust: [init], [poll], [config].
 * Rust -> Kotlin: [bridge], for the few things only Android can do.
 */
@Keep
object Native {
    init {
        System.loadLibrary("vulnwatch_app")
    }

    @JvmStatic external fun init(dataDir: String): Boolean
    @JvmStatic external fun poll(): String
    @JvmStatic external fun config(): String

    @Volatile private var app: Context? = null
    @Volatile private var activity = WeakReference<Activity>(null)

    /** Where the UI should go next (set when a notification is tapped). */
    @Volatile var pendingRoute: String = ""

    /** Open the database. Safe to call any number of times, from any entry point. */
    @Synchronized
    fun ensure(context: Context): Boolean {
        val ctx = context.applicationContext
        app = ctx
        return init(File(ctx.filesDir, "vulnwatch").absolutePath)
    }

    fun attach(a: Activity) {
        ensure(a)
        activity = WeakReference(a)
    }

    @JvmStatic
    fun bridge(what: String, arg: String): String {
        val ctx = app ?: return "null"
        return try {
            when (what) {
                "state" -> state(ctx)
                "request_notifications" -> { requestNotifications(ctx); "true" }
                "request_battery" -> { requestBattery(ctx); "true" }
                "request_alarms" -> { requestAlarms(ctx); "true" }
                "reschedule" -> { Scheduler.apply(ctx); "true" }
                "notify" -> { Notifier.show(ctx, JSONArray(arg)); "true" }
                "save_file" -> { saveFile(JSONObject(arg)); "true" }
                "share_file" -> { shareFile(ctx, JSONObject(arg)); "true" }
                "take_route" -> {
                    val route = pendingRoute
                    pendingRoute = ""
                    JSONObject().put("route", route).toString()
                }
                else -> "null"
            }
        } catch (e: Exception) {
            android.util.Log.w("vulnwatch", "bridge $what failed", e)
            "null"
        }
    }

    private fun notificationsAllowed(ctx: Context) = NotificationManagerCompat.from(ctx).areNotificationsEnabled()

    private fun state(ctx: Context): String {
        val power = ctx.getSystemService(Context.POWER_SERVICE) as PowerManager
        return JSONObject()
            .put("notifications", notificationsAllowed(ctx))
            .put("battery_exempt", power.isIgnoringBatteryOptimizations(ctx.packageName))
            .put("exact_alarms", Scheduler.exact(ctx))
            .toString()
    }

    private fun requestNotifications(ctx: Context) {
        val a = activity.get()
        val prefs = ctx.getSharedPreferences("vulnwatch", Context.MODE_PRIVATE)
        val canAsk = Build.VERSION.SDK_INT >= 33 &&
            ContextCompat.checkSelfPermission(ctx, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED &&
            prefs.getInt("asked_notifications", 0) < 2
        if (a != null && canAsk) {
            // Android stops showing the dialog after two refusals; after that, go to the settings page.
            prefs.edit().putInt("asked_notifications", prefs.getInt("asked_notifications", 0) + 1).apply()
            a.runOnUiThread {
                ActivityCompat.requestPermissions(a, arrayOf(Manifest.permission.POST_NOTIFICATIONS), 1)
            }
            return
        }
        open(ctx, Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS).putExtra(Settings.EXTRA_APP_PACKAGE, ctx.packageName))
    }

    private fun requestBattery(ctx: Context) {
        val direct = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, Uri.parse("package:${ctx.packageName}"))
        if (!open(ctx, direct)) open(ctx, Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS))
    }

    /** The "Alarms & reminders" switch for this app; without it Android moves the check alarm around. */
    private fun requestAlarms(ctx: Context) {
        val app = Uri.parse("package:${ctx.packageName}")
        if (Build.VERSION.SDK_INT >= 31 && open(ctx, Intent(Settings.ACTION_REQUEST_SCHEDULE_EXACT_ALARM, app))) return
        open(ctx, Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, app))
    }

    /** A name that is only a name, whatever was asked for. */
    private fun fileName(file: JSONObject) =
        file.optString("name").replace(Regex("[^A-Za-z0-9._-]"), "_").trim('.').ifEmpty { "vulnwatch.json" }

    /** Let the user pick where a file goes (the system's "save as"), then write it there. */
    private fun saveFile(file: JSONObject) {
        val a = activity.get() as? WryActivity ?: return
        val text = file.getString("text")
        val pick = Intent(Intent.ACTION_CREATE_DOCUMENT)
            .addCategory(Intent.CATEGORY_OPENABLE)
            .setType("application/json")
            .putExtra(Intent.EXTRA_TITLE, fileName(file))
        a.runOnUiThread {
            try {
                a.launchActivityForResult(pick) { result ->
                    val to = result?.data?.data
                    if (result?.resultCode == Activity.RESULT_OK && to != null) {
                        val ok = try {
                            a.contentResolver.openOutputStream(to, "wt")!!.use { it.write(text.toByteArray()) }
                            true
                        } catch (e: Exception) {
                            android.util.Log.w("vulnwatch", "could not write the export", e)
                            false
                        }
                        Toast.makeText(a, if (ok) "Saved" else "Could not save the file", Toast.LENGTH_SHORT).show()
                    }
                }
            } catch (e: Exception) {
                Toast.makeText(a, "No app on this phone can save files", Toast.LENGTH_LONG).show()
            }
        }
    }

    /** Hand a file to another app through the share sheet. It is written to the cache first. */
    private fun shareFile(ctx: Context, file: JSONObject) {
        val dir = File(ctx.cacheDir, "export")
        dir.deleteRecursively()
        dir.mkdirs()
        val out = File(dir, fileName(file))
        out.writeText(file.getString("text"))
        val uri = FileProvider.getUriForFile(ctx, "${ctx.packageName}.fileprovider", out)
        val send = Intent(Intent.ACTION_SEND)
            .setType("application/json")
            .putExtra(Intent.EXTRA_STREAM, uri)
            .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        send.clipData = ClipData.newRawUri(out.name, uri)
        open(ctx, Intent.createChooser(send, "Share").addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION))
    }

    private fun open(ctx: Context, intent: Intent): Boolean = try {
        val from = activity.get()
        if (from != null) from.startActivity(intent) else ctx.startActivity(intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        true
    } catch (e: Exception) {
        false
    }
}
