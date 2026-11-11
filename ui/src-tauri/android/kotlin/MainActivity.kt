package app.vulnwatch

import android.content.Intent
import android.content.res.Configuration
import android.graphics.Color
import android.os.Bundle
import android.view.View
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat

class MainActivity : TauriActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        // Open the database before the webview starts asking for data.
        Native.attach(this)
        takeRoute(intent)
        super.onCreate(savedInstanceState)
        fitSystemBars()
        try {
            Scheduler.apply(this)
        } catch (e: Exception) {
            android.util.Log.w("vulnwatch", "could not schedule background checks", e)
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        takeRoute(intent)
    }

    /** A tapped notification says which page to show; the UI picks it up when it becomes visible. */
    private fun takeRoute(intent: Intent?) {
        val route = intent?.getStringExtra("route") ?: return
        Native.pendingRoute = route
        intent.removeExtra("route")
    }

    /** Keep the page clear of the status bar, navigation bar and keyboard (Android 15+ draws edge to edge). */
    private fun fitSystemBars() {
        val night = (resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK) == Configuration.UI_MODE_NIGHT_YES
        window.decorView.setBackgroundColor(Color.parseColor(if (night) "#0e1116" else "#f6f7f9"))
        val content = findViewById<View>(android.R.id.content)
        WindowCompat.getInsetsController(window, content).apply {
            isAppearanceLightStatusBars = !night
            isAppearanceLightNavigationBars = !night
        }
        ViewCompat.setOnApplyWindowInsetsListener(content) { view, insets ->
            val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout() or WindowInsetsCompat.Type.ime())
            view.setPadding(bars.left, bars.top, bars.right, bars.bottom)
            WindowInsetsCompat.CONSUMED
        }
    }
}
