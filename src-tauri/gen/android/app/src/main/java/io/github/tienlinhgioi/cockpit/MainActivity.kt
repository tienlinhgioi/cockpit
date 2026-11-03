package io.github.tienlinhgioi.cockpit

import android.content.Context
import android.os.Bundle
import android.view.View
import androidx.activity.enableEdgeToEdge
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat

class MainActivity : TauriActivity() {
  override fun onCreate(savedInstanceState: Bundle?) {
    enableEdgeToEdge()
    super.onCreate(savedInstanceState)

    // targetSdk 36 forces edge-to-edge, so the WebView would draw under the status bar, the
    // gesture/navigation bar and the keyboard. Pad the content by those insets instead of
    // relying on CSS env(safe-area-inset-*), which older WebViews do not report.
    val content = findViewById<View>(android.R.id.content)
    ViewCompat.setOnApplyWindowInsetsListener(content) { view, insets ->
      val bars = insets.getInsets(
        WindowInsetsCompat.Type.systemBars() or
          WindowInsetsCompat.Type.displayCutout() or
          WindowInsetsCompat.Type.ime()
      )
      view.setPadding(bars.left, bars.top, bars.right, bars.bottom)
      WindowInsetsCompat.CONSUMED
    }

    // Restore the user's foreground-service choice when the app is reopened. The service is
    // only (re)started if the user explicitly enabled it earlier.
    if (CockpitBridge.isServiceEnabled(this)) {
      val status = getSharedPreferences(CockpitBridge.PREFS, Context.MODE_PRIVATE)
        .getString(CockpitBridge.PREF_STATUS, getString(R.string.service_default_status))
        ?: getString(R.string.service_default_status)
      CockpitBridge.setServiceEnabled(this, true, status)
    }
  }
}
