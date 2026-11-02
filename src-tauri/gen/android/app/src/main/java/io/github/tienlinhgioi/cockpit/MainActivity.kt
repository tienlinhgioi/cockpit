package io.github.tienlinhgioi.cockpit

import android.content.Context
import android.os.Bundle
import androidx.activity.enableEdgeToEdge

class MainActivity : TauriActivity() {
  override fun onCreate(savedInstanceState: Bundle?) {
    enableEdgeToEdge()
    super.onCreate(savedInstanceState)
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
