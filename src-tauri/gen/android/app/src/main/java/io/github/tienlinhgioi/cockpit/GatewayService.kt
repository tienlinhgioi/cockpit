package io.github.tienlinhgioi.cockpit

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder

/**
 * Foreground service that keeps the Cockpit process (and therefore the in-process Rust
 * API gateway and management API) at foreground-service priority while the user has
 * switched it on. It performs no work itself and is user-controlled: it can be stopped
 * from the notification or from the app. Android may still stop it (battery policy,
 * Android 15 timeouts, OEM task killers) so 24/7 operation is NOT guaranteed.
 */
class GatewayService : Service() {
    companion object {
        const val ACTION_START = "io.github.tienlinhgioi.cockpit.START"
        const val ACTION_UPDATE = "io.github.tienlinhgioi.cockpit.UPDATE"
        const val ACTION_STOP = "io.github.tienlinhgioi.cockpit.STOP"
        const val EXTRA_STATUS = "status"
        private const val CHANNEL_ID = "cockpit_gateway"
        private const val NOTIFICATION_ID = 7101
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                getString(R.string.service_channel_name),
                NotificationManager.IMPORTANCE_LOW
            )
            channel.description = getString(R.string.service_channel_description)
            getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            getSharedPreferences(CockpitBridge.PREFS, Context.MODE_PRIVATE).edit()
                .putBoolean(CockpitBridge.PREF_ENABLED, false).apply()
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return START_NOT_STICKY
        }
        val prefs = getSharedPreferences(CockpitBridge.PREFS, Context.MODE_PRIVATE)
        // A null intent means Android restarted a sticky service: only honour it if the user
        // still has the service enabled.
        if (intent == null && !prefs.getBoolean(CockpitBridge.PREF_ENABLED, false)) {
            stopSelf()
            return START_NOT_STICKY
        }
        val status = intent?.getStringExtra(EXTRA_STATUS)
            ?: prefs.getString(CockpitBridge.PREF_STATUS, null)
            ?: getString(R.string.service_default_status)
        val notification = buildNotification(status)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
        return START_STICKY
    }

    private fun buildNotification(status: String): Notification {
        val openApp = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val stop = PendingIntent.getService(
            this,
            1,
            Intent(this, GatewayService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION") Notification.Builder(this)
        }
        return builder
            .setSmallIcon(android.R.drawable.stat_notify_sync_noanim)
            .setContentTitle(getString(R.string.service_notification_title))
            .setContentText(status)
            .setStyle(Notification.BigTextStyle().bigText(status))
            .setContentIntent(openApp)
            .addAction(
                Notification.Action.Builder(
                    null,
                    getString(R.string.service_action_stop),
                    stop
                ).build()
            )
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .build()
    }
}
