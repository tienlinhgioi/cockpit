package io.github.tienlinhgioi.cockpit

import android.Manifest
import android.app.Activity
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Static entry points called from Rust through JNI (see `android_platform.rs`).
 * Everything here is deliberately small and free of business logic:
 *  - Android Keystore wrapping of Cockpit's data-encryption key / API tokens;
 *  - foreground-service control for the local gateway + management API.
 */
object CockpitBridge {
    private const val KEY_ALIAS = "cockpit_master_key_v1"
    private const val GCM_TAG_BITS = 128
    private const val IV_LEN = 12
    const val PREFS = "cockpit_service"
    const val PREF_ENABLED = "foreground_service_enabled"
    const val PREF_STATUS = "foreground_service_status"

    // ---- Android Keystore (AES-256-GCM, non-exportable key) -------------------------------

    private fun masterKey(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (store.getKey(KEY_ALIAS, null) as? SecretKey)?.let { return it }
        fun generate(strongBox: Boolean): SecretKey {
            val builder = KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
            if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                builder.setIsStrongBoxBacked(true)
            }
            val generator =
                KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
            generator.init(builder.build())
            return generator.generateKey()
        }
        return try {
            generate(true)
        } catch (_: Exception) {
            generate(false)
        }
    }

    /** Returns `iv(12) || ciphertext||tag`. */
    @JvmStatic
    fun keystoreEncrypt(plain: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, masterKey())
        val iv = cipher.iv
        require(iv.size == IV_LEN) { "unexpected IV length ${iv.size}" }
        return iv + cipher.doFinal(plain)
    }

    @JvmStatic
    fun keystoreDecrypt(blob: ByteArray): ByteArray {
        require(blob.size > IV_LEN) { "ciphertext too short" }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.DECRYPT_MODE,
            masterKey(),
            GCMParameterSpec(GCM_TAG_BITS, blob.copyOfRange(0, IV_LEN))
        )
        return cipher.doFinal(blob.copyOfRange(IV_LEN, blob.size))
    }

    // ---- Foreground service -----------------------------------------------------------------

    @JvmStatic
    fun setServiceEnabled(context: Context, enabled: Boolean, status: String) {
        val app = context.applicationContext
        app.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putBoolean(PREF_ENABLED, enabled)
            .putString(PREF_STATUS, status)
            .apply()
        if (enabled) {
            val intent = Intent(app, GatewayService::class.java)
                .setAction(GatewayService.ACTION_START)
                .putExtra(GatewayService.EXTRA_STATUS, status)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                app.startForegroundService(intent)
            } else {
                app.startService(intent)
            }
        } else {
            app.stopService(Intent(app, GatewayService::class.java))
        }
    }

    @JvmStatic
    fun isServiceEnabled(context: Context): Boolean =
        context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getBoolean(PREF_ENABLED, false)

    @JvmStatic
    fun updateServiceStatus(context: Context, status: String) {
        val app = context.applicationContext
        app.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putString(PREF_STATUS, status).apply()
        if (isServiceEnabled(app)) {
            app.startService(
                Intent(app, GatewayService::class.java)
                    .setAction(GatewayService.ACTION_UPDATE)
                    .putExtra(GatewayService.EXTRA_STATUS, status)
            )
        }
    }

    // ---- Permissions -------------------------------------------------------------------------

    @JvmStatic
    fun hasNotificationPermission(context: Context): Boolean =
        Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU ||
            context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) ==
            PackageManager.PERMISSION_GRANTED

    @JvmStatic
    fun requestNotificationPermission(activity: Activity) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            !hasNotificationPermission(activity)
        ) {
            activity.runOnUiThread {
                activity.requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 4711)
            }
        }
    }

    @JvmStatic
    fun filesDir(context: Context): String = context.applicationContext.filesDir.absolutePath
}
