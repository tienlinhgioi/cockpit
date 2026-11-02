//! Android platform bridge.
//!
//! * Prepares the process environment (HOME / TMPDIR) so every `dirs::home_dir()` based
//!   path in the shared Rust code resolves inside the app-private sandbox.
//! * Calls the small Kotlin `CockpitBridge` object over JNI for the two things Rust cannot
//!   do itself: Android Keystore encryption and foreground-service control.
//!
//! On non-Android targets the same API exists but reports `Unsupported`, so shared code
//! can call it without `cfg` noise.

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AndroidPlatformStatus {
    pub is_android: bool,
    pub service_enabled: bool,
    pub notification_permission: bool,
    pub keystore_available: bool,
    pub files_dir: Option<String>,
}

#[cfg(target_os = "android")]
mod imp {
    use jni::objects::{JByteArray, JClass, JObject, JString, JValue};
    use jni::{JNIEnv, JavaVM};

    const BRIDGE_CLASS: &str = "io.github.tienlinhgioi.cockpit.CockpitBridge";

    fn describe_exception(env: &mut JNIEnv) -> Option<String> {
        if !env.exception_check().unwrap_or(false) {
            return None;
        }
        let throwable = env.exception_occurred().ok();
        let _ = env.exception_clear();
        let throwable = throwable?;
        let text = env
            .call_method(&throwable, "toString", "()Ljava/lang/String;", &[])
            .and_then(|v| v.l())
            .ok()?;
        let text: JString = text.into();
        env.get_string(&text).ok().map(|s| s.into())
    }

    /// Runs `f` on an attached JNI thread with the app context and the bridge class.
    pub fn with_bridge<T>(
        f: impl for<'a> FnOnce(&mut JNIEnv<'a>, &JObject<'a>, &JClass<'a>) -> Result<T, jni::errors::Error>,
    ) -> Result<T, String> {
        let ctx = ndk_context::android_context();
        if ctx.vm().is_null() || ctx.context().is_null() {
            return Err("Android context is not initialised yet".to_string());
        }
        let vm = unsafe { JavaVM::from_raw(ctx.vm().cast()) }.map_err(|e| e.to_string())?;
        let mut guard = vm
            .attach_current_thread()
            .map_err(|e| format!("JNI attach failed: {e}"))?;
        let env: &mut JNIEnv = &mut guard;
        let activity = unsafe { JObject::from_raw(ctx.context().cast()) };
        // Application classes are not visible through FindClass on native threads, so resolve
        // the bridge through the activity's class loader.
        let class = (|| -> Result<JClass, jni::errors::Error> {
            let loader = env
                .call_method(&activity, "getClassLoader", "()Ljava/lang/ClassLoader;", &[])?
                .l()?;
            let name = env.new_string(BRIDGE_CLASS)?;
            let class = env
                .call_method(
                    &loader,
                    "loadClass",
                    "(Ljava/lang/String;)Ljava/lang/Class;",
                    &[JValue::Object(&name)],
                )?
                .l()?;
            Ok(JClass::from(class))
        })();
        let class = match class {
            Ok(class) => class,
            Err(error) => {
                let detail = describe_exception(env).unwrap_or_else(|| error.to_string());
                return Err(format!("CockpitBridge unavailable: {detail}"));
            }
        };
        match f(env, &activity, &class) {
            Ok(value) => Ok(value),
            Err(error) => {
                let detail = describe_exception(env).unwrap_or_else(|| error.to_string());
                Err(detail)
            }
        }
    }

    pub fn keystore_call(method: &str, input: &[u8]) -> Result<Vec<u8>, String> {
        with_bridge(|env, _activity, class| {
            let arg = env.byte_array_from_slice(input)?;
            let out = env
                .call_static_method(
                    class,
                    method,
                    "([B)[B",
                    &[JValue::Object(&JObject::from(arg))],
                )?
                .l()?;
            env.convert_byte_array(JByteArray::from(out))
        })
    }

    pub fn set_service_enabled(enabled: bool, status: &str) -> Result<(), String> {
        with_bridge(|env, activity, class| {
            let status = env.new_string(status)?;
            env.call_static_method(
                class,
                "setServiceEnabled",
                "(Landroid/content/Context;ZLjava/lang/String;)V",
                &[
                    JValue::Object(activity),
                    JValue::Bool(enabled as u8),
                    JValue::Object(&status),
                ],
            )?;
            Ok(())
        })
    }

    pub fn update_service_status(status: &str) -> Result<(), String> {
        with_bridge(|env, activity, class| {
            let status = env.new_string(status)?;
            env.call_static_method(
                class,
                "updateServiceStatus",
                "(Landroid/content/Context;Ljava/lang/String;)V",
                &[JValue::Object(activity), JValue::Object(&status)],
            )?;
            Ok(())
        })
    }

    pub fn bool_call(method: &str) -> Result<bool, String> {
        with_bridge(|env, activity, class| {
            env.call_static_method(
                class,
                method,
                "(Landroid/content/Context;)Z",
                &[JValue::Object(activity)],
            )?
            .z()
        })
    }

    pub fn request_notification_permission() -> Result<(), String> {
        with_bridge(|env, activity, class| {
            env.call_static_method(
                class,
                "requestNotificationPermission",
                "(Landroid/app/Activity;)V",
                &[JValue::Object(activity)],
            )?;
            Ok(())
        })
    }

    pub fn files_dir() -> Result<String, String> {
        with_bridge(|env, activity, class| {
            let value = env
                .call_static_method(
                    class,
                    "filesDir",
                    "(Landroid/content/Context;)Ljava/lang/String;",
                    &[JValue::Object(activity)],
                )?
                .l()?;
            let value: JString = value.into();
            let text: String = env.get_string(&value)?.into();
            Ok(text)
        })
    }
}

/// Resolve the app-private files directory without JNI (used if the bridge is not ready).
#[cfg(target_os = "android")]
fn files_dir_from_proc() -> Option<String> {
    let raw = std::fs::read("/proc/self/cmdline").ok()?;
    let package = raw
        .split(|b| *b == 0)
        .next()
        .and_then(|b| std::str::from_utf8(b).ok())?
        .trim();
    if package.is_empty() || package.contains('/') || package.contains(':') {
        return None;
    }
    Some(format!("/data/data/{package}/files"))
}

/// Point HOME/TMPDIR at the app sandbox. Must run before any other thread reads the
/// environment, i.e. at the very top of `run()`.
pub fn init_environment() {
    #[cfg(target_os = "android")]
    {
        let files = imp::files_dir().ok().or_else(files_dir_from_proc);
        if let Some(files) = files {
            let files_path = std::path::PathBuf::from(&files);
            let _ = std::fs::create_dir_all(&files_path);
            let cache = files_path
                .parent()
                .map(|p| p.join("cache"))
                .unwrap_or_else(|| files_path.join("tmp"));
            let _ = std::fs::create_dir_all(&cache);
            std::env::set_var("HOME", &files);
            if std::env::var_os("TMPDIR").is_none() {
                std::env::set_var("TMPDIR", &cache);
            }
        }
    }
}

pub const UNSUPPORTED: &str = "Unsupported on this platform";

pub fn keystore_available() -> bool {
    #[cfg(target_os = "android")]
    {
        imp::keystore_call("keystoreEncrypt", b"probe")
            .and_then(|blob| imp::keystore_call("keystoreDecrypt", &blob))
            .map(|plain| plain == b"probe")
            .unwrap_or(false)
    }
    #[cfg(not(target_os = "android"))]
    {
        false
    }
}

/// Encrypt with the non-exportable Android Keystore master key (AES-256-GCM).
pub fn keystore_encrypt(plain: &[u8]) -> Result<Vec<u8>, String> {
    #[cfg(target_os = "android")]
    {
        imp::keystore_call("keystoreEncrypt", plain)
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = plain;
        Err(UNSUPPORTED.to_string())
    }
}

pub fn keystore_decrypt(blob: &[u8]) -> Result<Vec<u8>, String> {
    #[cfg(target_os = "android")]
    {
        imp::keystore_call("keystoreDecrypt", blob)
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = blob;
        Err(UNSUPPORTED.to_string())
    }
}

pub fn service_set_enabled(enabled: bool, status: &str) -> Result<(), String> {
    #[cfg(target_os = "android")]
    {
        imp::set_service_enabled(enabled, status)
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = (enabled, status);
        Err(UNSUPPORTED.to_string())
    }
}

pub fn service_update_status(status: &str) -> Result<(), String> {
    #[cfg(target_os = "android")]
    {
        imp::update_service_status(status)
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = status;
        Err(UNSUPPORTED.to_string())
    }
}

pub fn service_enabled() -> bool {
    #[cfg(target_os = "android")]
    {
        imp::bool_call("isServiceEnabled").unwrap_or(false)
    }
    #[cfg(not(target_os = "android"))]
    {
        false
    }
}

pub fn notification_permission_granted() -> bool {
    #[cfg(target_os = "android")]
    {
        imp::bool_call("hasNotificationPermission").unwrap_or(false)
    }
    #[cfg(not(target_os = "android"))]
    {
        false
    }
}

pub fn request_notification_permission() -> Result<(), String> {
    #[cfg(target_os = "android")]
    {
        imp::request_notification_permission()
    }
    #[cfg(not(target_os = "android"))]
    {
        Err(UNSUPPORTED.to_string())
    }
}

pub fn status() -> AndroidPlatformStatus {
    AndroidPlatformStatus {
        is_android: cfg!(target_os = "android"),
        service_enabled: service_enabled(),
        notification_permission: notification_permission_granted(),
        keystore_available: keystore_available(),
        files_dir: std::env::var("HOME").ok().filter(|_| cfg!(target_os = "android")),
    }
}
