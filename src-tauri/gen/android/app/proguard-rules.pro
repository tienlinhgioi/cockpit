# Add project specific ProGuard rules here.
# You can control the set of applied configuration files using the
# proguardFiles setting in build.gradle.
#
# For more details, see
#   http://developer.android.com/guide/developing/tools/proguard.html

# If your project uses WebView with JS, uncomment the following
# and specify the fully qualified class name to the JavaScript interface
# class:
#-keepclassmembers class fqcn.of.javascript.interface.for.webview {
#   public *;
#}

# Uncomment this to preserve the line number information for
# debugging stack traces.
#-keepattributes SourceFile,LineNumberTable

# If you keep the line number information, uncomment this to
# hide the original source file name.
#-renamesourcefileattribute SourceFile
# Called by name from Rust over JNI (src-tauri/src/modules/android_platform.rs): class and method
# names must survive R8 shrinking/obfuscation or Keystore + foreground service break at runtime.
-keep class io.github.tienlinhgioi.cockpit.CockpitBridge { *; }
-keep class io.github.tienlinhgioi.cockpit.GatewayService { *; }
