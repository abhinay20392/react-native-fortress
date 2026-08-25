# Keep Turbo Module spec and Fortress native entry points.
-keep class com.fortress.FortressModule { *; }
-keep class com.fortress.FortressPackage { *; }
-keep class com.fortress.NativeFortressSpec { *; }

# Keep detection logic invoked via reflection-free paths from the module.
-keep class com.fortress.root.** { *; }
-keep class com.fortress.tamper.** { *; }
-keep class com.fortress.ssl.** { *; }
-keep class com.fortress.repackaging.** { *; }
-keep class com.fortress.emulator.** { *; }
-keep class com.fortress.ui.** { *; }

# OkHttp CertificatePinner uses string pins configured at runtime.
-keepclassmembers class okhttp3.CertificatePinner$Builder {
    public okhttp3.CertificatePinner$Builder add(java.lang.String, java.lang.String[]);
}

# React Native bridge
-keep @com.facebook.proguard.annotations.DoNotStrip class * { *; }
-keep @com.facebook.proguard.annotations.DoNotStrip interface * { *; }
-keepclassmembers class * {
    @com.facebook.react.bridge.ReactMethod <methods>;
}
