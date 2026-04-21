# BouncyCastle
-keep class org.bouncycastle.** { *; }
-dontwarn org.bouncycastle.**

# Netty
-keep class io.netty.** { *; }
-dontwarn io.netty.**

# LittleProxy
-keep class org.littleshoot.** { *; }
-dontwarn org.littleshoot.**

# OkHttp
-keep class okhttp3.** { *; }
-dontwarn okhttp3.**
-keep class okio.** { *; }
-dontwarn okio.**

# Guava
-dontwarn com.google.common.**
-keep class com.google.common.** { *; }

# SLF4J
-keep class org.slf4j.** { *; }
-dontwarn org.slf4j.**

# Logback
-keep class ch.qos.logback.** { *; }
-dontwarn ch.qos.logback.**

# Room
-keep class * extends androidx.room.RoomDatabase
-keep @androidx.room.Entity class *
-keep @androidx.room.Dao interface *

# Our core classes — never obfuscate
-keep class com.adblocker.** { *; }
