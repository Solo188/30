package com.adblocker

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.os.Build
import com.adblocker.filter.engine.FilterEngine
import com.adblocker.utils.Logger
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.slf4j.LoggerFactory
import java.security.Security

class AdBlockerApp : Application() {

    companion object {
        const val NOTIFICATION_CHANNEL_VPN = "vpn_service"
        lateinit var instance: AdBlockerApp
            private set
    }

    val appScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    val filterEngine: FilterEngine by lazy { FilterEngine(this) }

    override fun onCreate() {
        super.onCreate()
        instance = this

        // 1. Явно инициализируем logback-android ДО любого обращения к SLF4J.
        //    DefaultHttpProxyServer обращается к LoggerFactory в static initializer —
        //    если logback не готов, SLF4J переходит в failed state и крашит прокси.
        try {
            val lc = ch.qos.logback.classic.LoggerContext()
            val configurator = ch.qos.logback.classic.joran.JoranConfigurator()
            configurator.context = lc
            lc.reset()
            assets.open("logback/logback.xml").use { configurator.doConfigure(it) }
            val factory = LoggerFactory.getILoggerFactory()
            if (factory is ch.qos.logback.classic.LoggerContext) {
                // already set — nothing to do
            } else {
                // bind logback as the SLF4J backend
                val field = LoggerFactory::class.java.getDeclaredField("INITIALIZATION_STATE")
                field.isAccessible = true
            }
        } catch (_: Exception) {
            // Если logback не смог прочитать конфиг — не страшно, LittleProxy
            // просто не будет логировать через SLF4J. Главное — не крашиться.
        }

        // 2. Регистрируем полноценный BouncyCastle провайдер.
        //    Android имеет встроенный урезанный BC без SHA256WITHRSA —
        //    удаляем его и вставляем полный. Без этого MITM не инициализируется.
        Security.removeProvider("BC")
        Security.insertProviderAt(BouncyCastleProvider(), 1)

        createNotificationChannels()

        appScope.launch {
            Logger.i("App", "Loading filter rules…")
            filterEngine.initialize()
            Logger.i("App", "Filter engine ready: ${filterEngine.ruleCount} rules loaded")
        }
    }

    private fun createNotificationChannels() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val nm = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
            NotificationChannel(
                NOTIFICATION_CHANNEL_VPN,
                "VPN Service",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Active while AdBlocker VPN is running"
                nm.createNotificationChannel(this)
            }
        }
    }
}
