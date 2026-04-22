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

        // Регистрируем полноценный BouncyCastle провайдер.
        // Android имеет встроенный урезанный BC без SHA256WITHRSA —
        // удаляем его и вставляем полный. Без этого MITM не инициализируется.
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
