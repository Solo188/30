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

/**
 * Application entry point.
 *
 * Responsibilities:
 *  - Create notification channels (required on API 26+)
 *  - Initialise the FilterEngine asynchronously so the UI is responsive immediately
 *
 * The FilterEngine is a singleton shared by both the filter pipeline
 * (LittleProxy / HttpFilters) and the UI stats display.
 */
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
        createNotificationChannels()

        // Load EasyList rules in the background; does not block startup.
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
