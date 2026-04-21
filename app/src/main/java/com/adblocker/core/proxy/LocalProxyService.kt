package com.adblocker.core.proxy

import android.app.Service
import android.content.Intent
import android.os.IBinder
import com.adblocker.AdBlockerApp
import com.adblocker.utils.Logger
import com.adblocker.vpn.VpnProtector
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import java.net.Socket

/**
 * core.proxy — LocalProxyService
 *
 * Запускает LittleProxy + MITM. Живёт пока работает VPN.
 *
 * Ключевое отличие от оригинала: передаём socketProtector в LittleProxyServer,
 * чтобы upstream-сокеты прокси не шли обратно через VPN tun (бесконечная петля).
 */
class LocalProxyService : Service() {

    companion object {
        const val EXTRA_PORT = "proxy_port"
        private const val DEFAULT_PORT = 8118
        private const val TAG = "ProxyService"

        @Volatile var boundPort: Int = 0
    }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var proxyServer: LittleProxyServer? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val port = intent?.getIntExtra(EXTRA_PORT, DEFAULT_PORT) ?: DEFAULT_PORT
        boundPort = port
        startProxy(port)
        return START_NOT_STICKY
    }

    private fun startProxy(port: Int) {
        scope.launch {
            try {
                val app = application as AdBlockerApp

                // Fix #5: ждём полной инициализации FilterEngine (EasyList загружается
                // асинхронно в AdBlockerApp). Без этого ожидания первые запросы после
                // старта VPN уходят без фильтрации — правила ещё не загружены.
                if (!app.filterEngine.isReady) {
                    Logger.i(TAG, "Waiting for FilterEngine to initialize...")
                    app.filterEngine.awaitReady()
                    Logger.i(TAG, "FilterEngine ready — starting proxy")
                }

                // socketProtector: вызывается LittleProxy для каждого upstream-сокета.
                // Без этого upstream TCP-пакеты снова попадают в VPN tun → петля.
                val protector: (Socket) -> Unit = { socket ->
                    if (VpnProtector.isActive()) {
                        VpnProtector.protect(socket)
                    } else {
                        Logger.w(TAG, "VpnProtector not active — upstream socket not protected!")
                    }
                }

                val server = LittleProxyServer(
                    context         = applicationContext,
                    port            = port,
                    filterEngine    = app.filterEngine,
                    socketProtector = protector
                )
                proxyServer = server
                server.start()

                Logger.i(TAG, "LittleProxy started on port $port")
                Logger.i(TAG,
                    "Root CA PEM: ${server.getCaPemFile().absolutePath}\n" +
                    "  → Install via: Settings → Security → CA Certificate"
                )

            } catch (e: Exception) {
                Logger.e(TAG, "Proxy startup failed — stopping service", e)
                stopSelf()
            }
        }
    }

    override fun onDestroy() {
        scope.launch {
            proxyServer?.stop()
            Logger.i(TAG, "LittleProxy stopped")
        }
        scope.cancel()
        super.onDestroy()
    }
}
