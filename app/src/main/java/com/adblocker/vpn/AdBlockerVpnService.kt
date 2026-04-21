package com.adblocker.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import com.adblocker.core.proxy.LocalProxyService
import com.adblocker.tun.TcpStack
import java.io.FileInputStream
import java.io.FileOutputStream
import java.util.concurrent.atomic.AtomicBoolean

class AdBlockerVpnService : VpnService() {

    companion object {
        private const val TAG = "AdBlockerVpnService"
        private const val NOTIFICATION_ID = 1
        private const val CHANNEL_ID = "AdBlockerVpn"

        private const val VPN_ADDRESS  = "10.0.0.2"
        private const val DNS_SERVER   = "8.8.8.8"
        private const val MTU          = 1500

        const val PROXY_PORT = 8118

        const val ACTION_START         = "com.adblocker.vpn.START"
        const val ACTION_STOP          = "com.adblocker.vpn.STOP"
        const val ACTION_STATE_CHANGED = "com.adblocker.VPN_STATE_CHANGED"
        const val EXTRA_STATE          = "vpn_state"

        @Volatile var isRunning: Boolean = false
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private val running = AtomicBoolean(false)
    private var vpnThread: Thread? = null
    private var tcpStack: TcpStack? = null
    private val domainFilter = DomainFilter()

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        return when (intent?.action) {
            ACTION_STOP -> { stopVpn(); START_NOT_STICKY }
            else        -> { startVpn(); START_STICKY }
        }
    }

    private fun startVpn() {
        if (running.get()) return

        createNotificationChannel()
        startForeground(NOTIFICATION_ID, buildNotification())

        // Fix #1 + #2: загружаем список доменов СИНХРОННО до старта VPN-интерфейса.
        // VPN-тоннель ещё не поднят → сетевой запрос DomainListUpdater не попадает в tun.
        DomainListUpdater().update(this, vpnService = null)
        domainFilter.loadFromFile(this)
        if (domainFilter.getBlacklistSize() == 0) {
            domainFilter.loadFromAssets(this)
        }
        Log.i(TAG, "Domain list loaded: ${domainFilter.getBlacklistSize()} entries")

        // 2. Поднимаем LittleProxy + MITM
        VpnProtector.set(this)   // Fix #6
        startService(Intent(this, LocalProxyService::class.java).apply {
            putExtra(LocalProxyService.EXTRA_PORT, PROXY_PORT)
        })

        // 3. Устанавливаем VPN интерфейс
        vpnInterface = establishVpnInterface() ?: run {
            Log.e(TAG, "Failed to establish VPN interface")
            stopSelf()
            return
        }

        running.set(true)
        isRunning = true
        broadcastState(VpnState.CONNECTED)

        // 4. Запускаем TcpStack — заменяет весь старый runVpnLoop/handleTcpPacket
        val pfd = vpnInterface!!
        val stack = TcpStack(
            tunIn        = FileInputStream(pfd.fileDescriptor),
            tunOut       = FileOutputStream(pfd.fileDescriptor),
            vpnService   = this,
            domainFilter = domainFilter,
            proxyHost    = "127.0.0.1",
            proxyPort    = PROXY_PORT,
            dnsServer    = DNS_SERVER
        )
        tcpStack = stack

        vpnThread = Thread({
            stack.start()
        }, "AdBlockerTcpStack").apply { start() }

        Log.i(TAG, "VPN started. TcpStack + LittleProxy MITM active on port $PROXY_PORT")
    }

    private fun establishVpnInterface(): ParcelFileDescriptor? {
        return try {
            Builder()
                .setSession("AdBlocker VPN")
                .addAddress(VPN_ADDRESS, 32)
                // IPv6 link-local address for the tun interface
                .addAddress("fd00:1:fd00:1:fd00:1:fd00:1", 128)
                // 0.0.0.0/1 + 128.0.0.0/1 покрывают весь IPv4.
                // 127.x.x.x НЕ включён — loopback идёт мимо tun.
                .addRoute("0.0.0.0", 1)
                .addRoute("128.0.0.0", 1)
                // Fix #16: IPv6 маршрут убран. TcpStack парсит только IPv4 (Packet.wrap
                // возвращает null для version != 4). Если захватывать IPv6 но не
                // обрабатывать — пакеты тихо дропаются и DNS/соединения через IPv6 рвутся.
                // Браузеры используют Happy Eyeballs: при отказе IPv6 сами переключаются
                // на IPv4, где наша фильтрация работает корректно.
                .addDnsServer(DNS_SERVER)
                .addDnsServer("1.1.1.1")
                .setMtu(MTU)
                .addDisallowedApplication(packageName)
                .establish()
        } catch (e: Exception) {
            Log.e(TAG, "Error establishing VPN interface", e)
            null
        }
    }

    private fun stopVpn() {
        if (!running.compareAndSet(true, false)) return

        isRunning      = false
        VpnProtector.set(null)   // Fix #6

        tcpStack?.stop()
        tcpStack = null

        stopService(Intent(this, LocalProxyService::class.java))

        vpnThread?.interrupt()
        vpnThread = null

        try { vpnInterface?.close() } catch (e: Exception) {
            Log.e(TAG, "Error closing VPN interface", e)
        }
        vpnInterface = null

        broadcastState(VpnState.STOPPED)
        stopForeground(true)
        stopSelf()
        Log.i(TAG, "VPN stopped")
    }

    private fun broadcastState(state: VpnState) {
        sendBroadcast(Intent(ACTION_STATE_CHANGED).apply {
            putExtra(EXTRA_STATE, state.name)
            setPackage(packageName)
        })
    }

    override fun onDestroy() { stopVpn(); super.onDestroy() }
    override fun onRevoke()  { stopVpn(); super.onRevoke() }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID, "AdBlocker VPN", NotificationManager.IMPORTANCE_LOW
            ).apply { description = "AdBlocker VPN is active" }
            getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        }
    }

    private fun buildNotification(): Notification {
        val stopIntent = PendingIntent.getService(
            this, 0,
            Intent(this, AdBlockerVpnService::class.java).apply { action = ACTION_STOP },
            PendingIntent.FLAG_IMMUTABLE
        )
        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
            Notification.Builder(this, CHANNEL_ID)
        else
            @Suppress("DEPRECATION") Notification.Builder(this)

        return builder
            .setContentTitle("AdBlocker VPN")
            .setContentText("TcpStack + MITM active")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .addAction(android.R.drawable.ic_delete, "Stop", stopIntent)
            .setOngoing(true)
            .build()
    }
}

/**
 * Fix #6: VpnService reference для protect() upstream-сокетов прокси.
 * Инкапсулирован в object вместо file-level @Volatile var.
 */
object VpnProtector {
    @Volatile private var service: android.net.VpnService? = null

    fun set(svc: android.net.VpnService?)  { service = svc }
    fun protect(socket: java.net.Socket)   { service?.protect(socket) }
    fun isActive(): Boolean                = service != null
}
