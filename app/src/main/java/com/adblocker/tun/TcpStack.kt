package com.adblocker.tun

import android.net.VpnService
import android.util.Log
import com.adblocker.vpn.DnsPacketParser
import com.adblocker.vpn.DomainFilter
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * TcpStack — главный диспетчер пакетов.
 *
 * Читает сырые IP пакеты из tun fd и:
 *   - UDP:53  → DNS фильтрация (оригинальная логика)
 *   - UDP:443 → дроп (QUIC)
 *   - TCP:80  → HTTP proxy через LittleProxy
 *   - TCP:443 → HTTPS proxy через LittleProxy (MITM)
 *   - TCP прочее → pass-through (дроп из tun, идёт напрямую)
 *
 * Управляет таблицей TcpControlBlock (один на TCP-соединение).
 * Запускает TcpTunnel для каждого нового ESTABLISHED соединения.
 *
 * Заменяет: runVpnLoop() + processIpPacket() + handleTcpPacket() из AdBlockerVpnService.
 */
class TcpStack(
    private val tunIn: FileInputStream,
    private val tunOut: FileOutputStream,
    private val vpnService: VpnService,
    private val domainFilter: DomainFilter,
    private val proxyHost: String = "127.0.0.1",
    private val proxyPort: Int    = 8118,
    private val dnsServer: String = "8.8.8.8",
    private val dnsPort:   Int    = 53
) : TunWriter {

    companion object {
        private const val TAG = "TcpStack"
        private const val MTU = 1500
        // Интервал очистки мёртвых TCB (мс)
        private const val CLEANUP_INTERVAL_MS = 30_000L
        // Fix #9: снизили с 120s до 30s. 120s держат мёртвые соединения слишком долго;
        // на стриминге и активном браузинге tcbTable быстро заполнялась до лимита 1024.
        private const val TCB_TIMEOUT_MS = 30_000L
    }

    private val running = AtomicBoolean(false)
    private val tcbTable = ConcurrentHashMap<TcpTuple, TcpControlBlock>(256)
    private val tunnelTable = ConcurrentHashMap<TcpTuple, TcpTunnel>(256)
    private val tunLock = Any()

    // Fix #3: executor принадлежит TcpStack, shutdownNow() в stop()
    private val tunnelExecutor = Executors.newCachedThreadPool { r ->
        Thread(r, "TcpTunnel-upstream").apply { isDaemon = true }
    }

    // DNS кэш с TTL
    private val dnsCache = LinkedHashMap<String, DnsCacheEntry>(512, 0.75f, true)

    data class DnsCacheEntry(val response: ByteArray, val expiresAt: Long) {
        fun isExpired() = System.currentTimeMillis() > expiresAt
    }

    private val cleanupExecutor = Executors.newSingleThreadScheduledExecutor { r ->
        Thread(r, "TcpStack-cleanup").apply { isDaemon = true }
    }

    // ── Start / Stop ─────────────────────────────────────────────────────────

    fun start() {
        running.set(true)

        cleanupExecutor.scheduleAtFixedRate(
            ::cleanupDeadConnections,
            CLEANUP_INTERVAL_MS, CLEANUP_INTERVAL_MS, TimeUnit.MILLISECONDS
        )

        // Основной цикл в calling thread (вызывающий должен передать свой поток)
        runLoop()
    }

    fun stop() {
        running.set(false)
        cleanupExecutor.shutdownNow()
        tunnelExecutor.shutdownNow()   // Fix #3: убиваем все upstream-потоки

        // Закрываем все туннели
        tunnelTable.values.forEach { it.close() }
        tcbTable.values.forEach { it.close() }
        tunnelTable.clear()
        tcbTable.clear()
    }

    private fun runLoop() {
        val buf = ByteArray(MTU)
        Log.i(TAG, "TcpStack loop started (proxy=$proxyHost:$proxyPort)")

        while (running.get()) {
            try {
                val len = tunIn.read(buf)
                if (len <= 0) continue

                val packet = Packet.wrap(buf.copyOf(len), len) ?: continue
                dispatch(packet)

            } catch (e: InterruptedException) {
                Thread.currentThread().interrupt()
                break
            } catch (e: Exception) {
                if (running.get()) Log.e(TAG, "Packet processing error", e)
            }
        }

        Log.i(TAG, "TcpStack loop stopped")
    }

    // ── Dispatcher ───────────────────────────────────────────────────────────

    private fun dispatch(p: Packet) {
        when {
            p.isUdp && p.udpDstPort == 443 -> {
                // Дропаем QUIC — форсируем TCP/HTTPS
            }
            p.isUdp && p.udpDstPort == dnsPort -> {
                handleDns(p)
            }
            p.isTcp && (p.tcpDstPort == 80 || p.tcpDstPort == 443) -> {
                handleTcp(p)
            }
            p.isTcp -> {
                // TCP на другие порты — пропускаем без изменений
                // (ядро обработает само, пакет просто читается из tun и не возвращается)
            }
            // Всё прочее игнорируем
        }
    }

    // ── TCP обработка ────────────────────────────────────────────────────────

    private fun handleTcp(p: Packet) {
        val tuple = TcpTuple.from(p)

        // SYN без ACK → новое соединение
        if (p.tcpHasFlag(Packet.TCP_SYN) && !p.tcpHasFlag(Packet.TCP_ACK)) {
            handleNewConnection(p, tuple)
            return
        }

        // Ищем существующий TCB
        val tcb = tcbTable[tuple]
        if (tcb == null) {
            // Нет TCB для этого соединения — шлём RST
            write(p.buildRst())
            return
        }

        // Передаём пакет в TCB
        val responses = tcb.handlePacket(p)
        responses.forEach { write(it) }

        // Если TCB только что стал ESTABLISHED → открываем tunnel
        if (tcb.state == TcpState.ESTABLISHED && !tunnelTable.containsKey(tuple)) {
            openTunnel(tcb, p)
        }

        // Чистим закрытые TCB
        if (tcb.closed) {
            tcbTable.remove(tuple)
            tunnelTable.remove(tuple)?.close()
        }
    }

    private fun handleNewConnection(p: Packet, tuple: TcpTuple) {
        // Ограничиваем количество одновременных соединений
        if (tcbTable.size > 1024) {
            Log.w(TAG, "TCB table full, dropping SYN")
            write(p.buildRst())
            return
        }

        val tcb = TcpControlBlock(tuple, this)
        tcbTable[tuple] = tcb

        val responses = tcb.handlePacket(p)
        responses.forEach { write(it) }
    }

    private fun openTunnel(tcb: TcpControlBlock, lastPacket: Packet) {
        // Определяем оригинальный хост:порт
        // Для HTTPS (443) — хост будет получен из SNI в TLS ClientHello внутри LittleProxy
        // Для HTTP (80)  — из Host: заголовка
        // Нам нужно передать реальный dst IP:port в CONNECT запросе,
        // LittleProxy сам разберётся с SNI
        val dstIp   = TcpTuple.unpackIp(tcb.tuple.dstIp)
        val dstHost = InetAddress.getByAddress(dstIp).hostAddress ?: dstIp.joinToString(".")
        val dstPort = tcb.tuple.dstPort

        val tunnel = TcpTunnel(
            tcb             = tcb,
            proxyHost       = proxyHost,
            proxyPort       = proxyPort,
            vpnService      = vpnService,
            originalDstHost = dstHost,
            originalDstPort = dstPort,
            executor        = tunnelExecutor   // Fix #3
        )
        tunnelTable[tcb.tuple] = tunnel
        tunnel.connect()

        Log.d(TAG, "Tunnel created: ${tcb.tuple.srcPort} → $dstHost:$dstPort")
    }

    // ── DNS обработка ────────────────────────────────────────────────────────

    private fun handleDns(p: Packet) {
        val payload = p.udpPayload
        if (payload.isEmpty()) return

        val domainRaw = DnsPacketParser.extractDomain(payload) ?: return
        val domain    = domainRaw.lowercase()

        // Проверяем кэш
        val cached = synchronized(dnsCache) { dnsCache[domain] }
        if (cached != null && !cached.isExpired()) {
            val response = buildUdpResponse(p, cached.response)
            write(response)
            return
        }

        // Проверяем блэклист
        if (domainFilter.isBlocked(domain)) {
            Log.i(TAG, "DNS BLOCKED: $domain")
            val blocked = DnsPacketParser.buildBlockedResponse(payload)
            write(buildUdpResponse(p, blocked))
            return
        }

        // Форвардим реальный DNS запрос
        forwardDns(p, payload, domain)
    }

    private fun forwardDns(p: Packet, payload: ByteArray, domain: String) {
        val servers = listOf(dnsServer, "1.1.1.1")   // Fix #15: fallback DNS
        for (server in servers) {
            try {
                val sock = DatagramSocket()
                vpnService.protect(sock)

                sock.use { s ->
                    s.soTimeout = 3000
                    val addr = InetAddress.getByName(server)
                    s.send(DatagramPacket(payload, payload.size, addr, dnsPort))

                    val buf  = ByteArray(512)
                    val recv = DatagramPacket(buf, buf.size)
                    s.receive(recv)

                    val response = buf.copyOf(recv.length)

                    // Кэшируем с TTL 60 секунд
                    synchronized(dnsCache) {
                        if (dnsCache.size > 1000) {
                            dnsCache.keys.firstOrNull()?.let { dnsCache.remove(it) }
                        }
                        dnsCache[domain] = DnsCacheEntry(response, System.currentTimeMillis() + 60_000)
                    }

                    write(buildUdpResponse(p, response))
                }
                return  // успешно — выходим
            } catch (e: java.net.SocketTimeoutException) {
                Log.w(TAG, "DNS timeout from $server for $domain, trying next")
            } catch (e: Exception) {
                Log.e(TAG, "DNS forward error ($server) for $domain: ${e.message}")
                break
            }
        }
        // Fix #15: все серверы не ответили — шлём SERVFAIL клиенту вместо тишины
        val servFail = DnsPacketParser.buildServFail(payload)
        write(buildUdpResponse(p, servFail))
    }

    private fun buildUdpResponse(originalPacket: Packet, dnsResponse: ByteArray): ByteArray {
        return PacketUtils.buildUdpPacket(
            srcIp   = originalPacket.dstIp,
            dstIp   = originalPacket.srcIp,
            srcPort = dnsPort,
            dstPort = originalPacket.udpSrcPort,
            payload = dnsResponse
        )
    }

    // ── TunWriter ─────────────────────────────────────────────────────────────

    /**
     * Thread-safe запись пакета обратно в tun fd.
     * Синхронизируем: несколько TcpTunnel потоков могут писать одновременно.
     */
    override fun write(packet: ByteArray) {
        if (!running.get()) return
        try {
            synchronized(tunLock) {
                tunOut.write(packet)
            }
        } catch (e: Exception) {
            if (running.get()) Log.e(TAG, "tun write error: ${e.message}")
        }
    }

    // ── Cleanup ───────────────────────────────────────────────────────────────

    private fun cleanupDeadConnections() {
        val now = System.currentTimeMillis()
        val deadTuples = mutableListOf<TcpTuple>()

        tcbTable.forEach { (tuple, tcb) ->
            val timedOut = (now - tcb.createdAt) > TCB_TIMEOUT_MS && tcb.state == TcpState.ESTABLISHED
            if (tcb.closed || timedOut) {
                deadTuples.add(tuple)
                tcb.close()
            }
        }

        deadTuples.forEach { tuple ->
            tcbTable.remove(tuple)
            tunnelTable.remove(tuple)?.close()
        }

        if (deadTuples.isNotEmpty()) {
            Log.d(TAG, "Cleanup: removed ${deadTuples.size} dead connections, active: ${tcbTable.size}")
        }
    }
}
