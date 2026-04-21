package com.adblocker.tun

import android.util.Log
import com.adblocker.tun.Packet.Companion.TCP_ACK
import com.adblocker.tun.Packet.Companion.TCP_FIN
import com.adblocker.tun.Packet.Companion.TCP_PSH
import com.adblocker.tun.Packet.Companion.TCP_RST
import com.adblocker.tun.Packet.Companion.TCP_SYN
import java.io.OutputStream
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicLong

/**
 * Уникальный ключ TCP-соединения.
 * (клиентский IP:port → серверный IP:port)
 */
data class TcpTuple(
    val srcIp: Int,    // packed 4 bytes → Int
    val srcPort: Int,
    val dstIp: Int,
    val dstPort: Int
) {
    companion object {
        fun from(p: Packet): TcpTuple {
            val si = p.srcIp
            val di = p.dstIp
            return TcpTuple(
                srcIp   = packIp(si),
                srcPort = p.tcpSrcPort,
                dstIp   = packIp(di),
                dstPort = p.tcpDstPort
            )
        }

        fun packIp(b: ByteArray): Int =
            ((b[0].toInt() and 0xFF) shl 24) or
            ((b[1].toInt() and 0xFF) shl 16) or
            ((b[2].toInt() and 0xFF) shl 8)  or
            (b[3].toInt() and 0xFF)

        fun unpackIp(v: Int): ByteArray = byteArrayOf(
            (v shr 24 and 0xFF).toByte(),
            (v shr 16 and 0xFF).toByte(),
            (v shr 8  and 0xFF).toByte(),
            (v        and 0xFF).toByte()
        )
    }

    fun srcIpBytes() = unpackIp(srcIp)
    fun dstIpBytes() = unpackIp(dstIp)
}

/**
 * Состояния TCP state machine (упрощённый RFC 793).
 */
enum class TcpState {
    LISTEN,       // ждём SYN
    SYN_RCVD,     // отправили SYN-ACK, ждём ACK
    ESTABLISHED,  // соединение установлено
    FIN_WAIT,     // мы послали FIN, ждём ACK от клиента
    CLOSE_WAIT,   // клиент прислал FIN, ждём пока мы закроем
    CLOSED        // соединение закрыто
}

/**
 * Transmission Control Block — состояние одного TCP соединения.
 *
 * Жизненный цикл:
 *   SYN от клиента → LISTEN → SYN_RCVD  (шлём SYN-ACK)
 *   ACK от клиента → ESTABLISHED         (открываем upstream socket)
 *   DATA от клиента → форвардим в upstream
 *   DATA от upstream → форвардим клиенту через tun
 *   FIN от клиента → CLOSE_WAIT → закрываем
 */
class TcpControlBlock(
    val tuple: TcpTuple,
    private val tunWriter: TunWriter
) {
    companion object {
        private const val TAG = "TCB"
        private const val WINDOW_SIZE = 65535
        private const val MAX_SEGMENT_SIZE = 1460
        // Максимальный размер очереди данных от upstream до отправки в tun
        private const val UPSTREAM_QUEUE_CAPACITY = 256
    }

    @Volatile var state: TcpState = TcpState.LISTEN

    // Наши (серверные) sequence числа — AtomicLong: handlePacket() и sendToClient()
    // вызываются из разных потоков (TcpStack-thread vs TcpTunnel-thread).
    private val _localSeq = AtomicLong(System.nanoTime() and 0xFFFFFFFFL)
    private val _localAck = AtomicLong(0L)

    var localSeq: Long
        get() = _localSeq.get()
        set(v) { _localSeq.set(v) }

    var localAck: Long
        get() = _localAck.get()
        set(v) { _localAck.set(v) }

    // Клиентские sequence числа
    var remoteSeq: Long = 0L

    // Upstream connection (к реальному серверу через прокси)
    var upstreamWriter: OutputStream? = null

    // Очередь данных от upstream → клиент (через tun)
    val upstreamQueue = LinkedBlockingQueue<ByteArray>(UPSTREAM_QUEUE_CAPACITY)

    @Volatile var closed = false
    val createdAt: Long = System.currentTimeMillis()

    // ── Обработка входящих пакетов от клиента ────────────────────────────────

    /**
     * Основной обработчик. Вызывается из PacketProcessor для каждого
     * TCP пакета принадлежащего этому соединению.
     * Возвращает список пакетов для записи обратно в tun fd.
     */
    fun handlePacket(p: Packet): List<ByteArray> {
        if (closed) return listOf(buildRst(p))

        // RST от клиента — немедленно закрываем
        if (p.tcpHasFlag(TCP_RST)) {
            close()
            return emptyList()
        }

        return when (state) {
            TcpState.LISTEN    -> handleListen(p)
            TcpState.SYN_RCVD  -> handleSynRcvd(p)
            TcpState.ESTABLISHED, TcpState.CLOSE_WAIT -> handleEstablished(p)
            TcpState.FIN_WAIT  -> handleFinWait(p)
            TcpState.CLOSED    -> listOf(buildRst(p))
        }
    }

    private fun handleListen(p: Packet): List<ByteArray> {
        if (!p.tcpHasFlag(TCP_SYN) || p.tcpHasFlag(TCP_ACK)) {
            return listOf(buildRst(p))
        }

        // Клиент прислал SYN — отвечаем SYN-ACK
        remoteSeq = p.tcpSeq
        localAck  = (remoteSeq + 1) and 0xFFFFFFFFL
        state     = TcpState.SYN_RCVD

        val synAck = buildResponse(
            flags = TCP_SYN or TCP_ACK,
            seq   = localSeq,
            ack   = localAck
        )
        localSeq = (localSeq + 1) and 0xFFFFFFFFL   // SYN занимает 1 sequence number

        Log.d(TAG, "SYN → SYN-ACK: ${tuple.srcPort}→${tuple.dstPort}")
        return listOf(synAck)
    }

    private fun handleSynRcvd(p: Packet): List<ByteArray> {
        if (!p.tcpHasFlag(TCP_ACK)) return emptyList()

        // Получили ACK на наш SYN-ACK → handshake завершён
        remoteSeq = p.tcpSeq
        state     = TcpState.ESTABLISHED

        Log.d(TAG, "ESTABLISHED: ${tuple.srcPort}→${tuple.dstPort}")

        // Сигнализируем TcpTunnel чтобы он открыл upstream соединение
        // (делается в TcpTunnel через наблюдение за state)
        return emptyList()
    }

    private fun handleEstablished(p: Packet): List<ByteArray> {
        val result = mutableListOf<ByteArray>()

        val payload = p.tcpPayload

        if (payload.isNotEmpty()) {
            remoteSeq = p.tcpSeq
            localAck  = (remoteSeq + payload.size) and 0xFFFFFFFFL

            // Форвардим данные в upstream (через TcpTunnel.upstreamWriter)
            try {
                upstreamWriter?.write(payload)
                upstreamWriter?.flush()
            } catch (e: Exception) {
                Log.w(TAG, "Upstream write failed: ${e.message}")
                close()
                result.add(buildRst(p))
                return result
            }

            // ACK клиенту
            result.add(buildResponse(flags = TCP_ACK, seq = localSeq, ack = localAck))
        }

        if (p.tcpHasFlag(TCP_FIN)) {
            localAck = (localAck + 1) and 0xFFFFFFFFL
            state    = TcpState.CLOSE_WAIT

            // ACK на FIN
            result.add(buildResponse(flags = TCP_ACK, seq = localSeq, ack = localAck))

            // Шлём наш FIN
            result.add(buildResponse(flags = TCP_FIN or TCP_ACK, seq = localSeq, ack = localAck))
            localSeq = (localSeq + 1) and 0xFFFFFFFFL

            close()
            Log.d(TAG, "FIN received, closing: ${tuple.srcPort}→${tuple.dstPort}")
        }

        return result
    }

    private fun handleFinWait(p: Packet): List<ByteArray> {
        if (p.tcpHasFlag(TCP_ACK) || p.tcpHasFlag(TCP_FIN)) {
            close()
        }
        return emptyList()
    }

    // ── Данные от upstream → клиент ───────────────────────────────────────────

    /**
     * Отправляет данные от upstream сервера клиенту через tun fd.
     * Вызывается из потока TcpTunnel.
     */
    fun sendToClient(data: ByteArray) {
        if (closed || state != TcpState.ESTABLISHED) return

        // Режем на сегменты по MSS
        var offset = 0
        while (offset < data.size) {
            val segLen = minOf(MAX_SEGMENT_SIZE, data.size - offset)
            val segment = data.copyOfRange(offset, offset + segLen)

            val flags = TCP_PSH or TCP_ACK
            val pkt = buildResponse(flags = flags, seq = localSeq, ack = localAck, payload = segment)

            tunWriter.write(pkt)
            localSeq = (localSeq + segLen) and 0xFFFFFFFFL
            offset += segLen
        }
    }

    /** Посылает FIN клиенту (upstream закрыл соединение) */
    fun sendFin() {
        if (closed) return
        val fin = buildResponse(flags = TCP_FIN or TCP_ACK, seq = localSeq, ack = localAck)
        tunWriter.write(fin)
        localSeq = (localSeq + 1) and 0xFFFFFFFFL
        state    = TcpState.FIN_WAIT
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private fun buildResponse(flags: Int, seq: Long, ack: Long, payload: ByteArray = ByteArray(0)): ByteArray {
        return Packet(ByteArray(0), 0).buildTcpResponse(
            srcIp   = tuple.dstIpBytes(),
            dstIp   = tuple.srcIpBytes(),
            srcPort = tuple.dstPort,
            dstPort = tuple.srcPort,
            seq     = seq,
            ack     = ack,
            flags   = flags,
            window  = WINDOW_SIZE,
            payload = payload
        )
    }

    private fun buildRst(p: Packet): ByteArray = p.buildRst()

    fun close() {
        closed = true
        state  = TcpState.CLOSED
        try { upstreamWriter?.close() } catch (_: Exception) {}
    }
}

/**
 * Интерфейс для записи пакетов обратно в tun fd.
 * Реализуется в TcpStack / PacketProcessor.
 */
interface TunWriter {
    fun write(packet: ByteArray)
}
