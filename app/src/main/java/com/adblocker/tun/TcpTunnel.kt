package com.adblocker.tun

import android.net.VpnService
import android.util.Log
import java.io.ByteArrayOutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.ExecutorService

/**
 * TcpTunnel
 *
 * Связывает один TcpControlBlock с реальным upstream сервером
 * через HTTP proxy (LittleProxy на 127.0.0.1:PROXY_PORT).
 *
 * Fix #3: executor больше не статический — передаётся из TcpStack,
 *         который владеет его жизненным циклом и вызывает shutdownNow() при stop().
 *
 * Fix #4: readHttpResponseStatusLine — читаем байтами, без BufferedReader.
 */
class TcpTunnel(
    private val tcb: TcpControlBlock,
    private val proxyHost: String,
    private val proxyPort: Int,
    private val vpnService: VpnService?,
    private val originalDstHost: String,
    private val originalDstPort: Int,
    private val executor: ExecutorService          // Fix #3: инжектируется из TcpStack
) {
    companion object {
        private const val TAG = "TcpTunnel"
        private const val CONNECT_TIMEOUT_MS = 5_000
        private const val READ_BUFFER_SIZE   = 32_768
    }

    @Volatile private var socket: Socket? = null
    @Volatile private var started = false

    fun connect() {
        if (started) return
        started = true

        executor.submit {
            try {
                openUpstream()
            } catch (e: Exception) {
                Log.w(TAG, "Upstream connect failed for $originalDstHost:$originalDstPort: ${e.message}")
                tcb.close()
            }
        }
    }

    private fun openUpstream() {
        val sock = Socket()
        vpnService?.protect(sock)

        sock.connect(InetSocketAddress(proxyHost, proxyPort), CONNECT_TIMEOUT_MS)
        sock.soTimeout = 0
        sock.tcpNoDelay = true

        val connectRequest = "CONNECT $originalDstHost:$originalDstPort HTTP/1.1\r\n" +
                             "Host: $originalDstHost:$originalDstPort\r\n" +
                             "Proxy-Connection: keep-alive\r\n\r\n"

        sock.outputStream.write(connectRequest.toByteArray(Charsets.US_ASCII))
        sock.outputStream.flush()

        // Fix #4: читаем статус-строку и дочитываем заголовки до пустой строки
        val statusLine = readHttpResponseStatusLine(sock)
        if (!statusLine.startsWith("HTTP/1.1 200") && !statusLine.startsWith("HTTP/1.0 200")) {
            Log.w(TAG, "Proxy CONNECT rejected: [$statusLine] for $originalDstHost:$originalDstPort")
            sock.close()
            tcb.sendFin()
            return
        }

        socket = sock
        tcb.upstreamWriter = sock.outputStream

        Log.d(TAG, "Tunnel open: ${tcb.tuple.srcPort} -> $originalDstHost:$originalDstPort")
        readUpstream(sock)
    }

    /**
     * Fix #4: читаем HTTP CONNECT response побайтово без BufferedReader.
     * BufferedReader буферизирует до 8 KB из сокета — первые байты тела
     * ответа уходят в его внутренний буфер и теряются для readUpstream().
     */
    private fun readHttpResponseStatusLine(sock: Socket): String {
        val input = sock.inputStream
        val headerBuf = ByteArrayOutputStream(512)
        var b0 = -1; var b1 = -1; var b2 = -1
        while (true) {
            val b = input.read()
            if (b == -1) break
            headerBuf.write(b)
            // Detect 
                        // Detect end of HTTP headers (\r\n\r\n)
            if (b0 == '\r'.code && b1 == '\n'.code && b2 == '\r'.code && b == '\n'.code) {
                break
            }
            
            b0 = b1
            b1 = b2
            b2 = b
        }
        return headerBuf.toString(Charsets.US_ASCII.name()).lines().firstOrNull() ?: ""
    }

 
            

    private fun readUpstream(sock: Socket) {
        val buf = ByteArray(READ_BUFFER_SIZE)
        val stream = sock.inputStream

        try {
            while (!tcb.closed) {
                val n = stream.read(buf)
                if (n == -1) {
                    Log.d(TAG, "Upstream EOF: $originalDstHost:$originalDstPort")
                    if (!tcb.closed) tcb.sendFin()
                    break
                }
                if (n > 0) {
                    tcb.sendToClient(buf.copyOf(n))
                }
            }
        } catch (e: Exception) {
            if (!tcb.closed) {
                Log.d(TAG, "Upstream read error ($originalDstHost:$originalDstPort): ${e.message}")
                tcb.sendFin()
            }
        } finally {
            tcb.close()
            try { sock.close() } catch (_: Exception) {}
        }
    }

    fun close() {
        try { socket?.close() } catch (_: Exception) {}
    }
}
