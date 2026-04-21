package com.adblocker.core.proxy

import android.content.Context
import com.adblocker.filter.engine.FilterEngine
import com.adblocker.utils.Logger
import io.netty.channel.ChannelHandlerContext
import io.netty.handler.codec.http.HttpRequest
import org.littleshoot.proxy.HttpFilters
import org.littleshoot.proxy.HttpFiltersSourceAdapter
import org.littleshoot.proxy.impl.DefaultHttpProxyServer
import org.littleshoot.proxy.mitm.Authority
import org.littleshoot.proxy.mitm.CertificateSniffingMitmManager
import java.io.File
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import javax.net.SocketFactory

class LittleProxyServer(
    private val context: Context,
    private val port: Int,
    private val filterEngine: FilterEngine,
    private val socketProtector: ((Socket) -> Unit)? = null
) {
    companion object {
        private const val TAG = "LittleProxyServer"
        private const val RESPONSE_BUFFER_BYTES = 2 * 1024 * 1024
        private const val REQUEST_BUFFER_BYTES  = 1 * 1024 * 1024
    }

    @Volatile private var proxyServer: org.littleshoot.proxy.HttpProxyServer? = null
    @Volatile private var prevSocketFactory: SocketFactory? = null

    private fun buildAuthority(): Authority = Authority(
        context.filesDir, "adblocker-ca", "AdBlockerCA_2024!".toCharArray(),
        "AdBlocker Root CA", "AdBlocker", "Certificate Authority",
        "AdBlocker MITM", "AdBlocker TLS Interception"
    )

    fun start() {
        Logger.i(TAG, "Starting LittleProxy on port $port")

        // Устанавливаем глобальный SocketFactory который автоматически вызывает
        // VpnService.protect() для каждого upstream сокета создаваемого LittleProxy.
        // Это единственный способ защитить upstream без патча исходников LittleProxy 1.1.2.
        if (socketProtector != null) {
            UpstreamSocketProtectorHook.protector = socketProtector
            installProtectedSocketFactory(socketProtector)
        }

        val authority = buildAuthority()

        val mitmManager = try {
            CertificateSniffingMitmManager(authority).also {
                Logger.i(TAG, "Root CA: ${authority.aliasFile(".pem").absolutePath}")
            }
        } catch (e: Exception) {
            Logger.e(TAG, "MITM init failed — HTTPS interception disabled", e)
            null
        }

        val filtersSource = object : HttpFiltersSourceAdapter() {
            override fun filterRequest(req: HttpRequest, ctx: ChannelHandlerContext): HttpFilters =
                AdBlockerHttpFilters(req, ctx, filterEngine)
            override fun getMaximumRequestBufferSizeInBytes(): Int  = REQUEST_BUFFER_BYTES
            override fun getMaximumResponseBufferSizeInBytes(): Int = RESPONSE_BUFFER_BYTES
        }

        val bootstrap = DefaultHttpProxyServer.bootstrap()
            .withAddress(InetSocketAddress("127.0.0.1", port))
            .withFiltersSource(filtersSource)
            .withProxyAlias("AdBlocker")
            .withAllowLocalOnly(true)

        if (mitmManager != null) {
            bootstrap.withManInTheMiddle(mitmManager)
            Logger.i(TAG, "MITM enabled")
        }

        proxyServer = bootstrap.start()
        Logger.i(TAG, "LittleProxy listening on 127.0.0.1:$port")
    }

    fun stop() {
        UpstreamSocketProtectorHook.protector = null
        restorePreviousSocketFactory()
        proxyServer?.stop()
        proxyServer = null
        Logger.i(TAG, "LittleProxy stopped")
    }

    fun getCaPemFile(): File = buildAuthority().aliasFile(".pem")

    /**
     * Устанавливает глобальный javax.net.SocketFactory который вызывает
     * VpnService.protect() на каждом новом сокете.
     * LittleProxy и Netty используют javax.net.Socket напрямую для upstream —
     * кастомная фабрика перехватывает эти вызовы.
     */
    private fun installProtectedSocketFactory(protector: (Socket) -> Unit) {
        try {
            prevSocketFactory = SocketFactory.getDefault()
            val protectedFactory = object : SocketFactory() {
                override fun createSocket(): Socket =
                    Socket().also { tryProtect(it, protector) }

                override fun createSocket(host: String, port: Int): Socket =
                    Socket().also { tryProtect(it, protector) }.also {
                        it.connect(InetSocketAddress(host, port))
                    }

                override fun createSocket(host: String, port: Int,
                                          localHost: InetAddress, localPort: Int): Socket =
                    Socket().also { tryProtect(it, protector) }.also {
                        it.bind(InetSocketAddress(localHost, localPort))
                        it.connect(InetSocketAddress(host, port))
                    }

                override fun createSocket(host: InetAddress, port: Int): Socket =
                    Socket().also { tryProtect(it, protector) }.also {
                        it.connect(InetSocketAddress(host, port))
                    }

                override fun createSocket(address: InetAddress, port: Int,
                                          localAddress: InetAddress, localPort: Int): Socket =
                    Socket().also { tryProtect(it, protector) }.also {
                        it.bind(InetSocketAddress(localAddress, localPort))
                        it.connect(InetSocketAddress(address, port))
                    }

                private fun tryProtect(sock: Socket, p: (Socket) -> Unit) {
                    try { p(sock) } catch (e: Exception) {
                        Logger.w(TAG, "Socket protect failed: ${e.message}")
                    }
                }
            }

            // Устанавливаем через reflection — стандартный API не позволяет
            val field = SocketFactory::class.java.getDeclaredField("theFactory")
            field.isAccessible = true
            field.set(null, protectedFactory)
            Logger.i(TAG, "Protected SocketFactory installed")
        } catch (e: Exception) {
            Logger.w(TAG, "Cannot install SocketFactory: ${e.message} — upstream sockets may loop")
        }
    }

    private fun restorePreviousSocketFactory() {
        try {
            val field = SocketFactory::class.java.getDeclaredField("theFactory")
            field.isAccessible = true
            field.set(null, prevSocketFactory)
        } catch (_: Exception) {}
    }
}

object UpstreamSocketProtectorHook {
    @Volatile var protector: ((Socket) -> Unit)? = null
}
