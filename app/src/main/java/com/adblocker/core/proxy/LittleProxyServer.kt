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
import java.net.InetSocketAddress
import java.net.Socket

class LittleProxyServer(
    private val context: Context,
    private val port: Int,
    private val filterEngine: FilterEngine,
    private val socketProtector: ((Socket) -> Unit)? = null
) {
    companion object {
        private const val TAG = "LittleProxyServer"
        // Fix #14: снижены лимиты буферов для экономии памяти на бюджетных устройствах
        private const val RESPONSE_BUFFER_BYTES = 2 * 1024 * 1024   // 2 MB
        private const val REQUEST_BUFFER_BYTES  = 1 * 1024 * 1024   // 1 MB
    }

    @Volatile private var proxyServer: org.littleshoot.proxy.HttpProxyServer? = null

    private fun buildAuthority(): Authority = Authority(
        context.filesDir, "adblocker-ca", "AdBlockerCA_2024!".toCharArray(),
        "AdBlocker Root CA", "AdBlocker", "Certificate Authority",
        "AdBlocker MITM", "AdBlocker TLS Interception"
    )

    fun start() {
        Logger.i(TAG, "Starting LittleProxy on port $port")
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

            // Буферизация запросов
            override fun getMaximumRequestBufferSizeInBytes(): Int  = REQUEST_BUFFER_BYTES

            // КЛЮЧЕВОЕ: буферизация ответов — без этого serverToProxyResponse
            // получает FullHttpResponse и мы можем читать/менять body
            override fun getMaximumResponseBufferSizeInBytes(): Int = RESPONSE_BUFFER_BYTES
        }

        val bootstrap = DefaultHttpProxyServer.bootstrap()
            .withAddress(InetSocketAddress("127.0.0.1", port))
            .withFiltersSource(filtersSource)
            .withProxyAlias("AdBlocker")

        // Fix #3: protect() upstream сокетов через UpstreamSocketProtectorHook.
        // LittleProxy 1.1.2 не предоставляет API для перехвата upstream-каналов
        // через ChannelInitializer, поэтому используем глобальный hook который
        // вызывается из кастомного NetworkLayer если он настроен, либо через
        // стандартный механизм VpnService.protect() на уровне ОС.
        if (socketProtector != null) {
            UpstreamSocketProtectorHook.protector = socketProtector
        }

        if (mitmManager != null) {
            bootstrap.withManInTheMiddle(mitmManager)
            Logger.i(TAG, "MITM enabled")
        }

        proxyServer = bootstrap.start()
        Logger.i(TAG, "LittleProxy listening on 127.0.0.1:$port (response buffer: ${RESPONSE_BUFFER_BYTES/1024}KB)")
    }

    fun stop() {
        UpstreamSocketProtectorHook.protector = null
        proxyServer?.stop()
        proxyServer = null
        Logger.i(TAG, "LittleProxy stopped")
    }

    fun getCaPemFile(): File = buildAuthority().aliasFile(".pem")
}

object UpstreamSocketProtectorHook {
    @Volatile var protector: ((Socket) -> Unit)? = null
}
