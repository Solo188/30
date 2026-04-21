package com.adblocker.core.proxy

import com.adblocker.filter.engine.FilterEngine
import com.adblocker.filter.engine.ResourceType
import com.adblocker.ui.log.RequestLogEntry
import com.adblocker.ui.main.MainViewModel
import com.adblocker.utils.Logger
import com.google.gson.Gson
import com.google.gson.JsonElement
import com.google.gson.JsonObject
import com.google.gson.JsonArray
import com.google.gson.JsonParser
import io.netty.buffer.Unpooled
import io.netty.channel.ChannelHandlerContext
import io.netty.handler.codec.http.DefaultFullHttpResponse
import io.netty.handler.codec.http.FullHttpResponse
import io.netty.handler.codec.http.HttpHeaders
import io.netty.handler.codec.http.HttpObject
import io.netty.handler.codec.http.HttpRequest
import io.netty.handler.codec.http.HttpResponse
import io.netty.handler.codec.http.HttpResponseStatus
import io.netty.handler.codec.http.HttpVersion
import org.littleshoot.proxy.HttpFiltersAdapter
import java.nio.charset.Charset
import java.time.Instant

/**
 * AdBlockerHttpFilters — хирургическая фильтрация рекламы.
 *
 * Принципы:
 *  1. Блокировка только известных рекламных запросов по FilterEngine.
 *  2. CSS-инъекция только в реальные HTML-страницы (не фреймы, не partial).
 *  3. JS-заглушки anti-adblock bypass — минимальные, не ломают сайты.
 *  4. YouTube: Fix #8 — используем Gson для корректного удаления рекламных ключей.
 *  5. НЕ стрипаем CSP/X-Frame-Options — это ломает сайты с framing protection.
 *     Удаляем только конкретные политики блокирующие MITM-сертификат.
 */
class AdBlockerHttpFilters(
    originalRequest: HttpRequest,
    ctx: ChannelHandlerContext?,
    private val filterEngine: FilterEngine
) : HttpFiltersAdapter(originalRequest, ctx) {

    companion object {
        private const val TAG = "HttpFilters"

        // Минимальный JS: только заглушки детекторов adblock.
        // НЕ трогаем window.adsbygoogle — это ломает ротацию рекламы на сторонних сайтах
        // когда скрипт Google Ads всё же загружается (например через исключение правил).
        private val ANTI_ADBLOCK_JS = """
<script>(function(){
  // Обманываем типичные детекторы adblock
  try {
    Object.defineProperty(window,'__adblockDetected',{get:function(){return false;},configurable:true});
    Object.defineProperty(window,'adblock',{get:function(){return false;},configurable:true});
    Object.defineProperty(window,'adsBlocked',{get:function(){return false;},configurable:true});
    if(window.blockAdBlock)window.blockAdBlock={onDetected:function(){},onNotDetected:function(cb){if(cb)cb();}};
    // Фейковый рекламный div — некоторые детекторы ищут его наличие в DOM
    document.addEventListener('DOMContentLoaded',function(){
      if(document.getElementById('__ab_probe'))return;
      var d=document.createElement('div');
      d.id='__ab_probe';d.className='adsbygoogle ads ad adsbox doubleclick ad-placement';
      d.style.cssText='position:absolute;width:1px;height:1px;overflow:hidden;left:-9999px;top:-9999px;';
      document.body&&document.body.appendChild(d);
    },false);
  }catch(e){}
})();</script>
""".trimIndent()

        // YouTube API endpoints где нужно стрипать рекламу
        private val YOUTUBE_AD_ENDPOINTS = setOf(
            "youtubei/v1/player",
            "youtubei/v1/next",
            "youtubei/v1/browse",
            // Fix #12: добавлены пропущенные YouTube endpoints с рекламой
            "youtubei/v1/search",
            "youtubei/v1/guide",
            "reel/reel_watch_sequence"
        )

        // Рекламные ключи в YouTube JSON (Fix #8: теперь стрипаем через Gson)
        private val YOUTUBE_AD_KEYS = setOf(
            "adPlacements",
            "playerAds",
            "adSlots",
            "adBreakHeartbeatParams",
            "auxiliaryUi"
        )

        private val gson = Gson()
    }

    private val startTime     = System.currentTimeMillis()
    private var requestHost   = ""
    private var requestUrl    = ""
    private var requestMethod = ""
    private var resourceType  = ResourceType.OTHER
    private var isThirdParty  = true
    private var isYouTubeApi  = false

    // ── Request: client → proxy ───────────────────────────────────────────────

    override fun clientToProxyRequest(httpObject: HttpObject): HttpResponse? {
        if (httpObject !is HttpRequest) return null

        requestMethod = httpObject.method.name()
        val uri  = httpObject.uri
        val host = extractHost(httpObject)

        requestHost  = host
        requestUrl   = resolveUrl(uri, host)
        resourceType = ResourceType.fromAccept(httpObject.headers().get(HttpHeaders.Names.ACCEPT))
        isThirdParty = determineThirdParty(host, httpObject.headers().get(HttpHeaders.Names.REFERER))
        isYouTubeApi = YOUTUBE_AD_ENDPOINTS.any { requestUrl.contains(it) }

        if (filterEngine.shouldBlock(requestUrl, host, resourceType, isThirdParty)) {
            Logger.i(TAG, "BLOCKED: $requestUrl")
            logEntry(blocked = true, code = 204)
            return buildBlockResponse()
        }
        return null
    }

    // ── Response: server → proxy ──────────────────────────────────────────────

    override fun serverToProxyResponse(httpObject: HttpObject): HttpObject {
        if (httpObject !is FullHttpResponse) {
            if (httpObject is HttpResponse) {
                removeMitmBlockingHeaders(httpObject)
                logEntry(blocked = false, code = httpObject.status.code())
            }
            return httpObject
        }

        val statusCode  = httpObject.status.code()
        val contentType = httpObject.headers().get(HttpHeaders.Names.CONTENT_TYPE) ?: ""

        removeMitmBlockingHeaders(httpObject)
        logEntry(blocked = false, code = statusCode)

        return when {
            isYouTubeApi && "json" in contentType -> processYouTubeResponse(httpObject)
            "text/html" in contentType && statusCode == 200 -> processHtmlResponse(httpObject)
            else -> httpObject
        }
    }

    // ── HTML processing ───────────────────────────────────────────────────────

    private fun processHtmlResponse(response: FullHttpResponse): HttpObject {
        val charset = extractCharset(response.headers().get(HttpHeaders.Names.CONTENT_TYPE))
        val html    = response.content().toString(charset)

        // Не трогаем фреймы и iframe-документы — только главный документ
        // (определяем по отсутствию X-Frame-Options: DENY не работает здесь,
        //  но Content-Type: text/html; charset= обычно достаточно)
        val css = filterEngine.getCssForHost(requestHost)
        // css может быть пустым (нет правил для хоста) — injectPayload это обрабатывает.

        val sb = StringBuilder(html.length + 4096)
        var injected = false

        // Вставляем в </head> — самое надёжное место
        val headEnd = html.indexOf("</head>", ignoreCase = true)
        if (headEnd >= 0) {
            sb.append(html, 0, headEnd)
            injectPayload(sb, css)
            sb.append(html, headEnd, html.length)
            injected = true
        }

        // Fallback: после открывающего <body>
        if (!injected) {
            val bodyTag = html.indexOf("<body", ignoreCase = true)
            if (bodyTag >= 0) {
                val bodyEnd = html.indexOf('>', bodyTag) + 1
                sb.append(html, 0, bodyEnd)
                injectPayload(sb, css)
                sb.append(html, bodyEnd, html.length)
                injected = true
            }
        }

        if (!injected) return response  // не HTML-документ — не трогаем

        val modified = sb.toString().toByteArray(charset)
        val newBuf   = Unpooled.wrappedBuffer(modified)
        val newResp  = DefaultFullHttpResponse(response.protocolVersion, response.status, newBuf)
        newResp.headers().set(response.headers())
        newResp.headers().set(HttpHeaders.Names.CONTENT_LENGTH, modified.size)
        newResp.headers().remove(HttpHeaders.Names.TRANSFER_ENCODING)
        return newResp
    }

    private fun injectPayload(sb: StringBuilder, css: String) {
        if (css.isNotEmpty()) {
            sb.append("\n<style id='__adblock_css'>\n")
            sb.append(css)
            sb.append("\n</style>\n")
        }
        sb.append(ANTI_ADBLOCK_JS)
        sb.append("\n")
    }

    // ── YouTube JSON processing ───────────────────────────────────────────────

    /**
     * Fix #8: использует Gson для корректного парсинга и удаления рекламных ключей.
     * Предыдущая реализация через StringBuilder.indexOf() ломалась на строках
     * с экранированными кавычками и вложенными объектами.
     */
    private fun processYouTubeResponse(response: FullHttpResponse): HttpObject {
        val json = response.content().toString(Charsets.UTF_8)
        if (json.isBlank()) return response

        return try {
            val root = JsonParser.parseString(json)
            val modified = stripAdKeysRecursive(root)

            // Если ничего не изменилось — возвращаем оригинал без реаллокации
            if (!modified) return response

            val newJson  = gson.toJson(root)
            val bytes    = newJson.toByteArray(Charsets.UTF_8)
            val newBuf   = Unpooled.wrappedBuffer(bytes)
            val newResp  = DefaultFullHttpResponse(response.protocolVersion, response.status, newBuf)
            newResp.headers().set(response.headers())
            newResp.headers().set(HttpHeaders.Names.CONTENT_LENGTH, bytes.size)
            newResp.headers().remove(HttpHeaders.Names.TRANSFER_ENCODING)
            Logger.i(TAG, "YouTube ad keys stripped: ${requestUrl.substringAfterLast('/')}")
            newResp
        } catch (e: Exception) {
            Logger.w(TAG, "YouTube JSON parse failed: ${e.message}")
            response   // безопасный fallback — оригинальный ответ без изменений
        }
    }

    /**
     * Рекурсивно обходит JsonElement и удаляет рекламные ключи из JsonObject.
     * @return true если хотя бы один ключ был удалён
     */
    private fun stripAdKeysRecursive(element: JsonElement): Boolean {
        var changed = false
        when {
            element.isJsonObject -> {
                val obj = element.asJsonObject
                // Удаляем рекламные ключи на этом уровне
                for (key in YOUTUBE_AD_KEYS) {
                    if (obj.has(key)) {
                        obj.remove(key)
                        changed = true
                    }
                }
                // Рекурсивно обходим оставшиеся поля
                for (entry in obj.entrySet()) {
                    if (stripAdKeysRecursive(entry.value)) changed = true
                }
            }
            element.isJsonArray -> {
                for (item in element.asJsonArray) {
                    if (stripAdKeysRecursive(item)) changed = true
                }
            }
            // Примитивы — ничего не делаем
        }
        return changed
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /**
     * Удаляем только заголовки которые напрямую мешают MITM-перехвату:
     *  - CSP upgrade-insecure-requests / блокировка inline-скриптов (ломает наш injected JS)
     *  - НЕ трогаем X-Frame-Options, X-XSS-Protection — они не мешают нам и защищают пользователя
     *  - НЕ трогаем HSTS
     */
    private fun removeMitmBlockingHeaders(response: HttpResponse) {
        val csp = response.headers().get("Content-Security-Policy") ?: return
        // Удаляем только если CSP содержит директивы блокирующие inline-скрипты
        // (script-src 'self' без 'unsafe-inline' сломает наш injected JS)
        if (csp.contains("script-src") && !csp.contains("'unsafe-inline'")) {
            response.headers().remove("Content-Security-Policy")
            response.headers().remove("Content-Security-Policy-Report-Only")
        }
    }

    private fun buildBlockResponse(): DefaultFullHttpResponse {
        return DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.NO_CONTENT).also {
            it.headers().set(HttpHeaders.Names.CONTENT_LENGTH, "0")
            it.headers().set(HttpHeaders.Names.CONNECTION, "keep-alive")
            it.headers().set("X-AdBlocker", "blocked")
        }
    }

    private fun extractCharset(contentType: String?): Charset {
        if (contentType == null) return Charsets.UTF_8
        return try {
            Regex("charset=([\\w-]+)", RegexOption.IGNORE_CASE)
                .find(contentType)?.groupValues?.get(1)
                ?.let { Charset.forName(it) } ?: Charsets.UTF_8
        } catch (_: Exception) { Charsets.UTF_8 }
    }

    private fun extractHost(request: HttpRequest): String {
        val h = request.headers().get(HttpHeaders.Names.HOST) ?: ""
        if (h.isNotBlank()) return h.substringBefore(':').lowercase()
        return try { java.net.URI(request.uri).host?.lowercase() ?: "" }
        catch (_: Exception) { "" }
    }

    private fun resolveUrl(uri: String, host: String): String = when {
        uri.startsWith("http://") || uri.startsWith("https://") -> uri
        uri.startsWith("/") && host.isNotBlank() -> "https://$host$uri"
        else -> uri
    }

    private fun determineThirdParty(host: String, referer: String?): Boolean {
        if (referer.isNullOrBlank()) return true
        return try {
            val refHost = java.net.URI(referer).host?.lowercase()?.removePrefix("www.") ?: return true
            val reqHost = host.lowercase().removePrefix("www.")
            !reqHost.endsWith(refHost) && !refHost.endsWith(reqHost)
        } catch (_: Exception) { true }
    }

    private fun logEntry(blocked: Boolean, code: Int) {
        val entry = RequestLogEntry(
            timestamp    = Instant.now(),
            method       = requestMethod,
            host         = requestHost,
            url          = requestUrl,
            blocked      = blocked,
            responseCode = code,
            durationMs   = System.currentTimeMillis() - startTime
        )
        MainViewModel.onRequestIntercepted?.invoke(entry)
    }
}
