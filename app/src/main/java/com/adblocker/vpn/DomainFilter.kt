package com.adblocker.vpn

import android.content.Context
import java.io.File

class DomainFilter {

    // Fix #10: @Volatile ссылка на неизменяемый Set вместо мутируемого HashSet.
    // loadFromFile() строит новый Set и заменяет атомарно — нет ConcurrentModificationException
    // при одновременном чтении из TcpStack-потока.
    @Volatile private var blacklist: Set<String> = emptySet()

    // LRU cache: max 10 000 entries, access-order eviction (Fix #5)
    @Suppress("UNCHECKED_CAST")
    private val cache: LinkedHashMap<String, Boolean> = object :
        LinkedHashMap<String, Boolean>(1024, 0.75f, true) {
        override fun removeEldestEntry(eldest: Map.Entry<String, Boolean>) = size > 10_000
    }


    fun loadFromFile(context: Context) {
        try {
            val file = File(context.filesDir, "domains.txt")
            if (!file.exists()) return
            val newSet = HashSet<String>()
            file.forEachLine { line ->
                val domain = line.trim()
                if (domain.isNotEmpty()) newSet.add(domain)
            }
            blacklist = newSet  // атомарная замена — читающие потоки видят либо старый, либо новый Set
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    fun loadFromAssets(context: Context) {
        val newSet = HashSet<String>()
        val input = context.assets.open("ad_domains.txt")
        input.bufferedReader().useLines { lines ->
            lines.forEach { line ->
                val domain = line.trim()
                if (domain.isNotEmpty() && !domain.startsWith("#")) {
                    newSet.add(domain)
                }
            }
        }
        blacklist = newSet  // атомарная замена
    }

    fun isBlocked(domain: String): Boolean {
        if (domain.length < 5) return false

        val lower = domain.lowercase()
        // synchronized because LinkedHashMap (access-order) is not thread-safe
        synchronized(cache) { cache[lower] }?.let { return it }

        // 1. проверка по списку (включая поддомены)
        val parts = lower.split(".")
        for (i in parts.indices) {
            val sub = parts.drop(i).joinToString(".")
            if (blacklist.contains(sub)) {
                synchronized(cache) { cache[lower] = true }
                return true
            }
        }

        // 2. эвристика только для однозначных рекламных паттернов (Fix #7)
        if (isSuspicious(lower)) {
            synchronized(cache) { cache[lower] = true }
            return true
        }

        synchronized(cache) { cache[lower] = false }
        return false
    }

    fun getBlacklistSize(): Int = blacklist.size

    private fun isSuspicious(domain: String): Boolean {
        // Whitelist: легитимные домены с «рекламными» подстроками
        val whitelist = setOf(
            "pixel.google.com", "pixel.facebook.com",
            "analytics.google.com", "analyze.example.com",
            "credentials.example.com"
        )
        if (domain in whitelist) return false

        // Только явные рекламные паттерны (домен целиком начинается/содержит сегмент)
        val segments = domain.split(".")
        val tld2 = if (segments.size >= 2) segments.takeLast(2).joinToString(".") else domain

        // Заблокировать если первый сегмент — рекламный ключ
        val adPrefixes = setOf(
            "ads", "ad", "adservice", "adserver", "adtech",
            "doubleclick", "tracking", "tracker",
            "pagead", "adnxs", "adform"
        )
        if (segments.first() in adPrefixes) return true

        // Заблокировать если домен второго уровня (без TLD) — явно рекламный
        val adDomainPatterns = listOf(
            "doubleclick", "googlesyndication", "adnxs",
            "adform", "moatads", "adsrvr"
        )
        return adDomainPatterns.any { tld2.startsWith(it) || domain.contains(".$it.") }
    }
}
