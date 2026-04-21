package com.adblocker.vpn

import android.content.Context
import android.net.VpnService
import android.util.Log
import java.io.File
import java.net.HttpURLConnection
import java.net.URL

/**
 * Downloads the Steven Black unified hosts file and saves domain list to filesDir/domains.txt.
 *
 * Fix #2: The download must happen BEFORE the VPN interface is established,
 * OR the socket must be protected. We call update() from a pre-VPN thread, so
 * the socket naturally bypasses the (not-yet-active) tun. VpnService param kept
 * for future use if called after VPN start.
 */
class DomainListUpdater {

    companion object {
        private const val TAG = "DomainListUpdater"
        private const val HOSTS_URL =
            "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
        private const val CONNECT_TIMEOUT_MS = 15_000
        private const val READ_TIMEOUT_MS    = 30_000
    }

    fun update(context: Context, vpnService: VpnService? = null) {
        try {
            val url  = URL(HOSTS_URL)
            val conn = url.openConnection() as HttpURLConnection
            conn.connectTimeout          = CONNECT_TIMEOUT_MS
            conn.readTimeout             = READ_TIMEOUT_MS
            conn.instanceFollowRedirects = true

            val responseCode = conn.responseCode
            if (responseCode != HttpURLConnection.HTTP_OK) {
                Log.w(TAG, "Hosts download failed: HTTP $responseCode")
                conn.disconnect()
                return
            }

            val domains = conn.inputStream.bufferedReader().useLines { lines ->
                lines
                    .map { it.trim() }
                    .filter { it.isNotEmpty() && !it.startsWith("#") }
                    .mapNotNull { line ->
                        val parts = line.split(Regex("\\s+"))
                        if (parts.size >= 2) parts[1].lowercase().trim() else null
                    }
                    .filter { d -> d.isNotBlank() && d != "localhost" && d != "localhost.localdomain" }
                    .toList()
            }
            conn.disconnect()

            val file = File(context.filesDir, "domains.txt")
            file.writeText(domains.joinToString("\n"))

            Log.i(TAG, "Domain list updated: ${domains.size} entries -> ${file.absolutePath}")
        } catch (e: Exception) {
            Log.e(TAG, "Domain list update failed: ${e.message}")
        }
    }
}
