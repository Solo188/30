package com.adblocker.ui.main

import android.app.Activity
import android.content.Context
import android.content.Intent
import androidx.core.content.FileProvider
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.adblocker.vpn.VpnController
import com.adblocker.vpn.VpnState
import com.adblocker.ui.log.RequestLogEntry
import com.adblocker.utils.Logger
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.util.Collections

class MainViewModel : ViewModel() {

    companion object {
        private const val TAG = "MainViewModel"
        private const val MAX_LOG_ENTRIES = 500

        var onRequestIntercepted: ((RequestLogEntry) -> Unit)? = null
    }

    private var vpnController: VpnController? = null
    private var appContext: Context? = null

    private val _vpnState = MutableStateFlow(VpnState.STOPPED)
    val vpnState: StateFlow<VpnState> = _vpnState.asStateFlow()

    private val _requestLog = MutableStateFlow<List<RequestLogEntry>>(emptyList())
    val requestLog: StateFlow<List<RequestLogEntry>> = _requestLog.asStateFlow()

    private val _blockedCount = MutableStateFlow(0)
    val blockedCount: StateFlow<Int> = _blockedCount.asStateFlow()

    private val logBuffer = Collections.synchronizedList(mutableListOf<RequestLogEntry>())

    private var initialized = false

    fun initialize(context: Context) {
        if (initialized) return
        initialized = true

        val ctx = context.applicationContext
        appContext = ctx
        val controller = VpnController(ctx)
        vpnController = controller

        onRequestIntercepted = { entry ->
            viewModelScope.launch {
                logBuffer.add(0, entry)
                if (logBuffer.size > MAX_LOG_ENTRIES) logBuffer.removeAt(logBuffer.size - 1)
                _requestLog.value = logBuffer.toList()
                if (entry.blocked) _blockedCount.value++
            }
        }

        viewModelScope.launch {
            controller.state.collect { state ->
                _vpnState.value = state
            }
        }
    }

    fun toggleVpn() { vpnController?.toggle() }
    fun startVpn()  { vpnController?.start() }
    fun stopVpn()   { vpnController?.stop() }

    fun clearLog() {
        logBuffer.clear()
        _requestLog.value = emptyList()
        _blockedCount.value = 0
    }

    fun exportCaCertificate(activity: Activity) {
        val ctx = appContext ?: return
        viewModelScope.launch {
            try {
                val authority = org.littleshoot.proxy.mitm.Authority(
                    ctx.filesDir,
                    "adblocker-ca",
                    "AdBlockerCA_2024!".toCharArray(),
                    "AdBlocker Root CA", "AdBlocker",
                    "Certificate Authority", "AdBlocker MITM",
                    "AdBlocker TLS Interception"
                )
                val pemFile = authority.aliasFile(".pem")

                if (!pemFile.exists()) {
                    Logger.w(TAG, "CA PEM not found — start the VPN first to generate it")
                    return@launch
                }

                val uri = FileProvider.getUriForFile(
                    activity,
                    "${activity.packageName}.fileprovider",
                    pemFile
                )
                val intent = Intent(Intent.ACTION_VIEW).apply {
                    setDataAndType(uri, "application/x-x509-ca-cert")
                    flags = Intent.FLAG_GRANT_READ_URI_PERMISSION or
                            Intent.FLAG_ACTIVITY_NEW_TASK
                }
                activity.startActivity(intent)
                Logger.i(TAG, "CA cert share intent fired: ${pemFile.absolutePath}")

            } catch (e: Exception) {
                Logger.e(TAG, "CA export failed", e)
            }
        }
    }

    override fun onCleared() {
        onRequestIntercepted = null
        vpnController?.destroy()
        super.onCleared()
    }
}
