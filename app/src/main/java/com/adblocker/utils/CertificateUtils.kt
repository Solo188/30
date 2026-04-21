package com.adblocker.utils

import android.content.Context
import java.io.File
import java.security.KeyStore

/**
 * Helpers for persisting and loading the root CA key material on-device.
 */
object CertificateUtils {

    private const val CA_CERT_FILENAME = "adblocker_ca.crt"
    private const val CA_KEY_STORE_FILENAME = "adblocker_ca.bks"
    private const val KEY_STORE_PASSWORD = "adblocker_internal"

    fun getCaCertFile(context: Context): File =
        File(context.filesDir, CA_CERT_FILENAME)

    fun getKeyStoreFile(context: Context): File =
        File(context.filesDir, CA_KEY_STORE_FILENAME)

    fun keyStorePassword(): CharArray = KEY_STORE_PASSWORD.toCharArray()

    /**
     * Load the BKS keystore from disk.  Returns null if it doesn't exist yet.
     */
    fun loadKeyStore(context: Context): KeyStore? {
        val file = getKeyStoreFile(context)
        if (!file.exists()) return null
        return try {
            KeyStore.getInstance("BKS", "BC").also { ks ->
                file.inputStream().use { ks.load(it, keyStorePassword()) }
            }
        } catch (e: Exception) {
            Logger.e("CertUtils", "Failed to load keystore", e)
            null
        }
    }

    /**
     * Save a keystore to disk.
     */
    fun saveKeyStore(context: Context, keyStore: KeyStore) {
        try {
            getKeyStoreFile(context).outputStream().use { out ->
                keyStore.store(out, keyStorePassword())
            }
        } catch (e: Exception) {
            Logger.e("CertUtils", "Failed to save keystore", e)
        }
    }
}
