package org.littleshoot.proxy.mitm;

import android.util.Log;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;

import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.OperatorCreationException;
import org.littleshoot.proxy.SslEngineSource;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;

import io.netty.handler.ssl.util.InsecureTrustManagerFactory;

/**
 * {@link SslEngineSource} that manages a root CA and dynamically generates
 * per-domain leaf certificates.  This is the core MITM SSL engine.
 *
 * Adapted from LittleProxy-mitm for Android:
 *  - Uses PKCS12 keystore (not JKS — unavailable on Android)
 *  - Uses android.util.Log instead of SLF4J
 *  - Stores keystore in app files directory (passed via Authority)
 */
public class BouncyCastleSslEngineSource implements SslEngineSource {

    private static final String TAG = "BCSslEngineSource";
    private static final String KEY_STORE_TYPE = "PKCS12";
    private static final String KEY_STORE_EXT  = ".p12";

    private final Authority authority;
    private final boolean trustAllServers;
    private final boolean sendCerts;

    private SSLContext sslContext;
    private Certificate caCert;
    private PrivateKey  caPrivKey;

    /** Cache: hostname → SSLContext (avoids regenerating cert per connection) */
    private final Cache<String, SSLContext> serverSSLContexts;

    public BouncyCastleSslEngineSource(
            Authority authority,
            boolean trustAllServers,
            boolean sendCerts)
            throws RootCertificateException, GeneralSecurityException,
                   IOException, OperatorCreationException {
        this(authority, trustAllServers, sendCerts,
             CacheBuilder.newBuilder()
                 .expireAfterAccess(10, TimeUnit.MINUTES)
                 .concurrencyLevel(16)
                 .build());
    }

    public BouncyCastleSslEngineSource(
            Authority authority,
            boolean trustAllServers,
            boolean sendCerts,
            Cache<String, SSLContext> sslContexts)
            throws RootCertificateException, GeneralSecurityException,
                   IOException, OperatorCreationException {
        this.authority        = authority;
        this.trustAllServers  = trustAllServers;
        this.sendCerts        = sendCerts;
        this.serverSSLContexts = sslContexts;
        initializeKeyStore();
        initializeSSLContext();
    }

    // -------------------------------------------------------------------------
    //  SslEngineSource implementation
    // -------------------------------------------------------------------------

    @Override
    public SSLEngine newSslEngine() {
        SSLEngine engine = sslContext.createSSLEngine();
        engine.setUseClientMode(true);
        return engine;
    }

    @Override
    public SSLEngine newSslEngine(String remoteHost, int remotePort) {
        SSLEngine engine = sslContext.createSSLEngine(remoteHost, remotePort);
        engine.setUseClientMode(true);
        return engine;
    }

    // -------------------------------------------------------------------------
    //  Per-host certificate (MITM leaf cert)
    // -------------------------------------------------------------------------

    /**
     * Returns an SSLEngine presenting a fake certificate for {@code commonName},
     * signed by our root CA.  Result is cached so subsequent connections to the
     * same host reuse the same context.
     */
    public SSLEngine createCertForHost(
            final String commonName,
            final SubjectAlternativeNameHolder san)
            throws GeneralSecurityException, OperatorCreationException,
                   IOException, ExecutionException {

        if (commonName == null) throw new IllegalArgumentException("commonName is null");
        if (san == null) throw new IllegalArgumentException("san is null");

        SSLContext ctx;
        if (serverSSLContexts == null) {
            ctx = createServerContext(commonName, san);
        } else {
            ctx = serverSSLContexts.get(commonName, new Callable<SSLContext>() {
                @Override
                public SSLContext call() throws Exception {
                    return createServerContext(commonName, san);
                }
            });
        }
        SSLEngine engine = ctx.createSSLEngine();
        engine.setUseClientMode(false);
        return engine;
    }

    // -------------------------------------------------------------------------
    //  Keystore initialisation
    // -------------------------------------------------------------------------

    private void initializeKeyStore()
            throws RootCertificateException, GeneralSecurityException,
                   OperatorCreationException, IOException {

        File p12File  = authority.aliasFile(KEY_STORE_EXT);
        File pemFile  = authority.aliasFile(".pem");

        if (p12File.exists() && pemFile.exists()) {
            Log.i(TAG, "Existing root CA loaded from " + p12File.getAbsolutePath());
            return;
        }

        MillisecondsDuration timer = new MillisecondsDuration();
        KeyStore keystore = CertificateHelper.createRootCertificate(authority, KEY_STORE_TYPE);
        Log.i(TAG, "Root CA generated in " + timer + "ms → " + p12File.getAbsolutePath());

        try (FileOutputStream fos = new FileOutputStream(p12File)) {
            keystore.store(fos, authority.password());
        }

        Certificate cert = keystore.getCertificate(authority.alias());
        exportPem(pemFile, cert);
        Log.i(TAG, "Root CA PEM exported to " + pemFile.getAbsolutePath());
    }

    private void initializeSSLContext() throws GeneralSecurityException, IOException {
        KeyStore ks = loadKeyStore();
        caCert    = ks.getCertificate(authority.alias());
        caPrivKey = (PrivateKey) ks.getKey(authority.alias(), authority.password());

        TrustManager[] trustManagers;
        if (trustAllServers) {
            trustManagers = InsecureTrustManagerFactory.INSTANCE.getTrustManagers();
        } else {
            try {
                trustManagers = new TrustManager[]{ new MergeTrustManager(ks) };
            } catch (Exception e) {
                Log.w(TAG, "MergeTrustManager init failed, falling back to insecure", e);
                trustManagers = InsecureTrustManagerFactory.INSTANCE.getTrustManagers();
            }
        }

        KeyManager[] keyManagers;
        if (sendCerts) {
            keyManagers = CertificateHelper.getKeyManagers(ks, authority);
        } else {
            keyManagers = new KeyManager[0];
        }

        sslContext = CertificateHelper.newClientContext(keyManagers, trustManagers);
        Log.i(TAG, "SSL context initialised (trustAllServers=" + trustAllServers + ")");
    }

    private KeyStore loadKeyStore() throws GeneralSecurityException, IOException {
        KeyStore ks = KeyStore.getInstance(KEY_STORE_TYPE);
        try (FileInputStream fis = new FileInputStream(authority.aliasFile(KEY_STORE_EXT))) {
            ks.load(fis, authority.password());
        }
        return ks;
    }

    // -------------------------------------------------------------------------
    //  Server (leaf) SSLContext creation
    // -------------------------------------------------------------------------

    private SSLContext createServerContext(
            String commonName,
            SubjectAlternativeNameHolder san)
            throws GeneralSecurityException, OperatorCreationException,
                   IOException {

        MillisecondsDuration timer = new MillisecondsDuration();
        KeyStore serverKs = CertificateHelper.createServerCertificate(
                commonName, san, authority, caCert, caPrivKey);
        Log.d(TAG, "Leaf cert for " + commonName + " generated in " + timer + "ms");

        KeyManager[] km = CertificateHelper.getKeyManagers(serverKs, authority);
        return CertificateHelper.newServerContext(km);
    }

    // -------------------------------------------------------------------------
    //  PEM export
    // -------------------------------------------------------------------------

    private void exportPem(File pemFile, Certificate cert) throws IOException {
        try (StringWriter sw = new StringWriter();
             JcaPEMWriter pw = new JcaPEMWriter(sw)) {
            pw.writeObject(cert);
            pw.flush();
            try (FileOutputStream fos = new FileOutputStream(pemFile)) {
                fos.write(sw.toString().getBytes("UTF-8"));
            }
        }
    }

    /**
     * Returns the PEM-encoded root CA certificate as a String,
     * for display / export to the user.
     */
    public String getRootCaPem() throws CertificateEncodingException, IOException {
        StringWriter sw = new StringWriter();
        try (JcaPEMWriter pw = new JcaPEMWriter(sw)) {
            pw.writeObject(caCert);
        }
        return sw.toString();
    }
}
