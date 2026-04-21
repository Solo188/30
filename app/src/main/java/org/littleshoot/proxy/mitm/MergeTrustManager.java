package org.littleshoot.proxy.mitm;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * A composite {@link X509TrustManager} that merges the system trust store
 * with our own CA so that:
 *  - Upstream servers whose certs are in the system store are trusted normally.
 *  - Certificates we generated are also trusted.
 *
 * This prevents unnecessary "untrusted issuer" errors when forwarding to
 * legitimate HTTPS servers.
 */
public class MergeTrustManager implements X509TrustManager {

    private final X509TrustManager[] delegates;

    public MergeTrustManager(KeyStore ourKeyStore) throws Exception {
        List<X509TrustManager> managers = new ArrayList<>();

        // 1. System default trust manager
        TrustManagerFactory systemTmf =
            TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        systemTmf.init((KeyStore) null); // null → use system default
        for (TrustManager tm : systemTmf.getTrustManagers()) {
            if (tm instanceof X509TrustManager) {
                managers.add((X509TrustManager) tm);
            }
        }

        // 2. Our CA keystore
        TrustManagerFactory ourTmf =
            TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        ourTmf.init(ourKeyStore);
        for (TrustManager tm : ourTmf.getTrustManagers()) {
            if (tm instanceof X509TrustManager) {
                managers.add((X509TrustManager) tm);
            }
        }

        delegates = managers.toArray(new X509TrustManager[0]);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType)
            throws CertificateException {
        for (X509TrustManager tm : delegates) {
            try {
                tm.checkClientTrusted(chain, authType);
                return;
            } catch (CertificateException ignored) {}
        }
        throw new CertificateException("None of the trust managers trusted the client certificate");
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType)
            throws CertificateException {
        for (X509TrustManager tm : delegates) {
            try {
                tm.checkServerTrusted(chain, authType);
                return;
            } catch (CertificateException ignored) {}
        }
        throw new CertificateException("None of the trust managers trusted the server certificate");
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        List<X509Certificate> issuers = new ArrayList<>();
        for (X509TrustManager tm : delegates) {
            issuers.addAll(Arrays.asList(tm.getAcceptedIssuers()));
        }
        return issuers.toArray(new X509Certificate[0]);
    }
}
