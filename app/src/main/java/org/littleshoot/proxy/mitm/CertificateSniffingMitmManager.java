package org.littleshoot.proxy.mitm;

import android.util.Log;

import org.littleshoot.proxy.MitmManager;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;

import io.netty.handler.codec.http.HttpRequest;

/**
 * {@link MitmManager} that reads the upstream server's real certificate and
 * creates a matching fake certificate signed by our root CA.
 *
 * Flow for each HTTPS CONNECT:
 *  1. LittleProxy calls {@link #serverSslEngine(String, int)} to connect to the real server.
 *  2. After the TLS handshake, LittleProxy calls {@link #clientSslEngineFor} with the
 *     established SSLSession (which contains the real server cert).
 *  3. We extract the CN + SANs from the server cert and generate a fake cert.
 *  4. The client TLS handshake uses the fake cert — browser accepts it because
 *     our root CA is installed as trusted.
 */
public class CertificateSniffingMitmManager implements MitmManager {

    private static final String TAG = "MitmManager";

    private final BouncyCastleSslEngineSource sslEngineSource;

    /**
     * Create with default Authority — use for tests. For production, use the
     * constructor that takes a pre-configured {@link Authority} pointing to
     * app file storage.
     */
    public CertificateSniffingMitmManager(Authority authority) throws RootCertificateException {
        try {
            sslEngineSource = new BouncyCastleSslEngineSource(
                    authority,
                    true,  // trustAllServers — we verify via cert pinning separately
                    true   // sendCerts       — yes, send our fake certs to clients
            );
        } catch (Exception e) {
            throw new RootCertificateException("Failed to initialise MITM SSL engine", e);
        }
    }

    // -------------------------------------------------------------------------
    //  MitmManager interface
    // -------------------------------------------------------------------------

    /**
     * Creates an SSLEngine for connecting TO the real upstream server.
     * Called before the proxy has established a connection to the server.
     */
    @Override
    public SSLEngine serverSslEngine(String peerHost, int peerPort) {
        Log.d(TAG, "serverSslEngine → " + peerHost + ":" + peerPort);
        return sslEngineSource.newSslEngine(peerHost, peerPort);
    }

    /**
     * Fallback: called when host/port are not available.
     */
    @Override
    public SSLEngine serverSslEngine() {
        Log.d(TAG, "serverSslEngine (no host info)");
        return sslEngineSource.newSslEngine();
    }

    /**
     * Creates an SSLEngine for the CLIENT side, presenting a spoofed certificate
     * derived from the upstream server's real certificate.
     */
    @Override
    public SSLEngine clientSslEngineFor(HttpRequest httpRequest, SSLSession serverSslSession) {
        try {
            X509Certificate upstreamCert = getServerCert(serverSslSession);
            String commonName = extractCommonName(upstreamCert);

            SubjectAlternativeNameHolder san = new SubjectAlternativeNameHolder();
            san.addAll(upstreamCert.getSubjectAlternativeNames());

            // Always add the CN as a DNS SAN too (some certs only have CN)
            if (!commonName.isEmpty()) {
                san.addDnsName(commonName);
            }

            Log.d(TAG, "Generating fake cert for CN=" + commonName + " SANs=" + san);
            return sslEngineSource.createCertForHost(commonName, san);

        } catch (Exception e) {
            throw new FakeCertificateException(
                    "Failed to generate fake cert for client", e);
        }
    }

    // -------------------------------------------------------------------------
    //  CA export
    // -------------------------------------------------------------------------

    /**
     * Returns the PEM-encoded root CA certificate for user installation.
     */
    public String getRootCaPem() {
        try {
            return sslEngineSource.getRootCaPem();
        } catch (Exception e) {
            Log.e(TAG, "Failed to export CA PEM", e);
            return "";
        }
    }

    // -------------------------------------------------------------------------
    //  Helpers
    // -------------------------------------------------------------------------

    private X509Certificate getServerCert(SSLSession session)
            throws SSLPeerUnverifiedException {
        Certificate[] certs = session.getPeerCertificates();
        if (certs == null || certs.length == 0) {
            throw new SSLPeerUnverifiedException("No peer certificates in SSL session");
        }
        Certificate cert = certs[0];
        if (cert instanceof X509Certificate) {
            return (X509Certificate) cert;
        }
        throw new IllegalStateException(
                "Expected X509Certificate, got: " + cert.getClass().getName());
    }

    private String extractCommonName(X509Certificate cert) {
        String dn = cert.getSubjectX500Principal().getName();
        Log.d(TAG, "Upstream cert DN: " + dn);
        for (String part : dn.split(",\\s*")) {
            if (part.startsWith("CN=")) {
                String cn = part.substring(3).trim();
                Log.d(TAG, "Extracted CN: " + cn);
                return cn;
            }
        }
        // Fallback: return empty string; caller will use SANs only
        Log.w(TAG, "No CN found in DN: " + dn);
        return "";
    }
}
