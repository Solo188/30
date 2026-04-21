package org.littleshoot.proxy.mitm;

/**
 * Thrown when the root CA certificate cannot be generated or loaded.
 */
public class RootCertificateException extends Exception {

    public RootCertificateException(String message) {
        super(message);
    }

    public RootCertificateException(String message, Throwable cause) {
        super(message, cause);
    }
}
