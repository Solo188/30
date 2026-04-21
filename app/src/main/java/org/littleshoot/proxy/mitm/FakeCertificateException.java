package org.littleshoot.proxy.mitm;

/**
 * Thrown when a dynamic (per-domain) certificate cannot be generated.
 */
public class FakeCertificateException extends RuntimeException {

    public FakeCertificateException(String message) {
        super(message);
    }

    public FakeCertificateException(String message, Throwable cause) {
        super(message, cause);
    }
}
