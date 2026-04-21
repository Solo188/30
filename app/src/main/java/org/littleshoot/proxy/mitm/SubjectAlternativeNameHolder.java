package org.littleshoot.proxy.mitm;

import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.asn1.x509.Extension;

import java.io.IOException;
import java.security.cert.CertificateParsingException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * Collects Subject Alternative Names (SANs) from an upstream certificate
 * and copies them into the dynamically generated leaf certificate so that
 * modern browsers / apps accept the spoofed cert.
 */
public class SubjectAlternativeNameHolder {

    /** OID integer codes matching {@link GeneralName} constants. */
    private static final int DNS_NAME = GeneralName.dNSName;
    private static final int IP_ADDRESS = GeneralName.iPAddress;

    private final List<GeneralName> sans = new ArrayList<>();

    /**
     * Add SANs from the upstream certificate's
     * {@link java.security.cert.X509Certificate#getSubjectAlternativeNames()} output.
     *
     * @param upstreamSans collection of [type, value] pairs, may be null
     */
    public void addAll(Collection<List<?>> upstreamSans) throws CertificateParsingException {
        if (upstreamSans == null) return;
        for (List<?> entry : upstreamSans) {
            if (entry == null || entry.size() < 2) continue;
            int type = (Integer) entry.get(0);
            String value = String.valueOf(entry.get(1));
            if (type == DNS_NAME) {
                sans.add(new GeneralName(GeneralName.dNSName, value));
            } else if (type == IP_ADDRESS) {
                sans.add(new GeneralName(GeneralName.iPAddress, value));
            }
            // Other types (email, URI, etc.) are skipped — not needed for TLS.
        }
    }

    /**
     * Convenience method: add a single DNS SAN.
     */
    public void addDnsName(String dnsName) {
        sans.add(new GeneralName(GeneralName.dNSName, dnsName));
    }

    /**
     * Inject all collected SANs into the certificate builder.
     * No-op if there are no SANs.
     */
    public void fillInto(X509v3CertificateBuilder builder) throws IOException {
        if (sans.isEmpty()) return;
        GeneralName[] array = sans.toArray(new GeneralName[0]);
        GeneralNames names = new GeneralNames(array);
        builder.addExtension(Extension.subjectAlternativeName, false, names);
    }

    @Override
    public String toString() {
        return sans.toString();
    }
}
