package org.littleshoot.proxy.mitm;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.bc.BcX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyManagementException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

/**
 * Certificate generation utility — creates root CA and per-domain leaf certs.
 * Adapted from LittleProxy-mitm CertificateHelper for Android (PKCS12 keystore,
 * no sun.* APIs).
 */
public final class CertificateHelper {

    public static final String PROVIDER_NAME = BouncyCastleProvider.PROVIDER_NAME;

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.insertProviderAt(new BouncyCastleProvider(), 1);
        }
    }

    private static final String KEYGEN_ALGORITHM = "RSA";
    private static final String SECURE_RANDOM_ALGORITHM = "SHA1PRNG";

    // SHA256 is safe on Android; no need for 32-bit detection
    private static final String SIGNATURE_ALGORITHM = "SHA256WithRSAEncryption";

    private static final int ROOT_KEYSIZE = 2048;
    // 1024-bit leaf certs are fast; modern TLS requires ≥2048 for some clients.
    // Use 2048 for maximum compatibility.
    private static final int FAKE_KEYSIZE = 2048;

    private static final long ONE_DAY = 86_400_000L;
    private static final Date NOT_BEFORE = new Date(System.currentTimeMillis() - ONE_DAY * 365);
    private static final Date NOT_AFTER  = new Date(System.currentTimeMillis() + ONE_DAY * 365 * 10);

    // Use TLS (not SSLv3) — Android supports TLSv1.2 on API 20+
    private static final String SSL_CONTEXT_PROTOCOL = "TLSv1.2";

    private CertificateHelper() {}

    // -------------------------------------------------------------------------
    //  Key generation
    // -------------------------------------------------------------------------

    public static KeyPair generateKeyPair(int keySize)
            throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(KEYGEN_ALGORITHM);
        SecureRandom random = new SecureRandom();
        generator.initialize(keySize, random);
        return generator.generateKeyPair();
    }

    // -------------------------------------------------------------------------
    //  Root CA creation
    // -------------------------------------------------------------------------

    /**
     * Generates a self-signed root CA certificate and returns a PKCS12 KeyStore
     * containing the private key + certificate.
     */
    public static KeyStore createRootCertificate(Authority authority, String keyStoreType)
            throws NoSuchAlgorithmException, NoSuchProviderException, IOException,
                   OperatorCreationException, CertificateException, KeyStoreException {

        KeyPair keyPair = generateKeyPair(ROOT_KEYSIZE);

        X500NameBuilder nameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
        nameBuilder.addRDN(BCStyle.CN, authority.commonName());
        nameBuilder.addRDN(BCStyle.O,  authority.organization());
        nameBuilder.addRDN(BCStyle.OU, authority.organizationalUnitName());

        X500Name issuer = nameBuilder.build();
        BigInteger serial = BigInteger.valueOf(initRandomSerial());
        PublicKey pubKey = keyPair.getPublic();

        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuer, serial, NOT_BEFORE, NOT_AFTER, issuer, pubKey);

        builder.addExtension(Extension.subjectKeyIdentifier, false,
                createSubjectKeyIdentifier(pubKey));
        builder.addExtension(Extension.basicConstraints, true,
                new BasicConstraints(true));

        KeyUsage usage = new KeyUsage(
                KeyUsage.keyCertSign | KeyUsage.digitalSignature |
                KeyUsage.keyEncipherment | KeyUsage.dataEncipherment | KeyUsage.cRLSign);
        builder.addExtension(Extension.keyUsage, false, usage);

        ASN1EncodableVector purposes = new ASN1EncodableVector();
        purposes.add(KeyPurposeId.id_kp_serverAuth);
        purposes.add(KeyPurposeId.id_kp_clientAuth);
        purposes.add(KeyPurposeId.anyExtendedKeyUsage);
        builder.addExtension(Extension.extendedKeyUsage, false, new DERSequence(purposes));

        X509Certificate cert = signCertificate(builder, keyPair.getPrivate());

        KeyStore ks = KeyStore.getInstance(keyStoreType);
        ks.load(null, null);
        ks.setKeyEntry(authority.alias(), keyPair.getPrivate(),
                authority.password(), new Certificate[]{cert});
        return ks;
    }

    // -------------------------------------------------------------------------
    //  Per-domain leaf certificate
    // -------------------------------------------------------------------------

    /**
     * Generates a leaf certificate for {@code commonName} signed by the root CA.
     * The resulting PKCS12 keystore contains the leaf key + full chain.
     */
    public static KeyStore createServerCertificate(
            String commonName,
            SubjectAlternativeNameHolder subjectAlternativeNames,
            Authority authority,
            Certificate caCert,
            PrivateKey caPrivKey)
            throws NoSuchAlgorithmException, NoSuchProviderException, IOException,
                   OperatorCreationException, CertificateException,
                   InvalidKeyException, SignatureException, KeyStoreException {

        KeyPair keyPair = generateKeyPair(FAKE_KEYSIZE);

        X500Name issuer = new X509CertificateHolder(caCert.getEncoded()).getSubject();
        BigInteger serial = BigInteger.valueOf(initRandomSerial());

        X500NameBuilder name = new X500NameBuilder(BCStyle.INSTANCE);
        name.addRDN(BCStyle.CN, commonName);
        name.addRDN(BCStyle.O,  authority.certOrganisation());
        name.addRDN(BCStyle.OU, authority.certOrganizationalUnitName());
        X500Name subject = name.build();

        // Leaf cert valid for 1 day past now (short-lived is fine for MITM)
        Date notAfter = new Date(System.currentTimeMillis() + ONE_DAY * 825);
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuer, serial, NOT_BEFORE, notAfter, subject, keyPair.getPublic());

        builder.addExtension(Extension.subjectKeyIdentifier, false,
                createSubjectKeyIdentifier(keyPair.getPublic()));
        builder.addExtension(Extension.basicConstraints, false,
                new BasicConstraints(false));

        subjectAlternativeNames.fillInto(builder);

        X509Certificate cert = signCertificate(builder, caPrivKey);
        cert.checkValidity(new Date());
        cert.verify(caCert.getPublicKey());

        KeyStore result = KeyStore.getInstance("PKCS12");
        result.load(null, null);
        Certificate[] chain = {cert, caCert};
        result.setKeyEntry(authority.alias(), keyPair.getPrivate(),
                authority.password(), chain);
        return result;
    }

    // -------------------------------------------------------------------------
    //  SSL context factories
    // -------------------------------------------------------------------------

    public static SSLContext newClientContext(KeyManager[] keyManagers, TrustManager[] trustManagers)
            throws NoSuchAlgorithmException, KeyManagementException {
        SSLContext ctx = newSSLContext();
        ctx.init(keyManagers, trustManagers, null);
        return ctx;
    }

    public static SSLContext newServerContext(KeyManager[] keyManagers)
            throws NoSuchAlgorithmException, KeyManagementException {
        SSLContext ctx = newSSLContext();
        ctx.init(keyManagers, null, null);
        return ctx;
    }

    private static SSLContext newSSLContext() throws NoSuchAlgorithmException {
        try {
            return SSLContext.getInstance(SSL_CONTEXT_PROTOCOL);
        } catch (NoSuchAlgorithmException e) {
            return SSLContext.getInstance("TLS");
        }
    }

    // -------------------------------------------------------------------------
    //  Key / trust manager factories
    // -------------------------------------------------------------------------

    public static KeyManager[] getKeyManagers(KeyStore keyStore, Authority authority)
            throws NoSuchAlgorithmException, UnrecoverableKeyException, KeyStoreException {
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(
                KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, authority.password());
        return kmf.getKeyManagers();
    }

    public static TrustManager[] getTrustManagers(KeyStore keyStore)
            throws KeyStoreException, NoSuchAlgorithmException {
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(
                TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(keyStore);
        return tmf.getTrustManagers();
    }

    // -------------------------------------------------------------------------
    //  Internals
    // -------------------------------------------------------------------------

    private static SubjectKeyIdentifier createSubjectKeyIdentifier(Key key) throws IOException {
        try (ByteArrayInputStream bIn = new ByteArrayInputStream(key.getEncoded());
             ASN1InputStream is = new ASN1InputStream(bIn)) {
            ASN1Sequence seq = (ASN1Sequence) is.readObject();
            SubjectPublicKeyInfo info = SubjectPublicKeyInfo.getInstance(seq);
            return new BcX509ExtensionUtils().createSubjectKeyIdentifier(info);
        }
    }

    private static X509Certificate signCertificate(
            X509v3CertificateBuilder builder, PrivateKey privateKey)
            throws OperatorCreationException, CertificateException {
        ContentSigner signer = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM)
                .setProvider(PROVIDER_NAME)
                .build(privateKey);
        return new JcaX509CertificateConverter()
                .setProvider(PROVIDER_NAME)
                .getCertificate(builder.build(signer));
    }

    static long initRandomSerial() {
        final SecureRandom random = new SecureRandom();
        // Use only positive longs for serial numbers
        return Math.abs(random.nextLong());
    }
}
