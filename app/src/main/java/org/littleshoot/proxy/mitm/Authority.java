package org.littleshoot.proxy.mitm;

import java.io.File;

/**
 * Parameter object holding CA and certificate identity information.
 * Adapted from LittleProxy-mitm for use in Android app storage.
 */
public class Authority {

    private final File keyStoreDir;
    private final String alias;
    private final char[] password;
    private final String commonName;
    private final String organization;
    private final String organizationalUnitName;
    private final String certOrganization;
    private final String certOrganizationalUnitName;

    /** Default Authority — for use in tests only. */
    public Authority() {
        keyStoreDir = new File(".");
        alias = "adblocker-mitm";
        password = "AdBlockerCA2024".toCharArray();
        organization = "AdBlocker";
        commonName = "AdBlocker Root CA";
        organizationalUnitName = "Certificate Authority";
        certOrganization = organization;
        certOrganizationalUnitName = "AdBlocker MITM";
    }

    /**
     * Full constructor — use this to store the keystore in Android app storage.
     *
     * @param keyStoreDir  directory where the .p12 and .pem files are stored
     *                     (pass {@code context.getFilesDir()})
     */
    public Authority(File keyStoreDir, String alias, char[] password,
                     String commonName, String organization,
                     String organizationalUnitName, String certOrganization,
                     String certOrganizationalUnitName) {
        this.keyStoreDir = keyStoreDir;
        this.alias = alias;
        this.password = password;
        this.commonName = commonName;
        this.organization = organization;
        this.organizationalUnitName = organizationalUnitName;
        this.certOrganization = certOrganization;
        this.certOrganizationalUnitName = certOrganizationalUnitName;
    }

    public File aliasFile(String fileExtension) {
        return new File(keyStoreDir, alias + fileExtension);
    }

    public String alias() { return alias; }
    public char[] password() { return password; }
    public String commonName() { return commonName; }
    public String organization() { return organization; }
    public String organizationalUnitName() { return organizationalUnitName; }
    public String certOrganisation() { return certOrganization; }
    public String certOrganizationalUnitName() { return certOrganizationalUnitName; }
}
