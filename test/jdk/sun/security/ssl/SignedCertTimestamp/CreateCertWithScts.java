/*
 * Copyright (c) 2026, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.*;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.*;

import jdk.test.lib.security.CertificateBuilder;
import jdk.test.lib.security.MockCtLogEntity;

/*
 * @test
 * @bug 8351001
 * @summary Create SCTs to be embedded in certificates or as stand-alone SCTs
 * @modules java.base/sun.security.x509
 *          java.base/sun.security.util
 *          java.base/sun.security.ssl
 * @library /test/lib
 * @build jdk.test.lib.security.MockCtLogEntity jdk.test.lib.security.CertificateBuilder
 * @run main/othervm CreateCertWithScts
 */

public class CreateCertWithScts {

    private static final String KEY_ALG = "EC";
    private static final String KEY_CURVE = "secp384r1";
    // keyUsage bits for CA certs (digitalSignature, keyCertSign, crlSign)
    private static final boolean[] CA_KU_BITS =
            {true, false, false, false, false, true, true, false, false};
    // keyUsage bits for EE certs (digitalSignature only)
    private static final boolean[] EE_KU_BITS =
            {true, false, false, false, false, false, false, false, false};

    //  Convenience record for holding Key and Certificate info.
    public record PKInfo(KeyPair rootKp, X509Certificate rootCert,
            KeyPair intKp, X509Certificate intCert) {
        @Override
        public String toString() {
            return "----- Root CA Cert -----\n" +
                    certSummary(rootCert) +
                    "\n----- Intermediate CA Cert -----\n" +
                    certSummary(intCert);
        }
    }

    public record EEInfo(KeyPair eeKp, X509Certificate eeCert) { }

    private static final Map<byte[], MockCtLogEntity> CTLOGS =
            new TreeMap<>(Arrays::compare);

    public static void main(String[] args) throws Exception {

        // Start off by generating the Root and intermediate CAs, followed
        // by the EE certificate
        PKInfo cas = createCAs();
        System.out.println("Created Certificate Authorities:\n" + cas);

        // Next, create the CT logs that can make SCTs
        for (int i = 0; i < 3; i++) {
            var mklog = new MockCtLogEntity();
            CTLOGS.put(mklog.getLogId(), mklog);
        }

        EEInfo eeNoSct = createEE("No-SCT TLS Server", cas, null);
        System.out.println("----- EE Certificate (No SCTs) -----\n" +
                certSummary(eeNoSct.eeCert));
        EEInfo eeWithSct = createEE("Embedded SCT TLS Server", cas, CTLOGS);
        System.out.println("----- EE Certificate (With SCTs) -----\n" +
                certSummary(eeWithSct.eeCert));
        System.out.println("\n----- Full EE SCT Cert -----\n" +
                eeWithSct.eeCert + "\n");

        System.out.println("CT Logs:");
        CTLOGS.values().forEach(System.out::println);

        // Create 3 X509_SCTs, one from each Mock log
        List<SignedCertificateTimestamp> x509Scts = new ArrayList<>();
        for (var log : CTLOGS.values()) {
            x509Scts.add(log.getX509Sct(eeNoSct.eeCert));
        }

        System.out.println("----- SCTs -----");
        x509Scts.forEach(sct -> System.out.println(sct + "\n"));

        // Print the NO-SCT cert, its key and the SCTs for it so we can
        // use them with Apache.
        HexFormat hf = HexFormat.of().withUpperCase();
        var enc = Base64.getMimeEncoder();
        int eeCertId = x509CertFp(eeNoSct.eeCert);
        System.out.println("TLS Private Key");
        System.out.println("-----BEGIN PRIVATE KEY-----");
        System.out.println(enc.encodeToString(
                eeNoSct.eeKp.getPrivate().getEncoded()));
        System.out.println("-----END PRIVATE KEY-----");
        System.out.println();
        System.out.format("TLS Cert: %s (%08X)\n",
                eeNoSct.eeCert.getSubjectX500Principal(), eeCertId);
        System.out.println("-----BEGIN CERTIFICATE-----");
        System.out.println(enc.encodeToString(eeNoSct.eeCert.getEncoded()));
        System.out.println("-----END CERTIFICATE-----");
        System.out.println();
        System.out.println("Intermediate CA Cert: " +
                cas.intCert.getSubjectX500Principal());
        System.out.println("-----BEGIN CERTIFICATE-----");
        System.out.println(enc.encodeToString(cas.intCert.getEncoded()));
        System.out.println("-----END CERTIFICATE-----");
        System.out.println();
        System.out.println("Root CA Cert: " +
                cas.rootCert.getSubjectX500Principal());
        System.out.println("-----BEGIN CERTIFICATE-----");
        System.out.println(enc.encodeToString(cas.rootCert.getEncoded()));
        System.out.println("-----END CERTIFICATE-----");

        System.out.println("TLS Cert X509_SCTS");
        for (var sct : x509Scts) {
            System.out.format("%08X-%s.sct\n", eeCertId,
                    hf.formatHex(Arrays.copyOf(sct.getLogId(), 8)));
            System.out.format("-----\n%s\n",
                    enc.encodeToString(sct.getEncoded()));
            MockCtLogEntity log = CTLOGS.get(sct.getLogId());
            System.out.format("-----BEGIN PUBLIC KEY-----\n%s\n" +
                    "-----END PUBLIC KEY-----\n\n",
                    enc.encodeToString(log.getLogPubkey().getEncoded()));
        }
    }

    /**
     * Create a root and intermediate CA, along with private keys
     *
     * @return a {@code PKInfo} structure containing the private keys and
     *         certificates for the root and intermediate CAs.
     * @throws GeneralSecurityException if any JCE errors occur during cert
     *         creation.
     * @throws IOException if the key identifiers for the certificates
     *         fail to encode.
     */
    private static PKInfo createCAs() throws GeneralSecurityException,
            IOException {
        CertificateBuilder cbld = new CertificateBuilder();
        KeyPairGenerator caKeyGen = KeyPairGenerator.getInstance(KEY_ALG);
        caKeyGen.initialize(new ECGenParameterSpec(KEY_CURVE));

        // Generate Root, IntCA, EE keys
        KeyPair rootCaKP = caKeyGen.genKeyPair();
        System.out.println("Generated Root CA KeyPair");
        KeyPair intCaKP = caKeyGen.genKeyPair();
        System.out.println("Generated Intermediate CA KeyPair");

        // Set up the Root CA Cert
        // Make a 3-year validity starting from 60 days ago
        long start = System.currentTimeMillis() - TimeUnit.DAYS.toMillis(60);
        long end = start + TimeUnit.DAYS.toMillis(1085);
        X509Certificate rootCert = cbld.
                setSubjectName("CN=Root CA Cert, O=SomeCompany").
                setPublicKey(rootCaKP.getPublic()).
                setSerialNumber(new BigInteger("1")).
                setValidity(new Date(start), new Date(end)).
                addSubjectKeyIdExt(rootCaKP.getPublic()).
                addAuthorityKeyIdExt(rootCaKP.getPublic()).
                addBasicConstraintsExt(true, true, -1).
                addKeyUsageExt(CA_KU_BITS).
                build(null, rootCaKP.getPrivate(), "SHA384withECDSA");

        // Now that we have the root keystore we can create our intermediate CA.
        // Make a 2-year validity starting from 30 days ago
        start = System.currentTimeMillis() - TimeUnit.DAYS.toMillis(30);
        end = start + TimeUnit.DAYS.toMillis(730);
        X509Certificate intCaCert = cbld.reset().
                setSubjectName("CN=Intermediate CA Cert, O=SomeCompany").
                setPublicKey(intCaKP.getPublic()).
                setSerialNumber(new BigInteger("100")).
                setValidity(new Date(start), new Date(end)).
                addSubjectKeyIdExt(intCaKP.getPublic()).
                addAuthorityKeyIdExt(rootCaKP.getPublic()).
                addBasicConstraintsExt(true, true, -1).
                addKeyUsageExt(CA_KU_BITS).
                build(rootCert, rootCaKP.getPrivate(), "SHA384withECDSA");
        return new PKInfo(rootCaKP, rootCert, intCaKP, intCaCert);
    }

    /**
     * Using the intermediate CA certificate from a {@code PKInfo} object,
     * create an end-entity certificate and populate it with one or more
     * AIA access descriptions.
     *
     * @param commonName the common name for the certificate, must not be null
     * @param pki the {@code PKInfo} object used to make the end-entity
     *            certificate.
     * @param ctLogs the map containing the different logs to be used for
     *               embedded SCT generation.
     * @return an {@code EEInfo} object containing the private keys and
     *            end-entity certificate.
     * @throws CertificateException if any issues occur during certificate
     *            building.
     * @throws IOException if any encoding issues occur.
     */
    private static EEInfo createEE(String commonName, PKInfo pki,
            Map<byte[], MockCtLogEntity> ctLogs) throws GeneralSecurityException,
            IOException {
        Objects.requireNonNull(commonName, "Common Name must be supplied");
        // Let's create our EE cert
        KeyPairGenerator eeKeyGen = KeyPairGenerator.getInstance(KEY_ALG);
        eeKeyGen.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair eeKP = eeKeyGen.genKeyPair();
        System.out.println("Generated EE Cert KeyPair");

        // Make a 1-year validity starting from 15 days ago
        long start = System.currentTimeMillis() - TimeUnit.DAYS.toMillis(15);
        long end = start + TimeUnit.DAYS.toMillis(365);

        CertificateBuilder cbld = new CertificateBuilder().
                setSubjectName(String.format("CN=%s, O=SomeCompany",
                        commonName)).
                setPublicKey(eeKP.getPublic()).
                setSerialNumber(new BigInteger("4096")).
                setValidity(new Date(start), new Date(end)).
                addSubjectKeyIdExt(eeKP.getPublic()).
                addAuthorityKeyIdExt(pki.intKp().getPublic()).
                addKeyUsageExt(EE_KU_BITS).
                addExtendedKeyUsageExt(List.of("1.3.6.1.5.5.7.3.1"));
        if (ctLogs != null && !ctLogs.isEmpty()) {
            cbld.addSignedCertTimestampV1Ext(ctLogs.values());
        }
        X509Certificate eeCert = cbld.build(pki.intCert, pki.intKp.getPrivate(),
                "SHA256withECDSA");
        return new EEInfo(eeKP, eeCert);
    }



    /**
     * Helper routine that dumps only a few cert fields rather than
     * the whole toString() output.
     *
     * @param cert an X509Certificate to be displayed
     *
     * @return the String output of the issuer, subject and
     * serial number
     */
    private static String certSummary(X509Certificate cert) {
        return "Issuer: " + cert.getIssuerX500Principal() + "\n" +
                "Subject: " + cert.getSubjectX500Principal() + "\n" +
                "Serial: " + cert.getSerialNumber();
    }

    private static int x509CertFp(X509Certificate cert)
            throws GeneralSecurityException {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        ByteBuffer hashBuf = ByteBuffer.wrap(md.digest(cert.getEncoded()));
        return hashBuf.getInt();
    }
}
