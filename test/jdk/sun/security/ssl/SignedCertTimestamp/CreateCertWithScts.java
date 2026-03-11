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

import static jdk.test.lib.Asserts.assertTrue;
import static jdk.test.lib.Utils.runAndCheckException;

import java.io.IOException;
import java.math.BigInteger;
import java.net.SocketException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.TrustManagerFactory;
import jdk.test.lib.security.CertificateBuilder;
import jdk.test.lib.security.MockCtLogEntity;
import sun.security.x509.AuthorityKeyIdentifierExtension;
import sun.security.x509.GeneralName;
import sun.security.x509.GeneralNames;
import sun.security.x509.KeyIdentifier;
import sun.security.x509.SerialNumber;
import sun.security.x509.X500Name;

/*
 * @test
 * @bug 8351001
 * @summary Create SCTs to be embedded in certificates or as stand-alone SCTs
 * @modules java.base/sun.security.x509
 *          java.base/sun.security.util
 *          java.base/sun.security.ssl
 * @library /test/lib
 * @run main/othervm CreateCertWithScts
 */

public class CreateCertWithScts {

    private static Map<byte[], MockCtLogEntity> CTLOGS = new HashMap<>();

    public static void main(String[] args) throws Exception {
        for (int i = 0; i < 3; i++) {
            var mklog = new MockCtLogEntity();
            CTLOGS.put(mklog.getLogId(), mklog);
        }

        System.out.println("CT Logs:");
        CTLOGS.values().forEach(log -> System.out.println(log));
    }


    // Certificate-building helper methods.

//    private void setupCertificates() throws Exception {
//        KeyPairGenerator kpg = KeyPairGenerator.getInstance(
//                KEY_ALGORITHM);
//        KeyPair caKeys = kpg.generateKeyPair();
//        this.serverKeys = kpg.generateKeyPair();
//        this.clientKeys = kpg.generateKeyPair();
//
//        this.trustedCert = createTrustedCert(caKeys);
//
//        this.serverCert = customCertificateBuilder(
//                "O=Some-Org, L=Some-City, ST=Some-State, C=US",
//                serverKeys.getPublic(), caKeys.getPublic())
//                .addBasicConstraintsExt(false, false, -1)
//                .build(trustedCert, caKeys.getPrivate(), SERVER_CERT_SIG_ALG);
//
//        this.clientCert = customCertificateBuilder(
//                "CN=localhost, OU=SSL-Client, O=Some-Org, L=Some-City, ST=Some-State, C=US",
//                clientKeys.getPublic(), caKeys.getPublic())
//                .addBasicConstraintsExt(false, false, -1)
//                .build(trustedCert, caKeys.getPrivate(), CLIENT_CERT_SIG_ALG);
//    }
//
//    private static CertificateBuilder customCertificateBuilder(
//            String subjectName, PublicKey publicKey, PublicKey caKey)
//            throws CertificateException, IOException {
//        SecureRandom random = new SecureRandom();
//
//        CertificateBuilder builder = new CertificateBuilder()
//                .setSubjectName(subjectName)
//                .setPublicKey(publicKey)
//                .setNotBefore(
//                        Date.from(Instant.now().minus(1, ChronoUnit.HOURS)))
//                .setNotAfter(Date.from(Instant.now().plus(1, ChronoUnit.HOURS)))
//                .setSerialNumber(
//                        BigInteger.valueOf(random.nextLong(1000000) + 1))
//                .addSubjectKeyIdExt(publicKey)
//                .addAuthorityKeyIdExt(caKey);
//        builder.addKeyUsageExt(
//                new boolean[]{true, true, true, true, true, true});
//
//        return builder;
//    }

}
