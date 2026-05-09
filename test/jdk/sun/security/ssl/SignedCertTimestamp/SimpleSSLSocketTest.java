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

/*
 * @test
 * @bug 8351001
 * @summary Create SCTs to be embedded in certificates or as stand-alone SCTs
 * @modules java.base/sun.security.x509
 *          java.base/sun.security.util
 *          java.base/sun.security.ssl
 * @library /test/lib
 * @run main/othervm -Djavax.net.debug=ssl:handshake,verbose SimpleSSLSocketTest
 */

import javax.net.ssl.*;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

public class SimpleSSLSocketTest {


    private static final Map<byte[], PublicKey> CTLOGS;

    // Populate the CTLOGS with public/private keys
    static {
        try {
            Base64.Decoder b64dec = Base64.getDecoder();
            CF = CertificateFactory.getInstance("X.509");
            PUBKF = KeyFactory.getInstance("EC");

            Map<byte[], PublicKey> JTESTLOGS = new TreeMap<>(Arrays::compare) {{
                // Logs for making precert entries
                put(b64dec.decode("XPKThOWtgOjiz37oKFxTQzgel/R8gCFSaCsohHId32Y="),
                    genPublicKey("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE+gFYw2" +
                            "ksPQaaFImnDQpburIfBSO3eP35RIPuiSobIVwxEmM7IWCLY" +
                            "L3t9qKalqhV3O+hfkPQEL0Znk+3JV2E5Q=="));
                put(b64dec.decode("SV9WIXmC1XXJbVYdmgmb+RgzHxpBrstl8NZKnUqQ2T0="),
                    genPublicKey("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXRsQ+p" +
                            "gQEO3O/aboPEjHvCwm8xGNBNMrAyb35qJ/nwglNQjeLWxTD" +
                            "yhPsZBpLSAIli/iUK5dhz5kzlHlJoycBQ=="));
                put(b64dec.decode("pMyLkhTxOzFy4HWL48RvK4MzoiZ55UnVdmJ5h4ohn4k="),
                    genPublicKey("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYFh4B6" +
                            "AQ1rw6tnHMKdv+dxgPkOlSe8lHy67uY4D3Bd0GnQ0yGhAc8" +
                            "dU4U3BTen8vTcHmyhFUTc8Elq3Xwunzfg=="));

                // Logs for making x509 cert entries
                put(b64dec.decode("xf7x+FdFhpstXDD1ocpoiljrtyQA5kKfejzijQJkRAo="),
                        genPublicKey("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEMx" +
                                "qPYddM6rwDc70X0vP9hOcKfS8LP9nbSY34wV4RlAYIP" +
                                "dzbEaJZs1lscAMCvVAj0O7Zj1nAutmG35NQZLYGbg=="));
                put(b64dec.decode("3Or27o+BE1yqBfWjC35JhNHBJ2uOoB/RcBCZOZ7QYzo="),
                        genPublicKey("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQI" +
                                "4MyvZZHeMxOLTjbUxq3nFrl22jBO5pefGYdkdY+WwOo" +
                                "PvlmAutRQaYB2JyQ8qZC/AT660r00kIHS+jys6rJg=="));
                put(b64dec.decode("RVi2AOJ7zVtKl2aJJO3WBYOwAi5fWtkeXaorNI5xhtE="),
                        genPublicKey("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE45" +
                                "OCWZ3W/OC5ETrTZls0J+I7R6R9m9BJyjrPy6564RZ5M" +
                                "uDdWmY7V50IWjJL6jeXKOFiU8j1BHBytVs1pM+XJg=="));
            }};

            Map<byte[], PublicKey> GOOGLOGS = new TreeMap<>(Arrays::compare) {{
                put(b64dec.decode("lpdkv1VYl633Q4doNwhCd+nwOtX2pPM2bkakPw/KqcY="),
                    genPublicKey("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEOh/Iu8" +
                            "7VkEc0ysoBBCchHOIpPZK7kUXHWj6l1PIS5ujmQ7rze8I4r" +
                            "/wjigVW6wMKMMxjbNk8vvV7lLqU07+ITA=="));
                put(b64dec.decode("SZybad4dfOz8Nt7Nh2SmuFuvCoeAGdFVUvvp6ynd+MM="),
                    genPublicKey("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEq4S++D" +
                            "yHokIlmmacritS51r5IRsZA6UH4kYLH4pefGyu/xl3huh7/" +
                            "O5rNk/yvMOeBQKaCAG1SSM1xNNQK1Hp9A=="));
                put(b64dec.decode("FoMtq/CpJQ8P8DqlRf/Iv8gj0IdL9gQpJ/jnHzMT9fo="),
                        genPublicKey("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE73" +
                                "eDJyszDbzsWcgI0nbtU0+y11gQWjNjS/RSO5P4hOSFE" +
                                "+pPrDCtfNPHe6dq7/XQYwOFt9Feb8TwQW+mqXN5xg=="));
            }};

            CTLOGS = JTESTLOGS;
        } catch (GeneralSecurityException genSecExc) {
            throw new RuntimeException(genSecExc);
        }
    }

    private static final CertificateFactory CF;
    private static final KeyFactory PUBKF;
    private static final HexFormat HF = HexFormat.of().withUpperCase();
    private static final String PASS = "adminadmin0";

    public static void main(String[] args) throws Exception {

        System.out.println("----- CT Logs -----");
        CTLOGS.forEach((id, pk) -> {
            System.out.format("ID: %s\nPUBKEY: %s\n", HF.formatHex(id), pk);
        });
        System.out.println("--------------------");

        TrustManagerFactory tmf = createTrustManagerFactory(
                "/home/jjnimeh/testcode/kstest/trustdb.p12");
//                "/home/jjnimeh/testcode/kstest/othercas.p12");
        SSLContext sslc = SSLContext.getInstance("TLS");
        sslc.init(null, tmf.getTrustManagers(), new SecureRandom());

        // Okay, let's make a connection!
        SSLSocketFactory sslSf = sslc.getSocketFactory();
        try (SSLSocket sslSock = (SSLSocket)sslSf.createSocket(
//                "www.google.com", 443)) {
                "mustafar.pkigeek.org", 443)) {
            sslSock.getOutputStream().write("GET / HTTP/1.1\r\n".getBytes(
                    StandardCharsets.UTF_8));

            SSLSession sess = sslSock.getSession();
            System.out.println("Obtained SSLSession: " +
                               sess.getClass().getName() + ": " + sess);
            if (sess instanceof ExtendedSSLSession extSess) {
                X509Certificate[] srvCerts =
                        (X509Certificate[])extSess.getPeerCertificates();
                Map<X509Certificate, Set<CertTransElement>> sctMap =
                        extSess.getCertTransElements();

                for (int i = 0; i < srvCerts.length; i++) {
                    X509Certificate subj = srvCerts[i];
                    X509Certificate iss = (i == srvCerts.length - 1) ?
                            srvCerts[i] : srvCerts[i + 1];
                    Set<CertTransElement> cteSet =
                            sctMap.getOrDefault(subj, Collections.emptySet());

                    System.out.println(subj.getSubjectX500Principal());
                    System.out.println("--------------------------");
                    cteSet.forEach(cte -> {
                        if (cte instanceof SignedCertificateTimestamp sct) {
                            System.out.println(sct);
                            System.out.print("=== Verified: ");
                            byte[] logId = sct.getLogId();
                            PublicKey logKey = CTLOGS.get(logId);
                            if (logKey != null) {
                                try {
                                    if (sct.verify(subj, iss.getPublicKey(),
                                            logKey)) {
                                        System.out.println("PASS");
                                    } else {
                                        System.out.println("FAIL " +
                                           "(Signature verification error)");
                                    }
                                } catch (SignatureException se) {
                                    System.out.println("FAIL (Verify error)");
                                }
                            } else {
                                System.out.println("FAIL " +
                                       "(missing key for log ID)");
                            }
                        }
                    });
                    System.out.println("--------------------------");
                }
            } else {
                System.out.println("We're done, not an ExtendedSSLSession");
            }
        }
    }

    private static X509Certificate genCertificate(String pemCert)
            throws IOException, GeneralSecurityException {
        try (ByteArrayInputStream bais = new ByteArrayInputStream(
                pemCert.getBytes(StandardCharsets.UTF_8))) {
            return (X509Certificate)CF.generateCertificate(bais);
        }
    }

    private static PublicKey genPublicKey(String pemKey)
            throws InvalidKeySpecException {
        Base64.Decoder b64d = Base64.getMimeDecoder();
        return PUBKF.generatePublic(new X509EncodedKeySpec(
                b64d.decode(pemKey)));
    }

    private static TrustManagerFactory createTrustManagerFactory(
            String trustStorePath) throws IOException,
            GeneralSecurityException {
        TrustManagerFactory tmf = null;
        KeyStore trustKs = KeyStore.getInstance(new File(trustStorePath),
                PASS.toCharArray());
        PKIXBuilderParameters pkixParams =
                new PKIXBuilderParameters(trustKs, null);
        return createTmCommon(pkixParams);
    }

    private static TrustManagerFactory createTrustManagerFactory(
            List<X509Certificate> anchorCerts) throws IOException,
            GeneralSecurityException {
        TrustManagerFactory tmf = null;

        Set<TrustAnchor> anchors = new HashSet<>();
        anchorCerts.forEach(aCert -> anchors.add(new TrustAnchor(aCert, null)));
        PKIXBuilderParameters pkixParams = new PKIXBuilderParameters(anchors,
                new X509CertSelector());
        return createTmCommon(pkixParams);
    }

    private static TrustManagerFactory createTmCommon(
            PKIXBuilderParameters pkixParams) throws NoSuchAlgorithmException,
            InvalidAlgorithmParameterException {
        pkixParams.setRevocationEnabled(false);

        // Register the PKIXParameters with the trust manager factory
        ManagerFactoryParameters trustParams =
                new CertPathTrustManagerParameters(pkixParams);

        // Create the Trust Manager Factory using the PKIX variant
        // and initialize it with the parameters configured above
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");
        tmf.init(trustParams);

        return tmf;
    }
}
