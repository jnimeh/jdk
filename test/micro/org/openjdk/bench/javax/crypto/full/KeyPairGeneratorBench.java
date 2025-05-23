/*
 * Copyright (c) 2015, 2025, Oracle and/or its affiliates. All rights reserved.
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
package org.openjdk.bench.javax.crypto.full;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Setup;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

public class KeyPairGeneratorBench extends CryptoBase {

    private KeyPairGenerator generator;

    @Param({"DSA", "DiffieHellman"})
    private String algorithm;

    @Param({"1024", "2048"})
    private int keyLength;

    @Setup
    public void setup() throws NoSuchAlgorithmException {
        setupProvider();
        generator = (prov == null) ? KeyPairGenerator.getInstance(algorithm)
                                : KeyPairGenerator.getInstance(algorithm, prov);
        if (keyLength > 0) { // not all key pair generators allow the use of key length
            generator.initialize(keyLength);
        }
    }

    @Benchmark
    public KeyPair generateKeyPair() {
        return generator.generateKeyPair();
    }

    public static class RSA extends KeyPairGeneratorBench {

        @Param({"RSA"})
        private String algorithm;

        @Param({"1024", "2048", "3072", "4096"})
        private int keyLength;
    }

    public static class RSASSAPSS extends KeyPairGeneratorBench {

        @Param({"RSASSA-PSS"})
        private String algorithm;

        @Param({"1024", "2048", "3072", "4096"})
        private int keyLength;
    }

    public static class EC extends KeyPairGeneratorBench {

        @Param({"EC"})
        private String algorithm;

        @Param({"256", "384", "521"})
        private int keyLength;
    }

    public static class EdDSA extends KeyPairGeneratorBench {

        @Param({"EdDSA"})
        private String algorithm;

        @Param({"255", "448"})
        private int keyLength;
    }

    public static class XDH extends KeyPairGeneratorBench {

        @Param({"XDH"})
        private String algorithm;

        @Param({"255", "448"})
        private int keyLength;
    }

    public static class MLDSA extends KeyPairGeneratorBench {

        @Param({"ML-DSA-44", "ML-DSA-65", "ML-DSA-87" })
        private String algorithm;

        @Param({"0"}) // ML-DSA key length is not supported
        private int keyLength;
    }

    public static class MLKEM extends KeyPairGeneratorBench {

        @Param({"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024" })
        private String algorithm;

        @Param({"0"}) // ML-KEM key length is not supported
        private int keyLength;
    }

}
