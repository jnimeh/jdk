/*
 * Copyright (c) 2017, Oracle and/or its affiliates. All rights reserved.
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

/**
 * @test
 * @bug 6537039
 * @summary Add support for Camellia cipher algorithm
 */

import java.util.*;
import java.io.*;
import javax.crypto.SecretKey;
import java.security.SecureRandom;
import java.security.GeneralSecurityException;
import javax.crypto.Cipher;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.AEADBadTagException;
import java.nio.ByteBuffer;

public class CamelliaKAT {

    public enum ModeOfOp {
        ECB,                    // Electronic Codebook
        CBC,                    // Cipher Block Chaining
        CFB,                    // Cipher-Feedback
        OFB,                    // Output-Feedback
        CTR,                    // Counter Mode
        GCM                     // Galois Counter Mode
    }

    // Test vector file constants
    public static final String TEST_NAME = "TEST_NAME";
    public static final String KEY_TAG = "KEY";
    public static final String PT_TAG = "PLAINTEXT";
    public static final String CT_TAG = "CIPHERTEXT";
    public static final String IV_TAG = "IV";
    public static final String AAD_TAG = "AAD";
    public static final String TAG_TAG = "TAG";

    public static final byte[] YAK = new byte[16];

    // Test vector files
    public static final String ECB_VEC_FILE =
            System.getProperty("test.src", ".") + "/" + "camellia-ecb.txt";
    public static final String CBC_VEC_FILE =
            System.getProperty("test.src", ".") + "/" + "camellia-cbc.txt";
    public static final String CFB_VEC_FILE =
            System.getProperty("test.src", ".") + "/" + "camellia-cfb.txt";
    public static final String OFB_VEC_FILE =
            System.getProperty("test.src", ".") + "/" + "camellia-ofb.txt";
    public static final String CTR_VEC_FILE =
            System.getProperty("test.src", ".") + "/" + "camellia-ctr.txt";
    public static final String GCM_VEC_FILE =
            System.getProperty("test.src", ".") + "/" + "camellia-gcm.txt";

    // Other goodies
    public static final SecureRandom rand = new SecureRandom();

    public static class TestCase {
        ModeOfOp mode;
        public final Map<String, String> params = new HashMap<>();
    }

    public static void main(String args[]) throws Exception {
        int testsPassed = 0;
        int testNumber = 0;

        Map<ModeOfOp, List<TestCase>> allTests = new LinkedHashMap<>();
        allTests.put(ModeOfOp.ECB,
                addTestsFromFile(ModeOfOp.ECB, ECB_VEC_FILE));
        allTests.put(ModeOfOp.CBC,
                addTestsFromFile(ModeOfOp.CBC, CBC_VEC_FILE));
        allTests.put(ModeOfOp.CFB,
                addTestsFromFile(ModeOfOp.CFB, CFB_VEC_FILE));
        allTests.put(ModeOfOp.OFB,
                addTestsFromFile(ModeOfOp.OFB, OFB_VEC_FILE));
        allTests.put(ModeOfOp.CTR,
                addTestsFromFile(ModeOfOp.CTR, CTR_VEC_FILE));
        allTests.put(ModeOfOp.GCM,
                addTestsFromFile(ModeOfOp.GCM, GCM_VEC_FILE));
//        TestCase tc = new TestCase();
//        tc.params.put(TEST_NAME, "SP DEC CFB");
//        tc.params.put(KEY_TAG, "2B7E151628AED2A6ABF7158809CF4F3C");
//        tc.params.put(IV_TAG, "000102030405060708090A0B0C0D0E0F");
//        tc.params.put(PT_TAG, "6BC1BEE22E409F96E93D7E117393172A");
//        tc.params.put(CT_TAG, "14F7646187817EB586599146B82BD719");
//        if (!runDecCfb(tc)) {
//            throw new RuntimeException("runDec barfed!");
//        }

        // Run Single-Part tests
        for (ModeOfOp testKey : allTests.keySet()) {
            List<TestCase> modeList = allTests.get(testKey);

            System.out.format("----- Single-part %s Tests -----\n",
                    testKey.toString());
            for (TestCase test : modeList) {
                System.out.println("*** Test " + ++testNumber + ": " +
                        test.params.get(TEST_NAME));
                if (runSinglePartTest(test)) {
                    testsPassed++;
                }
            }
            System.out.println();
        }

        System.out.println("Total tests: " + testNumber +
                ", Passed: " + testsPassed + ", Failed: " +
                (testNumber - testsPassed));
        if (testsPassed != testNumber) {
            throw new RuntimeException("One or more tests failed.  " +
                    "Check output for details");
        }
    }

    private static List<TestCase> addTestsFromFile(ModeOfOp mode,
            String fileName) throws IOException,
            GeneralSecurityException {
        List<TestCase> testList = new ArrayList<>();
        try (FileInputStream fis = new FileInputStream(fileName);
                BufferedReader reader = new BufferedReader(
                        new InputStreamReader(fis))) {
            int testNo = 1;
            TestCase tc = new TestCase();
            String line;

            while ((line = reader.readLine()) != null) {
                String trimmedLine = line.trim();
                int idxComment = trimmedLine.indexOf("#");
                String cleanLine = (idxComment >= 0) ?
                        trimmedLine.substring(0, idxComment) : trimmedLine;
                String[] nameValPair = cleanLine.split(":", 2);
                if (nameValPair.length == 2) {
                    tc.params.put(nameValPair[0], nameValPair[1]);
//                    System.out.format("Added %s = %s\n", nameValPair[0],
//                            nameValPair[1]);
                }

                switch (mode) {
                    case ECB:
                        if ((tc.params.get(KEY_TAG) != null) &&
                            (tc.params.get(PT_TAG) != null) &&
                            (tc.params.get(CT_TAG) != null)) {
                            tc.params.put(TEST_NAME,
                                    String.format("%s Test %d",
                                    mode.toString(), testNo++));
                            tc.mode = mode;
                            // Preserve the key until explicitly changed
                            String saveKey = tc.params.get(KEY_TAG);
                            testList.add(tc);
                            tc = new TestCase();
                            tc.params.put(KEY_TAG, saveKey);
                        }
                        break;
                    case CBC:
                    case CFB:
                    case OFB:
                    case CTR:
                        // All three of these take key, iv, plaintext and
                        // ciphertext.
                        if ((tc.params.get(KEY_TAG) != null) &&
                            (tc.params.get(IV_TAG) != null) &&
                            (tc.params.get(PT_TAG) != null) &&
                            (tc.params.get(CT_TAG) != null)) {
                            tc.params.put(TEST_NAME,
                                    String.format("%s Test %d",
                                    mode.toString(), testNo++));
                            tc.mode = mode;
                            testList.add(tc);
                            tc = new TestCase();
                        }
                        break;
                    case GCM:
                        // If AAD_TAG is missing that's OK, we just
                        // have no AAD info to process at test time.
                        if ((tc.params.get(KEY_TAG) != null) &&
                            (tc.params.get(IV_TAG) != null) &&
                            (tc.params.get(PT_TAG) != null) &&
                            (tc.params.get(CT_TAG) != null) &&
                            (tc.params.get(TAG_TAG) != null)) {
                            tc.params.put(TEST_NAME,
                                    String.format("%s Test %d",
                                    mode.toString(), testNo++));
                            tc.mode = mode;
                            testList.add(tc);
                            tc = new TestCase();
                        }
                        break;
                    default:
                        throw new RuntimeException("Unknown mode: " +
                                mode.toString());
                }
            }
        }

        return testList;
    }

    public static boolean runSinglePartTest(TestCase test)
            throws GeneralSecurityException {
        boolean encResult = false;
        boolean decResult = false;
        byte[] encryptedResult;
        byte[] decryptedResult;
        byte[] testiv;
        byte[] testTag = null;                  // Used only for GCM tests
        byte[] testaad = null;                  // Used only for GCM tests
        AlgorithmParameterSpec params = null;

        // Put the key into SecretKey form
        byte[] keyBytes = hex2bin(Objects.requireNonNull(
                test.params.get(KEY_TAG), "null key found"));
        SecretKey testKey = new SecretKeySpec(keyBytes, "Camellia");
        byte[] plaintext = hex2bin(Objects.requireNonNull(
                test.params.get(PT_TAG), "null plaintext found"));

        // Create and init the cipher
        // The padding must be PKCS5Padding if the plaintext doesn't fall
        // on a block size boundary and is not CTR or GCM.
        String padding = ((plaintext.length % 16 == 0) ||
                (test.mode == ModeOfOp.CTR || test.mode == ModeOfOp.GCM)) ?
                "NoPadding" : "PKCS5Padding";
        String xform = String.format("Camellia/%s/%s",
                test.mode.toString(), padding);
        Cipher cam = Cipher.getInstance(xform);
        switch (test.mode) {
            case ECB:
                cam.init(Cipher.ENCRYPT_MODE, testKey);
                break;
            case CBC:
            case CFB:
            case OFB:
            case CTR:
                // All of these init using an IvParameterSpec
                testiv = hex2bin(Objects.requireNonNull(
                        test.params.get(IV_TAG), "null iv found"));
                params = new IvParameterSpec(testiv);
                cam.init(Cipher.ENCRYPT_MODE, testKey, params);
                break;
            case GCM:
                testiv = hex2bin(Objects.requireNonNull(
                        test.params.get(IV_TAG), "null iv found"));
                testTag = hex2bin(Objects.requireNonNull(
                        test.params.get(TAG_TAG), "null tag found"));
                params = new GCMParameterSpec(testTag.length * 8, testiv);
                cam.init(Cipher.ENCRYPT_MODE, testKey, params);
                if (test.params.containsKey(AAD_TAG)) {
                    testaad = hex2bin(Objects.requireNonNull(
                            test.params.get(AAD_TAG), "null aad found"));
                    cam.updateAAD(testaad);
                }
                break;
        }

        // Put the other test data into byte[] form:
        byte[] baseCt = hex2bin(Objects.requireNonNull(
                test.params.get(CT_TAG), "null ciphertext found"));
        byte[] expCiphertext = new byte[cam.getOutputSize(plaintext.length)];
        System.arraycopy(baseCt, 0, expCiphertext, 0, plaintext.length);
        if (test.mode == ModeOfOp.GCM && testTag != null) {
            System.arraycopy(testTag, 0, expCiphertext, plaintext.length,
                    testTag.length);
        }

        encryptedResult = cam.doFinal(plaintext);

        if (!Arrays.equals(encryptedResult, expCiphertext)) {
            System.out.println("ERROR - Encrypt Output Mismatch!");
            System.out.println("Expected:\n" +
                    dumpHexBytes(expCiphertext, 16, "\n", " "));
            System.out.println("Actual:\n" +
                    dumpHexBytes(encryptedResult, 16, "\n", " "));
            System.out.println();
        } else {
            encResult = true;
        }

        // Decrypt the result, make sure you can get original PT back
        if (params != null) {
            cam.init(Cipher.DECRYPT_MODE, testKey, params);
            if (test.mode == ModeOfOp.GCM && testaad != null) {
                cam.updateAAD(testaad);
            }
        } else {
            cam.init(Cipher.DECRYPT_MODE, testKey);
        }

        try {
            decryptedResult = cam.doFinal(encryptedResult);

            if (!Arrays.equals(decryptedResult, plaintext)) {
                System.out.println("ERROR - Decrypt Output Mismatch!");
                System.out.println("Expected:\n" +
                        dumpHexBytes(plaintext, 16, "\n", " "));
                System.out.println("Actual:\n" +
                        dumpHexBytes(decryptedResult, 16, "\n", " "));
                System.out.println();
            } else {
                decResult = true;
            }
        } catch (AEADBadTagException abte) {
            System.out.println("ERROR - Bad tag");
        }

        return (encResult && decResult);
    }

//    private static boolean runDecCfb(TestCase test) throws Exception {
//        boolean result = false;
//
//        // Put the key into SecretKey form
//        byte[] keyBytes = hex2bin(Objects.requireNonNull(
//                test.params.get(KEY_TAG), "null key found"));
//        SecretKey testKey = new SecretKeySpec(keyBytes, "Camellia");
//
//        // Create and init the cipher
//        String xform = "Camellia/CFB/NoPadding";
//        Cipher cam = Cipher.getInstance(xform);
//        // All of these init using an IvParameterSpec
//        byte[] testiv = hex2bin(Objects.requireNonNull(
//                test.params.get(IV_TAG), "null iv found"));
//        AlgorithmParameterSpec params = new IvParameterSpec(testiv);
//        cam.init(Cipher.DECRYPT_MODE, testKey, params);
//
//        // Put the other test data into byte[] form:
//        byte[] plaintext = hex2bin(Objects.requireNonNull(
//                test.params.get(PT_TAG), "null plaintext found"));
//        byte[] ciphertext = hex2bin(Objects.requireNonNull(
//                test.params.get(CT_TAG), "null ciphertext found"));
//        byte[] decRes = cam.doFinal(ciphertext);
//
//        if (!Arrays.equals(decRes, plaintext)) {
//            System.out.println("ERROR - Encrypt Output Mismatch!");
//            System.out.println("Expected:\n" +
//                    dumpHexBytes(plaintext, 16, "\n", " "));
//            System.out.println("Actual:\n" +
//                    dumpHexBytes(decRes, 16, "\n", " "));
//            System.out.println();
//        } else {
//            System.out.println("Pass!");
//            result = true;
//        }
//
//        return result;
//    }

//    private static boolean runSinglePartTest(TestData testData)
//            throws GeneralSecurityException {
//        boolean result = false;
//        byte[] encryptedResult;
//
//        // For each test instance, build a transform and instantiate the
//        // Cipher.
//        String transform = String.format("Camellia/%s/%s",
//                testData.mode, testData.padding);
//        Cipher camCipher = Cipher.getInstance(transform, "SunJCE");
//
//        // Depending on the cipher, we may need to init with special
//        // parameters
//        SecretKeySpec camKey = new SecretKeySpec(testData.key, "Camellia");
//        if (testData.mode.equals("ECB")) {
//            camCipher.init(testData.direction, camKey);
//        } else {
//            throw new UnsupportedOperationException("Mode not supported yet");
//        }
//
//        // Encrypt our input
//        encryptedResult = camCipher.doFinal(testData.input);
//
//        if (!Arrays.equals(encryptedResult, testData.expOutput)) {
//            System.out.println("ERROR - Output Mismatch!");
//            System.out.println("Expected:\n" +
//                    dumpHexBytes(testData.expOutput, 16, "\n", " "));
//            System.out.println("Actual:\n" +
//                    dumpHexBytes(encryptedResult, 16, "\n", " "));
//            System.out.println();
//        } else {
//            result = true;
//        }
//
//        return result;
//    }
//
//    private static boolean runMultiPartTest(TestData testData)
//            throws GeneralSecurityException {
//        boolean encRes = false;
//        boolean decRes = false;
//
//        // Get a cipher instance and initialize it
//        Cipher mambo = Cipher.getInstance("ChaCha20");
//        SecretKeySpec mamboKey = new SecretKeySpec(testData.key, "ChaCha20");
//        ChaCha20ParameterSpec mamboSpec = new ChaCha20ParameterSpec(
//                testData.nonce, testData.counter);
//
//        byte[] encryptedResult = new byte[testData.input.length];
//        mambo.init(Cipher.ENCRYPT_MODE, mamboKey, mamboSpec);
//        System.out.print("Encrypt - ");
//        doMulti(mambo, testData.input, encryptedResult);
//
//        if (!Arrays.equals(encryptedResult, testData.expOutput)) {
//            System.out.println("ERROR - Output Mismatch!");
//            System.out.println("Expected:\n" +
//                    dumpHexBytes(testData.expOutput, 16, "\n", " "));
//            System.out.println("Actual:\n" +
//                    dumpHexBytes(encryptedResult, 16, "\n", " "));
//            System.out.println();
//        } else {
//            encRes = true;
//        }
//
//        // Decrypt the result of the encryption operation
//        byte[] decryptedResult = new byte[encryptedResult.length];
//        mambo.init(Cipher.DECRYPT_MODE, mamboKey, mamboSpec);
//        System.out.print("Decrypt - ");
//        doMulti(mambo, encryptedResult, decryptedResult);
//
//        if (!Arrays.equals(decryptedResult, testData.input)) {
//            System.out.println("ERROR - Output Mismatch!");
//            System.out.println("Expected:\n" +
//                    dumpHexBytes(testData.input, 16, "\n", " "));
//            System.out.println("Actual:\n" +
//                    dumpHexBytes(decryptedResult, 16, "\n", " "));
//            System.out.println();
//        } else {
//            decRes = true;
//        }
//
//        return (encRes && decRes);
//    }
//
//    private static void doMulti(Cipher c, byte[] input, byte[] output)
//            throws GeneralSecurityException {
//        int offset = 0;
//        boolean done = false;
//        Random randIn = new Random(System.currentTimeMillis());
//
//        // Send small updates between 1 - 8 bytes in length until we get
//        // 8 or less bytes from the end of the input, then finalize.
//        System.out.println("Input length: " + input.length);
//        System.out.print("Multipart (bytes in/out): ");
//        while (!done) {
//            int mPartLen = randIn.nextInt(8) + 1;
//            int bytesLeft = input.length - offset;
//            int processed;
//            if (mPartLen < bytesLeft) {
//                System.out.print(mPartLen + "/");
//                processed = c.update(input, offset, mPartLen,
//                        output, offset);
//                offset += processed;
//                System.out.print(processed + " ");
//            } else {
//                processed = c.doFinal(input, offset, bytesLeft,
//                        output, offset);
//                System.out.print(bytesLeft + "/" + processed + " ");
//                done = true;
//            }
//        }
//        System.out.println();
//    }
//
//    private static boolean runByteBuffer(TestData testData)
//            throws GeneralSecurityException {
//        boolean encRes = false;
//        boolean decRes = false;
//
//        // Get a cipher instance and initialize it
//        Cipher mambo = Cipher.getInstance("ChaCha20");
//        SecretKeySpec mamboKey = new SecretKeySpec(testData.key, "ChaCha20");
//        ChaCha20ParameterSpec mamboSpec = new ChaCha20ParameterSpec(
//                testData.nonce, testData.counter);
//        mambo.init(Cipher.ENCRYPT_MODE, mamboKey, mamboSpec);
//
//        ByteBuffer bbIn = ByteBuffer.wrap(testData.input);
//        ByteBuffer bbEncOut = ByteBuffer.allocate(
//                mambo.getOutputSize(testData.input.length));
//        ByteBuffer bbExpOut = ByteBuffer.wrap(testData.expOutput);
//
//        mambo.doFinal(bbIn, bbEncOut);
//        bbIn.rewind();
//        bbEncOut.rewind();
//
//        if (bbEncOut.compareTo(bbExpOut) != 0) {
//            System.out.println("ERROR - Output Mismatch!");
//            System.out.println("Expected:\n" +
//                    dumpHexBytes(bbExpOut, 16, "\n", " "));
//            System.out.println("Actual:\n" +
//                    dumpHexBytes(bbEncOut, 16, "\n", " "));
//            System.out.println();
//        } else {
//            encRes = true;
//        }
//
//        // Decrypt the result of the encryption operation
//        mambo.init(Cipher.DECRYPT_MODE, mamboKey, mamboSpec);
//        System.out.print("Decrypt - ");
//        ByteBuffer bbDecOut = ByteBuffer.allocate(
//                mambo.getOutputSize(bbEncOut.remaining()));
//
//        mambo.doFinal(bbEncOut, bbDecOut);
//        bbEncOut.rewind();
//        bbDecOut.rewind();
//
//        if (bbDecOut.compareTo(bbIn) != 0) {
//            System.out.println("ERROR - Output Mismatch!");
//            System.out.println("Expected:\n" +
//                    dumpHexBytes(bbIn, 16, "\n", " "));
//            System.out.println("Actual:\n" +
//                    dumpHexBytes(bbDecOut, 16, "\n", " "));
//            System.out.println();
//        } else {
//            decRes = true;
//        }
//
//        return (encRes && decRes);
//    }
//
//    private static boolean runAEADTest(TestData testData)
//            throws GeneralSecurityException {
//        boolean result = false;
//
//        Cipher mambo = Cipher.getInstance("ChaCha20/AEAD/NoPadding");
//        SecretKeySpec mamboKey = new SecretKeySpec(testData.key, "ChaCha20");
//        ChaCha20ParameterSpec mamboSpec = new ChaCha20ParameterSpec(
//                testData.nonce, testData.counter);
//
//        mambo.init(testData.direction, mamboKey, mamboSpec);
//
//        byte[] out = new byte[mambo.getOutputSize(testData.input.length)];
//        int outOff = 0;
//        try {
//            mambo.updateAAD(testData.aad);
//            outOff += mambo.update(testData.input, 0, testData.input.length,
//                    out, outOff);
//            outOff += mambo.doFinal(out, outOff);
//        } catch (AEADBadTagException abte) {
//            // If we get a bad tag or derive a tag mismatch, log it
//            // and register it as a failure
//            System.out.println("FAIL: " + abte);
//            return false;
//        }
//
//        if (!Arrays.equals(out, testData.expOutput)) {
//            System.out.println("ERROR - Output Mismatch!");
//            System.out.println("Expected:\n" +
//                    dumpHexBytes(testData.expOutput, 16, "\n", " "));
//            System.out.println("Actual:\n" +
//                    dumpHexBytes(out, 16, "\n", " "));
//            System.out.println();
//        } else {
//            result = true;
//        }
//
//        return result;
//    }

    /**
     * Dump the hex bytes of a buffer into string form.
     *
     * @param data The array of bytes to dump to stdout.
     * @param itemsPerLine The number of bytes to display per line
     *      if the {@code lineDelim} character is blank then all bytes
     *      will be printed on a single line.
     * @param lineDelim The delimiter between lines
     * @param itemDelim The delimiter between bytes
     *
     * @return The hexdump of the byte array
     */
    private static String dumpHexBytes(byte[] data, int itemsPerLine,
            String lineDelim, String itemDelim) {
        return dumpHexBytes(ByteBuffer.wrap(data), itemsPerLine, lineDelim,
                itemDelim);
    }

    private static String dumpHexBytes(ByteBuffer data, int itemsPerLine,
            String lineDelim, String itemDelim) {
        StringBuilder sb = new StringBuilder();
        if (data != null) {
            data.mark();
            int i = 0;
            while (data.remaining() > 0) {
                if (i % itemsPerLine == 0 && i != 0) {
                    sb.append(lineDelim);
                }
                sb.append(String.format("%02X", data.get())).append(itemDelim);
                i++;
            }
            data.reset();
        }

        return sb.toString();
    }

    private static byte[] hex2bin(String hex) {
        int i;
        int len = hex.length();
        byte[] data = new byte [len / 2];
        for (i = 0; i < len; i += 2) {
            data[i / 2] = (byte)((Character.digit(hex.charAt(i), 16) << 4) +
                    Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

}
