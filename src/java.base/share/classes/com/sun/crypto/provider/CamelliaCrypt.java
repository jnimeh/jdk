/*
 * Copyright (c) 2021, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
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


package com.sun.crypto.provider;

import java.security.InvalidKeyException;
import java.util.Objects;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;

/**
 * Camellia is a symmetric cipher with a 128-bit
 * block size and variable key-size (128-, 192- and 256-bit).
 * <p>
 * Camellia was jointly developed by Mitsubishi Electric and NTT.
 */
final class CamelliaCrypt extends SymmetricCipher {

    // Allows us to reference byte arrays as longs
    private static final VarHandle asLongBE =
            MethodHandles.byteArrayViewVarHandle(long[].class,
                    ByteOrder.BIG_ENDIAN);

    // Useful constants/defined values
    public static final int CAMELLIA_BLOCK_SIZE = 16;
    public static final int[] CAMELLIA_KEYSIZES =  { 16, 24, 32 };
    private static final long SIGMA1 = 0xA09E667F3BCC908BL;
    private static final long SIGMA2 = 0xB67AE8584CAA73B2L;
    private static final long SIGMA3 = 0xC6EF372FE94F82BEL;
    private static final long SIGMA4 = 0x54FF53A5F1D36F1CL;
    private static final long SIGMA5 = 0x10E527FADE682D1DL;
    private static final long SIGMA6 = 0xB05688C2B3E6C1FDL;

    // SBOXes
    private static final byte[] SBOX1 = {
        112, -126,   44,  -20,  -77,   39,  -64,  -27,
        -28, -123,   87,   53,  -22,   12,  -82,   65,
         35,  -17,  107, -109,   69,   25,  -91,   33,
        -19,   14,   79,   78,   29,  101, -110,  -67,
       -122,  -72,  -81, -113,  124,  -21,   31,  -50,
         62,   48,  -36,   95,   94,  -59,   11,   26,
        -90,  -31,   57,  -54,  -43,   71,   93,   61,
        -39,    1,   90,  -42,   81,   86,  108,   77,
       -117,   13, -102,  102,   -5,  -52,  -80,   45,
        116,   18,   43,   32,  -16,  -79, -124, -103,
        -33,   76,  -53,  -62,   52,  126,  118,    5,
        109,  -73,  -87,   49,  -47,   23,    4,  -41,
         20,   88,   58,   97,  -34,   27,   17,   28,
         50,   15, -100,   22,   83,   24,  -14,   34,
         -2,   68,  -49,  -78,  -61,  -75,  122, -111,
         36,    8,  -24,  -88,   96,   -4,  105,   80,
        -86,  -48,  -96,  125,  -95, -119,   98, -105,
         84,   91,   30, -107,  -32,   -1,  100,  -46,
         16,  -60,    0,   72,  -93,   -9,  117,  -37,
       -118,    3,  -26,  -38,    9,   63,  -35, -108,
       -121,   92, -125,    2,  -51,   74, -112,   51,
        115,  103,  -10,  -13,  -99,  127,  -65,  -30,
         82, -101,  -40,   38,  -56,   55,  -58,   59,
       -127, -106,  111,   75,   19,  -66,   99,   46,
        -23,  121,  -89, -116,  -97,  110,  -68, -114,
         41,  -11,   -7,  -74,   47,   -3,  -76,   89,
        120, -104,    6,  106,  -25,   70,  113,  -70,
        -44,   37,  -85,   66, -120,  -94, -115,   -6,
        114,    7,  -71,   85,   -8,  -18,  -84,   10,
         54,   73,   42,  104,   60,   56,  -15,  -92,
         64,   40,  -45,  123,  -69,  -55,   67,  -63,
         21,  -29,  -83,  -12,  119,  -57, -128,  -98
    };

    private static final byte[] SBOX2 = {
        -32,    5,   88,  -39,  103,   78, -127,  -53,
        -55,   11,  -82,  106,  -43,   24,   93, -126,
         70,  -33,  -42,   39, -118,   50,   75,   66,
        -37,   28,  -98, -100,   58,  -54,   37,  123,
         13,  113,   95,   31,   -8,  -41,   62,  -99,
        124,   96,  -71,  -66,  -68, -117,   22,   52,
         77,  -61,  114, -107,  -85, -114,  -70,  122,
        -77,    2,  -76,  -83,  -94,  -84,  -40, -102,
         23,   26,   53,  -52,   -9, -103,   97,   90,
        -24,   36,   86,   64,  -31,   99,    9,   51,
        -65, -104, -105, -123,  104,   -4,  -20,   10,
        -38,  111,   83,   98,  -93,   46,    8,  -81,
         40,  -80,  116,  -62,  -67,   54,   34,   56,
        100,   30,   57,   44,  -90,   48,  -27,   68,
         -3, -120,  -97,  101, -121,  107,  -12,   35,
         72,   16,  -47,   81,  -64,   -7,  -46,  -96,
         85,  -95,   65,   -6,   67,   19,  -60,   47,
        -88,  -74,   60,   43,  -63,   -1,  -56,  -91,
         32, -119,    0, -112,   71,  -17,  -22,  -73,
         21,    6,  -51,  -75,   18,  126,  -69,   41,
         15,  -72,    7,    4, -101, -108,   33,  102,
        -26,  -50,  -19,  -25,   59,   -2,  127,  -59,
        -92,   55,  -79,   76, -111,  110, -115,  118,
          3,   45,  -34, -106,   38,  125,  -58,   92,
        -45,  -14,   79,   25,   63,  -36,  121,   29,
         82,  -21,  -13,  109,   94,   -5,  105,  -78,
        -16,   49,   12,  -44,  -49, -116,  -30,  117,
        -87,   74,   87, -124,   17,   69,   27,  -11,
        -28,   14,  115,  -86,  -15,  -35,   89,   20,
        108, -110,   84,  -48,  120,  112,  -29,   73,
       -128,   80,  -89,  -10,  119, -109, -122, -125,
         42,  -57,   91,  -23,  -18, -113,    1,   61
    };

    private static final byte[] SBOX3 = {
         56,   65,   22,  118,  -39, -109,   96,  -14,
        114,  -62,  -85, -102,  117,    6,   87,  -96,
       -111,   -9,  -75,  -55,  -94, -116,  -46, -112,
        -10,    7,  -89,   39, -114,  -78,   73,  -34,
         67,   92,  -41,  -57,   62,  -11, -113,  103,
         31,   24,  110,  -81,   47,  -30, -123,   13,
         83,  -16, -100,  101,  -22,  -93,  -82,  -98,
        -20, -128,   45,  107,  -88,   43,   54,  -90,
        -59, -122,   77,   51,   -3,  102,   88, -106,
         58,    9, -107,   16,  120,  -40,   66,  -52,
        -17,   38,  -27,   97,   26,   63,   59, -126,
        -74,  -37,  -44, -104,  -24, -117,    2,  -21,
         10,   44,   29,  -80,  111, -115, -120,   14,
         25, -121,   78,   11,  -87,   12,  121,   17,
        127,   34,  -25,   89,  -31,  -38,   61,  -56,
         18,    4,  116,   84,   48,  126,  -76,   40,
         85,  104,   80,  -66,  -48,  -60,   49,  -53,
         42,  -83,   15,  -54,  112,   -1,   50,  105,
          8,   98,    0,   36,  -47,   -5,  -70,  -19,
         69, -127,  115,  109, -124,  -97,  -18,   74,
        -61,   46,  -63,    1,  -26,   37,   72, -103,
        -71,  -77,  123,   -7,  -50,  -65,  -33,  113,
         41,  -51,  108,   19,  100, -101,   99,  -99,
        -64,   75,  -73,  -91, -119,   95,  -79,   23,
        -12,  -68,  -45,   70,  -49,   55,   94,   71,
       -108,   -6,   -4,   91, -105,   -2,   90,  -84,
         60,   76,    3,   53,  -13,   35,  -72,   93,
        106, -110,  -43,   33,   68,   81,  -58,  125,
         57, -125,  -36,  -86,  124,  119,   86,    5,
         27,  -92,   21,   52,   30,   28,   -8,   82,
         32,   20,  -23,  -67,  -35,  -28,  -95,  -32,
       -118,  -15,  -42,  122,  -69,  -29,   64,   79
    };

    private static final byte[] SBOX4 = {
        112,   44,  -77,  -64,  -28,   87,  -22,  -82,
         35,  107,   69,  -91,  -19,   79,   29, -110,
       -122,  -81,  124,   31,   62,  -36,   94,   11,
        -90,   57,  -43,   93,  -39,   90,   81,  108,
       -117, -102,   -5,  -80,  116,   43,  -16, -124,
        -33,  -53,   52,  118,  109,  -87,  -47,    4,
         20,   58,  -34,   17,   50, -100,   83,  -14,
         -2,  -49,  -61,  122,   36,  -24,   96,  105,
        -86,  -96,  -95,   98,   84,   30,  -32,  100,
         16,    0,  -93,  117, -118,  -26,    9,  -35,
       -121, -125,  -51, -112,  115,  -10,  -99,  -65,
         82,  -40,  -56,  -58, -127,  111,   19,   99,
        -23,  -89,  -97,  -68,   41,   -7,   47,  -76,
        120,    6,  -25,  113,  -44,  -85, -120, -115,
        114,  -71,   -8,  -84,   54,   42,   60,  -15,
         64,  -45,  -69,   67,   21,  -83,  119, -128,
       -126,  -20,   39,  -27, -123,   53,   12,   65,
        -17, -109,   25,   33,   14,   78,  101,  -67,
        -72, -113,  -21,  -50,   48,   95,  -59,   26,
        -31,  -54,   71,   61,    1,  -42,   86,   77,
         13,  102,  -52,   45,   18,   32,  -79, -103,
         76,  -62,  126,    5,  -73,   49,   23,  -41,
         88,   97,   27,   28,   15,   22,   24,   34,
         68,  -78,  -75, -111,    8,  -88,   -4,   80,
        -48,  125, -119, -105,   91, -107,   -1,  -46,
        -60,   72,   -9,  -37,    3,  -38,   63, -108,
         92,    2,   74,   51,  103,  -13,  127,  -30,
       -101,   38,   55,   59, -106,   75,  -66,   46,
        121, -116,  110, -114,  -11,  -74,   -3,   89,
       -104,  106,   70,  -70,   37,   66,  -94,   -6,
          7,   85,  -18,   10,   73,  104,   56,  -92,
         40,  123,  -55,  -63,  -29,  -12,  -57,  -98
    };

    private static final long MASK8 = 0x00000000000000FFL;
    private static final long MASK32 = 0x00000000FFFFFFFFL;

    // Key variables
    private int keyLength;
    private final long[] KL = new long[2];      // Left 128 bits of the key
    private final long[] KR = new long[2];      // Right 128 bits of the key
    private final long[] KA = new long[2];
    private final long[] KB = new long[2];
    private final long kw[] = new long[4];      // Whitening subkeys
    private final long k[] = new long[24];      // Feistel structure subkeys
    private final long ke[] = new long[6];      // FL/FLINV subkeys

    /**
     * No-args constructor for the cipher.
     */
    CamelliaCrypt() {
        // empty
    }

    /**
     * Returns this cipher's block size.
     *
     * @return this cipher's block size in bytes.
     */
    @Override
    int getBlockSize() {
        return CAMELLIA_BLOCK_SIZE;
    }

    /**
     * Initialize the Camellia cipher.
     *
     * @param decrypting {@code true} if in decryption mode, {@code false}
     *      if encrypting
     * @param algorithm the name of the algorithm.  Must be "Camellia"
     *      (case insensitive)
     * @param key the key as a byte array
     *
     * @throws InvalidKeyException if the wrong algorithm name is supplied
     *      or if the key byte array is not 16, 24, or 32 bytes in length.
     */
    @Override
    void init(boolean decrypting, String algorithm, byte[] key)
            throws InvalidKeyException {
        if (!algorithm.equalsIgnoreCase("Camellia")) {
            throw new InvalidKeyException
                ("Wrong algorithm: Camellia required");
        }
        if (!isKeySizeValid(key.length)) {
            throw new InvalidKeyException("Invalid Camellia key length: " +
                key.length + " bytes");
        }

        this.keyLength = key.length;

        doKeySchedule(key);
    }

    /**
     * Check if the specified key length (in bytes) is valid for Camellia.
     *
     * @param len the key length in bytes
     *
     * @return {@code true} if length is 16, 24, or 32, {@code false} if not.
     */
    static final boolean isKeySizeValid(int len) {
        for (int i = 0; i < CAMELLIA_KEYSIZES.length; i++) {
            if (len == CAMELLIA_KEYSIZES[i]) {
                return true;
            }
        }
        return false;
    }

    /**
     * Top-level function for running the key scheduler.  This is broken
     * down into three steps: (1) setting KL and KR, (2) setting KA and KB,
     * and (3) creating the subkeys (kX, keX, kwX).
     *
     * @throws InvalidKeyException if an invalid key length is provided.
     */
    private void doKeySchedule(byte[] key) throws InvalidKeyException {
        setKlKr(key);
        setKaKb();
        createSubkeys();
    }

    /**
     * Set the left and right halves (KL and KR) of the key.
     *
     * @throws InvalidKeyException if an invalid key length has been
     * provided.
     */
    private void setKlKr(byte[] key) throws InvalidKeyException {
        // KL will always be the leftmost 128 bits, regardless of key size
        KL[0] = (long)asLongBE.get(key, 0);
        KL[1] = (long)asLongBE.get(key, 8);

        switch (keyLength) {
            case 16:                    // 128-bit key
                // Nothing else to do, already done above.
                break;
            case 24:                    // 192-bit key
                long last64 = (long)asLongBE.get(key, 16);
                KR[0] = last64;
                KR[1] = ~last64;
                break;
            case 32:                    // 256-bit key
                KR[0] = (long)asLongBE.get(key, 16);
                KR[1] = (long)asLongBE.get(key, 24);
                break;
            default:                    // Some other invalid length
                // This should not happen
                throw new InvalidKeyException("Invalid key length: " +
                        (keyLength * 8) + " bits");
        }
    }

    /**
     * Set the KA and KB 128-bit integer values from KL/KR.
     */
    private void setKaKb() {
        long d1, d2;

        d1 = KL[0] ^ KR[0];             // D1 = (KL ^ KR) >> 64
        d2 = KL[1] ^ KR[1];             // D2 = (KL ^ KR) & MASK64
        d2 ^= fFunc(d1, SIGMA1);        // D2 = D2 ^ F(D1, Sigma1)
        d1 ^= fFunc(d2, SIGMA2);        // D1 = D1 ^ F(D2, Sigma2)
        d1 ^= KL[0];                    // D1 = D1 ^ (KL >> 64)
        d2 ^= KL[1];                    // D2 = D2 ^ (KL & MASK64)
        d2 ^= fFunc(d1, SIGMA3);        // D2 = D2 ^ F(D1, Sigma3)
        d1 ^= fFunc(d2, SIGMA4);        // D1 = D1 ^ F(D2, Sigma4)
        KA[0] = d1;                     // KA = (D1 << 64) | D2
        KA[1] = d2;

        d1 = KA[0] ^ KR[0];             // D1 = (KA ^ KR) >> 64
        d2 = KA[1] ^ KR[1];             // D2 = (KA ^ KR) & MASK64
        d2 ^= fFunc(d1, SIGMA5);        // D2 = D2 ^ F(D1, Sigma5)
        d1 ^= fFunc(d2, SIGMA6);        // D1 = D1 ^ F(D2, Sigma6)
        KB[0] = d1;                     // KB = (D1 << 64) | D2
        KB[1] = d2;
    }

    /**
     * Create the subkey schedule.
     *
     * @throws InvalidKeyException if an invalid key length is provided.
     */
    private void createSubkeys() throws InvalidKeyException {
        long[] int128 = new long[2];
        switch (keyLength) {
            case 16:
                kw[0] = KL[0];
                kw[1] = KL[1];
                k[0] = KA[0];
                k[1] = KA[1];

                leftRot128(KL, 15, int128);
                k[2] = int128[0];
                k[3] = int128[1];

                leftRot128(KA, 15, int128);
                k[4] = int128[0];
                k[5] = int128[1];

                leftRot128(KA, 30, int128);
                ke[0] = int128[0];
                ke[1] = int128[1];

                leftRot128(KL, 45, int128);
                k[6] = int128[0];
                k[7] = int128[1];
                leftRot128(KA, 45, int128);
                k[8] = int128[0];

                leftRot128(KL, 60, int128);
                k[9] = int128[1];
                leftRot128(KA, 60, int128);
                k[10] = int128[0];
                k[11] = int128[1];

                leftRot128(KL, 77, int128);
                ke[2] = int128[0];
                ke[3] = int128[1];

                leftRot128(KL, 94, int128);
                k[12] = int128[0];
                k[13] = int128[1];
                leftRot128(KA, 94, int128);
                k[14] = int128[0];
                k[15] = int128[1];

                leftRot128(KL, 111, int128);
                k[16] = int128[0];
                k[17] = int128[1];
                leftRot128(KA, 111, int128);
                kw[2] = int128[0];
                kw[3] = int128[1];
                break;
            case 24:
            case 32:
                kw[0] = KL[0];
                kw[1] = KL[1];
                k[0] = KB[0];
                k[1] = KB[1];

                leftRot128(KR, 15, int128);
                k[2] = int128[0];
                k[3] = int128[1];
                leftRot128(KA, 15, int128);
                k[4] = int128[0];
                k[5] = int128[1];

                leftRot128(KR, 30, int128);
                ke[0] = int128[0];
                ke[1] = int128[1];
                leftRot128(KB, 30, int128);
                k[6] = int128[0];
                k[7] = int128[1];

                leftRot128(KL, 45, int128);
                k[8] = int128[0];
                k[9] = int128[1];
                leftRot128(KA, 45, int128);
                k[10] = int128[0];
                k[11] = int128[1];

                leftRot128(KL, 60, int128);
                ke[2] = int128[0];
                ke[3] = int128[1];
                leftRot128(KR, 60, int128);
                k[12] = int128[0];
                k[13] = int128[1];
                leftRot128(KB, 60, int128);
                k[14] = int128[0];
                k[15] = int128[1];

                leftRot128(KL, 77, int128);
                k[16] = int128[0];
                k[17] = int128[1];
                leftRot128(KA, 77, int128);
                ke[4] = int128[0];
                ke[5] = int128[1];

                leftRot128(KR, 94, int128);
                k[18] = int128[0];
                k[19] = int128[1];
                leftRot128(KA, 94, int128);
                k[20] = int128[0];
                k[21] = int128[1];

                leftRot128(KL, 111, int128);
                k[22] = int128[0];
                k[23] = int128[1];
                leftRot128(KB, 111, int128);
                kw[2] = int128[0];
                kw[3] = int128[1];
                break;
            default:
                // This should never happen if called from init()
                throw new InvalidKeyException("Invalid key length: " +
                        keyLength);
        }
    }

    /**
     * Encrypt exactly one block of plaintext.
     *
     * @param in the plaintext bytes
     * @param inOffset the offset into the plaintext
     * @param out the output ciphertext
     * @param outOffset the offset at which the returned ciphertext starts
     */
    @Override
    void encryptBlock(byte[] in, int inOffset,
                      byte[] out, int outOffset) {
        Objects.checkFromIndexSize(inOffset, CAMELLIA_BLOCK_SIZE, in.length);
        Objects.checkFromIndexSize(outOffset, CAMELLIA_BLOCK_SIZE, out.length);
        implEncryptBlock(in, inOffset, out, outOffset);
    }

    /**
     * Actual encrypt block function.
     *
     * @param in the plaintext bytes
     * @param inOffset the offset into the plaintext
     * @param out the output ciphertext
     * @param outOffset the offset at which the returned ciphertext starts
     */
    private void implEncryptBlock(byte[] in, int inOffset,
                                  byte[] out, int outOffset) {
        long d1 = (long)asLongBE.get(in, inOffset);
        long d2 = (long)asLongBE.get(in, inOffset + 8);

        d1 ^= kw[0];                        // Prewhitening
        d2 ^= kw[1];

        // Regardless of key size, the first 18 rounds are the same
        d2 ^= fFunc(d1, k[0]);
        d1 ^= fFunc(d2, k[1]);
        d2 ^= fFunc(d1, k[2]);
        d1 ^= fFunc(d2, k[3]);
        d2 ^= fFunc(d1, k[4]);
        d1 ^= fFunc(d2, k[5]);
        d1 = flFunc(d1, ke[0]);
        d2 = flinvFunc(d2, ke[1]);

        d2 ^= fFunc(d1, k[6]);
        d1 ^= fFunc(d2, k[7]);
        d2 ^= fFunc(d1, k[8]);
        d1 ^= fFunc(d2, k[9]);
        d2 ^= fFunc(d1, k[10]);
        d1 ^= fFunc(d2, k[11]);
        d1 = flFunc(d1, ke[2]);
        d2 = flinvFunc(d2, ke[3]);

        d2 ^= fFunc(d1, k[12]);
        d1 ^= fFunc(d2, k[13]);
        d2 ^= fFunc(d1, k[14]);
        d1 ^= fFunc(d2, k[15]);
        d2 ^= fFunc(d1, k[16]);
        d1 ^= fFunc(d2, k[17]);

        // For 192 and 256-bit keys, there is an additional FL/FLINV
        // function pair followed by an additional 6 rounds before
        // postwhitening.
        if (keyLength == 24 || keyLength == 32) {
            d1 = flFunc(d1, ke[4]);
            d2 = flinvFunc(d2, ke[5]);
            d2 ^= fFunc(d1, k[18]);
            d1 ^= fFunc(d2, k[19]);
            d2 ^= fFunc(d1, k[20]);
            d1 ^= fFunc(d2, k[21]);
            d2 ^= fFunc(d1, k[22]);
            d1 ^= fFunc(d2, k[23]);
        }

        d2 ^= kw[2];                        // Postwhitening
        d1 ^= kw[3];

        // Write the d1/d2 values into the output buffer
        asLongBE.set(out, outOffset, d2);
        asLongBE.set(out, outOffset + 8, d1);
    }

    /**
     * Decrypt exactly one block of ciphertext.
     *
     * @param in the ciphertext bytes
     * @param inOffset the offset into the cipheretxt
     * @param out the output plaintext
     * @param outOffset the offset at which the returned plaintext begins
     */
    @Override
    void decryptBlock(byte[] in, int inOffset,
                      byte[] out, int outOffset) {
        Objects.checkFromIndexSize(inOffset, CAMELLIA_BLOCK_SIZE, in.length);
        Objects.checkFromIndexSize(outOffset, CAMELLIA_BLOCK_SIZE, out.length);
        implDecryptBlock(in, inOffset, out, outOffset);
    }

    /**
     * Actual decrypt block function.
     *
     * @param in the ciphertext bytes
     * @param inOffset the offset into the ciphertext
     * @param out the output plaintext
     * @param outOffset the offset at which the returned plaintext starts
     */
    private void implDecryptBlock(byte[] in, int inOffset,
                                  byte[] out, int outOffset) {
        long d1 = (long)asLongBE.get(in, inOffset);
        long d2 = (long)asLongBE.get(in, inOffset + 8);

        d1 ^= kw[2];                        // Prewhitening
        d2 ^= kw[3];

        switch (keyLength) {
            case 16:                        // 128-bit decryption
                d2 ^= fFunc(d1, k[17]);
                d1 ^= fFunc(d2, k[16]);
                d2 ^= fFunc(d1, k[15]);
                d1 ^= fFunc(d2, k[14]);
                d2 ^= fFunc(d1, k[13]);
                d1 ^= fFunc(d2, k[12]);
                d1 = flFunc(d1, ke[3]);
                d2 = flinvFunc(d2, ke[2]);

                d2 ^= fFunc(d1, k[11]);
                d1 ^= fFunc(d2, k[10]);
                d2 ^= fFunc(d1, k[9]);
                d1 ^= fFunc(d2, k[8]);
                d2 ^= fFunc(d1, k[7]);
                d1 ^= fFunc(d2, k[6]);
                d1 = flFunc(d1, ke[1]);
                d2 = flinvFunc(d2, ke[0]);

                d2 ^= fFunc(d1, k[5]);
                d1 ^= fFunc(d2, k[4]);
                d2 ^= fFunc(d1, k[3]);
                d1 ^= fFunc(d2, k[2]);
                d2 ^= fFunc(d1, k[1]);
                d1 ^= fFunc(d2, k[0]);
                break;
            case 24:                        // 192 or 256-bit decryption
            case 32:
                d2 ^= fFunc(d1, k[23]);
                d1 ^= fFunc(d2, k[22]);
                d2 ^= fFunc(d1, k[21]);
                d1 ^= fFunc(d2, k[20]);
                d2 ^= fFunc(d1, k[19]);
                d1 ^= fFunc(d2, k[18]);
                d1 = flFunc(d1, ke[5]);
                d2 = flinvFunc(d2, ke[4]);

                d2 ^= fFunc(d1, k[17]);
                d1 ^= fFunc(d2, k[16]);
                d2 ^= fFunc(d1, k[15]);
                d1 ^= fFunc(d2, k[14]);
                d2 ^= fFunc(d1, k[13]);
                d1 ^= fFunc(d2, k[12]);
                d1 = flFunc(d1, ke[3]);
                d2 = flinvFunc(d2, ke[2]);

                d2 ^= fFunc(d1, k[11]);
                d1 ^= fFunc(d2, k[10]);
                d2 ^= fFunc(d1, k[9]);
                d1 ^= fFunc(d2, k[8]);
                d2 ^= fFunc(d1, k[7]);
                d1 ^= fFunc(d2, k[6]);
                d1 = flFunc(d1, ke[1]);
                d2 = flinvFunc(d2, ke[0]);

                d2 ^= fFunc(d1, k[5]);
                d1 ^= fFunc(d2, k[4]);
                d2 ^= fFunc(d1, k[3]);
                d1 ^= fFunc(d2, k[2]);
                d2 ^= fFunc(d1, k[1]);
                d1 ^= fFunc(d2, k[0]);
                break;
        }

        d2 ^= kw[0];                        // Postwhitening
        d1 ^= kw[1];

        // Write the d1/d2 values into the output buffer
        asLongBE.set(out, outOffset, d2);
        asLongBE.set(out, outOffset + 8, d1);
    }

    /**
     * Perform a left-rotation on a 128-bit big-endian integer, interpreted
     * as an array of two longs.
     *
     * @param int128 an array of two longs.  No error checking is performed;
     *      it is the caller's responsibility to provide a 2-element long
     *      array. The value of {@code int128} will be unchanged after this
     *      method returns.
     * @param numBits the number of high order bits to mask off.  Must be a
     *      number between 0 <= X <= 128.  It is the caller's responsibility
     *      to make sure the bit count falls within this range.
     * @param out the returned 128-bit big endian integer as an array of two
     *      longs.
     */
    private static void leftRot128(long[] int128, int numBits, long[] out) {
        long left = int128[0];
        long right = int128[1];

        // If we have at least an odd multiple of 64 bits, we can simplify
        // things by swapping the two longs.  Then all we need to do is
        // left-shift the remainder (mod 64).
        if (((numBits >> 6) & 0x1) != 0) {
            left ^= right;
            right ^= left;
            left ^= right;
        }

        // Then left-rotate any leftover bits (numBits % 64)
        int actualShift = numBits % 64;
        int leftOver = 64 - actualShift;
        long mask = ((1L << actualShift) - 1) << leftOver;
        long lRollBits = (left & mask) >>> leftOver;
        long rRollBits = (right & mask) >>> leftOver;
        left = (left << actualShift) | rRollBits;
        right = (right << actualShift) | lRollBits;

        out[0] = left;
        out[1] = right;
    }

    /**
     * Implement the function F.
     *
     * @param f_in 64-bit integer value (data input).
     * @param ke a subkey as a 64-bit integer.
     *
     * @return data as a 64-bit integer.
     */
    private static long fFunc(long f_in, long ke) {
        byte t1, t2, t3, t4, t5, t6, t7, t8;
        long x = f_in ^ ke;

        t1 = SBOX1[(int)(x >>> 56)];
        t2 = SBOX2[(int)((x >>> 48) & MASK8)];
        t3 = SBOX3[(int)((x >>> 40) & MASK8)];
        t4 = SBOX4[(int)((x >>> 32) & MASK8)];
        t5 = SBOX2[(int)((x >>> 24) & MASK8)];
        t6 = SBOX3[(int)((x >>> 16) & MASK8)];
        t7 = SBOX4[(int)((x >>> 8) & MASK8)];
        t8 = SBOX1[(int)(x & MASK8)];

        return ((((long)(t1 ^ t3 ^ t4 ^ t6 ^ t7 ^ t8) & MASK8) << 56) |
                (((long)(t1 ^ t2 ^ t4 ^ t5 ^ t7 ^ t8) & MASK8) << 48) |
                (((long)(t1 ^ t2 ^ t3 ^ t5 ^ t6 ^ t8) & MASK8) << 40) |
                (((long)(t2 ^ t3 ^ t4 ^ t5 ^ t6 ^ t7) & MASK8) << 32) |
                (((long)(t1 ^ t2 ^ t6 ^ t7 ^ t8) & MASK8) << 24) |
                (((long)(t2 ^ t3 ^ t5 ^ t7 ^ t8) & MASK8) << 16) |
                (((long)(t3 ^ t4 ^ t5 ^ t6 ^ t8) & MASK8) << 8) |
                 ((long)(t1 ^ t4 ^ t5 ^ t6 ^ t7) & MASK8));
    }

    /**
     * Implement the FL function.
     *
     * @param fl_in 64-bit integer value (data input).
     * @param ke a subkey as a 64-bit integer.
     *
     * @return data as a 64-bit integer.
     */
    private static long flFunc(long fl_in, long ke) {
        int x1 = (int)(fl_in >>> 32);
        int x2 = (int)fl_in;
        int k1 = (int)(ke >>> 32);
        int k2 = (int)ke;

        int scratch = x1 & k1;
        x2 ^= ((scratch << 1) | (scratch >>> 31));
        x1 ^= (x2 | k2);
        return (((long)x1 << 32) | (x2 & MASK32));
    }

    /**
     * Implement the FLINV (inverse of FL) function.
     *
     * @param flinv_in 64-bit integer value (data input).
     * @param ke a subkey as a 64-bit integer.
     *
     * @return data as a 64-bit integer.
     */
    private static long flinvFunc(long flinv_in, long ke) {
        int y1 = (int)(flinv_in >>> 32);
        int y2 = (int)flinv_in;
        int k1 = (int)(ke >>> 32);
        int k2 = (int)ke;

        y1 ^= (y2 | k2);
        int scratch = y1 & k1;
        y2 ^= ((scratch << 1) | (scratch >>> 31));
        return (((long)y1 << 32) | (y2 & MASK32));
    }

}
