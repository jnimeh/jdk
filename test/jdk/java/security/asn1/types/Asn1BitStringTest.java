/*
 * @test
 * @summary Tests Asn1BitString construction, equality, hashCode, and invariants
 * @run main Asn1BitStringTest
 */

import java.security.asn1.Asn1Exception;
import java.security.asn1.Asn1Tags;
import java.util.Arrays;
import java.security.asn1.types.Asn1BitString;

public class Asn1BitStringTest {

    public static void main(String[] args) {
        testBasicConstruction();
        testConstructionWithUnusedBits();
        testDefensiveCopy();
        testEqualsAndHashCode();
        testInequality();
        testUnusedBitsAffectsEquality();
    }

    private static void testBasicConstruction() {
        byte[] input = new byte[] { (byte) 0xAA, (byte) 0xF0 };

        Asn1BitString bs = Asn1BitString.of(input);

        if (!bs.tag().equals(Asn1Tags.BIT_STRING)) {
            throw new RuntimeException("Expected " + Asn1Tags.BIT_STRING +
                    ", got " + bs.tag());
        }

        if (!Arrays.equals(input, bs.bytes())) {
            throw new RuntimeException(
                    "Basic construction failed: bytes mismatch");
        }

        if (bs.unusedBits() != 0) {
            throw new RuntimeException(
                    "Default unusedBits should be 0");
        }

        try {
            Asn1BitString.of(new byte[] {1}, 8);
            throw new RuntimeException(
                    "Expected exception for invalid unusedBits");
        } catch (Asn1Exception expected) {}

        try {
            Asn1BitString.of(new byte[] {1}, -3);
            throw new RuntimeException(
                    "Expected exception for invalid unusedBits");
        } catch (Asn1Exception expected) {}

        try {
            Asn1BitString.of(new byte[0], 5);
            throw new RuntimeException(
                    "Expected exception for invalid unusedBits");
        } catch (Asn1Exception expected) {}

        try {
            Asn1BitString.of(null);
            throw new RuntimeException(
                    "Expected exception for null input");
        } catch (NullPointerException expected) {}
    }

    private static void testConstructionWithUnusedBits() {
        byte[] input = new byte[] { (byte) 0xFF };

        Asn1BitString bs = Asn1BitString.of(input, 3);

        if (bs.unusedBits() != 3) {
            throw new RuntimeException(
                    "UnusedBits not set correctly");
        }

        // Ensure masking behavior (last 3 bits ignored)
        byte[] out = bs.bytes();
        if (out[out.length - 1] != (byte)(input[input.length - 1] << 3)) {
            throw new RuntimeException(
                    "Last byte not properly masked according to unusedBits");
        }
    }

    private static void testDefensiveCopy() {
        byte[] input = new byte[] { 1, 2, 3 };

        Asn1BitString bs = Asn1BitString.of(input);

        // mutate original
        input[0] = 9;

        if (bs.bytes()[0] != 1) {
            throw new RuntimeException(
                    "Constructor did not defensively copy input");
        }

        // mutate returned
        byte[] returned = bs.bytes();
        returned[1] = 9;

        if (bs.bytes()[1] != 2) {
            throw new RuntimeException(
                    "bytes() did not defensively copy output");
        }
    }

    private static void testEqualsAndHashCode() {
        byte[] a1 = new byte[] { 0x0F, (byte) 0xF0 };
        byte[] a2 = new byte[] { 0x0F, (byte) 0xF0 };

        Asn1BitString bs1 = Asn1BitString.of(a1, 2);
        Asn1BitString bs2 = Asn1BitString.of(a2, 2);

        if (!bs1.equals(bs2)) {
            throw new RuntimeException(
                    "Equal bit strings not considered equal");
        }

        if (bs1.hashCode() != bs2.hashCode()) {
            throw new RuntimeException(
                    "Equal bit strings must have same hashCode");
        }
    }

    private static void testInequality() {
        Asn1BitString bs1 = Asn1BitString.of(new byte[] { 1, 2, 3 });
        Asn1BitString bs2 = Asn1BitString.of(new byte[] { 1, 2, 4 });

        if (bs1.equals(bs2)) {
            throw new RuntimeException(
                    "Different byte arrays considered equal");
        }

        Asn1BitString bs3 = Asn1BitString.of(new byte[] { 1, 2, 3 }, 1);
        Asn1BitString bs4 = Asn1BitString.of(new byte[] { 1, 2, 3 }, 2);

        if (bs3.equals(bs4)) {
            throw new RuntimeException(
                    "Different unusedBits considered equal");
        }
    }

    private static void testUnusedBitsAffectsEquality() {
        // Same raw bytes, but masked differently → should not be equal
        byte[] data = new byte[] { (byte) 0xFF };

        Asn1BitString bs1 = Asn1BitString.of(data, 1);
        Asn1BitString bs2 = Asn1BitString.of(data, 2);

        if (bs1.equals(bs2)) {
            throw new RuntimeException(
                    "BitStrings with different unusedBits should not be equal");
        }
    }
}