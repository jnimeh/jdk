/*
 * @test
 * @summary Test Asn1RawElement equality and hashCode behavior
 */

import java.security.asn1.*;
import java.security.asn1.types.Asn1RawElement;

public class Asn1RawElementTest {

    public static void main(String[] args) {
        testEqualsAndHashCode();
        testDefensiveCopy();
    }

    private static void testEqualsAndHashCode() {
        Asn1Tag tag = Asn1Tag.priv(5, false);

        byte[] value1 = new byte[] {1, 2, 3};
        byte[] value2 = new byte[] {1, 2, 3};
        byte[] value3 = new byte[] {1, 2, 4};

        Asn1RawElement e1 = Asn1RawElement.of(tag, value1);
        Asn1RawElement e2 = Asn1RawElement.of(tag, value2);
        Asn1RawElement e3 = Asn1RawElement.of(tag, value3);
        Asn1RawElement e4 = Asn1RawElement.of(Asn1Tag.priv(4, false), value2);

        // Test value equivalence / non-equivalence
        if (!e1.equals(e2)) {
            throw new RuntimeException("Equal elements not considered equal");
        }

        if (e1.hashCode() != e2.hashCode()) {
            throw new RuntimeException("Equal elements must have same hashCode");
        }

        if (e1.equals(e3)) {
            throw new RuntimeException("Different elements considered equal");
        }

        // Test a non-equivalent case where two values are the same but with
        // different tags.
        if (e1.equals(e4)) {
            throw new RuntimeException("Different tags with same data " +
                    "erroneously considered equal");
        }
    }

    private static void testDefensiveCopy() {
        Asn1Tag tag = Asn1Tag.context(12, false);

        byte[] original = new byte[] {9, 9, 9};
        Asn1RawElement e = Asn1RawElement.of(tag, original);

        // mutate original
        original[0] = 0;

        byte[] returned = e.value();

        if (returned[0] != 9) {
            throw new RuntimeException(
                    "Constructor did not defensively copy input");
        }

        // mutate returned
        returned[1] = 0;

        byte[] returnedAgain = e.value();

        if (returnedAgain[1] != 9) {
            throw new RuntimeException(
                    "value() did not defensively copy output");
        }
    }
}