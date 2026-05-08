/*
 * @test
 * @summary Tests Asn1Boolean singleton behavior, factory, equality, and hashCode
 * @run main Asn1BooleanTest
 */

import java.security.asn1.Asn1Tag;
import java.security.asn1.types.Asn1Boolean;

public class Asn1BooleanTest {

    public static void main(String[] args) {
        testFactory();
        testValue();
        testEqualsAndHashCode();
        testInequality();
        testTagConsistency();
        testNullAndTypeSafety();
    }

    private static void testFactory() {
        Asn1Boolean t1 = Asn1Boolean.of(true);
        Asn1Boolean t2 = Asn1Boolean.TRUE;

        if (t1 != t2) {
            throw new RuntimeException("Factory should return TRUE singleton for true");
        }

        Asn1Boolean f1 = Asn1Boolean.of(false);
        Asn1Boolean f2 = Asn1Boolean.FALSE;

        if (f1 != f2) {
            throw new RuntimeException("Factory should return FALSE singleton for false");
        }
    }

    private static void testValue() {
        if (!Asn1Boolean.TRUE.value()) {
            throw new RuntimeException("TRUE.value() should be true");
        }

        if (Asn1Boolean.FALSE.value()) {
            throw new RuntimeException("FALSE.value() should be false");
        }
    }

    private static void testEqualsAndHashCode() {
        Asn1Boolean t1 = Asn1Boolean.of(true);
        Asn1Boolean t2 = Asn1Boolean.TRUE;

        if (!t1.equals(t2)) {
            throw new RuntimeException("TRUE values not equal");
        }

        if (t1.hashCode() != t2.hashCode()) {
            throw new RuntimeException("Equal TRUE values must have same hashCode");
        }

        Asn1Boolean f1 = Asn1Boolean.of(false);
        Asn1Boolean f2 = Asn1Boolean.FALSE;

        if (!f1.equals(f2)) {
            throw new RuntimeException("FALSE values not equal");
        }

        if (f1.hashCode() != f2.hashCode()) {
            throw new RuntimeException("Equal FALSE values must have same hashCode");
        }
    }

    private static void testInequality() {
        if (Asn1Boolean.TRUE.equals(Asn1Boolean.FALSE)) {
            throw new RuntimeException("TRUE and FALSE must not be equal");
        }
    }

    private static void testTagConsistency() {
        Asn1Tag tTag = Asn1Boolean.TRUE.tag();
        Asn1Tag fTag = Asn1Boolean.FALSE.tag();

        if (!tTag.equals(fTag)) {
            throw new RuntimeException("TRUE and FALSE must have same tag");
        }
    }

    private static void testNullAndTypeSafety() {
        if (Asn1Boolean.TRUE.equals(null)) {
            throw new RuntimeException("Should not equal null");
        }

        if (Asn1Boolean.TRUE.equals("not a boolean")) {
            throw new RuntimeException("Should not equal different type");
        }
    }
}