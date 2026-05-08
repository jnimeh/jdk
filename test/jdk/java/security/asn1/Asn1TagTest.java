/*
 * @test
 * @summary Tests equality, hashCode, and basic invariants of Asn1Tag
 * @run main Asn1TagTest
 */

import java.security.asn1.Asn1Tag;
import java.security.asn1.Asn1Tag.TagClass;

public class Asn1TagTest {

    public static void main(String[] args) {
        testEqualsAndHashCode();
        testInequality();
        testSelfEquality();
        testNullAndTypeSafety();
        testAccessors();
    }

    private static void testEqualsAndHashCode() {
        Asn1Tag t1 = Asn1Tag.universal(2, false);
        Asn1Tag t2 = Asn1Tag.universal(2, false);

        if (!t1.equals(t2)) {
            throw new RuntimeException("Equal tags not considered equal");
        }

        if (t1.hashCode() != t2.hashCode()) {
            throw new RuntimeException("Equal tags must have same hashCode");
        }
    }

    private static void testInequality() {
        Asn1Tag base = Asn1Tag.universal(2, false);

        Asn1Tag diffClass = Asn1Tag.application(2, false);
        Asn1Tag diffNumber = Asn1Tag.universal(3, false);
        Asn1Tag diffConstructed = Asn1Tag.universal(2, true);

        if (base.equals(diffClass)) {
            throw new RuntimeException("Different tagClass considered equal");
        }

        if (base.equals(diffNumber)) {
            throw new RuntimeException("Different tagNumber considered equal");
        }

        if (base.equals(diffConstructed)) {
            throw new RuntimeException("Different constructed bit considered equal");
        }
    }

    private static void testSelfEquality() {
        Asn1Tag t = Asn1Tag.context(10, true);

        if (!t.equals(t)) {
            throw new RuntimeException("Tag not equal to itself");
        }
    }

    private static void testNullAndTypeSafety() {
        Asn1Tag t = Asn1Tag.priv(5, false);

        if (t.equals(null)) {
            throw new RuntimeException("Tag equals null");
        }

        if (t.equals("not a tag")) {
            throw new RuntimeException("Tag equals different type");
        }
    }

    private static void testAccessors() {
        Asn1Tag t = Asn1Tag.priv(55, true);

        int tagNum = t.tagNumber();
        if (tagNum != 55) {
            throw new RuntimeException("Expected tag number 55, got " + tagNum);
        }

        TagClass tagClass = t.tagClass();
        if (tagClass != TagClass.PRIVATE) {
            throw new RuntimeException("Expected tag class PRIVATE, got " +
                    tagClass);
        }

        if (!t.isConstructed()) {
            throw new RuntimeException("Tag created with constructed bit, " +
                    "but isConstructed() returned false");
        }
    }
}