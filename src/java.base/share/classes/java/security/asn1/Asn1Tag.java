package java.security.asn1;

import java.util.AbstractMap;
import java.util.Map;
import java.util.Objects;

/**
 * Class that represents ASN.1 Tags
 */
public final class Asn1Tag {

    private final TagClass tagClass;
    private final int tagNumber;
    private final boolean constructed;

    private static final Map<Integer, Asn1Tag> UNIVERSAL_MAP = Map.ofEntries(
        new AbstractMap.SimpleImmutableEntry<>(1,
                new Asn1Tag(TagClass.UNIVERSAL, 1, false)),     // Integer
        new AbstractMap.SimpleImmutableEntry<>(2,
                new Asn1Tag(TagClass.UNIVERSAL, 2, false)),     // Boolean
        new AbstractMap.SimpleImmutableEntry<>(3,
                new Asn1Tag(TagClass.UNIVERSAL, 3, false)),     // Bit String
        new AbstractMap.SimpleImmutableEntry<>(4,
                new Asn1Tag(TagClass.UNIVERSAL, 4, false)),     // Octet String
        new AbstractMap.SimpleImmutableEntry<>(5,
                new Asn1Tag(TagClass.UNIVERSAL, 5, false)),     // NULL
        new AbstractMap.SimpleImmutableEntry<>(6,
                new Asn1Tag(TagClass.UNIVERSAL, 6, false)),     // Object ID
        new AbstractMap.SimpleImmutableEntry<>(7,
                new Asn1Tag(TagClass.UNIVERSAL, 7, false)),     // Object Desc
        new AbstractMap.SimpleImmutableEntry<>(8,
                new Asn1Tag(TagClass.UNIVERSAL, 8, true)),      // External
        new AbstractMap.SimpleImmutableEntry<>(9,
                new Asn1Tag(TagClass.UNIVERSAL, 9, false)),     // Real
        new AbstractMap.SimpleImmutableEntry<>(10,
                new Asn1Tag(TagClass.UNIVERSAL, 10, false)),    // Enumerated
        new AbstractMap.SimpleImmutableEntry<>(11,
                new Asn1Tag(TagClass.UNIVERSAL, 11, false)),    // Embedded PDV
        new AbstractMap.SimpleImmutableEntry<>(12,
                new Asn1Tag(TagClass.UNIVERSAL, 12, false)),    // UTF8 String
        new AbstractMap.SimpleImmutableEntry<>(16,
                new Asn1Tag(TagClass.UNIVERSAL, 16, true)),     // Sequence [Of]
        new AbstractMap.SimpleImmutableEntry<>(17,
                new Asn1Tag(TagClass.UNIVERSAL, 17, true)),     // Set [Of]
        new AbstractMap.SimpleImmutableEntry<>(18,
                new Asn1Tag(TagClass.UNIVERSAL, 18, false)),    // NumericString
        new AbstractMap.SimpleImmutableEntry<>(19,
                new Asn1Tag(TagClass.UNIVERSAL, 19, false)),    // PrintableString
        new AbstractMap.SimpleImmutableEntry<>(20,
                new Asn1Tag(TagClass.UNIVERSAL, 20, false)),    // Teletex/T61String
        new AbstractMap.SimpleImmutableEntry<>(21,
                new Asn1Tag(TagClass.UNIVERSAL, 21, false)),    // VideotexString
        new AbstractMap.SimpleImmutableEntry<>(22,
                new Asn1Tag(TagClass.UNIVERSAL, 22, false)),    // IA5String
        new AbstractMap.SimpleImmutableEntry<>(23,
                new Asn1Tag(TagClass.UNIVERSAL, 23, false)),    // UTCTime
        new AbstractMap.SimpleImmutableEntry<>(24,
                new Asn1Tag(TagClass.UNIVERSAL, 24, false)),    // GeneralizedTime
        new AbstractMap.SimpleImmutableEntry<>(25,
                new Asn1Tag(TagClass.UNIVERSAL, 25, false)),    // GraphicString
        new AbstractMap.SimpleImmutableEntry<>(26,
                new Asn1Tag(TagClass.UNIVERSAL, 26, false)),    // VisibleString
        new AbstractMap.SimpleImmutableEntry<>(27,
                new Asn1Tag(TagClass.UNIVERSAL, 27, false)),    // GeneralString
        new AbstractMap.SimpleImmutableEntry<>(28,
                new Asn1Tag(TagClass.UNIVERSAL, 28, false)),    // UniversalString
        new AbstractMap.SimpleImmutableEntry<>(30,
                new Asn1Tag(TagClass.UNIVERSAL, 30, false))     // BMPString
    );

    /**
     * Create an {@code Asn1Tag} from its {@link TagClass}, tag number and
     * primitive/constructed bit setting.
     *
     * @param tagClass the {@link TagClass} for this {@code Asn1Tag}
     * @param tagNumber the tag number
     * @param constructed {@code true} if the {@code Asn1Tag} represents a datum
     *                    that is constructed, {@code false} if it is primitive
     * @throws Asn1Exception if the {@code tagNumber} value is negative
     */
    private Asn1Tag(TagClass tagClass, int tagNumber, boolean constructed) {
        if (tagNumber < 0) {
            throw new Asn1Exception("tagNumber must be >= 0");
        }
        this.tagClass = Objects.requireNonNull(tagClass);
        this.tagNumber = tagNumber;
        this.constructed = constructed;
    }

    /**
     * Return the tag class for this {@code Asn1Tag}
     *
     * @return the {@link TagClass} for this object
     */
    public TagClass tagClass() {
        return tagClass;
    }

    /**
     * Return the tag number for this {@code Asn1Tag}
     *
     * @return the tag number
     */
    public int tagNumber() {
        return tagNumber;
    }

    /**
     * Indicate whether this {@code Asn1Tag} is primitive or constructed
     *
     * @return {@code true} if the tag is constructed, {@code false} if
     * it is primitive
     */
    public boolean isConstructed() {
        return constructed;
    }

    /**
     * Create a UNIVERSAL {@code Asn1Tag} with a chosen tag number and
     * primitive/constructed bit.
     *
     * @param tagNumber the tag number
     * @param constructed {@code true} if the tag represents a constructed
     *                    data type, {@code false} if it is primitive
     * @return the UNIVERSAL {@code Asn1Tag} with the desired tag number
     * and tag class.
     * @throws Asn1Exception if the {@code tagNumber} value is negative
     */
    public static Asn1Tag universal(int tagNumber, boolean constructed) {
        Asn1Tag temp = UNIVERSAL_MAP.get(tagNumber);
        return (temp != null && temp.isConstructed() == constructed) ? temp :
                new Asn1Tag(TagClass.UNIVERSAL, tagNumber, constructed);
    }

    /**
     * Create a CONTEXT SPECIFIC {@code Asn1Tag} with a chosen tag number and
     * primitive/constructed bit.
     *
     * @param tagNumber the tag number
     * @param constructed {@code true} if the tag represents a constructed
     *                    data type, {@code false} if it is primitive
     * @return the CONTEXT SPECIFIC {@code Asn1Tag} with the desired tag number
     * and tag class.
     * @throws Asn1Exception if the {@code tagNumber} value is negative
     */
    public static Asn1Tag context(int tagNumber, boolean constructed) {
        return new Asn1Tag(TagClass.CONTEXT_SPECIFIC, tagNumber, constructed);
    }

    /**
     * Create an APPLICATION {@code Asn1Tag} with a chosen tag number and
     * primitive/constructed bit.
     *
     * @param tagNumber the tag number
     * @param constructed {@code true} if the tag represents a constructed
     *                    data type, {@code false} if it is primitive
     * @return the APPLICATION {@code Asn1Tag} with the desired tag number
     * and tag class.
     * @throws Asn1Exception if the {@code tagNumber} value is negative
     */
    public static Asn1Tag application(int tagNumber, boolean constructed) {
        return new Asn1Tag(TagClass.APPLICATION, tagNumber, constructed);
    }

    /**
     * Create a PRIVATE {@code Asn1Tag} with a chosen tag number and
     * primitive/constructed bit.
     *
     * @param tagNumber the tag number
     * @param constructed {@code true} if the tag represents a constructed
     *                    data type, {@code false} if it is primitive
     * @return the PRIVATE {@code Asn1Tag} with the desired tag number
     * and tag class.
     * @throws Asn1Exception if the {@code tagNumber} value is negative
     */
    public static Asn1Tag priv(int tagNumber, boolean constructed) {
        return new Asn1Tag(TagClass.PRIVATE, tagNumber, constructed);
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        Asn1Tag asn1Tag = (Asn1Tag) o;
        return tagNumber == asn1Tag.tagNumber
                && isConstructed() == asn1Tag.isConstructed()
                && tagClass == asn1Tag.tagClass;
    }

    @Override
    public int hashCode() {
        int result = tagClass.hashCode();
        result = 31 * result + tagNumber;
        result = 31 * result + (isConstructed() ? 1 : 0);
        return result;
    }

    /**
     * Enumeration for ASN.1 tag classes
     */
    public enum TagClass {
        /** {@code UNIVERSAL} ASN.1 Tag Class */
        UNIVERSAL,

        /** {@code APPLICATION} ASN.1 Tag Class */
        APPLICATION,

        /** {@code Context-Specific} ASN.1 Tag Class */
        CONTEXT_SPECIFIC,

        /** {@code PRIVATE} ASN.1 Tag Class */
        PRIVATE
    }
}
