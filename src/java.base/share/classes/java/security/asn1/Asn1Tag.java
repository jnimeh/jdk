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
        new AbstractMap.SimpleImmutableEntry<>(1, Asn1Tags.BOOLEAN),
        new AbstractMap.SimpleImmutableEntry<>(2, Asn1Tags.INTEGER),
        new AbstractMap.SimpleImmutableEntry<>(3, Asn1Tags.BIT_STRING),
        new AbstractMap.SimpleImmutableEntry<>(4, Asn1Tags.OCTET_STRING),
        new AbstractMap.SimpleImmutableEntry<>(5, Asn1Tags.NULL),
        new AbstractMap.SimpleImmutableEntry<>(6, Asn1Tags.OBJECT_IDENTIFIER),
        new AbstractMap.SimpleImmutableEntry<>(7, Asn1Tags.OBJECT_DESCRIPTOR),
        new AbstractMap.SimpleImmutableEntry<>(8, Asn1Tags.EXTERNAL),
        new AbstractMap.SimpleImmutableEntry<>(9, Asn1Tags.REAL),
        new AbstractMap.SimpleImmutableEntry<>(10, Asn1Tags.ENUMERATED),
        new AbstractMap.SimpleImmutableEntry<>(11, Asn1Tags.EMBEDDED_PDV),
        new AbstractMap.SimpleImmutableEntry<>(12, Asn1Tags.UTF8String),
        new AbstractMap.SimpleImmutableEntry<>(16, Asn1Tags.SEQUENCE),
        new AbstractMap.SimpleImmutableEntry<>(17, Asn1Tags.SET),
        new AbstractMap.SimpleImmutableEntry<>(18, Asn1Tags.NUMERIC_STRING),
        new AbstractMap.SimpleImmutableEntry<>(19, Asn1Tags.PRINTABLE_STRING),
        new AbstractMap.SimpleImmutableEntry<>(20, Asn1Tags.TELETEX_STRING),
        new AbstractMap.SimpleImmutableEntry<>(21, Asn1Tags.VIDEOTEX_STRING),
        new AbstractMap.SimpleImmutableEntry<>(22, Asn1Tags.IA5_STRING),
        new AbstractMap.SimpleImmutableEntry<>(23, Asn1Tags.UTCTIME),
        new AbstractMap.SimpleImmutableEntry<>(24, Asn1Tags.GENERALIZEDTIME),
        new AbstractMap.SimpleImmutableEntry<>(25, Asn1Tags.GRAPHIC_STRING),
        new AbstractMap.SimpleImmutableEntry<>(26, Asn1Tags.VISIBLE_STRING),
        new AbstractMap.SimpleImmutableEntry<>(27, Asn1Tags.GENERAL_STRING),
        new AbstractMap.SimpleImmutableEntry<>(28, Asn1Tags.UNIVERSAL_STRING)
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
    public Asn1Tag(TagClass tagClass, int tagNumber, boolean constructed) {
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
