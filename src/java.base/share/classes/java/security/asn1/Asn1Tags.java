package java.security.asn1;

/**
 * Class that defines a number of statically defined {@link Asn1Tag} objects
 * for the most commonly used ASN.1 UNIVERSAL tags.
 */
public final class Asn1Tags {

    private Asn1Tags() {}

    /** {@code BOOLEAN} ASN.1 Tag object (primitive) */
    public static final Asn1Tag BOOLEAN = Asn1Tag.universal(1, false);

    /** {@code INTEGER} ASN.1 Tag object (primitive) */
    public static final Asn1Tag INTEGER = Asn1Tag.universal(2, false);

    /** {@code BIT STRING} ASN.1 Tag object (primitive) */
    public static final Asn1Tag BIT_STRING = Asn1Tag.universal(3, false);

    /** {@code OCTET STRING} ASN.1 Tag object (primitive) */
    public static final Asn1Tag OCTET_STRING = Asn1Tag.universal(4, false);

    /** {@code NULL} ASN.1 Tag object (primitive) */
    public static final Asn1Tag NULL = Asn1Tag.universal(5, false);

    /** {@code OBJECT IDENTIFIER} ASN.1 Tag object (primitive) */
    public static final Asn1Tag OBJECT_IDENTIFIER = Asn1Tag.universal(6, false);

    /** {@code ObjectDescriptor} ASN.1 Tag object (primitive) */
    public static final Asn1Tag OBJECT_DESCRIPTOR = Asn1Tag.universal(7, false);

    /** {@code EXTERNAL} ASN.1 Tag object (constructed) */
    public static final Asn1Tag EXTERNAL = Asn1Tag.universal(8, true);

    /** {@code REAL} ASN.1 Tag object (primitive) */
    public static final Asn1Tag REAL = Asn1Tag.universal(9, false);

    /** {@code ENUMERATED} ASN.1 Tag object (primitive) */
    public static final Asn1Tag ENUMERATED = Asn1Tag.universal(10, false);

    /** {@code EMBEDDED} PDV ASN.1 Tag object (constructed) */
    public static final Asn1Tag EMBEDDED_PDV = Asn1Tag.universal(11, true);

    /** {@code UTF8String} ASN.1 Tag object (primitive) */
    public static final Asn1Tag UTF8String = Asn1Tag.universal(12, false);

    /**
     * {@code SEQUENCE} and {@code SEQUENCE OF} ASN.1 Tag object (constructed)
     */
    public static final Asn1Tag SEQUENCE = Asn1Tag.universal(16, true);

    /** {@code SET} and {@code SET OF} ASN.1 Tag object (constructed) */
    public static final Asn1Tag SET = Asn1Tag.universal(17, true);

    /** {@code NumericString} ASN.1 Tag object (primitive) */
    public static final Asn1Tag NUMERIC_STRING = Asn1Tag.universal(18, false);

    /**
     * {@code PrintableString} ASN.1 Tag object (primitive)
     */
    public static final Asn1Tag PRINTABLE_STRING = Asn1Tag.universal(19, false);

    /** {@code TeletexString}/{@code T61String} ASN.1 Tag object (primitive) */
    public static final Asn1Tag TELETEX_STRING = Asn1Tag.universal(20, false);

    /** {@code VideotexString} ASN.1 Tag object (primitive) */
    public static final Asn1Tag VIDEOTEX_STRING = Asn1Tag.universal(21, false);

    /** {@code IA5String} ASN.1 Tag object (primitive) */
    public static final Asn1Tag IA5_STRING = Asn1Tag.universal(22, false);

    /** {@code UTCTime} ASN.1 Tag object (primitive) */
    public static final Asn1Tag UTCTIME = Asn1Tag.universal(23, false);

    /** {@code GeneralizedTime} ASN.1 Tag object (primitive) */
    public static final Asn1Tag GENERALIZEDTIME = Asn1Tag.universal(24, false);

    /** {@code GraphicString} ASN.1 Tag object (primitive) */
    public static final Asn1Tag GRAPHIC_STRING = Asn1Tag.universal(25, false);

    /** {@code VisibleString} ASN.1 Tag object (primitive) */
    public static final Asn1Tag VISIBLE_STRING = Asn1Tag.universal(26, false);

    /** {@code GeneralString} ASN.1 Tag object (primitive) */
    public static final Asn1Tag GENERAL_STRING = Asn1Tag.universal(27, false);

    /** {@code UniversalString} ASN.1 Tag object (primitive) */
    public static final Asn1Tag UNIVERSAL_STRING = Asn1Tag.universal(28, false);

    /** {@code BMPString} ASN.1 Tag object (primitive) */
    public static final Asn1Tag BMP_STRING = Asn1Tag.universal(30, false);
}
