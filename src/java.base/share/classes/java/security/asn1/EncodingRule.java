package java.security.asn1;

/**
 * Basic enumeration for encoding rules.  For BER, DER and CER rules, see
 * X.690: "Information technology – ASN.1 encoding rules: Specification of
 * Basic Encoding Rules (BER), Canonical Encoding Rules (CER) and
 * Distinguished Encoding Rules (DER)"
 */
public enum EncodingRule {
    /** Basic Encoding Rules (BER) (see X.690) */
    BER,

    /** Distinguished Encoding Rules (DER) (see X.690) */
    DER,

    /** Canonical Encoding Rules (CER) */
    CER
}
