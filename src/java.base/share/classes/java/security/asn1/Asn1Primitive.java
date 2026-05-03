package java.security.asn1;

import java.security.asn1.types.*;

/**
 * Interface for defining ASN.1 primitive data types
 */
public sealed interface Asn1Primitive extends Asn1Object
        permits Asn1ObjectIdentifier, Asn1BitString, Asn1Boolean,
        Asn1GeneralizedTime, Asn1IA5String, Asn1Integer, Asn1Null,
        Asn1PrintableString, Asn1UTCTime { }