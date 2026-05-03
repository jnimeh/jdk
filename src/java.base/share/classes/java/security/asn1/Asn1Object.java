
package java.security.asn1;

import java.security.asn1.types.Asn1OctetString;
import java.security.asn1.types.Asn1RawElement;
import java.security.asn1.types.Asn1Time;

/**
 * Top-level interface for defining primitive and constructed ASN.1 types.
 */
public sealed interface Asn1Object
        permits Asn1Constructed, Asn1Primitive, Asn1Tagged, Asn1OctetString,
        Asn1RawElement {

    /**
     * Return the ASN.1 tag for this {@code Asn1Object}
     * @return the ASN.1 tag used for this object
     */
    Asn1Tag tag();
}
