package java.security.asn1;

import java.security.asn1.types.Asn1Explicit;
import java.security.asn1.types.Asn1Implicit;

/**
 * Interface to handle ASN.1 tagging (implicit and explicit)
 */
public sealed interface Asn1Tagged extends Asn1Object
        permits Asn1Explicit, Asn1Implicit {

    /**
     * Return the underlying {@link Asn1Object} that the tagged object
     * encompasses.
     *
     * @return the inner {@link Asn1Object} represented by the tagged object.
     */
    Asn1Object inner();
}