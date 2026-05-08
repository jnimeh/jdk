package java.security.asn1;

import java.security.asn1.types.Asn1Explicit;
import java.security.asn1.types.Asn1Implicit;

/**
 * Interface to handle ASN.1 tagging (implicit and explicit)
 * @param <T> the class of the inner type that the {@code Asn1Tagged} type
 *            encapsulates.
 */
public sealed interface Asn1Tagged<T extends Asn1Object> extends Asn1Object
        permits Asn1Explicit, Asn1Implicit {

    /**
     * Return the underlying {@link Asn1Object} that the tagged object
     * encompasses.
     *
     * @return the inner object represented by the tagged object.
     */
    T inner();
}