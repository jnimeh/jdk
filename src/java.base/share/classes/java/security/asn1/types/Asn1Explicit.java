package java.security.asn1.types;

import java.security.asn1.Asn1Exception;
import java.security.asn1.Asn1Object;
import java.security.asn1.Asn1Tag;
import java.security.asn1.Asn1Tagged;
import java.util.Objects;

/**
 * Class that represents ASN.1 explicitly tagged types.  {@code Asn1Explicit}
 * objects are wrappers around an underlying ASN.1 data element, whether
 * constructed or primitive.
 */
public final class Asn1Explicit implements Asn1Tagged {

    private final Asn1Tag tag;
    private final Asn1Object inner;

    /**
     * Create an {@code Asn1Explicit} object from its tag value and the
     * {@link Asn1Object} that it encompasses.
     *
     * @param tag the {@link Asn1Tag} that represents the explicit tagging
     * @param inner the inner {@link Asn1Object} it wraps
     * @throws Asn1Exception if the {@code tag} does not have the constructed
     * bit set.
     */
    public Asn1Explicit(Asn1Tag tag, Asn1Object inner) {
        if (!tag.isConstructed()) {
            throw new Asn1Exception("EXPLICIT tag must be constructed");
        }
        this.tag = Objects.requireNonNull(tag);
        this.inner = Objects.requireNonNull(inner);
    }

    /**
     * Return the ASN.1 tag for this {@code Asn1Explicit} object
     *
     * @return the ASN.1 tag used for this object
     */
    @Override
    public Asn1Tag tag() {
        return tag;
    }

    /**
     * Return the underlying {@link Asn1Object} that the tagged object
     * encompasses.
     *
     * @return the inner {@link Asn1Object} represented by the tagged object.
     */
    @Override
    public Asn1Object inner() {
        return inner;
    }
}
