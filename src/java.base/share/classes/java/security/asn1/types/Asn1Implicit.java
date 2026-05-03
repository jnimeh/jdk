package java.security.asn1.types;

import java.security.asn1.Asn1Exception;
import java.security.asn1.Asn1Object;
import java.security.asn1.Asn1Tag;
import java.security.asn1.Asn1Tagged;
import java.util.Objects;

/**
 * Class that represents ASN.1 implicitly tagged types.  {@code Asn1Implicit}
 * objects are wrappers around an underlying ASN.1 data element, whether
 * constructed or primitive.
 */
public final class Asn1Implicit implements Asn1Tagged {

    private final Asn1Tag tag;
    private final Asn1Object inner;

    /**
     * Create an {@code Asn1Implicit} object from its underlying
     * {@link Asn1Object}
     *
     * @param tag the desired {@link Asn1Tag} to be applied to this object
     * @param inner the inner {@link Asn1Object} it wraps
     * @throws Asn1Exception if the {@code tag} does not match the
     * primitive/constructed bit of its underlying type.
     */
    public Asn1Implicit(Asn1Tag tag, Asn1Object inner) {
        if (tag.isConstructed() != inner.tag().isConstructed()) {
            throw new Asn1Exception("IMPLICIT must preserve constructed bit");
        }
        this.tag = Objects.requireNonNull(tag);
        this.inner = Objects.requireNonNull(inner);
    }

    /**
     * Return the ASN.1 tag for this {@code Asn1Implicit} object
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
