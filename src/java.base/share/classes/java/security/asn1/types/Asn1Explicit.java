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
 * @param <T> the type of the encapsulated {@code Asn1Object}
 */
public final class Asn1Explicit<T extends Asn1Object> implements Asn1Tagged<T> {

    private final Asn1Tag tag;
    private final T inner;

    private Asn1Explicit(Asn1Tag tag, T inner) {
        this.tag = tag;
        this.inner = inner;
    }

    /**
     * Create an {@code Asn1Explicit} object from its tag value and the
     * {@link Asn1Object} that it encompasses.
     *
     * @param tag the {@link Asn1Tag} that represents the explicit tagging
     * @param inner the inner {@link Asn1Object} (or subclass) it wraps
     * @param <T> the type of encapsulated data this object holds
     * @return the {@code Asn1Implicit} object that encapsulates the underlying
     * ASN.1 object.
     * @throws Asn1Exception if the {@code tag} does not have the constructed
     * bit set.
     */
    public static <T extends Asn1Object> Asn1Explicit<T> of(
            Asn1Tag tag, T inner) {
        if (!tag.isConstructed()) {
            throw new Asn1Exception("EXPLICIT tag must be constructed");
        }
        return new Asn1Explicit<>(Objects.requireNonNull(tag),
                Objects.requireNonNull(inner));
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
    public T inner() {
        return inner;
    }
}
