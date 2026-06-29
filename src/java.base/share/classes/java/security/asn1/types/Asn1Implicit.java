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
 * @param <T> the type of the encapsulated {@code Asn1Object}
 */
public final class Asn1Implicit<T extends Asn1Object> implements Asn1Tagged<T> {

    private final Asn1Tag tag;
    private final T inner;

    private Asn1Implicit(Asn1Tag tag, T inner) {
        this.tag = tag;
        this.inner = inner;
    }

    /**
     * Create an {@code Asn1Implicit} object from its underlying
     * {@link Asn1Object}
     *
     * @param tag the desired {@link Asn1Tag} to be applied to this object
     * @param inner the inner {@link Asn1Object} (or subclass) it wraps
     * @param <T> the type of encapsulated data this object holds
     * @return the {@code Asn1Implicit} object that encapsulates the underlying
     * ASN.1 object.
     * @throws NullPointerException if either {@code tag} or {@code inner} are
     * {@code null}
     * @throws Asn1Exception if the {@code tag} does not match the
     * primitive/constructed bit of its underlying type.
     */
    public static <T extends Asn1Object> Asn1Implicit<T> of(
            Asn1Tag tag, T inner) {
        Objects.requireNonNull(tag, "Illegal missing implicit tag");
        Objects.requireNonNull(inner, "Illegal missing implicit value");
        if (tag.isConstructed() != inner.tag().isConstructed()) {
            throw new Asn1Exception("IMPLICIT must preserve constructed bit");
        }
        return new Asn1Implicit<>(tag, inner);
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
    public T inner() {
        return inner;
    }
}
