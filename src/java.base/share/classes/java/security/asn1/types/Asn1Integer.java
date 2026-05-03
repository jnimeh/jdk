package java.security.asn1.types;

import java.math.BigInteger;
import java.util.Objects;
import java.security.asn1.*;

/**
 * Class designed to carry arbitrary-length integer data in ASN.1 per
 * X.680 and X.690.
 */
public final class Asn1Integer implements Asn1Primitive {

    private final BigInteger value;

    private Asn1Integer(BigInteger value) {
        this.value = value;
    }

    /**
     * Create an {@code Asn1Integer} from a {@link BigInteger} input
     *
     * @param value an integer held as a {@link BigInteger}
     * @return the {@code Asn1Integer}
     * @throws NullPointerException if {@code value} is {@code null}
     */
    public static Asn1Integer of(BigInteger value) {
        return new Asn1Integer(Objects.requireNonNull(value));
    }

    /**
     * Create an {@code Asn1Integer} from a primitive integral value
     *
     * @param value the integral value to represent with this
     * {@code Asn1Integer}
     * @return the {@code Asn1Integer}
     */
    public static Asn1Integer of(long value) {
        return new Asn1Integer(BigInteger.valueOf(value));
    }

    /**
     * Obtain the value of this {@code Asn1Integer} as a {@link BigInteger}
     *
     * @return the {@link BigInteger} value of this object
     */
    public BigInteger value() {
        return value;
    }

    /**
     * Return the ASN.1 tag for this {@code Asn1Object}
     *
     * @return the ASN.1 tag used for this object
     */
    @Override
    public Asn1Tag tag() {
        return Asn1Tags.INTEGER;
    }

    @Override
    public String toString() {
        return value.toString();
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        Asn1Integer that = (Asn1Integer) o;
        return value.equals(that.value);
    }

    @Override
    public int hashCode() {
        return value.hashCode();
    }
}
