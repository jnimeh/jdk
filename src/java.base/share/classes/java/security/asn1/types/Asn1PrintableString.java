package java.security.asn1.types;

import java.util.Objects;
import java.security.asn1.*;

/**
 * Class designed to represent the ASN.1 printable string type.  Printable
 * Strings must consist only of characters allowed in the printable string
 * character set defined in X.680 and X.690.
 */
public final class Asn1PrintableString implements Asn1Primitive {

    private final String value;

    private Asn1PrintableString(String value) {
        this.value = validate(value);
    }

    /**
     * Create an {@code Asn1PrintableString} from a {@link String} object
     *
     * @param value the string to construct the object from
     * @return the {@code Asn1PrintableString} representation of {@code value}
     * @throws NullPointerException if {@code value} is {@code null}
     * @throws Asn1Exception if the string value has characters not allowed
     * in the ASN.1 printable string character set.
     */
    public static Asn1PrintableString of(String value) {
        return new Asn1PrintableString(value);
    }

    private String validate(String s) {
        Objects.requireNonNull(s);
        if (!s.matches("[A-Za-z0-9 '()+,\\-./:=?]*")) {
            throw new Asn1Exception("Invalid PrintableString");
        }
        return s;
    }

    /**
     * Return the data represented by this {@code Asn1PrintableString}.
     *
     * @return the {@link String} data this object represents.
     */
    public String value() {
        return value;
    }

    /**
     * Return the ASN.1 tag for this {@code Asn1Object}
     *
     * @return the ASN.1 tag used for this object
     */
    @Override
    public Asn1Tag tag() {
        return Asn1Tags.PRINTABLE_STRING;
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        Asn1PrintableString that = (Asn1PrintableString) o;
        return value.equals(that.value);
    }

    @Override
    public int hashCode() {
        return value.hashCode();
    }
}
