package java.security.asn1.types;

import java.util.Objects;
import java.security.asn1.*;

/**
 * Class designed to hold IA5String data per X.680 and X.690
 */
public final class Asn1IA5String implements Asn1Primitive {

    private final String value;

    private Asn1IA5String(String value) {
        this.value = value;
    }

    /**
     * Create an {@code IA5String} object from simple {@link String} input.
     *
     * @param value the {@code String} used as input to this object
     * @return the {@code Asn1IA5String} representation of {@code value}
     * @throws NullPointerException if {@code value} is {@code null}
     * @throws Asn1Exception if there are any characters in the {@code value}
     * parameter that violate the IA5String character set.
     */
    public static Asn1IA5String of(String value) {
        if (validate(value)) {
            return new Asn1IA5String(value);
        } else {
            throw new Asn1Exception(
                    "Illegal characters provided to Asn1IA5String");
        }
    }

    /**
     * Create an {@code IA5String} object from simple {@link String} input.
     *
     * @param stringBytes the {@code String} used as input to this object
     * @return the {@code Asn1IA5String} representation of {@code stringBytes}
     * @throws NullPointerException if {@code value} is {@code null}
     * @throws Asn1Exception if there are any characters in the {@code value}
     * parameter that violate the IA5String character set.
     */
    public static Asn1IA5String of(byte[] stringBytes) {
        for (byte b : Objects.requireNonNull(stringBytes)) {
            if (b < 0) {            // Unsigned it is 128 or larger, disallowed
                throw new Asn1Exception(
                        "Illegal characters provided to Asn1IA5String");
            }
        }
        return new Asn1IA5String(new String(stringBytes));
    }

    private static boolean validate(String s) {
        return Objects.requireNonNull(s).codePoints().allMatch(c -> c <= 127);
    }

    /**
     * Obtain the value of this {@code Asn1IA5String} in {@link String} form.
     *
     * @return the {@link String} value for this {@code Asn1IA5String}
     */
    @Override
    public String toString() {
        return value;
    }

    /**
     * Return the ASN.1 tag for this {@code Asn1Object}
     * @return the ASN.1 tag used for this object
     */
    @Override
    public Asn1Tag tag() {
        return Asn1Tags.IA5_STRING;
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        Asn1IA5String that = (Asn1IA5String) o;
        return value.equals(that.value);
    }

    @Override
    public int hashCode() {
        return value.hashCode();
    }
}
