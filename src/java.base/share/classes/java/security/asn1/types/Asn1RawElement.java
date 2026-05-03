package java.security.asn1.types;

import java.security.asn1.Asn1Object;
import java.security.asn1.Asn1Tag;
import java.util.Arrays;
import java.util.Objects;

/**
 * Provide a general-purpose container for raw ASN.1 data.  This class can
 * be used to carry opaque data that would not be handled by other concrete
 * ASN.1 types.
 */
public final class Asn1RawElement implements Asn1Object {

    private final Asn1Tag tag;
    private final byte[] value;

    /**
     * Construct the Asn1RawElement
     *
     * @param tag the {@link Asn1Tag} for this element
     * @param value the data for this element
     * @throws NullPointerException if either {@code tag} or {@code value}
     * are {@code null}
     */
    private Asn1RawElement(Asn1Tag tag, byte[] value) {
        this.tag = Objects.requireNonNull(tag, "tag must not be null");
        this.value = Objects.requireNonNull(value, "value must not be null").clone();
    }

    /**
     * Create an {@code Asn1RawElement} from a tag and associated data.
     *
     * @param tag the {@link Asn1Tag} for this element
     * @param value the data for this element
     * @return the tagged, raw element
     * @throws NullPointerException if either {@code tag} or {@code value}
     * are {@code null}
     */
    public static Asn1RawElement of(Asn1Tag tag, byte[] value) {
        return new Asn1RawElement(tag, value);
    }

    /**
     * Return the ASN.1 tag for this {@code Asn1RawElement}
     *
     * @return the ASN.1 tag used for this object
     */
    @Override
    public Asn1Tag tag() {
        return tag;
    }

    /**
     * Get the data associated with this element
     *
     * @return the data
     */
    public byte[] value() {
        return value.clone();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || o.getClass() != getClass()) return false;
        Asn1RawElement other = (Asn1RawElement) o;
        return tag.equals(other.tag) && Arrays.equals(this.value, other.value);
    }

    @Override
    public int hashCode() {
        int result = tag.hashCode();
        result = 31 * result + Arrays.hashCode(value);
        return result;
    }
}
