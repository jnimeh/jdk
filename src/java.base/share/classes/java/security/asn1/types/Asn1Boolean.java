package java.security.asn1.types;

import java.security.asn1.*;
import java.util.Objects;


/**
 * ASN.1 class for representing boolean data
 */
public final class Asn1Boolean implements Asn1Primitive {

    /** Static instance for representing {@code Asn1Boolean} true values */
    public static final Asn1Boolean TRUE = new Asn1Boolean(true);
    /** Static instance for representing {@code Asn1Boolean} false values */
    public static final Asn1Boolean FALSE = new Asn1Boolean(false);

    private final boolean value;

    private Asn1Boolean(boolean value) {
        this.value = value;
    }

    /**
     * Create an {@code Asn1Boolean} from a simple {@code boolean} value
     *
     * @param value the underlying {@code boolean} value
     * @return the {@code Asn1Boolean}
     */
    public Asn1Boolean of(boolean value) {
        return value ? TRUE : FALSE;
    }

    /**
     * Return the boolean value this object represents
     *
     * @return the boolean value for the object
     */
    public boolean value() {
        return value;
    }

    /**
     * Return the ASN.1 tag for this {@code Asn1Boolean}
     * @return the ASN.1 tag used for this object
     */
    @Override
    public Asn1Tag tag() {
        return Asn1Tags.BOOLEAN;
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        Asn1Boolean that = (Asn1Boolean) o;
        return value == that.value;
    }

    @Override
    public int hashCode() {
        return Boolean.hashCode(value);
    }
}
