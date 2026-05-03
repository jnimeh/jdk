package java.security.asn1.types;

import java.security.asn1.*;

/**
 * Class to represent NULL ASN.1 data fields.  This class is a singleton
 * as it does not carry any unique data of its own.
 */
public final class Asn1Null implements Asn1Primitive {

    /** Singleton for the {@code Asn1Null} type */
    public static final Asn1Null NULL = new Asn1Null();

    private Asn1Null() { }

    /**
     * Return the ASN.1 tag for this {@code Asn1Boolean}
     *
     * @return the {@link Asn1Tag} used for this object
     */
    @Override
    public Asn1Tag tag() {
        return Asn1Tags.NULL;
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof Asn1Null;
    }

    @Override
    public int hashCode() {
        return 0;
    }
}
