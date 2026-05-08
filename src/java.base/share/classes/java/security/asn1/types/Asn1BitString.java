package java.security.asn1.types;

import java.security.MessageDigest;
import java.security.asn1.Asn1Exception;
import java.util.Arrays;
import java.util.Objects;
import java.security.asn1.Asn1Primitive;
import java.security.asn1.Asn1Tag;
import java.security.asn1.Asn1Tags;

/**
 * ASN.1 BIT STRING primitive type.
 * Stores a sequence of bits and a number of unused bits in the last byte.
 * Example: 10110110 11000000 (with 6 unused bits in last byte)
 */
public final class Asn1BitString implements Asn1Primitive {

    private final byte[] data;
    private final int unusedBits;

    private Asn1BitString(byte[] bytes, int unusedBits) {
        this.data = bytes;                  // already copied and != null
        this.unusedBits = unusedBits;
        // Mask the unused bits in the last byte
        if (this.data.length > 0 && this.unusedBits > 0) {
            int mask = (0xFF << this.unusedBits) & 0xFF;
            this.data[this.data.length - 1] &= (byte)mask;
        }
    }

    /**
     * Create a BIT STRING with given bytes, where every bit of the
     * data is significant (no unused bits).
     *
     * @param bytes the byte array storing the bits
     * @return the {@code Asn1BitString} with no unused bits
     * @throws NullPointerException if {@code bytes} is {@code null}
     */
    public static Asn1BitString of(byte[] bytes) {
        return of(bytes, 0);
    }

    /**
     * Create a BIT STRING with given bytes, the number of unused bits
     * in the last byte.
     *
     * @param bytes the byte array storing the bits
     * @param unusedBits number of unused bits in last byte (0-7)
     * @return the {@code Asn1BitString} with unused bits configured
     * @throws Asn1Exception if the number of unused bits is not
     * in the range [0..7] or if a zero-length array is provided with a
     * non-zero number of unused bits.
     * @throws NullPointerException if {@code bytes} is {@code null}
     */
    public static Asn1BitString of(byte[] bytes, int unusedBits) {
        byte[] dataCopy = Objects.requireNonNull(bytes).clone();
        if (unusedBits < 0 || unusedBits > 7) {
            throw new Asn1Exception("unusedBits must be 0..7");
        }
        if (dataCopy.length == 0 && unusedBits != 0) {
            throw new Asn1Exception("Cannot have unused bits with empty array");
        }
        if (dataCopy.length > 0 && unusedBits > 0) {
            dataCopy[dataCopy.length - 1] &= (byte)(0xFF << unusedBits);
        }
        return new Asn1BitString(dataCopy, unusedBits);
    }

    /**
     * Return a copy of the bits, implemented as a byte array.
     *
     * @return the data bytes
     */
    public byte[] bytes() {
        return data.clone();
    }

    /**
     * Returns the number of unused bits in the last byte.
     *
     * @return the number of unused bits
     */
    public int unusedBits() {
        return unusedBits;
    }

    /**
     * Return the ASN.1 tag for this bit string
     *
     * @return the {@code Asn1Tag} for this bit string
     */
    @Override
    public Asn1Tag tag() {
        return Asn1Tags.BIT_STRING;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || o.getClass() != getClass()) return false;
        Asn1BitString other = (Asn1BitString) o;
        return this.unusedBits == other.unusedBits &&
                MessageDigest.isEqual(this.data, other.data);
    }

    @Override
    public int hashCode() {
        // Because we've already normalized the unused bits in
        // the constructor, we can simply consume the entire byte
        // array and stir in the unused bit count.
        int result = Arrays.hashCode(data);
        result = 31 * result + unusedBits;
        return result;
    }
}
