package java.security.asn1.types;

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

    private final byte[] bytes;
    private final int unusedBits;

    private Asn1BitString(byte[] bytes, int unusedBits) {
        this.bytes = bytes.clone();
        this.unusedBits = unusedBits;
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
        if (bytes.length == 0 && unusedBits != 0) {
            throw new Asn1Exception("Cannot have unused bits with empty array");
        }
        if (bytes.length > 0 && unusedBits > 0) {
            bytes[bytes.length - 1] &= (byte)(0xFF << unusedBits);
        }
        return new Asn1BitString(dataCopy, unusedBits);
    }

    /**
     * Return a copy of the bits, implemented as a byte array.
     *
     * @return the data bytes
     */
    public byte[] bytes() {
        return bytes.clone();
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

        int diff = 0;

        // compare length and unused bits
        diff |= this.unusedBits ^ other.unusedBits;
        diff |= this.bytes.length ^ other.bytes.length;

        int len = Math.min(this.bytes.length, other.bytes.length);

        // Compare all bytes except last
        for (int i = 0; i < len - 1; i++) {
            diff |= (this.bytes[i] ^ other.bytes[i]);
        }

        // Compare last byte with masking
        if (len > 0) {
            int b1 = this.bytes[len - 1] & 0xFF;
            int b2 = other.bytes[len - 1] & 0xFF;
            int mask = 0xFF << this.unusedBits;

            // b1 is already normalized in the constructor
            diff |= (b1 ^ mask) ^ (b2 & mask);
        }

        return diff == 0;
    }

    @Override
    public int hashCode() {
        // Because we've already normalized the unused bits in
        // the constructor, we can simply consume the entire byte
        // array and stir in the unused bit count.
        int result = Arrays.hashCode(bytes);
        result = 31 * result + unusedBits;
        return result;
    }
}
