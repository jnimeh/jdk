package java.security.asn1.types;

import java.security.MessageDigest;
import java.util.*;
import java.security.asn1.*;

/**
 * Abstract class that represents ASN.1 octet string data.
 */
public abstract sealed class Asn1OctetString implements Asn1Object {

    /** No-argument abstract class constructor */
    protected Asn1OctetString() { }

    /**
     * Create a primitive {@code Asn1OctetString}
     *
     * @param data the data to be held in this {@code Asn1OctetString}
     * @return a primitive form of {@code Asn1OctetString}
     * @throws NullPointerException if {@code data} is {@code null}
     */
    public static Asn1OctetString ofPrimitive(byte[] data) {
        return new Asn1PrimitiveOctetString(Objects.requireNonNull(data,
                "Illegal null octet string data segment").clone());
    }

    /**
     * Create a constructed {@code Asn1OctetString}
     *
     * @param segments a {@link List} of data segments as byte arrays, which
     *                 will be interpreted as primitive octet string segments.
     * @return a constructed form of {@code Asn1OctetString}
     * @throws NullPointerException if {@code segments} is {@code null},
     * or if any element in the list is {@code null}
     */
    public static Asn1OctetString ofConstructed(List<byte[]> segments) {
        Objects.requireNonNull(segments,
                "Illegal null octet string collection");
        List<Asn1OctetString> segmentsCopy = segments.stream()
                .map(b -> Asn1OctetString.ofPrimitive(
                        Objects.requireNonNull(b, "Found null byte[] in list")))
                .toList();
        return new Asn1ConstructedOctetString(segmentsCopy);
    }

    /**
     * Create a constructed {@code Asn1OctetString}
     *
     * @param comps a {@link List} of zero or more {@code Asn1OctetString} data
     *              components.  These components may be primitive or
     *              constructed octet strings.
     * @return a constructed form of {@code Asn1OctetString}
     * @throws NullPointerException if {@code segments} is {@code null},
     * or if any element in the list is {@code null}
     */
    public static Asn1OctetString ofComponents(List<Asn1OctetString> comps) {
        return new Asn1ConstructedOctetString(List.copyOf(
                Objects.requireNonNull(comps,
                        "Illegal null octet string collection")));
    }

    /**
     * Return the data represented by this {@code Asn1OctetString}.
     *
     * @return the data this object represents.  For concrete subclasses of
     * this class that represent ASN.1 constructed octet strings, the returned
     * byte value will be the concatenation of every data segment of the
     * constructed data.
     */
    public abstract byte[] value();

    /**
     * Get a count of the number of data segments that form this
     * {@code Asn1OctetString}.
     *
     * @return if the {@code Asn1OctetString} is primitive, this method will
     * return 1. If it is constructed, it will return the total number of
     * data segments.  For any data segment that is a constructed octet string
     * this method will count its internal number of data segments and add it
     * to the total.
     */
    public abstract int segmentCount();

    static final class Asn1PrimitiveOctetString extends Asn1OctetString {
        private final byte[] data;

        private Asn1PrimitiveOctetString(byte[] data) {
            this.data = data;
        }

        @Override
        public Asn1Tag tag() {
            return Asn1Tags.OCTET_STRING;
        }

        @Override
        public byte[] value() {
            return data.clone();
        }

        @Override
        public int segmentCount() {
            return 1;
        }

        @Override
        public boolean equals(Object o) {
            if (o == null || getClass() != o.getClass()) return false;
            Asn1PrimitiveOctetString that = (Asn1PrimitiveOctetString) o;
            return MessageDigest.isEqual(data, that.data);
        }

        @Override
        public int hashCode() {
            return Arrays.hashCode(data);
        }
    }

    // TODO: Need something to prevent infinite nesting of constructed types
    static final class Asn1ConstructedOctetString extends Asn1OctetString
            implements Asn1Constructed<Asn1OctetString> {
        private final List<Asn1OctetString> dataSegments;

        private Asn1ConstructedOctetString(List<Asn1OctetString> segments) {
            // Our Asn1OctetString static factory has already done defensive
            // copies and verified the collection is null-clean.  A simple
            // assignment is sufficient.
            dataSegments = segments;
        }

        // Return the constructed form of OCTET_STRING
        @Override
        public Asn1Tag tag() {
            return Asn1Tag.universal(Asn1Tags.OCTET_STRING.tagNumber(), true);
        }

        @Override
        public byte[] value() {
            // First pass: compute total size
            int total = 0;
            for (Asn1OctetString s : dataSegments) {
                total += s.value().length;
            }

            // Allocate once
            byte[] result = new byte[total];

            // Second pass: copy
            int pos = 0;
            for (Asn1OctetString s : dataSegments) {
                byte[] v = s.value();
                System.arraycopy(v, 0, result, pos, v.length);
                pos += v.length;
            }

            return result;
        }

        @Override
        public int segmentCount() {
            int count = 0;
            for (Asn1OctetString child : dataSegments) {
                count += child.segmentCount();
            }
            return count;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            Asn1ConstructedOctetString that = (Asn1ConstructedOctetString) o;

            return dataSegments.equals(that.dataSegments);
        }

        @Override
        public int hashCode() {
            return dataSegments.hashCode();
        }

        @Override
        public int size() {
            return dataSegments.size();
        }

        @Override
        public Asn1OctetString get(int index) {
            return dataSegments.get(index);
        }

        @Override
        public List<Asn1OctetString> getElements() {
            return dataSegments;
        }

        @Override
        public Iterator<Asn1OctetString> iterator() {
            return new Asn1Iterator<>(dataSegments.iterator());
        }
    }
}
