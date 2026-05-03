package java.security.asn1;

import java.util.List;

/**
 * Interface for ASN.1 Constructed types.  All implementations of
 * {@code Asn1Constructed} will provide index-based access to individual
 * elements of the constructed type, and a method for retrieving all
 * elements as a {@link List}.  The order of the elements of a given
 * {@code Asn1Constructed} implementation will be implementation-specific.
 * <p>Encoded ordering of elements
 * contained within a specific {@code Asn1Constructed} derived type is
 * specific to the encoding rules being followed.  DER and BER may impose
 * different encoded ordering rules, as may different encoded types.  For
 * example,
 * {@link java.security.asn1.types.Asn1Set Asn1Set} and
 * {@link java.security.asn1.types.Asn1SetOf Asn1SetOf} will order their
 * elements differently and neither is guaranteed to match the ordering of
 * the elements returned by {@link Asn1Constructed#getElements()}.
 * @param <T> the data type(s) to be held in this {@code Asn1Constructed}
 *           object.  Must be of type {@link Asn1Object} or one of
 *           its derivatives.
 */
public non-sealed interface Asn1Constructed<T extends Asn1Object>
        extends Asn1Object, Iterable<T> {

    /**
     * Obtain the number of elements in this {@code Asn1Constructed} object.
     *
     * @return the number of elements in this constructed ASN.1 object
     */
    int size();

    /**
     * Returns the element at the given index
     *
     * @param index the index of the object to be retrieved.
     * @return the object at that index
     * @throws IndexOutOfBoundsException if the index is out of range
     * (index &lt; 0 || index &ge; size())
     */
    T get(int index);

    /**
     * Returns the element at the given index as the requested type.
     *
     * @param index the index of the object to be retrieved.
     * @param type the desired return type of the object
     * @return the object at that index
     * @param <U> the desired return type, must be either {@link Asn1Object}
     *           or a derived type.
     * @throws IndexOutOfBoundsException if the index is out of range
     * (index &lt; 0 || index &ge; size())
     */
    public default <U extends Asn1Object> U get(int index, Class<U> type) {
        Asn1Object obj = get(index);
        if (!type.isInstance(obj)) {
            throw new Asn1Exception("Expected " + type.getSimpleName() +
                    " but got " + obj.getClass().getSimpleName());
        }
        return type.cast(obj);
    }

    /**
     * Returns all elements in insertion order.
     * @return an immutable {@link List} of all elements
     */
    List<T> getElements();
}
