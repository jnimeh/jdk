package java.security.asn1.types;

import java.util.*;
import java.security.asn1.*;


/**
 * Class to support ASN.1 Sequence Of data types.  These are
 * sequences that are not heterogeneous and enforce a single type of
 * {@link Asn1Object} for all elements.
 *
 * @param <T> the {@code Asn1Object} or a subclass.
 */
public final class Asn1SequenceOf<T extends Asn1Object>
        implements Asn1Constructed<T> {

    private final List<T> elements;

    private Asn1SequenceOf(List<T> elements) {
        // Scan for null elements
        elements.forEach(e -> Objects.requireNonNull(e,
                "Found null element in List"));
        this.elements = elements;
    }

    /**
     * Create an {@code Asn1SequenceOf} providing the type and data elements.
     *
     * @param elements the {@link List} containing the sequence elements. The
     *                 insertion order of the {@code elements} parameter is
     *                 preserved in the ordering of this object.
     * @param <T> the base type of all elements within the
     *            {@code Asn1SequenceOf} object. All elements must be of this
     *            type or a subclass of it.
     * @return an {@code Asn1SequenceOf} object containing the elements in
     * the {@code elements} parameter
     * @throws NullPointerException if {@code elements} is {@code null} or any
     * object inside the provided list is {@code null}
     */
    public static <T extends Asn1Object> Asn1SequenceOf<T> of(
            List<? extends T> elements) {
        Objects.requireNonNull(elements, "Illegal null List");
        return new Asn1SequenceOf<>(List.copyOf(elements));
    }

    /**
     * Return the ASN.1 tag for this {@code Asn1Object}
     *
     * @return the ASN.1 tag used for this object
     */
    @Override
    public Asn1Tag tag() {
        return Asn1Tags.SEQUENCE;
    }

    /**
     * Obtain the number of elements in this {@code Asn1SequenceOf} object.
     *
     * @return the number of elements in this constructed ASN.1 object
     */
    @Override
    public int size() {
        return elements.size();
    }

    /**
     * Get an element from the provided index in the sequence.
     *
     * @param index the index number for the element to be retrieved.
     * @return the element at the specified position in this sequence
     * @throws IndexOutOfBoundsException if the index is out of range
     * (index &lt; 0 || index >= size())
     */
    @Override
    public T get(int index) {
        return elements.get(index);
    }

    /**
     * Returns all elements in insertion order.
     *
     * @return an immutable {@link List} of all elements
     */
    @Override
    public List<T> getElements() {
        return elements;
    }

    /**
     * Return an {@link Iterator} for this {@code Asn1Sequence}.
     *
     * @return the iterator for the sequence
     * @apiNote Although the return type is {@link Iterator}, the returned
     * instance will be {@link Asn1Iterator}, which in addition to iterator
     * methods provides a typed {@link Asn1Iterator#nextAs(Class)} call.
     */
    @Override
    public Iterator<T> iterator() {
        return new Asn1Iterator<>(elements.iterator());
    }

    /**
     * Creates a {@link Spliterator} over the elements described by this
     * {@link Iterable}.
     *
     * @return a Spliterator over the elements described by this Iterable.
     * @see Iterable
     */
    @Override
    public Spliterator<T> spliterator() {
        return Spliterators.spliterator(iterator(), size(), 0);
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        Asn1SequenceOf<?> that = (Asn1SequenceOf<?>) o;
        return elements.equals(that.elements);
    }

    @Override
    public int hashCode() {
        return elements.hashCode();
    }
}
