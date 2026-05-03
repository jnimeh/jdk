package java.security.asn1.types;

import java.util.*;
import java.security.asn1.*;

/**
 * Class used to describe ASN.1 SEQUENCE constructed types per X.680 and X.690.
 * <p>{@code Asn1Sequence} objects provide an ordered representation of
 * a heterogeneous collection of {@link Asn1Object} objects.
 */
public class Asn1Sequence implements Asn1Constructed<Asn1Object> {

    private final List<Asn1Object> elements;

    private Asn1Sequence(List<Asn1Object> elements) {
        // Check for null elements within the list
        elements.forEach(e -> Objects.requireNonNull(e,
                "Found null element in List"));
        this.elements = elements;
    }

    /**
     * Create an {@code Asn1Sequence} from a list of {@link Asn1Object} objects
     *
     * @param elements the {@link List} of elements to provide to this
     *                 sequence object.  The insertion order of the
     *                 elements in {@code elements} will be preserved in
     *                 this {@code Asn1Sequence}.
     * @return an {@code Asn1Sequence} object containing the elements in
     * the {@code elements} parameter
     * @throws NullPointerException if {@code elements} is {@code null} or any
     * object inside the provided list is {@code null}
     */
    public static Asn1Sequence of(List<Asn1Object> elements) {
        Objects.requireNonNull(elements, "Illegal null List");
        return new Asn1Sequence(List.copyOf(elements));
    }

    /**
     * Create an {@code Asn1Sequence} from a variable number of
     * {@link Asn1Object} objects
     *
     * @param elements zero or more elements to provide to this
     *                 sequence object.  The insertion order of the
     *                 elements in {@code elements} will be preserved in
     *                 this {@code Asn1Sequence}.
     * @return an {@code Asn1Sequence} object containing the elements in
     * the {@code elements} parameter
     * @throws NullPointerException if any object provided in {@code elements}
     * is {@code null}
     */
    public static Asn1Sequence of(Asn1Object... elements) {
        Objects.requireNonNull(elements, "Illegal null varargs");
        return new Asn1Sequence(List.of(elements));
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
     * Return an {@link Iterator} for this {@code Asn1Sequence}.
     * @return the iterator for the sequence
     * @apiNote Although the return type is {@link Iterator}, the returned
     * instance will be {@link Asn1Iterator}, which in addition to iterator
     * methods, provides a typed {@link Asn1Iterator#nextAs(Class)} call.
     */
    @Override
    public Iterator<Asn1Object> iterator() {
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
    public Spliterator<Asn1Object> spliterator() {
        return Spliterators.spliterator(iterator(), size(), 0);
    }

    /**
     * Obtain the number of elements in this {@code Asn1Sequence} object.
     *
     * @return the number of elements in this constructed ASN.1 object
     */
    @Override
    public int size() {
        return elements.size();
    }

    /**
     * Returns the element at the given index
     *
     * @param index the index of the object to be retrieved.
     * @return the object at that index
     * @throws IndexOutOfBoundsException if the index is out of range
     * (index &lt; 0 || index &ge; size())
     */
    @Override
    public Asn1Object get(int index) {
        return null;
    }

    /**
     * Returns all elements in insertion order.
     *
     * @return an immutable {@link List} of all elements
     */
    @Override
    public List<Asn1Object> getElements() {
        return elements;
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        Asn1Sequence that = (Asn1Sequence) o;
        return elements.equals(that.elements);
    }

    @Override
    public int hashCode() {
        return elements.hashCode();
    }
}
