package java.security.asn1.types;

import java.util.*;
import java.security.asn1.*;

/**
 * Class used to describe ASN.1 SET OF constructed types per X.680 and X.690.
 *
 * @param <T> the type of {@link Asn1Object} to be stored in SET OF
 *           instantiated objects.
 */
public final class Asn1SetOf<T extends Asn1Object>
        implements Asn1Constructed<T> {

    private final List<T> elements;
    private final Map<T, Integer> frequencyMap;

    private Asn1SetOf(List<T> elements) {
        elements.forEach(e -> Objects.requireNonNull(e,
                "Found null element in List"));
        this.elements = elements;
        this.frequencyMap = buildFrequency(this.elements);
    }

    /**
     * Build an internal frequency map.  This will aid in comparisons
     * for equals.
     *
     * @param elements the list of elements provided during construction
     * @return a {@link Map} view of the data with the ASN.1 objects themselves
     * as a key (both tag and value matter) and an integer value which is
     * their frequency count.
     */
    private Map<T, Integer> buildFrequency(List<T> elements) {
        Map<T, Integer> map = new HashMap<>();
        for (T e : elements) {
            map.merge(e, 1, Integer::sum);
        }
        return map;
    }

    /**
     * Create an {@code Asn1SetOf} from a caller-provided {@link List} of
     * {@link Asn1Object} objects of a specific derived class.
     *
     * @param elements a {@link List} of elements of the generic type specified
     *                 at declaration time.  Unlike the {@link Asn1Set} class,
     *                 duplicate values are allowed and may be provided in any
     *                 order.  There is no guarantee of internal ordering of
     *                 the elements within the resulting {@code Asn1SetOf},
     *                 and encoding order depends on the selected encoding rules
     *                 (BER, DER, etc.)
     * @param <T> the base type of all elements within the {@code Asn1SetOf}
     *           object. All elements must be of this type or a subclass of it.
     * @return an {@code Asn1SetOf} object containing the elements in
     * {@code elements}
     */
    public static <T extends Asn1Object> Asn1SetOf<T> of(
            List<? extends T> elements) {
        return new Asn1SetOf<>(List.copyOf(Objects.requireNonNull(elements,
                "Illegal null List")));
    }

    /**
     * Return the ASN.1 tag for this {@code Asn1Set}
     * @return the ASN.1 tag used for this object
     */
    @Override
    public Asn1Tag tag() {
        return Asn1Tags.SET;
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
     * @return the iterator for the sequence
     * @apiNote Although the return type is {@link Iterator}, the returned
     * instance will be {@link Asn1Iterator}, which in addition to iterator
     * methods provides a typed {@link Asn1Iterator#nextAs(Class)} call.
     */
    @Override
    public Iterator<T> iterator() {
        return new Asn1Iterator<>(elements.iterator());
    }

    @Override
    public Spliterator<T> spliterator() {
        return Spliterators.spliterator(iterator(), size(), 0);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || o.getClass() != getClass()) return false;

        Asn1SetOf<?> other = (Asn1SetOf<?>) o;
        return this.frequencyMap.equals(other.frequencyMap);
    }

    @Override
    public int hashCode() {
        return frequencyMap.hashCode();
    }
}
