package java.security.asn1.types;

import java.util.*;
import java.security.asn1.*;

/**
 * Class used to describe ASN.1 SET constructed types per X.680 and X.690
 */
public final class Asn1Set implements Asn1Constructed<Asn1Object> {

    private final List<Asn1Object> elements;

    private Asn1Set(List<Asn1Object> elements) {
        normalize(elements);
        this.elements = elements;
    }

    /**
     * Class that represents ASN.1 Set data per X.680 and X.690
     *
     * @param elements the list of {@link Asn1Object} objects to be added
     *                 to this set.  The {@code Asn1Set} enforces tag
     *                 uniqueness per ASN.1 rules.
     * @return an {@code Asn1Set} consisting of the elements in {@code elements}
     * @throws NullPointerException if {@code elements} is {@code null}, or
     * any values in {@code elements} are {@code null}
     * @throws Asn1Exception if elements with a duplicate {@link Asn1Tag} are
     * found in {@code elements}
     */
    public static Asn1Set of(List<Asn1Object> elements) {
        return new Asn1Set(List.copyOf(Objects.requireNonNull(elements,
                "Illegal null elements list")));
    }

    /**
     * Create an {@code Asn1Set} from a variable number of
     * {@link Asn1Object} objects
     *
     * @param elements zero or more elements to provide to this
     *                 set object.  The insertion order of the
     *                 elements in {@code elements} will be preserved in
     *                 this {@code Asn1Set}.
     * @return an {@code Asn1Set} consisting of the elements in {@code elements}
     * @throws NullPointerException if {@code elements} is {@code null}, or
     * any values in {@code elements} are {@code null}
     * @throws Asn1Exception if elements with a duplicate {@link Asn1Tag} are
     * found in {@code elements}
     */
    public static Asn1Set of(Asn1Object... elements) {
        return new Asn1Set(List.of(Objects.requireNonNull(elements,
                "Illegal null varargs")));
    }

    private static void normalize(List<Asn1Object> elements) {
        Set<Asn1Tag> seen = new HashSet<>();
        elements.forEach(e -> {
            Objects.requireNonNull(e, "ASN.1 SET element cannot be null");
            Asn1Tag tag = e.tag();
            if (!seen.add(tag)) {
                throw new Asn1Exception(
                        "Duplicate ASN.1 SET element with tag: " + tag);
            }
        });
    }

    /**
     * Return the ASN.1 tag for this {@code Asn1Set}
     *
     * @return the ASN.1 tag used for this object
     */
    @Override
    public Asn1Tag tag() {
        return Asn1Tags.SET;
    }

    /**
     * Return an {@link Iterator} for this {@code Asn1Set}.
     *
     * @return the iterator for the sequence
     * @apiNote Although the return type is {@link Iterator}, the returned
     * instance will be {@link Asn1Iterator}, which in addition to iterator
     * methods provides a typed {@link Asn1Iterator#nextAs(Class)} call.
     */
    @Override
    public Iterator<Asn1Object> iterator() {
        return new Asn1Iterator<>(elements.iterator());
    }

    @Override
    public Spliterator<Asn1Object> spliterator() {
        return Spliterators.spliterator(iterator(), size(), 0);
    }

    /**
     * Obtain the number of elements in this {@code Asn1Set} object.
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
        return elements.get(index);
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
        if (this == o) return true;
        if (o == null || o.getClass() != getClass()) return false;

        Asn1Set other = (Asn1Set) o;

        if (elements.size() != other.elements.size()) return false;

        // Build lookup map for "other"
        Map<Asn1Tag, Asn1Object> otherByTag = new HashMap<>();
        for (Asn1Object oe : other.elements) {
            otherByTag.put(oe.tag(), oe);
        }

        // Compare this against other
        for (Asn1Object e : elements) {
            if (!otherByTag.containsKey(e.tag()) ||
                    !e.equals(otherByTag.get(e.tag()))) {
                return false;
            }
        }

        return true;
    }

    @Override
    public int hashCode() {
        int hash = 0;
        for (Asn1Object e : elements) {
            hash += 31 * e.tag().hashCode() + e.hashCode();
        }
        return hash;
    }
}
