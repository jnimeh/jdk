package java.security.asn1.types;

import java.security.asn1.Asn1Exception;
import java.util.Iterator;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.security.asn1.Asn1Object;

/**
 * Iterator used for iterating across ASN.1 constructed types like
 * {@link Asn1Set}, {@link Asn1SetOf}, {@link Asn1Sequence} and
 * {@link Asn1SequenceOf}.
 *
 * @param <T> the type of data to be returned by the iterator.  Must be
 *           of type {@link Asn1Object} or one of its derived classes.
 */
public final class Asn1Iterator<T extends Asn1Object> implements Iterator<T> {

    private final Iterator<T> delegateIt;

    /**
     * Package-private constructor.  Callers should use the implementation of
     * {@link Iterable#iterator()} from the various concrete implementations
     * as permitted in
     * {@link java.security.asn1.Asn1Constructed Asn1Constructed}
     *
     * @param delIt the {@link Iterator} that this {@code Asn1Iterator} wraps.
     * @throws NullPointerException if {@code delIt} is {@code null}
     */
    Asn1Iterator(Iterator<T> delIt) {
        delegateIt = Objects.requireNonNull(delIt);
    }

    /**
     * Returns true if the iteration has more elements. (In other words,
     * returns true if {@link Asn1Iterator#next()}  would return an element
     * rather than throwing an exception.)
     *
     * @return {@code true} if the iteration has more elements
     */
    @Override
    public boolean hasNext() {
        return delegateIt.hasNext();
    }

    /**
     * Returns the next element in the iteration.
     *
     * @return the next element in the iteration
     *
     * @throws NoSuchElementException - if the iteration has no more elements
     */
    @Override
    public T next() {
        return delegateIt.next();
    }

    /**
     * Returns the next element in the iteration, but instead of returning
     * a generic {@link Asn1Object}, it instead allows the caller to specify
     * the return type.
     *
     * @param type the {@link Class} of the desired returned object
     * @param <U> the actual type, should either be the same type as that
     *           of the iterator or one of its subclasses.
     * @return the next element in the iteration, cast to the desired
     * type specified in the {@code type} argument.
     * @throws Asn1Exception if the desired ASN.1 type in {@code type} does
     * not match the current object returned by the iterator.
     */
    public <U extends T> T nextAs(Class<U> type) {
        Asn1Object obj = next();
        if (!type.isInstance(obj)) {
            throw new Asn1Exception("Expected " + type.getSimpleName() +
                    " but got " + obj.getClass().getSimpleName()
            );
        }
        return type.cast(obj);
    }
}