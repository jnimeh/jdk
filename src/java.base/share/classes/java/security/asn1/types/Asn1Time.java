package java.security.asn1.types;

import java.time.OffsetDateTime;
import java.time.Instant;

/**
 * Interface for date and time-based ASN.1 data types.
 */
public interface Asn1Time extends Comparable<Asn1Time> {

    /**
     * Returns the represented date-time with offset semantics.
     *
     * @return the date and time represented by this object
     */
    OffsetDateTime toOffsetDateTime();

    /**
     * Returns the date and time of this object represented as an
     * {@link Instant}
     *
     * @return the {@code Instant} represented by the object
     */
    default Instant toInstant() {
        return toOffsetDateTime().toInstant();
    }

    /**
     * Compares this {@code Asn1Time} to the specified {@code Asn1Instant}.
     * Time comparisons are done on the time-line positions of the
     * {@link Instant} represented by the {@code Asn1Time} objects compared.
     *
     * @param otherTime the other {@code Asn1Time} object to compare this
     *                  object to, may not be {@code null}
     * @return a value less than zero if this {@code Asn1Time} object is before
     * {@code otherTime}, zero if they are equal, or greater than zero if this
     * instant is after {@code otherTime}.
     *
     */
    @Override
    default int compareTo(Asn1Time otherTime) {
        return this.toInstant().compareTo(otherTime.toInstant());
    }
}