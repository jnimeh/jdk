package java.security.asn1.types;

import java.time.*;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeFormatterBuilder;
import java.time.temporal.ChronoField;
import java.time.temporal.TemporalAccessor;
import java.util.Objects;
import java.security.asn1.*;

/**
 * Class used to carry ASN.1 GeneralizedTime information.  GeneralizedTime
 * takes the basic form of {@code YYYYMMDDHH[mm[ss[.fff]]][Z | +/-HHmm]}.
 * This class supports GeneralizedTime fractional seconds to nanosecond
 * granularity
 */
public final class Asn1GeneralizedTime implements Asn1Primitive, Asn1Time {
    private static final DateTimeFormatter GENERALIZED_TIME_FORMATTER =
            new DateTimeFormatterBuilder()
                    .appendValue(ChronoField.YEAR, 4)
                    .appendValue(ChronoField.MONTH_OF_YEAR, 2)
                    .appendValue(ChronoField.DAY_OF_MONTH, 2)
                    .appendValue(ChronoField.HOUR_OF_DAY, 2)

                    // Optional Minutes
                    .optionalStart().appendValue(ChronoField.MINUTE_OF_HOUR, 2).
                            optionalEnd()

                    // Optional Seconds
                    .optionalStart().appendValue(
                            ChronoField.SECOND_OF_MINUTE, 2).optionalEnd()

                    // Optional Fractional Seconds (handles both . and ,)
                    .optionalStart().appendFraction(ChronoField.NANO_OF_SECOND,
                                    0, 9, true).optionalEnd()

                    // Optional Timezone (Z, +HHmm, or -HHmm)
                    .optionalStart().appendOffset("+HHmm", "Z").optionalEnd()
                    .toFormatter();

    private final OffsetDateTime dateTime;
    private final boolean hasExplicitOffset;

    private Asn1GeneralizedTime(OffsetDateTime value, boolean hasOffset) {
        dateTime = value;
        hasExplicitOffset = hasOffset;
    }

    /**
     * Create an {@code Asn1GeneralizedTime} from an {@link Instant}.  Objects
     * created with this constructor assume the UTC timezone.
     *
     * @param value the {@link Instant} representing the time for the object
     * @return the {@code Asn1GeneralizedTime} representing this {@link Instant}
     * @throws NullPointerException if {@code value} or {@code offset} is
     * {@code null}
     */
    public static Asn1GeneralizedTime of(Instant value) {
        return of(value, ZoneOffset.UTC);
    }

    /**
     * Create an {@code Asn1GeneralizedTime} from an {@link Instant} and
     * a {@link ZoneOffset} representing the timezone.
     *
     * @param value the {@link Instant} representing the time for the object
     * @param offset the {@link ZoneOffset} that represents the timezone
     * @return the {@code Asn1GeneralizedTime} representing the {@link Instant}
     * at the selected {@code offset}
     * @throws NullPointerException if {@code value} or {@code offset} is
     * {@code null}
     */
    public static Asn1GeneralizedTime of(Instant value, ZoneOffset offset) {
        return new Asn1GeneralizedTime(Objects.requireNonNull(value).
                atOffset(Objects.requireNonNull(offset)), true);
    }

    /**
     * Create an {@code Asn1GeneralizedTime} from a {@link String}
     *
     * @param timeString the {@link String} representing a GeneralizedTime
     *                      in X.680 notation.
     * @return the {@code Asn1GeneralizedTime} representing the date string
     * provided in {@code timeString}
     * @throws NullPointerException if {@code timeString} is {@code null}
     * @throws Asn1Exception if {@code timeString} does not
     * conform to the required GeneralizedTime string format.
     */
    public static Asn1GeneralizedTime of(String timeString) {
        if (Objects.requireNonNull(timeString).isEmpty()) {
            throw new Asn1Exception("GeneralizedTime string cannot be empty");
        }

        // ASN.1 allows ',' as a decimal separator; Java prefers '.'
        String normalized = timeString.replace(',', '.');

        try {
            // Parse generically first
            TemporalAccessor parsed =
                    GENERALIZED_TIME_FORMATTER.parse(normalized);

            // Most common case is to have the "Z" explicitly stated
            OffsetDateTime value;
            boolean hasOffset = parsed.isSupported(ChronoField.OFFSET_SECONDS);
            if (hasOffset) {
                value = OffsetDateTime.from(parsed);
            } else {
                // It is possible to get a time string from a BER encoding
                // that is missing the explicit time offset.  In order to
                // support this form, missing timezones in the encoding assume
                // the local timezone.
                LocalDateTime ldt = LocalDateTime.from(parsed);
                ZoneOffset offset = ZoneId.systemDefault().getRules()
                        .getOffset(ldt);
                value = ldt.atOffset(offset);
            }
            return new Asn1GeneralizedTime(value, hasOffset);
        } catch (DateTimeException dte) {
            throw new Asn1Exception(dte);
        }
    }

    /**
     * Obtain the time represented by the object.
     *
     * @return an {@link OffsetDateTime} that represents the time for
     * this object.
     */
    @Override
    public OffsetDateTime toOffsetDateTime() {
        return dateTime;
    }

    /**
     * Boolean value to indicate to the caller that this object was constructed
     * with or without an explicitly stated timezone.
     *
     * @return true if it was created with a timezone offset, false if not.
     */
    public boolean hasExplicitOffset() {
        return hasExplicitOffset;
    }

    /**
     * Return the ASN.1 tag for this {@code Asn1GeneralizedTime}
     * @return the ASN.1 tag used for this object
     */
    @Override
    public Asn1Tag tag() {
        return Asn1Tags.GENERALIZEDTIME;
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        Asn1GeneralizedTime that = (Asn1GeneralizedTime) o;
        return this.hasExplicitOffset == that.hasExplicitOffset
                && this.dateTime.equals(that.dateTime);
    }

    @Override
    public int hashCode() {
        int result = dateTime.hashCode();
        result = 31 * result + (hasExplicitOffset ? 1 : 0);
        return result;
    }
}
