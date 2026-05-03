package java.security.asn1.types;

import java.time.*;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeFormatterBuilder;
import java.time.format.DateTimeParseException;
import java.time.temporal.ChronoField;
import java.util.Date;
import java.util.Objects;
import java.security.asn1.*;

/**
 * Class used to carry ASN.1 UTCTime information.  UTCTime
 * takes the basic form of {@code YYMMDDHHmm[ss](Z | +/-HHmm)}.
 * While DER requires the "Z" timezone, other encoding rules allow
 * other time offsets.  This class will support other offsets, but
 * the actual encoded value will conform to the rules imposed by the
 * encoding scheme.
 */
public final class Asn1UTCTime implements Asn1Primitive, Asn1Time {

    private static final DateTimeFormatter UTC_TIME_FORMATTER =
            new DateTimeFormatterBuilder()
                    .appendValue(ChronoField.YEAR, 2)
                    .appendValue(ChronoField.MONTH_OF_YEAR, 2)
                    .appendValue(ChronoField.DAY_OF_MONTH, 2)
                    .appendValue(ChronoField.HOUR_OF_DAY, 2)
                    .appendValue(ChronoField.MINUTE_OF_HOUR, 2)

                    // Optional Seconds
                    .optionalStart()
                    .appendValue(ChronoField.SECOND_OF_MINUTE, 2)
                    .optionalEnd()

                    // Optional "Z" specifier
                    .appendOffset("+HHmm", "Z")

                    .toFormatter()
                    .withZone(ZoneOffset.UTC);

    // Minimum and Maximum allowed date ranges
    private static final Instant MIN = Instant.parse("1950-01-01T00:00:00Z");
    private static final Instant MAX = Instant.parse("2049-12-31T23:59:59Z");

    private final OffsetDateTime dateTime;

    private Asn1UTCTime(OffsetDateTime value) {
        this.dateTime = value;
    }

    /**
     * Create an {@code Asn1UTCTime} from a {@link String}
     *
     * @param timeString the {@link String} representing a UTCTime in
     *                   X.680 notation.
     * @return an {@code Asn1UTCTime} object representing the value of
     * {@code timeString}
     * @throws NullPointerException if {@code timeString} is {@code null}
     * @throws DateTimeParseException if {@code timeString} does not
     * conform to the required UTCTime string format.
     */
    public static Asn1UTCTime of(String timeString) {
        OffsetDateTime parsed = UTC_TIME_FORMATTER.parse(
                Objects.requireNonNull(timeString),
                OffsetDateTime::from);

        // UTCTime 2-digit years assign the century based on the 2-digit value
        int year = parsed.getYear();
        int fullYear = (year >= 50 ? 1900 : 2000) + year;
        return new Asn1UTCTime(parsed.withYear(fullYear));
    }

    /**
     * Construct an {@code Asn1UTCTime} from a {@link Date} object.
     *
     * @param inputDateTime the date to be represented in this object
     * @return the {@code Asn1UTCTime} representing this {@link Date}
     * @throws NullPointerException if {@code inputDateTime} is {@code null}
     * @throws DateTimeException if the date/time represented by
     * {@code inputDateTime} is either before 1950-01-01T00:00:00Z
     * or after 2049-12-31T23:59:59Z
     */
    public static Asn1UTCTime of(Date inputDateTime) {
        return of(Objects.requireNonNull(inputDateTime).toInstant());
    }

    /**
     * Construct an {@code Asn1UTCTime} from a {@link Instant} object.
     *
     * @param inputDateTime the date to be represented in this object
     * @return the {@code Asn1UTCTime} representing this {@link Instant}
     * @throws NullPointerException if {@code inputDateTime} is {@code null}
     * @throws DateTimeException if the date/time represented by
     * {@code inputDateTime} is either before 1950-01-01T00:00:00Z
     * or after 2049-12-31T23:59:59Z
     */
    public static Asn1UTCTime of(Instant inputDateTime) {
        // UTCTime objects support a specific range of dates, identified
        // by the static private fields MIN and MAX above.
        Objects.requireNonNull(inputDateTime);
        if (inputDateTime.isBefore(MIN) || inputDateTime.isAfter(MAX)) {
            throw new DateTimeException("Proposed time is outside the " +
                    "allowed UTCTime date/time range");
        }
        return new Asn1UTCTime(inputDateTime.atOffset(ZoneOffset.UTC));
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
     * Return the ASN.1 tag for this {@code Asn1UTCTime}
     * @return the ASN.1 tag used for this object
     */
    @Override
    public Asn1Tag tag() {
        return Asn1Tags.UTCTIME;
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        Asn1UTCTime that = (Asn1UTCTime) o;
        return dateTime.equals(that.dateTime);
    }

    @Override
    public int hashCode() {
        return dateTime.hashCode();
    }
}
