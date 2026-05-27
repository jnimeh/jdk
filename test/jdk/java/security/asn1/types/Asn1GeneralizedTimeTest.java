/*
 * @test
 * @bug 0000000
 * @summary Tests for Asn1GeneralizedTime: positive and negative cases,
 *          all string formats, timezone handling, equals, hashCode,
 *          and Asn1Time interface methods.
 * @library /test/lib
 * @run main Asn1GeneralizedTimeTest
 */

import java.security.asn1.Asn1Exception;
import java.security.asn1.Asn1Tags;
import java.security.asn1.types.Asn1GeneralizedTime;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import static jdk.test.lib.Asserts.*;

public class Asn1GeneralizedTimeTest {

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private static void pass(String testName) {
        System.out.println("PASS: " + testName);
    }

    private static void fail(String testName, String reason) {
        throw new RuntimeException("FAIL: " + testName + " -- " + reason);
    }

    // -----------------------------------------------------------------------
    // of(Instant) tests
    // -----------------------------------------------------------------------

    static void testOfInstant_valid() {
        Instant now = Instant.parse("2024-06-15T10:30:00Z");
        Asn1GeneralizedTime gt = Asn1GeneralizedTime.of(now);

        if (!gt.hasExplicitOffset()) {
            fail("ofInstant_valid", "hasExplicitOffset should be true");
        }
        if (!gt.toOffsetDateTime().toInstant().equals(now)) {
            fail("ofInstant_valid", "Instant roundtrip mismatch");
        }
        if (!gt.toOffsetDateTime().getOffset().equals(ZoneOffset.UTC)) {
            fail("ofInstant_valid", "Expected UTC offset");
        }
        pass("ofInstant_valid");
    }

    static void testOfInstant_null() {
        assertThrows(NullPointerException.class,
                () -> Asn1GeneralizedTime.of((Instant) null),
                "ofInstant_null");
    }

    // -----------------------------------------------------------------------
    // of(Instant, ZoneOffset) tests
    // -----------------------------------------------------------------------

    static void testOfInstantOffset_valid_utc() {
        Instant now = Instant.parse("2024-06-15T10:30:00Z");
        Asn1GeneralizedTime gt = Asn1GeneralizedTime.of(now, ZoneOffset.UTC);

        if (!gt.hasExplicitOffset()) {
            fail("ofInstantOffset_valid_utc", "hasExplicitOffset should be true");
        }
        if (!gt.toOffsetDateTime().toInstant().equals(now)) {
            fail("ofInstantOffset_valid_utc", "Instant roundtrip mismatch");
        }
        pass("ofInstantOffset_valid_utc");
    }

    static void testOfInstantOffset_valid_positiveOffset() {
        Instant now = Instant.parse("2024-06-15T10:30:00Z");
        ZoneOffset plus5 = ZoneOffset.of("+05:00");
        Asn1GeneralizedTime gt = Asn1GeneralizedTime.of(now, plus5);

        if (!gt.hasExplicitOffset()) {
            fail("ofInstantOffset_valid_positiveOffset",
                    "hasExplicitOffset should be true");
        }
        if (!gt.toOffsetDateTime().getOffset().equals(plus5)) {
            fail("ofInstantOffset_valid_positiveOffset",
                    "Expected +05:00 offset");
        }
        // Underlying instant must be preserved
        if (!gt.toOffsetDateTime().toInstant().equals(now)) {
            fail("ofInstantOffset_valid_positiveOffset",
                    "Instant roundtrip mismatch");
        }
        pass("ofInstantOffset_valid_positiveOffset");
    }

    static void testOfInstantOffset_valid_negativeOffset() {
        Instant now = Instant.parse("2024-06-15T10:30:00Z");
        ZoneOffset minus5 = ZoneOffset.of("-05:00");
        Asn1GeneralizedTime gt = Asn1GeneralizedTime.of(now, minus5);

        if (!gt.toOffsetDateTime().getOffset().equals(minus5)) {
            fail("ofInstantOffset_valid_negativeOffset",
                    "Expected -05:00 offset");
        }
        pass("ofInstantOffset_valid_negativeOffset");
    }

    static void testOfInstantOffset_nullInstant() {
        assertThrows(NullPointerException.class,
                () -> Asn1GeneralizedTime.of(null, ZoneOffset.UTC),
                "ofInstantOffset_nullInstant");
    }

    static void testOfInstantOffset_nullOffset() {
        assertThrows(NullPointerException.class,
                () -> Asn1GeneralizedTime.of(Instant.now(), null),
                "ofInstantOffset_nullOffset");
    }

    // -----------------------------------------------------------------------
    // of(String) — negative cases
    // -----------------------------------------------------------------------

    static void testOfString_null() {
        assertThrows(NullPointerException.class,
                () -> Asn1GeneralizedTime.of((String) null),  "ofString_null");
    }

    static void testOfString_empty() {
        Asn1Exception ex = assertThrows(Asn1Exception.class,
                () -> Asn1GeneralizedTime.of(""), "ofString_empty");
        if (!ex.getMessage().contains("empty")) {
            fail("ofString_empty_message",
                    "Expected 'empty' in message, got: " + ex.getMessage());
        }
        pass("ofString_empty_message");
    }

    static void testOfString_totallyInvalid() {
        assertThrows(Asn1Exception.class,
                () -> Asn1GeneralizedTime.of("not-a-time"),
                "ofString_totallyInvalid");
    }

    static void testOfString_badMonth() {
        // Month 13 — should trigger DateTimeException -> Asn1Exception
        assertThrows(Asn1Exception.class,
                () -> Asn1GeneralizedTime.of("20241315120000Z"),
                "ofString_badMonth");
    }

    static void testOfString_badDay() {
        // Day 32
        assertThrows(Asn1Exception.class,
                () -> Asn1GeneralizedTime.of("20240132120000Z"),
                "ofString_badDay");
    }

    static void testOfString_badHour() {
        // Hour 25
        assertThrows(Asn1Exception.class,
                () -> Asn1GeneralizedTime.of("20240615250000Z"),
                "ofString_badHour");
    }

    static void testOfString_truncatedYear() {
        // Only 3 digits for year — formatter requires exactly 4
        assertThrows(Asn1Exception.class,
                () -> Asn1GeneralizedTime.of("202061512Z"),
                "ofString_truncatedYear");
    }

    // -----------------------------------------------------------------------
    // of(String) — positive cases: format variations
    // -----------------------------------------------------------------------

    /**
     * Minimum valid form: YYYYMMDDHH + Z (no minutes, no seconds)
     */
    static void testOfString_hourOnly_Z() {
        Asn1GeneralizedTime gt = Asn1GeneralizedTime.of("2024061512Z");

        if (!gt.hasExplicitOffset()) {
            fail("ofString_hourOnly_Z", "hasExplicitOffset should be true");
        }
        OffsetDateTime odt = gt.toOffsetDateTime();
        if (odt.getYear() != 2024 || odt.getMonthValue() != 6
                || odt.getDayOfMonth() != 15 || odt.getHour() != 12) {
            fail("ofString_hourOnly_Z", "Parsed date/time fields mismatch");
        }
        if (odt.getMinute() != 0 || odt.getSecond() != 0) {
            fail("ofString_hourOnly_Z",
                    "Minutes/seconds should default to 0");
        }
        pass("ofString_hourOnly_Z");
    }

    /**
     * YYYYMMDDHHmm + Z (no seconds)
     */
    static void testOfString_hourMinute_Z() {
        Asn1GeneralizedTime gt = Asn1GeneralizedTime.of("202406151230Z");

        if (!gt.hasExplicitOffset()) {
            fail("ofString_hourMinute_Z", "hasExplicitOffset should be true");
        }
        OffsetDateTime odt = gt.toOffsetDateTime();
        if (odt.getHour() != 12 || odt.getMinute() != 30
                || odt.getSecond() != 0) {
            fail("ofString_hourMinute_Z", "Parsed time fields mismatch");
        }
        pass("ofString_hourMinute_Z");
    }

    /**
     * YYYYMMDDHHmmss + Z (full seconds, no fractions)
     */
    static void testOfString_fullSeconds_Z() {
        Asn1GeneralizedTime gt = Asn1GeneralizedTime.of("20240615123045Z");

        OffsetDateTime odt = gt.toOffsetDateTime();
        if (odt.getHour() != 12 || odt.getMinute() != 30
                || odt.getSecond() != 45) {
            fail("ofString_fullSeconds_Z", "Parsed time fields mismatch");
        }
        if (odt.getNano() != 0) {
            fail("ofString_fullSeconds_Z", "Nano should be 0");
        }
        pass("ofString_fullSeconds_Z");
    }

    /**
     * Fractional seconds with dot separator
     */
    static void testOfString_fractionalSeconds_dot() {
        // .5 == 500_000_000 nanoseconds
        Asn1GeneralizedTime gt = Asn1GeneralizedTime.of("20240615123045.5Z");

        OffsetDateTime odt = gt.toOffsetDateTime();
        if (odt.getNano() != 500_000_000) {
            fail("ofString_fractionalSeconds_dot",
                    "Expected 500_000_000 ns, got: " + odt.getNano());
        }
        pass("ofString_fractionalSeconds_dot");
    }

    /**
     * Fractional seconds with comma separator (ASN.1 allows this).
     * The comma must be normalized to a dot internally.
     */
    static void testOfString_fractionalSeconds_comma() {
        Asn1GeneralizedTime gt = Asn1GeneralizedTime.of("20240615123045,5Z");

        OffsetDateTime odt = gt.toOffsetDateTime();
        if (odt.getNano() != 500_000_000) {
            fail("ofString_fractionalSeconds_comma",
                    "Expected 500_000_000 ns, got: " + odt.getNano());
        }
        // dot and comma forms should produce equal objects
        Asn1GeneralizedTime dotForm =
                Asn1GeneralizedTime.of("20240615123045.5Z");
        if (!gt.equals(dotForm)) {
            fail("ofString_fractionalSeconds_comma",
                    "Comma and dot forms should be equal");
        }
        pass("ofString_fractionalSeconds_comma");
    }

    /**
     * Nanosecond precision (9 fractional digits)
     */
    static void testOfString_nanosecondPrecision() {
        Asn1GeneralizedTime gt =
                Asn1GeneralizedTime.of("20240615123045.123456789Z");

        OffsetDateTime odt = gt.toOffsetDateTime();
        if (odt.getNano() != 123_456_789) {
            fail("ofString_nanosecondPrecision",
                    "Expected 123_456_789 ns, got: " + odt.getNano());
        }
        pass("ofString_nanosecondPrecision");
    }

    /**
     * Multiple fractional digit counts to verify scaling
     */
    static void testOfString_fractionalSeconds_multipleDigits() {
        // 3 digits = milliseconds
        Asn1GeneralizedTime gt3 =
                Asn1GeneralizedTime.of("20240615123045.123Z");
        if (gt3.toOffsetDateTime().getNano() != 123_000_000) {
            fail("ofString_fractionalSeconds_3digits",
                    "Expected 123_000_000 ns, got: "
                            + gt3.toOffsetDateTime().getNano());
        }

        // 6 digits = microseconds
        Asn1GeneralizedTime gt6 =
                Asn1GeneralizedTime.of("20240615123045.123456Z");
        if (gt6.toOffsetDateTime().getNano() != 123_456_000) {
            fail("ofString_fractionalSeconds_6digits",
                    "Expected 123_456_000 ns, got: "
                            + gt6.toOffsetDateTime().getNano());
        }
        pass("ofString_fractionalSeconds_multipleDigits");
    }

    /**
     * Explicit positive UTC offset (+HHmm)
     */
    static void testOfString_positiveOffset() {
        Asn1GeneralizedTime gt =
                Asn1GeneralizedTime.of("20240615123045+0530");

        if (!gt.hasExplicitOffset()) {
            fail("ofString_positiveOffset",
                    "hasExplicitOffset should be true");
        }
        ZoneOffset expected = ZoneOffset.of("+05:30");
        if (!gt.toOffsetDateTime().getOffset().equals(expected)) {
            fail("ofString_positiveOffset",
                    "Expected +05:30, got: "
                            + gt.toOffsetDateTime().getOffset());
        }
        pass("ofString_positiveOffset");
    }

    /**
     * Explicit negative UTC offset (-HHmm)
     */
    static void testOfString_negativeOffset() {
        Asn1GeneralizedTime gt =
                Asn1GeneralizedTime.of("20240615123045-0800");

        if (!gt.hasExplicitOffset()) {
            fail("ofString_negativeOffset",
                    "hasExplicitOffset should be true");
        }
        ZoneOffset expected = ZoneOffset.of("-08:00");
        if (!gt.toOffsetDateTime().getOffset().equals(expected)) {
            fail("ofString_negativeOffset",
                    "Expected -08:00, got: "
                            + gt.toOffsetDateTime().getOffset());
        }
        pass("ofString_negativeOffset");
    }

    /**
     * No timezone — BER local-time form.  hasExplicitOffset must be false
     * and the parsed time fields must be preserved.
     */
    static void testOfString_noTimezone() {
        Asn1GeneralizedTime gt = Asn1GeneralizedTime.of("20240615123045");

        if (gt.hasExplicitOffset()) {
            fail("ofString_noTimezone",
                    "hasExplicitOffset should be false for local-time form");
        }
        OffsetDateTime odt = gt.toOffsetDateTime();
        if (odt.getYear() != 2024 || odt.getMonthValue() != 6
                || odt.getDayOfMonth() != 15 || odt.getHour() != 12
                || odt.getMinute() != 30 || odt.getSecond() != 45) {
            fail("ofString_noTimezone", "Parsed date/time fields mismatch");
        }
        // Offset should match the JVM's local zone, not necessarily UTC
        ZoneOffset localOffset = ZoneId.systemDefault().getRules()
                .getOffset(LocalDateTime.of(2024, 6, 15, 12, 30, 45));
        if (!odt.getOffset().equals(localOffset)) {
            fail("ofString_noTimezone",
                    "Expected local offset " + localOffset
                            + " but got " + odt.getOffset());
        }
        pass("ofString_noTimezone");
    }

    /**
     * No timezone, hour-only form (minimum BER local-time string)
     */
    static void testOfString_noTimezone_hourOnly() {
        Asn1GeneralizedTime gt = Asn1GeneralizedTime.of("2024061512");

        if (gt.hasExplicitOffset()) {
            fail("ofString_noTimezone_hourOnly",
                    "hasExplicitOffset should be false");
        }
        OffsetDateTime odt = gt.toOffsetDateTime();
        if (odt.getHour() != 12 || odt.getMinute() != 0
                || odt.getSecond() != 0) {
            fail("ofString_noTimezone_hourOnly",
                    "Parsed time fields mismatch");
        }
        pass("ofString_noTimezone_hourOnly");
    }

    // -----------------------------------------------------------------------
    // tag()
    // -----------------------------------------------------------------------

    static void testTag() {
        Asn1GeneralizedTime gt = Asn1GeneralizedTime.of("20240615123045Z");
        if (!gt.tag().equals(Asn1Tags.GENERALIZEDTIME)) {
            fail("tag", "Expected GENERALIZEDTIME tag");
        }
        pass("tag");
    }

    // -----------------------------------------------------------------------
    // toOffsetDateTime() and hasExplicitOffset()
    // -----------------------------------------------------------------------

    static void testToOffsetDateTime_roundtrip() {
        OffsetDateTime expected = OffsetDateTime.parse("2024-06-15T12:30:45Z");
        Instant instant = expected.toInstant();
        Asn1GeneralizedTime gt = Asn1GeneralizedTime.of(instant);

        if (!gt.toOffsetDateTime().isEqual(expected)) {
            fail("toOffsetDateTime_roundtrip",
                    "Expected " + expected + " got " + gt.toOffsetDateTime());
        }
        pass("toOffsetDateTime_roundtrip");
    }

    static void testHasExplicitOffset_trueFromInstant() {
        Asn1GeneralizedTime gt =
                Asn1GeneralizedTime.of(Instant.parse("2024-06-15T00:00:00Z"));
        if (!gt.hasExplicitOffset()) {
            fail("hasExplicitOffset_trueFromInstant",
                    "of(Instant) must always set hasExplicitOffset=true");
        }
        pass("hasExplicitOffset_trueFromInstant");
    }

    static void testHasExplicitOffset_trueFromStringWithZ() {
        Asn1GeneralizedTime gt = Asn1GeneralizedTime.of("20240615120000Z");
        if (!gt.hasExplicitOffset()) {
            fail("hasExplicitOffset_trueFromStringWithZ",
                    "String with Z must set hasExplicitOffset=true");
        }
        pass("hasExplicitOffset_trueFromStringWithZ");
    }

    static void testHasExplicitOffset_falseFromStringWithoutTZ() {
        Asn1GeneralizedTime gt = Asn1GeneralizedTime.of("20240615120000");
        if (gt.hasExplicitOffset()) {
            fail("hasExplicitOffset_falseFromStringWithoutTZ",
                    "String without TZ must set hasExplicitOffset=false");
        }
        pass("hasExplicitOffset_falseFromStringWithoutTZ");
    }

    // -----------------------------------------------------------------------
    // Asn1Time interface: toInstant() and compareTo()
    // -----------------------------------------------------------------------

    static void testToInstant() {
        Instant expected = Instant.parse("2024-06-15T12:30:45Z");
        Asn1GeneralizedTime gt = Asn1GeneralizedTime.of(expected);

        if (!gt.toInstant().equals(expected)) {
            fail("toInstant", "Instant mismatch");
        }
        pass("toInstant");
    }

    static void testCompareTo_before() {
        Asn1GeneralizedTime earlier =
                Asn1GeneralizedTime.of("20240615120000Z");
        Asn1GeneralizedTime later =
                Asn1GeneralizedTime.of("20240615130000Z");

        if (earlier.compareTo(later) >= 0) {
            fail("compareTo_before", "Expected earlier < later");
        }
        pass("compareTo_before");
    }

    static void testCompareTo_equal() {
        Asn1GeneralizedTime a = Asn1GeneralizedTime.of("20240615120000Z");
        Asn1GeneralizedTime b = Asn1GeneralizedTime.of("20240615120000Z");

        if (a.compareTo(b) != 0) {
            fail("compareTo_equal", "Expected comparison result 0");
        }
        pass("compareTo_equal");
    }

    static void testCompareTo_after() {
        Asn1GeneralizedTime earlier =
                Asn1GeneralizedTime.of("20240615120000Z");
        Asn1GeneralizedTime later =
                Asn1GeneralizedTime.of("20240615130000Z");

        if (later.compareTo(earlier) <= 0) {
            fail("compareTo_after", "Expected later > earlier");
        }
        pass("compareTo_after");
    }

    /**
     * Two times that represent the same instant but with different offsets
     * must compare as equal via compareTo (instant-based comparison).
     */
    static void testCompareTo_sameInstant_differentOffset() {
        // 12:00 UTC == 17:00 +05:00
        Asn1GeneralizedTime utc =
                Asn1GeneralizedTime.of("20240615120000Z");
        Asn1GeneralizedTime plus5 =
                Asn1GeneralizedTime.of("20240615170000+0500");

        if (utc.compareTo(plus5) != 0) {
            fail("compareTo_sameInstant_differentOffset",
                    "Same instant with different offsets should compare equal");
        }
        pass("compareTo_sameInstant_differentOffset");
    }

    // -----------------------------------------------------------------------
    // equals()
    // -----------------------------------------------------------------------

    static void testEquals_sameObject() {
        Asn1GeneralizedTime gt = Asn1GeneralizedTime.of("20240615120000Z");
        if (!gt.equals(gt)) {
            fail("equals_sameObject", "An object must equal itself");
        }
        pass("equals_sameObject");
    }

    static void testEquals_equalObjects() {
        Asn1GeneralizedTime a = Asn1GeneralizedTime.of("20240615120000Z");
        Asn1GeneralizedTime b = Asn1GeneralizedTime.of("20240615120000Z");
        if (!a.equals(b)) {
            fail("equals_equalObjects", "Equal objects must compare equal");
        }
        pass("equals_equalObjects");
    }

    static void testEquals_null() {
        Asn1GeneralizedTime gt = Asn1GeneralizedTime.of("20240615120000Z");
        if (gt.equals(null)) {
            fail("equals_null", "equals(null) must return false");
        }
        pass("equals_null");
    }

    static void testEquals_differentClass() {
        Asn1GeneralizedTime gt = Asn1GeneralizedTime.of("20240615120000Z");
        if (gt.equals("20240615120000Z")) {
            fail("equals_differentClass",
                    "equals must return false for different class");
        }
        pass("equals_differentClass");
    }

    static void testEquals_differentDateTime() {
        Asn1GeneralizedTime a = Asn1GeneralizedTime.of("20240615120000Z");
        Asn1GeneralizedTime b = Asn1GeneralizedTime.of("20240615130000Z");
        if (a.equals(b)) {
            fail("equals_differentDateTime",
                    "Different dateTimes must not be equal");
        }
        pass("equals_differentDateTime");
    }

    /**
     * Same underlying instant, different offsets -> different OffsetDateTime
     * objects -> not equal (equals uses OffsetDateTime.equals which is
     * offset-sensitive, unlike isEqual which is instant-sensitive).
     */
    static void testEquals_sameInstant_differentOffset_notEqual() {
        // Both represent the same instant, but different OffsetDateTime values
        Asn1GeneralizedTime utc  =
                Asn1GeneralizedTime.of("20240615120000Z");
        Asn1GeneralizedTime plus5 =
                Asn1GeneralizedTime.of("20240615170000+0500");

        // They represent the same instant but OffsetDateTime.equals is
        // offset-sensitive, so equals() must return false here.
        if (utc.equals(plus5)) {
            fail("equals_sameInstant_differentOffset_notEqual",
                    "Different OffsetDateTimes must not be equal even if "
                            + "they represent the same instant");
        }
        pass("equals_sameInstant_differentOffset_notEqual");
    }

    /**
     * Same dateTime but different hasExplicitOffset -> not equal.
     * Construct via string with and without timezone designator.
     * To isolate hasExplicitOffset as the only difference, we need both
     * objects to have the same OffsetDateTime, which means the local
     * timezone must be UTC for this test.  We skip the assertion if the
     * local zone is not UTC, so the test is always safe.
     */
    static void testEquals_differentHasExplicitOffset() {
        ZoneOffset localOffset = ZoneId.systemDefault()
                .getRules().getOffset(
                        java.time.LocalDateTime.of(2024, 6, 15, 12, 0, 0));

        if (!localOffset.equals(ZoneOffset.UTC)) {
            // Can't make the OffsetDateTime identical when local != UTC;
            // document why and skip rather than give a false failure.
            System.out.println("SKIP: equals_differentHasExplicitOffset "
                    + "(local zone is not UTC, cannot isolate hasExplicitOffset)");
            return;
        }

        // Both produce OffsetDateTime at UTC 12:00, but one has hasOffset=true
        // (Z suffix) and the other has hasOffset=false (no suffix).
        Asn1GeneralizedTime withZ =
                Asn1GeneralizedTime.of("20240615120000Z");
        Asn1GeneralizedTime noTZ =
                Asn1GeneralizedTime.of("20240615120000");

        if (withZ.equals(noTZ)) {
            fail("equals_differentHasExplicitOffset",
                    "Objects with different hasExplicitOffset must not be equal");
        }
        pass("equals_differentHasExplicitOffset");
    }

    // -----------------------------------------------------------------------
    // hashCode()
    // -----------------------------------------------------------------------

    static void testHashCode_consistentWithEquals() {
        Asn1GeneralizedTime a = Asn1GeneralizedTime.of("20240615120000Z");
        Asn1GeneralizedTime b = Asn1GeneralizedTime.of("20240615120000Z");

        if (a.hashCode() != b.hashCode()) {
            fail("hashCode_consistentWithEquals",
                    "Equal objects must have equal hash codes");
        }
        pass("hashCode_consistentWithEquals");
    }

    static void testHashCode_differsForDifferentDateTime() {
        Asn1GeneralizedTime a = Asn1GeneralizedTime.of("20240615120000Z");
        Asn1GeneralizedTime b = Asn1GeneralizedTime.of("20240616120000Z");

        // Hash collision is allowed by contract but extremely unlikely for
        // these inputs; flag as a likely bug if they collide.
        if (a.hashCode() == b.hashCode()) {
            System.out.println("WARN: hashCode_differsForDifferentDateTime "
                    + "-- hash collision for different dateTimes "
                    + "(allowed by contract but suspicious)");
        } else {
            pass("hashCode_differsForDifferentDateTime");
        }
    }

    static void testHashCode_differsForDifferentHasExplicitOffset() {
        // Only meaningful when local zone == UTC (same OffsetDateTime)
        ZoneOffset localOffset = ZoneId.systemDefault()
                .getRules().getOffset(
                        java.time.LocalDateTime.of(2024, 6, 15, 12, 0, 0));

        if (!localOffset.equals(ZoneOffset.UTC)) {
            System.out.println("SKIP: hashCode_differsForDifferentHasExplicitOffset"
                    + " (local zone is not UTC)");
            return;
        }

        Asn1GeneralizedTime withZ  = Asn1GeneralizedTime.of("20240615120000Z");
        Asn1GeneralizedTime noTZ   = Asn1GeneralizedTime.of("20240615120000");

        if (withZ.hashCode() == noTZ.hashCode()) {
            System.out.println("WARN: hashCode_differsForDifferentHasExplicitOffset"
                    + " -- hash collision (allowed but suspicious)");
        } else {
            pass("hashCode_differsForDifferentHasExplicitOffset");
        }
    }

    static void testHashCode_stable() {
        Asn1GeneralizedTime gt = Asn1GeneralizedTime.of("20240615120000Z");
        int h1 = gt.hashCode();
        int h2 = gt.hashCode();
        if (h1 != h2) {
            fail("hashCode_stable", "hashCode must be stable across calls");
        }
        pass("hashCode_stable");
    }

    // -----------------------------------------------------------------------
    // main
    // -----------------------------------------------------------------------

    public static void main(String[] args) {
        // of(Instant)
        testOfInstant_valid();
        testOfInstant_null();

        // of(Instant, ZoneOffset)
        testOfInstantOffset_valid_utc();
        testOfInstantOffset_valid_positiveOffset();
        testOfInstantOffset_valid_negativeOffset();
        testOfInstantOffset_nullInstant();
        testOfInstantOffset_nullOffset();

        // of(String) — negative
        testOfString_null();
        testOfString_empty();
        testOfString_totallyInvalid();
        testOfString_badMonth();
        testOfString_badDay();
        testOfString_badHour();
        testOfString_truncatedYear();

        // of(String) — positive format variations
        testOfString_hourOnly_Z();
        testOfString_hourMinute_Z();
        testOfString_fullSeconds_Z();
        testOfString_fractionalSeconds_dot();
        testOfString_fractionalSeconds_comma();
        testOfString_nanosecondPrecision();
        testOfString_fractionalSeconds_multipleDigits();
        testOfString_positiveOffset();
        testOfString_negativeOffset();
        testOfString_noTimezone();
        testOfString_noTimezone_hourOnly();

        // tag(), toOffsetDateTime(), hasExplicitOffset()
        testTag();
        testToOffsetDateTime_roundtrip();
        testHasExplicitOffset_trueFromInstant();
        testHasExplicitOffset_trueFromStringWithZ();
        testHasExplicitOffset_falseFromStringWithoutTZ();

        // Asn1Time interface
        testToInstant();
        testCompareTo_before();
        testCompareTo_equal();
        testCompareTo_after();
        testCompareTo_sameInstant_differentOffset();

        // equals()
        testEquals_sameObject();
        testEquals_equalObjects();
        testEquals_null();
        testEquals_differentClass();
        testEquals_differentDateTime();
        testEquals_sameInstant_differentOffset_notEqual();
        testEquals_differentHasExplicitOffset();

        // hashCode()
        testHashCode_consistentWithEquals();
        testHashCode_differsForDifferentDateTime();
        testHashCode_differsForDifferentHasExplicitOffset();
        testHashCode_stable();

        System.out.println("\nAll tests completed.");
    }
}
