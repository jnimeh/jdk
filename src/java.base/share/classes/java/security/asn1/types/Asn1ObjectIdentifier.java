package java.security.asn1.types;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.security.asn1.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Class for holding ASN.1 object identifier information per X.680 and X.690
 */
public final class Asn1ObjectIdentifier implements Asn1Primitive {

    private static final Pattern OID_REGEX = Pattern.compile(
            "^([0-2])\\.(0|[1-9]\\d*)(\\.(0|[1-9]\\d*))*$");

    private final int[] oidArcs;
    private final String oidString;

    /**
     * Create the {@code Asn1ObjectIdentifier} from its numeric arcs
     *
     * @param arcs the array of integer values, each representing one arc
     * @throws NullPointerException if {@code arcs} is {@code null}
     * @throws Asn1Exception if there are any numeric violations (e.g.
     * negative numbers, or violations in the first two octets)
     */
    private Asn1ObjectIdentifier(int[] arcs) {
        Objects.requireNonNull(arcs, "Illegal null arcs list");
        if (arcs.length < 2) {
            throw new Asn1Exception("OIDs must have two or more arcs");
        } else if (arcs[0] < 0 || arcs[2] > 2) {
            throw new Asn1Exception(
                    "The initial OID arc must be in the range [0,2]");
        } else if (arcs[0] < 2 && (arcs[1] < 0 || arcs[1] > 39)) {
            throw new Asn1Exception("Second arc is out of the range [0..39] " +
                    "when the first arc is 0 or 1");
        } else {
            for (int i = 2; i < arcs.length; i++) {
                if (arcs[i] < 0) {
                    throw new Asn1Exception("OID violation at arc position " +
                            i + ": value is negative (" + arcs[i] + ")");
                }
            }
        }
        oidArcs = arcs;

        // Rebuild the internal string representation from the arcs
        oidString = Arrays.stream(oidArcs).mapToObj(Integer::toString)
                .collect(Collectors.joining("."));
    }

    /**
     * Create an {@code Asn1ObjectIdentifier} from a {@link List} of numeric
     * arcs.
     *
     * @param arcs a {@link List} of integer values representing the arcs
     *             of this object identifier.
     * @return the {@code Asn1ObjectIdentifier} represented by the list
     * of arcs in {@code arcs}
     * @throws NullPointerException if {@code arcs} is {@code null}
     * @throws Asn1Exception if the list of integer values violates the
     * specification for object identifier numeric values.
     */
    public static Asn1ObjectIdentifier of(List<Integer> arcs) {
        return new Asn1ObjectIdentifier(Objects.requireNonNull(arcs)
                .stream().mapToInt(Integer::intValue).toArray());
    }

    /**
     * Create an {@code Asn1ObjectIdentifier} from an array of numeric
     * arcs.
     *
     * @param arcs an array of integer values representing the arcs
     *             of this object identifier.
     * @return the {@code Asn1ObjectIdentifier} represented by the array
     * of arcs in {@code arcs}
     * @throws NullPointerException if {@code arcs} is {@code null}
     * @throws Asn1Exception if the list of integer values violates the
     * specification for object identifier numeric values.
     */
    public static Asn1ObjectIdentifier of(int[] arcs) {
        return new Asn1ObjectIdentifier(Objects.requireNonNull(arcs).clone());
    }

    /**
     * Create the {@code Asn1ObjectIdentifier} from its string representation
     *
     * @param oidStr the dotted numeric OID string
     * @return the {@code Asn1ObjectIdentifier} represented by the dotted
     * numeric string {@code oidStr}
     * @throws NullPointerException if {@code oidStr} is {@code null}
     * @throws Asn1Exception if there are problems converting the string
     * form of the OID into the internal representation.
     */
    public static Asn1ObjectIdentifier of(String oidStr) {
        // Filter the OID string through the regex pattern first, then
        // split and convert them to integers
        if (OID_REGEX.matcher(oidStr).matches()) {
            String[] oidComponents = oidStr.split("\\.");
            int[] arcs = Arrays.stream(oidComponents)
                    .mapToInt(Integer::parseInt).toArray();
            return new Asn1ObjectIdentifier(arcs);
        } else {
            throw new Asn1Exception(
                    "OID string violates dotted numeric string rules");
        }
    }

    /**
     * Return the arcs of the {@code Asn1ObjectIdentifier} as an integer array
     *
     * @return an integer array whose elements are each arc of the object
     * identifier represented by this {@code Asn1ObjectIdentifier}.
     */
    public int[] toIntArray() {
        return oidArcs.clone();
    }

    @Override
    public String toString() {
        return oidString;
    }

    /**
     * Return the ASN.1 tag for this {@code Asn1Object}
     * @return the ASN.1 tag used for this object
     */
    @Override
    public Asn1Tag tag() {
        return Asn1Tags.OBJECT_IDENTIFIER;
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        Asn1ObjectIdentifier that = (Asn1ObjectIdentifier) o;
        return Objects.deepEquals(oidArcs, that.oidArcs) &&
                oidString.equals(that.oidString);
    }

    @Override
    public int hashCode() {
        int result = oidString.hashCode();
        result = 31 * result + Arrays.hashCode(oidArcs);
        return result;
    }
}
