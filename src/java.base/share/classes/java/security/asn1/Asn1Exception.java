package java.security.asn1;

import java.io.Serial;

/**
 * Base class for all ASN.1 related exceptions.
 * Unchecked to allow fluent parsing in typical schema-guided usage.
 */
public class Asn1Exception extends RuntimeException {

    @Serial
    private static final long serialVersionUID = 1L;

    /**
     * Create an {@code Asn1Exception} with a message
     *
     * @param message the message to attach to this exception
     */
    public Asn1Exception(String message) {
        super(message);
    }

    /**
     * Create an {@code Asn1Exception} with an underlying cause
     *
     * @param cause the underlying {@link Throwable} that triggered this
     *              exception
     */
    public Asn1Exception(Throwable cause) {
        super(cause);
    }

    /**
     * Create an {@code Asn1Exception} with an underlying cause and custom
     * message
     *
     * @param message the message to attach to this exception
     * @param cause the underlying {@link Throwable} that triggered this
     *              exception
     */
    public Asn1Exception(String message, Throwable cause) {
        super(message, cause);
    }
}