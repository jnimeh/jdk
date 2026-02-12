/*
 * Copyright (c) 2025, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

package javax.net.ssl;

import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Map;

/**
 * This interface provides access methods for the different components that
 * form a signed certificate timestamp (SCT).  This interface supports versions
 * 1 and 2 from RFC 6962 and 9162, respectively.
 *
 * @since 27
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc6962">RFC 6962</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9162">RFC 9162</a>
 */
public interface SignedCertificateTimestamp extends CertTransElement {

    /**
     * Provide the certificate transparency log identifier as a byte array.
     *
     * @return a byte array indicating the log ID.
     */
    byte[] getLogId();

    /**
     * Return the {@code timestamp} field from a signed certificate timestamp.
     *
     * @return an {@link Instant} object corresponding to the timestamp field of
     *         the signed certificate timestamp.
     */
    Instant getTimestamp();

    /**
     * Return the encoded signature data.
     *
     * @return the signature data in byte array form.
     */
    byte[] getSignature();

    /**
     * Return the extensions block of a signed certificate timestamp (SCT).
     *
     * @return a {@code Map} containing zero or more extensions indexed by
     * their integer ID value.  The value for any entry is a byte array
     * containing the extension data without the TLS vector length prefix.
     */
    Map<Integer, byte[]> getExtensions();

    /**
     * Verify the signature on a signed certificate timestamp.
     *
     * @param certificate the certificate to which the signed certificate
     *                    timestamp belongs
     * @param issuerKey the {@link PublicKey} for the certificate issuer
     * @param logKey the {@link PublicKey} for the certificate transparency log
     *
     * @return true if the signature verifies, false if it fails validation.
     * @throws SignatureException if an error occurs during signature
     *                            verification.
     */
    boolean verify(X509Certificate certificate, PublicKey issuerKey,
            PublicKey logKey) throws SignatureException;
}
