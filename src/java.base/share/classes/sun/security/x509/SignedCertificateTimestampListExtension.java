/*
 * Copyright (c) 2026, Oracle and/or its affiliates. All rights reserved.
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

package sun.security.x509;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.net.ssl.CertTransType;
import javax.net.ssl.SignedCertificateTimestamp;

import sun.security.ssl.SignedCertTimestampV1;
import sun.security.util.*;

/**
 * Represent the Signed Certificate Timestamp List extension.
 * <p>
 * This extension, if present, provides a means of embedding signed certificate
 * timestamps (SCTs) into an X.509 certificate.
 * <p>
 * For the structure of the SignedCertificateTimestamp itself, please refer
 * to RFC 6962.
 * <p>
 * Extensions are represented as a sequence of the extension identifier
 * (Object Identifier), a boolean flag stating whether the extension is to
 * be treated as being critical and the extension value itself (this is again
 * a DER encoding of the extension value).
 *
 * @see Extension
 */
public abstract class SignedCertificateTimestampListExtension
        extends Extension {

    // Attribute names
    public static final String X509_NAME =
            "PreCert Signed Certificate Timestamp List";
    public static final String OCSP_NAME =
            "OCSP Signed Certificate Timestamp List";

    // Private data member
    protected final List<SignedCertificateTimestamp> sctList =
            new ArrayList<>();
    protected final byte[] serializedSctList;

    /**
     * Create a SignedCertificateTimestampListExtension with the passed
     * octet string.  The criticality is set to False.  This assumes the
     * first two bytes are the sct_list vector length.
     *
     * @param octetString the octet string identifying the sct_list.
     *
     * @throws IOException if any SCT parsing errors occur.
     */
    protected SignedCertificateTimestampListExtension(byte[] octetString)
            throws IOException {
        this(Boolean.FALSE, octetString);
    }

    /**
     * Create a SignedCertificateTimestampListExtension with an Object
     * as the input and a specified criticality value.
     * This assumes the first two bytes are the sct_list
     * vector length.
     *
     * @param critical the criticality bit for the extension
     * @param value the octet string as an Object (which should be byte[]
     *      actually).
     *
     * @throws IOException if any SCT parsing errors occur.
     * @throws ClassCastException if the underlying type of the Object is
     *      not byte[].
     */
    protected SignedCertificateTimestampListExtension(Boolean critical,
            Object value) throws IOException {
        this(critical, (byte[])value);
    }

    /**
     * Create a SignedCertificateTimestampListExtension with the passed
     * octet string.  This assumes the first two bytes are the sct_list
     * vector length.
     *
     * @param critical the criticality bit for the extension
     * @param octetString the octet string identifying the sct_list.
     *
     * @throws IOException if any SCT parsing errors occur.
     */
    protected SignedCertificateTimestampListExtension(Boolean critical,
            byte[] octetString) throws IOException {
        DerValue encapsOctStr = new DerValue(octetString);
        serializedSctList = encapsOctStr.getDataBytes();
        this.extensionValue = octetString.clone();
        this.critical = critical;
    }

    /**
     * Obtain the list of SignedCertificateTimestamp objects from this
     * extension.
     *
     * @return an unmodifiable {@code List} containing the signed certificate
     * timestamps in the order they exist in the certificate.
     */
    public List<SignedCertificateTimestamp> getSignedCertTimestamps() {
        return Collections.unmodifiableList(sctList);
    }

    /**
     * Returns a printable representation.
     */
    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        int numElem = sctList.size();
        sb.append(super.toString());
        sb.append(getName()).append(" (").append(numElem).
                append(" ").append(numElem == 1 ? "entry" : "entries").
                append(") [\n");
        sctList.forEach(sct -> sb.append(sct).append("\n\n"));
        sb.append("]\n");
        return sb.toString();
    }

    public static class PreCertSCTListExt extends
            SignedCertificateTimestampListExtension {
        public PreCertSCTListExt(byte[] octetString) throws IOException {
            this(Boolean.FALSE, octetString);
        }

        public PreCertSCTListExt(Boolean critical, Object value)
                throws IOException {
            this(critical, (byte[])value);
        }

        public PreCertSCTListExt(Boolean critical, byte[] octetString)
                throws IOException {
            super(critical, octetString);
            this.extensionId = PKIXExtensions.SignedCertificateTimestampList_Id;
            sctList.addAll(SignedCertTimestampV1.getSCTs(
                    CertTransType.PRECERT_SCT, serializedSctList));
        }

        @Override
        public String getName() {
            return X509_NAME;
        }
    }

    public static class OCSPSCTListExt extends
            SignedCertificateTimestampListExtension {
        public OCSPSCTListExt(byte[] octetString) throws IOException {
            this(Boolean.FALSE, octetString);
        }

        public OCSPSCTListExt(Boolean critical, Object value)
                throws IOException {
            this(critical, (byte[])value);
        }

        public OCSPSCTListExt(Boolean critical, byte[] octetString)
                throws IOException {
            super(critical, octetString);
            this.extensionId =
                    PKIXExtensions.SignedCertificateTimestampListOCSP_Id;
            sctList.addAll(SignedCertTimestampV1.getSCTs(
                    CertTransType.X509_SCT, serializedSctList));
        }

        @Override
        public String getName() {
            return OCSP_NAME;
        }
    }
}
