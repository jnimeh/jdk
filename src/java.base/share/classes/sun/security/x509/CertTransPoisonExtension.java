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

/**
 * Represent the Signed Certificate Timestamp List extension.
 * <p>
 * This extension, should only be present in certificate transparency
 * precertificate entries.  Its presence in certificates prevents the use
 * of the certificate in standard PKIX path validation.
 * <p>
 * The structure of this extension is a simple ASN.1 NULL.
 * <p>
 * Extensions are represented as a sequence of the extension identifier
 * (Object Identifier), a boolean flag stating whether the extension is to
 * be treated as being critical and the extension value itself (this is again
 * a DER encoding of the extension value).
 *
 * @see Extension
 */
public class CertTransPoisonExtension extends Extension {

    public static final String NAME =
            "Certificate Transparency Poison Extension";

    /**
     * Create a critical Certificate Transparency poison extension.
     * Note that RFC 6962 states that the CT poison extension should be
     * marked critical.  If a non-critical form of the extension is required,
     * use {@link CertTransPoisonExtension#CertTransPoisonExtension(boolean)}.
     */
    public CertTransPoisonExtension() {
        this(true);
    }

    /**
     * Create a Certificate Transparency poison extension with optional
     * criticality.  Note that RFC 6962 states that the CT poison extension
     * should be marked critical.
     *
     * @param critical the criticality bit for the extension
     */
    public CertTransPoisonExtension(boolean critical) {
        this.extensionId = PKIXExtensions.CertificateTransparencyPoison_Id;
        this.critical = critical;
        this.extensionValue = new byte[0];
    }

    /**
     * Returns a printable representation.
     */
    @Override
    public String toString() {
        return NAME + "\n";
    }

    @Override
    public String getName() {
        return NAME;
    }
}
