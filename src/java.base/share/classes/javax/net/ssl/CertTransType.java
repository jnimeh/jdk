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

package javax.net.ssl;

import java.util.Locale;

/**
 * An enumeration describing various types of certificate transparency objects.
 * Known types include the two forms of signed certificate timestamps from
 * version 1 (RFC 6962) and all TransItem types from version 2 (RFC 9162).
 *
 * @since 27
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc6962">RFC 6962</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9162">RFC 9162</a>
 */
public enum CertTransType {
    /**
     * Type describing an X509 log entry.
     * This has the ID value of 0x00.
     */
    X509_ENTRY(0x00),

    /**
     * Type describing a pre-certificate log entry.
     * This has the ID value of 0x01.
     */
    PRECERT_ENTRY(0x01),

    /**
     * Type describing an X509 signed certificate timestamp
     * This has the id value of 0x02.
     */
    X509_SCT(0x02),

    /**
     * Type describing a pre-certificate signed certificate timestamp
     * This has the id value of 0x03.
     */
    PRECERT_SCT(0x03),

    /**
     * Type describing a signed tree head
     * This has the id value of 0x04.
     */
    SIGNED_TREE_HEAD(0x04),

    /**
     * Type describing a consistency proof.
     * This has the id value of 0x05.
     */
    CONSISTENCY_PROOF(0x05),

    /**
     * Type describing an inclusion proof
     * This has the id value of 0x06.
     */
    INCLUSION_PROOF(0x06);

    private final int id;

    CertTransType(int idVal) {
        this.id = idVal;
    }

    /**
     * Obtain the numeric ID value for a given {@code CertTransType}
     *
     * @return the ID value.
     */
    public int getId() {
        return id;
    }

    /**
     * Retrun a {@code VersionedTransType} based on its numeric ID value.
     *
     * @param idVal an integer containing the ID value.
     *
     * @return the corresponding {@code VersionedTransType} for the
     * {@code idVal} parameter, or {@code null} if it is not a known value.
     */
    public static CertTransType valueOf(int idVal) {
        for (CertTransType ctt : CertTransType.values()) {
            if (ctt.id == idVal) {
                return ctt;
            }
        }
        return null;
    }

    @Override
    public String toString() {
        return this.name().toLowerCase(Locale.ROOT);
    }

}
