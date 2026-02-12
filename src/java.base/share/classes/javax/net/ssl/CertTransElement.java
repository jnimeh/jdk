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

import java.io.IOException;

/**
 * A basic interface for objects returned through the Certificate Transparency
 * support in JSSE.  This interface can be used to encompass RFC 6962 signed
 * certificate timestamps, or any RFC 9162 TransItem structure that is provided
 * to a JSSE consumer.
 *
 * @since 27
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc6962">RFC 6962</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9162">RFC 9162</a>
 */
public interface CertTransElement {

    /**
     * Obtain the type of certificate transparency object.
     *
     * @return a {@code CertTransType} that corresponds to the type
     * of certificate transparency object being used, or {@code null} if the
     * type is unknown.
     */
    CertTransType getType();

    /**
     * Obtain the version of the certificate transparency protocol to which
     * this {@code CertTransElement} belongs.
     *
     * @return an integer indicating the version of certificate transparency
     * for this object.
     */
    int getVersion();

    /**
     * Return the encoded form of this certificate transparency object.
     *
     * @return a byte array with the encoded form of this object.
     *
     * @throws IOException if any encoding errors occur.
     */
    byte[] getEncoded() throws IOException;

}
