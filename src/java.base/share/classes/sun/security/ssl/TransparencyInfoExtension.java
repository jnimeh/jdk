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

package sun.security.ssl;


package sun.security.ssl;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import sun.security.ssl.SSLExtension.ExtensionConsumer;
import sun.security.ssl.SSLExtension.SSLExtensionSpec;
import sun.security.ssl.SSLHandshake.HandshakeMessage;

import javax.net.ssl.SignedCertificateTimestamp;

import static sun.security.ssl.SSLExtension.*;

final class TransparencyInfoExtension {

    static final HandshakeProducer chNetworkProducer =
            new CHTransparencyInfoProducer();
    static final ExtensionConsumer chOnLoadConsumer =
            new CHTransparencyInfoConsumer();

    static final HandshakeProducer shNetworkProducer =
            new SHTransparencyInfoProducer();
    static final ExtensionConsumer shOnLoadConsumer =
            new SHTransparencyInfoConsumer();

    static final HandshakeProducer ctNetworkProducer =
            new CTTransparencyInfoProducer();
    static final ExtensionConsumer ctOnLoadConsumer =
            new CTTransparencyInfoConsumer();

    static final SSLStringizer transparencyInfoStringizer =
            new TransparencyInfoStringizer();


    /**
     * The "transparency_info" extension.
     * <p>
     * RFC 9162 defines the certificate transparency v2.0 TLS extension,
     * "transparency_info" (type 0x34), which allows the client to
     * request signed certificate timestamps from the server via any of the
     * three defined mechanisms.
     * The handling logic in this file covers sending the ClientHello extension
     * and processing the TransItem structures returned in the ServerHello
     * (TLS <= 1.2) or Certificate (TLS >= 1.3) messages.  Processing for
     * TransItems delivered via X.509 certificates and OCSP responses are
     * handled in other parts of the handshaking code.
     * <p>
     * The "extension data" field of this extension contains a
     * "TransItemList" structure:
     * <pre>
     * opaque SerializedTransItem<1..2^16-1>
     *
     * struct {
     *      SerializedTransItem trans_item_list<1..2^16-1>;
     * } SignedCertificateTimestamp;
     * </pre>
     * The spec itself handles a SignedCertificateTimestampList, a vector
     * consisting of one or more SerializedSCT structures:
     * <pre>
     * opaque SerializedSCT<1..2^16-1>;
     *
     * struct {
     *      SerializedSCT sct_list <1..2^16-1>;
     * } SignedCertificateTimestampList;
     * </pre>
     */
    static final class TransItemListSpec implements SSLExtensionSpec {
        static final TransItemListSpec NOMINAL =
                new TransItemListSpec(Collections.emptyList());

        final List<TransItem> transItemList;

        private TransItemListSpec(List<TransItem> sctList) {
            this.transItemList = sctList;
        }

        private TransItemListSpec(HandshakeContext hc, ByteBuffer buffer)
                throws IOException {
            //TODO
            transItemList = List.of();
//            try {
//                this.sigCertTsList = new ArrayList<>(
//                        SignedCertificateTimestamp.getSCTList(
//                                X509CertSctV1.class, buffer));
//            } catch (IOException ioe) {
//                throw hc.conContext.fatal(Alert.DECODE_ERROR, ioe);
//            }
        }


    /**
     * Network data producer of a "signed_certificate_timestamp" extension in
     * the ClientHello handshake message.
     */
    private static final class CHTransparencyInfoProducer
            implements HandshakeProducer {
        // Prevent instantiation of this class.
        private CHTransparencyInfoProducer() {
            // blank
        }

        @Override
        public byte[] produce(ConnectionContext context,
                HandshakeMessage message) throws IOException {
            // The producing happens in client side only.
            ClientHandshakeContext chc = (ClientHandshakeContext)context;
            if (!SSLConfiguration.enableClientCertTrans) {
                return null;
            }

            if (!chc.sslConfig.isAvailable(CH_TRANSPARENCY_INFO)) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("Ignore unavailable extension: " +
                            CH_TRANSPARENCY_INFO.name);
                }
                return null;
            }

            // Produce the extension.  For the client hello, the extension
            // should have an empty extension_data field.
            byte[] extData = new byte[0];

            // Update the context.
            chc.handshakeExtensions.put(CH_TRANSPARENCY_INFO,
                    SignedCertTimestampExtension.SignedCertTimestampSpec.NOMINAL);

            return extData;
        }
    }

}
